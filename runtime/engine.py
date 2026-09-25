"""阶段编排：把配置、覆盖层、模板、插件串成一次真实执行。

    resolve → login → prepare → detect → execute → verification → confirm → render

引擎是唯一「知道整件事怎么串起来」的地方。插件互不认识：登录方式不知道要执行什么任务，
任务方式不知道怎么登录，模板只描述站点。这条边界是旧实现最缺的——
``providers/actions/api.py`` 的 400 行状态机同时干了这四件事，于是「余额交叉验证」
既关不掉也没法给别的站点族复用，「先纯 API 再开浏览器」的降级链写死在 browser_script
里、别的动作用不上。

三条不变量：
1. **固定即固定**：``flow`` 里写死的阶段失败就失败，绝不自行扩大候选（旧实现的静默
   降级正是「日志看不出走了哪条路」的根因）；
2. **执行即学习**：真正跑通的候选被写回覆盖层，下次直接命中；
3. **一个账号一次浏览器**：登录阶段与所有任务共享同一个惰性租约。
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from browser.service import (
    BrowserService,
    PersistedSession,
    crash_outcome,
    is_driver_crash,
    is_network_transport_crash,
    network_transport_outcome,
)
from config.overlay import Overlay
from config.proxies import ProxyGroup, resolve_proxy
from core import chain as chain_module
from core.account import AccountSpec, ResolvedAccount, TaskSpec
from core.errors import ConfigError, TaskError
from core.flow import AUTO, Discovery, FlowPlan, StageMode, StagePlan
from core.manifest import STAGES
from core.outcome import DisplaySpec, Outcome, Verdict, failed, no_effect
from core.timebase import business_date
from login import LOGINS
from login.base import LoginContext
from net.http import HttpClient, HttpConfig
from sdk.context import AccountView, EvidenceCollector, TaskContext
from sdk.store import Store
from task import TASKS
from templates import registry as templates
from . import capabilities as caps_module
from . import probe
from .budget import Deadline
from .events import event_scope, make_logger

__all__ = ["AccountRun", "TaskRecord", "run_account"]


# ── 结果 ────────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class TaskRecord:
    """一个任务的执行结果。结果文件与汇总表的最小单元。"""

    account_id: str
    task_id: str
    name: str
    base_url: str
    outcome: Outcome
    template: str = ""
    flow: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    display_defaults: DisplaySpec = DisplaySpec()
    duration_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.outcome.ok

    def rendered(self) -> DisplaySpec:
        return self.outcome.rendered(defaults=self.display_defaults)

    def to_payload(self, *, business_day: str = "") -> dict[str, Any]:
        payload = self.outcome.to_payload()
        view = self.rendered()
        payload.update(
            {
                "account_id": self.account_id,
                "task_id": self.task_id,
                "name": self.name,
                "base_url": self.base_url,
                "template": self.template,
                "label": view.label,
                "icon": view.icon,
                "flow": dict(self.flow),
                "duration_seconds": round(self.duration_seconds, 3),
                "business_date": business_day or business_date(),
            }
        )
        if view.text:
            payload["text"] = view.text
            payload["text_label"] = view.text_label
        else:
            payload.pop("text", None)
            payload.pop("text_label", None)
        if view.extras:
            payload["extras"] = [list(item) for item in view.extras]
        return payload


@dataclass(frozen=True, slots=True)
class AccountRun:
    account_id: str
    name: str
    base_url: str
    records: tuple[TaskRecord, ...] = ()

    @property
    def ok(self) -> bool:
        return all(record.ok for record in self.records)

    def to_payload(self, *, business_day: str = "") -> dict[str, Any]:
        return {
            "schema_version": 2,
            "account_id": self.account_id,
            "name": self.name,
            "base_url": self.base_url,
            "results": [record.to_payload(business_day=business_day) for record in self.records],
        }


# ── 入口 ────────────────────────────────────────────────────────────────────
async def run_account(
    spec: AccountSpec,
    *,
    overlay: Overlay,
    explicit: Iterable[str] = (),
    only_tasks: Sequence[str] = (),
    structured: bool = True,
    oauth_state: Any = None,
    proxy_groups: Sequence[ProxyGroup] = (),
    default_proxy_group: str = "",
    environ_proxy: str | None = None,
) -> AccountRun:
    """执行一个账号的全部任务；登录、HTTP、浏览器和脚本共享一次代理解析。"""
    account = overlay.apply(spec, explicit=explicit)
    emit = make_logger(account=account.name, structured=structured)
    try:
        selection = resolve_proxy(
            spec.network, proxy_groups, default_proxy_group,
            environ_proxy=os.environ.get("CHECKIN_PROXY", "") if environ_proxy is None else environ_proxy,
        )
    except ConfigError as exc:
        tasks = [task for task in spec.enabled_tasks() if not only_tasks or task.id in only_tasks]
        return AccountRun(spec.id, spec.name, spec.base_url,
                          tuple(_stub_record(spec, task, exc.to_outcome()) for task in tasks))
    effective = replace(spec.network, proxy=selection.url, proxy_group="",
                        proxy_mode="custom" if selection.url else "direct")
    account = replace(account, effective_network=effective)
    emit("network", selection.description)
    caps = caps_module.detect(account)

    browser = _make_browser(account, overlay, spec, log=lambda m: emit("browser", m)) if "browser" in caps else None
    records: list[TaskRecord] = []
    state_holder: dict[str, Any] = {"account": account, "login": None}

    try:
        tasks = _ordered_tasks(spec, only_tasks)
    except ConfigError as exc:
        return AccountRun(
            spec.id, spec.name, spec.base_url,
            (_stub_record(spec, TaskSpec(id="daily"), exc.to_outcome()),),
        )

    for task in tasks:
        blocked = _blocked_by(task, records)
        if blocked:
            records.append(
                _stub_record(
                    spec,
                    task,
                    no_effect(
                        f"前置任务 {blocked} 未完成，本任务跳过。",
                        reason="not_applicable",
                        data={"blocked_by": blocked},
                    ),
                )
            )
            continue
        started = time.perf_counter()
        try:
            with event_scope(task=task.id):
                record = await _run_one(
                    spec, state_holder, task,
                    overlay=overlay, caps=caps, browser=browser, emit=emit, oauth_state=oauth_state,
                )
        except TaskError as exc:
            record = _stub_record(spec, task, exc.to_outcome())
        except Exception as exc:  # noqa: BLE001 - 引擎内任何异常都要收敛成结论
            if is_driver_crash(exc):
                record = _stub_record(spec, task, crash_outcome(exc).to_outcome())
            elif is_network_transport_crash(exc):
                record = _stub_record(spec, task, network_transport_outcome(exc).to_outcome())
            else:
                record = _stub_record(
                    spec, task, failed(f"任务执行异常：{type(exc).__name__}: {exc}")
                )
        record = replace(record, duration_seconds=time.perf_counter() - started)
        record = _apply_policy(spec, task, record)
        if browser is not None:
            browser.note_outcome(record.outcome)
        overlay.record_health(
            spec.id, ok=record.ok, verdict=str(record.outcome.verdict), reason=record.outcome.reason
        )
        records.append(record)

    if browser is not None:
        await browser.aclose()
    return AccountRun(spec.id, spec.name, spec.base_url, tuple(records))


# ── 单任务 ──────────────────────────────────────────────────────────────────
async def _run_one(
    spec: AccountSpec,
    holder: dict[str, Any],
    task: TaskSpec,
    *,
    overlay: Overlay,
    caps: frozenset[str],
    browser: BrowserService | None,
    emit: Any,
    oauth_state: Any,
) -> TaskRecord:
    account: ResolvedAccount = holder["account"]
    http = _make_http(account, log=None)
    template = await _resolve_template(spec, task, http, overlay, emit)
    manifest = template.manifest

    plan = FlowPlan.resolve(
        configured=_flow_config(spec, task),
        template=manifest,
        learned=account.learned_flow,
        capabilities=caps,
        failure_streak=int(account.health.get("failure_streak", 0) or 0),
    )
    # 访问链任务的参数按步骤解析（见 _chain_args）；这里不按原流程的任务方式校验，
    # 以免某个方式的参数声明挡住整条链。
    args = _resolve_args(manifest, task, plan) if task.chain is None else MappingProxyType(dict(task.args or {}))
    store = Store(spec.id, overlay=overlay, namespace=manifest.id, log=lambda m: emit("store", m))
    evidence = EvidenceCollector(store.evidence_dir(), log=lambda m: emit("run", m))
    ctx = TaskContext(
        account=AccountView.of(account, task),
        args=args,
        flow=plan,
        http=http,
        store=store,
        capabilities=caps,
        evidence=evidence,
        clock=Deadline(task.timeout),
        browser_service=browser,
        stage="run",
        emit=lambda stage, message, **fields: emit(stage, message, task=task.id, **fields),
    )

    discoveries: list[Discovery] = []
    login_ctx = _login_context(account, template, http, browser, caps, emit, oauth_state, ctx)

    # ── 访问链：配置了 chain 的任务由访问链接管登录与执行方式 ──
    if task.chain is not None:
        return await _run_chain(
            spec, holder, task, template, plan, ctx,
            overlay=overlay, caps=caps, browser=browser, emit=emit, oauth_state=oauth_state,
        )

    # ── login ──
    login_plan = plan.get("login")
    result = await LOGINS.establish(
        login_ctx, login_plan, on_credentials=_credential_writer(spec, holder, overlay)
    )
    if result.outcome is not None:
        return _record(spec, task, template, plan, result.outcome, ctx)
    if result.state is not None:
        _apply_login(ctx, login_ctx, result.state, login_plan, spec, holder, overlay)
        if result.discovery is not None:
            discoveries.append(result.discovery)
        ctx.evidence.stage(f"login:{result.state.method}")

    # ── execute（含 verification / confirm）──
    outcome, execute_discovery = await _execute(ctx, template, plan, task)
    if execute_discovery is not None:
        discoveries.append(execute_discovery)

    if discoveries:
        overlay.record_flow(spec.id, discoveries)
    return _record(spec, task, template, plan, outcome, ctx)


async def _execute(
    ctx: TaskContext, template: Any, plan: FlowPlan, task: TaskSpec
) -> tuple[Outcome, Discovery | None]:
    """按候选链执行任务方式。"""
    stage_plan = plan.get("execute")
    candidates = stage_plan.candidates or template.manifest.task_order() or ("http_api",)
    last: Outcome | None = None

    for method_id in candidates:
        driver = TASKS.find(method_id)
        if driver is None:
            last = failed(f"未知任务方式 {method_id}", reason="need_config")
            if stage_plan.locked:
                return last, None
            continue
        missing = set(getattr(driver, "requires", ())) - set(ctx.capabilities)
        if missing:
            reason = caps_module.missing_reason(missing)
            last = failed(f"任务方式 {method_id} 不可用：{reason}", reason="need_config")
            if stage_plan.locked:
                return last, None
            continue

        ctx.stage = "execute"
        ctx.evidence.stage(f"execute:{method_id}")
        try:
            outcome = await driver.run(ctx, template)
        except TaskError as exc:
            outcome = exc.to_outcome()
        except Exception as exc:  # noqa: BLE001
            if is_driver_crash(exc):
                outcome = crash_outcome(exc).to_outcome()
            elif is_network_transport_crash(exc):
                outcome = network_transport_outcome(exc).to_outcome()
            else:
                outcome = failed(f"任务方式 {method_id} 执行异常：{type(exc).__name__}: {exc}")

        outcome = await _verification(ctx, template, plan, outcome)
        outcome = await _confirm(ctx, template, plan, outcome)

        if outcome.ok:
            return outcome, Discovery(stage="execute", value=method_id, source="probe")
        if stage_plan.locked or not _retry_other_method(outcome):
            return outcome, None
        ctx.log(f"任务方式 {method_id} 未完成（{outcome.reason or outcome.verdict}），尝试下一候选")
        last = outcome

    return last or failed("没有可用的任务方式", reason="need_config"), None


async def _verification(ctx: TaskContext, template: Any, plan: FlowPlan, outcome: Outcome) -> Outcome:
    """需要人机验证时，交给模板的 ``verify`` 钩子再试一次。

    引擎自己不会「盲目重放提交」：它不知道这个站点把验证结果放在请求的哪个字段里，
    猜错只会白白消耗一次可作答的挑战。模板知道，所以钩子在模板侧。
    """
    if outcome.reason != "need_verification" or not plan.enabled("verification"):
        return outcome
    hook = template.hook("verify") if hasattr(template, "hook") else None
    if hook is None:
        return outcome
    ctx.stage = "verification"
    ctx.evidence.stage("verification:retry")
    try:
        retried = await hook(ctx, outcome)
    except TaskError as exc:
        return exc.to_outcome()
    except Exception as exc:  # noqa: BLE001
        ctx.log(f"验证重试异常：{type(exc).__name__}: {exc}")
        return outcome
    return retried if isinstance(retried, Outcome) else outcome


async def _confirm(ctx: TaskContext, template: Any, plan: FlowPlan, outcome: Outcome) -> Outcome:
    """结果未确认时的交叉验证。模板未提供钩子就保持「未确认」——不猜。"""
    if outcome.reason != "unconfirmed" or not plan.enabled("confirm"):
        return outcome
    hook = template.hook("confirm") if hasattr(template, "hook") else None
    if hook is None:
        return outcome
    ctx.stage = "confirm"
    ctx.evidence.stage("confirm")
    try:
        confirmed = await hook(ctx, outcome)
    except TaskError as exc:
        return exc.to_outcome()
    except Exception as exc:  # noqa: BLE001
        ctx.log(f"交叉验证异常：{type(exc).__name__}: {exc}")
        return outcome
    return confirmed if isinstance(confirmed, Outcome) else outcome


# ── 访问链 ──────────────────────────────────────────────────────────────────
async def _run_chain(
    spec: AccountSpec,
    holder: dict[str, Any],
    task: TaskSpec,
    template: Any,
    plan: FlowPlan,
    ctx: TaskContext,
    *,
    overlay: Overlay,
    caps: frozenset[str],
    browser: BrowserService | None,
    emit: Any,
    oauth_state: Any,
) -> TaskRecord:
    """按访问链逐步执行：某一步成功即止，失败才回退到下一步。

    一个任务仍只产出一条记录：每一步的明细进 ``data.chain.steps``，实际完成任务的
    步骤记在 ``data.chain.hit``，``flow.chain`` 是一行摘要。访问链不写学习结论——
    执行顺序就是用户看到的顺序，不会被上次的结果悄悄改写。
    """
    resolved = chain_module.resolve(task.chain, template.manifest)
    _validate_chain(resolved, template.manifest, task)
    order = resolved.order()
    ctx.stage = "chain"
    source = "模板默认" if resolved.source == chain_module.USE_TEMPLATE else "自定义"
    ctx.log(f"访问链（{source}）：{resolved.describe()}")

    entries: list[dict[str, Any]] = []
    final: Outcome | None = None
    final_status = ""
    hit = ""
    last_failure: Outcome | None = None
    unavailable: list[str] = []
    for index, step in enumerate(order, start=1):
        if ctx.clock.expired():
            final = failed("任务时间预算已耗尽，停止访问链", reason="timeout")
            final_status = "failed"
            break
        position = f"{index}/{len(order)}"
        ctx.stage = "chain"
        ctx.log(f"步骤 {position}「{step.label}」开始", step=step.id, kind=step.kind, status="running")
        started = time.perf_counter()
        outcome, attempts, status = await _run_step(
            step, spec=spec, holder=holder, task=task, template=template, plan=plan, base=ctx,
            overlay=overlay, caps=caps, browser=browser, emit=emit, oauth_state=oauth_state,
        )
        entry: dict[str, Any] = {
            "id": step.id,
            "kind": step.kind,
            "title": step.label,
            "status": status,
            "verdict": str(outcome.verdict),
            "reason": outcome.reason,
            "message": outcome.message,
            "duration_seconds": round(time.perf_counter() - started, 3),
        }
        if attempts:
            entry["login"] = attempts
        entries.append(entry)
        ctx.stage = "chain"
        detail = f"：{outcome.message}" if outcome.message else ""
        ctx.log(
            f"步骤 {position}「{step.label}」{chain_module.STATUS_TEXT.get(status, status)}{detail}",
            step=step.id, kind=step.kind, status=status, reason=outcome.reason,
        )
        final, final_status = outcome, status
        if status == "unavailable":
            unavailable.append(f"「{step.label}」不可用：{outcome.message}")
        elif not outcome.ok:
            last_failure = outcome
        if outcome.ok:
            hit = step.id
            break
        if not chain_module.should_fallback(step, outcome):
            break
        if index < len(order):
            ctx.log(f"「{step.label}」未完成（{outcome.reason or outcome.verdict}），回退到「{order[index].label}」")

    # 没轮到的步骤（含从入口走不到的）也列出来：结果详情与编辑器要看得到整条链。
    listed = {item["id"] for item in entries}
    for step in (*order, *resolved.steps):
        if step.id not in listed:
            listed.add(step.id)
            entries.append({"id": step.id, "kind": step.kind, "title": step.label, "status": "not_run"})

    if final is None:
        final = failed("访问链没有可执行的步骤", reason="need_config")
    elif final_status == "unavailable" and last_failure is not None:
        # 回退步骤根本没法执行时，用户要处理的是前一步的失败；不可用的原因附在后面。
        note = "；".join(unavailable)
        final = last_failure.with_message(f"{last_failure.message}（{note}）" if last_failure.message else note)
    summary = chain_module.summarize(entries)
    final = chain_module.strip_control(final).with_data(
        chain={"source": resolved.source, "hit": hit, "summary": summary, "steps": entries}
    )
    ctx.stage = "chain"
    ctx.log(f"访问链结果：{summary}")
    return _record(spec, task, template, plan, final, ctx, flow={"chain": summary})


async def _run_step(
    step: chain_module.ChainStep,
    *,
    spec: AccountSpec,
    holder: dict[str, Any],
    task: TaskSpec,
    template: Any,
    plan: FlowPlan,
    base: TaskContext,
    overlay: Overlay,
    caps: frozenset[str],
    browser: BrowserService | None,
    emit: Any,
    oauth_state: Any,
) -> tuple[Outcome, list[str], str]:
    """把准备、登录、执行和收尾都收敛到本步骤，超时也保留已有尝试明细。"""
    clock = _step_clock(base.clock, step)
    attempts: list[str] = []
    with event_scope(step=step.id, kind=step.kind, status="running", reason=""):
        try:
            _check_chain_clock(clock)
            async with asyncio.timeout(clock.remaining()):
                outcome, _, status = await _attempt_step(
                    step, spec=spec, holder=holder, task=task, template=template, plan=plan, base=base,
                    overlay=overlay, caps=caps, browser=browser, emit=emit, oauth_state=oauth_state,
                    clock=clock, attempts=attempts,
                )
        except TimeoutError:
            outcome = failed(f"「{step.label}」时间预算已耗尽", reason="timeout")
            status = "failed"
        except TaskError as exc:
            outcome, status = exc.to_outcome(), "failed"
        except Exception as exc:  # noqa: BLE001 - 登录/上下文准备异常也必须留下步骤结果
            if is_driver_crash(exc):
                outcome = crash_outcome(exc).to_outcome()
            elif is_network_transport_crash(exc):
                outcome = network_transport_outcome(exc).to_outcome()
            else:
                outcome = failed(f"「{step.label}」执行异常：{type(exc).__name__}: {exc}")
            status = "failed"
    if base.clock.expired() and not outcome.ok:
        outcome = chain_module.final(outcome)
    return outcome, attempts, status


async def _attempt_step(
    step: chain_module.ChainStep,
    *,
    spec: AccountSpec,
    holder: dict[str, Any],
    task: TaskSpec,
    template: Any,
    plan: FlowPlan,
    base: TaskContext,
    overlay: Overlay,
    caps: frozenset[str],
    browser: BrowserService | None,
    emit: Any,
    oauth_state: Any,
    clock: Deadline,
    attempts: list[str],
) -> tuple[Outcome, list[str], str]:
    """执行访问链的一步：准备凭据或会话 → 调模板钩子 → 验证重试与交叉确认。

    返回 (结论, 登录尝试记录, 步骤状态)。每一步用独立的 HTTP 客户端与时间预算，
    前一步被服务端拒掉的认证头不会带进下一步。
    """
    manifest = template.manifest
    if step.kind == "browser" and (browser is None or "browser" not in caps):
        reason = caps_module.missing_reason({"browser"})
        return failed(f"本次运行不能启动浏览器：{reason}", reason="need_config"), [], "unavailable"
    hook = template.hook(step.hook) if hasattr(template, "hook") else None
    if hook is None and step.kind != "http":
        message = f"模板 {manifest.id} 没有实现 {step.hook}(ctx)，无法执行「{step.label}」"
        return failed(message, reason="need_config"), [], "unavailable"
    try:
        args = _chain_args(manifest, task, step)
    except ConfigError as exc:
        return exc.to_outcome(), [], "failed"

    account: ResolvedAccount = holder["account"]
    http = _make_http(account, log=lambda message: emit("http", message))
    step_ctx = TaskContext(
        account=AccountView.of(account, task),
        args=args,
        flow=plan,
        http=http,
        store=base.store,
        capabilities=caps,
        evidence=base.evidence,
        clock=clock,
        browser_service=browser,
        stage="login",
        emit=base.emit,
    )
    step_ctx.evidence.stage(f"chain:{step.id}")
    login_ctx = _login_context(account, template, http, browser, caps, emit, oauth_state, step_ctx)

    sources = _step_login(manifest, step)
    _check_chain_clock(clock)
    if sources:
        login_plan = StagePlan(stage="login", mode=StageMode.CHAIN, candidates=sources, source="chain")
        result = await LOGINS.establish(
            login_ctx, login_plan, on_credentials=_credential_writer(spec, holder, overlay)
        )
        attempts.extend(item.describe() for item in result.attempts)
        if result.state is not None:

            def renewal(items: tuple[Any, ...]) -> None:
                # 请求中途 AT 被拒 → 在本步骤的来源里续期（如 RT 刷新）：写进步骤明细，
                # 否则步骤里只看得到「access_token=成功」，看不出实际是续期后才签上的。
                attempts.extend(f"续期：{item.describe()}" for item in items)

            _apply_login(
                step_ctx, login_ctx, result.state, login_plan, spec, holder, overlay, on_renewal=renewal,
            )
        elif result.outcome is not None and result.outcome.reason == "blocked":
            # 出口 IP 被站点安全规则拒绝：页面流程同样过不去，换哪一步都没用。
            return chain_module.final(result.outcome), attempts, "failed"
        elif not step.page_login:
            return result.outcome or failed("没有可用的登录方式", reason="need_config"), attempts, "failed"
    if step.page_login and step_ctx.login_handle is None:
        attempts.append(f"{chain_module.BROWSER_PAGE_LOGIN}=由页面流程在需要时账密登录")

    _check_chain_clock(clock)
    step_ctx.stage = "execute"
    try:
        if hook is not None:
            outcome = await hook(step_ctx)
            if not isinstance(outcome, Outcome):
                raise ConfigError(
                    f"模板 {manifest.id} 的 {step.hook}() 必须返回 Outcome，实际返回 {type(outcome).__name__}"
                )
        else:
            outcome = await TASKS.find("http_api").run(step_ctx, template)
    except TaskError as exc:
        outcome = exc.to_outcome()
    except Exception as exc:  # noqa: BLE001 - 步骤内任何异常都要收敛成该步的结论
        if is_driver_crash(exc):
            outcome = crash_outcome(exc).to_outcome()
        elif is_network_transport_crash(exc):
            outcome = network_transport_outcome(exc).to_outcome()
        else:
            outcome = failed(f"「{step.label}」执行异常：{type(exc).__name__}: {exc}")

    was_final = chain_module.is_final(outcome)
    if outcome.reason == "need_verification" and plan.enabled("verification"):
        _check_chain_clock(clock)
    outcome = await _verification(step_ctx, template, plan, outcome)
    if outcome.reason == "unconfirmed" and plan.enabled("confirm"):
        _check_chain_clock(clock)
    outcome = await _confirm(step_ctx, template, plan, outcome)
    if was_final and not outcome.ok and not chain_module.is_final(outcome):
        outcome = chain_module.final(outcome)
    return outcome, attempts, _step_status(outcome)


def _step_login(manifest: Any, step: chain_module.ChainStep) -> tuple[str, ...]:
    """步骤里由登录方式注册表处理的来源。

    没写 ``login`` 时取模板声明的登录方式（按优先级）：http 步骤取不需要浏览器的
    （token / refresh / 账密），浏览器步骤取需要浏览器的（登录态快照 / OAuth）。
    浏览器步骤的 ``password`` 由页面流程自己完成，不在这里，且只在显式列出时启用。
    """
    wants_browser = step.kind == "browser"
    options = {option.method: option for option in manifest.login}
    sources = step.session_sources if wants_browser else step.login
    if not step.login:
        sources = tuple(option.method for option in sorted(manifest.login, key=lambda item: (item.priority, item.method)))
    methods: list[str] = []
    for method in sources:
        registered = LOGINS.get(method)
        if registered is None:
            raise ConfigError(f"步骤 {step.id} 的 login 包含未知登录方式 {method!r}")
        option = options.get(method)
        requires = set(getattr(option, "requires", ()) or ()) | set(getattr(registered, "requires", ()) or ())
        if ("browser" in requires) is wants_browser:
            methods.append(method)
        elif step.login:
            raise ConfigError(f"步骤 {step.id} 的 login 来源 {method!r} 不适用于 {step.kind} 步骤")
    return tuple(methods)


def _validate_chain(resolved: chain_module.ResolvedChain, manifest: Any, task: TaskSpec) -> None:
    """先检查整条链的候选与参数，再允许任何节点产生外部副作用。"""
    for step in resolved.steps:
        _step_login(manifest, step)
        _chain_args(manifest, task, step)


def _check_chain_clock(clock: Deadline) -> None:
    if clock.expired():
        raise TimeoutError("访问链时间预算已耗尽")


def _chain_args(manifest: Any, task: TaskSpec, step: chain_module.ChainStep) -> Mapping[str, Any]:
    """步骤参数 = 模板全部任务方式的参数声明 + 任务 args + 步骤 args（步骤优先）。

    浏览器步骤额外给出 ``login_fallback``：登录来源里没有 ``password`` 时，页面流程
    遇到登录页不再自行账密登录（与 Sub2API 页面流程的既有开关同名）。
    """
    schema = manifest.args
    for option in manifest.task:
        schema = schema.merge(option.args)
    values = {**dict(task.args or {}), **dict(step.args or {})}
    if step.kind == "browser":
        values["login_fallback"] = values.get("login_fallback", True) if step.page_login else False
    return schema.resolve(values, label=f"任务 {task.id} 步骤 {step.id} 的")


def _step_clock(clock: Deadline, step: chain_module.ChainStep) -> Deadline:
    """步骤预算：步骤自己的 timeout 与任务剩余时间取小者。"""
    return clock.child(step.timeout)


def _step_status(outcome: Outcome) -> str:
    if outcome.verdict is Verdict.SUCCESS:
        return "success"
    if outcome.verdict is Verdict.ALREADY_DONE:
        return "already_done"
    if outcome.verdict is Verdict.NO_EFFECT:
        return "no_effect"
    return "failed"


def explain_chain(task: TaskSpec, template: Any, caps: frozenset[str], account: ResolvedAccount | None = None) -> dict[str, Any]:
    """不执行，只说明访问链会怎么跑。CLI ``--explain`` 与 GUI 流程预览共用。"""
    manifest = template.manifest
    resolved = chain_module.resolve(task.chain, manifest)
    _validate_chain(resolved, manifest, task)
    steps: list[dict[str, Any]] = []
    for index, step in enumerate(resolved.order(), start=1):
        nxt = resolved.next_of(step)
        login = list(_step_login(manifest, step))
        if step.page_login:
            login.append(chain_module.BROWSER_PAGE_LOGIN)
        notes: list[str] = []
        if step.kind == "browser" and "browser" not in caps:
            notes.append("本次不能启动浏览器：" + caps_module.missing_reason({"browser"}))
        if step.kind == "browser" and not template.hook(step.hook):
            notes.append(f"模板没有实现 {step.hook}(ctx)")
        steps.append(
            {
                **chain_module.step_payload(step),
                "order": index,
                "title": step.label,
                "login": login,
                "on_failure_next": nxt.id if nxt is not None else "",
                "notes": notes,
            }
        )
    payload: dict[str, Any] = {
        "source": resolved.source,
        "describe": resolved.describe(),
        "steps": steps,
        "unreachable": list(resolved.unreachable()),
    }
    if account is not None:
        # 只列字段名，不含任何凭据内容。
        payload["credentials_present"] = sorted(account.credentials.nonempty())
    return payload


# ── 组装 ────────────────────────────────────────────────────────────────────
def _make_http(account: ResolvedAccount, *, log: Any) -> HttpClient:
    network = account.network
    return HttpClient(
        base_url=account.base_url,
        config=HttpConfig.from_settings(proxy=network.proxy, verify_ssl=network.verify_ssl),
        tag=account.name,
        log=log,
    )


def _make_browser(
    account: ResolvedAccount, overlay: Overlay, spec: AccountSpec, *, log: Any
) -> BrowserService:
    policy = account.policy

    def persist(session: PersistedSession) -> None:
        overlay.record_credentials(
            spec,
            origin="browser",
            browser_state=session.state_text,
            access_token=session.access_token,
            refresh_token=session.refresh_token,
        )

    return BrowserService(
        base_url=account.base_url,
        proxy=account.network.proxy,
        headless=policy.headless,
        humanize=policy.humanize,
        log=log,
        persist=persist,
    )


def _login_context(
    account: ResolvedAccount,
    template: Any,
    http: HttpClient,
    browser: BrowserService | None,
    caps: frozenset[str],
    emit: Any,
    oauth_state: Any,
    ctx: TaskContext,
) -> LoginContext:
    return LoginContext(
        account=account,
        template=template,
        http=http,
        browser=browser,
        capabilities=caps,
        oauth_state=oauth_state or (lambda provider, name: ""),
        log=lambda message: emit("login", message),
        deadline=ctx.clock,
    )


def _credential_writer(spec: AccountSpec, holder: dict[str, Any], overlay: Overlay):
    """登录方式产出新凭据时：写覆盖层 + 更新内存视图（供后续任务复用）。"""

    def _write(credentials: Mapping[str, str], origin: str) -> None:
        overlay.record_credentials(spec, origin=origin, **dict(credentials))
        account: ResolvedAccount = holder["account"]
        holder["account"] = account.with_credentials(**dict(credentials))

    return _write


def _apply_login(
    ctx: TaskContext,
    login_ctx: LoginContext,
    state: Any,
    login_plan: StagePlan,
    spec: AccountSpec,
    holder: dict[str, Any],
    overlay: Overlay,
    *,
    on_renewal: Any = None,
) -> None:
    """把登录结果注入本次任务的 HTTP 客户端，并装上一次性续期钩子。

    续期只在 ``login_plan`` 的候选里找（排除刚被拒的当前方式）：访问链的 HTTP 步骤
    因此只会在它自己列出的凭据来源之间续期，例如 AT 失效后用 RT 刷新。
    ``on_renewal`` 收到续期的逐个尝试记录，访问链用它把续期写进步骤明细。
    """
    fresh = ctx.http.with_auth(extra=state.headers)
    if state.cookie_jar is not None:
        fresh.cookie_jar = state.cookie_jar
    ctx.http.adopt(fresh)
    ctx.http.reset_auth_renewal()

    writer = _credential_writer(spec, holder, overlay)

    def refresher(exc: TaskError) -> HttpClient | None:
        renewed = LOGINS.renew_sync(
            login_ctx, login_plan, current=state.method, on_credentials=writer, on_attempts=on_renewal,
        )
        if renewed is None:
            return None
        return ctx.http.with_auth(extra=renewed.headers)

    ctx.http.auth_refresher = refresher
    ctx.login_handle = _LoginHandle(state, refresher)


@dataclass
class _LoginHandle:
    """暴露给脚本的登录能力（只读 + 一次续期）。"""

    state: Any
    refresher: Any

    @property
    def method(self) -> str:
        return str(getattr(self.state, "method", ""))

    def describe(self) -> str:
        note = str(getattr(self.state, "note", "") or "")
        return f"{self.method}（{note}）" if note else self.method

    async def renew(self) -> bool:
        return self.refresher(TaskError("脚本请求续期")) is not None


async def _resolve_template(
    spec: AccountSpec, task: TaskSpec, http: HttpClient, overlay: Overlay, emit: Any
) -> Any:
    """解析模板引用；``auto`` 时按站点指纹探测，并把结论写回覆盖层复用。"""
    reference = str(spec.task_template(task) or "").strip()
    if reference and reference.lower() != AUTO:
        return templates.get(reference)

    entry = overlay.entry(spec.id)
    learned = entry.flow_discoveries().get("template")
    if learned is not None and learned.is_fresh() and entry.failure_streak < 2:
        emit("detect", f"沿用上次探测到的模板：{learned.value}")
        try:
            return templates.get(learned.value)
        except Exception:
            emit("detect", f"上次探测到的模板 {learned.value} 已不可用，重新探测")

    candidates = [templates.get(item) for item in templates.ids()]
    chosen, scores = await probe.detect_template(
        http, candidates, log=lambda message: emit("detect", message)
    )
    if chosen is None:
        detail = "；".join(item.describe() for item in scores) or "没有任何模板声明了指纹"
        raise ConfigError(
            f"未能自动识别站点类型（{detail}）。请在账号配置里显式指定 template。"
        )
    overlay.record_flow(spec.id, [probe.template_discovery(scores[0])])
    return chosen


def _flow_config(spec: AccountSpec, task: TaskSpec) -> dict[str, Any]:
    """账号级 flow ← 任务级 flow ← 显式的 login.method / task.method。

    显式方法最高：用户在 ``task.method`` 里写死了就是写死了，不该被 flow 的 auto 覆盖。
    """
    config: dict[str, Any] = {str(k).lower(): v for k, v in (spec.flow or {}).items()}
    config.update({str(k).lower(): v for k, v in (task.flow or {}).items()})
    if spec.login.method and "login" not in config:
        config["login"] = spec.login.method
    if spec.login.method and spec.login.fallback:
        config["login"] = [spec.login.method] + [
            item.method for item in spec.login.fallback if item.method
        ]
    if task.method:
        config["execute"] = task.method
    return config


def _resolve_args(manifest: Any, task: TaskSpec, plan: FlowPlan) -> Mapping[str, Any]:
    """任务参数 = 模板级 args schema + 选中任务方式的 args schema。"""
    schema = manifest.args
    method = plan.get("execute").primary or (manifest.task_order() or ("http_api",))[0]
    option = manifest.task_option(method)
    if option is not None:
        schema = schema.merge(option.args)
    return schema.resolve(task.args, label=f"任务 {task.id} 的")


def _record(
    spec: AccountSpec,
    task: TaskSpec,
    template: Any,
    plan: FlowPlan,
    outcome: Outcome,
    ctx: TaskContext,
    *,
    flow: Mapping[str, str] | None = None,
) -> TaskRecord:
    """收尾：模板 render → 证据合并 → 当前数值并入消息 → 组装记录。"""
    hook = template.hook("render") if hasattr(template, "hook") else None
    if hook is not None:
        try:
            spec_display = hook(outcome)
        except Exception:
            spec_display = None
        if isinstance(spec_display, DisplaySpec):
            # 模板 render 在结论自带 display 之下：脚本要改就该改得动。
            outcome = replace(outcome, display=spec_display.merge(outcome.display))
    if not ctx.evidence.value.is_empty():
        outcome = outcome.with_evidence(ctx.evidence.value)
    defaults = _display_defaults(spec, task, template)
    outcome = _with_current_balance(outcome, defaults)
    return TaskRecord(
        account_id=spec.id,
        task_id=task.id,
        name=task.title or spec.name,
        base_url=spec.base_url,
        outcome=outcome,
        template=template.manifest.id,
        flow=MappingProxyType(dict(flow) if flow is not None else plan.to_payload()),
        display_defaults=defaults,
        )


def _with_current_balance(outcome: Outcome, defaults: DisplaySpec) -> Outcome:
    """把「当前额度」并入成功 / 今日已完成的消息文本。

    消息此前只说「获得多少」，账上还剩多少只出现在汇总表的自定义文本列里——而通知、
    CI 摘要与结果文件的 ``message`` 在很多场景下是唯一被读到的那一行，看不到余额。

    取值用**已渲染的展示文本**，而不是 ``data`` 里的某个键：展示文本正是汇总表那一列
    的内容，已按各模板自己的 unit 格式化好（newapi 的 ``quota`` 是站点原始单位，
    1_250_000 = $2.50，打原值会显示成「当前额度 1250000」）。这样两处永远一致，
    也不必在这里维护一张「各站余额字段叫什么」的清单。

    唯一的例外要挡掉：少数站点的自定义文本列放的是**本次获得**而不是账户余额
    （实测 Fengwind 的「积分」列就是当天签到所得）。此时它与「获得」附加项同值，
    照搬会把「今天得了 1.6」谎报成「账上还有 1.6」，因此同值时什么都不加——
    宁可少说一句，不可报错数。
    """
    if outcome.verdict not in (Verdict.SUCCESS, Verdict.ALREADY_DONE):
        return outcome
    view = outcome.rendered(defaults=defaults)
    text = str(view.text or "").strip()
    if not text:
        return outcome
    # 自定义文本列其实是「本次获得」时不追加（见上文 Fengwind）。
    if any(str(value or "").strip() == text for key, value in view.extras if str(key).strip() == "获得"):
        return outcome
    label = str(view.text_label or "").strip() or "额度"
    message = str(outcome.message or "").strip()
    # 幂等：模板自己已经写过当前值时不再追加第二遍。
    if f"当前{label}" in message:
        return outcome
    suffix = f"（当前{label} {text}）"
    return outcome.with_message(f"{message}{suffix}" if message else f"当前{label} {text}")


def _display_defaults(spec: AccountSpec, task: TaskSpec, template: Any) -> DisplaySpec:
    display = template.manifest.display
    return DisplaySpec(
        label=display.label,
        icon=display.icon,
        text_label=(
            task.text_label
            or str((spec.display or {}).get("text_label") or "")
            or display.text_label
        ),
    )


def _stub_record(spec: AccountSpec, task: TaskSpec, outcome: Outcome) -> TaskRecord:
    return TaskRecord(
        account_id=spec.id,
        task_id=task.id,
        name=task.title or spec.name,
        base_url=spec.base_url,
        outcome=outcome,
        template=str(spec.task_template(task) or ""),
    )


def _apply_policy(spec: AccountSpec, task: TaskSpec, record: TaskRecord) -> TaskRecord:
    """``tolerate_failure``：把失败改判为「无影响/已豁免」，原结论留在 data 里。

    旧实现是在汇总阶段打一个标记、同时保持 ok=False，于是「不计失败」和「当天不再
    重试」两个语义纠缠在一起，判定处处要写特例。
    """
    policy = spec.task_policy(task)
    if policy.tolerate_failure and not record.outcome.ok:
        return replace(record, outcome=record.outcome.tolerated())
    return record


# ── 任务顺序 ────────────────────────────────────────────────────────────────
def _ordered_tasks(spec: AccountSpec, only: Sequence[str]) -> list[TaskSpec]:
    tasks = list(spec.enabled_tasks())
    if not tasks:
        # 没有显式任务清单时给一个默认任务：一个账号至少有一件事要做。
        tasks = [TaskSpec(id="daily")]
    if only:
        wanted = {str(item).strip() for item in only if str(item).strip()}
        tasks = [item for item in tasks if item.id in wanted]
    return _topological(tasks)


def _topological(tasks: list[TaskSpec]) -> list[TaskSpec]:
    """按 depends_on 排序。成环即配置错误——静默忽略只会让用户困惑于执行顺序。"""
    by_id = {item.id: item for item in tasks}
    ordered: list[TaskSpec] = []
    visiting: set[str] = set()
    done: set[str] = set()

    def visit(item: TaskSpec, trail: tuple[str, ...]) -> None:
        if item.id in done:
            return
        if item.id in visiting:
            raise ConfigError(f"任务依赖成环：{' → '.join((*trail, item.id))}")
        visiting.add(item.id)
        for dep in item.depends_on:
            parent = by_id.get(dep)
            if parent is not None:
                visit(parent, (*trail, item.id))
        visiting.discard(item.id)
        done.add(item.id)
        ordered.append(item)

    for item in tasks:
        visit(item, ())
    return ordered


def _blocked_by(task: TaskSpec, records: list[TaskRecord]) -> str:
    """前置任务是否未完成。只看已执行过的记录，缺失的依赖视为「没这个任务」。"""
    finished = {record.task_id: record for record in records}
    for dep in task.depends_on:
        record = finished.get(dep)
        if record is not None and not record.ok:
            return dep
    return ""


def _retry_other_method(outcome: Outcome) -> bool:
    """这次失败换个任务方式还有没有意义。

    「方式不适用」（端点不存在、缺能力）值得换；「方式适用但被拒」（需验证、被封、
    账号问题）不值得——换一条路只会多花几十秒再失败一次，还会掩盖真正的原因。
    """
    if outcome.verdict is not Verdict.FAILED:
        return False
    return outcome.reason in {"", "need_config", "unconfirmed"}


# 供 apps 层做「本次运行涉及哪些阶段」的展示。
ENGINE_STAGES = tuple(STAGES)
