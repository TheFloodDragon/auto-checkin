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
from urllib.parse import urlsplit

from browser.service import (
    BrowserService,
    PersistedSession,
    decode_state,
    crash_outcome,
    is_driver_crash,
    is_network_transport_crash,
    network_transport_outcome,
)
from config.overlay import TTL_DEFAULTS, OAuthStateResolution, Overlay, _hash as _oauth_hash
from config.proxies import ProxyGroup, resolve_proxy
from config.schema import OAuthStateReader
from core import chain as chain_module
from core.account import AccountSpec, ResolvedAccount, TaskSpec
from core.errors import ConfigError, TaskError
from core.flow import AUTO, Discovery, FlowPlan, StageMode, StagePlan
from core.manifest import STAGES
from core.outcome import DisplaySpec, Outcome, Verdict, failed, no_effect
from core.timebase import business_date
from login import LOGINS
from login.base import OAuthStateUpdate
from login.base import LoginContext
from net.http import HttpClient, HttpConfig
from sdk.context import AccountView, EvidenceCollector, TaskContext
from sdk.store import Store
from task import TASKS
from task.base import hook_owns_execute
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
    oauth_renew_hours: float | None = None,
    oauth_force_verify: bool = False,
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
    emit("network", selection.description)
    bridge = None
    proxy_url = selection.url
    if selection.requires_bridge:
        # vless / anytls 等协议由本机 mihomo 桥接；启动失败按配置/瞬时错误收敛，绝不改用直连。
        bridge = _bridge_factory(selection.bridge, log=lambda m: emit("network", m))
        try:
            proxy_url = await asyncio.to_thread(bridge.start)
        except TaskError as exc:
            await asyncio.to_thread(bridge.close)
            tasks = [task for task in spec.enabled_tasks() if not only_tasks or task.id in only_tasks]
            return AccountRun(spec.id, spec.name, spec.base_url,
                              tuple(_stub_record(spec, task, exc.to_outcome()) for task in tasks))
        except BaseException:
            await asyncio.to_thread(bridge.close)
            raise
    try:
        await _keepalive_shared(
            spec, overlay, oauth_state, proxy_url, emit,
            renew_hours=oauth_renew_hours, force_verify=oauth_force_verify,
        )
        return await _run_tasks(
            spec, account, proxy_url,
            overlay=overlay, only_tasks=only_tasks, emit=emit, oauth_state=oauth_state,
        )
    finally:
        if bridge is not None:
            # 浏览器在 _run_tasks 内先关闭；桥最后关，避免浏览器收尾请求撞上已关闭的端口。
            await asyncio.to_thread(bridge.close)


async def _keepalive_shared(
    spec: AccountSpec, overlay: Overlay, oauth_state: Any, proxy_url: str, emit: Any,
    *, renew_hours: float | None = None, force_verify: bool = False,
) -> None:
    """单账号 CLI / GUI 使用与批量相同的共享会话保活规则；父进程已做过则跳过。"""
    if oauth_state is None:
        return
    from runtime import keepalive

    if keepalive.skip_in_child():
        return
    try:
        references = keepalive.references_oauth(spec)
        # 代理已在 run_account 中解析/桥接，不能在保活时换出口或再次启动桥。
        network = replace(
            spec.network, proxy=proxy_url, proxy_group="", proxy_mode="custom" if proxy_url else "direct",
        )
        await keepalive.preflight(
            references, overlay=overlay, oauth_state=oauth_state, network=network,
            window_seconds=keepalive.renew_window_seconds(renew_hours), force_verify=force_verify,
            log=lambda message: emit("login", message),
        )
    except Exception as exc:  # noqa: BLE001 - 保活失败绝不阻断任务
        emit("login", f"共享 OAuth 登录态保活未完成（{type(exc).__name__}），继续执行任务")


def _bridge_factory(outbound: Any, *, log: Any = None) -> Any:
    """延迟导入，便于测试替换；未使用桥接节点时不加载子进程相关代码。"""
    from net.proxy_bridge import ProxyBridge

    return ProxyBridge(outbound, log=log)


async def _run_tasks(
    spec: AccountSpec,
    account: ResolvedAccount,
    proxy_url: str,
    *,
    overlay: Overlay,
    only_tasks: Sequence[str],
    emit: Any,
    oauth_state: Any,
) -> AccountRun:
    effective = replace(spec.network, proxy=proxy_url, proxy_group="",
                        proxy_mode="custom" if proxy_url else "direct")
    account = replace(account, effective_network=effective)
    caps = caps_module.detect(account)

    browser = _make_browser(
        account, overlay, spec, log=lambda m: emit("browser", m), oauth_state=oauth_state,
    ) if "browser" in caps else None
    records: list[TaskRecord] = []
    state_holder: dict[str, Any] = {"account": account, "login": None}

    try:
        tasks = _ordered_tasks(spec, only_tasks)
    except ConfigError as exc:
        if browser is not None:
            await browser.aclose()
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
    oauth_resolve = _shared_oauth_resolver(overlay, oauth_state)
    login_ctx = _login_context(
        account, template, http, browser, caps, emit, oauth_state, ctx,
        oauth_resolve=oauth_resolve,
    )
    ctx.browser_credentials_callback = _browser_credential_writer(
        ctx, login_ctx, spec, holder, overlay, plan.get("login"),
    )

    async def relogin(provider: str = "", account: str = "") -> bool:
        from login.oauth import OAuthLogin

        login_args = {**dict(login_ctx.account.login.args or {}), **dict(ctx.args)}
        if provider:
            login_args["provider"] = provider
        if account:
            login_args["account"] = account
        fresh_ctx = replace(login_ctx, account=holder["account"], args=login_args)
        state = await OAuthLogin().relogin(fresh_ctx, evidence=ctx.evidence)
        # 前序任务可能已启动共享浏览器。退休旧上下文，避免账号收尾时把旧快照盖回去。
        if browser is not None and browser.started:
            remaining = ctx.remaining_seconds()
            try:
                await asyncio.wait_for(browser.aclose(persist=False),
                                       timeout=max(0.01, min(8.0, remaining if remaining is not None else 8.0)))
            except TimeoutError:
                ctx.log("旧浏览器关闭超时，已停止续存旧会话")
        _apply_login(ctx, fresh_ctx, state, plan.get("login"), spec, holder, overlay, replace_auth=True)
        _credential_writer(spec, holder, overlay, browser=browser)(state.credentials, state.origin)
        _record_oauth_updates(state, overlay, oauth_resolve)
        fresh_ctx.account = holder["account"]
        ctx.evidence.stage("login:relogin_oauth")
        return True

    async def recover_login() -> bool:
        """只恢复已被服务端拒绝的认证；调用方负责仅重试安全的原请求。"""
        if ctx.expired():
            raise TaskError("登录恢复时间预算已耗尽", reason="timeout")
        previous = getattr(ctx.login_handle, "state", None)
        if previous is None:
            return False
        ctx.login_handle.reject(previous)
        rejected = set(ctx.login_handle.rejected_methods)
        note = getattr(browser, "note_outcome", None)
        if callable(note):
            note(failed("用户接口已明确拒绝当前认证", reason="need_login"))
        login_ctx.account = holder["account"]
        ctx.log("用户接口已拒绝当前凭据，按配置执行一次异步登录恢复")
        result = await LOGINS.establish(
            login_ctx, plan.get("login"), exclude=rejected,
            on_credentials=_credential_writer(spec, holder, overlay, browser=browser),
        )
        if result.state is None:
            if result.outcome is not None:
                raise TaskError(result.outcome.message, reason=result.outcome.reason, data=dict(result.outcome.data))
            return False
        # 新会话安装后不再用旧 token/Cookie 的同步回退换回此前被拒的身份。
        _apply_login(ctx, login_ctx, result.state, plan.get("login"), spec, holder, overlay, replace_auth=True)
        _record_oauth_updates(result.state, overlay, oauth_resolve, browser=browser)
        if result.discovery is not None:
            discoveries.append(result.discovery)
        ctx.evidence.stage(f"login:recovered_{result.state.method}")
        return True

    ctx.login_handle = _LoginHandle(
        relogin_callback=relogin, recover_callback=recover_login if task.chain is None else None,
    )

    # ── 访问链：配置了 chain 的任务由访问链接管登录与执行方式 ──
    if task.chain is not None:
        return await _run_chain(
            spec, holder, task, template, plan, ctx,
            overlay=overlay, caps=caps, browser=browser, emit=emit, oauth_state=oauth_state,
        )
    
    # ── login ──
    if relogin_owns_login(template, plan):
        _relogin_http_baseline(ctx, login_ctx)
        ctx.evidence.stage("login:deferred_to_relogin")
        emit("login", "由 relogin 任务在隔离会话中执行新 OAuth；不恢复目标站点浏览器缓存")
    else:
        result = await LOGINS.establish(
            login_ctx, plan.get("login"), on_credentials=_credential_writer(spec, holder, overlay, browser=browser)
        )
        if result.outcome is not None:
            return _record(spec, task, template, plan, result.outcome, ctx)
        if result.state is not None:
            _apply_login(ctx, login_ctx, result.state, plan.get("login"), spec, holder, overlay)
            _record_oauth_updates(result.state, overlay, oauth_resolve, browser=browser)
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
        if ctx.browser_service is not None:
            ctx.browser_service.note_outcome(outcome)

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
        # 后续步骤可能纯 HTTP 成功，不能因此遮蔽此步骤已观察到的登录失效。
        if browser is not None:
            browser.note_outcome(outcome)
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
    oauth_resolve = _shared_oauth_resolver(overlay, oauth_state)
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
    login_ctx = _login_context(
        account, template, http, browser, caps, emit, oauth_state, step_ctx,
        oauth_resolve=oauth_resolve,
    )

    sources = _step_login(manifest, step)
    _check_chain_clock(clock)
    if sources:
        login_plan = StagePlan(stage="login", mode=StageMode.CHAIN, candidates=sources, source="chain")
        result = await LOGINS.establish(
            login_ctx, login_plan, on_credentials=_credential_writer(spec, holder, overlay, browser=browser)
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
            _record_oauth_updates(result.state, overlay, oauth_resolve, browser=browser)
        elif result.outcome is not None and result.outcome.reason == "blocked":
            # 出口 IP 被站点安全规则拒绝：页面流程同样过不去，换哪一步都没用。
            return chain_module.final(result.outcome), attempts, "failed"
        elif not step.page_login:
            return result.outcome or failed("没有可用的登录方式", reason="need_config"), attempts, "failed"
    if step.page_login and step_ctx.login_handle is None:
        attempts.append(f"{chain_module.BROWSER_PAGE_LOGIN}=由页面流程在需要时账密登录")

    _check_chain_clock(clock)
    step_ctx.browser_credentials_callback = _browser_credential_writer(
        step_ctx, login_ctx, spec, holder, overlay,
        StagePlan(stage="login", mode=StageMode.CHAIN, candidates=sources, source="chain"),
    )
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
    account: ResolvedAccount, overlay: Overlay, spec: AccountSpec, *, log: Any, oauth_state: Any = None,
) -> BrowserService:
    policy = account.policy
    explicit = tuple(name for name, origin in account.origins.items() if origin == "explicit")

    def persist(session: PersistedSession) -> bool:
        if not session.auth_verified or session.expected_revisions is None:
            return False
        return overlay.record_credentials(
            spec,
            origin="browser",
            expected_revisions=session.expected_revisions,
            browser_state=session.state_text,
            access_token=session.access_token,
            refresh_token=session.refresh_token,
        )

    def restoration_guard(state_text: str) -> dict[str, set[str]]:
        """恢复的快照里，与磁盘当前 token 不同的值都已被取代，不能再续存回去。"""
        from browser import storage_scope

        resolved, _revisions, entry = overlay.credential_snapshot(spec, explicit=explicit)
        storage = decode_state(state_text)
        snapshot = {
            "access_token": storage_scope.storage_access_token(storage, base_url=spec.base_url),
            "refresh_token": storage_scope.storage_refresh_token(storage, base_url=spec.base_url),
        }
        stale: dict[str, set[str]] = {}
        for name, value in snapshot.items():
            cached = entry.fields.get(name)
            # 未过期判定只看原始值：TTL 到期回落到配置不代表快照里的 token 更旧。
            current = cached.value if cached is not None else str(resolved.credentials.get(name) or "")
            known = cached is not None or bool(current)
            if value and known and value != current:
                stale.setdefault(name, set()).add(value)
        return stale

    return BrowserService(
        base_url=account.base_url,
        proxy=account.network.proxy,
        headless=policy.headless,
        humanize=policy.humanize,
        log=log,
        persist=persist,
        revision_reader=lambda: overlay.credential_revisions(
            spec.id, fields=("browser_state", "access_token", "refresh_token"),
        ),
        restoration_guard=restoration_guard,
        shared_writer=_shared_state_writer(overlay, oauth_state, account.base_url) if oauth_state is not None else None,
    )


def _shared_state_writer(overlay: Overlay, oauth_state: Any, base_url: str):
    """浏览器收尾时把同一会话轮换出的提供商认证值写回共享态（CAS + 谱系校验）。

    只有当前共享态的全部认证值仍属于本上下文的谱系时才写。GitHub 等提供商有多个
    认证 Cookie：仅一个值仍相同不能证明其他值未被并发轮换；任何未知的新认证值
    都说明来源已变化，绝不把旧浏览器快照覆盖回去。
    """
    from browser import oauth_providers, storage_scope
    from login.base import LoginState
    from login.oauth import oauth_state_update

    resolver = _shared_oauth_resolver(overlay, oauth_state)
    host = urlsplit(base_url).hostname or ""

    def write(provider: str, account: str, storage_state: dict[str, Any], lineage: frozenset[str]) -> bool:
        source = resolver(provider, account)
        if not source.state:
            return False
        current = storage_scope.provider_auth_values(decode_state(source.state), provider)
        if not current or not current.issubset(lineage):
            return False
        own_domain = any(
            oauth_providers.hostname_matches_domain(host, domain)
            for domain in oauth_providers.get_oauth_provider(provider).state_domain_hints
        )
        update = oauth_state_update(
            source, storage_state, provider, base_url="" if own_domain else base_url, same_identity=True,
        )
        if update is None:
            return False
        state = LoginState(method="shared_sync", verified=True, oauth_updates=(update,))
        return _record_oauth_updates(state, overlay, resolver) > 0

    return write


#: 共享 OAuth 态认证 Cookie 无到期时间（会话 Cookie）时的缓存寿命。
OAUTH_STATE_TTL = 14 * 86400


def _oauth_config_basis(reader: Any, provider: str, account: str, *, current: bool = False) -> tuple[str, str]:
    if isinstance(reader, (OAuthStateReader, _SharedOAuthResolver)):
        result = reader.basis(provider, account, current=current)
        if isinstance(result, tuple) and len(result) == 2:
            configured, digest = result
            if isinstance(configured, str) and isinstance(digest, str):
                return configured.strip(), digest.strip() or _oauth_hash(configured)
        raise TypeError("OAuthStateReader.basis 返回值无效")
    configured = str(reader(provider, account) or "").strip() if callable(reader) else ""
    return configured, _oauth_hash(configured)


class _SharedOAuthResolver:
    """一次运行内缓存原配置快照；可选 basis() 才重新读取外部配置。"""

    def __init__(self, overlay: Overlay, configured_reader: Any) -> None:
        self.overlay = overlay
        self.reader = configured_reader
        self.cache: dict[tuple[str, str], tuple[str, str]] = {}

    def __call__(self, provider: str, account: str) -> OAuthStateResolution:
        key = (str(provider or "").strip().lower(), str(account or "default").strip() or "default")
        if key not in self.cache:
            self.cache[key] = _oauth_config_basis(self.reader, *key)
        configured, basis = self.cache[key]
        resolved = self.overlay.resolve_oauth_state(key[0], key[1], configured, config_hash=basis)
        if isinstance(self.reader, OAuthStateReader) and self.reader.path is not None:
            try:
                unchanged = self.reader.basis(*key, current=True) == (configured, basis)
            except Exception:
                unchanged = False
            if not unchanged:
                # 冻结草稿可以继续用其显式配置，但不能用缓存覆盖新捕获或删除。
                return replace(resolved, state=configured, from_overlay=False)
        return resolved

    def basis(self, provider: str, account: str, *, current: bool = False) -> tuple[str, str]:
        key = (str(provider or "").strip().lower(), str(account or "default").strip() or "default")
        if current and isinstance(self.reader, OAuthStateReader):
            return _oauth_config_basis(self.reader, *key, current=True)
        if key not in self.cache:
            self.cache[key] = _oauth_config_basis(self.reader, *key)
        return self.cache[key]


def _shared_oauth_resolver(overlay: Overlay, configured_reader: Any):
    """统一读取 provider/account 共享态，并保留一次 CAS 写回来源。"""
    return _SharedOAuthResolver(overlay, configured_reader)


def _record_oauth_updates(state: Any, overlay: Overlay, reader: Any, *, browser: Any = None) -> int:
    """新认证已安装后才发布共享续期；失败、来源不明和未轮换均不写回。返回写入条数。

    传入 ``browser`` 时，把刚写回的认证值登记为该上下文的共享谱系：之后同一会话
    继续轮换出的新值，在浏览器收尾时也能安全写回共享态（见 BrowserService）。
    """
    if getattr(state, "verified", False) is not True:
        return 0
    from browser.service import decode_state, encode_state
    from browser import storage_scope

    written = 0
    for update in getattr(state, "oauth_updates", ()):
        if not isinstance(update, OAuthStateUpdate) or not isinstance(update.source, OAuthStateResolution):
            continue
        source = update.source
        if update.fresh_authorization is not True and update.same_identity is not True:
            continue
        try:
            refreshed = storage_scope.provider_renewal_state(decode_state(update.state), source.provider)
            if not storage_scope.provider_state_rotated(decode_state(source.state), refreshed, source.provider):
                continue
            if overlay.record_oauth_state(
                source, encode_state(refreshed),
                current_config=lambda: _oauth_config_basis(reader, source.provider, source.account, current=True),
                # 共享态的寿命跟随 provider 认证 Cookie 的真实到期时间，而不是固定 14 天。
                ttl=storage_scope.provider_state_ttl(refreshed, source.provider, default=OAUTH_STATE_TTL),
            ):
                written += 1
                track = getattr(browser, "track_shared", None)
                if callable(track):
                    track(source.provider, source.account,
                          storage_scope.provider_auth_values(refreshed, source.provider))
        except Exception:
            # 写回失败不影响已确认的本轮认证，旧缓存保持不变。
            continue
    return written


def _login_context(
    account: ResolvedAccount,
    template: Any,
    http: HttpClient,
    browser: BrowserService | None,
    caps: frozenset[str],
    emit: Any,
    oauth_state: Any,
    ctx: TaskContext,
    *,
    oauth_resolve: Any = None,
) -> LoginContext:
    reader = oauth_state or (lambda provider, name: "")
    if oauth_resolve is not None:
        def reader(provider: str, name: str) -> str:
            return oauth_resolve(provider, name).state
    return LoginContext(
        account=account,
        template=template,
        http=http,
        args={**dict(account.login.args or {}), **dict(ctx.args)},
        browser=browser,
        capabilities=caps,
        oauth_state=reader,
        oauth_resolve=oauth_resolve,
        log=lambda message: emit("login", message),
        deadline=ctx.clock,
    )


@dataclass
class _CredentialWriter:
    """发布新凭据：写覆盖层、更新 holder，并告知浏览器哪些旧 token 已作废。

    显式空值写 tombstone，跨运行保持为空；浏览器来源的写入以浏览器基线做 CAS。
    """

    spec: AccountSpec
    holder: dict[str, Any]
    overlay: Overlay
    browser: Any = None

    def __call__(
        self,
        credentials: Mapping[str, str],
        origin: str,
        *,
        ttl: Mapping[str, int] | None = None,
        expected_revisions: Mapping[str, str] | None = None,
    ) -> bool:
        fields = dict(credentials)
        service = self.browser if isinstance(self.browser, BrowserService) else None
        browser_origin = service is not None and service.started and origin in {"browser", "oauth"}
        expected = service.credential_revisions if browser_origin else expected_revisions
        current = self.holder["account"].credentials
        previous = {name: current.get(name) for name in fields} if service is not None else {}
        receipt: dict[str, str] = {}
        written = False
        if not browser_origin or expected is not None:
            written = self.overlay.record_credentials(
                self.spec, origin=origin, ttl=ttl,
                clear=tuple(name for name, value in fields.items() if value == ""),
                expected_revisions=expected,
                written_revisions=receipt,
                **fields,
            )
        if service is not None:
            service.note_credentials_written(fields, receipt, previous=previous, published=browser_origin)
        self.remember(fields)
        return written

    def confirm(self, credentials: Mapping[str, str], origin: str) -> bool:
        """服务端确认仍有效、未轮换的凭据：续上覆盖层寿命（浏览器里它一直都在）。

        只在磁盘当前生效值**仍是这个值**时写，并以读到的原始版本做 CAS：另一进程
        若刚轮换过，旧值绝不能借「续期」回滚它。
        """
        fields = {name: str(value) for name, value in credentials.items() if str(value or "").strip()}
        if not fields:
            return False
        try:
            resolved, revisions, _entry = self.overlay.credential_snapshot(self.spec)
        except Exception:
            return False
        if any(resolved.credentials.get(name) != value for name, value in fields.items()):
            return False
        return self(
            fields, origin,
            expected_revisions={name: revisions[name] for name in fields if name in revisions},
        )

    def cookie_rotated(self, header: str, updates: list[Any]) -> None:
        """HTTP 响应用 ``Set-Cookie`` 续期了会话：写回生成该 Cookie 头的那个字段。"""
        from net.lifetime import cookie_pairs, cookie_ttl, render_cookie

        durable = [item for item in updates if not _volatile_cookie(getattr(item, "name", ""))]
        if not durable:
            # 只有 WAF/挑战类 Cookie 在变：它们绑定出口 IP、分钟级寿命，落盘没有意义。
            return
        sent = cookie_pairs(header)
        credentials = self.holder["account"].credentials
        for name in ("cookie", "session_cookie"):
            stored = cookie_pairs(credentials.get(name))
            if stored and set(stored) <= set(sent) and any(item.name in stored for item in durable):
                merged = {key: sent.get(key, value) for key, value in stored.items()}
                if merged == stored and not any(item.lifetime() is not None for item in durable):
                    return
                self(
                    {name: render_cookie(merged)}, "session",
                    ttl={name: cookie_ttl(durable, default=TTL_DEFAULTS[name])},
                )
                return

    def remember(self, credentials: Mapping[str, str]) -> None:
        """只更新本次运行的内存视图（未经服务端确认的浏览器凭据不落盘）。"""
        account: ResolvedAccount = self.holder["account"]
        self.holder["account"] = account.with_credentials(**dict(credentials))


#: WAF / 人机挑战类 Cookie 前缀：绑定出口 IP 与分钟级寿命，随响应频繁变化，只在内存里跟随。
_VOLATILE_COOKIE_PREFIXES = ("acw_", "cf_", "__cf", "_cf", "ssxmod_", "aliyungf_", "tfstk", "__ddg")


def _volatile_cookie(name: str) -> bool:
    return str(name or "").strip().lower().startswith(_VOLATILE_COOKIE_PREFIXES)


def _credential_writer(
    spec: AccountSpec, holder: dict[str, Any], overlay: Overlay, *, browser: BrowserService | None = None,
) -> _CredentialWriter:
    return _CredentialWriter(spec, holder, overlay, browser)


def _browser_credential_writer(
    ctx: TaskContext, login_ctx: LoginContext, spec: AccountSpec,
    holder: dict[str, Any], overlay: Overlay, login_plan: StagePlan,
):
    """浏览器已验证凭据的唯一交接点：先安装 HTTP 认证，再发布正式覆盖层及任务视图。"""
    from login.browser_state import state_to_login
    from net.http import normalize_access_token

    def accept(credentials: Mapping[str, str]) -> bool:
        if not isinstance(credentials, Mapping) or set(credentials) - {"access_token", "refresh_token"}:
            return False
        if any(not isinstance(value, str) for value in credentials.values()):
            return False
        access = normalize_access_token(credentials.get("access_token", ""))
        if not access:
            return False
        refresh = credentials.get("refresh_token", "").strip()
        service = ctx.browser_service
        # 页面 localStorage 可能仍留着已被轮换的旧 token：拒绝交接，保留当前认证。
        if isinstance(service, BrowserService) and service.superseded(
            {"access_token": access, "refresh_token": refresh}
        ):
            return False
        fresh_ctx = replace(login_ctx, account=holder["account"])
        state = state_to_login(
            fresh_ctx, method="browser_state", access=access, refresh=refresh, cookie="",
            verified=True, origin="browser", note="浏览器新会话已由服务端确认",
        )
        # 新登录没返回 RT 也要显式清除旧 RT；不能把新 AT 和已失效的旧 RT 拼成一组。
        state = replace(state, credentials={"access_token": access, "refresh_token": refresh})
        _apply_login(ctx, fresh_ctx, state, login_plan, spec, holder, overlay, replace_auth=True)
        _credential_writer(spec, holder, overlay, browser=ctx.browser_service)(state.credentials, state.origin)
        login_ctx.account = holder["account"]
        fresh_ctx.account = holder["account"]
        return True

    return accept


def relogin_owns_login(template: Any, plan: FlowPlan) -> bool:
    """执行候选已解析后，只有首选的内置 relogin 接管登录（供 explain 共用）。"""
    candidates = plan.get("execute").candidates or template.manifest.task_order() or ("http_api",)
    return candidates[0] == "relogin" and not hook_owns_execute(template, "relogin")


def _relogin_http_baseline(ctx: TaskContext, login_ctx: LoginContext) -> None:
    """仅装载现成 HTTP 凭据，供任务只读比较旧数值；不解码或恢复浏览器快照。"""
    from login._common import auth_headers, cookie_headers

    credentials = login_ctx.credentials
    baseline_ctx = replace(login_ctx, args={**dict(login_ctx.account.login.args or {}), **dict(ctx.args)})
    if credentials.access_token:
        headers = auth_headers(baseline_ctx, credentials.access_token)
    elif credentials.cookie or credentials.session_cookie:
        headers = cookie_headers(baseline_ctx, credentials.cookie or credentials.session_cookie)
    else:
        headers = baseline_ctx.base_headers()
    ctx.http.adopt(ctx.http.with_auth(extra=headers))
    ctx.http.auth_refresher = None


def _apply_login(
    ctx: TaskContext,
    login_ctx: LoginContext,
    state: Any,
    login_plan: StagePlan,
    spec: AccountSpec,
    holder: dict[str, Any],
    overlay: Overlay,
    *,
    replace_auth: bool = False,
    on_renewal: Any = None,
) -> None:
    """安装认证及一次性续期；闭包每次都读取 holder 最新的凭据，不重置续期额度。"""
    base = ctx.http
    if replace_auth:
        base = replace(base, headers={k: v for k, v in base.headers.items()
                                     if k.lower() not in {"authorization", "cookie"}},
                       cookie_jar=None, auth_refresher=None)
    fresh = base.with_auth(extra=state.headers)
    if state.cookie_jar is not None:
        fresh.cookie_jar = state.cookie_jar
    ctx.http.adopt(fresh)
    if replace_auth:
        ctx.http.cookie_jar = fresh.cookie_jar
    ctx.http.reset_auth_renewal()
    login_ctx.account = holder["account"]

    writer = _credential_writer(spec, holder, overlay, browser=ctx.browser_service)
    # 站点滚动续期的会话 Cookie 跟随写回（浏览器无条件接受 Set-Cookie）。
    ctx.http.on_cookie_rotated = writer.cookie_rotated

    def refresher(exc: TaskError) -> HttpClient | None:
        nonlocal state
        login_ctx.account = holder["account"]
        # 被拒的是请求携带的 AT/Cookie，而不是生成它的 refresh/password 方式。
        # 初次登录若已轮转过 RT，仍应允许用新 RT 刷新，但不扩大本步骤候选集合。
        auth_names = {name.lower() for name in state.headers}
        current = "access_token" if "authorization" in auth_names else (
            "cookie" if "cookie" in auth_names else state.method
        )
        proactive = bool(getattr(exc, "data", {}).get("proactive"))
        rejected = set()
        if not proactive and exc.reason == "need_login" and isinstance(ctx.login_handle, _LoginHandle):
            ctx.login_handle.reject(state)
            rejected.update(ctx.login_handle.rejected_methods)
        if state.method == "browser_state":
            rejected.add("browser_state")
        renewed = LOGINS.renew_sync(
            login_ctx, login_plan, current=current, on_credentials=writer, on_attempts=on_renewal,
            proactive=proactive, exclude=rejected,
        )
        if renewed is None:
            return None
        login_ctx.account = holder["account"]
        state = renewed
        updated = ctx.http.with_auth(extra=renewed.headers)
        if renewed.cookie_jar is not None:
            updated.cookie_jar = renewed.cookie_jar
        if isinstance(ctx.login_handle, _LoginHandle):
            ctx.login_handle.state = renewed
        return updated

    # 新 OAuth 会话不能被历史 token/refresh/cookie 的自动兜底换回旧身份。
    active_refresher = None if replace_auth else refresher
    ctx.http.auth_refresher = active_refresher
    if isinstance(ctx.login_handle, _LoginHandle):
        ctx.login_handle.state = state
        ctx.login_handle.refresher = active_refresher
    else:
        ctx.login_handle = _LoginHandle(state, active_refresher)


@dataclass
class _LoginHandle:
    """脚本只拿能力，不拿共享 OAuth 凭据或浏览器上下文。"""

    state: Any = None
    refresher: Any = None
    relogin_callback: Any = None
    recover_callback: Any = None
    recovery_attempted: bool = False
    rejected_methods: set[str] = field(default_factory=set)

    @property
    def method(self) -> str:
        return str(getattr(self.state, "method", ""))

    def describe(self) -> str:
        note = str(getattr(self.state, "note", "") or "")
        return f"{self.method}（{note}）" if note else self.method

    def reject(self, state: Any) -> None:
        """记住已被服务端拒绝的静态来源，不能在同步回退换 state 后重新选择它。"""
        if self.recover_callback is None or state is None:
            return
        if state.method in {"browser_state", "access_token", "cookie"}:
            self.rejected_methods.add(state.method)
        auth_names = {name.lower() for name in state.headers}
        if "authorization" in auth_names:
            self.rejected_methods.add("access_token")
        if "cookie" in auth_names or state.cookie_jar is not None:
            self.rejected_methods.add("cookie")

    async def renew(self) -> bool:
        return self.refresher is not None and self.refresher(TaskError("脚本请求续期")) is not None

    async def recover(self) -> bool:
        """明确认证失败后的异步恢复，每个任务最多尝试一次；不替访问链扩大候选。"""
        if self.recover_callback is None or self.recovery_attempted:
            return False
        self.recovery_attempted = True
        return await self.recover_callback()

    async def relogin(self, provider: str = "", account: str = "") -> bool:
        if self.relogin_callback is None:
            raise ConfigError("本次运行没有可用的隔离 OAuth 重登能力")
        return await self.relogin_callback(provider, account)


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
    if not spec.tasks:
        # 仅缺省清单补 daily；显式停用的任务不能被重新启用。
        tasks = [TaskSpec(id="daily")]
    by_id = {item.id: item for item in tasks}
    if len(by_id) != len(tasks):
        raise ConfigError("任务 id 重复")
    wanted = {str(item).strip() for item in only if str(item).strip()} if only else set(by_id)
    missing = wanted - by_id.keys()
    if missing:
        raise ConfigError(f"任务不存在或已停用：{', '.join(sorted(missing))}")

    def include(task_id: str) -> None:
        for dep in by_id[task_id].depends_on:
            if dep not in by_id:
                raise ConfigError(f"任务 {task_id} 的前置任务 {dep} 不存在或已停用")
            if dep not in wanted:
                wanted.add(dep)
                include(dep)

    for task_id in tuple(wanted):
        include(task_id)
    return _topological([item for item in tasks if item.id in wanted])


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
    """依赖必须完成；被上游阻断的 no_effect 不能解锁后续任务。"""
    finished = {record.task_id: record for record in records}
    for dep in task.depends_on:
        record = finished.get(dep)
        if record is None or not record.ok or record.outcome.data.get("blocked_by"):
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
