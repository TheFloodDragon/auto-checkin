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

import time
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from browser.service import BrowserService, PersistedSession, crash_outcome, is_driver_crash
from config.overlay import Overlay
from core.account import AccountSpec, ResolvedAccount, TaskSpec
from core.errors import ConfigError, TaskError
from core.flow import AUTO, Discovery, FlowPlan
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
from .events import make_logger

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
) -> AccountRun:
    """执行一个账号的全部任务。同账号任务共享登录态与浏览器。"""
    account = overlay.apply(spec, explicit=explicit)
    caps = caps_module.detect(account)
    emit = make_logger(account=account.name, structured=structured)

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
            record = await _run_one(
                spec, state_holder, task,
                overlay=overlay, caps=caps, browser=browser, emit=emit, oauth_state=oauth_state,
            )
        except TaskError as exc:
            record = _stub_record(spec, task, exc.to_outcome())
        except Exception as exc:  # noqa: BLE001 - 引擎内任何异常都要收敛成结论
            if is_driver_crash(exc):
                record = _stub_record(spec, task, crash_outcome(exc).to_outcome())
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
    args = _resolve_args(manifest, task, plan)
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

    # ── login ──
    login_plan = plan.get("login")
    result = await LOGINS.establish(
        login_ctx, login_plan, on_credentials=_credential_writer(spec, holder, overlay)
    )
    if result.outcome is not None:
        return _record(spec, task, template, plan, result.outcome, ctx)
    if result.state is not None:
        _apply_login(ctx, login_ctx, result.state, plan, spec, holder, overlay)
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
    plan: FlowPlan,
    spec: AccountSpec,
    holder: dict[str, Any],
    overlay: Overlay,
) -> None:
    """把登录结果注入本次任务的 HTTP 客户端，并装上一次性续期钩子。"""
    fresh = ctx.http.with_auth(extra=state.headers)
    if state.cookie_jar is not None:
        fresh.cookie_jar = state.cookie_jar
    ctx.http.adopt(fresh)
    ctx.http.reset_auth_renewal()

    writer = _credential_writer(spec, holder, overlay)

    def refresher(exc: TaskError) -> HttpClient | None:
        renewed = LOGINS.renew_sync(
            login_ctx, plan.get("login"), current=state.method, on_credentials=writer
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
    spec: AccountSpec, task: TaskSpec, template: Any, plan: FlowPlan, outcome: Outcome, ctx: TaskContext
) -> TaskRecord:
    """收尾：模板 render → 证据合并 → 组装记录。"""
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
    return TaskRecord(
        account_id=spec.id,
        task_id=task.id,
        name=task.title or spec.name,
        base_url=spec.base_url,
        outcome=outcome,
        template=template.manifest.id,
        flow=MappingProxyType(plan.to_payload()),
        display_defaults=_display_defaults(spec, task, template),
        )


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
