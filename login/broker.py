"""登录编排：按 FlowPlan 的候选链取得已认证会话，并在中途失效时续期一次。

这里取代旧实现四处各写一遍的降级逻辑：
- ``providers/actions/_common.py:build_http_client`` 的 auth_method 分支；
- ``providers/actions/browser_script.py`` 的「token → refresh → 账密 → 浏览器」；
- ``Sub2ApiClient._maybe_refresh_token`` 的请求内续期；
- ``profiles.build_lazy_refresh_client`` 的缓存优先客户端。

统一后的语义只有两条：
1. **auto**：按「学到的 → 模板 priority」逐个试，首个成功者被记为下次的首选；
2. **固定/优先序**：只在用户给的列表内降级，绝不自行扩大候选——失败就明确失败，
   并说明每个候选为什么没走通。

**同步与异步**：纯 HTTP 的登录方式（token / cookie / refresh / password）是同步函数，
浏览器类（browser_state / oauth）是协程。这不是随意的：请求打到一半发现 401 时，调用栈
正处在同步的 ``HttpClient.request`` 里，此时能做的只有同步续期。``renew_sync`` 因此只
使用同步方式，遇到浏览器类候选会如实说明「无法在请求中途启动浏览器」，由外层的候选链
在下一轮处理。
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, replace as _dataclass_replace
from typing import Any, Callable, Iterable, Mapping, Sequence

from core.account import LoginSpec
from core.errors import TaskError, VerificationRequired
from core.flow import Discovery, StagePlan
from core.manifest import LoginOption
from core.outcome import Outcome, failed
from .base import LoginContext, LoginMethod, LoginState

__all__ = ["LOGINS", "LoginAttempt", "LoginBroker", "LoginResult"]


@dataclass(frozen=True, slots=True)
class LoginAttempt:
    """一个候选的尝试记录。``ok=False`` 时 ``reason`` 必须可读且可行动。"""

    method: str
    ok: bool
    reason: str = ""
    skipped: bool = False

    def describe(self) -> str:
        if self.ok:
            return f"{self.method}=成功"
        return f"{self.method}={'跳过' if self.skipped else '失败'}（{self.reason}）"


@dataclass(frozen=True, slots=True)
class LoginResult:
    state: LoginState | None = None
    outcome: Outcome | None = None
    attempts: tuple[LoginAttempt, ...] = ()
    discovery: Discovery | None = None

    @property
    def ok(self) -> bool:
        return self.state is not None

    def describe(self) -> str:
        return " / ".join(item.describe() for item in self.attempts) or "未尝试任何登录方式"


@dataclass(frozen=True, slots=True)
class _Candidate:
    method_id: str
    method: LoginMethod | None
    option: LoginOption


class LoginBroker:
    """登录方式注册表 + 候选链执行器。"""

    __slots__ = ("_methods",)

    def __init__(self, methods: Mapping[str, LoginMethod] | None = None) -> None:
        self._methods: dict[str, LoginMethod] = dict(methods or {})

    # -- 注册 --
    def register(self, method: LoginMethod, *, replace_existing: bool = False) -> LoginMethod:
        key = str(getattr(method, "id", "")).strip().lower()
        if not key:
            raise ValueError("登录方式必须有 id")
        if key in self._methods and not replace_existing:
            raise ValueError(f"登录方式 {key!r} 已注册")
        self._methods[key] = method
        return method

    def get(self, method_id: str) -> LoginMethod | None:
        return self._methods.get(str(method_id or "").strip().lower())

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._methods))

    # -- 执行 --
    async def establish(
        self,
        ctx: LoginContext,
        plan: StagePlan | None,
        *,
        on_credentials: Callable[[Mapping[str, str], str], None] | None = None,
        exclude: Iterable[str] = (),
    ) -> LoginResult:
        """按候选链建立登录态。

        ``plan`` 为 None 或 OFF 时返回空结果（匿名执行）——公开活动页不需要登录，
        强行要求会把「本来能跑」的任务判成 need_login。
        """
        return await self._run(ctx, plan, on_credentials=on_credentials, exclude=exclude, sync_only=False)

    def renew_sync(
        self,
        ctx: LoginContext,
        plan: StagePlan | None,
        *,
        current: str = "",
        on_credentials: Callable[[Mapping[str, str], str], None] | None = None,
    ) -> LoginState | None:
        """请求中途登录失效时的一次性同步续期。

        排除当前正在用的方式：它刚刚被服务端拒了，再试一次只会得到同样的 401。
        """
        ctx.log(f"登录态在请求中途失效（当前方式 {current or '未知'}），尝试同步续期")
        result = self._run_sync(
            ctx, plan, on_credentials=on_credentials, exclude=(current,) if current else ()
        )
        if result.state is None:
            ctx.log(f"续期未成功：{result.describe()}")
        return result.state

    # -- 内部：两种执行形态共用同一套候选与筛选 --
    async def _run(
        self,
        ctx: LoginContext,
        plan: StagePlan | None,
        *,
        on_credentials: Callable[[Mapping[str, str], str], None] | None,
        exclude: Iterable[str],
        sync_only: bool,
    ) -> LoginResult:
        prepared = self._prepare(ctx, plan, exclude)
        if prepared is None:
            return LoginResult()
        candidates, locked = prepared
        attempts: list[LoginAttempt] = []
        hook = ctx.template.hook("login") if hasattr(ctx.template, "hook") else None

        for candidate in candidates:
            attempt_ctx, skip = self._screen(ctx, candidate)
            if skip is not None:
                attempts.append(skip)
                if locked:
                    break
                continue
            try:
                state = self._invoke(hook, candidate, attempt_ctx)
                if inspect.isawaitable(state):
                    state = await state
            except TaskError as exc:
                attempts.append(LoginAttempt(candidate.method_id, False, exc.message))
                if locked or _is_terminal(exc):
                    return LoginResult(outcome=_outcome_of(exc, attempts), attempts=tuple(attempts))
                continue
            except Exception as exc:  # noqa: BLE001 - 插件异常同样只该降级
                attempts.append(LoginAttempt(candidate.method_id, False, f"{type(exc).__name__}: {exc}"))
                if locked:
                    break
                continue
            settled = self._settle(ctx, candidate, state, attempts, on_credentials)
            if settled is not None:
                return settled

        return LoginResult(outcome=_no_candidate_outcome(attempts, locked=locked), attempts=tuple(attempts))

    def _run_sync(
        self,
        ctx: LoginContext,
        plan: StagePlan | None,
        *,
        on_credentials: Callable[[Mapping[str, str], str], None] | None,
        exclude: Iterable[str],
    ) -> LoginResult:
        prepared = self._prepare(ctx, plan, exclude)
        if prepared is None:
            return LoginResult()
        candidates, locked = prepared
        attempts: list[LoginAttempt] = []
        hook = ctx.template.hook("login") if hasattr(ctx.template, "hook") else None

        for candidate in candidates:
            attempt_ctx, skip = self._screen(ctx, candidate)
            if skip is not None:
                attempts.append(skip)
                continue
            try:
                state = self._invoke(hook, candidate, attempt_ctx)
                if inspect.isawaitable(state):
                    # 协程只能在异步栈里跑；这里正处在同步的 HTTP 调用中间。
                    state.close()
                    attempts.append(
                        LoginAttempt(
                            candidate.method_id, False,
                            "需要启动浏览器，无法在请求中途续期（将在下一轮候选链中尝试）",
                            skipped=True,
                        )
                    )
                    continue
            except TaskError as exc:
                attempts.append(LoginAttempt(candidate.method_id, False, exc.message))
                if locked:
                    break
                continue
            except Exception as exc:  # noqa: BLE001
                attempts.append(LoginAttempt(candidate.method_id, False, f"{type(exc).__name__}: {exc}"))
                continue
            settled = self._settle(ctx, candidate, state, attempts, on_credentials)
            if settled is not None:
                return settled

        return LoginResult(outcome=_no_candidate_outcome(attempts, locked=locked), attempts=tuple(attempts))

    def _prepare(
        self, ctx: LoginContext, plan: StagePlan | None, exclude: Iterable[str]
    ) -> tuple[list[_Candidate], bool] | None:
        if plan is not None and not plan.enabled:
            return None
        manifest = getattr(ctx.template, "manifest", None)
        ids = _candidate_ids(plan, manifest, exclude)
        if not ids:
            return None
        locked = bool(plan.locked) if plan is not None else False
        return [_Candidate(item, self.get(item), _option(manifest, item)) for item in ids], locked

    def _screen(
        self, ctx: LoginContext, candidate: _Candidate
    ) -> tuple[LoginContext, LoginAttempt | None]:
        """能力与可用性筛选。返回 (带参数的上下文, 跳过记录或 None)。"""
        method, method_id = candidate.method, candidate.method_id
        if method is None:
            return ctx, LoginAttempt(method_id, False, "未知登录方式", skipped=True)
        missing = set(getattr(method, "requires", ())) - set(ctx.capabilities)
        if missing:
            from runtime.capabilities import missing_reason

            return ctx, LoginAttempt(method_id, False, missing_reason(missing), skipped=True)
        try:
            attempt_ctx = _with_args(ctx, candidate.option, method_id)
        except TaskError as exc:
            return ctx, LoginAttempt(method_id, False, exc.message, skipped=True)
        available = method.available(attempt_ctx, candidate.option)
        if not available.ready:
            return attempt_ctx, LoginAttempt(method_id, False, available.reason, skipped=True)
        return attempt_ctx, None

    @staticmethod
    def _invoke(hook: Any, candidate: _Candidate, ctx: LoginContext) -> Any:
        """模板的 login 钩子优先；返回 None 表示「这个候选交给内置实现」。"""
        if hook is not None:
            state = hook(ctx, candidate.option)
            if state is not None:
                return state
        return candidate.method.authenticate(ctx, candidate.option)

    @staticmethod
    def _settle(
        ctx: LoginContext,
        candidate: _Candidate,
        state: LoginState | None,
        attempts: list[LoginAttempt],
        on_credentials: Callable[[Mapping[str, str], str], None] | None,
    ) -> LoginResult | None:
        if state is None:
            attempts.append(LoginAttempt(candidate.method_id, False, "登录方式未返回可用会话", skipped=True))
            return None
        attempts.append(LoginAttempt(candidate.method_id, True, state.note))
        if on_credentials is not None and state.credentials:
            on_credentials(state.credentials, state.origin)
        ctx.log(f"登录成功：{candidate.method_id}" + (f"（{state.note}）" if state.note else ""))
        return LoginResult(
            state=state,
            attempts=tuple(attempts),
            discovery=Discovery(stage="login", value=candidate.method_id, source="probe"),
        )


# ── 内部 ────────────────────────────────────────────────────────────────────
def _candidate_ids(plan: StagePlan | None, manifest: Any, exclude: Iterable[str]) -> tuple[str, ...]:
    skip = {str(item).strip().lower() for item in exclude if str(item).strip()}
    values: Sequence[str] = ()
    if plan is not None and plan.candidates:
        values = plan.candidates
    elif manifest is not None:
        values = manifest.login_order()
    return tuple(item for item in values if item not in skip)


def _option(manifest: Any, method_id: str) -> LoginOption:
    if manifest is not None:
        found = manifest.login_option(method_id)
        if found is not None:
            return found
    # 模板没声明也允许使用：用户显式配置的方式优先于模板的想象力。
    return LoginOption(method=method_id)


def _with_args(ctx: LoginContext, option: LoginOption, method_id: str) -> LoginContext:
    """为某个候选解析参数：账号 login.args + 同名 fallback 条目的 args。"""
    spec: LoginSpec = ctx.account.login
    merged: dict[str, Any] = dict(spec.args or {})
    if spec.provider:
        merged.setdefault("provider", spec.provider)
    if spec.account:
        merged.setdefault("account", spec.account)
    for item in spec.fallback:
        if str(item.method or "").strip().lower() != method_id:
            continue
        merged.update(dict(item.args or {}))
        if item.provider:
            merged["provider"] = item.provider
        if item.account:
            merged["account"] = item.account
        break
    resolved = option.args.resolve(merged, label=f"登录方式 {method_id} 的")
    # option.args 只声明了它关心的字段；provider/account 这类通用项要原样带过去。
    combined = {**merged, **dict(resolved)}
    return _dataclass_replace(ctx, args=combined)


def _is_terminal(exc: TaskError) -> bool:
    """这次失败是否「换个登录方式也没用」。

    人机验证与出口 IP 被封是站点层面的拒绝，与用哪把钥匙无关；继续换方式只会多跑
    几十秒再失败一次，而且掩盖真正的原因。
    """
    return isinstance(exc, VerificationRequired) or exc.reason in {"blocked", "need_verification"}


def _outcome_of(exc: TaskError, attempts: list[LoginAttempt]) -> Outcome:
    return exc.to_outcome().with_data(login_attempts=[item.describe() for item in attempts])


def _no_candidate_outcome(attempts: list[LoginAttempt], *, locked: bool) -> Outcome:
    if not attempts:
        return failed(
            "没有可用的登录方式：模板未声明任何登录方式，配置也没有指定。", reason="need_config"
        )
    detail = "；".join(item.describe() for item in attempts)
    data = {"login_attempts": [item.describe() for item in attempts]}
    # 全部候选都是「跳过」= 缺配置；有真正失败的 = 登录失效。这两类用户要做的事不同：
    # 前者去填凭据，后者去重新登录 / 重新捕获登录态。
    if all(item.skipped for item in attempts):
        return failed(f"没有可用的登录凭据：{detail}", reason="need_config", data=data)
    prefix = "按配置固定的登录方式" if locked else "全部登录方式"
    return failed(f"{prefix}均未成功：{detail}", reason="need_login", data=data)


LOGINS = LoginBroker()
