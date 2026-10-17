"""共享 linux.do 登录态保活：所有任务开始前静态检查到期时间，快到期就先续期。

浏览器里的论坛会话之所以「一直登录着」，是因为人天天在访问：Discourse 在已登录的
页面请求上滚动轮换 ``_t`` 并把它的有效期重置为完整寿命。自动化只在少数任务里碰
linux.do，共享态就会在没人访问的日子里静静过期——这时所有依赖它的 OAuth 站点都会
一起失效，且只能人工重新捕获。

这里的做法与真人一致：

1. **静态检查**（不开浏览器）：读覆写文件/配置里共享态 ``_t`` 的 ``expires``，剩余
   寿命不少于窗口（默认 30 小时，``CHECKIN_OAUTH_RENEW_HOURS`` 或 ``--oauth-renew-hours``
   可调，0 关闭）就什么都不做；
2. **续期**：快到期（或已过本地到期时间——快照恢复时按会话 Cookie 交给服务端判定）
   时，在隔离浏览器里恢复共享态、正常打开论坛、经 ``/session/current.json`` 服务端
   确认登录后导出新快照，以 CAS 写回覆写文件；
3. **永不放大损害**：服务端确认匿名才报「需要重新捕获」；人机验证、限流、网络问题
   一律保留原态，绝不写回；续期结果怎样都不阻塞后续任务。

跨进程用文件锁串行，拿到锁后重新读一次：另一个进程刚续过就直接跳过。
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence
from urllib.parse import urlsplit

from config import paths
from config.overlay import CachePolicy, Overlay

__all__ = [
    "DEFAULT_RENEW_HOURS",
    "KeepaliveResult",
    "ensure_linuxdo_sessions",
    "linuxdo_accounts",
    "renew_window_seconds",
]

LINUXDO_URL = "https://linux.do"
PROVIDER = "linuxdo"
DEFAULT_RENEW_HOURS = 30.0
RENEW_HOURS_ENV = "CHECKIN_OAUTH_RENEW_HOURS"
#: 批量父进程已做过保活时设置，子进程据此跳过（避免每个 worker 都排队等锁）。
SKIP_ENV = "CHECKIN_OAUTH_KEEPALIVE_DONE"
#: 一次续期（启动浏览器 + 过 Cloudflare + 服务端确认 + 导出）的预算。
RENEW_BUDGET_SECONDS = 150.0
LOCK_PATH = paths.CACHE_DIR / "oauth_keepalive"


@dataclass(frozen=True, slots=True)
class KeepaliveResult:
    account: str
    status: str            # fresh / renewed / unchanged / expired / challenge / undetermined / skipped / error
    remaining_hours: float | None = None
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.status in {"fresh", "renewed", "unchanged", "skipped"}


def renew_window_seconds(hours: float | str | None = None) -> float:
    """续期窗口（秒）。参数优先于环境变量；非法值退回默认 30 小时；0 或负数表示关闭。"""
    raw = hours if hours is not None else os.environ.get(RENEW_HOURS_ENV, "")
    try:
        value = float(raw) if str(raw).strip() else DEFAULT_RENEW_HOURS
    except (TypeError, ValueError):
        value = DEFAULT_RENEW_HOURS
    if value != value or value in (float("inf"), float("-inf")):
        value = DEFAULT_RENEW_HOURS
    return max(0.0, value) * 3600.0


def remaining_seconds(state_text: str, *, now: float | None = None) -> float | None:
    """共享态 ``_t`` 的剩余寿命（秒，可为负）；没有认证 Cookie 或只有会话 Cookie 时为 None。"""
    from browser import storage_scope
    from browser.service import decode_state

    expiry = storage_scope.provider_auth_expiry(decode_state(state_text), PROVIDER)
    if expiry is None:
        return None
    return expiry - (time.time() if now is None else float(now))


def references_linuxdo(spec: Any) -> tuple[str, ...]:
    """账号显式依赖了哪些 linux.do 共享账号（登录链里的 provider，或论坛自身）。"""
    found: list[str] = []
    host = (urlsplit(str(getattr(spec, "base_url", "") or "")).hostname or "").lower()
    login = getattr(spec, "login", None)
    for item in login.chain() if login is not None else ():
        method = str(item.method or "").strip().lower()
        provider = str(item.provider or "").strip().lower()
        args = dict(item.args or {})
        provider = str(args.get("provider") or provider).strip().lower()
        if provider == PROVIDER or (host == "linux.do" and method in {"", "oauth", "browser_state"}):
            name = str(args.get("account") or item.account or "default").strip() or "default"
            found.append(name)
    return tuple(dict.fromkeys(found))


def linuxdo_accounts(oauth_states: Any) -> tuple[str, ...]:
    """配置里已捕获的 linux.do 共享账号名。"""
    bucket = (oauth_states or {}).get(PROVIDER) if hasattr(oauth_states, "get") else None
    accounts = bucket.get("accounts") if hasattr(bucket, "get") else None
    if not hasattr(accounts, "items"):
        return ()
    return tuple(
        str(name) for name, item in accounts.items()
        if hasattr(item, "get") and str(item.get("state") or "").strip()
    )


async def ensure_linuxdo_sessions(
    accounts: Iterable[str],
    *,
    overlay: Overlay,
    oauth_state: Any,
    proxy: str = "",
    window_seconds: float | None = None,
    log: Callable[[str], None] = lambda _m: None,
    now: Callable[[], float] = time.time,
) -> list[KeepaliveResult]:
    """逐个检查共享账号，必要时续期。永不抛出：任何失败都只是结果里的一行。"""
    window = renew_window_seconds() if window_seconds is None else max(0.0, float(window_seconds))
    names = tuple(dict.fromkeys(str(name).strip() or "default" for name in accounts))
    if window <= 0 or not names:
        return []
    if overlay.policy != CachePolicy.COMPATIBLE:
        log("覆写文件为只读/忽略模式：续期结果无法保存，跳过 linux.do 共享态保活")
        return [KeepaliveResult(name, "skipped", message="覆写文件不可写") for name in names]
    results: list[KeepaliveResult] = []
    for name in names:
        try:
            results.append(await _ensure_one(
                name, overlay=overlay, oauth_state=oauth_state, proxy=proxy, window=window, log=log, now=now,
            ))
        except Exception as exc:  # noqa: BLE001 - 保活绝不能阻断后续任务
            results.append(KeepaliveResult(name, "error", message=f"{type(exc).__name__}"))
            log(f"linux.do:{name} 保活异常（{type(exc).__name__}），保留现有登录态，继续执行任务")
    return results


async def _ensure_one(
    name: str, *, overlay: Overlay, oauth_state: Any, proxy: str, window: float,
    log: Callable[[str], None], now: Callable[[], float],
) -> KeepaliveResult:
    from runtime.engine import _shared_oauth_resolver

    resolver = _shared_oauth_resolver(overlay, oauth_state)
    label = f"linux.do:{name}"

    def check() -> tuple[Any, float | None]:
        source = resolver(PROVIDER, name)
        if not source.state:
            return source, None
        return source, remaining_seconds(source.state, now=now())

    source, remaining = check()
    if not source.state:
        return KeepaliveResult(name, "skipped", message="未捕获共享态")
    if remaining is None:
        # 没有认证 Cookie，或 _t 是会话 Cookie（无 expires）：静态无法判断，不为此每轮开浏览器。
        log(f"{label} 共享登录态没有可读的到期时间，跳过静态保活（由使用它的任务按需校验）")
        return KeepaliveResult(name, "skipped", message="到期时间未知")
    if remaining > window:
        log(f"{label} 共享登录态剩余 {remaining / 3600:.1f} 小时，无需续期")
        return KeepaliveResult(name, "fresh", remaining / 3600)

    lock_wait = RENEW_BUDGET_SECONDS + 30.0
    try:
        with paths.file_lock(LOCK_PATH, timeout=lock_wait):
            # 排队期间另一进程可能已续过：锁内重读，不重复轮换（重复轮换会让刚写回的值作废）。
            source, remaining = check()
            if not source.state or remaining is None:
                return KeepaliveResult(name, "skipped", message="共享态已变化")
            if remaining > window:
                log(f"{label} 已被其他进程续期，剩余 {remaining / 3600:.1f} 小时")
                return KeepaliveResult(name, "fresh", remaining / 3600)
            hint = "已过本地到期时间" if remaining <= 0 else f"剩余 {remaining / 3600:.1f} 小时"
            log(f"{label} 共享登录态{hint}（窗口 {window / 3600:g} 小时），任务开始前先续期")
            return await _renew(name, source, resolver, overlay=overlay, proxy=proxy, log=log, now=now)
    except Exception as exc:
        from core.errors import ConfigError

        if isinstance(exc, ConfigError):
            log(f"{label} 等待续期锁超时，保留现有登录态")
            return KeepaliveResult(name, "skipped", remaining / 3600 if remaining is not None else None,
                                   message="等待续期锁超时")
        raise


async def _renew(
    name: str, source: Any, resolver: Any, *, overlay: Overlay, proxy: str,
    log: Callable[[str], None], now: Callable[[], float],
) -> KeepaliveResult:
    from browser import storage_scope
    from browser.service import BrowserService, decode_state, encode_state
    from login.base import LoginState
    from login.oauth import oauth_state_update
    from runtime.engine import _record_oauth_updates
    from templates import registry as templates

    label = f"linux.do:{name}"
    browse = templates.get("scripts/tasks/linuxdo_browse.py").module
    scoped = storage_scope.provider_storage_state(decode_state(source.state), PROVIDER)
    # 与刷帖任务一致：保留论坛认证，不复用上次浏览器/出口的 Cloudflare 放行 Cookie。
    state_text = browse._shared_browser_state(encode_state(scoped))
    service = BrowserService(base_url=LINUXDO_URL, proxy=proxy, log=log, persist=None)
    deadline = time.monotonic() + RENEW_BUDGET_SECONDS
    try:
        async with asyncio.timeout_at(deadline):
            async with service.lease(reason="oauth_keepalive", state_text=state_text) as lease:
                status, storage = await browse.keepalive_session(lease, log=log, deadline=deadline)
    except TimeoutError:
        status, storage = "undetermined", None
    finally:
        try:
            await asyncio.wait_for(service.aclose(persist=False), timeout=10.0)
        except Exception:
            pass

    if status == "authenticated" and storage is not None:
        update = oauth_state_update(source, storage, PROVIDER, base_url="", same_identity=True)
        if update is None:
            log(f"{label} 服务端确认登录有效，本次未轮换认证 Cookie，保留现有登录态")
            return KeepaliveResult(name, "unchanged", _hours(source.state, now))
        written = _record_oauth_updates(
            LoginState(method="oauth_keepalive", verified=True, oauth_updates=(update,)), overlay, resolver,
        )
        if not written:
            log(f"{label} 续期成功但写回覆写文件未完成（版本冲突或配置已变），下次运行重试")
            return KeepaliveResult(name, "error", message="写回失败")
        renewed = resolver(PROVIDER, name)
        hours = _hours(renewed.state, now)
        log(f"{label} 已续期并写回覆写文件" + (f"，新的剩余寿命 {hours:.1f} 小时" if hours is not None else ""))
        return KeepaliveResult(name, "renewed", hours)
    if status == "anonymous":
        log(f"{label} 服务端确认共享登录态已失效，请在管理界面重新捕获 linux.do 登录态并更新配置")
        return KeepaliveResult(name, "expired", _hours(source.state, now), message="需要重新捕获")
    if status == "challenge":
        log(f"{label} 续期时人机验证未通过，保留现有登录态，任务照常执行")
    else:
        log(f"{label} 续期结果无法判定（限流/网络），保留现有登录态，任务照常执行")
    return KeepaliveResult(name, status, _hours(source.state, now))


def _hours(state_text: str, now: Callable[[], float]) -> float | None:
    try:
        remaining = remaining_seconds(state_text, now=now())
    except Exception:
        return None
    return None if remaining is None else remaining / 3600


def pick_network(specs: Sequence[Any]) -> Any:
    """保活走哪个出口：优先论坛账号自身，其次依赖 linux.do 的账号，否则直连默认。"""
    from core.account import NetworkSpec

    forum = [s for s in specs if (urlsplit(str(s.base_url or "")).hostname or "").lower() == "linux.do"]
    users = [s for s in specs if references_linuxdo(s)]
    chosen = (forum or users or [None])[0]
    return chosen.network if chosen is not None else NetworkSpec()


async def preflight(
    accounts: Iterable[str],
    *,
    overlay: Overlay,
    oauth_state: Any,
    network: Any,
    proxy_groups: Sequence[Any] = (),
    default_proxy_group: str = "",
    window_seconds: float | None = None,
    log: Callable[[str], None] = lambda _m: None,
) -> list[KeepaliveResult]:
    """任务开始前的入口：静态判断 → 必要时解析代理（含桥接）→ 续期。永不抛出。"""
    window = renew_window_seconds() if window_seconds is None else max(0.0, float(window_seconds))
    names = tuple(dict.fromkeys(str(name).strip() or "default" for name in accounts))
    if window <= 0 or not names:
        return []
    from runtime.engine import _shared_oauth_resolver

    resolver = _shared_oauth_resolver(overlay, oauth_state)
    due = []
    for name in names:
        try:
            state = resolver(PROVIDER, name).state
            remaining = remaining_seconds(state) if state else None
        except Exception:
            remaining = None
        if remaining is not None and remaining <= window:
            due.append(name)
        elif remaining is not None:
            log(f"linux.do:{name} 共享登录态剩余 {remaining / 3600:.1f} 小时，无需续期")
    if not due:
        return [KeepaliveResult(name, "fresh") for name in names]
    from runtime import capabilities

    if "browser" not in capabilities.environment():
        log("linux.do 共享登录态即将到期，但本机没有可用浏览器，无法续期；请安装 Camoufox")
        return [KeepaliveResult(name, "skipped", message="缺少浏览器") for name in due]

    from config.proxies import resolve_proxy

    bridge = None
    try:
        selection = resolve_proxy(
            network, proxy_groups, default_proxy_group, environ_proxy=os.environ.get("CHECKIN_PROXY", ""),
        )
        proxy = selection.url
        if selection.requires_bridge:
            from runtime.engine import _bridge_factory

            bridge = _bridge_factory(selection.bridge, log=log)
            proxy = await asyncio.to_thread(bridge.start)
    except Exception as exc:  # noqa: BLE001 - TaskError 与启动异常同样只能放弃续期
        if bridge is not None:
            await asyncio.to_thread(bridge.close)
        log(f"linux.do 保活所需的代理不可用（{type(exc).__name__}），保留现有登录态")
        return [KeepaliveResult(name, "skipped", message="代理不可用") for name in due]
    try:
        return await ensure_linuxdo_sessions(
            due, overlay=overlay, oauth_state=oauth_state, proxy=proxy, window_seconds=window, log=log,
        )
    finally:
        if bridge is not None:
            await asyncio.to_thread(bridge.close)


def skip_in_child() -> bool:
    return os.environ.get(SKIP_ENV) == "1"


def mark_done(env: dict[str, str]) -> dict[str, str]:
    return {**env, SKIP_ENV: "1"}


__all__ += ["pick_network", "references_linuxdo", "remaining_seconds", "skip_in_child", "mark_done"]
