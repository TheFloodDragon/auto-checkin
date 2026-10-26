"""共享 OAuth（linux.do / GitHub）登录态保活。

按 (provider, account) 静态检查认证 Cookie 的真实到期时间；默认 30 小时内才验证，
0 关闭自动检查，force_verify 可显式忽略窗口（含未知到期时间）。隔离恢复提供商态，
通过正常页面请求让服务端确认身份；只有真实认证 Cookie 轮换/延寿才以原来源 CAS
写回。匿名才报失效，验证挑战、限流、导航异常均保留原态，不提交密码或二次验证。

跨进程沿用文件锁，锁内重新读取共享态；旧 LinuxDO 专用入口保持兼容。
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
    "ensure_oauth_sessions",
    "linuxdo_accounts",
    "oauth_accounts",
    "references_oauth",
    "preflight",
    "renew_window_seconds",
]

LINUXDO_URL = "https://linux.do"
PROVIDER = "linuxdo"  # 旧调用方的默认 provider。
PROVIDERS = ("linuxdo", "github")
OAuthReference = tuple[str, str]
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
    provider: str = PROVIDER

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


def remaining_seconds(
    state_text: str, *, provider: str = PROVIDER, now: float | None = None,
) -> float | None:
    """认证 Cookie 的真实剩余寿命；GitHub 双 Cookie 取较早者，未知不能报 fresh。"""
    from browser import oauth_providers, storage_scope
    from browser.service import decode_state

    state = decode_state(state_text)
    key = str(provider or "").strip().lower()
    if key not in PROVIDERS:
        return None
    if key == "github":
        adapter = oauth_providers.get_oauth_provider(key)
        expiries = [
            storage_scope.provider_auth_expiry({"cookies": [cookie]}, key)
            for cookie in state.get("cookies", [])
            if isinstance(cookie, dict) and cookie.get("name") in adapter.authenticated_cookie_names
            and str(cookie.get("value") or "")
            and oauth_providers.normalize_hostname(cookie.get("domain")) == "github.com"
        ]
        # 会话 Cookie 不能静态推断寿命；显式 force_verify 可以检查这类快照。
        expiry = min(expiries) if expiries and all(value is not None for value in expiries) else None
    else:
        expiry = storage_scope.provider_auth_expiry(state, key)
    if expiry is None:
        return None
    return expiry - (time.time() if now is None else float(now))


def _references(accounts: Iterable[str | OAuthReference]) -> tuple[OAuthReference, ...]:
    """兼容旧式 LinuxDO 账号名，同时禁止未知 provider 回落成另一个 provider。"""
    found = []
    for item in accounts:
        if isinstance(item, str):
            provider, name = PROVIDER, item
        elif isinstance(item, (tuple, list)) and len(item) == 2:
            provider, name = item
        else:
            continue
        provider = str(provider or "").strip().lower()
        if provider in PROVIDERS:
            found.append((provider, str(name or "default").strip() or "default"))
    return tuple(dict.fromkeys(found))


def references_oauth(spec: Any) -> tuple[OAuthReference, ...]:
    """登录链的共享引用；LinuxDO GitHub fallback 继承主参数且尊重显式 false。"""
    login = getattr(spec, "login", None)
    if login is None:
        return ()
    host = (urlsplit(str(getattr(spec, "base_url", "") or "")).hostname or "").lower()
    found: list[OAuthReference] = []
    for item in login.chain():
        args = dict(login.args or {})
        if login.provider:
            args.setdefault("provider", login.provider)
        if login.account:
            args.setdefault("account", login.account)
        if item is not login:
            args.update(dict(item.args or {}))
            if item.provider:
                args["provider"] = item.provider
            if item.account:
                args["account"] = item.account
        method = str(item.method or "").strip().lower()
        provider = str(args.get("provider") or "").strip().lower()
        forum = host == "linux.do" and method in {"", "oauth", "browser_state"}
        if not provider and (forum or method == "oauth"):
            provider = PROVIDER
        if provider in PROVIDERS:
            found.append((provider, str(args.get("account") or "default").strip() or "default"))
        if forum and str(args.get("github_fallback") or "").strip().lower() in {"1", "true", "yes", "y", "on"}:
            name = str(args.get("github_account") or "default").strip() or "default"
            found.append(("github", name))
    enabled_tasks = getattr(spec, "enabled_tasks", lambda: ())
    for task in enabled_tasks():
        method = str(getattr(task, "method", "") or "").strip().lower()
        args = dict(getattr(task, "args", None) or {})
        if method != "relogin" and not (not method and ({"provider", "account"} & args.keys())):
            continue
        # ReloginTask 与普通登录的参数来源不同：任务 args 覆盖 login 的顶层 provider/account。
        provider = str(args.get("provider") or login.provider or PROVIDER).strip().lower()
        name = str(args.get("account") or login.account or "default").strip() or "default"
        if provider in PROVIDERS:
            found.append((provider, name))
    return tuple(dict.fromkeys(found))


def references_linuxdo(spec: Any) -> tuple[str, ...]:
    """兼容入口：只返回引用中的 LinuxDO 账号名。"""
    return tuple(name for provider, name in references_oauth(spec) if provider == PROVIDER)


def oauth_accounts(oauth_states: Any) -> tuple[OAuthReference, ...]:
    """已捕获共享态的 (provider, account)，同名账号不会跨 provider 去重。"""
    found: list[OAuthReference] = []
    for provider in PROVIDERS:
        bucket = (oauth_states or {}).get(provider) if hasattr(oauth_states, "get") else None
        accounts = bucket.get("accounts") if hasattr(bucket, "get") else None
        if not hasattr(accounts, "items"):
            continue
        found.extend(
            (provider, str(name).strip() or "default") for name, item in accounts.items()
            if hasattr(item, "get") and str(item.get("state") or "").strip()
        )
    return tuple(dict.fromkeys(found))


def linuxdo_accounts(oauth_states: Any) -> tuple[str, ...]:
    """兼容入口：配置里已捕获的 LinuxDO 共享账号名。"""
    return tuple(name for provider, name in oauth_accounts(oauth_states) if provider == PROVIDER)


async def ensure_linuxdo_sessions(
    accounts: Iterable[str],
    *,
    overlay: Overlay,
    oauth_state: Any,
    proxy: str = "",
    window_seconds: float | None = None,
    log: Callable[[str], None] = lambda _m: None,
    now: Callable[[], float] = time.time,
    force_verify: bool = False,
) -> list[KeepaliveResult]:
    """兼容旧 LinuxDO 专用入口。"""
    return await ensure_oauth_sessions(
        ((PROVIDER, name) for name in accounts), overlay=overlay, oauth_state=oauth_state,
        proxy=proxy, window_seconds=window_seconds, log=log, now=now, force_verify=force_verify,
    )


async def ensure_oauth_sessions(
    accounts: Iterable[str | OAuthReference],
    *,
    overlay: Overlay,
    oauth_state: Any,
    proxy: str = "",
    window_seconds: float | None = None,
    log: Callable[[str], None] = lambda _m: None,
    now: Callable[[], float] = time.time,
    force_verify: bool = False,
) -> list[KeepaliveResult]:
    """按 provider/account 去重后续期；force_verify 显式验证未知/未临期状态。"""
    window = renew_window_seconds() if window_seconds is None else max(0.0, float(window_seconds))
    references = _references(accounts)
    if (window <= 0 and not force_verify) or not references:
        return []
    if overlay.policy != CachePolicy.COMPATIBLE:
        log("覆写文件为只读/忽略模式：续期结果无法保存，跳过共享 OAuth 保活")
        return [KeepaliveResult(name, "skipped", message="覆写文件不可写", provider=provider)
                for provider, name in references]
    results: list[KeepaliveResult] = []
    for provider, name in references:
        try:
            results.append(await _ensure_one(
                name, provider=provider, overlay=overlay, oauth_state=oauth_state, proxy=proxy,
                window=window, force_verify=force_verify, log=log, now=now,
            ))
        except Exception as exc:  # noqa: BLE001 - 保活绝不能阻断后续任务
            results.append(KeepaliveResult(name, "error", message=type(exc).__name__, provider=provider))
            log(f"{provider}:{name} 保活异常（{type(exc).__name__}），保留现有登录态，继续执行任务")
    return results


async def _ensure_one(
    name: str, *, overlay: Overlay, oauth_state: Any, proxy: str, window: float,
    log: Callable[[str], None], now: Callable[[], float], provider: str = PROVIDER,
    force_verify: bool = False,
) -> KeepaliveResult:
    from runtime.engine import _shared_oauth_resolver

    resolver = _shared_oauth_resolver(overlay, oauth_state)
    label = f"{provider}:{name}"

    def check() -> tuple[Any, float | None]:
        source = resolver(provider, name)
        if not source.state:
            return source, None
        return source, remaining_seconds(source.state, provider=provider, now=now())

    source, remaining = check()
    if not source.state:
        return KeepaliveResult(name, "skipped", message="未捕获共享态", provider=provider)
    if not force_verify:
        if remaining is None:
            log(f"{label} 共享登录态没有可读的到期时间，跳过静态保活（可显式强制验证）")
            return KeepaliveResult(name, "skipped", message="到期时间未知", provider=provider)
        if remaining > window:
            log(f"{label} 共享登录态剩余 {remaining / 3600:.1f} 小时，无需续期")
            return KeepaliveResult(name, "fresh", remaining / 3600, provider=provider)

    lock_wait = RENEW_BUDGET_SECONDS + 30.0
    try:
        with paths.file_lock(LOCK_PATH, timeout=lock_wait):
            # 每次验证只用锁内重读的来源；写回冲突时不能换 revision 重放旧产物。
            source, remaining = check()
            if not source.state or (remaining is None and not force_verify):
                return KeepaliveResult(name, "skipped", message="共享态已变化", provider=provider)
            if not force_verify and remaining is not None and remaining > window:
                log(f"{label} 已被其他进程续期，剩余 {remaining / 3600:.1f} 小时")
                return KeepaliveResult(name, "fresh", remaining / 3600, provider=provider)
            hint = "到期时间未知" if remaining is None else (
                "已过本地到期时间" if remaining <= 0 else f"剩余 {remaining / 3600:.1f} 小时"
            )
            action = "按显式要求验证" if force_verify else "任务开始前先续期"
            log(f"{label} 共享登录态{hint}（窗口 {window / 3600:g} 小时），{action}")
            return await _renew(name, source, resolver, provider=provider, overlay=overlay,
                                proxy=proxy, log=log, now=now)
    except Exception as exc:
        from core.errors import ConfigError

        if isinstance(exc, ConfigError):
            log(f"{label} 等待续期锁超时，保留现有登录态")
            return KeepaliveResult(name, "skipped", remaining / 3600 if remaining is not None else None,
                                   message="等待续期锁超时", provider=provider)
        raise


async def _cookie_names_note(lease: Any) -> str:
    """只记录装载后上下文里的 Cookie 名称，用于分开「没装进去」与「被服务端拒绝」。

    实测同一轮里论坛刷帖能正常登录，而共享态校验却报匿名，这两种成因必须区分开：
    前者要查装载链路，后者才需要重新捕获。名字不是凭据，但仍不记录任何值。
    """
    try:
        cookies = await lease.context.cookies()
    except Exception as exc:
        return f"读取上下文 Cookie 失败（{type(exc).__name__}）"
    if not isinstance(cookies, list):
        return "读取上下文 Cookie 结果异常"
    names = sorted({str(c.get("name") or "") for c in cookies if isinstance(c, dict)})
    auth = [name for name in names if name in {"_t", "user_session", "__Host-user_session_same_site"}]
    return f"上下文 Cookie {len(names)} 条，认证类 {auth or '无'}：{names}"


async def _renew(
    name: str, source: Any, resolver: Any, *, overlay: Overlay, proxy: str,
    log: Callable[[str], None], now: Callable[[], float], provider: str = PROVIDER,
) -> KeepaliveResult:
    from browser import oauth_providers, storage_scope
    from browser.service import BrowserService, decode_state, encode_state
    from login.base import LoginState
    from login.oauth import oauth_state_update
    from runtime.engine import _record_oauth_updates

    label = f"{provider}:{name}"
    if provider == PROVIDER:
        from templates import registry as templates

        browse = templates.get("scripts/tasks/linuxdo_browse.py").module
        scoped = storage_scope.provider_storage_state(decode_state(source.state), provider)
        state_text = browse._shared_browser_state(encode_state(scoped))
        verify = browse.keepalive_session
        base_url = LINUXDO_URL
    else:
        adapter = oauth_providers.get_oauth_provider(provider)
        state_text = encode_state(adapter.keepalive_storage_state(decode_state(source.state)))
        verify = adapter.keepalive_session
        base_url = "https://github.com"
    service = BrowserService(base_url=base_url, proxy=proxy, log=log, persist=None)
    deadline = time.monotonic() + RENEW_BUDGET_SECONDS
    try:
        async with asyncio.timeout_at(deadline):
            async with service.lease(reason="oauth_keepalive", state_text=state_text) as lease:
                log(f"{label} " + await _cookie_names_note(lease))
                status, storage = await verify(lease, log=log, deadline=deadline)
    except TimeoutError:
        status, storage = "undetermined", None
    finally:
        try:
            await asyncio.wait_for(service.aclose(persist=False), timeout=10.0)
        except Exception:
            pass

    if status == "authenticated" and storage is not None:
        update = oauth_state_update(source, storage, provider, base_url="", same_identity=True)
        if update is None:
            log(f"{label} 服务端确认登录有效，本次未轮换认证 Cookie，保留现有登录态")
            return KeepaliveResult(name, "unchanged", _hours(source.state, now, provider), provider=provider)
        written = _record_oauth_updates(
            LoginState(method="oauth_keepalive", verified=True, oauth_updates=(update,)), overlay, resolver,
        )
        if not written:
            log(f"{label} 续期成功但写回覆写文件未完成（版本冲突或配置已变），下次运行重试")
            return KeepaliveResult(name, "error", message="写回失败", provider=provider)
        renewed = resolver(provider, name)
        hours = _hours(renewed.state, now, provider)
        log(f"{label} 已续期并写回覆写文件" + (f"，新的剩余寿命 {hours:.1f} 小时" if hours is not None else ""))
        return KeepaliveResult(name, "renewed", hours, provider=provider)
    if status == "anonymous":
        log(f"{label} 服务端确认共享登录态已失效，请在管理界面重新捕获 {provider} 登录态并更新配置")
        return KeepaliveResult(name, "expired", _hours(source.state, now, provider),
                               message="需要重新捕获", provider=provider)
    if status == "challenge":
        log(f"{label} 续期时需要人工验证，保留现有登录态，任务照常执行")
    else:
        status = "undetermined"
        log(f"{label} 续期结果无法判定（限流/网络），保留现有登录态，任务照常执行")
    return KeepaliveResult(name, status, _hours(source.state, now, provider), provider=provider)


def _hours(state_text: str, now: Callable[[], float], provider: str = PROVIDER) -> float | None:
    try:
        remaining = remaining_seconds(state_text, provider=provider, now=now())
    except Exception:
        return None
    return None if remaining is None else remaining / 3600


def pick_network(specs: Sequence[Any]) -> Any:
    """保活出口：优先论坛账号自身，其次依赖共享 OAuth 的账号，否则直连。"""
    from core.account import NetworkSpec

    forum = [s for s in specs if (urlsplit(str(s.base_url or "")).hostname or "").lower() == "linux.do"]
    users = [s for s in specs if references_oauth(s)]
    chosen = (forum or users or [None])[0]
    return chosen.network if chosen is not None else NetworkSpec()


async def preflight(
    accounts: Iterable[str | OAuthReference],
    *,
    overlay: Overlay,
    oauth_state: Any,
    network: Any,
    proxy_groups: Sequence[Any] = (),
    default_proxy_group: str = "",
    window_seconds: float | None = None,
    log: Callable[[str], None] = lambda _m: None,
    force_verify: bool = False,
) -> list[KeepaliveResult]:
    """任务前静态判断，再按需准备浏览器/代理。旧 str 账户默认解释为 LinuxDO。"""
    window = renew_window_seconds() if window_seconds is None else max(0.0, float(window_seconds))
    references = _references(accounts)
    if (window <= 0 and not force_verify) or not references:
        return []
    if overlay.policy != CachePolicy.COMPATIBLE:
        return [KeepaliveResult(name, "skipped", message="覆写文件不可写", provider=provider)
                for provider, name in references]
    from runtime.engine import _shared_oauth_resolver

    resolver = _shared_oauth_resolver(overlay, oauth_state)
    due: list[OAuthReference] = []
    results: dict[OAuthReference, KeepaliveResult] = {}
    for provider, name in references:
        ref = (provider, name)
        try:
            state = resolver(provider, name).state
            remaining = remaining_seconds(state, provider=provider) if state else None
        except Exception as exc:
            results[ref] = KeepaliveResult(name, "error", message=type(exc).__name__, provider=provider)
            continue
        if not state:
            results[ref] = KeepaliveResult(name, "skipped", message="未捕获共享态", provider=provider)
        elif force_verify or (remaining is not None and remaining <= window):
            due.append(ref)
        elif remaining is not None:
            log(f"{provider}:{name} 共享登录态剩余 {remaining / 3600:.1f} 小时，无需续期")
            results[ref] = KeepaliveResult(name, "fresh", remaining / 3600, provider=provider)
        else:
            results[ref] = KeepaliveResult(name, "skipped", message="到期时间未知", provider=provider)

    def finish(message: str = "") -> list[KeepaliveResult]:
        if message:
            for provider, name in due:
                results[(provider, name)] = KeepaliveResult(name, "skipped", message=message, provider=provider)
        return [results[ref] for ref in references]

    if not due:
        return finish()
    from runtime import capabilities

    if "browser" not in capabilities.environment():
        log("共享 OAuth（linux.do / GitHub）需要验证，但本机没有可用浏览器，无法续期；请安装 Camoufox")
        return finish("缺少浏览器")

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
        renewed = await ensure_oauth_sessions(
            due, overlay=overlay, oauth_state=oauth_state, proxy=proxy, window_seconds=window,
            force_verify=force_verify, log=log,
        )
        results.update(((item.provider, item.account), item) for item in renewed)
        return finish()
    except Exception as exc:  # noqa: BLE001 - 保活失败不影响后续任务
        log(f"共享 OAuth 保活未完成（{type(exc).__name__}），保留现有登录态")
        return finish("保活未完成")
    finally:
        if bridge is not None:
            try:
                await asyncio.to_thread(bridge.close)
            except Exception:
                pass


def skip_in_child() -> bool:
    return os.environ.get(SKIP_ENV) == "1"


def mark_done(env: dict[str, str]) -> dict[str, str]:
    return {**env, SKIP_ENV: "1"}


__all__ += ["pick_network", "references_linuxdo", "remaining_seconds", "skip_in_child", "mark_done"]
