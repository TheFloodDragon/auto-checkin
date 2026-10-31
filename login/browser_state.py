"""登录方式：恢复浏览器登录态快照，并从中派生可用于纯 HTTP 的认证。

用途有二：
1. Sub2API 系：localStorage 里的 ``auth_token`` 就是接口凭据，取出来即可纯 HTTP 调用；
2. New API 系过 WAF：浏览器执行一次 JS 挑战拿到 ``cf_clearance`` / 阿里云 ``acw_*``
   Cookie，后续 HTTP 请求带上它们才不会被重新挑战。

取 token 时**必须限定站点 origin**：跑完的 storage_state 常含多个 origin（站点自身 +
共享 OAuth provider + 第三方 iframe），而 ``auth_token`` 这个键名各站通用；不限定就会
拿着别站身份去请求，表现为「明明刚捕获成功却一直登录失效」。
"""

from __future__ import annotations

import asyncio
from typing import Any

from core.errors import LoginRequired, VerificationRequired
from solvers.registry import CAP_BROWSER
from ._common import auth_headers, cookie_headers
from .base import Availability, LoginContext, LoginState, READY, unavailable

__all__ = ["BrowserStateLogin", "harvest", "probe_server", "settle_page"]


async def settle_page(ctx: LoginContext, lease: Any, page: Any) -> None:
    """把页面推进到「可读业务响应」的状态：过 WAF / Cloudflare 挑战、关弹窗。"""
    from browser import bypass, waf

    await lease.goto("", page=page, wait_until="domcontentloaded", timeout=60000)
    try:
        await lease.dismiss_popups(page=page)
    except Exception:
        pass
    try:
        if await waf.is_waf_html(page):
            if not waf.waf_is_blocked(page):
                ctx.log("检测到阿里云 WAF 挑战，尝试求解")
                if not await waf.solve_waf(page, ctx.base_url, ctx.log, rounds=2):
                    raise VerificationRequired("防护页尚未确认通过，保留会话，不重新认证", data=waf.waf_circuit(page).get("challenge") or {"preserve_page": True, "retry_allowed": False})
            if waf.waf_is_blocked(page):
                # 熔断意味着出口 IP 被持续风控：继续点下去只是空耗，换代理才有意义。
                raise VerificationRequired(
                    "出口 IP 被站点安全规则持续拒绝，浏览器同样无法通过；请更换代理节点后重试。",
                    reason="blocked",
                )
            return
        from runtime.events import emit_challenge, challenge_data
        result = await bypass.TurnstileBypass(log=ctx.log).solve_result(page, mode="page_access", timeout=10)
        emit_challenge(result)
        if not result.ok:
            raise VerificationRequired(result.message or "Cloudflare 验证尚未完成", data=challenge_data(result), evidence=getattr(result, "evidence", None))
    except (LoginRequired, VerificationRequired):
        raise
    except Exception as exc:  # noqa: BLE001 - 未确认防护状态不能触发认证回退
        ctx.log(f"防护页观察未完成（{type(exc).__name__}），保留已有登录态")
        raise VerificationRequired("防护页状态尚未确认，保留当前页面与登录态",
                                   data={"status": "unknown", "preserve_page": True, "retry_allowed": False}) from exc


async def harvest(ctx: LoginContext, lease: Any) -> tuple[str, str, str]:
    """从当前浏览器上下文取出 (access_token, refresh_token, cookie)，均限定本站。"""
    from browser import storage_scope

    state = await lease.context.storage_state()
    access = storage_scope.storage_access_token(state, base_url=ctx.base_url)
    refresh = storage_scope.storage_refresh_token(state, base_url=ctx.base_url)
    cookie = storage_scope.site_cookie_string(state.get("cookies") or [], ctx.base_url)
    return access, refresh, cookie


#: 在页面上下文向模板声明的 ``user`` 端点发一次请求，只回答一个问题：
#: 服务端认不认这个会话。刻意三态：``ok`` / ``rejected`` / ``unknown``——
#: 「没确认」和「被拒绝」要分开，只有后者才值得换下一种登录方式。
_PROBE_JS = """async ([baseUrl, path, uid, timeoutMs]) => {
    const headers = { Accept: 'application/json' };
    let token = localStorage.getItem('auth_token') || localStorage.getItem('access_token') || '';
    let userId = uid;
    if (!token) {
        try {
            const u = JSON.parse(localStorage.getItem('user') || 'null');
            if (u) {
                token = u.access_token || u.token || '';
                if (!userId && u.id != null) userId = String(u.id);
            }
        } catch (_) {}
    }
    if (userId) headers['New-Api-User'] = String(userId);
    if (token) headers.Authorization = 'Bearer ' + token;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const r = await fetch(baseUrl + path, {
            credentials: 'include', headers, signal: controller.signal,
        });
        // 风控页会以 200 返回 HTML：那不是「拒绝」，只是这次没看清。
        const raw = await r.text();
        if (/aliyun_waf|slidecaptcha|acw_sc__|Just a moment|cf-challenge|cf-chl-|challenge-platform|Checking your browser|verify you are human|Access denied/i.test(raw)) return 'unknown';
        if (r.status === 403 && raw.trim().startsWith('<')) return 'unknown';
        if (r.status === 401 || r.status === 403) return 'rejected';
        if (!r.ok) return 'unknown';
        let body = null;
        try { body = JSON.parse(raw); } catch (_) { return 'unknown'; }
        if (body && body.success === false) return 'rejected';
        const data = body && typeof body.data === 'object' && body.data ? body.data : body;
        // 认账的标志是回体里真的有这个用户，而不只是 HTTP 200。
        return (data && (data.id ?? data.user_id ?? data.username ?? data.email)) ? 'ok' : 'unknown';
    } catch (_) {
        return 'unknown';
    } finally {
        clearTimeout(timer);
    }
}"""


async def probe_server(ctx: LoginContext, page: Any) -> str:
    """向站点的 ``user`` 端点确认浏览器会话，返回 ok / rejected / unknown。

    为什么值得多这一次请求：保存的登录态快照可能藏着一个**早已过期的会话 Cookie**
    （实测 AnyRouter 的 ``session`` 已过期六天）。它让浏览器照样过 WAF、照样拿到
    Cookie，于是 browser_state 一路报「登录成功」，后续每个业务请求都 401，而配置里
    的 OAuth 兜底因为「已经登录成功」永远不会被尝试。这里把「服务端明确拒绝」这个
    事实提早暴露出来，候选链才能换下一种方式。
    """
    from browser.storage_scope import same_origin

    path = ctx.endpoint("user").strip()
    if not path:
        return "unknown"
    if not same_origin(str(getattr(page, "url", "") or ""), ctx.base_url):
        return "unknown"
    remaining = ctx.deadline.remaining() if ctx.deadline is not None else None
    timeout = min(10.0, remaining) if remaining is not None else 10.0
    if timeout <= 0:
        return "unknown"
    try:
        result = await asyncio.wait_for(
            page.evaluate(
                _PROBE_JS,
                [ctx.base_url.rstrip("/"), path, str(ctx.args.get("user_id") or ""), max(1, int(timeout * 1000))],
            ),
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001 - 探测失败只等于「没看清」，不影响原有判定
        ctx.log(f"浏览器会话探测未完成（{type(exc).__name__}），按未确认处理")
        return "unknown"
    return result if result in {"ok", "rejected"} else "unknown"


def state_to_login(
    ctx: LoginContext,
    *,
    method: str,
    access: str,
    refresh: str,
    cookie: str,
    verified: bool,
    origin: str,
    note: str = "",
) -> LoginState:
    """把浏览器里拿到的东西组装成 LoginState；token 优先于 Cookie。"""
    credentials: dict[str, str] = {}
    if access:
        credentials["access_token"] = access
    if refresh:
        credentials["refresh_token"] = refresh
    if cookie:
        credentials["session_cookie"] = cookie
    if access:
        headers = auth_headers(ctx, access)
    elif cookie:
        headers = cookie_headers(ctx, cookie)
    else:
        raise LoginRequired("浏览器登录态里没有可用的 token 或 Cookie，登录态可能已失效")
    return LoginState(
        method=method,
        headers=headers,
        credentials=credentials,
        verified=verified,
        origin=origin,
        note=note or ("已从浏览器取得 token" if access else "已从浏览器取得站点 Cookie"),
    )


class BrowserStateLogin:
    id = "browser_state"
    requires = frozenset({CAP_BROWSER})

    def available(self, ctx: LoginContext, option: Any = None) -> Availability:
        if not str(ctx.credentials.browser_state or "").strip():
            return unavailable("没有站点登录态快照（可在管理界面「捕获登录态」）")
        if ctx.browser is None:
            return unavailable("本次运行未启用浏览器")
        return READY

    async def authenticate(self, ctx: LoginContext, option: Any = None) -> LoginState:
        async with ctx.browser.lease(reason="login", state_text=ctx.credentials.browser_state) as lease:
            page = await lease.new_page()
            await settle_page(ctx, lease, page)
            access, refresh, cookie = await harvest(ctx, lease)
            verdict = await probe_server(ctx, page) if (access or cookie) else "unknown"
            if verdict == "rejected":
                # 服务端明确拒绝：这个快照里的会话已经作废，别把它当成「登录成功」。
                # 抛 need_login 让候选链继续尝试下一种方式（如配置里排在其后的 OAuth），
                # 而不是让任务带着一个死 Cookie 一路 401 到底。
                raise LoginRequired(
                    "保存的浏览器登录态已被站点拒绝（会话已过期），改试其它登录方式",
                    reason="need_login",
                )
            if verdict == "ok":
                ctx.log("浏览器登录态已经服务端确认仍然有效")
            state = state_to_login(
                ctx,
                method=self.id,
                access=access,
                refresh=refresh,
                cookie=cookie,
                # 服务端认账过才算 verified；只是从快照里读出来仍要由首个业务请求判定。
                verified=verdict == "ok",
                origin="browser",
            )
        return state
