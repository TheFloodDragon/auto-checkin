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

from typing import Any

from core.errors import LoginRequired
from solvers.registry import CAP_BROWSER
from ._common import auth_headers, cookie_headers
from .base import Availability, LoginContext, LoginState, READY, unavailable

__all__ = ["BrowserStateLogin", "harvest", "settle_page"]


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
                await waf.solve_waf(page, ctx.base_url, ctx.log, rounds=2)
            if waf.waf_is_blocked(page):
                # 熔断意味着出口 IP 被持续风控：继续点下去只是空耗，换代理才有意义。
                raise LoginRequired(
                    "出口 IP 被站点安全规则持续拒绝，浏览器同样无法通过；请更换代理节点后重试。",
                    reason="blocked",
                )
            return
        await bypass.solve_cloudflare(page, log=ctx.log, wait_seconds=10)
    except LoginRequired:
        raise
    except Exception as exc:  # noqa: BLE001 - 过盾失败不该掩盖后续的真实认证结论
        ctx.log(f"防护页处理未完成（{type(exc).__name__}: {exc}），继续尝试读取登录态")


async def harvest(ctx: LoginContext, lease: Any) -> tuple[str, str, str]:
    """从当前浏览器上下文取出 (access_token, refresh_token, cookie)，均限定本站。"""
    from browser import storage_scope

    state = await lease.context.storage_state()
    access = storage_scope.storage_access_token(state, base_url=ctx.base_url)
    refresh = storage_scope.storage_refresh_token(state, base_url=ctx.base_url)
    cookie = storage_scope.site_cookie_string(state.get("cookies") or [], ctx.base_url)
    return access, refresh, cookie


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
            state = state_to_login(
                ctx,
                method=self.id,
                access=access,
                refresh=refresh,
                cookie=cookie,
                # 快照可能已过期，服务端还没确认过；由首个业务请求来判定。
                verified=False,
                origin="browser",
            )
        return state
