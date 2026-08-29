"""登录方式：用共享 OAuth 登录态（linux.do / GitHub）完成站点回跳。

共享登录态存在 ACCOUNTS 的 ``oauth_states`` 里，一份 provider 登录态可供多个站点复用
—— 这是本工具最省事的一条路径：不用为每个站点单独维护账号。

与旧实现的差别：旧代码在三处各写了一遍 OAuth 触发（``actions/relogin.py``、
``browser/session.run_oauth_checkin``、``script_runner`` 的 OAuth 预处理），且脚本
若声明 ``script_handles_oauth`` 还要在 action 层特判。现在只有一条路径：登录阶段完成
回跳，任务阶段拿到的就是已登录页面；需要自管 OAuth 的模板把 ``login`` 阶段配成
``off`` 并在 ``run()`` 里自己走。
"""

from __future__ import annotations

from typing import Any

from core.errors import LoginRequired, TaskError, VerificationRequired
from solvers.registry import CAP_BROWSER
from .base import Availability, LoginContext, LoginState, READY, unavailable
from .browser_state import harvest, settle_page, state_to_login

__all__ = ["OAuthLogin"]


class OAuthLogin:
    id = "oauth"
    requires = frozenset({CAP_BROWSER})

    def _provider(self, ctx: LoginContext) -> tuple[str, str]:
        spec = ctx.account.login
        provider = str(ctx.args.get("provider") or spec.provider or "linuxdo").strip().lower()
        account = str(ctx.args.get("account") or spec.account or "default").strip()
        return provider, account

    def _state_text(self, ctx: LoginContext) -> str:
        provider, account = self._provider(ctx)
        # 站点级快照优先：首次回跳后我们会把「provider 登录态 + 本站会话」整体存下来，
        # 复用它可以跳过整段 OAuth（含 Cloudflare 挑战）。没有才回退共享 provider 态。
        return str(ctx.credentials.browser_state or "").strip() or ctx.oauth_state(provider, account)

    def available(self, ctx: LoginContext, option: Any = None) -> Availability:
        provider, account = self._provider(ctx)
        if ctx.browser is None:
            return unavailable("本次运行未启用浏览器")
        if not self._state_text(ctx):
            return unavailable(f"缺少 {provider}:{account} 的共享 OAuth 登录态（请先在管理界面捕获）")
        return READY

    async def authenticate(self, ctx: LoginContext, option: Any = None) -> LoginState:
        provider, account = self._provider(ctx)
        async with ctx.browser.lease(reason="oauth", state_text=self._state_text(ctx)) as lease:
            page = await lease.new_page()
            await settle_page(ctx, lease, page)

            # 已经是登录态就不必再走一遍 OAuth：省掉一次跳转与一次可能的 Cloudflare。
            access, refresh, cookie = await harvest(ctx, lease)
            if access or cookie:
                ctx.log(f"站点会话仍然有效，跳过 {provider} OAuth 回跳")
                state = state_to_login(
                    ctx, method=self.id, access=access, refresh=refresh, cookie=cookie,
                    verified=False, origin="oauth", note=f"复用已缓存的 {provider} 站点会话",
                )
                return state

            ctx.log(f"通过 {provider}:{account} 完成 OAuth 登录回跳…")
            link = await lease.oauth(provider, page=page)
            if not link.get("landed_back"):
                raise _oauth_error(provider, account, link)
            lease.mark_authenticated()
            try:
                await lease.dismiss_popups(page=page)
            except Exception:
                pass
            access, refresh, cookie = await harvest(ctx, lease)
            state = state_to_login(
                ctx, method=self.id, access=access, refresh=refresh, cookie=cookie,
                verified=True, origin="oauth", note=f"{provider}:{account} OAuth 登录成功",
            )
        return state


def _oauth_error(provider: str, account: str, link: dict[str, Any]) -> TaskError:
    """把 OAuth 失败翻译成**确定原因**，而不是一句「自动登录未完成」。

    区分三种成因，因为用户要做的事完全不同：
    - Cloudflare 挑战 / 需要人工 → 需人机验证，换出口 IP 或手工过一次；
    - provider 登录态失效 → 重新捕获共享登录态；
    - 站点未开启该 OAuth → 改配置。
    """
    from core.errors import ConfigError

    if link.get("cloudflare") or link.get("need_human"):
        return VerificationRequired(
            f"{provider} OAuth 回跳被人机验证拦下（Cloudflare 或需人工确认），本次未能自动完成。",
            data={"oauth": dict(link)},
        )
    if link.get("waf_blocked"):
        error = TaskError(
            "出口 IP 被站点安全规则持续拒绝，OAuth 无法完成；请更换代理节点后重试。",
            data={"oauth": dict(link)},
        )
        error.reason = "blocked"
        return error
    if link.get("state_error") or link.get("client_id_missing"):
        return ConfigError(
            f"站点未开启 {provider} OAuth 登录，或未能获取授权参数（{link.get('state_error') or '缺少 client_id'}）。",
            data={"oauth": dict(link)},
        )
    return LoginRequired(
        f"{provider}:{account} 的共享登录态未能完成回跳，多半已失效；请在管理界面重新捕获。",
        data={"oauth": dict(link)},
    )
