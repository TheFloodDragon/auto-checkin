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
            # 但「拿到了 cookie」不等于「已登录」：站点的风控层（阿里云 WAF 的
            # acw_tc、Cloudflare 的 cf_clearance）对匿名访问也会下发 cookie。实测
            # 匿名访问 agentrouter.org 必定拿到一个 acw_tc，于是这里曾把它当成有效
            # 会话、整段跳过 OAuth 回跳，随后每个业务请求都 401。只有服务端认账才算数。
            access, refresh, cookie = await harvest(ctx, lease)
            if access or cookie:
                if await _server_confirms_login(ctx, page):
                    ctx.log(f"站点会话经服务端确认仍然有效，跳过 {provider} OAuth 回跳")
                    return state_to_login(
                        ctx, method=self.id, access=access, refresh=refresh, cookie=cookie,
                        verified=True, origin="oauth", note=f"复用已缓存的 {provider} 站点会话",
                    )
                ctx.log("已有 cookie 未通过服务端登录校验（可能只是风控 cookie），继续 OAuth 回跳")

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


_CONFIRM_LOGIN_JS = """async ([baseUrl, path, uid, timeoutMs]) => {
    const headers = { Accept: 'application/json' };
    if (uid) headers['New-Api-User'] = String(uid);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const r = await fetch(baseUrl + path, {
            credentials: 'include',
            headers,
            signal: controller.signal,
        });
        const text = await r.text();
        // WAF/Cloudflare 的挑战页会以 200 返回 HTML，不能算登录成功。
        if (/aliyun_waf|slidecaptcha|acw_sc__|Just a moment|cf-challenge/i.test(text)) {
            return false;
        }
        if (!r.ok) return false;
        let body = null;
        try { body = JSON.parse(text); } catch (_) { return false; }
        if (body && body.success === false) return false;
        const data = body && typeof body.data === 'object' && body.data ? body.data : body;
        // 认账的标志是回体里真的有这个用户，而不只是 HTTP 200。
        return Boolean(data && (data.id ?? data.user_id ?? data.username ?? data.email));
    } catch (_) {
        return false;
    } finally {
        clearTimeout(timer);
    }
}"""


async def _server_confirms_login(ctx: LoginContext, page: Any) -> bool:
    """在页面上下文请求模板声明的 ``user`` 端点，确认服务端是否认这个会话。

    只有服务端认账才算登录成功。浏览器里存在 cookie 并不足以说明问题：站点的风控层
    对匿名访问同样会下发 cookie（实测 agentrouter.org 必回一个 acw_tc），据此判定
    「会话有效」会让 OAuth 回跳被整段跳过，后续业务请求全部 401。

    模板没声明 ``user`` 端点时返回 False：宁可多走一次 OAuth 回跳，也不要在无法验证
    的情况下假定已登录——前者只是慢，后者会让整个任务以 401 收场。
    """
    path = ctx.endpoint("user").strip()
    if not path:
        ctx.log("模板未声明 [endpoints].user，无法验证既有会话，按未登录处理")
        return False
    try:
        confirmed = await page.evaluate(
            _CONFIRM_LOGIN_JS,
            [ctx.base_url.rstrip("/"), path, str(ctx.args.get("user_id") or ""), 15000],
        )
    except Exception as exc:  # noqa: BLE001 - 校验失败只意味着「没确认」，照常走 OAuth
        ctx.log(f"会话校验未能完成（{type(exc).__name__}），继续 OAuth 回跳")
        return False
    return bool(confirmed)


def _oauth_error(provider: str, account: str, link: dict[str, Any]) -> TaskError:
    """把 OAuth 失败翻译成**确定原因**，而不是一句「自动登录未完成」。

    区分四种成因，因为用户要做的事完全不同：
    - 停在第三方登录页（need_human）→ 共享登录态失效，重新捕获；
    - Cloudflare 挑战未过（cloudflare）→ 需人机验证，多为出口 IP 信誉低，换代理；
    - 出口 IP 被 WAF 持续拒绝（waf_blocked）→ 换代理节点；
    - 站点未开启该 OAuth → 改配置。

    ``need_human`` 与 ``cloudflare`` 必须分开：前者是浏览器停在了 provider 自己的
    登录页，说明会话没被 provider 认账（登录态失效），重新捕获登录态才有用；后者是
    人机验证没过，重新捕获没用、得换 IP。旧实现把两者并列都报 need_verification，
    于是 AgentRouter(G) 的 GitHub 会话失效被误报成「被 Cloudflare 拦下」，用户按提示
    换 IP 反复无效，真正该做的重新捕获登录态反而没被提示。need_human 只在检测到
    provider 登录页标记时置位，含义单一，因此优先判定。
    """
    from core.errors import ConfigError

    if link.get("need_human"):
        # 复用签到结果路径的同一套文案：会区分「Cookie 没进浏览器」与「已装载但被拒」，
        # 两者的排查动作不同（查加载链路 vs 重新捕获）。
        from browser.oauth_flow import _provider_login_message

        return LoginRequired(_provider_login_message(link), data={"oauth": dict(link)})
    if link.get("cloudflare"):
        return VerificationRequired(
            f"{provider} OAuth 回跳被 Cloudflare 人机验证拦下，本次未能自动完成；"
            "多为数据中心/CI 出口 IP 信誉过低，请更换住宅代理后重试。",
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
