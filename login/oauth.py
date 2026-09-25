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

import asyncio
import time
from dataclasses import replace
from typing import Any

from browser.service import BrowserService, decode_state, encode_state
from core.errors import ConfigError, LoginRequired, TaskError, TransientError, VerificationRequired
from solvers.registry import CAP_BROWSER
from .base import Availability, LoginContext, LoginState, READY, unavailable
from .browser_state import harvest, settle_page, state_to_login

__all__ = ["OAuthLogin"]

#: 回站确认成功后仍需导出登录态（凭据 + 站点快照），而 ``storage_state()`` 实测可达 8s+。
#: 强制重登据此为「确认 + 导出」这段收尾预留预算：确认轮询提前收手、导出单次有界读取，
#: 避免把一次已确认成功的 OAuth 重登拖成「state_export 阶段超时」而丢弃。
_STATE_EXPORT_RESERVE = 12.0


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
            if not await _server_confirms_login(ctx, page):
                raise LoginRequired("OAuth 已回跳，但服务端未确认登录，保留旧认证信息")
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

    async def relogin(self, ctx: LoginContext, *, evidence: Any = None) -> LoginState:
        """强制走一条新 OAuth 链；永不读取站点快照，也不复用账号浏览器上下文。"""
        from browser import oauth_providers, storage_scope

        provider, account = self._provider(ctx)
        if provider not in oauth_providers.KNOWN_OAUTH_PROVIDERS:
            raise ConfigError(f"不支持的 OAuth 提供商：{provider}")
        if ctx.browser is None:
            raise ConfigError("强制重登需要浏览器，但本次运行未启用浏览器")
        shared = ctx.oauth_state(provider, account)
        if not shared:
            raise ConfigError(f"缺少 {provider}:{account} 的共享 OAuth 登录态（请先在管理界面捕获）")
        scoped = storage_scope.provider_storage_state(decode_state(shared), provider, base_url=ctx.base_url)
        if not oauth_providers.get_oauth_provider(provider).has_authenticated_state(scoped["cookies"]):
            raise LoginRequired(f"{provider}:{account} 的共享态不含该提供商的认证 Cookie，请重新捕获")

        # 给关闭旧/新上下文及结果写回保留预算；启动也在此总预算内。
        # 上限放宽到 240s：linux.do / connect.linux.do 授权页的 Cloudflare managed challenge
        # 放行本就慢（实测约 40s，datacenter 出口 IP 更久），旧的 180s 上限常在 CF 放行后就
        # 所剩无几，callback 阶段（等站点回跳换 token）来不及完成而超时。给足总预算让「慢 CF
        # + 回跳」这条链有机会走完；仍受账号 usable 预算约束，不会凭空拉长。
        usable = ctx.deadline.usable() if ctx.deadline is not None else None
        timeout = min(240.0, usable) if usable is not None else 240.0
        if timeout <= 0:
            raise LoginRequired("强制重登的剩余预算不足，未启动 OAuth", data={"stage": "relogin_start"})
        deadline = time.monotonic() + timeout
        policy = ctx.account.policy
        isolated = BrowserService(
            base_url=ctx.base_url, proxy=ctx.account.network.proxy,
            headless=policy.headless, humanize=policy.humanize,
            log=ctx.log, evidence=evidence,
            # 只返回已认证凭据，调用方应用 HTTP 成功后才能写覆盖层。
            persist=None,
        )
        fresh_ctx = replace(ctx, browser=isolated)
        stage = "browser_launch"
        cf_diagnostics: dict[str, Any] = {}

        async def capture_failure(lease: Any, page: Any) -> None:
            remaining = min(2.0, max(0.0, deadline - time.monotonic()))
            if evidence is None or remaining <= 0:
                return
            try:
                await asyncio.wait_for(lease.screenshot("relogin-failed.png", page=page), timeout=remaining)
            except Exception:
                pass

        try:
            async with asyncio.timeout(timeout):
                async with isolated.lease(reason="relogin", state_text=encode_state(scoped)) as lease:
                    page = await lease.new_page()
                    stage = "site_navigation"
                    # 只等导航「提交」而非 domcontentloaded：AgentRouter 这类站点在
                    # Cloudflare / 阿里云 WAF 后常常长时间不触发 domcontentloaded，死等它
                    # 会把整段重登预算耗在这一跳上，最终被外层总超时截断、误报「site_navigation
                    # 阶段超时」——这正是 goto 默认用 commit、settle_page 早已吃过的教训。
                    # 同时把本跳预算限定为剩余预算的一半（至多 30s），给后续 Cloudflare 求解
                    # 与 OAuth 回跳留足时间；传输层被重置/拒绝时 goto 自身会退避重试并抛出
                    # 可操作的 TransientError，走不到下面的兜底。
                    nav_budget = min(30.0, max(1.0, (deadline - time.monotonic()) * 0.5))
                    await lease.goto("", page=page, wait_until="commit",
                                     timeout=int(nav_budget * 1000))
                    # goto 吞掉自身超时后会正常返回、但页面仍停在 about:blank：连导航都没提交
                    # 到目标站点，说明这一跳压根没连通。按可重试的链路问题即时上报，而不是把
                    # 空白页喂给 Cloudflare 求解、最终误报成「人机验证未通过」误导用户换 IP。
                    if not storage_scope.same_origin(str(getattr(page, "url", "") or ""), ctx.base_url):
                        await capture_failure(lease, page)
                        raise TransientError(
                            "浏览器导航到站点未得到响应：多为出口 IP 或代理节点到站点的链路抖动，"
                            "本次未启动新登录，保留旧认证信息；请稍后重试或更换代理节点。",
                            data={"stage": stage, "timeout_stage": stage},
                        )
                    from browser import bypass

                    stage = "cloudflare"
                    if not await bypass.solve_cloudflare(
                        page, log=ctx.log, wait_seconds=min(30.0, max(0.0, deadline - time.monotonic())),
                        diagnostics=cf_diagnostics,
                    ):
                        await capture_failure(lease, page)
                        raise _oauth_error(provider, account, {"cloudflare": True, "cf_diagnostics": cf_diagnostics})
                    stage = "oauth"
                    ctx.log(f"在隔离会话中重新执行 {provider}:{account} OAuth…")
                    link = await lease.oauth(provider, page=page, require_fresh=True, deadline=deadline)
                    if not link.get("landed_back") or not link.get("fresh_authorization"):
                        await capture_failure(lease, page)
                        raise _oauth_error(provider, account, link)
                    stage = "server_confirmation"
                    if not await _confirm_after_relogin(fresh_ctx, page, deadline):
                        await capture_failure(lease, page)
                        raise LoginRequired("OAuth 已回跳，但服务端未确认新会话，保留旧认证信息",
                                            data={"stage": stage})
                    stage = "state_export"
                    # 登录已确认成功。此前 harvest + export_state 会各调一次 storage_state()
                    # （实测可达 8s+），叠加起来常拖过外层截止点，把已确认的成功翻转成
                    # 「state_export 阶段超时」而白白丢弃。这里只取一次状态，兼作凭据提取与
                    # 快照；有界读取，快照编码失败也只是本次不缓存，不否定这次已确认的登录。
                    export_budget = max(1.0, min(_STATE_EXPORT_RESERVE, deadline - time.monotonic()))
                    storage_state = await asyncio.wait_for(
                        lease.context.storage_state(), timeout=export_budget,
                    )
                    access = storage_scope.storage_access_token(storage_state, base_url=ctx.base_url)
                    refresh = storage_scope.storage_refresh_token(storage_state, base_url=ctx.base_url)
                    cookie = storage_scope.site_cookie_string(storage_state.get("cookies") or [], ctx.base_url)
                    state = state_to_login(
                        fresh_ctx, method=self.id, access=access, refresh=refresh, cookie=cookie,
                        verified=True, origin="oauth", note=f"{provider}:{account} 强制 OAuth 重登成功",
                    )
                    lease.mark_authenticated()
                    try:
                        snapshot = encode_state(storage_state)
                    except Exception:
                        snapshot = ""
                    return replace(state, credentials={**state.credentials, "browser_state": snapshot})
        except TimeoutError as exc:
            if stage == "cloudflare":
                cf_diagnostics.setdefault("timeout_stage", "cloudflare")
                raise _oauth_error(provider, account, {"cloudflare": True, "cf_diagnostics": cf_diagnostics}) from exc
            raise TransientError(f"强制重登在 {stage} 阶段超时，未完成新登录，保留旧认证信息",
                                 data={"stage": stage, "timeout_stage": stage}) from exc
        finally:
            # 即使启动/恢复失败或外层取消，也不续存未认证快照。
            remaining = ctx.deadline.remaining() if ctx.deadline is not None else None
            close_timeout = min(8.0, remaining) if remaining is not None else 8.0
            try:
                await asyncio.wait_for(isolated.aclose(), timeout=max(0.01, close_timeout))
            except Exception:
                ctx.log("隔离浏览器收尾未完成，未写入任何未认证快照")


_CONFIRM_LOGIN_JS = """async ([baseUrl, path, uid, timeoutMs]) => {
    const headers = { Accept: 'application/json' };
    let token = localStorage.getItem('auth_token') || localStorage.getItem('access_token') || '';
    let userId = uid;
    if (!token) {
        // New API 登录态存在 localStorage 的 'user' 对象里（含 access_token / id）。
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
    from browser.storage_scope import same_origin

    if not same_origin(str(page.url), ctx.base_url):
        return False
    remaining = ctx.deadline.remaining() if ctx.deadline is not None else None
    timeout = min(15.0, remaining) if remaining is not None else 15.0
    if timeout <= 0:
        return False
    try:
        confirmed = await asyncio.wait_for(page.evaluate(
            _CONFIRM_LOGIN_JS,
            [ctx.base_url.rstrip("/"), path, str(ctx.args.get("user_id") or ""), max(1, int(timeout * 1000))],
        ), timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - 校验失败只意味着「没确认」，照常走 OAuth
        ctx.log(f"会话校验未能完成（{type(exc).__name__}），继续 OAuth 回跳")
        return False
    return bool(confirmed)


async def _confirm_after_relogin(ctx: LoginContext, page: Any, deadline: float) -> bool:
    """弹窗式 OAuth 的回调页要用 code 异步换取 token 再写入登录态（New API 存在
    localStorage 的 'user' 对象里，同源共享给 opener）；观察到回调 URL 时往往尚未
    就绪，单次确认会把「还在换 token」误判成未登录。这里在剩余预算内轮询，直到
    服务端认账或时间不够——给回调页完成换取与写入的时间。

    收手时刻提前 ``_STATE_EXPORT_RESERVE``：确认成功后还要导出登录态（凭据 + 快照），
    而 ``storage_state()`` 实测可达 8s+。若把预算耗尽在轮询上，导出阶段就会撞外层
    截止点，把一次已确认成功的登录反而拖成「state_export 阶段超时」而白白丢弃。
    """
    interval = 1.0
    while True:
        if await _server_confirms_login(ctx, page):
            return True
        if time.monotonic() >= deadline - _STATE_EXPORT_RESERVE:
            return False
        remaining = ctx.deadline.remaining() if ctx.deadline is not None else None
        if remaining is not None and remaining <= _STATE_EXPORT_RESERVE:
            return False
        await asyncio.sleep(interval)


def _oauth_error(provider: str, account: str, link: dict[str, Any]) -> TaskError:
    """按实际失败阶段归因；不从「遇到 CF」推断出口 IP 信誉或暴露授权 URL。"""
    flags = (
        "landed_back", "fresh_authorization", "need_human", "cloudflare", "waf_blocked",
        "provider_session_present", "client_id_missing", "driver_crashed", "clicked",
    )
    safe = {key: link[key] for key in flags if isinstance(link.get(key), (bool, type(None))) and key in link}
    safe["provider"] = provider
    for key in ("stage", "timeout_stage"):
        value = link.get(key)
        if isinstance(value, str) and value and all(c.isalnum() or c in "_-" for c in value):
            safe[key] = value[:80]
    diagnostics = link.get("cf_diagnostics") or {}
    # 诊断值只接受内部阶段枚举；任意外部文本/URL/凭据都不进入结果。
    safe_cf = {}
    if isinstance(diagnostics, dict):
        for key in ("stage", "target_kind", "clicked", "timeout_stage", "reason", "blocked"):
            value = diagnostics.get(key)
            if isinstance(value, bool):
                safe_cf[key] = value
            elif isinstance(value, str) and value and all(c.isalnum() or c in "_-" for c in value):
                safe_cf[key] = value[:80]
    if safe_cf:
        safe["cf_diagnostics"] = safe_cf
    data = {"oauth": safe}
    if link.get("need_human"):
        from browser.oauth_flow import _provider_login_message

        return LoginRequired(_provider_login_message(safe), data=data)
    if link.get("waf_blocked") or safe_cf.get("blocked") is True:
        return TaskError("页面明确显示安全规则拒绝访问，OAuth 无法完成；请检查站点访问限制或代理。",
                         reason="blocked", data=data)
    if link.get("cloudflare"):
        stage = safe_cf.get("timeout_stage") or safe_cf.get("stage") or safe_cf.get("reason") or "challenge"
        clicked = "已完成点击，等待验证放行" if safe_cf.get("clicked") else "尚未完成有效点击"
        return VerificationRequired(
            f"{provider} OAuth 的 Cloudflare 验证尚未通过（阶段：{stage}；{clicked}）；"
            "本次未完成授权，不能据此判断 IP 信誉。", data=data,
        )
    if link.get("state_error") or link.get("client_id_missing"):
        return ConfigError(f"站点未开启 {provider} OAuth，或未能获取新的授权参数。", data=data)
    if link.get("timeout_stage"):
        return TransientError(f"{provider} OAuth 在 {safe.get('timeout_stage', '授权')} 阶段未在剩余预算内完成，保留旧认证信息。",
                              data=data)
    return LoginRequired(
        f"{provider}:{account} 未完成本次新 OAuth 回跳；请检查共享登录态和站点授权入口。", data=data,
    )
