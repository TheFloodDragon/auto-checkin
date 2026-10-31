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
from dataclasses import dataclass, replace
from typing import Any

from browser.service import BrowserService, decode_state, encode_state
from core.errors import ConfigError, LoginRequired, TaskError, TransientError, VerificationRequired
from solvers.registry import CAP_BROWSER
from .base import Availability, LoginContext, LoginState, OAuthStateUpdate, READY, unavailable
from .browser_state import settle_page, state_to_login

__all__ = ["OAuthLogin", "oauth_state_update"]


def oauth_state_update(
    source: Any,
    storage_state: dict[str, Any] | None,
    provider: str,
    *,
    base_url: str = "",
    fresh_authorization: bool = False,
    same_identity: bool = False,
) -> OAuthStateUpdate | None:
    """构造供引擎在 HTTP adopt 成功后写回的共享 OAuth 更新。"""
    if source is None or not (fresh_authorization or same_identity):
        return None
    if str(getattr(source, "provider", "") or "").strip().lower() != str(provider or "").strip().lower():
        return None
    try:
        from browser import storage_scope
        previous_text = str(getattr(source, "state", "") or "")
        previous = decode_state(previous_text)
        scoped = storage_scope.provider_renewal_state(storage_state, provider, base_url=base_url)
        if not storage_scope.provider_state_rotated(previous, scoped, provider):
            return None
        state = encode_state(scoped)
    except Exception:
        return None
    return OAuthStateUpdate(
        source=source,
        state=state,
        fresh_authorization=bool(fresh_authorization),
        same_identity=bool(same_identity),
    )


#: 回站确认成功后仍需导出登录态（凭据 + 站点快照），而 ``storage_state()`` 实测可达 8s+。
#: 强制重登据此为「确认 + 导出」这段收尾预留预算：确认轮询提前收手、导出单次有界读取，
#: 避免把一次已确认成功的 OAuth 重登拖成「state_export 阶段超时」而丢弃。
_STATE_EXPORT_RESERVE = 12.0
_SERVER_CONFIRM_RESERVE = 15.0
_RELOGIN_CLOSE_RESERVE = 8.0

#: 隔离会话首跳导航（到目标站点）未提交时的最大尝试次数（含首次）。首跳未提交多是
#: 链路瞬时抖动，重载一次常能连上；仍受外层 deadline 约束，不会拉长整轮。
_NAV_MAX_ATTEMPTS = 2
#: 仅当剩余预算高于此下限时才追加一次重载重试；不够就直接收敛为「站点不可达」。
_NAV_RETRY_MIN_SECONDS = 20.0
#: 重载前的短暂退避：立刻重试常撞进同一个失败窗口。
_NAV_RETRY_BACKOFF_SECONDS = 1.5


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
        # 复用它可以跳过整段 OAuth（含 Cloudflare 挑战）。没有才解析共享 provider 态。
        cached = str(ctx.credentials.browser_state or "").strip()
        if cached:
            return cached
        shared, _source = ctx.resolve_oauth(provider, account)
        return str(shared or "")

    def available(self, ctx: LoginContext, option: Any = None) -> Availability:
        provider, account = self._provider(ctx)
        if ctx.browser is None:
            return unavailable("本次运行未启用浏览器")
        if not self._state_text(ctx):
            return unavailable(f"缺少 {provider}:{account} 的共享 OAuth 登录态（请先在管理界面捕获）")
        return READY

    async def authenticate(self, ctx: LoginContext, option: Any = None) -> LoginState:
        provider, account = self._provider(ctx)
        cached_state = str(ctx.credentials.browser_state or "").strip()
        shared_source = None
        if cached_state:
            state_text = cached_state
        else:
            from browser import storage_scope

            state_text, shared_source = ctx.resolve_oauth(provider, account)
            # 共享态只恢复提供商来源；已有上下文可能混入前序任务/站点快照的
            # 另一份提供商身份，不能仅凭这次读取了共享态就授权共享写回。
            if bool(getattr(ctx.browser, "started", False)):
                shared_source = None
            state_text = encode_state(storage_scope.provider_storage_state(
                decode_state(state_text), provider, base_url=ctx.base_url,
            ))
        async with ctx.browser.lease(reason="oauth", state_text=state_text) as lease:
            if not cached_state and shared_source is not None:
                _track(lease, provider, account, state_text)
            page = await lease.new_page()
            await settle_page(ctx, lease, page)

            # 已经是登录态就不必再走一遍 OAuth：省掉一次跳转与一次可能的 Cloudflare。
            # 但「拿到了 cookie」不等于「已登录」：站点的风控层（阿里云 WAF 的
            # acw_tc、Cloudflare 的 cf_clearance）对匿名访问也会下发 cookie。实测
            # 匿名访问 agentrouter.org 必定拿到一个 acw_tc，于是这里曾把它当成有效
            # 会话、整段跳过 OAuth 回跳，随后每个业务请求都 401。只有服务端认账才算数。
            from browser import storage_scope
            storage_state = await lease.context.storage_state()
            candidate = storage_scope.storage_login_candidate(storage_state, base_url=ctx.base_url)
            cookie = storage_scope.site_cookie_string(storage_state.get("cookies") or [], ctx.base_url)
            if candidate["conflict"]:
                raise LoginRequired("站点浏览器凭据身份冲突，未启动授权", reason="identity_mismatch")
            if candidate["access_token"] or cookie:
                confirmation = _confirmation(await _server_confirms_login(ctx, page))
                if confirmation:
                    ctx.log(f"站点会话经服务端确认仍然有效，跳过 {provider} OAuth 回跳")
                    return _prepared_login(ctx, storage_state, confirmation, note=f"复用已缓存的 {provider} 站点会话")
                if confirmation.status == "unknown":
                    raise TransientError("站点会话暂时无法确认，未重放 OAuth，保留旧认证信息", data={"stage": "server_confirmation"})
                ctx.log("已有会话被服务端明确拒绝，继续 OAuth 回跳")

            if cached_state:
                # 站点会话已失效才需要提供商：此时快照里的提供商 Cookie 可能早被轮换作废，
                # 共享态更新就换成它（只在真的要访问提供商前读取共享态）。
                shared_source = await _refresh_provider_cookies(ctx, lease, provider, account, cached_state)
            ctx.log(f"通过 {provider}:{account} 完成 OAuth 登录回跳…")
            link = await lease.oauth(provider, page=page, require_fresh=True)
            if not link.get("landed_back"):
                raise _oauth_error(provider, account, link)
            # 弹窗回调先到达 URL，再异步换取并写入凭据；普通 OAuth 与强制
            # 重登使用相同的有界确认，避免第一次 GET 过早返回未登录而丢掉回跳。
            remaining = ctx.deadline.remaining() if ctx.deadline is not None else (
                _SERVER_CONFIRM_RESERVE + _STATE_EXPORT_RESERVE
            )
            export_reserve = min(_STATE_EXPORT_RESERVE, max(0.0, remaining) * 0.15)
            confirm_budget = min(_SERVER_CONFIRM_RESERVE, max(0.0, remaining - export_reserve))
            confirmation = _confirmation(await _confirm_after_relogin(
                ctx, page, time.monotonic() + confirm_budget + export_reserve,
                export_reserve=export_reserve, handoff=getattr(lease, "_oauth_handoff", None),
            ))
            if not confirmation:
                if confirmation.status == "unknown":
                    raise TransientError("OAuth 已回跳，但服务端暂时无法确认会话，不重放授权", data={"stage": "server_confirmation"})
                raise LoginRequired("OAuth 已回跳，但服务端未确认登录，保留旧认证信息")
            try:
                await lease.dismiss_popups(page=page)
            except Exception:
                pass
            remaining = ctx.deadline.remaining() if ctx.deadline is not None else None
            export_budget = min(8.0, remaining) if remaining is not None else 8.0
            storage_state = await asyncio.wait_for(lease.context.storage_state(), timeout=max(0.001, export_budget))
            state = _prepared_login(ctx, storage_state, confirmation, note=f"{provider}:{account} OAuth 候选会话已准备")
            update = oauth_state_update(
                shared_source, storage_state, provider,
                base_url=ctx.base_url,
                fresh_authorization=bool(link.get("fresh_authorization")),
            )
            return replace(state, oauth_updates=(update,) if update is not None else ())
        return state

    async def relogin(self, ctx: LoginContext, *, evidence: Any = None) -> LoginState:
        """强制走一条新 OAuth 链；永不读取站点快照，也不复用账号浏览器上下文。"""
        from browser import oauth_providers, storage_scope

        provider, account = self._provider(ctx)
        if provider not in oauth_providers.KNOWN_OAUTH_PROVIDERS:
            raise ConfigError(f"不支持的 OAuth 提供商：{provider}")
        if ctx.browser is None:
            raise ConfigError("强制重登需要浏览器，但本次运行未启用浏览器")
        shared, source = ctx.resolve_oauth(provider, account)
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
        # 从同一个绝对截止点切出收尾余量，不在阶段切换时重置总预算。
        # 短预算同比缩小预留，仍允许有界地尝试一次新授权。
        close_reserve = min(_RELOGIN_CLOSE_RESERVE, timeout * 0.1)
        export_reserve = min(_STATE_EXPORT_RESERVE, timeout * 0.15)
        confirm_reserve = min(_SERVER_CONFIRM_RESERVE, timeout * 0.15)
        work_deadline = deadline - close_reserve
        oauth_deadline = work_deadline - export_reserve - confirm_reserve
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
            remaining = min(2.0, max(0.0, work_deadline - time.monotonic()))
            if evidence is None or remaining <= 0:
                return
            try:
                await asyncio.wait_for(lease.screenshot("relogin-failed.png", page=page), timeout=remaining)
            except Exception:
                pass

        try:
            async with asyncio.timeout_at(work_deadline):
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
                    # goto 吞掉自身超时后会正常返回、但页面仍停在 about:blank：连导航都没提交
                    # 到目标站点，说明这一跳没连通。首跳未提交多是链路瞬时抖动，剩余预算够就
                    # 重载再试一次，而不是首跳失败即终局——把空白页喂给 Cloudflare 求解会误报
                    # 「人机验证未通过」，误导用户换 IP。用尽有限重试仍未提交才按链路问题上报。
                    committed = False
                    for nav_attempt in range(_NAV_MAX_ATTEMPTS):
                        if nav_attempt:
                            # 退避期间可能已经提交导航；不要重新打开站点或打断已发生的重定向。
                            current_url = str(getattr(page, "url", "") or "")
                            if storage_scope.same_origin(current_url, ctx.base_url):
                                committed = True
                                break
                            if current_url not in {"", "about:blank"}:
                                break
                        nav_budget = min(30.0, max(0.001, (oauth_deadline - time.monotonic()) * 0.5))
                        await lease.goto("", page=page, wait_until="commit",
                                         timeout=int(nav_budget * 1000))
                        if storage_scope.same_origin(str(getattr(page, "url", "") or ""), ctx.base_url):
                            committed = True
                            break
                        # 只重试空白页：其他 origin 可能已进入授权，不把已重定向当作未提交。
                        if (nav_attempt + 1 < _NAV_MAX_ATTEMPTS
                                and str(getattr(page, "url", "") or "") in {"", "about:blank"}
                                and oauth_deadline - time.monotonic() > _NAV_RETRY_MIN_SECONDS):
                            ctx.log("站点导航未提交，链路可能抖动，重载后重试一次")
                            await asyncio.sleep(_NAV_RETRY_BACKOFF_SECONDS)
                            continue
                        break
                    if not committed:
                        await capture_failure(lease, page)
                        raise TransientError(
                            "浏览器导航到站点未得到响应：多为出口 IP 或代理节点到站点的链路抖动，"
                            "本次未启动新登录，保留旧认证信息；请稍后重试或更换代理节点。",
                            data={"stage": stage, "timeout_stage": stage},
                        )
                    from browser import bypass

                    stage = "cloudflare"
                    if not await bypass.solve_cloudflare(
                        page, log=ctx.log, wait_seconds=min(30.0, max(0.0, oauth_deadline - time.monotonic())),
                        diagnostics=cf_diagnostics,
                    ):
                        await capture_failure(lease, page)
                        raise _oauth_error(provider, account, {"cloudflare": True, "cf_diagnostics": cf_diagnostics})
                    stage = "oauth"
                    ctx.log(f"在隔离会话中重新执行 {provider}:{account} OAuth…")
                    async with asyncio.timeout_at(oauth_deadline):
                        link = await lease.oauth(provider, page=page, require_fresh=True, deadline=oauth_deadline)
                    if not link.get("landed_back") or not link.get("fresh_authorization"):
                        await capture_failure(lease, page)
                        raise _oauth_error(provider, account, link)
                    stage = "server_confirmation"
                    confirmation = _confirmation(await _confirm_after_relogin(
                        fresh_ctx, page, work_deadline, export_reserve=export_reserve,
                        handoff=getattr(lease, "_oauth_handoff", None),
                    ))
                    if not confirmation:
                        await capture_failure(lease, page)
                        raise LoginRequired("OAuth 已回跳，但服务端未确认新会话，保留旧认证信息",
                                            data={"stage": stage})
                    stage = "state_export"
                    # 登录已确认成功。此前 harvest + export_state 会各调一次 storage_state()
                    # （实测可达 8s+），叠加起来常拖过外层截止点，把已确认的成功翻转成
                    # 「state_export 阶段超时」而白白丢弃。这里只取一次状态，兼作凭据提取与
                    # 快照；有界读取，快照编码失败也只是本次不缓存，不否定这次已确认的登录。
                    export_budget = max(0.0, min(export_reserve, work_deadline - time.monotonic()))
                    storage_state = await asyncio.wait_for(
                        lease.context.storage_state(), timeout=export_budget,
                    )
                    state = _prepared_login(fresh_ctx, storage_state, confirmation, note=f"{provider}:{account} 强制 OAuth 候选会话已准备")
                    try:
                        snapshot = encode_state(storage_state)
                    except Exception:
                        snapshot = ""
                    update = oauth_state_update(
                        source, storage_state, provider,
                        base_url=ctx.base_url,
                        fresh_authorization=True,
                    ) if snapshot else None
                    return replace(
                        state,
                        credentials={**state.credentials, "browser_state": snapshot},
                        oauth_updates=(update,) if update is not None else (),
                    )
        except TimeoutError as exc:
            if stage == "cloudflare":
                cf_diagnostics.setdefault("timeout_stage", "cloudflare")
                raise _oauth_error(provider, account, {"cloudflare": True, "cf_diagnostics": cf_diagnostics}) from exc
            raise TransientError(f"强制重登在 {stage} 阶段超时，未完成新登录，保留旧认证信息",
                                 data={"stage": stage, "timeout_stage": stage}) from exc
        finally:
            # 即使启动/恢复失败或外层取消，也不续存未认证快照。
            remaining = ctx.deadline.remaining() if ctx.deadline is not None else None
            close_timeout = min(_RELOGIN_CLOSE_RESERVE, max(0.0, deadline - time.monotonic()))
            if remaining is not None:
                close_timeout = min(close_timeout, remaining)
            try:
                await asyncio.wait_for(isolated.aclose(), timeout=max(0.01, close_timeout))
            except Exception:
                ctx.log("隔离浏览器收尾未完成，未写入任何未认证快照")


def _prepared_login(ctx: LoginContext, storage_state: dict[str, Any], confirmation: Any, *, note: str) -> LoginState:
    from browser import storage_scope

    candidate = storage_scope.storage_login_candidate(storage_state, base_url=ctx.base_url)
    confirmation = _confirmation(confirmation)
    identity = dict(confirmation.identity or {})
    captured_id = candidate["identity"].get("user_id", "")
    confirmed_id = str(identity.get("user_id") or "")
    if candidate["conflict"] or (captured_id and confirmed_id and captured_id != confirmed_id):
        raise LoginRequired("OAuth 候选凭据与服务端身份冲突，保留旧认证信息", reason="identity_mismatch")
    if captured_id:
        identity["user_id"] = captured_id
    # 本轮候选身份不能沿用上一身份/配置里的 uid。
    candidate_ctx = replace(ctx, args={**ctx.args, "user_id": str(identity.get("user_id") or "")})
    state = state_to_login(
        candidate_ctx, method="oauth", access=candidate["access_token"],
        refresh=storage_scope.storage_refresh_token(storage_state, base_url=ctx.base_url),
        cookie=storage_scope.site_cookie_string(storage_state.get("cookies") or [], ctx.base_url),
        verified=False, origin="oauth", note=note,
    )
    try:
        snapshot = encode_state(storage_state)
    except Exception:
        snapshot = ""
    return replace(state, credentials={**state.credentials, "browser_state": snapshot},
                   identity=identity, replace_credentials=True)


def _track(lease: Any, provider: str, account: str, state_text: str) -> None:
    """登记本上下文的提供商会话来自共享态，供收尾时同步轮换后的认证值。"""
    track = getattr(lease, "track_shared", None)
    if not callable(track):
        return
    try:
        from browser import storage_scope

        track(provider, account, storage_scope.provider_auth_values(decode_state(state_text), provider))
    except Exception:
        pass


async def _refresh_provider_cookies(
    ctx: LoginContext, lease: Any, provider: str, account: str, cached_state: str,
) -> Any:
    """站点快照里的提供商 Cookie 可能早已被轮换作废；共享态更新时换成共享态的。

    只比较静态到期时间：共享态更晚到期，说明它是这份会话更新的副本（保活或其他站点
    刚续过）。注入后本上下文的提供商会话就是共享态，返回其来源以便回跳后写回轮换。
    """
    from browser import storage_scope

    try:
        shared_text, source = ctx.resolve_oauth(provider, account)
        if not shared_text:
            return None
        shared = storage_scope.provider_storage_state(decode_state(shared_text), provider, base_url=ctx.base_url)
        cached = storage_scope.provider_storage_state(decode_state(cached_state), provider, base_url=ctx.base_url)
    except Exception:
        return None
    shared_expiry = storage_scope.provider_auth_expiry(shared, provider)
    cached_expiry = storage_scope.provider_auth_expiry(cached, provider)
    shared_values = storage_scope.provider_auth_values(shared, provider)
    if not shared_values:
        return None
    if shared_values == storage_scope.provider_auth_values(cached, provider):
        _track(lease, provider, account, encode_state(shared))
        return source
    if shared_expiry is None or (cached_expiry is not None and cached_expiry >= shared_expiry):
        return None
    await lease.restore_state(encode_state(shared))
    ctx.log(f"站点快照里的 {provider} 登录态较旧，已换用更新的共享登录态")
    _track(lease, provider, account, encode_state(shared))
    return source


_CONFIRM_LOGIN_JS = """async ([baseUrl, path, _configuredUid, timeoutMs]) => {
    const unknown = {status:'unknown', identity:{}};
    const scalar = v => (typeof v === 'string' || (typeof v === 'number' && Number.isSafeInteger(v))) && String(v).trim() ? String(v).trim() : '';
    const headers = {Accept:'application/json'};
    const tokens = new Set(); const ids = new Set();
    for (const key of ['auth_token','access_token']) {
        const token = localStorage.getItem(key); if (typeof token === 'string' && token.trim()) tokens.add(token.trim());
    }
    try {
        const u = JSON.parse(localStorage.getItem('user') || 'null');
        if (u && typeof u === 'object' && !Array.isArray(u)) {
            for (const key of ['access_token','token','auth_token']) if (typeof u[key] === 'string' && u[key].trim()) tokens.add(u[key].trim());
            for (const key of ['id','user_id']) if (scalar(u[key])) ids.add(scalar(u[key]));
        }
    } catch (_) {}
    if (tokens.size > 1 || ids.size > 1) return unknown;
    const token = [...tokens][0] || ''; const userId = [...ids][0] || '';
    if (userId) headers['New-Api-User'] = userId;
    if (token) headers.Authorization = 'Bearer ' + token;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const r = await fetch(baseUrl + path, {credentials:'include',headers,signal:controller.signal});
        const text = await r.text();
        if (/^\\s*</.test(text) || /aliyun_waf|slidecaptcha|acw_sc__|Just a moment|cf-challenge/i.test(text)) return unknown;
        if (r.status === 429 || r.status >= 500) return unknown;
        let body; try {body = JSON.parse(text);} catch (_) {return unknown;}
        if (r.status === 401 || r.status === 403) return {status:'rejected',identity:{}};
        if (!r.ok || !body || typeof body !== 'object' || Array.isArray(body)) return unknown;
        if (body.success === false) return {status:'rejected',identity:{}};
        const data = body.data && typeof body.data === 'object' ? body.data : body;
        const responseIds = new Set([scalar(data.id),scalar(data.user_id)].filter(Boolean));
        if (responseIds.size > 1) return unknown;
        const confirmedId = [...responseIds][0] || '';
        if (userId && confirmedId && userId !== confirmedId) return {status:'rejected',identity:{}};
        if (!confirmedId && !scalar(data.username) && !scalar(data.email)) return unknown;
        return {status:'ok', identity:confirmedId ? {user_id:confirmedId} : {}};
    } catch (_) {return unknown;} finally {clearTimeout(timer);}
}"""


@dataclass(frozen=True)
class SessionConfirmation:
    status: str = "unknown"
    identity: Any = None

    def __bool__(self) -> bool:
        return self.status == "ok"


def _confirmation(value: Any) -> SessionConfirmation:
    if isinstance(value, SessionConfirmation):
        return value
    if isinstance(value, dict):
        status = value.get("status")
        return SessionConfirmation(status if status in {"ok", "rejected"} else "unknown", value.get("identity") or {})
    # 兼容仅返回布尔的旧离线浏览器适配；生产脚本总是返回结构化三态。
    return SessionConfirmation("ok" if value is True else "rejected" if value is False else "unknown", {})


async def _server_confirms_login(ctx: LoginContext, page: Any) -> SessionConfirmation:
    """在页面上下文请求模板声明的 ``user`` 端点，确认服务端是否认这个会话。

    只有服务端认账才算登录成功。浏览器里存在 cookie 并不足以说明问题：站点的风控层
    对匿名访问同样会下发 cookie（实测 agentrouter.org 必回一个 acw_tc），据此判定
    「会话有效」会让 OAuth 回跳被整段跳过，后续业务请求全部 401。

    模板没声明 ``user`` 端点时返回 False：宁可多走一次 OAuth 回跳，也不要在无法验证
    的情况下假定已登录——前者只是慢，后者会让整个任务以 401 收场。
    """
    path = ctx.endpoint("user").strip()
    if not path:
        return SessionConfirmation()
    from browser.storage_scope import same_origin

    if not same_origin(str(page.url), ctx.base_url):
        return SessionConfirmation()
    remaining = ctx.deadline.remaining() if ctx.deadline is not None else None
    timeout = min(15.0, remaining) if remaining is not None else 15.0
    if timeout <= 0:
        return SessionConfirmation()
    try:
        confirmed = await asyncio.wait_for(page.evaluate(
            _CONFIRM_LOGIN_JS,
            [ctx.base_url.rstrip("/"), path, "", max(1, int(timeout * 1000))],
        ), timeout=timeout)
    except Exception as exc:
        ctx.log(f"会话校验未能完成（{type(exc).__name__}），不重放授权")
        return SessionConfirmation()
    return _confirmation(confirmed)


async def _forward_callback_to_api(
    ctx: LoginContext, page: Any, *, handoff: Any = None, deadline: float | None = None,
) -> bool:
    """仅转交本链已关联且未消费的 callback；裸 URL 的旧 POC 路径明确弃用。"""
    from urllib.parse import quote, parse_qs, urlsplit
    from browser.storage_scope import same_origin

    if handoff is None or not handoff.valid or handoff.consumed or handoff.forwarded or deadline is None:
        return False
    remaining = max(0.0, deadline - time.monotonic())
    if remaining <= 0:
        return False
    try:
        url = handoff.url
        parsed = urlsplit(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if not same_origin(url, ctx.base_url) or parsed.fragment or parsed.username or parsed.password:
            return False
        if any(len(query.get(key, [])) != 1 or not query[key][0].strip() for key in ("code", "state")):
            return False
        api_path = f"/api/oauth/{handoff.provider}"
        if parsed.path.rstrip("/") == api_path:
            return False
        target = f"{ctx.base_url.rstrip('/')}{api_path}?code={quote(query['code'][0], safe='')}&state={quote(query['state'][0], safe='')}"
        callback_page = handoff.page
        closed = getattr(callback_page, "is_closed", None)
        if callback_page is None or (callable(closed) and closed()):
            callback_page = page
        # 在 dispatch 前锁定；超时/导航异常也绝不重送单次授权码。
        handoff.forwarded = True
        ctx.log("本链回调尚未消费，转交后端接口完成授权换取")
        await asyncio.wait_for(callback_page.goto(target, wait_until="commit", timeout=max(1, int(remaining * 1000))), timeout=remaining)
        return True
    except Exception:
        return False


async def _confirm_after_relogin(
    ctx: LoginContext, page: Any, deadline: float, *, export_reserve: float = _STATE_EXPORT_RESERVE,
    handoff: Any = None,
) -> SessionConfirmation:
    """弹窗式 OAuth 的回调页要用 code 异步换取 token 再写入登录态（New API 存在
    localStorage 的 'user' 对象里，同源共享给 opener）；观察到回调 URL 时往往尚未
    就绪，单次确认会把「还在换 token」误判成未登录。这里在剩余预算内轮询，直到
    服务端认账或时间不够——给回调页完成换取与写入的时间。

    收手时刻提前 ``_STATE_EXPORT_RESERVE``：确认成功后还要导出登录态（凭据 + 快照），
    而 ``storage_state()`` 实测可达 8s+。若把预算耗尽在轮询上，导出阶段就会撞外层
    截止点，把一次已确认成功的登录反而拖成「state_export 阶段超时」而白白丢弃。
    """
    confirm_deadline = deadline - export_reserve
    started = time.monotonic()
    latest = SessionConfirmation()
    while True:
        remaining = max(0.0, confirm_deadline - time.monotonic())
        account_remaining = ctx.deadline.remaining() if ctx.deadline is not None else None
        if account_remaining is not None:
            remaining = min(remaining, max(0.0, account_remaining - export_reserve))
        if remaining <= 0:
            return latest
        check_page = page
        if handoff is not None and handoff.page is not None:
            closed = getattr(handoff.page, "is_closed", None)
            if not callable(closed) or not closed():
                check_page = handoff.page
        try:
            latest = _confirmation(await asyncio.wait_for(_server_confirms_login(ctx, check_page), timeout=remaining))
            if latest:
                return latest
        except TimeoutError:
            return SessionConfirmation()
        # 先观察 SPA 换取；只在明确拒绝而非网络/限流/挑战 unknown 时转交一次。
        if latest.status == "rejected" and time.monotonic() - started >= 1.0:
            forward_remaining = max(0.0, confirm_deadline - time.monotonic())
            if ctx.deadline is not None:
                forward_remaining = min(forward_remaining, max(0.0, ctx.deadline.remaining() - export_reserve))
            forward_deadline = time.monotonic() + forward_remaining
            await _forward_callback_to_api(ctx, page, handoff=handoff, deadline=forward_deadline)
        # 转交/goto 自身可能耗时，必须重算，绝不借导出余量。
        remaining = max(0.0, confirm_deadline - time.monotonic())
        if ctx.deadline is not None:
            remaining = min(remaining, max(0.0, ctx.deadline.remaining() - export_reserve))
        if remaining <= 0:
            return latest
        await asyncio.sleep(min(1.0, remaining))


def _oauth_error(provider: str, account: str, link: dict[str, Any]) -> TaskError:
    """按实际失败阶段归因；不从「遇到 CF」推断出口 IP 信誉或暴露授权 URL。"""
    flags = (
        "landed_back", "fresh_authorization", "need_human", "cloudflare", "waf_blocked",
        "provider_session_present", "client_id_missing", "driver_crashed", "clicked",
        "intermediate_clicked", "popup", "callback_observed",
    )
    safe = {key: link[key] for key in flags if isinstance(link.get(key), (bool, type(None))) and key in link}
    safe["provider"] = provider
    for key in ("stage", "timeout_stage", "timeout_kind", "human_reason", "page_kind"):
        value = link.get(key)
        if isinstance(value, str) and value and all(c.isalnum() or c in "_-" for c in value):
            safe[key] = value[:80]
    diagnostics = link.get("cf_diagnostics") or {}
    # 诊断值只接受内部阶段枚举；任意外部文本/URL/凭据都不进入结果。
    safe_cf = {}
    if isinstance(diagnostics, dict):
        for key in ("stage", "target_kind", "clicked", "timeout_stage", "reason", "blocked", "status", "observation_status", "preserve_page", "retry_allowed", "input_dispatched", "widget_acknowledged"):
            value = diagnostics.get(key)
            if isinstance(value, bool):
                safe_cf[key] = value
            elif isinstance(value, str) and value and all(c.isalnum() or c in "_-" for c in value):
                safe_cf[key] = value[:80]
        if isinstance(diagnostics.get("challenge_observed"), bool):
            safe_cf["challenge_observed"] = diagnostics["challenge_observed"]
        for key, allowed in (
            ("page_state", {"unknown", "clear", "interstitial", "interactive"}),
            ("page_state_reason", {
                "not_observed", "challenge_page", "page_query_failed", "token_present",
                "challenge_target", "page_rendered", "probe_failed", "probe_timeout",
                "challenge_widget", "page_empty",
            }),
        ):
            value = diagnostics.get(key)
            if isinstance(value, str) and value in allowed:
                safe_cf[key] = value
    if safe_cf:
        safe["cf_diagnostics"] = safe_cf
    navigation = link.get("navigation")
    safe_navigation: dict[str, Any] = {}
    if isinstance(navigation, dict):
        for key in ("provider_observed", "provider_requested", "recovery_attempted", "submission_observed"):
            if isinstance(navigation.get(key), bool):
                safe_navigation[key] = navigation[key]
        for key, allowed in (
            ("state", {"provider", "site", "other", "blank", "uncommitted", "load_failed"}),
            ("load_error", {"none", "network", "browser_error"}),
        ):
            value = navigation.get(key)
            if isinstance(value, str) and value in allowed:
                safe_navigation[key] = value
        if safe_navigation:
            safe["navigation"] = safe_navigation
    data = {"oauth": safe}
    if safe_cf.get("preserve_page") is True or safe_cf.get("retry_allowed") is False:
        data.update(preserve_page=True, retry_allowed=False, terminal=True)
    provider_error = link.get("provider_error")
    if isinstance(provider_error, str) and provider_error in {
        "unauthorized_client", "invalid_client", "invalid_request", "invalid_scope",
        "unsupported_response_type", "access_denied", "server_error", "temporarily_unavailable",
    }:
        safe["provider_error"] = provider_error
        hint = link.get("provider_error_hint")
        if isinstance(hint, str) and hint in {
            "重定向地址不匹配", "应用不存在", "应用未获授权", "授权范围不符", "应用标识无效",
        }:
            safe["provider_error_hint"] = hint
        if provider_error in {"server_error", "temporarily_unavailable"}:
            return TransientError(f"{provider} 授权服务返回 {provider_error}，保留旧认证信息，请稍后重试。",
                                  data=data)
        if provider_error == "access_denied":
            return TaskError(f"{provider} 已拒绝本次授权（access_denied），保留旧认证信息。",
                             reason="oauth_denied", data=data)
        return ConfigError(
            f"{provider} 拒绝站点 OAuth 应用（{provider_error}"
            f"{'，' + hint if hint else ''}），需要站点管理员修复应用授权配置；"
            "本次未完成签到，保留旧认证信息。",
            reason="oauth_client_rejected", data=data,
        )
    if link.get("need_human"):
        from browser.oauth_flow import _provider_login_message

        return LoginRequired(_provider_login_message(safe), data=data)
    if link.get("waf_blocked") or safe_cf.get("blocked") is True:
        return TaskError("页面明确显示安全规则拒绝访问，OAuth 无法完成；请检查站点访问限制或代理。",
                         reason="blocked", data=data)
    if link.get("cloudflare"):
        stage = safe_cf.get("timeout_stage") or safe_cf.get("stage") or safe_cf.get("reason") or "challenge"
        if safe_cf.get("page_state") == "unknown" and safe_cf.get("challenge_observed") is False:
            detail = safe_cf.get("page_state_reason", "not_observed")
            return VerificationRequired(
                f"{provider} OAuth 页面状态尚未确认（阶段：{stage}；原因：{detail}）；"
                "本次未完成授权，保留旧认证信息。尚未观察到明确的人机挑战，"
                "不能据此判断登录态失效或 IP 信誉。", data=data,
            )
        clicked = "已完成点击，等待验证放行" if safe_cf.get("clicked") else "尚未完成有效点击"
        return VerificationRequired(
            f"{provider} OAuth 的 Cloudflare 验证尚未通过（阶段：{stage}；{clicked}）；"
            "本次未完成授权，不能据此判断 IP 信誉。", data=data,
        )
    if link.get("state_error") or link.get("client_id_missing"):
        return ConfigError(f"站点未开启 {provider} OAuth，或未能获取新的授权参数。", data=data)
    authorization_started = bool(link.get("clicked") or link.get("intermediate_clicked")
                                 or safe_navigation.get("submission_observed"))
    if (safe_navigation.get("state") in {"blank", "uncommitted", "load_failed"}
            and not authorization_started and not link.get("callback_observed")
            and not link.get("driver_crashed")):
        stage = safe.get("timeout_stage") or safe.get("stage") or "authorization"
        return TransientError(
            f"{provider} OAuth 授权页未能加载（阶段：{stage}；导航：{safe_navigation['state']}），"
            "本次未完成新登录，保留旧认证信息；此证据不能证明站点不可达或 IP 信誉异常。",
            data=data,
        )
    if link.get("timeout_stage"):
        timeout_stage = safe.get("timeout_stage", "授权")
        # 只有正式授权已发起后，callback 超时才是可重试的传输/等待故障。
        # provider 页没有可操作控件时停在 approval 阶段，应提示人工处理，不能
        # 把「根本没点击」伪装成 callback 网络失败。
        if timeout_stage == "callback" and authorization_started:
            limit = "阶段等待上限已到" if safe.get("timeout_kind") == "phase_cap" else "可用总预算耗尽"
            return TransientError(
                f"{provider} OAuth 在 {timeout_stage} 阶段{limit}，保留旧认证信息。",
                data=data,
            )
        # DOM 的 unknown 不代表导航失败；真实 provider 页面也可能没有匹配的表单。
        # 未完成新授权不证明旧凭据过期，用独立原因保留这一不确定性。
        return LoginRequired(
            f"{provider} OAuth 尚未完成可操作的授权动作（阶段：{timeout_stage}）；"
            "保留旧认证信息，请检查授权页面并按需人工完成授权。",
            reason="oauth_incomplete", data=data,
        )
    return LoginRequired(
        f"{provider}:{account} 未完成本次新 OAuth 回跳，保留旧认证信息；请检查共享登录态和站点授权入口。",
        reason="oauth_incomplete", data=data,
    )
