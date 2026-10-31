"""任务方式：访问保活。

有些站点不发放额度，只按「最近是否登录/访问过」保留账号或额度。这类任务没有签到接口，
唯一能做的就是发一次已认证请求，并记录当天已经访问过。

与旧 ``providers/actions/visit.py`` 的差别：不再往
``.cache-checkin/login_grant_state.json`` 写一份自己的状态文件，改用 ``ctx.store``
（进覆盖层的 learning 段，跟着账号的失效规则走）。

纯 HTTP 被 WAF / Cloudflare 挑战拦下时，若本次运行有浏览器（例如登录方式就是
``browser_state``），改在浏览器页面上下文里读同一个接口：浏览器已经过了挑战，
``acw_sc__v2`` / ``cf_clearance`` 这类 Cookie 绑定的是浏览器指纹，拿到 Python 侧
的 HTTP 客户端里并不通用（实测 AnyRouter 的阿里云 WAF 对每个纯 HTTP 请求重新出题）。
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import Any

from core.errors import ConfigError, LoginRequired, TaskError, TransientError, VerificationRequired
from core.outcome import DisplaySpec, Outcome, already_done, success
from core.timebase import business_date
from net.http import HttpConfig, _http_error, parse_json, unwrap_data
from .base import hook_owns_execute, run_template_hook

__all__ = ["VisitTask"]

STORE_KEY = "visit_baseline"
_BROWSER_FETCH_TIMEOUT_MS = 20_000
_PAGE_SETTLE_MS = 2_500
#: 在页面里转发给接口的基线头；Cookie / Authorization 由浏览器自身的会话提供。
_FORWARD_HEADERS = ("new-api-user", "referer")


def _accepted_user(payload: Any) -> bool:
    """只有用户端点的明确身份/会话信号能给浏览器认证；公共 JSON 不是证明。"""
    if not isinstance(payload, Mapping):
        return False
    data = unwrap_data(payload)
    if not isinstance(data, Mapping):
        return False
    if "current_user" in data:
        return isinstance(data["current_user"], Mapping) and bool(data["current_user"])
    if any(data.get(key) is True for key in ("authenticated", "is_authenticated", "logged_in")):
        return True
    return any(not isinstance(data.get(key), bool) and isinstance(data.get(key), (str, int))
               and str(data[key]).strip() not in {"", "0"} for key in ("id", "user_id", "username", "email"))


def _user_data(payload: Any) -> Mapping[str, Any]:
    """HTTP 200 仍需检查业务与认证回执；无身份的额度回体兼容旧只读调用方。"""
    from net import guard

    data = unwrap_data(payload)
    for candidate in (payload, data):
        if not isinstance(candidate, Mapping):
            continue
        if "current_user" in candidate and (not isinstance(candidate["current_user"], Mapping) or not candidate["current_user"]):
            raise LoginRequired("用户端点明确返回未登录")
        login = candidate.get("login")
        message = str(candidate.get("message") or candidate.get("error") or "")
        if guard.looks_like_verification(message):
            raise VerificationRequired("用户端点要求验证，保留现有登录态", data={"preserve_page": True, "retry_allowed": False})
        status = candidate.get("code", candidate.get("status"))
        if not isinstance(status, bool) and status in (401, 403, "401", "403"):
            raise LoginRequired("用户端点明确拒绝当前认证")
        if any(candidate.get(key) is False for key in ("authenticated", "is_authenticated", "logged_in")) or candidate.get("login_required") is True or (
            "login" in candidate and (isinstance(login, bool) or login in (None, "required", "login", "/login"))
        ):
            raise LoginRequired("用户端点明确要求登录")
        if candidate.get("success") is False:
            if any(hint in message.lower() for hint in ("not logged in", "unauthorized", "未登录", "请先登录", "session expired", "login required", "authentication required", "会话已过期")):
                raise LoginRequired("用户端点明确拒绝当前会话")
            raise TaskError("用户端点拒绝请求，尚未确认访问保活", reason="authentication_unknown",
                            data={"preserve_page": True, "retry_allowed": False})
    if isinstance(data, Mapping) and isinstance(data.get("current_user"), Mapping):
        data = data["current_user"]
    user_fields = ("quota", "balance", "credits", "credit", "points", "id", "user_id", "username", "email", "authenticated", "is_authenticated", "logged_in")
    if not isinstance(data, Mapping) or not data or not any(key in data and data[key] is not None for key in user_fields):
        raise TaskError("用户端点未返回可确认的业务数据", reason="authentication_unknown",
                        data={"preserve_page": True, "retry_allowed": False})
    return data


def _user_get(ctx: Any, path: str) -> Any:
    remaining_fn = getattr(ctx, "remaining_seconds", None)
    remaining = remaining_fn() if callable(remaining_fn) else None
    if remaining is None:
        return ctx.http.get(path)
    if remaining <= 0:
        raise TransientError("用户读取没有剩余时间预算", reason="timeout",
                             data={"preserve_page": True, "retry_allowed": False})
    cap = getattr(getattr(ctx.http, "config", None), "timeout", 20.0)
    return ctx.http.get(path, timeout=min(cap, remaining))


class VisitTask:
    id = "visit"
    requires: frozenset[str] = frozenset()

    async def run(self, ctx: Any, template: Any) -> Outcome:
        if hook_owns_execute(template, self.id):
            return await run_template_hook(ctx, template, what=self.id)

        manifest = template.manifest
        path = str((manifest.endpoints or {}).get("user") or "").strip()
        if not path:
            raise ConfigError(
                f"模板 {manifest.id} 未声明 [endpoints].user，访问保活不知道该请求哪个接口。"
            )
        response = manifest.response
        today = business_date()
        baseline = ctx.store.get(STORE_KEY) or {}
        # 引擎可确认现有未验证认证；直接单元替身没有该能力时仍走原有只读接缝。
        try:
            handle = ctx.login
        except AttributeError:
            handle = None
        except RuntimeError:
            return TaskError("本次未建立可确认的认证", reason="authentication_unknown").to_outcome()
        ensure = getattr(handle, "ensure_authenticated", None)
        if callable(ensure):
            try:
                if not await ensure():
                    return TaskError("现有认证尚未得到用户端点确认", reason="authentication_unknown",
                                     data={"preserve_page": True, "retry_allowed": False}).to_outcome()
            except TaskError as exc:
                return exc.to_outcome()
        # 这里只重读无副作用的用户接口，不重放模板脚本、签到或抽奖任务。
        for attempt in range(2):
            try:
                payload = _user_data(_user_get(ctx, path))
                break
            except TaskError as exc:
                recover = getattr(getattr(ctx, "login_handle", None), "recover", None)
                if attempt == 0 and exc.reason == "need_login" and callable(recover):
                    try:
                        if await recover():
                            continue
                    except TaskError as recovery_exc:
                        return recovery_exc.to_outcome()
                if not _is_guard_challenge(exc) or ctx.browser_service is None:
                    return exc.to_outcome()
                ctx.log("纯 HTTP 被站点防护拦截，改在浏览器会话中读取接口")
                try:
                    payload = _user_data(await _fetch_in_browser(ctx, path, user_endpoint=True))
                    break
                except TaskError as browser_exc:
                    # HTTP 层只见到 WAF 时，认证拒绝可能要到浏览器接口中才出现。
                    if attempt == 0 and browser_exc.reason == "need_login" and callable(recover):
                        try:
                            if await recover():
                                continue
                        except TaskError as recovery_exc:
                            return recovery_exc.to_outcome()
                    return browser_exc.to_outcome()

        data = dict(payload) if isinstance(payload, Mapping) else {}
        balance = response.pick(data, "balance")
        text = response.format(balance)
        display = DisplaySpec(text=text)
        detail = {"source": "visit", "balance": balance}

        previous_date = str(baseline.get("date") or "")
        ctx.store.put(STORE_KEY, {"date": today, "balance": balance})
        if previous_date == today:
            return already_done("今日已访问保活。", data=detail).with_display(display)
        return success("访问保活成功。", data=detail).with_display(display)


def _is_guard_challenge(exc: TaskError) -> bool:
    """只有「浏览器能过」的挑战才值得改走浏览器；出口 IP 被封禁换浏览器也没用。"""
    data = getattr(exc, "data", None) or {}
    guard_kind = str(data.get("guard") or "") if isinstance(data, dict) else ""
    if guard_kind == "block" or getattr(exc, "reason", "") == "blocked":
        return False
    return guard_kind == "challenge" or getattr(exc, "reason", "") == "need_verification"


def _budget_ms(deadline: float | None, cap: int) -> int:
    if deadline is None:
        return cap
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0:
        raise TimeoutError
    return max(1, min(cap, int(remaining * 1000)))


async def _fetch_in_browser(ctx: Any, path: str, *, user_endpoint: bool = False) -> Any:
    """整个页面观察与有限用户 GET 共用 ctx 的剩余预算，失败不重新导航。"""
    remaining_fn = getattr(ctx, "remaining_seconds", None)
    remaining = remaining_fn() if callable(remaining_fn) else None
    if remaining is not None and remaining <= 0:
        raise TransientError("浏览器读取没有剩余时间预算", reason="timeout",
                             data={"stage": "visit_navigation", "preserve_page": True, "retry_allowed": False})
    deadline = asyncio.get_running_loop().time() + remaining if remaining is not None else None
    observed: dict[str, Any] = {"stage": "visit_navigation"}
    try:
        async with asyncio.timeout_at(deadline):
            return await _read_browser_user(ctx, path, deadline, observed, user_endpoint=user_endpoint)
    except TimeoutError as exc:
        if observed["stage"] == "visit_guard":
            from runtime.events import challenge_data, emit_challenge
            from solvers.registry import SolveResult
            result = SolveResult.failure("pending", data={**observed.get("cf_diagnostics", {}),
                "status": "pending", "preserve_page": True, "retry_allowed": False})
            emit_challenge(result)
            raise VerificationRequired("浏览器防护观察预算已耗尽，保留当前页面与登录态",
                                       data={"guard": "challenge", **challenge_data(result)}) from exc
        raise TransientError("浏览器用户读取预算已耗尽，保留现有登录态", reason="timeout",
                             data={"stage": observed["stage"], "preserve_page": True, "retry_allowed": False}) from exc


async def _check_browser_guard(ctx: Any, page: Any, deadline: float | None, observed: dict[str, Any]) -> None:
    from browser import bypass, waf
    from runtime.events import challenge_data, emit_challenge
    from solvers.registry import SolveResult

    observed["stage"] = "visit_guard"
    diagnostics: dict[str, Any] = {}
    observed["cf_diagnostics"] = diagnostics
    try:
        # 只为区分阿里云 JS 挑战读取文档；CF 探测/点击全部由同一 structured session 管理。
        content = getattr(page, "content", None)
        html = (await content() or "").lower() if callable(content) else None
        aliyun = any(marker in (html or "") for marker in ("aliyun_waf", "acw_sc__", "slidecaptcha"))
        if aliyun or (html is None and await waf.is_waf_html(page)):
            if waf.waf_is_blocked(page):
                raise TaskError("浏览器同样被站点安全规则拒绝", reason="blocked", data={"guard": "block"})
            cleared = await waf.solve_waf(page, ctx.account.base_url, ctx.log, rounds=2)
            if waf.waf_is_blocked(page):
                raise TaskError("浏览器同样被站点安全规则拒绝", reason="blocked", data={"guard": "block"})
            if not cleared:
                data = waf.waf_circuit(page).get("challenge") or {"status": "pending", "stage": "visit_guard",
                    "preserve_page": True, "retry_allowed": False}
                raise VerificationRequired("浏览器页面的 WAF 挑战尚未通过，保留原登录态", data={"guard": "challenge", **data})
            return
        result = await bypass.TurnstileBypass(log=ctx.log).solve_result(
            page, mode="page_access", timeout=_budget_ms(deadline, 5000) / 1000,
            deadline=deadline, diagnostics=diagnostics)
        emit_challenge(result)
        if not result.ok:
            raise VerificationRequired(result.message or "Cloudflare 验证尚未确认，保留当前页面",
                                       data={"guard": "challenge", **challenge_data(result)}, evidence=getattr(result, "evidence", None))
    except (TaskError, TimeoutError):
        raise
    except Exception as exc:
        result = SolveResult.failure("observation_error", data={**diagnostics, "status": "observation_error",
            "preserve_page": True, "retry_allowed": False})
        emit_challenge(result)
        raise VerificationRequired("防护页观察未完成，不继续读取业务接口",
                                   data={"guard": "challenge", **challenge_data(result), "error_code": type(exc).__name__}) from exc


async def _read_browser_user(ctx: Any, path: str, deadline: float | None, observed: dict[str, Any], *, user_endpoint: bool) -> Any:
    headers = {key: value for key, value in dict(ctx.http.headers or {}).items()
               if key.lower() in _FORWARD_HEADERS and str(value).strip()}
    async with ctx.browser.lease(reason="visit") as lease:
        page = await lease.new_page()
        await lease.goto("", page=page, wait_until="commit", timeout=_budget_ms(deadline, 30000))
        try:
            await lease.dismiss_popups(page=page)
        except Exception:
            pass
        await _check_browser_guard(ctx, page, deadline, observed)
        last = None
        for attempt in range(3):
            if attempt:
                # 接口挑战或导航错误后先只读观察；pending/rejected 不得继续 GET。
                await _check_browser_guard(ctx, page, deadline, observed)
            observed["stage"] = "visit_settle"
            await page.wait_for_timeout(_budget_ms(deadline, _PAGE_SETTLE_MS))
            observed["stage"] = "visit_fetch"
            last = await _page_fetch_json(page, lease.resolve(path), headers,
                                          timeout_ms=_budget_ms(deadline, _BROWSER_FETCH_TIMEOUT_MS))
            if last is None or not last.get("status"):
                continue
            status = int(last["status"])
            body = last.get("body")
            text = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
            if status >= 400:
                retry_statuses = getattr(getattr(ctx.http, "config", None), "retry_statuses", HttpConfig().retry_statuses)
                error = _http_error(status, text, retry_statuses=retry_statuses)
                if error.reason == "blocked" and any(marker in text.lower() for marker in ("cloudflare", "cf-ray")):
                    from runtime.events import challenge_data, emit_challenge
                    from solvers.registry import SolveResult
                    result = SolveResult.failure("rejected", data={**observed.get("cf_diagnostics", {}),
                        "status": "rejected", "stage": "visit_fetch", "preserve_page": True, "retry_allowed": False})
                    emit_challenge(result)
                    error.data.update(challenge_data(result))
                raise error
            try:
                payload = parse_json(text)
            except VerificationRequired:
                if attempt < 2:
                    continue
                raise
            data = _user_data(payload)
            if user_endpoint and _accepted_user(payload):
                lease.mark_authenticated()
            return data
        raise TransientError("浏览器内用户读取未取得响应，保留原登录态",
                             data={"stage": "visit_fetch", "error_code": str((last or {}).get("error_code") or "fetch_failed")})


async def _page_fetch_json(page: Any, url: str, headers: dict[str, str], *, timeout_ms: int = _BROWSER_FETCH_TIMEOUT_MS) -> dict[str, Any] | None:
    try:
        return await page.evaluate(
            """async ([url, extra, timeoutMs]) => {
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), timeoutMs);
                try {
                    const headers = Object.assign({ Accept: 'application/json' }, extra || {});
                    const r = await fetch(url, { credentials: 'include', headers, signal: controller.signal });
                    const text = await r.text();
                    try { return { status: r.status, body: JSON.parse(text) }; }
                    // 防护标记可能在 HTML 的后部；分类前不能截成 200 字符。
                    catch (_) { return { status: r.status, body: text }; }
                } catch (e) {
                    return { status: 0, body: String(e && e.name === 'AbortError' ? 'fetch timeout' : e) };
                } finally {
                    clearTimeout(timer);
                }
            }""",
            [url, headers, timeout_ms],
        )
    except Exception as exc:
        from browser.runtime_loop import is_driver_closed_error

        if is_driver_closed_error(exc):
            # 驱动崩溃不能靠同一页面重试恢复，也不属于验证码问题。
            raise TransientError("浏览器驱动连接已关闭，未取得接口响应，保留原登录态。",
                                 data={"stage": "visit_fetch", "error_code": "driver_closed"}) from exc
        # 不输出原始异常（可能含 URL/凭据）；页面导航中的短暂 evaluate 失败仍可重试。
        return {"status": 0, "error_code": type(exc).__name__}
