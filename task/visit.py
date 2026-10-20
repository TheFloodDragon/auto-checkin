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

import json
from typing import Any

from core.errors import ConfigError, TaskError, TransientError, VerificationRequired
from core.outcome import DisplaySpec, Outcome, already_done, success
from core.timebase import business_date
from net.http import HttpConfig, _http_error, parse_json, unwrap_data
from .base import hook_owns_execute, run_template_hook
from .http_api import outcome_from_error

__all__ = ["VisitTask"]

STORE_KEY = "visit_baseline"
_BROWSER_FETCH_TIMEOUT_MS = 20_000
_PAGE_SETTLE_MS = 2_500
#: 在页面里转发给接口的基线头；Cookie / Authorization 由浏览器自身的会话提供。
_FORWARD_HEADERS = ("new-api-user", "referer")


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
        # 这里只重读无副作用的用户接口，不重放模板脚本、签到或抽奖任务。
        for attempt in range(2):
            try:
                payload = unwrap_data(ctx.http.get(path))
                break
            except TaskError as exc:
                recover = getattr(getattr(ctx, "login_handle", None), "recover", None)
                if attempt == 0 and exc.reason == "need_login" and callable(recover):
                    try:
                        if await recover():
                            continue
                    except TaskError as recovery_exc:
                        return outcome_from_error(recovery_exc)
                if not _is_guard_challenge(exc) or ctx.browser_service is None:
                    return outcome_from_error(exc)
                ctx.log("纯 HTTP 被站点防护拦截，改在浏览器会话中读取接口")
                try:
                    payload = await _fetch_in_browser(ctx, path)
                    break
                except TaskError as browser_exc:
                    # HTTP 层只见到 WAF 时，认证拒绝可能要到浏览器接口中才出现。
                    if attempt == 0 and browser_exc.reason == "need_login" and callable(recover):
                        try:
                            if await recover():
                                continue
                        except TaskError as recovery_exc:
                            return outcome_from_error(recovery_exc)
                    return outcome_from_error(browser_exc)

        data = payload if isinstance(payload, dict) else {}
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


async def _fetch_in_browser(ctx: Any, path: str) -> Any:
    """在浏览器页面里读取接口 JSON；浏览器会话已由登录阶段过盾并注入登录态。"""
    from browser import bypass, waf

    headers = {
        key: value for key, value in dict(ctx.http.headers or {}).items()
        if key.lower() in _FORWARD_HEADERS and str(value).strip()
    }
    async with ctx.browser.lease(reason="visit") as lease:
        page = await lease.new_page()
        # 挑战页可能一直不触发 DOMContentLoaded；等待提交即可开始防护处理。
        await lease.goto("", page=page, wait_until="commit", timeout=30000)
        try:
            await lease.dismiss_popups(page=page)
        except Exception:
            pass
        try:
            if await waf.is_waf_html(page):
                cleared = False
                if not waf.waf_is_blocked(page):
                    cleared = await waf.solve_waf(page, ctx.account.base_url, ctx.log, rounds=2)
                if waf.waf_is_blocked(page):
                    raise TaskError(
                        "出口 IP 被站点安全规则持续拒绝，浏览器同样无法通过；请更换代理节点后重试。",
                        reason="blocked",
                        data={"guard": "block"},
                    )
                if not cleared:
                    raise VerificationRequired("浏览器页面的 WAF 挑战尚未通过，保留原登录态。",
                                               data={"guard": "challenge", "stage": "visit_guard"})
            else:
                if not await bypass.solve_cloudflare(page, log=ctx.log, wait_seconds=5):
                    raise VerificationRequired("浏览器页面的 Cloudflare 挑战尚未通过，保留原登录态。",
                                               data={"guard": "challenge", "stage": "visit_guard"})
        except TaskError:
            raise
        except Exception as exc:  # noqa: BLE001 - 过盾失败不掩盖后面的真实响应
            ctx.log(f"防护页处理未完成（{type(exc).__name__}），继续尝试读取接口")
        # 刚过盾的页面里，前几秒的 fetch 可能还被 WAF 的连接级拦截打断（实测表现为
        # NetworkError），给页面一点稳定时间后再读，失败再短暂重试。
        await page.wait_for_timeout(_PAGE_SETTLE_MS)
        last: dict[str, Any] | None = None
        for attempt in range(3):
            last = await _page_fetch_json(page, lease.resolve(path), headers)
            if last is not None and last.get("status"):
                body = last.get("body")
                text = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
                if int(last["status"]) < 400 and attempt < 2:
                    try:
                        parse_json(text)
                    except VerificationRequired:
                        # 刚过盾时接口也可能暂时返回 HTTP 200 的防护 HTML；
                        # 有响应不代表已取得业务 JSON，沿用原有三次 GET 预算。
                        ctx.log("浏览器接口仍返回防护页面，等待会话稳定后重读用户接口")
                        await page.wait_for_timeout(_PAGE_SETTLE_MS)
                        continue
                break
            await page.wait_for_timeout(_PAGE_SETTLE_MS)
        if last is None or not last.get("status"):
            # 未取得响应并不能证明验证码未过，更不能否定保存的凭据。
            raise TransientError(
                f"浏览器内读取 {path} 未取得响应，可能是页面导航或网络连接中断，保留原登录态。",
                data={"stage": "visit_fetch", "error_code": str((last or {}).get("error_code") or "fetch_failed")},
            )
        status = int(last.get("status") or 0)
        body = last.get("body")
        text = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
        if status >= 400:
            # 与 HTTP 路径使用相同的防护/源站/登录分类，403 HTML 不是账号失效。
            retry_statuses = getattr(getattr(ctx.http, "config", None), "retry_statuses", HttpConfig().retry_statuses)
            raise _http_error(status, text, retry_statuses=retry_statuses)
        payload = parse_json(text)
        if not isinstance(payload, (dict, list)):
            raise TaskError(f"浏览器接口返回非业务 JSON：HTTP {status}", status=status)
        lease.mark_authenticated()
        return unwrap_data(payload)


async def _page_fetch_json(page: Any, url: str, headers: dict[str, str]) -> dict[str, Any] | None:
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
            [url, headers, _BROWSER_FETCH_TIMEOUT_MS],
        )
    except Exception as exc:
        from browser.runtime_loop import is_driver_closed_error

        if is_driver_closed_error(exc):
            # 驱动崩溃不能靠同一页面重试恢复，也不属于验证码问题。
            raise TransientError("浏览器驱动连接已关闭，未取得接口响应，保留原登录态。",
                                 data={"stage": "visit_fetch", "error_code": "driver_closed"}) from exc
        # 不输出原始异常（可能含 URL/凭据）；页面导航中的短暂 evaluate 失败仍可重试。
        return {"status": 0, "error_code": type(exc).__name__}
