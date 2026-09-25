#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""站点 OAuth 触发、第三方授权与结果判定。"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

from config.settings import Timeouts

from . import bypass, oauth_providers, popups
from .runtime_loop import LogFn, fetch_json_in_page, is_driver_closed_error, noop
from .site_messages import (
    add_site_error,
    attach_site_errors,
    install_site_error_collector,
    message_with_site_error,
    site_error_messages,
    site_success_message,
)
from .storage_scope import same_origin
from .waf import is_waf_html, solve_waf, waf_is_blocked, wait_for_ready

OAUTH_WAIT_SECONDS = Timeouts.OAUTH_WAIT
# 授权页从 CF 挑战到渲染「允许」按钮的总等待预算（实测 linux.do 约 20 秒）。
APPROVE_WAIT_SECONDS = 60
# 到达第三方授权页时，入口处的 Cloudflare interstitial（"Just a moment"）自动放行
# 的等待预算。实测 connect.linux.do 授权页在数据中心出口 IP 下需约 40 秒才自行放行
# （放行体现为页面级跳转，而非写入 turnstile 令牌字段）。默认 10 秒远不够，会把一次
# 本可通过的挑战判成 need_verification。给足预算是安全的：非挑战页 solve_cloudflare
# 会立即返回，不会空等。
OAUTH_CF_WAIT_SECONDS = 50

DEFAULT_LOGIN_SELECTORS = [
    "text=/linux.?do/i",
    "text=/使用.*登录/i",
    "text=/登录|登入|Sign in|Log in/i",
    "[href*='oauth']",
    "[href*='/login']",
    "button:has-text('Linux')",
    "button:has-text('GitHub')",
    "text=/github/i",
]

SITE_OAUTH_TOGGLE_SELECTORS = [
    "main a[href='/register']",
    "main a[href$='/register']",
    "main a:has-text('注册')",
    "main button:has-text('注册')",
    "main >> text=/没有账户|No account|Create account|Sign up|Register/i",
    "main a[href='/login']",
    "main a[href$='/login']",
    "main a:has-text('登录')",
    "main button:has-text('登录')",
    "main >> text=/已有账户|Already have|Sign in|Log in/i",
]


def _redact_oauth_text(value: Any) -> str:
    """OAuth 日志不保留 URL、一次性参数或认证材料。"""
    text = re.sub(r"https?://[^\s<>\"']+", "[URL]", str(value), flags=re.I)
    text = re.sub(r"\b(?:cookie|set-cookie|authorization)\s*[:=].*", "[认证信息已隐藏]", text, flags=re.I)
    return re.sub(
        r"(?i)([\"']?\b(?:code|state|access_token|refresh_token|token|client_secret)[\"']?\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&}\]]+)",
        r"\1[已隐藏]", text,
    )


def _oauth_log(log: LogFn) -> LogFn:
    return lambda message: log(_redact_oauth_text(message))


def _remaining(deadline: float | None, cap: float) -> float:
    if deadline is None:
        return max(0.0, cap)
    return max(0.0, min(cap, deadline - time.monotonic()))


def _timeout_ms(deadline: float | None, cap: int) -> int:
    remaining = _remaining(deadline, cap / 1000)
    if remaining <= 0:
        raise TimeoutError
    return max(1, int(remaining * 1000))


async def _oauth_sleep(seconds: float, deadline: float | None) -> None:
    remaining = _remaining(deadline, seconds)
    if remaining <= 0:
        raise TimeoutError
    await asyncio.sleep(remaining)


def _provider_callback(url: str, base_url: str, provider: Any) -> bool:
    """仅匹配所选 provider 的本站 callback；旧页快照本身不构成证据。"""
    if not same_origin(url, base_url):
        return False
    try:
        parsed = urlsplit(url)
        if parsed.username or parsed.password:
            return False
        key = provider.key.casefold()
        paths = {
            provider.callback_path().casefold(), f"/oauth/{key}", f"/oauth/{key}/callback",
            f"/auth/{key}/callback", f"/api/oauth/{key}/callback",
        }
        return parsed.path.rstrip("/").casefold() in paths and bool(parse_qs(parsed.query).get("code"))
    except (ValueError, AttributeError):
        return False


class _OAuthAttempt:
    """只保留本次事件产生的布尔证据；不向结果或日志暴露授权 URL。"""

    def __init__(self, base_url: str, provider: Any, require_fresh: bool) -> None:
        self.base_url = base_url
        self.provider = provider
        self.require_fresh = require_fresh
        self.armed = False
        self.provider_seen = False
        self.provider_pages: set[int] = set()
        self.provider_requested = False
        self.callback_seen = False
        self.callback_mismatch = False
        self.pages: list[Any] = []
        self.urls: dict[int, str] = {}
        self.returned: set[int] = set()
        self.listeners: list[tuple[Any, str, Any]] = []
        self.contexts: set[int] = set()
        self.pending_requests: dict[int, list[str]] = {}

    def is_provider(self, url: str) -> bool:
        try:
            parsed = urlsplit(url)
            return (
                not parsed.username and not parsed.password and parsed.port in (None, 443)
                and not same_origin(url, self.base_url) and self.provider.matches_url(url)
            )
        except (AttributeError, ValueError):
            return False

    def observe(self, page: Any, url: str, *, event: bool = False, request: bool = False) -> None:
        previous = self.urls.get(id(page), "")
        if not request:
            self.urls[id(page)] = str(url or "")
        if not self.armed or (not event and url == previous):
            return
        if self.is_provider(url):
            if request:
                self.provider_requested = True
            else:
                self.provider_seen = True
                self.provider_pages.add(id(page))
        if same_origin(url, self.base_url):
            if _provider_callback(url, self.base_url, self.provider):
                self.callback_seen = True
            for key in oauth_providers.KNOWN_OAUTH_PROVIDERS:
                if key != self.provider.key and _provider_callback(
                    url, self.base_url, oauth_providers.get_oauth_provider(key)
                ):
                    self.callback_mismatch = True
            if not request and (id(page) in self.provider_pages or self.callback_seen) and is_oauth_callback_url(
                url, self.base_url,
            ):
                self.returned.add(id(page))

    def watch(self, page: Any, *, popup: bool = False) -> None:
        if any(item is page for item in self.pages):
            return
        self.pages.append(page)
        self.observe(page, getattr(page, "url", ""), event=popup)
        # popup 事件可能晚于初始 302；仅在确认属于本次 opener 后重放缓存的请求证据。
        for url in self.pending_requests.pop(id(page), []):
            self.observe(page, url, event=True, request=True)
        context = getattr(page, "context", None)
        if id(context) not in self.contexts and callable(getattr(context, "on", None)):
            self.contexts.add(id(context))

            def context_request(request: Any) -> None:
                if not self.armed:
                    return
                try:
                    target = request.frame.page
                    if not request.is_navigation_request() or request.frame is not target.main_frame:
                        return
                    if any(item is target for item in self.pages):
                        self.observe(target, request.url, event=True, request=True)
                    elif len(self.pending_requests) < 16:
                        self.pending_requests.setdefault(id(target), []).append(request.url)
                        self.pending_requests[id(target)] = self.pending_requests[id(target)][-12:]
                except Exception:
                    pass

            context.on("request", context_request)
            self.listeners.append((context, "request", context_request))

        def navigation(frame: Any) -> None:
            if frame is getattr(page, "main_frame", None):
                self.observe(page, getattr(frame, "url", ""), event=True)

        def request_started(request: Any) -> None:
            try:
                if request.frame is page.main_frame and (
                    request.is_navigation_request() or _provider_callback(request.url, self.base_url, self.provider)
                ):
                    self.observe(page, request.url, event=True, request=True)
            except Exception:
                pass

        for event, callback in (
            ("framenavigated", navigation), ("request", request_started),
            ("popup", lambda new_page: self.watch(new_page, popup=True) if self.armed else None),
        ):
            on = getattr(page, "on", None)
            if callable(on):
                on(event, callback)
                self.listeners.append((page, event, callback))

    def refresh(self) -> None:
        for page in self.pages:
            try:
                self.observe(page, page.url)
            except Exception:
                pass

    @property
    def chain_started(self) -> bool:
        self.refresh()
        return self.provider_seen or self.provider_requested or self.callback_seen or self.callback_mismatch

    def active_page(self, fallback: Any) -> Any:
        self.refresh()
        live_pages = []
        for page in reversed(self.pages):
            try:
                closed = getattr(page, "is_closed", None)
                if not callable(closed) or not closed():
                    live_pages.append(page)
            except Exception:
                pass
        # callback 已到主页面时，不应被仍开着的 provider 弹窗抢走焦点。
        for page in live_pages:
            if self.landed(page) and (self.callback_seen or id(page) in self.returned):
                return page
        for page in live_pages:
            if self.is_provider(getattr(page, "url", "")):
                return page
        return fallback

    def landed(self, page: Any) -> bool:
        url = getattr(page, "url", "")
        if self.callback_mismatch:
            return False
        if self.callback_seen and same_origin(url, self.base_url):
            try:
                parsed = urlsplit(url)
                # popup callback 已观察到但弹窗关闭时，站内 opener 可留在登录页；
                # 是否真正登录由调用方的服务端校验决定，不能靠旧 DOM 猜测。
                return not parsed.username and not parsed.password
            except ValueError:
                return False
        if not is_oauth_callback_url(url, self.base_url):
            return False
        return not self.require_fresh or id(page) in self.returned

    def evidence(self, result: dict[str, Any]) -> None:
        result["fresh_authorization"] = bool(
            result.get("landed_back") and (self.callback_seen or self.returned) and not self.callback_mismatch
        )
        result["fresh_evidence"] = {
            "provider_observed": self.provider_seen,
            "callback_observed": self.callback_seen,
        }
        if self.callback_mismatch:
            result["error"] = "oauth_provider_mismatch"
            result["landed_back"] = False

    def close(self) -> None:
        for page, event, callback in self.listeners:
            try:
                page.remove_listener(event, callback)
            except Exception:
                pass
        self.listeners.clear()
        self.pending_requests.clear()
        self.urls.clear()


async def _oauth_goto(page: Any, url: str, deadline: float | None, log: LogFn) -> None:
    """授权导航只发起一次；超时后不得重放同一 state URL。"""
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=_timeout_ms(deadline, 30000))
    except Exception as exc:
        if is_driver_closed_error(exc):
            raise
        if deadline is not None and _remaining(deadline, 1) <= 0:
            raise TimeoutError from None
        log(f"OAuth 导航等待未完成（{type(exc).__name__}），继续观察本次导航")


async def _safe_site_messages(page: Any, collector: dict[str, Any] | None) -> list[str]:
    return [_redact_oauth_text(item) for item in await site_error_messages(page, collector)]


def _mark_oauth_timeout(result: dict[str, Any], log: LogFn) -> dict[str, Any]:
    stage = result.get("stage", "authorization")
    result.update(error="oauth_timeout", timeout_stage=stage, landed_back=False)
    diagnostics = result.get("cf_diagnostics")
    if isinstance(diagnostics, dict) and result.get("cf_pending"):
        diagnostics.update(timeout_stage=stage, reason="deadline_exceeded")
        result["cloudflare"] = True
    log(f"OAuth 预算耗尽（阶段：{stage}），停止等待并保留原登录态")
    return result


async def _solve_oauth_cf(
    page: Any, result: dict[str, Any], stage: str, deadline: float | None, log: LogFn,
    *, cap: float = OAUTH_CF_WAIT_SECONDS,
) -> bool:
    diagnostics: dict[str, Any] = {
        "stage": stage, "target_kind": "unknown", "clicked": False, "timeout_stage": "", "reason": "",
    }
    result.update(stage=stage, cf_diagnostics=diagnostics, cf_pending=True)
    try:
        passed = await bypass.solve_cloudflare(
            page, log=log, wait_seconds=_remaining(deadline, cap), deadline=deadline, diagnostics=diagnostics,
        )
    finally:
        diagnostics["stage"] = stage
    result["cf_pending"] = False
    result["cloudflare"] = not passed
    if not passed:
        result["landed_back"] = False
        result["error"] = "cloudflare_unresolved"
        if not diagnostics.get("reason"):
            diagnostics["reason"] = "challenge_unresolved"
        log(f"Cloudflare 尚未通过（阶段：{stage}），停止后续授权")
    return passed


def _quota_to_usd(value: Any) -> str:
    """内部 quota → $ 展示。

    New API 的内部额度单位是「quota」，除以 50 万得美元。这里只做展示，不参与任何
    判定；拿不到数值时原样回显，不编造 $0。
    """
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    usd = number / 500_000
    return f"${usd:.2f}" if abs(usd) >= 0.01 else f"${usd:.4f}"


async def api_get_json(page: Any, url: str) -> dict[str, Any] | None:
    """在页面上下文 GET JSON，自动携带同源 Cookie。"""
    return await fetch_json_in_page(page, url, timeout_ms=15000)


def extract_oauth_state(body: Any) -> str:
    """兼容不同 New API 派生站的 OAuth state 响应结构。"""
    if isinstance(body, dict):
        for key in ("data", "state", "oauth_state", "oauthState"):
            value = body.get(key)
            if isinstance(value, dict):
                nested = extract_oauth_state(value)
                if nested:
                    return nested
            elif value:
                return str(value)
    elif isinstance(body, str):
        text = body.strip()
        if text and not text.startswith("<") and len(text) <= 512:
            return text
    return ""


def oauth_landed(link: dict[str, Any]) -> bool:
    """授权是否完成；过程中出现过 CF 不代表最终失败。"""
    return bool(link.get("landed_back")) and not link.get("need_human") and not link.get("waf_blocked")


def oauth_failure_reason(link: dict[str, Any]) -> str:
    """OAuth 链路没走通时的具体原因；走通了返回空串。

    独立成函数是因为顺序即语义：relogin 站点在登录前读额度必然失败（当时确实
    未登录），所以「读不到额度」是最弱的线索，绝不能盖住「停在第三方登录页」这类
    确定原因。旧实现把「额度前后都读不到」放在最前面判定，于是日志里明明写着
    「停在 github 登录页」，结论却只剩一句「无法读取额度，登录态可能已失效」。
    """
    if link.get("waf_blocked"):
        return "waf_blocked"
    if link.get("need_human"):
        return "provider_login"
    if link.get("cloudflare"):
        return "cloudflare"
    if link.get("state_error"):
        return "state_error"
    if not link.get("landed_back"):
        return "no_callback"
    return ""


def _provider_login_message(link: dict[str, Any]) -> str:
    """停在第三方登录页时的可操作提示，并区分「登录态没装进浏览器」与「已被拒绝」。"""
    provider = str(link.get("provider") or "第三方").strip() or "第三方"
    session_present = link.get("provider_session_present")
    if session_present is False:
        detail = (
            f"浏览器上下文里没有 {provider} 的认证 Cookie（共享登录态未成功加载或已被清空）"
        )
    elif session_present is True:
        detail = (
            f"{provider} 认证 Cookie 已装载但被 {provider} 拒绝（会话已过期或被吊销）"
        )
    else:
        detail = f"浏览器停在 {provider} 登录页"
    return (
        f"共享 {provider} 登录态已失效：{detail}，站点无法自动完成 OAuth 授权。"
        f"请在管理界面重新捕获 {provider} 登录态后重试。"
    )


def oauth_checkin_result(quota_before: Any, quota_after: Any, link: dict[str, Any]) -> dict[str, Any]:
    """综合额度变化、OAuth 回跳状态和站点弹窗生成签到结果。"""
    result: dict[str, Any] = {
        "quota_before": quota_before,
        "quota_after": quota_after,
        "delta": None,
        "link": link,
    }

    if quota_before is not None and quota_after is not None and quota_after > quota_before:
        delta = quota_after - quota_before
        result["delta"] = delta
        result["status"] = "success"
        result["message"] = f"OAuth 重登成功，额度增加 {_quota_to_usd(delta)}（当前 {_quota_to_usd(quota_after)}）。"
        return result

    success_message = str(link.get("site_success_message") or "").strip()
    oauth_completed = oauth_landed(link)
    if oauth_completed and success_message:
        result["status"] = "success"
        result["message"] = f"签到成功（站点弹窗：{success_message}）。"
        return result

    # 授权确实走通了：先按额度/弹窗判定，不能因为「过程中出现过 CF 挑战」翻案。
    # waf_blocked / need_human 已在 oauth_landed 里否决，不会落到这里。
    if oauth_completed:
        current = quota_after if quota_after is not None else quota_before
        if current is None:
            # 授权跳回了站点，但前后都读不到额度：站点没认到登录身份或额度接口异常，
            # 不能当成「今日已发放」。
            result["status"] = "need_login"
            result["message"] = message_with_site_error(
                "OAuth 已跳回站点，但仍读不到额度（站点未认到登录身份或额度接口异常）。"
                "请确认站点登录方式与账号状态，必要时重新捕获登录态。",
                link,
            )
            return result
        result["status"] = "already_done"
        result["message"] = f"OAuth 重登完成，额度无变化（当前 {_quota_to_usd(current)}，今日可能已发放）。"
        return result

    reason = oauth_failure_reason(link)
    if reason == "waf_blocked":
        result["status"] = "need_verification"
        result["message"] = message_with_site_error(
            "站点阿里云 WAF 持续拦截当前出口 IP（数据中心/CI IP 信誉过低），"
            "浏览器无法通过 JS 挑战，本次签到中止。登录态可能仍有效，无需重新捕获；"
            "请为该账号配置住宅代理（proxy 字段），或改用住宅 IP 环境运行。",
            link,
        )
        return result
    if reason == "provider_login":
        result["status"] = "need_login"
        result["message"] = message_with_site_error(_provider_login_message(link), link)
        return result
    if reason == "cloudflare":
        result["status"] = "need_verification"
        result["message"] = message_with_site_error(
            "OAuth 过程命中 Cloudflare/WAF 人机验证，无法自动完成，请重新捕获登录态。",
            link,
        )
        return result
    if reason == "state_error":
        result["status"] = "need_login"
        result["message"] = message_with_site_error(
            f"OAuth 自动重登未完成：站点未下发一次性 state（{link.get('state_error')}），"
            "可能被限流或该站未开启此 OAuth 登录方式。",
            link,
        )
        return result

    result["status"] = "need_login"
    result["message"] = message_with_site_error(
        "OAuth 自动重登未完成：授权未带 code 顺畅跳回站点。请重新捕获登录态。", link
    )
    return result


async def fetch_oauth_client_id(page: Any, base_url: str, provider: Any) -> tuple[str, bool]:
    """从站点状态接口读取 provider client_id 与启用开关。"""
    response = await api_get_json(page, base_url + "/api/status")
    body = response.get("body") if isinstance(response, dict) else None
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        return "", False
    client_id = str(data.get(provider.status_client_id_field()) or "")
    raw_enabled = data.get(provider.status_oauth_field())
    if raw_enabled is None:
        enabled = bool(client_id)
    elif isinstance(raw_enabled, bool):
        enabled = raw_enabled
    else:
        enabled = str(raw_enabled).strip().lower() not in {"", "0", "false", "no", "off"}
    return client_id, enabled


async def fetch_oauth_state(
    page: Any, base_url: str, log: LogFn = noop, *, deadline: float | None = None,
) -> tuple[str, str]:
    """只向站点申请新 state；诊断不输出响应正文或旧授权 URL。"""
    last_diagnostic = "接口无响应"
    for attempt in range(3):
        if deadline is not None and _remaining(deadline, 1) <= 0:
            raise TimeoutError
        async with asyncio.timeout_at(deadline):
            response = await api_get_json(page, base_url.rstrip("/") + "/api/oauth/state")
        if not isinstance(response, dict):
            last_diagnostic = "接口无响应"
        else:
            status = response.get("status")
            status = status if isinstance(status, int) else "unknown"
            oauth_state = extract_oauth_state(response.get("body"))
            if oauth_state:
                return oauth_state, f"status={status}"
            last_diagnostic = f"status={status}，响应未包含有效 state"
            if status not in (408, 425, 429, 500, 502, 503, 504):
                break
        if attempt < 2:
            delay = 5 * (attempt + 1)
            log(f"/api/oauth/state 暂不可用（{last_diagnostic}），等待后重试...")
            await _oauth_sleep(delay, deadline)
    return "", last_diagnostic


def site_oauth_selectors(provider: Any) -> list[str]:
    """返回站点登录页上与 provider 对应的入口选择器。"""
    if provider.key == "linuxdo":
        return [
            "main button:has-text('使用 LinuxDO 继续')",
            "button:has-text('使用 LinuxDO 继续')",
            "button:has-text('Continue with LinuxDO')",
            "button:has-text('LinuxDO')",
            "button:has-text('Linux.do')",
            "button:has-text('Linux')",
            "button:has(#linuxdo_icon)",
            "text=/使用\\s*LinuxDO\\s*继续/i",
            "text=/Continue\\s+with\\s+LinuxDO/i",
            "text=/LinuxDO|Linux\\.do/i",
            "#linuxdo_icon",
        ]
    if provider.key == "github":
        return [
            "main button:has-text('使用 GitHub 继续')",
            "button:has-text('使用 GitHub 继续')",
            "button:has-text('GitHub')",
            "button:has([aria-label='github_logo'])",
            "text=/使用\\s*GitHub\\s*继续/i",
            "text=/GitHub/i",
        ]
    return DEFAULT_LOGIN_SELECTORS


async def maybe_click_with_popup(
    page: Any,
    locator: Any,
    log: LogFn,
    error_collector: dict[str, Any] | None = None,
    base_url: str = "",
    *, deadline: float | None = None, attempt: _OAuthAttempt | None = None,
) -> Any:
    """入口一旦发出点击或观察到授权导航，只继续该链，不再触发第二条。"""
    log = _oauth_log(log)
    popup_task = asyncio.create_task(page.wait_for_event("popup", timeout=_timeout_ms(deadline, 10000)))
    try:
        # 让 popup waiter 在 click 之前注册；事件跟踪器另外负责极速重定向。
        await asyncio.sleep(0)
        clicked = False
        click_attempts = (
            ("普通点击", lambda: locator.click(timeout=_timeout_ms(deadline, 7000))),
            ("强制点击", lambda: locator.click(timeout=_timeout_ms(deadline, 3000), force=True)),
            ("DOM dispatch", lambda: locator.dispatch_event("click", timeout=_timeout_ms(deadline, 3000))),
        )
        for label, click in click_attempts:
            try:
                await click()
                clicked = True
                break
            except Exception as exc:
                if is_driver_closed_error(exc):
                    raise
                if attempt is not None and attempt.chain_started:
                    return attempt.active_page(page)
                if popup_task.done() and not popup_task.cancelled():
                    try:
                        popup = popup_task.result()
                    except Exception:
                        popup = None
                    if popup is not None:
                        if attempt is not None:
                            attempt.watch(popup, popup=True)
                        return popup
                if deadline is not None and _remaining(deadline, 1) <= 0:
                    raise TimeoutError from None
                log(f"OAuth 入口{label}失败（{type(exc).__name__}）")
        if not clicked:
            log("OAuth 入口点击未成功且未观察到新授权链")
            return None
        if attempt is not None and attempt.chain_started:
            return attempt.active_page(page)
        try:
            popup = await popup_task
        except Exception:
            popup = None
        if popup is not None:
            if attempt is not None:
                attempt.watch(popup, popup=True)
            if error_collector is not None:
                install_site_error_collector(popup, base_url, error_collector)
            log("站点前端已打开 OAuth 弹窗")
            return popup
        if attempt is not None:
            attempt.refresh()
        log("OAuth 入口已点击，继续观察本次导航（不另起直连授权链）")
        return attempt.active_page(page) if attempt is not None else page
    finally:
        if not popup_task.done():
            popup_task.cancel()
        try:
            await popup_task
        except (asyncio.CancelledError, Exception):
            pass


async def click_site_oauth_entry(
    page: Any,
    base_url: str,
    provider: Any,
    log: LogFn = noop,
    error_collector: dict[str, Any] | None = None,
    *, deadline: float | None = None, attempt: _OAuthAttempt | None = None,
    result: dict[str, Any] | None = None,
) -> Any:
    """通过站点登录/注册界面触发一条新授权链。"""
    log = _oauth_log(log)
    selectors = site_oauth_selectors(provider)

    async def _first_visible(selectors_to_try: list[str]) -> tuple[str, Any]:
        for selector in selectors_to_try:
            try:
                locator = page.locator(selector).first
                if await locator.count() <= 0:
                    continue
                try:
                    visible = await locator.is_visible()
                except Exception as visibility_error:
                    if is_driver_closed_error(visibility_error):
                        raise
                    visible = True
                if visible:
                    return selector, locator
            except Exception as exc:
                if is_driver_closed_error(exc):
                    raise
        return "", None

    async def _dismiss_current_popups() -> None:
        closed = await popups.dismiss_popups(page)
        if closed:
            log(f"已关闭 {closed} 个公告/弹窗")
            await _oauth_sleep(0.5, deadline)

    async def _click_oauth_if_visible() -> Any:
        selector, locator = await _first_visible(selectors)
        if locator is None:
            return None
        log(f"点击站点前端 OAuth 登录入口：{selector}")
        return await maybe_click_with_popup(
            page, locator, log, error_collector, base_url, deadline=deadline, attempt=attempt,
        )

    async def _try_switch_auth_panel() -> bool:
        for selector in SITE_OAUTH_TOGGLE_SELECTORS:
            try:
                locator = page.locator(selector).first
                if await locator.count() <= 0:
                    continue
                try:
                    visible = await locator.is_visible()
                except Exception as visibility_error:
                    if is_driver_closed_error(visibility_error):
                        raise
                    visible = True
                if not visible:
                    continue
                before_url = page.url
                log(f"切换站点登录/注册面板以显示 OAuth 入口：{selector}")
                await locator.click(timeout=_timeout_ms(deadline, 7000))
                if attempt is not None and attempt.chain_started:
                    return True
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=_timeout_ms(deadline, 10000))
                except Exception:
                    pass
                await _oauth_sleep(1.2, deadline)
                if page.url != before_url:
                    log("站点登录/注册页已切换")
                await wait_for_ready(page, timeout_ms=_timeout_ms(deadline, 8000), log=log)
                await _dismiss_current_popups()
                return True
            except Exception as exc:
                if is_driver_closed_error(exc):
                    raise
        return False

    root = base_url.rstrip("/")
    targets = [root + "/login", root + "/register", root]
    seen: set[str] = set()
    for target in targets:
        if attempt is not None and attempt.chain_started:
            return attempt.active_page(page)
        if deadline is not None and _remaining(deadline, 1) <= 0:
            raise TimeoutError
        if target in seen:
            continue
        if waf_is_blocked(page):
            log("WAF 熔断，停止逐个打开站点登录页兜底")
            break
        seen.add(target)
        try:
            current_url = page.url.split("#", 1)[0].split("?", 1)[0].rstrip("/")
            target_url = target.rstrip("/")
            if current_url != target_url or (attempt is not None and attempt.require_fresh):
                log("打开站点登录页兜底")
                await _oauth_goto(page, target, deadline, log)
            if attempt is not None and attempt.chain_started:
                return attempt.active_page(page)
            if await bypass.has_cloudflare_challenge(page):
                diagnostics_result = result if result is not None else {}
                if not await _solve_oauth_cf(page, diagnostics_result, "site_entry_cf", deadline, log):
                    return page
            await wait_for_ready(page, timeout_ms=_timeout_ms(deadline, 15000), log=log)
        except Exception as exc:
            if is_driver_closed_error(exc):
                raise
            log(f"打开登录页失败（继续尝试当前页）：{type(exc).__name__}")
        if attempt is not None and attempt.chain_started:
            return attempt.active_page(page)
        await _dismiss_current_popups()

        entry_page = await _click_oauth_if_visible()
        if entry_page is not None:
            return entry_page

        for _ in range(2):
            if not await _try_switch_auth_panel():
                break
            if attempt is not None and attempt.chain_started:
                return attempt.active_page(page)
            entry_page = await _click_oauth_if_visible()
            if entry_page is not None:
                return entry_page

    log("未找到可点击的站点前端 OAuth 登录入口")
    return None


def attach_oauth_completion_messages(
    result: dict[str, Any],
    messages: list[str],
    log: LogFn = noop,
) -> None:
    """成功回跳只保留成功提示；失败诊断也必须移除认证材料。"""
    messages = [_redact_oauth_text(message) for message in messages]
    log = _oauth_log(log)
    if result.get("landed_back"):
        success = site_success_message(messages)
        if success:
            result.setdefault("site_success_message", success)
            log(f"站点成功提示：{success}")
        result.pop("site_error", None)
        result.pop("site_errors", None)
        return
    attach_site_errors(result, messages, log)


def is_oauth_callback_url(url: str, base_url: str) -> bool:
    """严格按同源与回跳特征判断 URL，拒绝字符串包含造成的伪回跳。

    「已经回到本站」本身就是回跳成立的充分条件：同源是硬门槛（provider 页永远
    不同源，不会被误判）。不能再额外要求 /console、/oauth 或 code= —— 有的站点
    callback 成功后直接 302 到业务页并把 code 去掉，实测 ABR 福利站落在
    `/checkin`，旧判据因此把一次成功的回跳报成「未跳回站点」。

    唯一要排除的是仍停留在本站的登录入口：那说明还没真正走完授权。
    """
    if not same_origin(url, base_url):
        return False
    try:
        parsed = urlsplit(str(url or ""))
    except ValueError:
        return False
    if parsed.username or parsed.password:
        return False
    path = parsed.path.casefold()
    # 本站的登录入口不算回跳终点（例如 /auth/<provider>/login）。
    if path.endswith("/login") or "/auth/" in path:
        query = parsed.query.casefold()
        has_code = any(part.partition("=")[0] == "code" for part in query.split("&"))
        # 但带 code 的 /auth/... 正是标准 callback，必须视为回跳成功。
        return has_code
    return True


async def provider_session_present(page: Any, provider: Any) -> bool | None:
    """浏览器上下文里是否仍带着该 provider 的认证 Cookie；读不到返回 None。

    停在第三方登录页时这是唯一能分开两种成因的证据：Cookie 还在却被拒 → 会话确实
    过期/被吊销，重新捕获有用；Cookie 根本不在上下文里 → 是登录态没装进浏览器，
    重新捕获再多次也没用，得先查登录态加载链路。
    """
    try:
        cookies = await page.context.cookies()
    except Exception as exc:
        if is_driver_closed_error(exc):
            raise
        return None
    if not isinstance(cookies, list):
        return None
    try:
        return bool(provider.has_authenticated_state(cookies))
    except Exception:
        return None


async def _finish_oauth_authorization(
    page: Any,
    base_url: str,
    provider: Any,
    result: dict[str, Any],
    log: LogFn = noop,
    error_collector: dict[str, Any] | None = None,
    *, deadline: float | None = None, attempt: _OAuthAttempt,
) -> dict[str, Any]:
    """同一授权链内处理挑战、批准与回跳，成功前再次确认回站页已放行。"""
    if not await _solve_oauth_cf(page, result, "provider_cf", deadline, log):
        attach_site_errors(result, await _safe_site_messages(page, error_collector), log)
        return result
    loop = asyncio.get_running_loop()
    approve_deadline = loop.time() + _remaining(deadline, APPROVE_WAIT_SECONDS)
    callback_deadline: float | None = None
    while True:
        page = attempt.active_page(page)
        attempt.evidence(result)
        if attempt.callback_mismatch:
            return result
        if attempt.landed(page):
            if not await _solve_oauth_cf(page, result, "callback_cf", deadline, log):
                return result
            result["stage"] = "callback_waf"
            if await is_waf_html(page):
                await solve_waf(page, base_url, log, rounds=2)
            if waf_is_blocked(page):
                result.update(waf_blocked=True, landed_back=False)
                return result
            # CF/WAF 处理可能重新导航；不得把导航前的候选回跳当作最终成功。
            attempt.refresh()
            if not attempt.landed(page):
                continue
            result.update(landed_back=True, stage="landed")
            log("OAuth 已观察到回站；服务端登录确认由调用方继续执行")
            attach_oauth_completion_messages(result, await _safe_site_messages(page, error_collector), log)
            return result

        result["stage"] = "approval" if not result["clicked"] and loop.time() < approve_deadline else "callback"
        if result["stage"] == "callback" and callback_deadline is None:
            callback_deadline = loop.time() + _remaining(deadline, OAUTH_WAIT_SECONDS)
        if callback_deadline is not None and loop.time() >= callback_deadline:
            return _mark_oauth_timeout(result, log)

        if attempt.is_provider(getattr(page, "url", "")):
            for marker in provider.login_markers:
                try:
                    if await page.query_selector(marker):
                        result["need_human"] = True
                        result["provider_session_present"] = await provider_session_present(page, provider)
                        log(_provider_login_message(result))
                        attach_site_errors(result, await _safe_site_messages(page, error_collector), log)
                        return result
                except Exception as exc:
                    if is_driver_closed_error(exc):
                        raise
            if result["stage"] == "approval":
                for selector in provider.approve_selectors:
                    try:
                        button = await page.query_selector(selector)
                        if button is None or not await button.is_visible():
                            continue
                        log("点击所选 provider 的授权按钮")
                        await button.click(timeout=_timeout_ms(deadline, 5000))
                        result["clicked"] = True
                        page = attempt.active_page(page)
                        if not await _solve_oauth_cf(page, result, "approval_cf", deadline, log):
                            return result
                        break
                    except Exception as exc:
                        if is_driver_closed_error(exc):
                            raise
                        attempt.refresh()
                        if attempt.landed(page):
                            break
                        log(f"授权按钮等待未成功（{type(exc).__name__}），继续观察")
        page = attempt.active_page(page)
        if attempt.landed(page):
            continue
        if await bypass.has_cloudflare_challenge(page):
            cap = OAUTH_CF_WAIT_SECONDS
            if not result["clicked"] and loop.time() < approve_deadline:
                cap = min(cap, approve_deadline - loop.time())
            if not await _solve_oauth_cf(page, result, "approval_cf", deadline, log, cap=cap):
                return result
        await _oauth_sleep(0.25, deadline)


async def finish_oauth_authorization(
    page: Any,
    base_url: str,
    provider: Any,
    result: dict[str, Any],
    log: LogFn = noop,
    error_collector: dict[str, Any] | None = None,
    *, require_fresh: bool = False, deadline: float | None = None,
    attempt: _OAuthAttempt | None = None,
) -> dict[str, Any]:
    """截止点使用单调时钟；已有授权链透传同一 deadline，不重新分配预算。"""
    log = _oauth_log(log)
    if deadline is None:
        deadline = time.monotonic() + max(
            0.0, float(OAUTH_CF_WAIT_SECONDS + APPROVE_WAIT_SECONDS + OAUTH_WAIT_SECONDS),
        )
    owned = attempt is None
    if attempt is None:
        attempt = _OAuthAttempt(base_url, provider, require_fresh)
        attempt.watch(page)
        attempt.armed = True
    result.setdefault("stage", "authorization")
    try:
        if _remaining(deadline, 1) <= 0:
            return _mark_oauth_timeout(result, log)
        async with asyncio.timeout_at(deadline):
            return await _finish_oauth_authorization(
                page, base_url, provider, result, log, error_collector, deadline=deadline, attempt=attempt,
            )
    except TimeoutError:
        return _mark_oauth_timeout(result, log)
    finally:
        attempt.evidence(result)
        if owned:
            result.pop("cf_pending", None)
            attempt.close()


async def trigger_oauth(
    page: Any,
    base_url: str,
    oauth_provider: str,
    log: LogFn = noop,
    error_collector: dict[str, Any] | None = None,
    *, require_fresh: bool = False, deadline: float | None = None,
) -> dict[str, Any]:
    """触发新授权；fresh 模式必须观察本次 provider 导航或匹配的本站 callback。"""
    log = _oauth_log(log)
    provider = oauth_providers.get_oauth_provider(oauth_provider)
    result: dict[str, Any] = {
        "clicked": False, "landed_back": False, "need_human": False,
        "cloudflare": False, "provider": provider.key, "stage": "site_entry",
    }
    if deadline is None:
        deadline = time.monotonic() + max(
            0.0, float(OAUTH_CF_WAIT_SECONDS + APPROVE_WAIT_SECONDS + OAUTH_WAIT_SECONDS),
        )
    attempt = _OAuthAttempt(base_url, provider, require_fresh)
    attempt.watch(page)
    try:
        if _remaining(deadline, 1) <= 0:
            return _mark_oauth_timeout(result, log)
        async with asyncio.timeout_at(deadline):
            if await bypass.has_cloudflare_challenge(page):
                if not await _solve_oauth_cf(page, result, "site_entry_cf", deadline, log):
                    return result
            result["stage"] = "site_entry"
            if await is_waf_html(page):
                if not waf_is_blocked(page):
                    await solve_waf(page, base_url, log, rounds=2)
                if waf_is_blocked(page):
                    result["waf_blocked"] = True
                    log("站点明确拒绝访问，停止 OAuth 触发")
                    attach_site_errors(result, await _safe_site_messages(page, error_collector), log)
                    return result
            attempt.armed = True
            log(f"尝试通过站点前端登录页触发 {provider.key} OAuth...")
            entry_page = await click_site_oauth_entry(
                page, base_url, provider, log, error_collector, deadline=deadline, attempt=attempt, result=result,
            )
            if result.get("cloudflare"):
                return result
            if entry_page is not None or attempt.chain_started:
                result["frontend_entry"] = True
                return await finish_oauth_authorization(
                    attempt.active_page(entry_page if entry_page is not None else page),
                    base_url, provider, result, log, error_collector,
                    require_fresh=require_fresh, deadline=deadline, attempt=attempt,
                )
            if waf_is_blocked(page):
                result["waf_blocked"] = True
                return result
            log("站点前端未触发授权，申请新 state 后直连授权页")
            result["stage"] = "client_id"
            client_id, enabled = await fetch_oauth_client_id(page, base_url, provider)
            if (not client_id or not enabled) and not attempt.chain_started:
                log(f"未能确认站点已开启 {provider.key} OAuth")
                attach_site_errors(result, await _safe_site_messages(page, error_collector), log)
                return result
            # 前端延迟导航也属于前一条链，不能被 status/state 请求重置。
            if not attempt.chain_started:
                result["stage"] = "state"
                oauth_state, state_diagnostic = await fetch_oauth_state(page, base_url, log, deadline=deadline)
                if not oauth_state and not attempt.chain_started:
                    result["state_error"] = state_diagnostic
                    log(f"未能获取新 OAuth state（{state_diagnostic}）")
                    attach_site_errors(result, await _safe_site_messages(page, error_collector), log)
                    return result
                if not attempt.chain_started:
                    result["stage"] = "provider_navigation"
                    log(f"导航到所选 {provider.key} 授权页")
                    await _oauth_goto(page, provider.build_authorize_url(client_id, oauth_state), deadline, log)
            return await finish_oauth_authorization(
                attempt.active_page(page), base_url, provider, result, log, error_collector,
                require_fresh=require_fresh, deadline=deadline, attempt=attempt,
            )
    except TimeoutError:
        return _mark_oauth_timeout(result, log)
    except Exception as exc:
        result["error"] = "oauth_navigation_failed"
        if is_driver_closed_error(exc):
            result["driver_crashed"] = True
        # 异常字符串可能包含 Playwright call log 及完整 code/state URL。
        safe_error = type(exc).__name__
        log(f"OAuth 阶段失败（{result['stage']}：{safe_error}）")
        add_site_error(error_collector, "exception", safe_error)
        return result
    finally:
        attempt.evidence(result)
        result.pop("cf_pending", None)
        attempt.close()


__all__ = [
    "DEFAULT_LOGIN_SELECTORS",
    "OAUTH_WAIT_SECONDS",
    "SITE_OAUTH_TOGGLE_SELECTORS",
    "api_get_json",
    "attach_oauth_completion_messages",
    "click_site_oauth_entry",
    "extract_oauth_state",
    "fetch_oauth_client_id",
    "fetch_oauth_state",
    "finish_oauth_authorization",
    "is_oauth_callback_url",
    "maybe_click_with_popup",
    "oauth_checkin_result",
    "oauth_failure_reason",
    "oauth_landed",
    "provider_session_present",
    "site_oauth_selectors",
    "trigger_oauth",
]
