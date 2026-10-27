#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""站点 OAuth 触发、第三方授权与结果判定。"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit, urlunsplit

from config.settings import Timeouts

from . import bypass, oauth_providers, popups
from .runtime_loop import LogFn, fetch_json_in_page, is_driver_closed_error, is_network_transport_error, noop
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
# GitHub managed challenge 放行后，前端控件可能还需短暂 hydration；期间只观察，不误报按钮不可用。
GITHUB_AUTHORIZATION_SETTLE_SECONDS = 2.0
# 授权页从 CF 挑战到渲染「允许」按钮的总等待预算（实测 linux.do 约 20 秒）。
APPROVE_WAIT_SECONDS = 60
# 到达第三方授权页时，入口处的 Cloudflare interstitial（"Just a moment"）自动放行
# 的等待预算。实测 connect.linux.do 授权页在数据中心出口 IP 下需约 40 秒才自行放行
# （放行体现为页面级跳转，而非写入 turnstile 令牌字段）。默认 10 秒远不够，会把一次
# 本可通过的挑战判成 need_verification。给足预算是安全的：非挑战页 solve_cloudflare
# 会立即返回，不会空等。
OAUTH_CF_WAIT_SECONDS = 50
# 空白弹窗、初始/循环 CF 共用一次恢复；不重建 state，不重置总预算或阶段预算。
OAUTH_RECOVERY_MIN_SECONDS = 35.0
# 只在既有 approval 窗口内观察尚未提交的导航，避免刚打开弹窗就打断正常首跳。
OAUTH_NAVIGATION_SETTLE_SECONDS = 2.0
_UNLOADED_NAVIGATION = frozenset({"blank", "uncommitted", "load_failed"})
#: Cloudflare 托管挑战放行时附加在原地址上的令牌参数前缀（如 __cf_chl_f_tk / __cf_chl_rt_tk）。
_CF_CHALLENGE_PARAM_PREFIX = "__cf_chl_"


def _query_keys(query: str) -> list[str]:
    return [segment.split("=", 1)[0] for segment in query.split("&") if segment] if query else []


def _cf_challenge_url(url: str) -> bool:
    """挑战平台自身的请求/回传：属于 Cloudflare 放行流程，不是用户的授权动作。"""
    try:
        parsed = urlsplit(str(url or ""))
    except ValueError:
        return False
    if parsed.path.startswith("/cdn-cgi/challenge-platform/"):
        return True
    return any(key.startswith(_CF_CHALLENGE_PARAM_PREFIX) for key in _query_keys(parsed.query))


def _without_cf_challenge_params(url: str) -> str:
    """去掉挑战令牌参数，保留其余查询的原始编码，用于与本链已观察的授权地址比对。"""
    text = str(url or "")
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text
    segments = [segment for segment in parsed.query.split("&") if segment] if parsed.query else []
    kept = [segment for segment in segments if not segment.split("=", 1)[0].startswith(_CF_CHALLENGE_PARAM_PREFIX)]
    if len(kept) == len(segments):
        return text
    return urlunsplit(parsed._replace(query="&".join(kept)))

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


def _navigation_failure(error: Any) -> str:
    """只保留明确的加载失败枚举，导航被新请求取消不等于网络故障。"""
    lines = str(error or "").splitlines()
    text = _redact_oauth_text(lines[0] if lines else "").lower()
    if "err_aborted" in text or "ns_binding_aborted" in text:
        return ""
    return "network" if is_network_transport_error(text) else ""


class _OAuthAttempt:
    """授权地址仅在本链内存中使用；结果与日志只有布尔/枚举证据。"""

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
        self.pending_requests: dict[int, list[tuple[str, str, str]]] = {}
        self.requested_pages: set[int] = set()
        self.popup_pages: set[int] = set()
        self.retired_pages: set[int] = set()
        self.authorize_urls: dict[int, str] = {}
        self.ambiguous_authorize: set[int] = set()
        self.load_failures: dict[int, str] = {}
        self.submission_observed = False
        self.recovery_attempted = False

    def is_provider(self, url: str) -> bool:
        try:
            parsed = urlsplit(url)
            return (
                not parsed.username and not parsed.password and parsed.port in (None, 443)
                and not same_origin(url, self.base_url) and self.provider.matches_url(url)
            )
        except (AttributeError, ValueError):
            return False

    def is_authorize_url(self, url: str) -> bool:
        """恢复仅接受所选 provider 的精确授权端点、单一 state/client_id 和本站回调。"""
        try:
            if not isinstance(url, str) or any(char.isspace() or ord(char) < 32 for char in url) or "\\" in url:
                return False
            parsed = urlsplit(url)
            endpoint = urlsplit(self.provider.authorize_endpoint)
            if (not self.is_provider(url) or not same_origin(url, self.provider.authorize_endpoint)
                    or parsed.path != endpoint.path or parsed.fragment):
                return False
            query = parse_qs(parsed.query, keep_blank_values=True)
            if any(len(query.get(key, [])) != 1 or not query[key][0].strip() for key in ("state", "client_id")):
                return False
            if query.get("response_type", ["code"]) != ["code"]:
                return False
            if any(key in query for key in ("code", "token", "access_token", "refresh_token", "client_secret")):
                return False
            if "redirect_uri" in query:
                redirects = query["redirect_uri"]
                if len(redirects) != 1 or not same_origin(redirects[0], self.base_url):
                    return False
                redirect = urlsplit(redirects[0])
                if redirect.username or redirect.password or redirect.fragment:
                    return False
            return True
        except (AttributeError, ValueError):
            return False

    def navigation_state(self, page: Any) -> str:
        url = str(getattr(page, "url", "") or "")
        if url.startswith(("about:neterror", "chrome-error://", "edge-error://")):
            return "load_failed"
        if id(page) in self.load_failures:
            return "load_failed"
        if url in {"", "about:blank"}:
            return "uncommitted" if id(page) in self.requested_pages else "blank"
        if self.is_provider(url):
            return "provider"
        if id(page) in self.requested_pages and id(page) not in self.provider_pages:
            return "uncommitted"
        return "site" if same_origin(url, self.base_url) else "other"

    def observe(
        self, page: Any, url: str, *, event: bool = False, request: bool = False,
        method: str = "GET", failure: str = "",
    ) -> None:
        previous = self.urls.get(id(page), "")
        if not request:
            self.urls[id(page)] = str(url or "")
        if not self.armed or (not event and url == previous):
            return
        if not request and url not in {"", "about:blank"}:
            self.load_failures.pop(id(page), None)
            self.requested_pages.discard(id(page))
        if failure and (self.is_provider(url) or same_origin(url, self.base_url)):
            self.load_failures[id(page)] = failure
        if self.is_provider(url):
            if request:
                self.provider_requested = True
                self.requested_pages.add(id(page))
                approve_path = (
                    self.provider.key == "linuxdo" and urlsplit(url).path.rstrip("/") == "/oauth2/approve"
                )
                # Cloudflare 托管挑战放行时会向同一地址回传一次表单（带 __cf_chl_* 令牌）。那是
                # 挑战平台的提交而非授权：若据此锁链，会跳过「允许」按钮空等回跳并误报不可达。
                # LinuxDO /oauth2/authorize 的挑战 POST 也可能不带 __cf_chl_*，
                # 只有 /oauth2/approve 才证明批准；GitHub 则只认正式授权端点的提交。
                github_approval = (
                    self.provider.key == "github" and method != "GET"
                    and same_origin(url, self.provider.authorize_endpoint)
                    and urlsplit(url).path == urlsplit(self.provider.authorize_endpoint).path
                    and not _cf_challenge_url(url)
                )
                if approve_path or github_approval:
                    self.submission_observed = True
            else:
                self.provider_seen = True
                self.provider_pages.add(id(page))
            # 挑战令牌变体与原授权地址是同一个；不同 state 仍按歧义处理，绝不导航旧 nonce。
            clean = _without_cf_challenge_params(url)
            if (not request or method == "GET") and self.is_authorize_url(clean):
                previous_authorize = self.authorize_urls.setdefault(id(page), clean)
                if previous_authorize != clean:
                    self.ambiguous_authorize.add(id(page))
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

    def observe_request(self, request: Any, *, failed: bool = False, pending: bool = False) -> None:
        if not self.armed:
            return
        try:
            page = request.frame.page
            if request.frame is not page.main_frame or not (
                request.is_navigation_request() or (
                    not pending and _provider_callback(request.url, self.base_url, self.provider)
                )
            ):
                return
            method = str(getattr(request, "method", "GET")).upper()
            failure = _navigation_failure(getattr(request, "failure", "")) if failed else ""
            if failed and not failure:
                return
            if any(item is page for item in self.pages):
                self.observe(page, request.url, event=True, request=True, method=method, failure=failure)
            elif pending and len(self.pending_requests) < 16:
                self.pending_requests.setdefault(id(page), []).append((request.url, method, failure))
                self.pending_requests[id(page)] = self.pending_requests[id(page)][-12:]
        except Exception:
            pass

    def watch(self, page: Any, *, popup: bool = False) -> None:
        if any(item is page for item in self.pages):
            return
        self.pages.append(page)
        if popup:
            self.popup_pages.add(id(page))
        self.observe(page, getattr(page, "url", ""), event=popup)
        # popup 可能晚于初始请求/302；只接受已确认属于本次 opener 的请求证据。
        # 单次 URL 快照不能抹除明确的 requestfailed；后续真实提交事件才可清除它。
        for url, method, failure in self.pending_requests.pop(id(page), []):
            self.observe(page, url, event=True, request=True, method=method, failure=failure)
        context = getattr(page, "context", None)
        if id(context) not in self.contexts and callable(getattr(context, "on", None)):
            self.contexts.add(id(context))
            for event, callback in (
                ("request", lambda request: self.observe_request(request, pending=True)),
                ("requestfailed", lambda request: self.observe_request(request, failed=True, pending=True)),
            ):
                context.on(event, callback)
                self.listeners.append((context, event, callback))

        def navigation(frame: Any) -> None:
            if frame is getattr(page, "main_frame", None):
                self.observe(page, getattr(frame, "url", ""), event=True)

        for event, callback in (
            ("framenavigated", navigation), ("request", self.observe_request),
            ("requestfailed", lambda request: self.observe_request(request, failed=True)),
            ("popup", lambda new_page: self.watch(new_page, popup=True) if self.armed else None),
        ):
            on = getattr(page, "on", None)
            if callable(on):
                on(event, callback)
                self.listeners.append((page, event, callback))

    def refresh(self) -> None:
        for page in self.pages:
            if id(page) in self.retired_pages:
                continue
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
            if id(page) in self.retired_pages:
                continue
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
        for page in live_pages:
            if id(page) in self.popup_pages:
                return page
        return live_pages[0] if id(fallback) in self.retired_pages and live_pages else fallback

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
        self.refresh()
        result["fresh_authorization"] = bool(
            result.get("landed_back") and (self.callback_seen or self.returned) and not self.callback_mismatch
        )
        result["fresh_evidence"] = {
            "provider_observed": self.provider_seen,
            "callback_observed": self.callback_seen,
        }
        current = self.active_page(self.pages[0]) if self.pages else None
        nav_state = self.navigation_state(current)
        result["navigation"] = {
            "state": nav_state,
            "provider_observed": self.provider_seen or self.is_provider(getattr(current, "url", "")),
            "provider_requested": self.provider_requested,
            "load_error": self.load_failures.get(id(current), "browser_error" if nav_state == "load_failed" else "none"),
            "recovery_attempted": self.recovery_attempted,
            "submission_observed": self.submission_observed,
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
        self.authorize_urls.clear()
        self.load_failures.clear()


async def _oauth_goto(
    page: Any, url: str, deadline: float | None, log: LogFn, *, attempt: _OAuthAttempt | None = None,
) -> None:
    """只发出一次导航；恢复资格和同链共享次数由调用方检查。

    只等导航「提交」而非 ``domcontentloaded``：AgentRouter 这类站点在 Cloudflare /
    阿里云 WAF 后常常长时间不触发 domcontentloaded（CI 实测 30s 仍不触发），死等它
    会把本该立刻开始的挑战求解与入口点击一起拖住，最后被阶段上限截断、误报「站点
    不可达」。导航已提交就足够——后续的挑战求解与 DOM 轮询都在页面自身上做。
    """
    try:
        timeout = _timeout_ms(deadline, 30000)
        if attempt is not None:
            attempt.observe(page, url, event=True, request=True)
        await page.goto(url, wait_until="commit", timeout=timeout)
    except Exception as exc:
        if is_driver_closed_error(exc):
            raise
        if attempt is not None:
            attempt.refresh()
            failure = _navigation_failure(exc)
            if failure:
                attempt.load_failures[id(page)] = failure
        if deadline is not None and _remaining(deadline, 1) <= 0:
            raise TimeoutError from None
        log(f"OAuth 导航等待未完成（{type(exc).__name__}），继续观察本次导航")


async def _safe_site_messages(page: Any, collector: dict[str, Any] | None) -> list[str]:
    return [_redact_oauth_text(item) for item in await site_error_messages(page, collector)]


_PROVIDER_ERROR_CODES = frozenset({
    "unauthorized_client", "invalid_client", "invalid_request", "invalid_scope",
    "unsupported_response_type", "access_denied", "server_error", "temporarily_unavailable",
})


async def _provider_error_code(page: Any) -> str:
    """只读取授权页明确显示的标准错误码，不保留正文、身份或授权参数。"""
    try:
        query = getattr(page, "query_selector_all", None)
        if not callable(query):
            return ""
        for heading in (await query("h1, h2, [role='heading']"))[:8]:
            if not await heading.is_visible():
                continue
            code = (await heading.inner_text()).strip().lower()
            if code in _PROVIDER_ERROR_CODES:
                return code
    except Exception as exc:
        if is_driver_closed_error(exc):
            raise
    return ""


#: 错误页正文只允许出现这些类别词，其余一律丢弃。
#: 顺序即优先级：先判更具体的成因，避免 "client" 命中 "unauthorized_client" 本身
#: 这种把错误码当成正文证据的误判。
_PROVIDER_ERROR_HINTS = (
    ("redirect_uri", "重定向地址不匹配"),
    ("redirect uri", "重定向地址不匹配"),
    ("回调地址", "重定向地址不匹配"),
    ("重定向", "重定向地址不匹配"),
    ("does not exist", "应用不存在"),
    ("not registered", "应用不存在"),
    ("不存在", "应用不存在"),
    ("scope", "授权范围不符"),
    ("client", "应用标识无效"),
    ("unauthorized", "应用未获授权"),
)


def _strip_provider_error_codes(text: str) -> str:
    """去掉正文里的标准错误码，剩下的才是页面对成因的自然语言说明。"""
    cleaned = text
    for code in _PROVIDER_ERROR_CODES:
        cleaned = cleaned.replace(code, " ")
    return cleaned


async def _provider_error_hint(page: Any) -> str:
    """从错误页正文里取出**类别**，用于区分同码不同因。

    ``unauthorized_client`` 既可能是应用被吊销、也可能是回调地址不在注册表里，
    两者修法完全不同。这里只映射到固定类别文案，不回传任何原始文本，
    避免页面上的授权参数或身份信息进入日志与错误数据。
    """
    try:
        query = getattr(page, "query_selector_all", None)
        if not callable(query):
            return ""
        nodes = (await query("p, li, [role='alert'], .error, .message"))[:12]
        for node in nodes:
            try:
                if not await node.is_visible():
                    continue
                raw = (await node.inner_text() or "").strip().casefold()
            except Exception:
                continue
            text = _strip_provider_error_codes(raw)
            if not text.strip():
                continue
            for needle, hint in _PROVIDER_ERROR_HINTS:
                if needle in text:
                    return hint
    except Exception as exc:
        if is_driver_closed_error(exc):
            raise
    return ""


def _mark_oauth_timeout(
    result: dict[str, Any], log: LogFn, *, kind: str = "overall",
) -> dict[str, Any]:
    stage = result.get("stage", "authorization")
    result.update(error="oauth_timeout", timeout_stage=stage, timeout_kind=kind, landed_back=False)
    diagnostics = result.get("cf_diagnostics")
    if isinstance(diagnostics, dict) and result.get("cf_pending"):
        diagnostics.update(timeout_stage=stage, reason="deadline_exceeded")
        result["cloudflare"] = True
    if kind == "overall":
        result["remaining_seconds"] = 0.0
    reason = "阶段等待上限已到" if kind == "phase_cap" else "总预算耗尽"
    log(f"OAuth {reason}（阶段：{stage}；页面类别：{result.get('page_kind', 'unknown')}；"
        f"clicked={bool(result.get('clicked'))}；callback={bool(result.get('callback_observed'))}；"
        f"popup={bool(result.get('popup'))}；剩余秒={result.get('remaining_seconds', 0):.1f}），"
        "停止等待并保留原登录态")
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
        if diagnostics.get("page_state") == "unknown" and diagnostics.get("challenge_observed") is False:
            log(f"OAuth 页面状态尚未确认（阶段：{stage}；未观察到明确挑战），停止后续授权")
        else:
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
    return (bool(link.get("landed_back")) and not link.get("need_human")
            and not link.get("waf_blocked") and not link.get("provider_error"))


def oauth_failure_reason(link: dict[str, Any]) -> str:
    """OAuth 链路没走通时的具体原因；走通了返回空串。

    独立成函数是因为顺序即语义：relogin 站点在登录前读额度必然失败（当时确实
    未登录），所以「读不到额度」是最弱的线索，绝不能盖住「停在第三方登录页」这类
    确定原因。旧实现把「额度前后都读不到」放在最前面判定，于是日志里明明写着
    「停在 github 登录页」，结论却只剩一句「无法读取额度，登录态可能已失效」。
    """
    if link.get("waf_blocked"):
        return "waf_blocked"
    if link.get("provider_error") in _PROVIDER_ERROR_CODES:
        return "provider_error"
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
    if link.get("human_reason") == "account_selection":
        return f"{provider} 需要人工确认账号身份，未自动选择账号；请在管理界面确认并重新捕获登录态。"
    if link.get("human_reason") == "verification":
        return f"{provider} 需要人工完成密码或二次验证；请在管理界面完成验证并重新捕获登录态。"
    if link.get("human_reason") == "authorization_unavailable":
        return f"{provider} 授权确认按钮不可用或页面未提供；请在管理界面完成授权并重新捕获登录态。"
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
    if reason == "provider_error":
        code = link["provider_error"]
        result["status"] = "need_config" if code in {
            "unauthorized_client", "invalid_client", "invalid_request", "invalid_scope",
            "unsupported_response_type",
        } else "failed"
        result["message"] = f"OAuth 提供商拒绝授权（{code}），请检查站点应用的授权配置。"
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


def _is_github_authorization_url(url: Any, provider: Any) -> bool:
    """仅识别 GitHub HTTPS 正式授权端点，不把相似主机当作授权页。"""
    if getattr(provider, "key", "") != "github":
        return False
    try:
        parsed = urlsplit(str(url or ""))
        return (
            parsed.scheme.lower() == "https"
            and parsed.hostname == "github.com"
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
            and parsed.path == "/login/oauth/authorize"
            and not parsed.fragment
        )
    except (AttributeError, ValueError):
        return False


async def _github_authorization_candidate(page: Any, provider: Any) -> tuple[Any | None, bool]:
    """在 GitHub 正式授权页安全查找正式授权控件。

    GitHub 的授权页可能省略 form action、button type/name/value，或先渲染隐藏
    的重复表单。只接受当前 HTTPS ``github.com/login/oauth/authorize`` 页面中，
    action 精确指向同一路径、且控件文本/属性明确表示授权的 button/input；第二项
    仅表示发现了合法但当前不可操作的候选，不把任意 Continue/Submit 当授权。
    """
    if provider.key != "github":
        return None, False
    try:
        parsed = urlsplit(str(getattr(page, "url", "")))
        if (
            parsed.scheme.lower() != "https"
            or parsed.hostname != "github.com"
            or parsed.port not in (None, 443)
            or parsed.username
            or parsed.password
            or parsed.path != "/login/oauth/authorize"
        ):
            return None, False
    except (AttributeError, ValueError):
        return None, False

    query_all = getattr(page, "query_selector_all", None)
    if not callable(query_all):
        return None, False
    try:
        # 不把 type/name/value 写死在 CSS 选择器中；不同 GitHub 页面版本会省略
        # 其中部分属性。正式表单 action 与授权语义在页面上下文内严格验证。
        controls = await query_all('button, input')
    except Exception as exc:
        if is_driver_closed_error(exc):
            raise
        return None, False

    found = False
    for control in controls:
        try:
            info = await control.evaluate(r"""el => {
                const form = el.form;
                if (!form || !['BUTTON', 'INPUT'].includes(el.tagName)) return null;
                const action = new URL(form.getAttribute('action') || '', location.href);
                const type = String(el.type || (el.tagName === 'BUTTON' ? 'submit' : '')).toLowerCase();
                const text = (el.textContent || el.value || el.getAttribute('aria-label') || '').trim();
                const testid = (el.getAttribute('data-testid') || '').toLowerCase();
                const semantic = el.name === 'authorize'
                    || /authorize|authorization|allow/i.test(text)
                    || /authorize|authorization/i.test(testid);
                if (location.origin !== 'https://github.com'
                    || location.pathname !== '/login/oauth/authorize'
                    || action.origin !== location.origin
                    || action.pathname !== '/login/oauth/authorize'
                    || type !== 'submit' || !semantic) return null;
                return {valid: true};
            }""")
            if not isinstance(info, dict) or not info.get("valid"):
                continue
            if not await control.is_visible():
                continue
            found = True
            if not await control.is_enabled():
                continue
            return control, False
        except Exception as exc:
            if is_driver_closed_error(exc):
                raise
    return None, found


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
            # no_wait_after：入口点击后跳到 provider 的 CF 挑战页可能迟迟不 commit，Playwright
            # 默认等导航会把「已经点中」误报成超时，随后强制点击/dispatch 会再起第二、三条
            # 授权链并刷新挑战。导航由 attempt 事件跟踪，不需要 click 自己等。
            ("普通点击", lambda: locator.click(timeout=_timeout_ms(deadline, 7000), no_wait_after=True)),
            ("强制点击", lambda: locator.click(
                timeout=_timeout_ms(deadline, 3000), force=True, no_wait_after=True,
            )),
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
                if attempt is not None and not attempt.chain_started:
                    # 点击可能已生效只是导航还没被观察到：稍等再判，避免补点重复起链。
                    for _ in range(6):
                        if attempt.chain_started or popup_task.done():
                            break
                        if deadline is not None and _remaining(deadline, 1) <= 0:
                            break
                        await asyncio.sleep(0.25)
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
                await _oauth_goto(page, target, deadline, log, attempt=attempt)
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


async def _recover_oauth_navigation(
    page: Any, attempt: _OAuthAttempt, result: dict[str, Any], deadline: float | None,
    log: LogFn, *, cloudflare: bool = False,
) -> Any:
    """同链的一次 GET 恢复；绝不重建 state、重发认证提交或放宽授权来源。"""
    attempt.refresh()

    def locked() -> bool:
        diagnostics = result.get("cf_diagnostics")
        return bool(
            not attempt.armed or attempt.callback_seen or attempt.callback_mismatch or attempt.returned
            or attempt.submission_observed or result.get("clicked") or result.get("intermediate_clicked")
            or result.get("need_human") or result.get("waf_blocked") or result.get("landed_back")
            or (isinstance(diagnostics, dict) and diagnostics.get("blocked") is True)
        )

    if attempt.recovery_attempted or locked() or not attempt.pages:
        return None
    url = attempt.authorize_urls.get(id(page), "")

    def authorization_unchanged() -> bool:
        return bool(
            attempt.authorize_urls.get(id(page)) == url
            and not attempt.ambiguous_authorize
            and set(attempt.authorize_urls.values()) == {url}
            and attempt.is_authorize_url(url)
        )

    if not authorization_unchanged():
        return None
    unloaded = attempt.navigation_state(page) in _UNLOADED_NAVIGATION
    if not unloaded and (not cloudflare or _without_cf_challenge_params(str(getattr(page, "url", ""))) != url):
        return None
    opener = attempt.pages[0]
    popup = page is not opener and id(page) in attempt.popup_pages
    if not popup and not cloudflare:
        return None
    target = opener if popup else page
    if popup and not same_origin(str(getattr(opener, "url", "")), attempt.base_url):
        return None
    if _remaining(deadline, 1e9) < OAUTH_RECOVERY_MIN_SECONDS:
        return None
    try:
        if target.is_closed() or page.is_closed():
            return None
    except Exception:
        return None
    # 在任何 await 前消费唯一预算：关闭失败或调用超时也不能再重试。
    attempt.recovery_attempted = True
    if popup:
        try:
            await asyncio.wait_for(page.close(), timeout=_remaining(deadline, 5.0))
        except Exception as exc:
            if is_driver_closed_error(exc):
                raise
            return None
        attempt.retired_pages.add(id(page))
    attempt.refresh()
    # close() 会让出执行权；期间任何页面的新 state 都使原绑定失效，不能导航旧 nonce。
    if locked() or not authorization_unchanged() or _remaining(deadline, 1e9) < OAUTH_RECOVERY_MIN_SECONDS:
        return None
    if popup and not same_origin(str(getattr(opener, "url", "")), attempt.base_url):
        return None
    reason = "Cloudflare 未放行" if cloudflare else "导航尚未加载"
    destination = "主标签页" if popup else "当前标签页"
    log(f"OAuth {reason}，仅在{destination}恢复本链已观察到的同一授权地址（最多一次）")
    for key in ("cloudflare", "error"):
        result.pop(key, None)
    result["stage"] = "provider_navigation"
    await _oauth_goto(target, url, deadline, log, attempt=attempt)
    attempt.refresh()
    return target


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
    # 授权窗口从进入本条链就开始计时，而不是等 provider_cf 走完再起算。
    # 实测 connect.linux.do 的授权页 CF 要几十秒才放行，前序挑战一旦吃掉大半预算，
    # 到 approval_cf 时只剩二十来秒，会把一次本可通过的放行误报成页面空白。
    # 起点前移不改变「阶段窗口是硬上限」的约束：仍然不超过 deadline。
    approve_budget = _remaining(deadline, APPROVE_WAIT_SECONDS)
    approve_started = time.monotonic()

    async def challenge(current: Any, stage: str, limit: float | None) -> tuple[Any, bool]:
        # 空白/明确加载失败不是 CF 证据，不把 page_wait 失败猜成挑战或 IP 问题。
        if attempt.navigation_state(current) in _UNLOADED_NAVIGATION:
            return current, True
        if await _solve_oauth_cf(current, result, stage, limit, log):
            return current, True
        recovered = await _recover_oauth_navigation(current, attempt, result, limit, log, cloudflare=True)
        if recovered is None:
            return current, False
        if attempt.navigation_state(recovered) in _UNLOADED_NAVIGATION:
            return recovered, True
        return recovered, await _solve_oauth_cf(recovered, result, stage, limit, log)

    page, passed = await challenge(page, "provider_cf", deadline)
    if not passed:
        attach_site_errors(result, await _safe_site_messages(page, error_collector), log)
        return result
    approve_deadline = approve_started + approve_budget
    # 预算诊断：授权页 CF 分到的窗口偏小时，需要知道是总截止点不够还是阶段切分过紧。
    log(
        f"授权阶段预算：总剩余 {_remaining(deadline, 10 ** 6):.1f}s，"
        f"授权窗口 {approve_budget:.1f}s，approval_cf 上限 {_remaining(approve_deadline, 10 ** 6):.1f}s"
    )
    callback_deadline: float | None = None
    submitted_intermediates: set[str] = set()
    unloaded_since: dict[int, float] = {}
    last_progress = None
    authorization_candidate_unavailable = False
    authorization_candidate_since: float | None = None

    def diagnose(kind: str | None = None) -> None:
        nonlocal last_progress
        if kind is None and not result.get("clicked") and _is_github_authorization_url(
            getattr(page, "url", ""), provider,
        ):
            kind = "provider_authorization"
        if kind is not None:
            result["page_kind"] = kind
        attempt.evidence(result)
        result.update(callback_observed=attempt.callback_seen, popup=len(attempt.pages) > 1,
                      remaining_seconds=round(_remaining(deadline, 1e9), 1))
        navigation = result["navigation"]
        progress = (result.get("page_kind", "unknown"), bool(result.get("clicked")),
                    attempt.callback_seen, result["popup"], result.get("stage"),
                    navigation["state"], navigation["recovery_attempted"])
        if progress != last_progress:
            log(f"OAuth 页面类别={progress[0]}；clicked={progress[1]}；callback={progress[2]}；"
                f"popup={progress[3]}；导航={progress[5]}；provider已出现={navigation['provider_observed']}；"
                f"恢复已尝试={progress[6]}；剩余秒={result['remaining_seconds']:.1f}")
            last_progress = progress

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
            diagnose("site_callback")
            log("OAuth 已观察到回站；服务端登录确认由调用方继续执行")
            attach_oauth_completion_messages(result, await _safe_site_messages(page, error_collector), log)
            return result

        if attempt.is_provider(str(getattr(page, "url", "") or "")):
            provider_error = await _provider_error_code(page)
            if provider_error:
                result.update(provider_error=provider_error, landed_back=False, stage="provider_error")
                hint = await _provider_error_hint(page)
                if hint:
                    result["provider_error_hint"] = hint
                diagnose("provider_error")
                log(f"OAuth 提供商拒绝授权：{provider_error}；停止本链并保留原登录态")
                return result

        # 未完成正式授权或身份确认时只能停留在 approval 阶段。旧逻辑会在
        # approve_deadline 到期后无条件创建 callback_deadline，导致 clicked=False
        # 的 provider 页面白等完整回跳预算并被误归因成 callback 网络失败。
        authorization_started = bool(
            result.get("clicked") or result.get("intermediate_clicked") or attempt.submission_observed
        )
        if not authorization_started:
            result["stage"] = "approval"
            diagnose()
            if time.monotonic() >= approve_deadline:
                if authorization_candidate_unavailable:
                    result.update(
                        need_human=True,
                        human_reason="authorization_unavailable",
                        provider_session_present=await provider_session_present(page, provider),
                    )
                    diagnose("provider_authorization")
                    log("GitHub 正式授权按钮候选存在但不可点击，需要人工处理")
                    attach_site_errors(result, await _safe_site_messages(page, error_collector), log)
                    return result
                kind = "overall" if _remaining(deadline, 1) <= 0 else "phase_cap"
                return _mark_oauth_timeout(result, log, kind=kind)
        else:
            result["stage"] = "callback"
            if callback_deadline is None:
                callback_deadline = time.monotonic() + _remaining(deadline, OAUTH_WAIT_SECONDS)
            diagnose()
            if time.monotonic() >= callback_deadline:
                kind = "overall" if _remaining(deadline, 1) <= 0 else "phase_cap"
                return _mark_oauth_timeout(result, log, kind=kind)

        navigation = attempt.navigation_state(page)
        if navigation in _UNLOADED_NAVIGATION:
            since = unloaded_since.setdefault(id(page), time.monotonic())
            if not authorization_started and (
                navigation == "load_failed" or time.monotonic() - since >= OAUTH_NAVIGATION_SETTLE_SECONDS
            ):
                recovered = await _recover_oauth_navigation(page, attempt, result, approve_deadline, log)
                if recovered is not None:
                    page = recovered
                    continue
            await _oauth_sleep(0.25, deadline)
            continue
        unloaded_since.pop(id(page), None)

        authorization_unavailable = False
        if attempt.is_provider(getattr(page, "url", "")):
            verification_path = urlsplit(str(page.url)).path.startswith(("/sessions/two-factor", "/login/device", "/settings/sudo"))
            # GitHub 登录页的用户名/密码字段优先归类为 provider_login；
            # 通用 password/OTP 标记仍用于二次验证页面。
            markers = [(marker, "login") for marker in provider.login_markers]
            markers += [(marker, "verification") for marker in getattr(provider, "human_markers", [])]
            for marker, reason in markers:
                try:
                    element = await page.query_selector(marker)
                    if (verification_path and provider.key == "github") or (
                        element is not None and await element.is_visible()
                    ):
                        result.update(need_human=True, human_reason="verification" if verification_path else reason)
                        result["provider_session_present"] = await provider_session_present(page, provider)
                        diagnose("provider_verification" if result["human_reason"] == "verification" else "provider_login")
                        log(_provider_login_message(result))
                        attach_site_errors(result, await _safe_site_messages(page, error_collector), log)
                        return result
                except Exception as exc:
                    if is_driver_closed_error(exc):
                        raise
            if not result["clicked"] and not (attempt.submission_observed and not result.get("intermediate_clicked")):
                for selector in provider.approve_selectors:
                    try:
                        button = await page.query_selector(selector)
                        if button is None or not await button.is_visible() or not await button.is_enabled():
                            continue
                        # 点击一旦发起即锁定本链：驱动导航超时不证明 submit 未送达，不能重发。
                        result["clicked"] = True
                        callback_deadline = time.monotonic() + _remaining(deadline, OAUTH_WAIT_SECONDS)
                        diagnose("provider_authorization")
                        log("点击所选 provider 的正式授权按钮")
                        await button.click(timeout=_timeout_ms(deadline, 5000), no_wait_after=True)
                    except Exception as exc:
                        if is_driver_closed_error(exc):
                            raise
                        attempt.refresh()
                        log(f"授权按钮等待未成功（{type(exc).__name__}），仅观察本链回跳")
                    if result["clicked"]:
                        break
                if not result["clicked"] and provider.key == "github":
                    try:
                        fallback_button, unavailable = await _github_authorization_candidate(page, provider)
                    except Exception as exc:
                        if is_driver_closed_error(exc):
                            raise
                        fallback_button, unavailable = None, True
                    if fallback_button is not None:
                        result["clicked"] = True
                        callback_deadline = time.monotonic() + _remaining(deadline, OAUTH_WAIT_SECONDS)
                        diagnose("provider_authorization")
                        log("点击所选 provider 的正式授权按钮")
                        try:
                            await fallback_button.click(timeout=_timeout_ms(deadline, 5000), no_wait_after=True)
                        except Exception as exc:
                            if is_driver_closed_error(exc):
                                raise
                            attempt.refresh()
                            log(f"授权按钮等待未成功（{type(exc).__name__}），仅观察本链回跳")
                    else:
                        # 先让 intermediate_action 检查同一页面上的身份确认按钮；
                        # 授权页刚完成 CF 时 DOM 可能仍在渲染，保留状态并继续轮询，
                        # 不因一次隐藏/不可用候选立即终止整条授权链。
                        authorization_unavailable = unavailable
                        authorization_candidate_unavailable = (
                            authorization_candidate_unavailable or unavailable
                        )
                        if unavailable and authorization_candidate_since is None:
                            authorization_candidate_since = time.monotonic()
                if not result["clicked"]:
                    intermediate = getattr(provider, "intermediate_action", None)
                    if callable(intermediate):
                        try:
                            kind, button, human = await intermediate(page)
                            diagnose(kind)
                            if human:
                                result.update(need_human=True, human_reason="account_selection")
                                log(_provider_login_message(result))
                                return result
                            if button is not None and kind not in submitted_intermediates:
                                submitted_intermediates.add(kind)
                                result["intermediate_clicked"] = True
                                if callback_deadline is None:
                                    callback_deadline = time.monotonic() + _remaining(deadline, OAUTH_WAIT_SECONDS)
                                log("推进所选 provider 的身份确认（非正式授权）")
                                await button.click(timeout=_timeout_ms(deadline, 5000), no_wait_after=True)
                        except Exception as exc:
                            if is_driver_closed_error(exc):
                                raise
                            attempt.refresh()
                            log(f"身份确认等待未成功（{type(exc).__name__}），仅观察本链进展")
                if (
                    authorization_unavailable
                    and not result.get("clicked")
                    and not result.get("intermediate_clicked")
                    and authorization_candidate_since is not None
                    and time.monotonic() - authorization_candidate_since >= GITHUB_AUTHORIZATION_SETTLE_SECONDS
                ):
                    result.update(
                        need_human=True,
                        human_reason="authorization_unavailable",
                        provider_session_present=await provider_session_present(page, provider),
                    )
                    diagnose("provider_authorization")
                    log("GitHub 正式授权按钮持续不可用，需要人工处理")
                    attach_site_errors(result, await _safe_site_messages(page, error_collector), log)
                    return result
        page = attempt.active_page(page)
        if attempt.landed(page):
            continue
        if await bypass.has_cloudflare_challenge(page):
            phase_deadline = callback_deadline if callback_deadline is not None else approve_deadline
            page, passed = await challenge(page, "approval_cf", phase_deadline)
            if not passed:
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
        # 调用方（福利站脚本）已自行发起本链并停在提供商页：把当前地址记为本链观察到的
        # 授权页，同链恢复才能复用它；只记录提供商域名，不改站内回跳的判定。
        current = str(getattr(page, "url", "") or "")
        if attempt.is_provider(current):
            attempt.observe(page, current, event=True)
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
                    # 提供商只按注册值精确比对回调；站点不同版本注册的路径不同，
                    # 给错就回 unauthorized_client。逐个试，命中即用。
                    candidates = provider.redirect_candidates(base_url) or ("",)
                    for index, redirect in enumerate(candidates):
                        suffix = f"（回调候选 {index + 1}/{len(candidates)}）" if len(candidates) > 1 else ""
                        log(f"导航到所选 {provider.key} 授权页{suffix}")
                        await _oauth_goto(
                            page, provider.build_authorize_url(client_id, oauth_state, redirect_uri=redirect),
                            deadline, log, attempt=attempt,
                        )
                        outcome = await finish_oauth_authorization(
                            attempt.active_page(page), base_url, provider, result, log, error_collector,
                            require_fresh=require_fresh, deadline=deadline, attempt=attempt,
                        )
                        # 只有「提供商不认这个应用」值得换回调；其它错误换回调没有意义。
                        if outcome.get("provider_error") != "unauthorized_client":
                            return outcome
                        if index + 1 >= len(candidates):
                            return outcome
                        log(f"{provider.key} 未接受当前回调地址，换下一个候选重试")
                        for stale in ("provider_error", "provider_error_hint", "cloudflare", "landed_back"):
                            result.pop(stale, None)
                        attempt.chain_started = False
                        oauth_state, _state_diag = await fetch_oauth_state(
                            page, base_url, log, deadline=deadline,
                        )
                        if not oauth_state:
                            break
                    return outcome
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
