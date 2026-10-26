#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三方 OAuth 提供商适配器（linux.do / github）。

每个 provider 定义 relogin 签到所需的一切「站点无关」知识：
- 授权端点与授权 URL 构造；
- 站点 /api/status 里 client_id / oauth 开关的字段名；
- 授权页的「同意授权」按钮选择器；
- 第三方登录页特征（用于判定登录态是否失效）。

站点侧固定约定（New API 系）：
- GET {origin}/api/status      → {linuxdo_client_id, github_client_id, linuxdo_oauth, github_oauth, ...}
- GET {origin}/api/oauth/state → {"data": "<state>"}（一次性，每次重新获取）
- 回调 {origin}/api/oauth/{provider}?code=..&state=.. → 站点发额度
- 授权后跳回 {origin}/console/token 或 URL 含 code=
"""

from __future__ import annotations

import asyncio
import re
import time
from abc import ABC
from copy import deepcopy
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit


def normalize_hostname(value: str | None) -> str:
    """规范化 URL/cookie hostname，移除 cookie 域名前导点。"""
    return str(value or "").strip().lstrip(".").rstrip(".").lower()


def hostname_matches_domain(hostname: str | None, domain: str | None) -> bool:
    """判断 hostname 是否等于 domain，或位于 domain 的真实子域边界下。"""
    host = normalize_hostname(hostname)
    base = normalize_hostname(domain)
    return bool(host and base and (host == base or host.endswith("." + base)))


def url_matches_domains(url: str, domains: tuple[str, ...], *, require_https: bool = True) -> bool:
    """按 URL hostname 边界匹配允许域名；OAuth 页面默认只接受 HTTPS。"""
    try:
        parsed = urlsplit(str(url or ""))
        hostname = parsed.hostname
    except ValueError:
        return False
    if require_https and parsed.scheme.lower() != "https":
        return False
    return any(hostname_matches_domain(hostname, domain) for domain in domains)


class OAuthProvider(ABC):
    key: str = ""
    authorize_endpoint: str = ""
    # 授权页「同意授权」按钮候选选择器（按顺序尝试）
    approve_selectors: list[str] = []
    # 第三方登录页特征选择器（出现即说明未登录/登录态失效）
    login_markers: list[str] = []
    # 人工捕获共享登录态时打开的入口页
    capture_url: str = ""
    # 用于判断 storage_state 是否包含该 provider 登录态的域名特征
    state_domain_hints: tuple[str, ...] = ()
    # 只有这些认证 Cookie 才代表真正登录；普通匿名/CSRF Cookie 不能判成功。
    authenticated_cookie_names: tuple[str, ...] = ()
    # 授权 URL 附加 scope（github 需要）
    scope: str = ""

    def redirect_uri(self, base_url: str) -> str:
        """站点 OAuth 回调地址；提供商按它做精确校验，必须与授权请求一致。"""
        return f"{str(base_url or '').rstrip('/')}{self.callback_path()}"

    def build_authorize_url(self, client_id: str, state: str, *, base_url: str = "") -> str:
        """拼授权 URL。

        ``redirect_uri`` 是必须项：linux.do 这类提供商会按注册值精确比对，
        缺失时直接回 ``unauthorized_client``，看起来像「应用被吊销」，
        实际只是请求没带回调地址。
        """
        params = {"response_type": "code", "client_id": client_id, "state": state}
        if base_url:
            params["redirect_uri"] = self.redirect_uri(base_url)
        if self.scope:
            params["scope"] = self.scope
        return f"{self.authorize_endpoint}?{urlencode(params)}"

    def status_client_id_field(self) -> str:
        return f"{self.key}_client_id"

    def status_oauth_field(self) -> str:
        return f"{self.key}_oauth"

    def callback_path(self) -> str:
        return f"/api/oauth/{self.key}"

    def matches_url(self, url: str) -> bool:
        """当前 HTTPS URL 是否处于该 provider 的授权域名边界下。"""
        return url_matches_domains(url, self.state_domain_hints)

    def has_authenticated_state(self, cookies: list[dict[str, object]]) -> bool:
        """storage/context cookies 是否包含当前 provider 的真实认证会话。"""
        for cookie in cookies:
            name = str(cookie.get("name") or "")
            domain = str(cookie.get("domain") or "")
            value = str(cookie.get("value") or "")
            if name not in self.authenticated_cookie_names or not value:
                continue
            if any(hostname_matches_domain(domain, hint) for hint in self.state_domain_hints):
                return True
        return False


class LinuxDoProvider(OAuthProvider):
    key = "linuxdo"
    authorize_endpoint = "https://connect.linux.do/oauth2/authorize"
    capture_url = "https://linux.do"
    state_domain_hints = ("linux.do", "connect.linux.do")
    authenticated_cookie_names = ("_t",)
    approve_selectors = ['a[href^="/oauth2/approve"]', 'button:has-text("允许")', 'button:has-text("Authorize")']
    login_markers = ["#login-account-name", "#login-account-password", "#login-button"]


_GITHUB_HUMAN_PATHS = (
    "/sessions/two-factor", "/sessions/verified-device", "/sessions/sudo", "/sudo",
    "/login/device", "/login/passkey", "/account_verifications", "/captcha", "/challenge",
)


def _github_human_path(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in _GITHUB_HUMAN_PATHS)


class _GitHubSessionDocument(HTMLParser):
    """只解析本次 HTTPS 响应正文的布尔证据，不读取页面脚本/localStorage 或暴露身份。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.user_marker = False
        self.logged_in = False
        self.logout = False
        self.challenge = False
        self.password = False
        self.login_user = False
        self.login_password = False
        self._login_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        name = str(values.get("name") or "").lower()
        element_id = str(values.get("id") or "").lower()
        if any(marker in element_id for marker in ("captcha", "cf-chl", "challenge-running")):
            self.challenge = True
        if tag == "meta" and name == "user-login":
            self.user_marker = bool(re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?", str(values.get("content") or ""), re.I,
            ))
        if tag == "body":
            self.logged_in = "logged-in" in str(values.get("class") or "").split()
        if tag == "form":
            try:
                action = urlsplit(urljoin("https://github.com", str(values.get("action") or "")))
                trusted = (action.scheme == "https" and action.hostname == "github.com"
                           and action.port in (None, 443) and not action.username and not action.password)
            except ValueError:
                trusted = False
            post = str(values.get("method") or "").lower() == "post"
            self._login_form = trusted and post and action.path == "/session"
            self.logout = self.logout or (trusted and post and action.path == "/logout")
            self.challenge = self.challenge or (trusted and _github_human_path(action.path))
        if tag == "input":
            password = str(values.get("type") or "").lower() == "password"
            self.password = self.password or password
            self.login_user = self.login_user or (self._login_form and name in {"login", "user_login"})
            self.login_password = self.login_password or (self._login_form and password)
            if (str(values.get("autocomplete") or "").lower() == "one-time-code"
                    or name in {"otp", "app_otp", "otp_code", "recovery_code"}
                    or element_id in {"otp", "app_totp"}):
                self.challenge = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._login_form = False


class GitHubProvider(OAuthProvider):
    key = "github"
    authorize_endpoint = "https://github.com/login/oauth/authorize"
    capture_url = "https://github.com/login"
    state_domain_hints = ("github.com",)
    authenticated_cookie_names = ("user_session", "__Host-user_session_same_site")
    scope = "user:email"
    # 普通 submit 可能只是账号确认，绝不能当作正式 OAuth 批准。
    # GitHub 页面会把 action 写成相对/绝对 URL，也可能附带 query；同时
    # 「允许」控件在不同页面版本中是 button 或 input。
    approve_selectors = [
        'form[action^="/login/oauth/authorize"] button[type="submit"][name="authorize"][value="1"]',
        'form[action^="/login/oauth/authorize"] input[type="submit"][name="authorize"][value="1"]',
        'form[action^="https://github.com/login/oauth/authorize"] button[type="submit"][name="authorize"][value="1"]',
        'form[action^="https://github.com/login/oauth/authorize"] input[type="submit"][name="authorize"][value="1"]',
    ]
    # 新版登录页常见的字段名优先于通用 password/OTP 标记，归类为 provider_login。
    login_markers = [
        "#login_field", "#password", "input[name='login']", "input[name='password']",
        "input[autocomplete='username']", "input[autocomplete='current-password']",
        "#user_login", "#user_password",
    ]
    human_markers = [
        'input[type="password"]', 'input[autocomplete="one-time-code"]',
        '#otp', '#app_totp', 'input[name="otp"]', 'input[name="app_otp"]',
        'input[name="recovery_code"]',
    ]

    def matches_url(self, url: str) -> bool:
        """GitHub 授权仅位于主站，不接受用户内容子域作为提供商授权证据。"""
        try:
            parsed = urlsplit(url)
            return (parsed.scheme.lower() == "https" and parsed.hostname == "github.com"
                    and parsed.port in (None, 443) and not parsed.username and not parsed.password)
        except ValueError:
            return False

    keepalive_url = "https://github.com/settings/profile"

    def keepalive_storage_state(self, storage_state: dict[str, Any]) -> dict[str, Any]:
        """隔离主站 Cookie，保留原始 expiry；本地过期仅由恢复器临时按会话交给服务端。"""
        fields = {"name", "value", "domain", "path", "expires", "httpOnly", "secure", "sameSite"}
        cookies = [
            {key: deepcopy(cookie[key]) for key in fields if key in cookie}
            for cookie in storage_state.get("cookies", [])
            if isinstance(cookie, dict) and normalize_hostname(cookie.get("domain")) == "github.com"
            and cookie.get("name") and cookie.get("value")
            and not str(cookie.get("name") or "").lower().startswith(("cf_", "__cf", "_cf"))
        ]
        return {"cookies": cookies, "origins": []}

    def keepalive_verdict(
        self, *, url: str, response_url: str, status: int, content_type: str, html: str,
    ) -> str:
        """固定认证页的服务端响应判定；cookie/DOM 头像不是认证证据。"""
        if not self.matches_url(url) or not self.matches_url(response_url):
            return "undetermined"
        path = urlsplit(url).path
        if path != urlsplit(response_url).path:
            return "undetermined"
        if type(status) is not int or status == 429 or status >= 500:
            return "undetermined"
        if _github_human_path(path):
            return "challenge"
        if (not any(kind in content_type.lower() for kind in ("text/html", "application/xhtml+xml"))
                or not isinstance(html, str) or len(html) > 2_000_000):
            return "undetermined"
        document = _GitHubSessionDocument()
        document.feed(html)
        document.close()
        if document.challenge or (path == "/settings/profile" and document.password):
            return "challenge"
        if not 200 <= status < 300:
            return "undetermined"
        authenticated = document.user_marker and (document.logged_in or document.logout)
        if path == "/settings/profile" and authenticated:
            return "authenticated"
        if (path in {"/login", "/session"} and document.login_user and document.login_password
                and not document.user_marker and not document.logged_in and not document.logout):
            return "anonymous"
        return "undetermined"

    async def keepalive_session(
        self, lease: Any, *, log: Any, deadline: float,
    ) -> tuple[str, dict[str, Any] | None]:
        """只 GET 正常认证页；绝不点击授权、提交密码/OTP 或发起身份切换。"""
        try:
            async with asyncio.timeout_at(deadline):
                page = await lease.new_page()
                response = await page.goto(
                    self.keepalive_url, wait_until="domcontentloaded",
                    timeout=max(1, min(60000, int((deadline - time.monotonic()) * 1000))),
                )
                if response is None:
                    return "undetermined", None
                verdict = self.keepalive_verdict(
                    url=str(page.url), response_url=str(response.url), status=response.status,
                    content_type=str(response.headers.get("content-type") or ""), html=await response.text(),
                )
                if verdict != "authenticated":
                    return verdict, None
                snapshot = await lease.context.storage_state()
                lease.mark_authenticated()
                return "authenticated", snapshot
        except Exception:  # 导航/限流/正文或快照导出异常都不能证明旧会话失效。
            return "undetermined", None

    async def intermediate_action(self, page: Any) -> tuple[str, Any | None, bool]:
        """仅推进身份唯一/明确为当前身份的确认；不猜账号，不提交密码或二次验证。

        身份只在本函数内比较，不进入结果、日志或诊断。按钮即使暂时 disabled 也计入
        身份候选，不能把「只有一个可点击」误当成「只有一个账号」。
        """
        query = getattr(page, "query_selector_all", None)
        if not callable(query):
            return "provider", None, False
        candidates = []
        for button in await query('form button[type="submit"], form input[type="submit"]'):
            if not await button.is_visible():
                continue
            info = await button.evaluate(r"""el => {
                const form = el.form;
                if (!form || el.name === 'authorize') return null;
                const action = new URL(form.getAttribute('action') || '', location.href);
                if (location.origin !== 'https://github.com' || action.origin !== location.origin
                    || action.username || action.password) return null;
                const kind = action.pathname === '/login/oauth/authorize' ? 'continue'
                    : ['/session', '/sessions/switch'].includes(action.pathname) ? 'account_selection' : '';
                if (!kind) return null;
                const text = (el.textContent || el.value || '').trim();
                const named = /^(?:login|user_login)$/.test(el.name || '');
                const as = text.match(/^(?:Continue|Sign in) as\s+([a-z0-9-]+)$/i);
                if (!as && !/^Continue$/i.test(text) && !(named && kind === 'account_selection')) return null;
                const current = (document.querySelector('meta[name="user-login"]')?.content || '').trim();
                const hidden = form.querySelector('input[type="hidden"][name="login"], input[type="hidden"][name="user_login"]');
                const identities = [el.getAttribute('data-login'), named ? el.value : '', hidden?.value, as?.[1]]
                    .map(value => (value || '').trim().toLowerCase()).filter(Boolean);
                if (new Set(identities).size > 1) return {kind, identity: '', current: ''};
                const identity = identities[0] || (kind === 'continue' ? current.toLowerCase() : '');
                if (identity && !/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/i.test(identity))
                    return {kind, identity: '', current: ''};
                return {kind, identity, current: current.toLowerCase()};
            }""")
            if isinstance(info, dict):
                candidates.append((button, info))
        if not candidates:
            return "unknown", None, False
        current = [(button, info) for button, info in candidates
                   if info.get("identity") and info.get("identity") == info.get("current")]
        identities = {info.get("identity") for _, info in candidates}
        unique_identity = len(identities) == 1 and all(isinstance(value, str) and value for value in identities)
        safe = current if len(current) == 1 else candidates if unique_identity else []
        if len(safe) != 1:
            return "account_selection", None, True
        button, info = safe[0]
        return info["kind"], button if await button.is_enabled() else None, False


_PROVIDERS: dict[str, OAuthProvider] = {
    "linuxdo": LinuxDoProvider(),
    "github": GitHubProvider(),
}

KNOWN_OAUTH_PROVIDERS = tuple(_PROVIDERS)
DEFAULT_OAUTH_PROVIDER = "linuxdo"


def normalize_oauth_provider(value: str | None) -> str:
    key = (value or "").strip().lower()
    return key if key in _PROVIDERS else DEFAULT_OAUTH_PROVIDER


def get_oauth_provider(value: str | None) -> OAuthProvider:
    return _PROVIDERS[normalize_oauth_provider(value)]


__all__ = [
    "normalize_hostname",
    "hostname_matches_domain",
    "url_matches_domains",
    "OAuthProvider",
    "LinuxDoProvider",
    "GitHubProvider",
    "KNOWN_OAUTH_PROVIDERS",
    "DEFAULT_OAUTH_PROVIDER",
    "normalize_oauth_provider",
    "get_oauth_provider",
]
