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

from abc import ABC
from typing import Any
from urllib.parse import urlencode, urlsplit


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

    def build_authorize_url(self, client_id: str, state: str) -> str:
        params = {"response_type": "code", "client_id": client_id, "state": state}
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
            return "provider", None, False
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
