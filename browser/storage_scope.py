#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""storage_state 的来源判定与取值（纯函数，不碰浏览器）。

从 ``session.py`` 摘出来的原因：这里的每个判断都是**安全边界**——
``storage_state`` 是整个浏览器上下文的快照，可能同时含共享 OAuth 站点、上一个
站点的残留 origin 和第三方 iframe，而 ``auth_token`` / ``refresh_token`` 这类键名
在各站点高度重复。跨源取值会把 A 站的凭据当成 B 站的存入缓存、甚至发给 B 站
（已实测）。这类逻辑应当能脱离浏览器直接断言，而不是埋在 2500 行会话流程里。

``session.py`` 会 re-export 这里的名字（含 ``_same_origin`` 等下划线别名），
既有调用与测试中的 ``session.storage_*`` 保持有效。
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any
from urllib.parse import urlparse, urlsplit

from . import oauth_providers

# scheme 的默认端口：判定同源时 https://a 与 https://a:443 必须视为同一来源。
DEFAULT_PORTS = {"http": 80, "https": 443}

# Sub2API 系前端把 access_token 存作 auth_token；两个键名都要认。
ACCESS_TOKEN_KEYS = ("auth_token", "access_token")
REFRESH_TOKEN_KEY = "refresh_token"


def origin_of(url: str) -> str:
    """取 URL 的 scheme://host[:port]；解析不出来时原样去掉尾部斜杠返回。"""
    parsed = urlparse(str(url or ""))
    if not parsed.scheme or not parsed.netloc:
        return str(url or "").rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}"


def same_origin(left: str, right: str) -> bool:
    """按 scheme + hostname + 生效端口比较来源，不做字符串包含判断。

    字符串包含会把 ``https://evil-site.invalid`` 判成 ``https://site.invalid``
    的同源，因此这里逐字段比较，并把默认端口归一化。
    """
    try:
        a, b = urlsplit(str(left or "")), urlsplit(str(right or ""))
    except ValueError:
        return False
    scheme_a, scheme_b = a.scheme.lower(), b.scheme.lower()
    host_a = oauth_providers.normalize_hostname(a.hostname)
    host_b = oauth_providers.normalize_hostname(b.hostname)
    if not scheme_a or not host_a or scheme_a != scheme_b or host_a != host_b:
        return False
    try:
        port_a = a.port or DEFAULT_PORTS.get(scheme_a)
        port_b = b.port or DEFAULT_PORTS.get(scheme_b)
    except ValueError:
        return False
    return port_a == port_b


def storage_item(storage_state: dict[str, Any] | None, name: str, *, base_url: str = "") -> str:
    """从 storage_state 的 localStorage 里取某个键的值；找不到返回空串。

    传入 base_url 时只读同源条目：找不到同源条目就返回空串，绝不跨源兜底——
    宁可退化成重新登录，也不能拿错身份。base_url 为空表示调用方明确不关心来源
    （如仅做存在性诊断），保持旧行为。
    """
    if not isinstance(storage_state, dict):
        return ""
    want_origin = str(base_url or "").strip()
    for origin_entry in storage_state.get("origins") or []:
        if not isinstance(origin_entry, dict):
            continue
        if want_origin and not same_origin(origin_entry.get("origin") or "", want_origin):
            continue
        for item in origin_entry.get("localStorage") or []:
            if not isinstance(item, dict):
                continue
            if str(item.get("name") or "").strip() == name:
                value = str(item.get("value") or "").strip()
                if value:
                    return value
    return ""


def storage_refresh_token(storage_state: dict[str, Any] | None, *, base_url: str = "") -> str:
    """取出 refresh_token。

    Sub2API 系站点把 access_token（短期 JWT）与 refresh_token（长期）都放在
    localStorage。把 refresh_token 提出来，纯 HTTP 路径就能自行调
    /api/v1/auth/refresh 续期，不必为「JWT 过期」这种常见情况开浏览器。
    """
    return storage_item(storage_state, REFRESH_TOKEN_KEY, base_url=base_url)


def storage_access_token(storage_state: dict[str, Any] | None, *, base_url: str = "") -> str:
    """取出 access_token（Sub2API 系前端存作 auth_token）。"""
    for key in ACCESS_TOKEN_KEYS:
        value = storage_item(storage_state, key, base_url=base_url)
        if value:
            return value
    return ""


def provider_storage_state(
    storage_state: dict[str, Any], provider_key: str, *, base_url: str = ""
) -> dict[str, Any]:
    """重登只导入所选提供商的共享认证，不把快照内混杂的本站会话带进浏览器。"""
    key = str(provider_key or "").strip().lower()
    if key not in oauth_providers.KNOWN_OAUTH_PROVIDERS:
        raise ValueError("未知 OAuth 提供商")
    provider = oauth_providers.get_oauth_provider(key)
    target_host = urlsplit(base_url).hostname if base_url else ""

    def allowed_host(host: str) -> bool:
        return any(
            oauth_providers.hostname_matches_domain(host, domain)
            for domain in provider.state_domain_hints
        )

    cookies = []
    for cookie in storage_state.get("cookies") or []:
        if not isinstance(cookie, dict):
            continue
        domain = str(cookie.get("domain") or "")
        if not allowed_host(domain):
            continue
        # 如果目标恰好位于提供商的域树中，也不能导入会发送给目标站点的 Cookie。
        if target_host and oauth_providers.hostname_matches_domain(target_host, domain):
            continue
        cookies.append(deepcopy(cookie))

    origins = []
    for entry in storage_state.get("origins") or []:
        if not isinstance(entry, dict):
            continue
        origin = str(entry.get("origin") or "")
        try:
            parsed = urlsplit(origin)
            trusted = (
                parsed.scheme == "https" and allowed_host(parsed.hostname or "")
                and parsed.port in (None, 443) and not parsed.username and not parsed.password
                and parsed.path in ("", "/") and not parsed.query and not parsed.fragment
            )
        except ValueError:
            trusted = False
        if not trusted or (base_url and same_origin(origin, base_url)):
            continue
        # 不继承快照里的额外存储类型或未知字段。
        origins.append({"origin": origin, "localStorage": deepcopy(entry.get("localStorage") or [])})
    return {"cookies": cookies, "origins": origins}


def site_cookie_string(cookies: list[dict[str, Any]], base_url: str) -> str:
    """从 context.cookies() 里挑出会发给站点的 cookie，拼成 "k=v; k2=v2"。

    把浏览器过 WAF 后拿到的 acw_tc 等 WAF cookie 与站点 session cookie 一起导出，
    交给 HTTP 层复用。只保留作用域真正覆盖站点 host 的条目（cookie 域等于 host
    或为其父域），避免把第三方 OAuth（linux.do/github）或兄弟子域的 cookie 混入
    站点请求。域边界判定复用 oauth_providers 的唯一实现。
    """
    host = urlparse(origin_of(base_url)).hostname or ""
    if not host:
        return ""
    pairs: dict[str, str] = {}
    for cookie in cookies or []:
        name = str(cookie.get("name") or "")
        if not name:
            continue
        domain = str(cookie.get("domain") or "")
        if not domain:
            continue
        # host 位于 cookie 域边界内即代表该 cookie 会被发送给站点。
        if oauth_providers.hostname_matches_domain(host, domain):
            pairs[name] = str(cookie.get("value") or "")
    return "; ".join(f"{k}={v}" for k, v in pairs.items())


__all__ = [
    "ACCESS_TOKEN_KEYS",
    "DEFAULT_PORTS",
    "REFRESH_TOKEN_KEY",
    "origin_of",
    "provider_storage_state",
    "same_origin",
    "site_cookie_string",
    "storage_access_token",
    "storage_item",
    "storage_refresh_token",
]
