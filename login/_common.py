"""登录插件的共享小工具。"""

from __future__ import annotations

from typing import Any, Mapping

from core.manifest import pick_path
from net.http import normalize_access_token, normalize_cookie

__all__ = ["auth_headers", "cookie_headers", "token_pair"]

#: 各站点/各 fork 返回 token 的字段名不统一，按候选顺序取第一个非空。
#: 不含 ``.`` 的候选会在整个响应里按键名 BFS —— 有的站点包在 ``data`` 里，
#: 有的直接放顶层，写死层级会让一次改版就失效。
ACCESS_TOKEN_KEYS = (
    "access_token",
    "accessToken",
    "auth_token",
    "authToken",
    "token",
    "jwt",
)
REFRESH_TOKEN_KEYS = ("refresh_token", "refreshToken")


def token_pair(payload: Any) -> tuple[str, str]:
    """从登录/续期响应里取出 (access_token, refresh_token)。"""
    access = normalize_access_token(pick_path(payload, ACCESS_TOKEN_KEYS))
    refresh = str(pick_path(payload, REFRESH_TOKEN_KEYS) or "").strip()
    return access, refresh


def auth_headers(ctx: Any, token: str, *, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Bearer 认证头 + 模板声明的站点族固定头。"""
    headers = ctx.base_headers()
    headers["Authorization"] = f"Bearer {normalize_access_token(token)}"
    headers.update(dict(extra or {}))
    return headers


def cookie_headers(ctx: Any, cookie: str, *, extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Cookie 认证头 + 模板声明的站点族固定头。

    刻意不同时带 Authorization：用户选了 Cookie 登录就该走 Cookie。旧实现里
    ``load_auth()`` 同时返回两者，客户端只要看见 token 就发 Bearer 并剥掉 session
    cookie，于是「选了 Cookie 实际走 Token」——可能是另一个账号的身份，且极难定位。
    """
    headers = ctx.base_headers()
    headers["Cookie"] = normalize_cookie(cookie)
    headers.update(dict(extra or {}))
    return headers
