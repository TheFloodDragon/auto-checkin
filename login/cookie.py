"""登录方式：使用配置/覆盖层里现成的 Cookie。"""

from __future__ import annotations

from typing import Any

from net.http import normalize_cookie
from ._common import cookie_headers
from .base import Availability, LoginContext, LoginState, READY, unavailable

__all__ = ["CookieLogin"]


class CookieLogin:
    id = "cookie"
    requires: frozenset[str] = frozenset()

    def _cookie(self, ctx: LoginContext) -> str:
        # session_cookie 是浏览器流程续存的站点会话，与用户手工粘贴的 cookie 同源同用；
        # 手工值优先（用户刚贴上的意图更明确）。
        return normalize_cookie(ctx.credentials.cookie or ctx.credentials.session_cookie)

    def available(self, ctx: LoginContext, option: Any = None) -> Availability:
        if self._cookie(ctx):
            return READY
        return unavailable("配置里 cookie 为空")

    def authenticate(self, ctx: LoginContext, option: Any = None) -> LoginState:
        cookie = self._cookie(ctx)
        return LoginState(
            method=self.id,
            headers=cookie_headers(ctx, cookie),
            origin="config",
            note=f"使用已保存的 Cookie（{len(cookie)} 字符）",
        )
