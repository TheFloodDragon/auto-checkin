"""登录方式：使用配置/覆盖层里现成的 access_token。"""

from __future__ import annotations

from typing import Any

from ..net.http import describe_token_defect, normalize_access_token
from ._common import auth_headers
from .base import Availability, LoginContext, LoginState, READY, unavailable

__all__ = ["TokenLogin"]


class TokenLogin:
    id = "access_token"
    requires: frozenset[str] = frozenset()

    def available(self, ctx: LoginContext, option: Any = None) -> Availability:
        raw = ctx.credentials.access_token
        if normalize_access_token(raw):
            return READY
        # 区分「没填」和「填了但不可用」：非 ASCII（从截断显示里复制的残缺值）会被
        # normalize 静默判空，只说「未配置」会让用户明明填了却查不出问题在哪。
        return unavailable(describe_token_defect(raw))

    def authenticate(self, ctx: LoginContext, option: Any = None) -> LoginState:
        token = normalize_access_token(ctx.credentials.access_token)
        return LoginState(
            method=self.id,
            headers=auth_headers(ctx, token),
            origin="config",
            note=f"使用已保存的 access_token（{len(token)} 字符）",
        )
