"""登录方式插件（原 auth_method）。

内置六种：``access_token`` / ``cookie`` / ``refresh`` / ``password`` /
``browser_state`` / ``oauth``。模板通过 ``LoginOption`` 声明自己支持哪些、优先序如何、
各需要什么参数；用户可以在 ``flow.login`` 里固定其中一种或给一个优先序。
"""

from __future__ import annotations

from .base import Availability, LoginContext, LoginMethod, LoginState, render_headers
from .broker import LOGINS, LoginAttempt, LoginBroker, LoginResult

__all__ = [
    "LOGINS",
    "Availability",
    "LoginAttempt",
    "LoginBroker",
    "LoginContext",
    "LoginMethod",
    "LoginResult",
    "LoginState",
    "render_headers",
]


def _bootstrap() -> None:
    from .browser_state import BrowserStateLogin
    from .cookie import CookieLogin
    from .oauth import OAuthLogin
    from .password import PasswordLogin
    from .refresh import RefreshLogin
    from .token import TokenLogin

    for method in (
        TokenLogin(),
        CookieLogin(),
        RefreshLogin(),
        PasswordLogin(),
        BrowserStateLogin(),
        OAuthLogin(),
    ):
        LOGINS.register(method, replace_existing=True)


_bootstrap()
