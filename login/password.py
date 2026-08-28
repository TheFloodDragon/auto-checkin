"""登录方式：纯 HTTP 账密登录换新 token（站点未启 Turnstile 时可行）。

凭据来源由 ``LoginOption.args`` 的 ``ArgSchema`` 决定，支持环境变量回退与 ``secret``
标记。旧实现让每个脚本自己实现 ``email_env``/``password_env`` 的二段查找
（``providers/actions/browser_script.py:_script_credentials``），写错键名要到运行期
才发现，而且账密会随 ``script_args`` 进配置文件。
"""

from __future__ import annotations

from typing import Any

from ..core.errors import LoginRequired, TaskError
from ._common import auth_headers, token_pair
from .base import Availability, LoginContext, LoginState, READY, unavailable

__all__ = ["PasswordLogin"]

DEFAULT_LOGIN_PATH = "/api/v1/auth/login"


class PasswordLogin:
    id = "password"
    requires: frozenset[str] = frozenset()

    def _credentials(self, ctx: LoginContext) -> tuple[str, str]:
        return (
            str(ctx.args.get("email") or ctx.args.get("username") or "").strip(),
            str(ctx.args.get("password") or ""),
        )

    def available(self, ctx: LoginContext, option: Any = None) -> Availability:
        email, password = self._credentials(ctx)
        if not email or not password:
            return unavailable("未提供账密（login.args.email/password，或对应环境变量）")
        if not ctx.endpoint("login", DEFAULT_LOGIN_PATH):
            return unavailable("模板未声明 login 端点")
        return READY

    def authenticate(self, ctx: LoginContext, option: Any = None) -> LoginState:
        email, password = self._credentials(ctx)
        path = ctx.endpoint("login", DEFAULT_LOGIN_PATH)
        ctx.log(f"纯 HTTP 账密登录（{path}）")
        # 必须带 cookie jar：部分站点把会话绑定到客户端指纹，登录时下发的 cookie
        # 不带回后续请求即被拒（实测：Session network fingerprint changed）。
        client = ctx.http.with_session().with_auth(extra=ctx.base_headers())
        try:
            payload = client.request("POST", path, json_body={"email": email, "password": password})
        except TaskError as exc:
            raise LoginRequired(
                f"账密登录未成功：{exc.message}", status=exc.status, payload=exc.payload
            ) from exc
        access, refresh = token_pair(payload)
        if not access:
            raise LoginRequired("账密登录响应里没有可用的 access_token")
        credentials = {"access_token": access}
        if refresh:
            credentials["refresh_token"] = refresh
        return LoginState(
            method=self.id,
            headers=auth_headers(ctx, access),
            credentials=credentials,
            verified=True,
            cookie_jar=client.cookie_jar,
            origin="password",
            note=f"账密登录成功（{email}）",
        )
