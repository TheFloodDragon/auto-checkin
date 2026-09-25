"""登录方式：用 refresh_token 纯 HTTP 续期，不启动浏览器。

这是 Sub2API 系站点最重要的一条路径：access_token 是数小时过期的 JWT，而
refresh_token 通常 30 天有效。没有它，每次过期都要拉起一次 Camoufox（实测每站
数十秒），CI 里还常因此触发风控。
"""

from __future__ import annotations

from typing import Any

from core.errors import LoginRequired, TaskError
from ._common import auth_headers, token_pair
from .base import Availability, LoginContext, LoginState, READY, unavailable

__all__ = ["RefreshLogin"]

DEFAULT_REFRESH_PATH = "/api/v1/auth/refresh"


class RefreshLogin:
    id = "refresh"
    requires: frozenset[str] = frozenset()

    def available(self, ctx: LoginContext, option: Any = None) -> Availability:
        if not str(ctx.credentials.refresh_token or "").strip():
            return unavailable("未配置 refresh_token（可在管理界面「浏览器登录捕获」或手工填写）")
        if not ctx.endpoint("refresh", DEFAULT_REFRESH_PATH):
            return unavailable("模板未声明 refresh 端点")
        return READY

    def authenticate(self, ctx: LoginContext, option: Any = None) -> LoginState:
        path = ctx.endpoint("refresh", DEFAULT_REFRESH_PATH)
        token = str(ctx.credentials.refresh_token).strip()
        ctx.log(f"用 refresh_token 续期（{path}，rt {len(token)} 字符）")
        client = ctx.http.with_auth(extra=ctx.base_headers())
        # 续期请求自身失败（401/403/429）绝不能再触发 auth_refresher，否则续期钩子会
        # 递归调用自己：实测 refresh_token 失效时会反复打 /api/v1/auth/refresh 直到撞满
        # 429（vcnovb / 极速蹬 日志里数百次 invalid refresh token 即由此产生）。
        client.auth_refresher = None
        try:
            payload = client.request("POST", path, json_body={"refresh_token": token})
        except TaskError as exc:
            # 续期端点回 401/403 就是「这张 refresh_token 也失效了」，必须让候选链
            # 继续降级；报成普通错误会让整条链在这里停住。
            raise LoginRequired(
                f"refresh_token 续期未成功：{exc.message}",
                status=exc.status,
                payload=exc.payload,
            ) from exc
        access, rotated = token_pair(payload)
        if not access:
            raise LoginRequired("refresh_token 续期响应里没有可用的 access_token")
        credentials = {"access_token": access}
        if rotated and rotated != token:
            credentials["refresh_token"] = rotated
        return LoginState(
            method=self.id,
            headers=auth_headers(ctx, access),
            credentials=credentials,
            verified=True,
            origin="refresh",
            note="refresh_token 续期成功",
        )
