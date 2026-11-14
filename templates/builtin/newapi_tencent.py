"""New API 腾讯验证：官方 SDK 票据 -> 站内 token -> 单次签到。

票据只在本次调用内传递，不跨账号缓存，不用一次性票据自动重放请求。
"""
from __future__ import annotations

import math
import re
import time
import uuid
from dataclasses import replace
from typing import Any
from urllib.parse import quote

from core.errors import ConfigError, TaskError, TransientError, VerificationRequired
from core.masking import mask_secrets, sanitize_data
from net.http import HttpClient

EXCHANGE_PATH = "/api/go-captcha-check-data/tencent"
CHECKIN_PATH = "/api/user/checkin"
TOTAL_BUDGET = 120.0
SDK_BUDGET = 90.0
REQUEST_TIMEOUT = 15.0


def _field(value: Any, limit: int) -> str:
    """不接受类型强转、空值、控制字符或可注入 multipart 的换行。"""
    if not isinstance(value, str) or not 0 < len(value) <= limit:
        return ""
    if not all("!" <= char <= "~" for char in value):
        return ""
    return value


def _safe(value: Any, sensitive: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        for secret in sensitive:
            if secret:
                value = value.replace(secret, "<redacted>")
        return mask_secrets(value)
    if isinstance(value, dict):
        return sanitize_data({_safe(str(key), sensitive): _safe(item, sensitive) for key, item in value.items()})
    if isinstance(value, (tuple, list)):
        return [_safe(item, sensitive) for item in value]
    return value


def _timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise VerificationRequired("腾讯验证码处理预算已耗尽；未追加提交。", data={"verification_mode": "tencent"})
    return min(REQUEST_TIMEOUT, remaining)


def _multipart(ticket: str, randstr: str) -> tuple[bytes, str]:
    boundary = "----checkin-tencent-" + uuid.uuid4().hex
    body = b"".join(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode("ascii")
        for key, value in (("ticket", ticket), ("randstr", randstr))
    )
    return body + f"--{boundary}--\r\n".encode("ascii"), f"multipart/form-data; boundary={boundary}"


def _single_use_client(http: Any) -> Any:
    if not isinstance(http, HttpClient):
        # 测试/脚本的客户端须遵守 request(retry_non_idempotent=False) 契约。
        return http
    # 保持同一认证、代理、Cookie jar；票据响应及带 token 的 URL 不进入 HTTP 日志。
    # 401 也不能让 auth_refresher 把已经提交的一次性票据自动重放。
    return replace(http, config=replace(http.config, max_attempts=1, log_body=False), log=None,
                   auth_refresher=None, renew_ahead=False)


def _request(http: Any, path: str, deadline: float, sensitive: tuple[str, ...], **kwargs: Any) -> Any:
    try:
        return http.request("POST", path, timeout=_timeout(deadline), retry_non_idempotent=False, **kwargs)
    except TaskError as exc:
        # 服务端有时将输入票据写进错误 message；不带原始 payload/异常链跨出本模块。
        raise TaskError(
            _safe(exc.message, sensitive), reason=exc.reason or "need_verification", status=exc.status,
            data={"verification_mode": "tencent", "stage": "exchange" if path == EXCHANGE_PATH else "submit"},
        ) from None
    except Exception as exc:
        raise TransientError(
            f"腾讯验证码请求未完成（{type(exc).__name__}）；不重放一次性票据。",
            data={"verification_mode": "tencent"},
        ) from None


async def checkin(ctx: Any, options: dict[str, Any]) -> dict[str, Any]:
    from .newapi_verify import checkin_data

    app_id = options.get("tencent_captcha_app_id")
    app_id = str(app_id) if type(app_id) is int else app_id
    if not isinstance(app_id, str) or not re.fullmatch(r"[0-9]{1,32}", app_id):
        raise ConfigError("站点启用了腾讯验证码，但未提供有效的 tencent_captcha_app_id。",
                          data={"verification_mode": "tencent"})
    remaining = getattr(ctx, "remaining_seconds", lambda: None)()
    budget = TOTAL_BUDGET if remaining is None else min(TOTAL_BUDGET, float(remaining))
    if not math.isfinite(budget) or budget <= 0:
        raise VerificationRequired("腾讯验证码没有可用的时间预算。", data={"verification_mode": "tencent"})
    deadline = time.monotonic() + budget
    ctx.log("站点要求腾讯验证码，等待官方 SDK 成功回调；未通过时不会提交签到")
    origin = str(getattr(getattr(ctx, "account", None), "base_url", "") or getattr(ctx.http, "base_url", ""))
    result = await ctx.solve("tencent", app_id=app_id, origin=origin,
                             budget=min(SDK_BUDGET, max(0.0, budget - 2 * REQUEST_TIMEOUT)))
    if not result.ok:
        # 不传播解算器 data，其中可能有不完整的瞬时票据。
        network = result.reason in {"network_error", "transport_error"}
        message = "腾讯验证码网络请求未完成。" if network else "腾讯验证码未完成，请在浏览器完成验证后重试。"
        error = TransientError if network else VerificationRequired
        raise error(message, data={"verification_mode": "tencent", "stage": "sdk"}, evidence=result.evidence)
    ticket = _field(result.data.get("ticket"), 8192)
    randstr = _field(result.data.get("randstr"), 1024)
    if not ticket or not randstr or ticket.lower().startswith("trerror_"):
        raise VerificationRequired("腾讯验证码未返回有效票据；未提交签到。",
                                   data={"verification_mode": "tencent", "stage": "sdk"})
    sensitive = (ticket, randstr)
    http = _single_use_client(ctx.http)
    body, content_type = _multipart(ticket, randstr)
    ctx.log("腾讯验证码回调成功，向本站兑换本次签到验证令牌")
    payload = _request(http, EXCHANGE_PATH, deadline, sensitive,
                       data=body, headers={"Content-Type": content_type})
    if (not isinstance(payload, dict) or type(payload.get("code")) is not int
            or payload["code"] != 0 or payload.get("success") is False):
        raise VerificationRequired("腾讯验证码票据未被本站接受；未提交签到。",
                                   data={"verification_mode": "tencent", "stage": "exchange"})
    token = _field(payload.get("token"), 16384)
    if not token:
        raise VerificationRequired("腾讯验证码兑换未返回有效令牌；未提交签到。",
                                   data={"verification_mode": "tencent", "stage": "exchange"})
    sensitive += (token,)
    path = CHECKIN_PATH + "?captcha_token=" + quote(token, safe="")
    if options.get("turnstile_check"):
        sitekey = options.get("turnstile_site_key")
        if not isinstance(sitekey, str) or not sitekey.strip():
            raise ConfigError("站点同时启用 Turnstile，但未提供 sitekey；未提交签到。",
                              data={"verification_mode": "tencent"})
        extra = await ctx.solve("turnstile:inject", sitekey=sitekey.strip(),
                                budget=max(0.0, deadline - time.monotonic() - REQUEST_TIMEOUT))
        turnstile = _field(extra.value, 16384) if extra.ok else ""
        if not turnstile:
            raise VerificationRequired("腾讯验证码已通过，但 Turnstile 尚未完成；未提交签到。",
                                       data={"verification_mode": "tencent", "stage": "turnstile"},
                                       evidence=extra.evidence)
        sensitive += (turnstile,)
        path += "&turnstile=" + quote(turnstile, safe="")
    ctx.log("本站验证令牌已取得，单次提交签到并检查业务回执")
    response = _request(http, path, deadline, sensitive)
    try:
        data = checkin_data(_safe(response, sensitive))
    except TaskError as exc:
        exc.data.update(verification_mode="tencent", stage="submit")
        raise
    out = dict(data) if isinstance(data, dict) else {"raw": data}
    out["verification_mode"] = "tencent"
    return out
