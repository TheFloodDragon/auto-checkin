"""凭据寿命：像浏览器前端那样「看过期时间办事」，而不是等服务端回 401。

浏览器里的 SPA 续期遵循三条朴素规则，这里一一对应：

1. **AT 过期前主动刷新**。前端拦截器在每个请求前解码 JWT 的 ``exp``，剩余寿命低于
   阈值就先用 RT 换新 AT 再发请求（``jwt_expiry`` / ``needs_renewal``）；
2. **Cookie 跟随服务端**。浏览器无条件接受 ``Set-Cookie``，滚动会话（每次响应延长
   有效期或换新值）因此永不过期（``parse_set_cookie``）；
3. **本地存储寿命 = 凭据真实寿命**。覆盖层的 TTL 应来自 ``exp`` / ``Max-Age``，
   而不是一个与凭据无关的固定值（``credential_ttl``）。

全部是纯函数，不校验签名——签名只有服务端能验，这里只读时间声明来安排续期时机；
读不出来就返回 None，由调用方退回原有的固定 TTL 与 401 被动续期。
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Iterable, Mapping

__all__ = [
    "RENEW_SKEW_SECONDS",
    "SetCookie",
    "cookie_ttl",
    "credential_ttl",
    "jwt_claims",
    "jwt_expiry",
    "needs_renewal",
    "parse_set_cookie",
]

#: 距过期多少秒内视为「需要续期」。与常见前端（axios 拦截器 / oidc-client 默认 60–300s）
#: 同一量级：留足一次刷新往返与时钟偏差，又不至于把刚签发的 token 当成快过期。
RENEW_SKEW_SECONDS = 300
#: 短寿命 token（如 10 分钟 AT）的阈值不超过其总寿命的这个比例，避免刚签发就续期。
RENEW_SKEW_RATIO = 0.25
#: Cookie 寿命上限，与 Chromium 的 400 天上限一致（Max-Age 声明更长也按此截断）。
COOKIE_TTL_CAP = 400 * 86400


def jwt_claims(token: object) -> dict | None:
    """解码 JWT payload（不验签）；不是 JWT 或解码失败返回 None。"""
    text = str(token or "").strip()
    if text.lower().startswith("bearer "):
        text = text[7:].strip()
    parts = text.split(".")
    if len(parts) != 3 or not parts[1]:
        return None
    segment = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(segment.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeError, binascii.Error):
        return None
    return payload if isinstance(payload, dict) else None


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if number == number and number not in (float("inf"), float("-inf")) else None


def jwt_expiry(token: object) -> float | None:
    """JWT 的 ``exp``（epoch 秒）；没有或非法返回 None。"""
    claims = jwt_claims(token)
    if claims is None:
        return None
    exp = _number(claims.get("exp"))
    return exp if exp is not None and exp > 0 else None


def needs_renewal(token: object, *, now: float | None = None, skew: float = RENEW_SKEW_SECONDS) -> bool:
    """token 是否已进入续期窗口（含已过期）。读不出寿命时返回 False——交给 401 兜底。"""
    exp = jwt_expiry(token)
    if exp is None:
        return False
    claims = jwt_claims(token) or {}
    issued = _number(claims.get("iat")) or _number(claims.get("nbf"))
    window = float(skew)
    if issued is not None and exp > issued:
        window = min(window, (exp - issued) * RENEW_SKEW_RATIO)
    moment = time.time() if now is None else float(now)
    return exp - moment <= window


def credential_ttl(name: str, value: object, *, default: int, now: float | None = None) -> int:
    """覆盖层 TTL：JWT 取剩余寿命（已过期则 1 秒，让它尽快让位），否则用默认值。

    返回值恒为正：覆盖层把 ``ttl<=0`` 解释为「永不过期」，过期 token 绝不能因此永生。
    """
    exp = jwt_expiry(value)
    if exp is None:
        return int(default)
    moment = time.time() if now is None else float(now)
    return max(1, int(exp - moment))


@dataclass(frozen=True, slots=True)
class SetCookie:
    """一条 ``Set-Cookie`` 的最小解析结果（只关心会话续期需要的字段）。"""

    name: str
    value: str
    domain: str = ""
    max_age: float | None = None      # 秒；None 表示未声明
    expires: float | None = None      # epoch 秒；None 表示未声明

    def lifetime(self, *, now: float | None = None) -> float | None:
        """剩余寿命（秒）。Max-Age 优先于 Expires（RFC 6265 §5.3）；未声明为 None。"""
        if self.max_age is not None:
            return self.max_age
        if self.expires is not None:
            return self.expires - (time.time() if now is None else float(now))
        return None

    def deleted(self, *, now: float | None = None) -> bool:
        """服务端是否在删除这个 Cookie（空值或已过期）。"""
        life = self.lifetime(now=now)
        return not self.value or (life is not None and life <= 0)


def parse_set_cookie(header: str) -> SetCookie | None:
    text = str(header or "").strip()
    if not text or "=" not in text.split(";", 1)[0]:
        return None
    first, *attributes = text.split(";")
    name, _, value = first.partition("=")
    name, value = name.strip(), value.strip()
    if not name:
        return None
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    domain = ""
    max_age: float | None = None
    expires: float | None = None
    for attribute in attributes:
        key, _, raw = attribute.partition("=")
        key, raw = key.strip().lower(), raw.strip()
        if key == "domain":
            domain = raw.lstrip(".").lower()
        elif key == "max-age":
            try:
                max_age = float(int(raw))
            except ValueError:
                continue
        elif key == "expires":
            try:
                expires = parsedate_to_datetime(raw).timestamp()
            except (TypeError, ValueError, IndexError, OverflowError):
                continue
    return SetCookie(name=name, value=value, domain=domain, max_age=max_age, expires=expires)


def cookie_ttl(updates: Iterable[SetCookie], *, default: int, now: float | None = None) -> int:
    """一组被续期 Cookie 的覆盖层 TTL：取最短的已声明寿命；都未声明则用默认值。"""
    lifetimes = [life for item in updates if (life := item.lifetime(now=now)) is not None and life > 0]
    if not lifetimes:
        return int(default)
    return max(1, min(COOKIE_TTL_CAP, int(min(lifetimes))))


def cookie_pairs(header: str) -> dict[str, str]:
    """把 ``k=v; k2=v2`` 拆成有序字典（同名后者胜，与浏览器发送行为一致）。"""
    pairs: dict[str, str] = {}
    for part in str(header or "").split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name.strip():
            pairs[name.strip()] = value.strip()
    return pairs


def render_cookie(pairs: Mapping[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in pairs.items())
