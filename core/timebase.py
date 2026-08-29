"""时间语义：统一写 UTC，业务日按固定业务时区。

为什么要有这一层：状态缓存曾经用本地时间的 naive ISO 串并直接按**字符串**比较新旧。
CI 用 Asia/Shanghai、GUI 用用户本地时区，字典序不等于真实先后；跨日后「今日已完成」
也不会失效。这里统一时间语义：

- 落盘统一 UTC，形如 ``2026-07-29T03:20:15Z``；
- 读取兼容 ``Z``、``+08:00`` 与旧的无时区值（按本地时区解释）；
- 业务日按固定业务时区（默认 Asia/Shanghai，与 CI 的 TZ 一致），避免 UTC 跨日让
  「昨天/今天」与用户直觉不符；
- ``age_*`` / ``newer_than`` 是覆盖层判断「缓存还新不新」「配置是不是后改的」的唯一实现。
"""

from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable

BUSINESS_TZ_NAME = os.environ.get("CHECKIN_BUSINESS_TZ", "Asia/Shanghai")
_FALLBACK_BUSINESS_TZ = timezone(timedelta(hours=8))

__all__ = [
    "BUSINESS_TZ_NAME",
    "age_days",
    "age_seconds",
    "business_date",
    "business_date_of",
    "business_timezone",
    "is_today",
    "newer_than",
    "parse_timestamp",
    "utc_iso",
    "utc_now",
]


# ── 基础：时区与解析 ────────────────────────────────────────────────────────
def business_timezone() -> timezone:
    """业务时区；zoneinfo 不可用时回落到固定 +08:00。"""
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(BUSINESS_TZ_NAME)  # type: ignore[return-value]
    except Exception:
        return _FALLBACK_BUSINESS_TZ


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(moment: datetime | None = None) -> str:
    """带时区的 UTC ISO 字符串（秒精度，以 Z 结尾）。"""
    value = moment or utc_now()
    if value.tzinfo is None:
        value = value.astimezone()
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_timestamp(value: object) -> datetime | None:
    """解析 ISO 时间戳；无时区值按本地时区解释。无法解析返回 None。"""
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # 旧数据是本地时间：按本地时区解释，而不是直接判为损坏。
        parsed = parsed.astimezone()
    return parsed


# ── 业务日 ──────────────────────────────────────────────────────────────────
def business_date(moment: datetime | None = None) -> str:
    """业务时区下的日期（YYYY-MM-DD）。"""
    value = moment or utc_now()
    if value.tzinfo is None:
        value = value.astimezone()
    return value.astimezone(business_timezone()).date().isoformat()


def business_date_of(value: object) -> str:
    """从时间戳推导业务日；无法解析返回空串。"""
    parsed = parse_timestamp(value)
    return business_date(parsed) if parsed is not None else ""


def is_today(value: object, *, today: date | None = None) -> bool:
    """时间戳是否属于业务时区的今天；无法解析视为否。"""
    stamp = business_date_of(value)
    if not stamp:
        return False
    reference = today.isoformat() if today is not None else business_date()
    return stamp == reference


# ── 新旧比较（覆盖层判据）──────────────────────────────────────────────────

def _now(now_iso: str = "", clock: Callable[[], datetime] | None = None) -> datetime:
    if now_iso:
        parsed = parse_timestamp(now_iso)
        if parsed is not None:
            return parsed
    if clock is not None:
        value = clock()
        if value.tzinfo is None:
            value = value.astimezone()
        return value
    return utc_now()


def age_seconds(value: Any, *, now_iso: str = "", clock: Callable[[], datetime] | None = None) -> float | None:
    """时间戳距今多少秒；无法解析返回 None。未来时间戳返回负值（不夹到 0）。

    返回负值而不是 0 是刻意的：负值意味着写入时间在「现在」之后，通常是时钟回拨
    或手工改过缓存，调用方应当据此保守处理（视为不可信），而不是当成刚写入。
    """
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    return (_now(now_iso, clock) - parsed.astimezone(timezone.utc)).total_seconds()


def age_days(value: Any, *, now_iso: str = "", clock: Callable[[], datetime] | None = None) -> float | None:
    seconds = age_seconds(value, now_iso=now_iso, clock=clock)
    return None if seconds is None else seconds / 86400.0


def newer_than(left: Any, right: Any) -> bool:
    """``left`` 是否严格晚于 ``right``。任一无法解析时返回 False。

    覆盖层的核心判据（「配置字段改动时间 vs 缓存写入时间」）就用这一个函数。
    无法解析按 False 处理 = 不认为配置更新过 = 保留缓存，属于安全侧：
    真要让配置生效，用户改一次配置就会写出可解析的新时间戳。
    """
    a = parse_timestamp(left)
    b = parse_timestamp(right)
    if a is None or b is None:
        return False
    return a.astimezone(timezone.utc) > b.astimezone(timezone.utc)
