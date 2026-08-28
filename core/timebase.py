"""时间语义：统一写 UTC，业务日按固定业务时区。

在 ``root/time_utils.py`` 的基础上补两件流程层需要的能力：

- ``age_days`` / ``age_seconds``：覆盖层判断「缓存值还新不新」的唯一实现；
- ``newer_than``：比较两个 ISO 时间戳的先后，用于「配置改动时间 vs 缓存写入时间」。

旧代码在多处直接对 ISO 字符串做字典序比较（``gui/status_store.py:_is_newer``），
带时区和不带时区的值混在一起时字典序不等于真实先后，这里彻底收敛为解析后比较。
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

# 基础实现复用仓库既有 time_utils（已在多轮运行中验证过时区兼容性），
# 这里只做 re-export 与扩展，避免出现第二套解析规则。
from time_utils import (  # noqa: F401
    BUSINESS_TZ_NAME,
    business_date,
    business_date_of,
    business_timezone,
    is_today,
    parse_timestamp,
    utc_iso,
    utc_now,
)

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
