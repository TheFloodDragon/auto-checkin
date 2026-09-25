"""时间预算：一个截止点，按阶段切片。

为什么需要它：任务有硬超时（配置的 ``task.timeout``），而中途的每一步——OAuth 回跳、
Cloudflare 挑战、hCaptcha 求解——都只知道「这一步值得等多久」，不知道前面已经花了
多少。旧实现只有 hCaptcha 一家做了预算收敛（``ScriptHelpers._clamp_hcaptcha_budget``），
其余步骤一旦超时就被外层 ``asyncio.wait_for`` 整体强杀，结论退化成一句「执行超时」，
本可返回的 need_verification、失败阶段与截图全部丢失。

这里把它上移为通用能力：
- ``Deadline`` 是唯一的时间真相，``remaining()`` 给所有层用；
- ``slice()`` 按阶段份额切一块预算，且永远不超过剩余时间减收尾余量；
- 解算器注册表已经在用同一个收尾余量常量（见 ``solvers/registry.py``）。
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterator, Mapping

__all__ = [
    "Budget",
    "DEFAULT_SHARES",
    "Deadline",
    "TEARDOWN_RESERVE_SECONDS",
]

#: 解算结束后仍需时间落盘截图、组装结果、续存登录态，预留这段收尾余量。
#: 与 ``dailytask.solvers.registry.TEARDOWN_RESERVE_SECONDS`` 必须一致。
TEARDOWN_RESERVE_SECONDS = 20.0

#: 各阶段的默认预算份额（相对于**任务开始时**的总预算）。
#: 份额之和刻意大于 1：它们是上限而不是配额，正常流程里不会每个阶段都吃满。
DEFAULT_SHARES: Mapping[str, float] = MappingProxyType(
    {
        "login": 0.35,
        "prepare": 0.15,
        "detect": 0.25,
        "execute": 0.60,
        "verification": 0.40,
        "confirm": 0.15,
    }
)


@dataclass(frozen=True, slots=True)
class Budget:
    """一段命名预算。``seconds`` 为 None 表示不限。"""

    name: str
    seconds: float | None
    started_at: float

    @property
    def expired(self) -> bool:
        if self.seconds is None:
            return False
        return (time.monotonic() - self.started_at) >= self.seconds

    def remaining(self) -> float | None:
        if self.seconds is None:
            return None
        return max(0.0, self.seconds - (time.monotonic() - self.started_at))

    def ms(self, *, default: int = 0) -> int:
        """毫秒形式，供 Playwright 的 timeout 参数使用。"""
        remaining = self.remaining()
        if remaining is None:
            return default
        return int(remaining * 1000)


class Deadline:
    """任务的硬截止点。``total`` 为 None 表示不限时（GUI 单站调试）。"""

    __slots__ = ("total", "_start")

    def __init__(self, total: float | None = None) -> None:
        self.total = None if total is None else max(1.0, float(total))
        self._start = time.monotonic()

    def child(self, seconds: float | None = None) -> "Deadline":
        """派生不晚于父级截止点的预算；不足一秒或已过期时也绝不补时。"""
        child = Deadline()
        limit = None if seconds is None else max(0.0, float(seconds))
        if self.at is not None:
            remaining = max(0.0, self.at - child._start)
            if remaining == 0:
                child._start = self.at
            limit = remaining if limit is None else min(limit, remaining)
        child.total = limit
        return child

    @property
    def at(self) -> float | None:
        """monotonic 截止点，供 ``Context.deadline`` 直接使用。"""
        return None if self.total is None else self._start + self.total

    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def remaining(self) -> float | None:
        if self.total is None:
            return None
        return max(0.0, self.total - self.elapsed())

    def expired(self) -> bool:
        remaining = self.remaining()
        return remaining is not None and remaining <= 0

    def usable(self) -> float | None:
        """扣掉收尾余量后真正可用于「干活」的剩余时间。"""
        remaining = self.remaining()
        if remaining is None:
            return None
        return max(0.0, remaining - TEARDOWN_RESERVE_SECONDS)

    def slice(self, name: str, seconds: float | None = None) -> Budget:
        """切出一段阶段预算。

        显式 ``seconds`` 优先，否则按 ``DEFAULT_SHARES`` 的份额；两者都会被剩余
        可用时间截断——阶段预算永远不该大于「到硬超时还剩多少」。
        """
        usable = self.usable()
        if seconds is None:
            share = DEFAULT_SHARES.get(name)
            if share is None or self.total is None:
                seconds = None
            else:
                seconds = self.total * share
        if seconds is not None and usable is not None:
            seconds = min(float(seconds), usable)
        elif seconds is None and usable is not None:
            seconds = usable
        return Budget(name=name, seconds=seconds, started_at=time.monotonic())

    @contextmanager
    def stage(self, name: str, seconds: float | None = None) -> Iterator[Budget]:
        """``with deadline.stage("login") as budget:`` —— 只提供预算，不强制中断。

        刻意不在退出时抛异常：中断的判断权在调用方，它才知道「已经拿到结论了吗」。
        强制中断会重新制造本模块要解决的问题——把有结论的失败变成没结论的超时。
        """
        yield self.slice(name, seconds)
