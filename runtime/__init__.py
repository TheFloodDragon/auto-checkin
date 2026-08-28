"""运行时：阶段编排、探测、预算、能力、事件与批量分组。

``runtime`` 是唯一「知道整件事怎么串起来」的层：它组装 Context、按 FlowPlan 逐阶段
求值、把结论写回覆盖层。插件（login / task / templates / solvers）都不认识彼此，只
认识 SDK 契约与自己的输入。
"""

from __future__ import annotations

from .budget import Budget, Deadline
from .capabilities import CAP_BROWSER, CAP_NODE, CAP_VISION
from .events import EventLevel, RunEvent, emit

__all__ = [
    "CAP_BROWSER",
    "CAP_NODE",
    "CAP_VISION",
    "Budget",
    "Deadline",
    "EventLevel",
    "RunEvent",
    "emit",
]
