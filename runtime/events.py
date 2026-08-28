"""结构化运行事件：worker → 批量层的诊断通道。

沿用旧 ``checkin_core/events.py`` 的行协议（``@checkin-event {json}``，写 stderr），
因为批量层已经在按它解析，换协议只会让过渡期两边都要认两套。变化有两处：

- ``stage`` 收敛为引擎阶段名（见 ``core.manifest.STAGES``）加 ``solve``/``http``/
  ``overlay``，不再是各模块自取的前缀字符串。旧实现靠一张前缀白名单挑日志行，
  漏登记一个前缀就整条链路静默（README 为此写过一节排查）。
- 事件带 ``account`` 与 ``task``，一个 worker 现在可能跑多个任务。
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, Callable

from ..core.timebase import utc_iso

__all__ = [
    "EVENT_PREFIX",
    "EVENT_VERSION",
    "EventLevel",
    "RunEvent",
    "emit",
    "make_logger",
]

EVENT_PREFIX = "@checkin-event "
EVENT_VERSION = 2


class EventLevel(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(slots=True)
class RunEvent:
    stage: str
    message: str
    level: EventLevel = EventLevel.INFO
    account: str = ""
    task: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    version: int = EVENT_VERSION
    created_at: str = field(default_factory=utc_iso)

    def to_payload(self) -> dict[str, Any]:
        from mask_utils import sanitize_data

        return sanitize_data(asdict(self))

    def to_line(self) -> str:
        return EVENT_PREFIX + json.dumps(
            self.to_payload(), ensure_ascii=False, separators=(",", ":")
        )

    def to_text(self) -> str:
        """人读形态：``[stage:account/task] message [k=v]``。"""
        who = self.account
        if self.task:
            who = f"{who}/{self.task}" if who else self.task
        marker = f"{self.stage}:{who}" if who else self.stage
        extra = " ".join(f"{k}={v}" for k, v in self.fields.items())
        return f"[{marker}] {self.message}" + (f" [{extra}]" if extra else "")

    @classmethod
    def from_line(cls, line: str) -> "RunEvent | None":
        text = str(line or "").strip()
        if not text.startswith(EVENT_PREFIX):
            return None
        try:
            payload = json.loads(text[len(EVENT_PREFIX):])
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict) or payload.get("version") != EVENT_VERSION:
            return None
        try:
            level = EventLevel(str(payload.get("level") or EventLevel.INFO))
        except ValueError:
            return None
        raw_fields = payload.get("fields")
        return cls(
            stage=str(payload.get("stage") or ""),
            message=str(payload.get("message") or ""),
            level=level,
            account=str(payload.get("account") or ""),
            task=str(payload.get("task") or ""),
            fields=dict(raw_fields) if isinstance(raw_fields, dict) else {},
            version=EVENT_VERSION,
            created_at=str(payload.get("created_at") or ""),
        )


def emit(
    stage: str,
    message: str,
    *,
    level: EventLevel = EventLevel.INFO,
    account: str = "",
    task: str = "",
    fields: dict[str, Any] | None = None,
    sink: Callable[[str], None] | None = None,
    structured: bool = True,
) -> RunEvent:
    """发一个事件。

    ``structured=False`` 用于交互式场景（GUI / 人工跑单站）：那里没有解析方，
    打人读文本更合适。worker 一律用结构化行。
    """
    event = RunEvent(
        stage=stage, message=message, level=level, account=account, task=task, fields=dict(fields or {})
    )
    line = event.to_line() if structured else event.to_text()
    if sink is not None:
        sink(line)
    else:
        # stdout 是 worker 的机器协议通道，任何诊断都必须走 stderr。
        print(line, file=sys.stderr, flush=True)
    return event


def make_logger(
    *,
    account: str = "",
    task: str = "",
    structured: bool = True,
    sink: Callable[[str], None] | None = None,
) -> Callable[..., None]:
    """构造 ``ctx.log`` 用的日志函数（阶段名由调用方在闭包外层给定）。"""

    def _log(stage: str, message: str, /, **fields: Any) -> None:
        text = str(message or "").strip()
        if not text:
            return
        emit(
            stage or "run",
            text,
            account=account,
            task=task,
            fields=fields,
            sink=sink,
            structured=structured,
        )

    return _log
