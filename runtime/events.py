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
import hashlib
import re
from collections.abc import Mapping
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, Callable

from core.timebase import utc_iso

__all__ = [
    "EVENT_PREFIX",
    "EVENT_VERSION",
    "EventLevel",
    "RunEvent",
    "emit",
    "emit_challenge",
    "challenge_data",
    "event_scope",
    "make_logger",
]

EVENT_PREFIX = "@checkin-event "
EVENT_VERSION = 2
_LOG_CONTEXT: ContextVar[dict[str, Any]] = ContextVar("run_event_context", default={})
_EVENT_SINK: ContextVar[Callable[[str], None] | None] = ContextVar("run_event_sink", default=None)
_CHALLENGE_SEEN: ContextVar[set[tuple] | None] = ContextVar("challenge_event_seen", default=None)


def challenge_data(result: Any) -> dict[str, Any]:
    """只保留可跨进程传递的状态证据；不透传页面、URL 或求解器私密数据。"""
    raw = getattr(result, "data", {})
    raw = raw if isinstance(raw, Mapping) else {}
    safe = {}
    for key in ("status", "stage", "generation", "input_dispatched", "widget_acknowledged", "retry_allowed", "preserve_page"):
        value = raw.get(key)
        if key == "generation" and isinstance(value, str) and value:
            # 即使 DOM generation 意外带上页面属性，也只公开稳定 opaque 摘要。
            safe[key] = hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]
        elif key in {"status", "stage"} and isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", value):
            safe[key] = value
        elif key in {"input_dispatched", "widget_acknowledged", "retry_allowed", "preserve_page"} and isinstance(value, bool):
            safe[key] = value
    reason = str(getattr(result, "reason", "") or "unknown")
    safe.setdefault("status", "passed" if getattr(result, "ok", False) else (reason if re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", reason) else "unknown"))
    safe.setdefault("preserve_page", safe["status"] != "passed")
    safe.setdefault("retry_allowed", False)
    return safe


def emit_challenge(result: Any, *, source: str = "cloudflare") -> RunEvent | None:
    """明确拒绝立即通知一次，未确认只报告进度，不按错误文案猜测网络或凭据。"""
    fields = challenge_data(result)
    status = fields["status"]
    context = _LOG_CONTEXT.get()
    seen = _CHALLENGE_SEEN.get()
    if seen is None:
        seen = set()
        _CHALLENGE_SEEN.set(seen)
    key = (context.get("account", ""), context.get("task", ""), context.get("step", ""), fields.get("generation", ""), status)
    if key in seen or len(seen) >= 2048:
        return None
    seen.add(key)
    message = "Cloudflare 明确拒绝此次验证" if status == "rejected" else (
        "Cloudflare 验证已通过" if status == "passed" else "Cloudflare 验证尚未确认，保留当前页面等待")
    return emit("solve", message, level=EventLevel.WARNING if status == "rejected" else EventLevel.INFO,
                fields={"event": "challenge_status", "challenge": source, **fields})


@contextmanager
def event_scope(*, sink: Callable[[str], None] | None = None, **fields: Any):
    """异步安全归属与事件接收方；最外层作用域保存一次运行的通知去重集合。"""
    previous = _LOG_CONTEXT.get()
    token = _LOG_CONTEXT.set({**previous, **fields})
    sink_token = _EVENT_SINK.set(sink) if sink is not None else None
    seen_token = _CHALLENGE_SEEN.set(set()) if not previous else None
    try:
        yield
    finally:
        _LOG_CONTEXT.reset(token)
        if sink_token is not None:
            _EVENT_SINK.reset(sink_token)
        if seen_token is not None:
            _CHALLENGE_SEEN.reset(seen_token)


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
        from core.masking import sanitize_data

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
    context = _LOG_CONTEXT.get()
    values = {**context, **dict(fields or {})}
    event = RunEvent(
        stage=stage, message=message, level=level,
        account=account or str(values.pop("account", "") or ""),
        task=task or str(values.pop("task", "") or ""), fields=values,
    )
    event.fields.pop("account", None)
    event.fields.pop("task", None)
    line = event.to_line() if structured else event.to_text()
    sink = sink or _EVENT_SINK.get()
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
        values = {**_LOG_CONTEXT.get(), **fields}
        event_task = str(values.pop("task", task) or "")
        emit(
            stage or "run",
            text,
            account=account,
            task=event_task,
            fields=values,
            sink=sink,
            structured=structured,
        )

    return _log
