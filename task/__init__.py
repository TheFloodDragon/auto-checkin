"""任务方式插件（原 checkin_action）。

内置五种：``http_api`` / ``browser_flow`` / ``script`` / ``visit`` / ``relogin``。
模板通过 ``TaskOption`` 声明支持哪些、优先序如何、各自自管哪些阶段（``owns``）。
"""

from __future__ import annotations

from core.errors import ConfigError
from .base import TaskMethod
from .browser_flow import BrowserFlowTask, ScriptTask
from .http_api import HttpApiTask, outcome_from_error
from .relogin import ReloginTask
from .visit import VisitTask

__all__ = [
    "TASKS",
    "TaskMethod",
    "TaskRegistry",
    "describe",
    "outcome_from_error",
]


class TaskRegistry:
    __slots__ = ("_methods",)

    def __init__(self) -> None:
        self._methods: dict[str, TaskMethod] = {}

    def register(self, method: TaskMethod, *, replace_existing: bool = False) -> TaskMethod:
        key = str(getattr(method, "id", "")).strip().lower()
        if not key:
            raise ValueError("任务方式必须有 id")
        if key in self._methods and not replace_existing:
            raise ValueError(f"任务方式 {key!r} 已注册")
        self._methods[key] = method
        return method

    def get(self, method_id: str) -> TaskMethod:
        key = str(method_id or "").strip().lower()
        method = self._methods.get(key)
        if method is None:
            known = "、".join(sorted(self._methods)) or "（空）"
            raise ConfigError(f"未知任务方式 {method_id!r}；可用：{known}")
        return method

    def find(self, method_id: str) -> TaskMethod | None:
        return self._methods.get(str(method_id or "").strip().lower())

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._methods))

    def requires(self, method_id: str) -> frozenset[str]:
        method = self.find(method_id)
        return frozenset(getattr(method, "requires", ()) or ()) if method else frozenset()


TASKS = TaskRegistry()


def _bootstrap() -> None:
    for method in (HttpApiTask(), BrowserFlowTask(), ScriptTask(), VisitTask(), ReloginTask()):
        TASKS.register(method, replace_existing=True)


_bootstrap()


def describe(method_id: str) -> str:
    """人读标签，用于汇总行与 GUI。"""
    labels: dict[str, str] = {
        "http_api": "接口任务",
        "browser_flow": "浏览器流程",
        "script": "自定义脚本",
        "visit": "访问保活",
        "relogin": "重登发放",
    }
    return labels.get(str(method_id or "").strip().lower(), str(method_id or ""))
