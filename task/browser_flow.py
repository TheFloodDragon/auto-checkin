"""任务方式：浏览器流程与脚本自管流程。

两者的实现相同（都调用模板的 ``run(ctx)``），区别只在**声明**：

- ``browser_flow`` 声明 ``requires={"browser"}``：引擎在候选过滤阶段就知道没有浏览器
  这条路走不通，直接给需配置的结论，而不是跑到一半才发现；
- ``script`` 不声明依赖：脚本自己决定要不要碰 ``ctx.browser``（惰性，碰了才启动）。
  典型场景是「先纯 API 试一次，不行再开浏览器」——旧实现把这个判断写死在 action 层
  的启发式里（``_should_try_api_first``），脚本无从参与，也无法固定。
"""

from __future__ import annotations

from typing import Any

from core.outcome import Outcome
from solvers.registry import CAP_BROWSER
from .base import run_template_hook

__all__ = ["BrowserFlowTask", "ScriptTask"]


class BrowserFlowTask:
    id = "browser_flow"
    requires = frozenset({CAP_BROWSER})

    async def run(self, ctx: Any, template: Any) -> Outcome:
        return await run_template_hook(ctx, template, what=self.id)


class ScriptTask:
    id = "script"
    requires: frozenset[str] = frozenset()

    async def run(self, ctx: Any, template: Any) -> Outcome:
        return await run_template_hook(ctx, template, what=self.id)
