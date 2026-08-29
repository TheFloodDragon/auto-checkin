"""任务方式插件的契约（原 checkin_action）。

「任务方式」回答的是：**引擎该准备什么资源、以及自己要不要介入**。它不关心站点接口
长什么样（模板的事），也不关心怎么登录（登录方式的事）。

驱动与模板的分工：
- 驱动：准备资源（只给 HTTP？还是连浏览器一起）、决定通用阶段（探测 / 交叉验证）跑不跑；
- 模板：站点逻辑（``run()`` 或声明式 ``endpoints`` + ``[response]``）。

这条分工是旧实现里最缺的一块：``actions/api.py`` 的 400 行状态机同时干了这两件事，
于是 New API 的「余额交叉验证」既无法关掉，也无法被别的站点族复用。
"""

from __future__ import annotations

from typing import Any, Protocol

from core.errors import ConfigError
from core.outcome import Outcome

__all__ = ["TaskMethod", "run_template_hook"]


class TaskMethod(Protocol):
    """任务方式实现契约。"""

    id: str
    requires: frozenset[str]

    async def run(self, ctx: Any, template: Any) -> Outcome: ...


async def run_template_hook(ctx: Any, template: Any, *, what: str) -> Outcome:
    """调用模板的 ``run(ctx)``；没有该钩子时给出可行动的配置错误。"""
    hook = template.hook("run") if hasattr(template, "hook") else None
    if hook is None:
        raise ConfigError(
            f"任务方式 {what} 要求模板实现 async def run(ctx)，"
            f"但模板 {getattr(template, 'id', '?')} 没有定义它。"
        )
    result = await hook(ctx)
    if not isinstance(result, Outcome):
        raise ConfigError(
            f"模板 {getattr(template, 'id', '?')} 的 run() 必须返回 Outcome，"
            f"实际返回 {type(result).__name__}；请使用 sdk 的 ok()/done()/fail()/no_effect() 构造。"
        )
    return result
