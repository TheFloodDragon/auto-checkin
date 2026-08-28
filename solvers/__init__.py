"""解算器：图形验证码 / Turnstile / hCaptcha / WAF 的统一注册表。

内置项在 import 时完成**注册**（只登记 id 与 factory），实现模块在首次调用时才
import——所以 ``import dailytask.solvers`` 不会拉起 numpy / opencv / playwright。
"""

from __future__ import annotations

from .registry import (
    CAP_BROWSER,
    CAP_NODE,
    CAP_VISION,
    SOLVERS,
    SolveResult,
    Solver,
    SolverRegistry,
    SolverSpec,
    solve,
)

__all__ = [
    "CAP_BROWSER",
    "CAP_NODE",
    "CAP_VISION",
    "SOLVERS",
    "SolveResult",
    "Solver",
    "SolverRegistry",
    "SolverSpec",
    "solve",
]


def _bootstrap() -> None:
    from . import image, turnstile_widget, web

    image.register_all(SOLVERS)
    web.register_all(SOLVERS)
    turnstile_widget.register(SOLVERS)


_bootstrap()
