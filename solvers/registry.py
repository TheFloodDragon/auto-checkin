"""解算器注册表：图形验证码 / Turnstile / hCaptcha / WAF 的统一入口。

旧实现里这些能力散落在四个地方、四种调用法：``helpers.solve_captcha(image, scheme)``
走 ``captcha_ocr``；``helpers.solve_hcaptcha(trigger=..., options=...)`` 走
``browser.hcaptcha``；Turnstile 只能自己 ``from browser import turnstile``；
Cloudflare / 阿里云 WAF 藏在 ``bypass``/``waf`` 里由各链路自行调用。脚本作者要记四套
签名，而且没有任何地方能回答「这个站点的验证我到底支不支持」。

统一后：

    result = await ctx.solve("hcaptcha", trigger=box, budget=45)

- ``requires`` 声明资源依赖（browser / vision / node），引擎在阶段开始前就能判断
  「这条路本次走不通」，直接给出 need_config 而不是跑满预算再失败；
- 预算裁剪由注册表统一按 ``ctx.deadline`` 施加，任何解算器都自动获得
  「不被强杀、留下结论与截图」的性质（旧实现只有 hCaptcha 一家做了这件事）；
- 注册是**惰性**的：``factory`` 在真正调用时才 import 实现模块，所以
  ``import dailytask.solvers`` 不会拉起 numpy / playwright / opencv。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Mapping, Protocol

from ..core.errors import ConfigError
from ..core.outcome import Evidence

__all__ = [
    "SOLVERS",
    "SolveResult",
    "Solver",
    "SolverRegistry",
    "SolverSpec",
    "solve",
]

#: 解算器可能依赖的资源。引擎按账号策略与环境算出本次实际可用集合。
CAP_BROWSER = "browser"
CAP_VISION = "vision"
CAP_NODE = "node"


@dataclass(frozen=True, slots=True)
class SolveResult:
    """解算结果。

    失败**不抛异常**是刻意的：验证码解不出属于常见分支，调用方通常要换一张重试
    或降级到别的机制，用异常表达会逼着每个调用点写 try/except。真正的配置错误
    （如解算器不存在、缺 API Key）才抛。
    """

    ok: bool
    value: str = ""
    confidence: float = 0.0
    attempts: int = 0
    reason: str = ""            # timeout / uncertain / widget_absent / vision_error / refused
    message: str = ""
    evidence: Evidence = Evidence()
    data: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def failure(cls, reason: str, message: str = "", **kwargs: Any) -> "SolveResult":
        return cls(ok=False, reason=reason, message=message or reason, **kwargs)

    @classmethod
    def solved(cls, value: str, *, confidence: float = 1.0, **kwargs: Any) -> "SolveResult":
        return cls(ok=True, value=value, confidence=confidence, **kwargs)

    def with_evidence(self, evidence: Evidence | None) -> "SolveResult":
        return replace(self, evidence=self.evidence.merge(evidence))


class Solver(Protocol):
    """解算器实现契约。``ctx`` 是 SDK Context；纯图像解算器可以不用它。"""

    async def solve(self, ctx: Any, /, **kwargs: Any) -> SolveResult: ...


@dataclass(frozen=True, slots=True)
class SolverSpec:
    id: str
    factory: Callable[[], Solver]
    requires: frozenset[str] = frozenset()
    title: str = ""
    description: str = ""
    #: 该解算器的默认总预算（秒）。为 0 表示不限，由调用方/引擎给。
    default_budget: float = 0.0

    @property
    def label(self) -> str:
        return self.title or self.id


class SolverRegistry:
    """解算器注册表。内置项与用户脚本注册项同级。"""

    __slots__ = ("_specs",)

    def __init__(self) -> None:
        self._specs: dict[str, SolverSpec] = {}

    def register(
        self,
        solver_id: str,
        factory: Callable[[], Solver],
        *,
        requires: Iterable[str] = (),
        title: str = "",
        description: str = "",
        default_budget: float = 0.0,
        replace_existing: bool = False,
    ) -> SolverSpec:
        key = str(solver_id or "").strip().lower()
        if not key:
            raise ValueError("解算器 id 不能为空")
        if key in self._specs and not replace_existing:
            raise ValueError(f"解算器 {key!r} 已注册；如需覆盖请传 replace_existing=True")
        spec = SolverSpec(
            id=key,
            factory=factory,
            requires=frozenset(str(item) for item in requires),
            title=title,
            description=description,
            default_budget=default_budget,
        )
        self._specs[key] = spec
        return spec

    def get(self, solver_id: str) -> SolverSpec:
        key = str(solver_id or "").strip().lower()
        spec = self._specs.get(key)
        if spec is None:
            known = "、".join(sorted(self._specs)) or "（空）"
            raise ConfigError(f"未知解算器 {solver_id!r}；可用：{known}")
        return spec

    def has(self, solver_id: str) -> bool:
        return str(solver_id or "").strip().lower() in self._specs

    def ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def available(self, capabilities: Iterable[str]) -> tuple[str, ...]:
        caps = frozenset(str(item) for item in capabilities)
        return tuple(
            sorted(key for key, spec in self._specs.items() if not (spec.requires - caps))
        )

    def missing_capabilities(self, solver_id: str, capabilities: Iterable[str]) -> frozenset[str]:
        caps = frozenset(str(item) for item in capabilities)
        return frozenset(self.get(solver_id).requires - caps)

    async def solve(
        self,
        ctx: Any,
        solver_id: str,
        *,
        budget: float | None = None,
        **kwargs: Any,
    ) -> SolveResult:
        """执行解算。预算按 ``ctx`` 剩余时间统一收敛。

        为什么必须在这里收敛：解算器只知道「这一步值得等多久」，不知道 OAuth /
        Cloudflare 已经花掉多少。总预算超过任务硬超时时，外层 ``wait_for`` 会直接
        强杀，结果退化成一句「执行超时」，丢掉本可返回的 need_verification、失败
        阶段与挑战截图。
        """
        spec = self.get(solver_id)
        missing = self.missing_capabilities(solver_id, _capabilities_of(ctx))
        if missing:
            return SolveResult.failure(
                "unavailable",
                f"解算器 {spec.label} 需要 {'、'.join(sorted(missing))}，本次不可用",
            )
        effective = _clamp_budget(ctx, budget if budget is not None else spec.default_budget)
        if effective is not None and effective <= 0:
            return SolveResult.failure("timeout", f"剩余时间不足，跳过 {spec.label} 求解以保留明确结论")
        solver = spec.factory()
        result = await solver.solve(ctx, budget=effective, **kwargs)
        if not isinstance(result, SolveResult):
            return SolveResult.failure("invalid", f"解算器 {spec.label} 返回了非 SolveResult")
        return result


def _capabilities_of(ctx: Any) -> frozenset[str]:
    caps = getattr(ctx, "capabilities", None)
    if caps is None:
        return frozenset()
    return frozenset(str(item) for item in caps)


#: 解算结束后仍需时间落盘截图、组装结果、续存登录态，预留这段收尾余量。
TEARDOWN_RESERVE_SECONDS = 20.0


def _clamp_budget(ctx: Any, budget: float | None) -> float | None:
    remaining = None
    getter = getattr(ctx, "remaining_seconds", None)
    if callable(getter):
        try:
            remaining = getter()
        except Exception:
            remaining = None
    if remaining is None:
        return budget if budget else None
    ceiling = max(0.0, float(remaining) - TEARDOWN_RESERVE_SECONDS)
    if not budget:
        return ceiling
    return min(float(budget), ceiling)


SOLVERS = SolverRegistry()


async def solve(ctx: Any, solver_id: str, **kwargs: Any) -> SolveResult:
    return await SOLVERS.solve(ctx, solver_id, **kwargs)
