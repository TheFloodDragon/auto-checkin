"""流程计划：把「未配置就自动探测、已配置就照配置走」变成可求值的数据。

旧实现把降级链写死在代码里（``providers/actions/browser_script.py`` 的
「token → refresh → 账密 → 浏览器」四级、``api.py`` 的 legacy/challenge 互为兜底、
``scripts/newapi_verification.py`` 的验证机制分流），三条链各写各的，用户既不能
固定其中一环，也看不到本次实际走了哪条。

这里统一为：**每个阶段独立求值**，取值四态——

    省略 / "auto"       先用学到的结论，没有就探测，再没有就按模板优先序全试
    "http_api"          固定；失败即失败，不再暗中降级
    ["refresh","oauth"] 固定优先序，只在列内降级
    "off"               跳过该阶段

因为逐阶段求值，「部分配置、部分自动」是天然成立的，不需要额外的组合规则。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from .account import sequence
from .manifest import STAGES, TemplateManifest

__all__ = [
    "Discovery",
    "FlowPlan",
    "StageMode",
    "StagePlan",
    "AUTO",
    "OFF",
]

AUTO = "auto"
OFF = "off"

#: 学到的流程结论默认有效期（天）。站点改版通常伴随连续失败，由 failure_streak 兜底。
DEFAULT_TTL_DAYS = 30
#: 连续失败到这个次数就强制重新探测，不再复用学到的结论。
RELEARN_AFTER_FAILURES = 2


class StageMode(StrEnum):
    AUTO = "auto"        # 学习 → 探测 → 全试
    FIXED = "fixed"      # 用户固定单一方式
    ORDERED = "ordered"  # 用户固定优先序
    OFF = "off"          # 跳过


@dataclass(frozen=True, slots=True)
class Discovery:
    """一次探测得出的阶段结论，写入覆盖层供下次复用。"""

    stage: str
    value: str
    confidence: float = 1.0
    probed_at: str = ""
    ttl_days: int = DEFAULT_TTL_DAYS
    source: str = "probe"
    note: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "value": self.value,
            "confidence": round(float(self.confidence), 3),
            "probed_at": self.probed_at,
            "ttl_days": int(self.ttl_days),
            "source": self.source,
            "note": self.note,
        }

    @classmethod
    def from_payload(cls, stage: str, payload: Any) -> "Discovery | None":
        if not isinstance(payload, Mapping):
            return None
        value = str(payload.get("value") or "").strip()
        if not value:
            return None
        try:
            confidence = float(payload.get("confidence", 1.0))
        except (TypeError, ValueError):
            confidence = 1.0
        try:
            ttl = int(payload.get("ttl_days", DEFAULT_TTL_DAYS))
        except (TypeError, ValueError):
            ttl = DEFAULT_TTL_DAYS
        return cls(
            stage=stage,
            value=value,
            confidence=confidence,
            probed_at=str(payload.get("probed_at") or ""),
            ttl_days=ttl,
            source=str(payload.get("source") or "learned"),
            note=str(payload.get("note") or ""),
        )

    def is_fresh(self, *, now_iso: str = "", clock: Any = None) -> bool:
        """是否仍在有效期内。无时间戳视为已过期（保守重探一次即可修好）。"""
        from .timebase import age_days

        if not self.probed_at:
            return False
        if self.ttl_days <= 0:
            return True
        age = age_days(self.probed_at, now_iso=now_iso, clock=clock)
        # 负数 = 时间戳在未来（时钟回拨/手工改过），不可信，按过期处理。
        return age is not None and 0 <= age <= self.ttl_days


@dataclass(frozen=True, slots=True)
class StagePlan:
    """单个阶段的执行计划。"""

    stage: str
    mode: StageMode
    #: 按顺序尝试的候选方式。空元组表示跳过或无候选。
    candidates: tuple[str, ...] = ()
    #: 首选来源，用于日志与结果展示："config" / "learned" / "template" / "probe"
    source: str = "template"
    learned: Discovery | None = None
    #: 因能力不满足（无浏览器 / 无视觉模型）被剔除的候选及原因。
    skipped: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def enabled(self) -> bool:
        return self.mode is not StageMode.OFF

    @property
    def primary(self) -> str:
        return self.candidates[0] if self.candidates else ""

    @property
    def locked(self) -> bool:
        """用户显式固定：失败时不允许引擎自行扩大候选范围。"""
        return self.mode in (StageMode.FIXED, StageMode.ORDERED)

    def describe(self) -> str:
        if self.mode is StageMode.OFF:
            return f"{self.stage}=off"
        if not self.candidates:
            return f"{self.stage}=<无候选>"
        head = f"{self.stage}={self.primary}({self.source})"
        rest = self.candidates[1:]
        return f"{head}→{'/'.join(rest)}" if rest else head

    def with_result(self, value: str, *, source: str = "probe") -> "StagePlan":
        """记录本次实际选中的方式，把它提到候选首位。"""
        chosen = str(value or "").strip().lower()
        if not chosen:
            return self
        rest = tuple(item for item in self.candidates if item != chosen)
        return replace(self, candidates=(chosen,) + rest, source=source)


@dataclass(frozen=True, slots=True)
class FlowPlan:
    """账号本次运行的完整阶段计划。"""

    stages: Mapping[str, StagePlan]

    def __getitem__(self, stage: str) -> StagePlan:
        return self.stages[stage]

    def get(self, stage: str) -> StagePlan:
        return self.stages.get(stage) or StagePlan(stage=stage, mode=StageMode.AUTO)

    def enabled(self, stage: str) -> bool:
        return self.get(stage).enabled

    def candidates(self, stage: str) -> tuple[str, ...]:
        return self.get(stage).candidates

    def describe(self) -> str:
        """一行可读摘要，进日志与结果文件的 ``flow`` 字段。"""
        return " / ".join(
            plan.describe() for plan in self.stages.values() if plan.mode is not StageMode.AUTO or plan.candidates
        )

    def to_payload(self) -> dict[str, str]:
        return {
            plan.stage: f"{plan.primary}({plan.source})" if plan.primary else str(plan.mode)
            for plan in self.stages.values()
        }

    def with_stage(self, plan: StagePlan) -> "FlowPlan":
        stages = dict(self.stages)
        stages[plan.stage] = plan
        return FlowPlan(MappingProxyType(stages))

    # ── 求值 ────────────────────────────────────────────────────────────
    @classmethod
    def resolve(
        cls,
        *,
        configured: Mapping[str, Any] | None,
        template: TemplateManifest | None = None,
        learned: Mapping[str, Any] | None = None,
        capabilities: Iterable[str] = (),
        failure_streak: int = 0,
        stages: Sequence[str] = STAGES,
        now_iso: str = "",
    ) -> "FlowPlan":
        """把配置 + 学习结论 + 模板优先序 + 可用能力解析成执行计划。

        ``capabilities`` 是本次运行**实际可用**的资源（如 ``{"browser","vision"}``）。
        AUTO/ORDERED 模式下会剔除不满足 ``requires`` 的候选并记进 ``skipped``；
        FIXED 模式**不剔除**——用户显式指定了就该明确失败并说明缺什么，而不是
        被静默换成另一条链路（旧实现里这类静默降级正是「日志看不出走了哪条路」的根因）。
        """
        config = {str(k).strip().lower(): v for k, v in (configured or {}).items()}
        learned_map = learned or {}
        caps = frozenset(str(c) for c in capabilities)
        plans: dict[str, StagePlan] = {}

        for stage in stages:
            raw = config.get(stage)
            values = sequence(raw)
            default_order = _template_order(template, stage)

            if values and values[0] == OFF:
                plans[stage] = StagePlan(stage=stage, mode=StageMode.OFF)
                continue

            if values and values[0] != AUTO:
                mode = StageMode.FIXED if len(values) == 1 else StageMode.ORDERED
                plans[stage] = StagePlan(
                    stage=stage,
                    mode=mode,
                    candidates=values,
                    source="config",
                )
                continue

            # ── auto ──
            discovery = Discovery.from_payload(stage, learned_map.get(stage))
            candidates, skipped = _filter_by_capabilities(default_order, template, stage, caps)
            source = "template"
            if (
                discovery is not None
                and failure_streak < RELEARN_AFTER_FAILURES
                and discovery.is_fresh(now_iso=now_iso)
                and discovery.value not in skipped
            ):
                # 复用上次探测出的正确流程，同时保留其余候选作为兜底。
                rest = tuple(item for item in candidates if item != discovery.value)
                candidates = (discovery.value,) + rest
                source = "learned"
            plans[stage] = StagePlan(
                stage=stage,
                mode=StageMode.AUTO,
                candidates=candidates,
                source=source,
                learned=discovery,
                skipped=MappingProxyType(skipped),
            )

        return cls(MappingProxyType(plans))


def _template_order(template: TemplateManifest | None, stage: str) -> tuple[str, ...]:
    if template is None:
        return ()
    if stage == "login":
        return template.login_order()
    if stage == "execute":
        return template.task_order()
    return ()


def _filter_by_capabilities(
    order: tuple[str, ...],
    template: TemplateManifest | None,
    stage: str,
    caps: frozenset[str],
) -> tuple[tuple[str, ...], dict[str, str]]:
    if template is None or not order:
        return order, {}
    keep: list[str] = []
    skipped: dict[str, str] = {}
    for method in order:
        option = template.login_option(method) if stage == "login" else template.task_option(method)
        requires = getattr(option, "requires", frozenset())
        missing = set(requires) - caps
        if missing:
            skipped[method] = "缺少能力：" + "、".join(sorted(missing))
            continue
        keep.append(method)
    return tuple(keep), skipped
