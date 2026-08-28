"""任务结论模型：四基准结果 + 自由子结果 + 自定义展示。

设计要点（对应重构诉求 5）：

1. **基准只有四个**：成功 / 已完成 / 失败 / 无影响。聚合、退出码、重试判定只看它。
2. **子结果（reason）是自由字符串**：``need_login``、``level_gate``、``lottery_miss``
   都合法。内置子结果预注册了标签与图标；脚本可以现场 ``REASONS.register()``，
   未注册的 slug 也不会报错——回落基准标签并原样保留，便于日后补注册。
3. **展示与判定分离**：``DisplaySpec`` 决定用户看到什么，``Verdict``/``reason``
   决定程序怎么判。旧实现把 ``STATUS_META`` 的 label/icon 硬编码在枚举旁边，
   脚本无法覆写一个字。
4. **额度不再是一等公民**：旧模型里 ``quota_awarded``/``current_quota`` 一路从
   provider 穿到汇总表，非额度任务（抽奖、答题、保活）被迫塞假值或永远空一列。
   现在统一为 ``DisplaySpec.text`` + ``text_label`` 的「自定义文本」，由模板或
   脚本决定填什么、甚至不填。
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Iterable, Mapping

__all__ = [
    "REASONS",
    "DisplaySpec",
    "Evidence",
    "Outcome",
    "ReasonSpec",
    "Verdict",
    "already_done",
    "blocked",
    "failed",
    "from_legacy_status",
    "need_config",
    "need_login",
    "need_verification",
    "network_error",
    "no_effect",
    "not_applicable",
    "success",
    "to_legacy_status",
]

_EMPTY_MAP: Mapping[str, Any] = MappingProxyType({})


# ── 基准结果 ────────────────────────────────────────────────────────────────
class Verdict(StrEnum):
    """任务的四个基准结论。

    SUCCESS / ALREADY_DONE / NO_EFFECT 都算「不需要用户处置」，只有 FAILED 计失败。
    NO_EFFECT 覆盖旧枚举的 ``not_open``，并扩展到「不适用」「已豁免」——这类情况
    重试与启动浏览器都不会改变结果，不该产生失败噪声，也不该影响批量退出码。
    """

    SUCCESS = "success"
    ALREADY_DONE = "already_done"
    FAILED = "failed"
    NO_EFFECT = "no_effect"


#: 视为「已完成，无需用户处置」的基准结果。批量退出码与当日沿用判定都用它。
OK_VERDICTS: frozenset[Verdict] = frozenset(
    {Verdict.SUCCESS, Verdict.ALREADY_DONE, Verdict.NO_EFFECT}
)

_DEFAULT_LABELS: Mapping[Verdict, tuple[str, str]] = MappingProxyType(
    {
        Verdict.SUCCESS: ("成功", "✅"),
        Verdict.ALREADY_DONE: ("今日已完成", "🎁"),
        Verdict.FAILED: ("失败", "❌"),
        Verdict.NO_EFFECT: ("无影响", "➖"),
    }
)


def parse_verdict(value: object, default: Verdict = Verdict.FAILED) -> Verdict:
    """把外部字符串收敛为 Verdict；未知值安全回落。"""
    try:
        return Verdict(str(value or "").strip().lower())
    except ValueError:
        return default


# ── 子结果注册表 ────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class ReasonSpec:
    """一个子结果的语义与默认展示。

    ``retryable`` 供批量重试策略使用：网络抖动值得当天再试一次，缺配置不值得。
    ``actionable`` 表示「需要用户做点什么」，GUI 据此高亮。
    """

    slug: str
    verdict: Verdict
    label: str
    icon: str = ""
    retryable: bool = False
    actionable: bool = False
    description: str = ""


class ReasonRegistry:
    """子结果注册表。

    刻意允许**未注册**的 slug：脚本作者不该为了报一个自定义结论而先改内核。
    未注册时 ``get()`` 返回一个按基准结果生成的临时 spec，slug 原样保留在结果里。
    """

    __slots__ = ("_specs",)

    def __init__(self) -> None:
        self._specs: dict[str, ReasonSpec] = {}

    def register(
        self,
        slug: str,
        *,
        verdict: Verdict,
        label: str,
        icon: str = "",
        retryable: bool = False,
        actionable: bool = False,
        description: str = "",
        replace_existing: bool = False,
    ) -> ReasonSpec:
        key = _norm_slug(slug)
        if not key:
            raise ValueError("子结果 slug 不能为空")
        if key in self._specs and not replace_existing:
            existing = self._specs[key]
            if existing.verdict is not verdict:
                raise ValueError(
                    f"子结果 {key!r} 已注册为 {existing.verdict}，不能改判为 {verdict}；"
                    "如确需覆盖请传 replace_existing=True"
                )
            return existing
        spec = ReasonSpec(
            slug=key,
            verdict=verdict,
            label=label,
            icon=icon or _DEFAULT_LABELS[verdict][1],
            retryable=retryable,
            actionable=actionable,
            description=description,
        )
        self._specs[key] = spec
        return spec

    def get(self, slug: object, verdict: Verdict = Verdict.FAILED) -> ReasonSpec:
        key = _norm_slug(slug)
        spec = self._specs.get(key)
        if spec is not None:
            return spec
        label, icon = _DEFAULT_LABELS[verdict]
        if key:
            # 未注册的 slug 仍要能看：拼在基准标签后面，而不是静默丢弃。
            label = f"{label}（{key}）"
        return ReasonSpec(slug=key, verdict=verdict, label=label, icon=icon)

    def known(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def __contains__(self, slug: object) -> bool:
        return _norm_slug(slug) in self._specs


def _norm_slug(value: object) -> str:
    return str(value or "").strip().lower().replace("-", "_")


REASONS = ReasonRegistry()

# 内置子结果。前五个由旧 ResultStatus 的失败态迁移而来，语义与文案保持一致，
# 保证用户看到的判定不因重构而漂移。
REASONS.register(
    "need_login",
    verdict=Verdict.FAILED,
    label="登录失效",
    icon="🔐",
    actionable=True,
    description="凭据过期或被吊销，需要重新登录/捕获登录态。",
)
REASONS.register(
    "need_verification",
    verdict=Verdict.FAILED,
    label="需人机验证",
    icon="⚠",
    actionable=True,
    description="站点要求人机验证且本次未能自动通过。",
)
REASONS.register(
    "need_config",
    verdict=Verdict.FAILED,
    label="需配置",
    icon="⚙",
    actionable=True,
    description="缺少只能由用户提供的配置项（脚本路径、每日口令、账密等）。",
)
REASONS.register(
    "network_error",
    verdict=Verdict.FAILED,
    label="站点不可达",
    icon="🌐",
    retryable=True,
    description="网络失败、超时、限流或 5xx 等瞬时错误。",
)
REASONS.register(
    "unconfirmed",
    verdict=Verdict.FAILED,
    label="结果未确认",
    icon="❓",
    retryable=True,
    description="接口回了 2xx 但没有任何任务成立的正面证据，交叉验证也未通过。",
)
REASONS.register(
    "blocked",
    verdict=Verdict.FAILED,
    label="出口 IP 被拒",
    icon="🚫",
    actionable=True,
    description="安全规则拒绝当前出口 IP，浏览器同样无法通过，需更换代理节点。",
)
REASONS.register(
    "not_open",
    verdict=Verdict.NO_EFFECT,
    label="活动未开放",
    icon="🚧",
    description="站点未启用该功能、未到开始时间或活动已结束。",
)
REASONS.register(
    "not_applicable",
    verdict=Verdict.NO_EFFECT,
    label="不适用",
    icon="➖",
    description="该账号/站点不具备执行该任务的条件，且不构成故障。",
)
REASONS.register(
    "tolerated",
    verdict=Verdict.NO_EFFECT,
    label="已豁免",
    icon="➖",
    description="站点配置了 tolerate_failure，失败被降级为不计成败。",
)


# ── 展示与证据 ──────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class DisplaySpec:
    """结论的展示形态。空字段表示「用默认」，不表示「显示空」。

    ``text`` 就是重构诉求里的「自定义文本」：取代旧汇总表写死的额度列。
    newapi / sub2api 模板把余额格式化后放这里（``text_label="额度"``）；抽奖脚本
    可以放 "中 3 次"；不支持的任务留空，该列就是空的，不再被迫编一个额度。
    """

    label: str = ""
    icon: str = ""
    text: str = ""
    text_label: str = ""
    extras: tuple[tuple[str, str], ...] = ()

    def merge(self, other: "DisplaySpec | None") -> "DisplaySpec":
        """用 ``other`` 的非空字段覆盖自身；extras 追加去重。

        用于三级渲染优先级（脚本 → 模板 → 内置默认）的逐级叠加。
        """
        if other is None:
            return self
        seen = {key for key, _ in self.extras}
        extras = self.extras + tuple(
            (key, value) for key, value in other.extras if key not in seen
        )
        return DisplaySpec(
            label=other.label or self.label,
            icon=other.icon or self.icon,
            text=other.text or self.text,
            text_label=other.text_label or self.text_label,
            extras=extras,
        )

    def with_extra(self, key: str, value: object) -> "DisplaySpec":
        text = _as_text(value)
        if not key or not text:
            return self
        if any(existing == key for existing, _ in self.extras):
            return self
        return replace(self, extras=self.extras + ((str(key), text),))


EMPTY_DISPLAY = DisplaySpec()


@dataclass(frozen=True, slots=True)
class Evidence:
    """排查证据：截图、原始响应片段、阶段轨迹。

    旧实现里这些东西各写各的：脚本往 ``detail["screenshot"]`` 塞路径，HTTP 层把
    响应体塞 ``ApiError.payload``，阶段信息只存在于 stderr 日志里（日志会滚走）。
    统一成一等字段后，任何一层都能追加，汇总与 GUI 有稳定的读取位置。
    """

    screenshots: tuple[str, ...] = ()
    responses: tuple[str, ...] = ()
    stages: tuple[str, ...] = ()

    def with_screenshot(self, path: object) -> "Evidence":
        text = _as_text(path)
        if not text or text in self.screenshots:
            return self
        return replace(self, screenshots=self.screenshots + (text,))

    def with_response(self, snippet: object, *, limit: int = 300) -> "Evidence":
        text = _as_text(snippet)[:limit]
        if not text or text in self.responses:
            return self
        return replace(self, responses=self.responses + (text,))

    def with_stage(self, stage: object) -> "Evidence":
        text = _as_text(stage)
        if not text:
            return self
        return replace(self, stages=self.stages + (text,))

    def merge(self, other: "Evidence | None") -> "Evidence":
        if other is None:
            return self
        def _cat(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
            out = list(left)
            out.extend(item for item in right if item not in left)
            return tuple(out)

        return Evidence(
            screenshots=_cat(self.screenshots, other.screenshots),
            responses=_cat(self.responses, other.responses),
            stages=self.stages + other.stages,
        )

    def is_empty(self) -> bool:
        return not (self.screenshots or self.responses or self.stages)


EMPTY_EVIDENCE = Evidence()


# ── 结论 ────────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class Outcome:
    """一次任务执行的完整结论。不可变；所有变形都返回新对象。"""

    verdict: Verdict
    reason: str = ""
    message: str = ""
    display: DisplaySpec = EMPTY_DISPLAY
    data: Mapping[str, Any] = field(default=_EMPTY_MAP)
    evidence: Evidence = EMPTY_EVIDENCE

    def __post_init__(self) -> None:
        # frozen dataclass 里规范化字段只能走 object.__setattr__。
        object.__setattr__(self, "verdict", parse_verdict(self.verdict))
        object.__setattr__(self, "reason", _norm_slug(self.reason))
        object.__setattr__(self, "message", str(self.message or "").strip())
        if not isinstance(self.data, Mapping):
            object.__setattr__(self, "data", _EMPTY_MAP)

    # -- 判定 --
    @property
    def ok(self) -> bool:
        """是否「已完成、无需用户处置」。批量退出码与当日沿用判定的唯一依据。"""
        return self.verdict in OK_VERDICTS

    @property
    def spec(self) -> ReasonSpec:
        return REASONS.get(self.reason, self.verdict)

    @property
    def retryable(self) -> bool:
        return not self.ok and self.spec.retryable

    @property
    def actionable(self) -> bool:
        return not self.ok and self.spec.actionable

    # -- 展示 --
    def rendered(self, *, defaults: DisplaySpec | None = None) -> DisplaySpec:
        """解析出最终展示形态：内置默认 ← 模板/调用方默认 ← 本结论自带覆写。

        顺序即优先级：后者的非空字段覆盖前者，所以脚本的 ``display`` 永远最高。

        一处例外：**已注册子结果**自带语义标签（「登录失效 🔐」「需人机验证 ⚠」），
        它比模板默认更准确。模板的 ``DisplayDefaults`` 是为成功路径准备的（额度列
        表头、站点图标），不该把一个明确的失败原因改写成通用文案。因此已注册
        reason 时忽略 defaults 的 label/icon，只取它的 text/text_label/extras；
        结论自带的 display 仍然最高——脚本要改就该改得动。
        """
        spec = self.spec
        base = DisplaySpec(label=spec.label, icon=spec.icon)
        weak = defaults
        if defaults is not None and self.reason in REASONS:
            weak = replace(defaults, label="", icon="")
        return base.merge(weak).merge(self.display)

    @property
    def label(self) -> str:
        return self.rendered().label

    @property
    def icon(self) -> str:
        return self.rendered().icon

    # -- 变形 --
    def with_display(self, display: DisplaySpec | None = None, **fields: Any) -> "Outcome":
        patch = display
        if fields:
            patch = DisplaySpec(**fields) if patch is None else patch.merge(DisplaySpec(**fields))
        if patch is None:
            return self
        return replace(self, display=self.display.merge(patch))

    def with_data(self, *maps: Mapping[str, Any] | None, **fields: Any) -> "Outcome":
        merged: dict[str, Any] = dict(self.data)
        for item in maps:
            if isinstance(item, Mapping):
                merged.update(item)
        merged.update(fields)
        return replace(self, data=MappingProxyType(dict(merged)))

    def with_evidence(self, evidence: Evidence | None) -> "Outcome":
        return replace(self, evidence=self.evidence.merge(evidence))

    def with_message(self, message: str) -> "Outcome":
        return replace(self, message=str(message or "").strip())

    def as_reason(self, reason: str, *, verdict: Verdict | None = None) -> "Outcome":
        """改判子结果；不传 verdict 时沿用已注册子结果声明的基准结果。"""
        slug = _norm_slug(reason)
        target = verdict
        if target is None:
            target = REASONS.get(slug, self.verdict).verdict if slug in REASONS else self.verdict
        return replace(self, verdict=target, reason=slug)

    def tolerated(self) -> "Outcome":
        """把失败降级为「无影响 / 已豁免」，原结论存进 data 以便追溯。

        旧实现是在汇总阶段打一个 ``tolerated`` 标记、同时保持 ``ok=False``，于是
        「不计失败」和「当天不再重试」两个语义纠缠在一起，判定处处要写特例。
        这里直接改判基准结果，聚合侧就只剩一条规则。
        """
        if self.ok:
            return self
        return replace(
            self,
            verdict=Verdict.NO_EFFECT,
            reason="tolerated",
            data=MappingProxyType(
                {
                    **dict(self.data),
                    "tolerated_from": {"verdict": str(self.verdict), "reason": self.reason},
                }
            ),
        )

    # -- 序列化 --
    def to_payload(self) -> dict[str, Any]:
        """结果文件 v2 的单条形态。``data``/``evidence`` 由调用方负责脱敏。"""
        view = self.rendered()
        payload: dict[str, Any] = {
            "verdict": str(self.verdict),
            "reason": self.reason,
            "ok": self.ok,
            "label": view.label,
            "icon": view.icon,
            "message": self.message,
            "legacy_status": to_legacy_status(self),
        }
        if view.text:
            payload["text"] = view.text
            payload["text_label"] = view.text_label
        if view.extras:
            payload["extras"] = [list(item) for item in view.extras]
        if self.data:
            payload["data"] = dict(self.data)
        if not self.evidence.is_empty():
            payload["evidence"] = {
                key: list(value)
                for key, value in (
                    ("screenshots", self.evidence.screenshots),
                    ("responses", self.evidence.responses),
                    ("stages", self.evidence.stages),
                )
                if value
            }
        return payload

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "Outcome":
        """读回结果文件条目；v1（8 值 status）与 v2 都能解析。"""
        if not isinstance(payload, Mapping):
            return failed("结果条目格式无效", reason="unconfirmed")
        if "verdict" in payload:
            verdict = parse_verdict(payload.get("verdict"))
            reason = str(payload.get("reason") or "")
        else:
            verdict, reason = from_legacy_status(payload.get("status"))
        raw_extras = payload.get("extras")
        extras: tuple[tuple[str, str], ...] = ()
        if isinstance(raw_extras, list):
            extras = tuple(
                (str(item[0]), str(item[1]))
                for item in raw_extras
                if isinstance(item, (list, tuple)) and len(item) == 2
            )
        raw_evidence = payload.get("evidence")
        evidence = EMPTY_EVIDENCE
        if isinstance(raw_evidence, Mapping):
            evidence = Evidence(
                screenshots=_as_str_tuple(raw_evidence.get("screenshots")),
                responses=_as_str_tuple(raw_evidence.get("responses")),
                stages=_as_str_tuple(raw_evidence.get("stages")),
            )
        data = payload.get("data")
        if not isinstance(data, Mapping):
            data = payload.get("detail") if isinstance(payload.get("detail"), Mapping) else {}
        return cls(
            verdict=verdict,
            reason=reason,
            message=str(payload.get("message") or ""),
            display=DisplaySpec(
                label=str(payload.get("label") or ""),
                icon=str(payload.get("icon") or ""),
                text=str(payload.get("text") or ""),
                text_label=str(payload.get("text_label") or ""),
                extras=extras,
            ),
            data=MappingProxyType(dict(data)),
            evidence=evidence,
        )


# ── 构造器（脚本与内部层共用）─────────────────────────────────────────────
def _build(
    verdict: Verdict,
    message: str,
    *,
    reason: str = "",
    text: str = "",
    text_label: str = "",
    label: str = "",
    icon: str = "",
    extras: Iterable[tuple[str, object]] = (),
    data: Mapping[str, Any] | None = None,
    evidence: Evidence | None = None,
) -> Outcome:
    display = DisplaySpec(
        label=label,
        icon=icon,
        text=_as_text(text),
        text_label=str(text_label or ""),
        extras=tuple(
            (str(key), _as_text(value)) for key, value in extras if _as_text(value)
        ),
    )
    return Outcome(
        verdict=verdict,
        reason=reason,
        message=message,
        display=display,
        data=MappingProxyType(dict(data or {})),
        evidence=evidence or EMPTY_EVIDENCE,
    )


def success(message: str, **kwargs: Any) -> Outcome:
    """任务本次确实完成并产生效果。"""
    return _build(Verdict.SUCCESS, message, **kwargs)


def already_done(message: str, **kwargs: Any) -> Outcome:
    """今日此前已完成，本次无需重复执行。"""
    return _build(Verdict.ALREADY_DONE, message, **kwargs)


def failed(message: str, **kwargs: Any) -> Outcome:
    """执行失败。``reason`` 给出可行动的细分原因。"""
    return _build(Verdict.FAILED, message, **kwargs)


def no_effect(message: str, **kwargs: Any) -> Outcome:
    """站点未开放 / 任务不适用：既不算成功也不算失败。"""
    kwargs.setdefault("reason", "not_open")
    return _build(Verdict.NO_EFFECT, message, **kwargs)


# ── 常用子结果的具名构造器 ──────────────────────────────────────────────────
# 这些不是新的判定，只是 ``failed(..., reason=...)`` 的可读写法。脚本里
# ``return need_login("登录态已失效")`` 比手写 reason 字符串更不容易拼错，
# 而拼错的后果是结论掉进「未分类失败」——用户看不出该去做什么。
def need_login(message: str, **kwargs: Any) -> Outcome:
    """登录态失效：需要重新登录 / 重新捕获登录态。"""
    kwargs["reason"] = "need_login"
    return _build(Verdict.FAILED, message, **kwargs)


def need_verification(message: str, **kwargs: Any) -> Outcome:
    """需要人机验证，本次未能自动完成。"""
    kwargs["reason"] = "need_verification"
    return _build(Verdict.FAILED, message, **kwargs)


def need_config(message: str, **kwargs: Any) -> Outcome:
    """缺少只能由用户提供的配置（口令、账密、模板参数）。"""
    kwargs["reason"] = "need_config"
    return _build(Verdict.FAILED, message, **kwargs)


def network_error(message: str, **kwargs: Any) -> Outcome:
    """站点不可达 / 瞬时网络故障：可重试。"""
    kwargs["reason"] = "network_error"
    return _build(Verdict.FAILED, message, **kwargs)


def blocked(message: str, **kwargs: Any) -> Outcome:
    """出口 IP 被站点安全规则拒绝：换代理才有意义，重试与浏览器都无用。"""
    kwargs["reason"] = "blocked"
    return _build(Verdict.FAILED, message, **kwargs)


def not_applicable(message: str, **kwargs: Any) -> Outcome:
    """本任务对该账号不适用（等级不够、前置未完成）：不计失败。"""
    kwargs["reason"] = "not_applicable"
    return _build(Verdict.NO_EFFECT, message, **kwargs)


# ── 与旧 8 值 status 的双向映射 ─────────────────────────────────────────────
# 过渡期用途：结果文件写 ``legacy_status``，CI 汇总（ci/report.py）与旧 GUI 状态
# 缓存继续可读；读旧结果文件时反向解析。一个大版本后连同这两个函数一起删除。
_LEGACY_TO_NEW: Mapping[str, tuple[Verdict, str]] = MappingProxyType(
    {
        "success": (Verdict.SUCCESS, ""),
        "already_done": (Verdict.ALREADY_DONE, ""),
        "not_open": (Verdict.NO_EFFECT, "not_open"),
        "need_login": (Verdict.FAILED, "need_login"),
        "need_verification": (Verdict.FAILED, "need_verification"),
        "need_config": (Verdict.FAILED, "need_config"),
        "network_error": (Verdict.FAILED, "network_error"),
        "error": (Verdict.FAILED, ""),
    }
)

_NEW_TO_LEGACY: Mapping[tuple[Verdict, str], str] = MappingProxyType(
    {
        (Verdict.SUCCESS, ""): "success",
        (Verdict.ALREADY_DONE, ""): "already_done",
        (Verdict.NO_EFFECT, "not_open"): "not_open",
        (Verdict.NO_EFFECT, "not_applicable"): "not_open",
        (Verdict.NO_EFFECT, "tolerated"): "not_open",
        (Verdict.FAILED, "need_login"): "need_login",
        (Verdict.FAILED, "need_verification"): "need_verification",
        (Verdict.FAILED, "need_config"): "need_config",
        (Verdict.FAILED, "network_error"): "network_error",
    }
)


def from_legacy_status(value: object) -> tuple[Verdict, str]:
    """旧 8 值 status → (基准结果, 子结果)。未知值按失败处理。"""
    return _LEGACY_TO_NEW.get(str(value or "").strip().lower(), (Verdict.FAILED, ""))


def to_legacy_status(outcome: Outcome) -> str:
    """(基准结果, 子结果) → 旧 8 值 status。

    自定义 slug 没有对应旧值时，按基准结果落到最接近的旧状态：成功系映射到
    success/already_done，无影响映射到 not_open，其余一律 error。
    """
    exact = _NEW_TO_LEGACY.get((outcome.verdict, outcome.reason))
    if exact:
        return exact
    if outcome.verdict is Verdict.SUCCESS:
        return "success"
    if outcome.verdict is Verdict.ALREADY_DONE:
        return "already_done"
    if outcome.verdict is Verdict.NO_EFFECT:
        return "not_open"
    return "error"


# ── 小工具 ──────────────────────────────────────────────────────────────────
def _as_text(value: object) -> str:
    if value is None or isinstance(value, bool):
        return "" if value is None else ("是" if value else "否")
    text = str(value)
    return " ".join(text.split()).strip()


def _as_str_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value if str(item))
    return ()
