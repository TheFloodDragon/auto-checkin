"""自动探测：模板指纹与流程结论。

探测的五条规则（把既有正确经验固化为通用规则，见 docs/REFACTOR_PLAN.md §5.4）：

1. **只读优先**：先 GET 确认端点存在，才发写请求。旧 ``scripts/newapi_verification.py``
   读 ``/api/status`` 的开关来分流验证机制，就是这条规则的范例。
2. **不适用 ≠ 失败**：404/405/端点不存在 → 继续下一候选；机制适用但被拒 → 立即停止
   并如实报告。混淆这两者会把「站点改了端点」和「账号被封」显示成同一句话。
3. **留证据**：每个结论记录判据来源，失败时用户能自查。
4. **有预算**：探测占任务预算的固定份额，超出就用当前最优候选。
5. **执行即学习**：真正跑通的那条路径就是结论——不需要专门的探测阶段也能积累经验。
   这是「二次复用原些探测的正确流程」的主路径，见 ``engine`` 里的 ``record_flow``。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from core.errors import TaskError
from core.flow import Discovery
from net import guard

__all__ = ["TemplateScore", "detect_template", "score_template"]

#: 判定「就是这一族站点」的最低分。低于它宁可让用户显式指定模板，
#: 也不要用一个猜错的模板去发写请求。
MIN_CONFIDENCE = 0.6


@dataclass(frozen=True, slots=True)
class TemplateScore:
    template_id: str
    confidence: float
    evidence: tuple[str, ...] = ()

    def describe(self) -> str:
        marks = "、".join(self.evidence) if self.evidence else "无命中"
        return f"{self.template_id}={self.confidence:.2f}（{marks}）"


def score_template(manifest: Any, payloads: dict[str, Any]) -> TemplateScore:
    """按 ``DetectSpec`` 给一个模板打分。

    命中一个 json_key 或 marker 各得一分，除以候选总数即置信度；``weight`` 用于让
    更具体的模板（私改站）压过它继承的基础模板。
    """
    detect = getattr(manifest, "detect", None)
    if detect is None:
        return TemplateScore(manifest.id, 0.0)
    hits: list[str] = []
    total = len(detect.json_keys) + len(detect.markers)
    if total == 0:
        return TemplateScore(manifest.id, 0.0)
    for path in detect.paths or ():
        payload = payloads.get(path)
        if payload is None:
            continue
        text = str(payload)
        for key in detect.json_keys:
            if _has_key(payload, key):
                hits.append(f"{path}:{key}")
        for marker in detect.markers:
            if guard.contains_any(text, [marker]):
                hits.append(f"{path}~{marker}")
    unique = tuple(dict.fromkeys(hits))
    confidence = min(1.0, len(unique) / total * float(detect.weight or 1.0))
    return TemplateScore(manifest.id, confidence, unique)


async def detect_template(
    http: Any,
    candidates: Iterable[Any],
    *,
    log: Any = None,
) -> tuple[Any | None, list[TemplateScore]]:
    """在候选模板里挑出最像的一个。

    只发 GET，且每个路径只发一次（多个模板共用 ``/api/status`` 是常态）。任何请求失败
    都按「该路径无信息」处理——站点半边不可用不该让整个探测崩掉。
    """
    templates = [item for item in candidates if getattr(item.manifest, "detect", None) is not None]
    if not templates:
        return None, []

    paths: list[str] = []
    for item in templates:
        for path in item.manifest.detect.paths or ():
            if path not in paths:
                paths.append(path)

    payloads: dict[str, Any] = {}
    for path in paths:
        try:
            payloads[path] = http.get(path)
        except TaskError as exc:
            if log is not None:
                log(f"探测 {path} 未取到响应：{exc.message}")
        except Exception:
            continue

    scores = sorted(
        (score_template(item.manifest, payloads) for item in templates),
        key=lambda item: item.confidence,
        reverse=True,
    )
    if log is not None:
        log("模板探测：" + "；".join(item.describe() for item in scores))
    if not scores or scores[0].confidence < MIN_CONFIDENCE:
        return None, scores
    best = scores[0].template_id
    chosen = next((item for item in templates if item.manifest.id == best), None)
    return chosen, scores


def template_discovery(score: TemplateScore) -> Discovery:
    return Discovery(
        stage="template",
        value=score.template_id,
        confidence=score.confidence,
        source="probe",
        note="；".join(score.evidence[:3]),
    )


def _has_key(payload: Any, key: str) -> bool:
    from core.manifest import pick_path

    return pick_path(payload, (key,)) is not None
