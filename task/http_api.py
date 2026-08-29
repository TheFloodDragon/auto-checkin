"""任务方式：纯 HTTP 接口任务。

两种执行形态：
1. 模板实现了 ``run(ctx)`` → 直接调用（内置 newapi / sub2api 走这条）；
2. 模板只有 ``endpoints`` + ``[response]`` 声明 → 走**声明式执行器**。

第 2 条是「不写一行 Python 就能加一个站点」真正成立的地方。它把旧
``providers/actions/api.py`` 里那台 400 行状态机的通用部分固化下来：

    读状态 → 已完成？ → 记下当前数值 → 提交 → 解析回执
                                          ↓ 没有正面证据
                                     交叉验证（数值增长 / 状态回读）

其中最重要的一条经验原样保留：**接口回 200 不等于任务成立**。实测存在站点静默拒绝、
或配置的端点根本不是签到接口的情况，直接报成功会出现「显示成功但额度没到账」。
"""

from __future__ import annotations

from typing import Any

from core.errors import ConfigError, TaskError
from core.manifest import ResponseMap
from core.outcome import DisplaySpec, Outcome, already_done, failed, no_effect, success
from net import guard
from net.http import extract_message, unwrap_data
from .base import run_template_hook

__all__ = ["HttpApiTask", "declarative_run", "outcome_from_error"]


class HttpApiTask:
    id = "http_api"
    requires: frozenset[str] = frozenset()

    async def run(self, ctx: Any, template: Any) -> Outcome:
        if template.hook("run") is not None:
            return await run_template_hook(ctx, template, what=self.id)
        return await declarative_run(ctx, template)


# ── 声明式执行器 ────────────────────────────────────────────────────────────
async def declarative_run(ctx: Any, template: Any) -> Outcome:
    manifest = template.manifest
    endpoints = dict(manifest.endpoints or {})
    response: ResponseMap = manifest.response
    submit = str(endpoints.get("submit") or endpoints.get("checkin") or "").strip()
    if not submit:
        raise ConfigError(
            f"模板 {manifest.id} 既没有 run()，也没有声明 [endpoints].submit，无法执行任务。"
        )
    if response.is_empty():
        raise ConfigError(
            f"模板 {manifest.id} 声明了端点但没有 [response] 映射，"
            "通用驱动无法判断任务是否成立（这正是会造成误报的地方）。"
        )

    state = await _read_state(ctx, endpoints, response)
    if state.get("checked_in"):
        return already_done("今日已完成。", data=_state_data(state)).with_display(
            _display(response, balance=state.get("balance"))
        )

    before = response.to_number(state.get("balance"))
    if before is None:
        before = await _read_balance(ctx, endpoints, response)

    body = _submit_body(ctx, manifest)
    try:
        payload = unwrap_data(ctx.http.request("POST", submit, json_body=body))
    except TaskError as exc:
        return outcome_from_error(exc)

    data = payload if isinstance(payload, dict) else {}
    awarded = response.pick(data, "awarded")
    balance = response.pick(data, "balance")
    detail = {
        "source": "http_api",
        "awarded": awarded,
        "balance": balance,
        "streak": response.pick(data, "streak"),
        "total": response.pick(data, "total"),
    }
    detail = {key: value for key, value in detail.items() if value is not None}

    if response.pick(data, "already") or guard.already_done_hint(str(response.pick(data, "message") or "")):
        return already_done("今日已完成。", data=detail).with_display(
            _display(response, balance=balance if balance is not None else state.get("balance"))
        )

    message = str(response.pick(data, "message") or "").strip()
    if response.has_amount(awarded):
        text = response.format(awarded)
        return success(message or f"任务完成，获得：{text}", data=detail).with_display(
            _display(response, balance=balance, awarded=awarded)
        )

    # 没有任何正面证据：用前后数值差与状态回读交叉验证，验证不到就不谎报成功。
    confirmed = await _confirm(ctx, endpoints, response, before=before, data=data)
    if confirmed is not None:
        gained, after = confirmed
        return success(
            message or f"任务完成，获得：{response.format(_raw_delta(response, gained))}",
            data={**detail, "awarded": _raw_delta(response, gained), "balance": after},
        ).with_display(_display(response, balance=after, awarded=_raw_delta(response, gained)))

    recheck = await _read_state(ctx, endpoints, response)
    if recheck.get("checked_in"):
        return success(message or "任务完成（站点已标记今日完成）。", data=detail).with_display(
            _display(response, balance=recheck.get("balance"))
        )
    if awarded is not None or response.pick(data, "streak") is not None:
        return success(message or "任务完成（站点未返回本次数值）。", data=detail).with_display(
            _display(response, balance=balance)
        )
    return failed(
        "接口返回成功但没有任何任务成立的证据（无数值、无连续天数、状态也未变），"
        "为避免误报未判定为成功；该站点可能需要在网页手动完成，或端点已变更。",
        reason="unconfirmed",
        data=detail,
    )


def outcome_from_error(exc: TaskError) -> Outcome:
    """把 HTTP 异常翻译成结论。

    顺序重要：先判「今日已完成」与「未开放」，再看异常自带的 reason。不少站点用
    非零业务码表达「今天已经签过了」，先看 reason 会把它报成失败。
    """
    text = f"{exc.message} {exc.payload}"
    if guard.already_done_hint(text):
        return already_done(exc.message or "今日已完成。", data={"source": "http_api"})
    if guard.not_open_hint(text):
        return no_effect(exc.message, reason="not_open")
    outcome = exc.to_outcome()
    if not outcome.message:
        outcome = outcome.with_message(extract_message(exc.payload))
    return outcome


# ── 内部 ────────────────────────────────────────────────────────────────────
async def _read_state(ctx: Any, endpoints: dict[str, str], response: ResponseMap) -> dict[str, Any]:
    path = str(endpoints.get("state") or endpoints.get("status") or "").strip()
    if not path:
        return {}
    try:
        payload = unwrap_data(ctx.http.get(path))
    except TaskError as exc:
        # 状态接口失败不致命：继续尝试提交，让站点自己拒绝。但要留证据。
        ctx.log(f"读取任务状态失败：{exc.message}")
        return {"state_error": exc.reason or "error"}
    data = payload if isinstance(payload, dict) else {}
    checked = response.pick(data, "checked_in")
    return {
        "checked_in": bool(checked) if checked is not None else None,
        "balance": response.pick(data, "balance"),
        "raw": data,
    }


async def _read_balance(ctx: Any, endpoints: dict[str, str], response: ResponseMap) -> float | None:
    path = str(endpoints.get("user") or "").strip()
    if not path:
        return None
    try:
        payload = unwrap_data(ctx.http.get(path))
    except TaskError:
        return None
    return response.to_number(response.pick(payload if isinstance(payload, dict) else {}, "balance"))


async def _confirm(
    ctx: Any,
    endpoints: dict[str, str],
    response: ResponseMap,
    *,
    before: float | None,
    data: dict[str, Any],
) -> tuple[float, Any] | None:
    """数值是否真的增长了；返回 (增量, 当前值) 或 None。"""
    if before is None:
        return None
    after = response.to_number(response.pick(data, "balance"))
    if after is None:
        after = await _read_balance(ctx, endpoints, response)
    if after is None:
        return None
    delta = after - before
    # 浮点余额比较留一点容差，避免把计费抖动当成到账。
    return (delta, after) if delta > 1e-9 else None


def _raw_delta(response: ResponseMap, delta: float) -> float:
    """把「已换算的增量」还原成站点原始单位，好让 detail 与展示走同一套换算。"""
    from core.manifest import QUOTA_UNIT

    return delta * QUOTA_UNIT if response.unit == "quota_500000" else delta


def _display(response: ResponseMap, *, balance: Any = None, awarded: Any = None) -> DisplaySpec:
    text = response.format(balance) if balance is not None else ""
    extras = (("获得", response.format(awarded)),) if response.has_amount(awarded) else ()
    return DisplaySpec(text=text, extras=extras)


def _state_data(state: dict[str, Any]) -> dict[str, Any]:
    return {"source": "http_api", **{k: v for k, v in state.items() if k != "raw" and v is not None}}


def _submit_body(ctx: Any, manifest: Any) -> dict[str, Any] | None:
    """提交体：把任务参数里模板声明过的字段带上（如每日口令）。"""
    declared = {spec.name for spec in manifest.args}
    body = {
        name: value
        for name, value in (ctx.args or {}).items()
        if name in declared and value not in (None, "")
    }
    return body or None
