#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""站点模板：SOTA Model（sotamodel.net）每日签到。

该站是 New API 派生站，但标准签到接口被关闭（``GET /api/user/checkin`` 固定回
「签到功能未启用」），签到被搬到 ``/agents`` 页面的独立端点：

- ``GET  /api/user/sota-agent-checkin`` → ``{checked_in_today, reward_credits, reward_quota}``
- ``POST /api/user/sota-agent-checkin`` → ``{reward_credits, quota_awarded, current_quota}``

因此本模板继承 ``newapi``（复用它的登录方式、请求头与额度换算），但用自己的
``run()`` 接管执行——通用探测去请求那个被关闭的端点，只会制造「签到功能未启用」的
噪声失败。

奖励金额由后台按星期配置（``checkin_setting.sota_agent_{monday..sunday}_credits``），
每天可不同，模板只如实上报服务端返回值。
"""

from __future__ import annotations

from typing import Any

from core.errors import TaskError, TransientError
from sdk import (
    DisplaySpec,
    Outcome,
    TaskOption,
    TemplateManifest,
    already_done,
    need_verification,
    success,
)
from templates.builtin.newapi import QUOTA_UNIT, format_usd, quota_to_usd

SITE_LABEL = "SOTA Model"
CHECKIN_ROUTE = "/api/user/sota-agent-checkin"
USER_ROUTE = "/api/user/self"
#: 站点当前 turnstile_check=false，但接口保留该校验；被要求人机验证时按需验证归类，
#: 不能当成签到失败或谎报成功。
TURNSTILE_MARKERS = ("turnstile", "人机验证")
ALREADY_MARKERS = ("already", "已签到", "今日已", "重复签到")

MANIFEST = TemplateManifest(
    id="sotamodel",
    title="SOTA Model",
    extends="newapi",
    description="New API 派生站，签到搬到 /api/user/sota-agent-checkin",
    task=(
        TaskOption(
            "http_api",
            priority=10,
            title="Agent 签到",
            # 状态查询、签到与结果确认全部由本模板完成；不要再探测被关闭的标准端点。
            owns=frozenset({"detect", "confirm"}),
        ),
    ),
)


async def run(ctx: Any) -> Outcome:
    """执行 SOTA Model 的 agent 每日签到。"""
    ctx.log(f"读取 {SITE_LABEL} agent 签到状态（{CHECKIN_ROUTE}）")
    try:
        status = _data(ctx.http.get(CHECKIN_ROUTE))
    except TaskError as exc:
        if _contains(exc, TURNSTILE_MARKERS):
            return _turnstile_outcome(exc)
        raise

    if status.get("checked_in_today") is True:
        return _outcome(ctx, status, already=True, signal="sota_agent_status")

    ctx.log("今日尚未签到，调用 agent 签到接口")
    try:
        # 不做非幂等自动重试：重复 POST 在服务端是一次真实的签到写入。
        action = _data(ctx.http.request("POST", CHECKIN_ROUTE, json_body={}))
    except TaskError as exc:
        if _contains(exc, TURNSTILE_MARKERS):
            return _turnstile_outcome(exc)
        # POST 结果不确定（网络中断 / 5xx / 重复提交）时先回读状态：服务端已记账就
        # 按已签到返回，避免把已经成功的签到报成失败。
        after = _safe_status(ctx)
        if after.get("checked_in_today") is True or _contains(exc, ALREADY_MARKERS):
            return _outcome(ctx, after or status, already=True, signal="sota_agent_status_after_post")
        raise

    if _awarded_quota(action) is None:
        # 响应里没有任何金额证据时不谎报成功：回读状态确认服务端是否真的记账。
        after = _safe_status(ctx)
        if after.get("checked_in_today") is not True:
            raise TransientError(
                f"{SITE_LABEL} 签到接口返回成功，但未给出奖励额度且状态接口未确认已签到",
                payload={"action": action, "status": after},
            )
        return _outcome(ctx, after, already=True, signal="sota_agent_status_after_post")

    return _outcome(ctx, action, already=False, signal="sota_agent_checkin_response")


# ── 结论组装 ────────────────────────────────────────────────────────────────
def _outcome(ctx: Any, data: dict[str, Any], *, already: bool, signal: str) -> Outcome:
    message = _message(data, already=already)
    payload: dict[str, Any] = {
        "checked_in_today": True,
        "completion_signal": signal,
        "checkin_route": CHECKIN_ROUTE,
    }
    credits = _number(data.get("reward_credits"))
    if credits is not None:
        # 已签到时不写 quota_awarded：那会让汇总把「今日这一档的奖励」当成本次到账。
        payload["today_reward_credits" if already else "reward_credits"] = credits
    awarded = None if already else _awarded_quota(data)
    if awarded is not None:
        payload["quota_awarded"] = awarded
    current = _current_quota(ctx, data)
    if current is not None:
        payload["quota"] = current

    factory = already_done if already else success
    outcome = factory(message, data=payload)
    text = format_usd(current) if current is not None else ""
    extras: tuple[tuple[str, str], ...] = ()
    amount = _amount_text(data)
    if amount:
        extras = ((("今日奖励" if already else "获得"), amount),)
    ctx.log(message)
    return outcome.with_display(
        DisplaySpec(text=text, text_label="额度" if text else "", extras=extras)
    )


def _message(data: dict[str, Any], *, already: bool) -> str:
    prefix = "今日已签到" if already else "签到成功"
    amount = _amount_text(data)
    if not amount:
        return prefix
    # 已签到时金额是「今日这一档的奖励」，不是本次新到账，措辞需要区分。
    return f"{prefix}，今日奖励 {amount}" if already else f"{prefix}，获得 {amount}"


def _amount_text(data: dict[str, Any]) -> str:
    """奖励金额的美元展示；拿不到数值时返回空串（不编造 $0）。"""
    credits = _number(data.get("reward_credits"))
    if credits is not None and credits != 0:
        return f"${credits:.2f}" if abs(credits) >= 0.01 else f"${credits:.4f}"
    quota = _awarded_quota(data)
    if quota is not None and quota != 0:
        return format_usd(quota)
    return ""


def _awarded_quota(data: dict[str, Any]) -> float | None:
    """本次/今日奖励，统一换算为站点内部 quota 单位。

    展示层按 New API 的内部 quota 换算，因此这里不能混入美元数值：只在站点仅回
    credits（美元）时才乘回 QUOTA_UNIT。
    """
    for key in ("quota_awarded", "reward_quota"):
        value = _number(data.get(key))
        if value is not None:
            return value
    credits = _number(data.get("reward_credits"))
    return credits * QUOTA_UNIT if credits is not None else None


def _current_quota(ctx: Any, data: dict[str, Any]) -> Any:
    """当前余额（站点内部 quota）。

    签到响应自带 current_quota 时直接用；否则读站点原生 ``/api/user/self``——那是
    该站仍然启用的标准端点，与被关闭的签到端点无关。读取失败按未知处理。
    """
    value = data.get("current_quota")
    if value is not None:
        return value
    try:
        return _data(ctx.http.get(USER_ROUTE)).get("quota")
    except Exception:  # noqa: BLE001 - 余额只是补充信息，不能影响签到结论
        return None


def _safe_status(ctx: Any) -> dict[str, Any]:
    try:
        return _data(ctx.http.get(CHECKIN_ROUTE))
    except TaskError:
        return {}


def _turnstile_outcome(exc: TaskError) -> Outcome:
    return need_verification(
        f"{SITE_LABEL} 签到要求 Cloudflare Turnstile 人机验证（服务端回执：{exc.message}）。"
        "纯 HTTP 无法自动完成，请在网页手动签到，或为该账号配置浏览器登录方式。",
        payload=exc.payload,
    )


def _contains(exc: TaskError, markers: tuple[str, ...]) -> bool:
    payload = exc.payload if isinstance(exc.payload, dict) else {}
    text = " ".join(
        str(value or "") for value in (exc.message, payload.get("message"), payload.get("reason"))
    ).casefold()
    return any(marker in text for marker in markers)


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _data(payload: Any) -> dict[str, Any]:
    from net.http import unwrap_data

    value = unwrap_data(payload)
    return value if isinstance(value, dict) else {}


def render(outcome: Outcome) -> DisplaySpec:
    """余额展示沿用 newapi 的换算（内部 quota → 美元）。"""
    quota = outcome.data.get("quota")
    usd = quota_to_usd(quota)
    return DisplaySpec(text=format_usd(quota) if usd is not None else "", text_label="额度")
