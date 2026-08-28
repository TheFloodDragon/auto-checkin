"""内置模板：Sub2API 系站点。

端点方言、判据与「无正面证据不谎报成功」的规则从 ``providers/profiles/
sub2api_protocol.py`` 原样迁移。形态上的两处改进：

- 端点探测结论进覆盖层的 ``flow`` 段（``ctx.store``），下次直接命中，不再每轮从
  第一个候选开始试；
- 额度由本模板的 ``render()`` 写进自定义文本列，框架层不再认识「额度」这个概念。
"""

from __future__ import annotations

import math
from typing import Any

from ...core.errors import TaskError
from ...core.manifest import (
    ArgSchema,
    ArgSpec,
    DetectSpec,
    DisplayDefaults,
    LoginOption,
    TaskOption,
    TemplateManifest,
)
from ...core.outcome import DisplaySpec, Outcome, Verdict, already_done, failed, no_effect, success
from ...net import guard
from ...net.http import unwrap_data

API_PREFIX = "/api/v1"

#: 各 fork 的签到端点不统一，按顺序探测；命中的会被记进覆盖层复用。
#: 每项为 (签到 POST 路径, 状态 GET 路径)；状态路径为 None 表示该 fork 无状态接口。
CHECKIN_ENDPOINTS: tuple[tuple[str, str | None], ...] = (
    ("/check-in", "/check-in/status"),
    ("/play/checkin", "/play/checkin/status"),
)

PROFILE_PATHS = ("/user/profile", "/auth/me")

LOGIN_PATTERNS = ("unauthorized", "登录", "token", "expired", "invalid", "forbidden", "无效", "过期")
# 在通用词表上追加「验证 / verify」：本模板的分类顺序是先判登录再判验证，
# token 失效类消息已被 need_login 拦截，宽泛词在此语境安全（保持既有行为）。
VERIFICATION_PATTERNS = (*guard.VERIFICATION_PATTERNS, "验证", "verify")
ALREADY_DONE_PATTERNS = ("already", "已签到", "今日已", "已领取")
UNSUPPORTED_PATTERNS = (
    "404", "405", "not found", "no route", "route not found",
    "method not allowed", "不存在", "未找到",
)

#: 「今日已签到」在各 fork 里的字段名。
CHECKED_IN_KEYS = (
    "checked_in_today", "checked_in", "today_checked",
    "has_checked_in", "is_checked_in", "checked",
)
BALANCE_KEYS = ("balance", "remaining", "credit", "credits", "quota")

#: 覆盖层里记住「哪个端点可用」的键。
ENDPOINT_LEARNING_KEY = "sub2api_endpoint"

MANIFEST = TemplateManifest(
    id="sub2api",
    title="Sub2API",
    description="Sub2API 系站点（/api/v1/check-in 等，{code,data}，余额已是美元）",
    detect=DetectSpec(
        paths=(f"{API_PREFIX}/auth/me", f"{API_PREFIX}/check-in/status"),
        json_keys=("balance", "current_streak"),
    ),
    login=(
        LoginOption("access_token", priority=10, title="Access Token"),
        LoginOption("refresh", priority=20, title="Refresh Token 续期"),
        LoginOption(
            "password",
            priority=30,
            title="账密登录",
            args=ArgSchema(
                (
                    ArgSpec("email", env="", title="账号邮箱"),
                    ArgSpec("password", secret=True, title="密码"),
                )
            ),
        ),
        LoginOption("browser_state", priority=40, requires=frozenset({"browser"}), title="浏览器登录态"),
        LoginOption("oauth", priority=50, requires=frozenset({"browser"}), title="OAuth 登录态"),
    ),
    task=(
        TaskOption("http_api", priority=10, title="接口签到"),
        TaskOption(
            "browser_flow",
            priority=20,
            requires=frozenset({"browser"}),
            owns=frozenset({"detect", "confirm"}),
            title="浏览器签到",
        ),
    ),
    display=DisplayDefaults(text_label="额度"),
    endpoints={
        "prefix": API_PREFIX,
        # 登录方式插件按名字取端点；写在这里而不是让插件写死默认值，
        # 私改站点只要覆盖这几行就能复用整套登录链路。
        "login": f"{API_PREFIX}/auth/login",
        "refresh": f"{API_PREFIX}/auth/refresh",
        "user": f"{API_PREFIX}/user/profile",
    },
)


def to_usd(value: Any) -> float | None:
    """Sub2API 的余额本身就是美元，只做数值与有限性校验。"""
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def format_usd(value: Any) -> str:
    usd = to_usd(value)
    if usd is None:
        return ""
    return f"${usd:.2f}" if abs(usd) >= 0.01 else f"${usd:.4f}"


def has_awarded(value: Any) -> bool:
    usd = to_usd(value)
    return usd is not None and abs(usd) > 0


# ── 钩子 ────────────────────────────────────────────────────────────────────
async def fetch_state(ctx: Any) -> dict[str, Any]:
    endpoint = _resolve_endpoint(ctx)
    state: dict[str, Any] = {"endpoint": endpoint[0]}
    if endpoint[1]:
        try:
            data = unwrap_data(ctx.http.get(f"{API_PREFIX}{endpoint[1]}")) or {}
        except TaskError as exc:
            state["state_error"] = _classify(exc)
            return state
        state["checked_in_today"] = _checked_in(data)
        state["balance"] = _first(data, BALANCE_KEYS)
        state["raw"] = data
    return state


async def run(ctx: Any) -> Outcome:
    state = await fetch_state(ctx)
    if state.get("checked_in_today"):
        return already_done("今日已签到。", data={"source": "http_api", **_balance_data(state)}).with_display(
            _display(state.get("balance"))
        )

    last_error: TaskError | None = None
    for checkin_path, status_path in _endpoint_candidates(ctx):
        try:
            payload = ctx.http.request("POST", f"{API_PREFIX}{checkin_path}", json_body={})
        except TaskError as exc:
            if _unsupported(exc):
                # 这个 fork 没有该端点，继续试下一个；不算失败。
                ctx.log(f"端点 {checkin_path} 不可用（{exc.message}），尝试下一个候选")
                last_error = exc
                continue
            return _outcome_from_error(exc)
        _remember_endpoint(ctx, checkin_path, status_path)
        return _outcome_from_reward(unwrap_data(payload))

    if last_error is not None:
        return no_effect(
            "站点未提供任何已知的 Sub2API 签到端点，可能未开放该功能或使用了未收录的私改路径。",
            reason="not_applicable",
            data={"tried": [path for path, _ in CHECKIN_ENDPOINTS]},
        )
    return failed("未能确定签到端点", reason="unconfirmed")


def render(outcome: Outcome) -> DisplaySpec:
    current = _first(outcome.data, ("current_quota", *BALANCE_KEYS))
    text = format_usd(current)
    extras: tuple[tuple[str, str], ...] = ()
    awarded = outcome.data.get("quota_awarded")
    if outcome.verdict is Verdict.SUCCESS and has_awarded(awarded):
        extras = (("获得", format_usd(awarded)),)
    for key, label in (("consecutive_days", "连续天数"), ("total_checkins", "累计签到")):
        value = outcome.data.get(key)
        if value not in (None, ""):
            extras += ((label, str(value)),)
    return DisplaySpec(text=text, text_label="额度" if text else "", extras=extras)


# ── 内部 ────────────────────────────────────────────────────────────────────
def _endpoint_candidates(ctx: Any) -> tuple[tuple[str, str | None], ...]:
    """把上次命中的端点排到最前，其余保留为兜底。"""
    learned = ctx.store.get(ENDPOINT_LEARNING_KEY) if hasattr(ctx, "store") else None
    if not isinstance(learned, dict):
        return CHECKIN_ENDPOINTS
    path = str(learned.get("checkin") or "")
    if not path:
        return CHECKIN_ENDPOINTS
    rest = tuple(item for item in CHECKIN_ENDPOINTS if item[0] != path)
    return ((path, learned.get("status")),) + rest


def _resolve_endpoint(ctx: Any) -> tuple[str, str | None]:
    return _endpoint_candidates(ctx)[0]


def _remember_endpoint(ctx: Any, checkin: str, status: str | None) -> None:
    if hasattr(ctx, "store"):
        ctx.store.put(ENDPOINT_LEARNING_KEY, {"checkin": checkin, "status": status})


def _checked_in(data: Any) -> bool | None:
    if not isinstance(data, dict):
        return None
    for key in CHECKED_IN_KEYS:
        if key in data and data[key] is not None:
            return bool(data[key])
    return None


def _first(data: Any, keys: tuple[str, ...]) -> Any:
    if not isinstance(data, dict):
        return None
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return None


def _balance_data(state: dict[str, Any]) -> dict[str, Any]:
    balance = state.get("balance")
    return {"current_quota": balance} if balance is not None else {}


def _display(balance: Any) -> DisplaySpec:
    text = format_usd(balance)
    return DisplaySpec(text=text, text_label="额度" if text else "")


def _outcome_from_reward(data: Any) -> Outcome:
    """把签到响应解析为结论。无正面证据时不报成功。

    曾出现的误报链条：某些 fork 对未生效的签到请求也回 HTTP 200 且 body 里没有
    任何奖励字段（``{}`` 或 ``{"data":null}``），旧实现当成空成功，最终「显示签到
    成功但额度没到账」。因此这里要求至少命中一项可信信号。
    """
    if not isinstance(data, dict):
        return failed(
            "签到接口返回了无法解析的响应，未能确认签到是否成立。",
            reason="unconfirmed",
            data={"source": "http_api", "raw": str(data)[:300]},
        )

    reward = data.get("reward_amount")
    if reward is None:
        reward = data.get("today_reward")
    balance = data.get("balance")
    detail: dict[str, Any] = {"source": "http_api"}
    if reward is not None:
        detail["quota_awarded"] = reward
    if balance is not None:
        detail["current_quota"] = balance
    if data.get("total_reward") is not None:
        detail["total_reward"] = data["total_reward"]
    if data.get("current_streak") is not None:
        detail["consecutive_days"] = data["current_streak"]
    if data.get("total_check_in_days") is not None:
        detail["total_checkins"] = data["total_check_in_days"]

    if data.get("already_checked_in"):
        return already_done("今日已签到。", data=detail).with_display(_display(balance))

    confirmed = (
        reward is not None
        or balance is not None
        or data.get("current_streak") is not None
        or data.get("total_check_in_days") is not None
        or bool(_checked_in(data))
        or data.get("success") is True
        or bool(data.get("checkin_date") or data.get("checked_at") or data.get("check_in_at"))
    )
    if not confirmed:
        return failed(
            "签到接口返回成功但响应里没有任何签到成立的证据（无奖励、无余额、无连续天数）；"
            "为避免误报，未判定为成功。",
            reason="unconfirmed",
            data=detail,
        )
    message = f"签到成功，获得额度：{format_usd(reward)}" if has_awarded(reward) else "签到成功。"
    return success(message, data=detail).with_display(
        _display(balance).merge(
            DisplaySpec(extras=(("获得", format_usd(reward)),) if has_awarded(reward) else ())
        )
    )


def _unsupported(exc: TaskError) -> bool:
    """该错误是否表示「这个 fork 没有这个端点」（可继续试下一个）。"""
    return (
        exc.status in {404, 405}
        or guard.contains_any(exc.message, UNSUPPORTED_PATTERNS)
        or guard.contains_any(str(exc.payload), UNSUPPORTED_PATTERNS)
    )


def _classify(exc: TaskError) -> str:
    """分类顺序沿用旧实现：未开放 → 已完成 → 登录 → 验证。

    「未开放」必须先于宽泛的登录词表：否则「未开启签到」会被 LOGIN_PATTERNS 里的
    「无效/过期」误伤，把站点没开门报成登录失效。
    """
    if isinstance(exc, TaskError) and exc.reason in {"not_open", "need_config"}:
        return exc.reason
    if guard.not_open_hint(exc.message):
        return "not_open"
    if guard.contains_any(exc.message, ALREADY_DONE_PATTERNS):
        return "already_done"
    if (
        exc.status == 401
        or guard.contains_any(exc.message, LOGIN_PATTERNS)
        or guard.contains_any(str(exc.payload), ("unauthorized",))
    ):
        return "need_login"
    if guard.contains_any(exc.message, VERIFICATION_PATTERNS):
        return "need_verification"
    return "error"


def _outcome_from_error(exc: TaskError) -> Outcome:
    kind = _classify(exc)
    if kind == "already_done":
        return already_done(exc.message or "今日已签到。", data={"source": "http_api"})
    if kind == "not_open":
        return no_effect(exc.message, reason="not_open")
    if kind in {"need_login", "need_verification", "need_config"}:
        return failed(exc.message, reason=kind)
    return exc.to_outcome()
