"""内置模板：New API 系站点。

与旧 ``providers/profiles/newapi.py`` 的关系：接口路径、响应结构、额度换算、
「已签到 / 未开放 / 需验证」的判据全部照搬——那些是实测出来的事实，不该在重构中被
重新发明。变化只在**形态**：

- 从 ``SiteProfile`` + ``ProfileClient`` 两个类，变成一个声明式 ``MANIFEST`` 加几个
  纯函数钩子；
- 验证机制（Turnstile / 三种验证码）从「用户要手工填脚本路径」变成模板自带能力，
  由 ``flow.verification`` 控制（见 ``newapi_verify``）；
- 额度不再是框架的一等字段，而是由本模板的 ``render()`` 写进 ``DisplaySpec.text``
  （``text_label="额度"``）——这正是「自定义文本」的样板。
"""

from __future__ import annotations

import math
import os
import subprocess
from typing import Any

from core.errors import ConfigError, TaskError, TransientError
from core.manifest import (
    ArgSchema,
    ArgSpec,
    DetectSpec,
    DisplayDefaults,
    LoginOption,
    ResponseMap,
    TaskOption,
    TemplateManifest,
)
from core.outcome import (
    DisplaySpec,
    Outcome,
    Verdict,
    already_done,
    failed,
    no_effect,
    success,
)
from net import guard
from net.http import extract_message, unwrap_data
from . import newapi_verify as verify

#: New API 内部 quota 与美元的换算系数。
QUOTA_UNIT = 500_000

STATUS_PATH = "/api/status"
CHECKIN_PATH = "/api/user/checkin"
USER_PATH = "/api/user/self"

ALREADY_DONE_PATTERNS = ("已签到", "今日已", "已领取", "明天再来", "already")
LOGIN_PATTERNS = (
    "登录", "unauthorized", "token", "not logged in", "access token", "未登录", "无权", "权限不足",
)
#: 服务端说「你得先过验证」时的回执特征。命中说明公开配置漏报了验证方式。
CAPTCHA_REQUIRED_PATTERNS = ("请输入验证码", "captcha is required", "验证码不能为空")
TURNSTILE_MISSING_PATTERNS = ("turnstile token 为空", "turnstile token is empty", "turnstile 校验失败")
#: 站点提示「签到流程已升级」→ 该走 challenge（WASM PoW）变体。
UPGRADED_FLOW_PATTERNS = ("checkin_flow_upgraded", "新版流程", "签到接口已升级")
CHALLENGE_UNSUPPORTED_PATTERNS = ("404", "not found", "page not found", "no route", "unsupported")
CHALLENGE_NETWORK_PATTERNS = ("fetch failed", "econnreset", "etimedout", "socket hang up")

MANIFEST = TemplateManifest(
    id="newapi",
    title="New API",
    description="New API 系站点（/api/user/checkin、/api/user/self，{success,data}，内部 quota）",
    detect=DetectSpec(
        paths=(STATUS_PATH,),
        json_keys=("turnstile_check", "system_name", "quota_per_unit"),
        markers=("new-api", "new api"),
    ),
    login=(
        LoginOption("access_token", priority=10, title="Access Token"),
        LoginOption("cookie", priority=20, title="Cookie"),
        LoginOption("oauth", priority=40, requires=frozenset({"browser"}), title="OAuth 登录态"),
        LoginOption("browser_state", priority=50, requires=frozenset({"browser"}), title="浏览器登录态"),
    ),
    task=(
        TaskOption(
            "http_api",
            priority=10,
            title="接口签到",
            args=ArgSchema(
                (
                    ArgSpec(
                        "variant",
                        default="legacy",
                        choices=("legacy", "challenge"),
                        title="接口变体",
                        help="legacy=旧接口优先（默认）；challenge=WASM PoW 优先，需要 Node.js",
                    ),
                    ArgSpec(
                        "checkin_code",
                        title="今日签到口令",
                        help="站点站外发布、当日有效的口令；仅 code_required 站点需要",
                    ),
                )
            ),
        ),
        TaskOption("relogin", priority=30, requires=frozenset({"browser"}), title="OAuth 重登发放"),
        TaskOption("visit", priority=40, title="访问保活"),
    ),
    display=DisplayDefaults(text_label="额度"),
    endpoints={
        "status": STATUS_PATH,
        "state": CHECKIN_PATH,
        "submit": CHECKIN_PATH,
        "user": USER_PATH,
        "login": "/api/user/login",
    },
    # New API 用 New-Api-User 头标��用户；写死在客户端类里意味着换个站点族就要改内核。
    headers={"New-Api-User": "{user_id}", "Referer": "{base_url}{referer_path}"},
    response=ResponseMap(
        checked_in=("stats.checked_in_today", "checked_in_today"),
        awarded=("quota_awarded", "awarded_quota", "award_quota", "reward_quota"),
        balance=("quota", "remain_quota", "balance"),
        streak=("consecutive_days", "continuous_days"),
        total=("total_checkins", "checkin_count", "checked_days"),
        unit="quota_500000",
    ),
)


# ── 额度 ────────────────────────────────────────────────────────────────────
def quota_to_usd(value: Any) -> float | None:
    """内部 quota → 美元。非数字（含 bool）或非有限值返回 None。

    NaN / Infinity 必须挡在这里：json 会把它们写成裸 NaN（非标准 JSON），且 NaN 参与
    任何比较都为 False，会让「额度是否增长」的交叉验证静默失效。
    """
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return number / QUOTA_UNIT


def format_usd(value: Any) -> str:
    usd = quota_to_usd(value)
    if usd is None:
        return ""
    return f"${usd:.2f}" if abs(usd) >= 0.01 else f"${usd:.4f}"


def has_awarded(value: Any) -> bool:
    """本次是否有「值得展示的获得额度」。

    0 一律视为「没有金额信息」而不是「获得 $0」：站点签到成功但不带具体金额时常回 0，
    展示成「获得额度：$0.0000」既不是事实，也让用户以为签到出了问题。
    """
    usd = quota_to_usd(value)
    return usd is not None and abs(usd) > 0


# ── 钩子 ────────────────────────────────────────────────────────────────────
async def fetch_state(ctx: Any) -> dict[str, Any]:
    """读取「今日是否已完成 + 是否要口令 + 是否要验证码」。"""
    state: dict[str, Any] = {}
    try:
        data = unwrap_data(ctx.http.get(CHECKIN_PATH)) or {}
    except TaskError as exc:
        # 状态接口失败不致命：分类后交给 run() 决定是否继续尝试签到。
        state["state_error"] = classify(exc)
        state["error"] = exc
        return state
    if not isinstance(data, dict):
        return state
    stats = data.get("stats") if isinstance(data.get("stats"), dict) else {}
    checked = None
    for source in (stats, data):
        if isinstance(source, dict) and "checked_in_today" in source:
            checked = bool(source["checked_in_today"])
            break
    state["checked_in_today"] = checked
    state["code_required"] = bool(data.get("code_required"))
    state["captcha_enabled"] = bool(data.get("captcha_enabled"))
    state["raw"] = data
    return state


async def run(ctx: Any) -> Outcome:
    """执行一次接口签到。"""
    state = await fetch_state(ctx)
    if state.get("checked_in_today"):
        return already_done("今日已签到。", data={"source": "http_api"}).with_display(
            _display(await _read_quota(ctx))
        )

    # 每日口令不是验证码：站点只发布在站外，程序拿不到。裸提交必被拒（实测星芽回
    # 「签到验证码不正确」），所以要么用配置的口令，要么直接给出可操作结论。
    if state.get("code_required"):
        code = str(ctx.args.get("checkin_code") or "").strip()
        if not code:
            return failed(
                "本站签到需要「今日签到口令」（站点站外发布、当日有效），程序无法自动获取。"
                "请在该任务的 args.checkin_code 填入今日口令，或关闭/容错该账号。",
                reason="need_config",
            )
        ctx.log("使用配置的今日签到口令提交")
        return await _submit_and_parse(ctx, lambda: verify.submit_checkin(ctx, code=code))

    outcome = await _verified_checkin(ctx, state)
    if outcome is not None:
        return outcome
    return await _submit_and_parse(ctx, lambda: _plain_checkin(ctx))


async def confirm(ctx: Any, outcome: Outcome) -> Outcome:
    """交叉验证「接口回了 200 但没有任何证据」的情况。

    实测存在站点静默拒绝、或配置的端点并非签到接口的情况，直接报成功会出现
    「显示成功但额度没到账」。这里用签到前后余额差与状态回读做证据。
    """
    before = outcome.data.get("quota_before")
    after = await _read_quota(ctx)
    if isinstance(before, (int, float)) and isinstance(after, (int, float)) and after - before > 1e-9:
        delta = after - before
        return success(
            f"签到成功，获得额度：{format_usd(delta * QUOTA_UNIT)}",
            data={**dict(outcome.data), "quota_awarded": delta * QUOTA_UNIT, "quota": after * QUOTA_UNIT},
        ).with_display(_display(after, awarded=delta * QUOTA_UNIT))
    state = await fetch_state(ctx)
    if state.get("checked_in_today"):
        return success("签到成功（站点已标记今日已签到）。", data=dict(outcome.data)).with_display(
            _display(after)
        )
    return outcome


def render(outcome: Outcome) -> DisplaySpec:
    """把结论里的额度渲染成自定义文本列。"""
    current = _first(outcome.data, ("current_quota", "quota", "remain_quota", "balance"))
    text = format_usd(current)
    extras: tuple[tuple[str, str], ...] = ()
    awarded = outcome.data.get("quota_awarded")
    if outcome.verdict is Verdict.SUCCESS and has_awarded(awarded):
        extras = (("获得", format_usd(awarded)),)
    for key, label in (
        ("consecutive_days", "连续天数"),
        ("total_checkins", "累计签到"),
        ("captcha_dialect", "验证码"),
    ):
        value = outcome.data.get(key)
        if value not in (None, ""):
            extras += ((label, str(value)),)
    return DisplaySpec(text=text, text_label="额度" if text else "", extras=extras)


# ── 签到实现 ────────────────────────────────────────────────────────────────
async def _verified_checkin(ctx: Any, state: dict[str, Any]) -> Outcome | None:
    """需要人机验证时走验证机制路由；不需要则返回 None。"""
    if not ctx.flow.enabled("verification"):
        return None
    options = _status_options(ctx)
    preferred = ctx.flow.get("verification").primary
    modes = verify.detect_modes(options, state)
    order = [preferred] if preferred and preferred not in ("auto", "") else []
    order.extend(mode for mode in modes if mode not in order)
    ctx.log(f"验证路由：preferred={preferred or 'auto'}，auto_detected={modes or ['none']}，order={order or ['default']}")
    if not order:
        return None

    for mode in order:
        try:
            data = await verify.run_mechanism(ctx, mode, options)
        except TaskError as exc:
            if verify.not_applicable(exc):
                ctx.log(f"验证机制 {mode} 不适用（{exc.message}），继续自动分流")
                continue
            return _outcome_from_error(exc)
        if data is not None:
            return _reward_outcome(ctx, data)
        ctx.log(f"验证机制 {mode} 未声明适用，继续自动分流")
    return None


def _plain_checkin(ctx: Any) -> Any:
    """不带验证的签到，按 variant 选择接口变体，两者互为兜底。"""
    variant = str(ctx.args.get("variant") or "legacy").strip().lower()
    ctx.log(f"开始接口签到（variant={variant}）")
    if variant == "challenge":
        return _challenge_with_fallback(ctx)
    return _legacy_with_fallback(ctx)


def _legacy_with_fallback(ctx: Any) -> Any:
    try:
        return verify.submit_checkin(ctx)
    except TaskError as exc:
        if guard.contains_any(f"{exc.message} {exc.payload}", UPGRADED_FLOW_PATTERNS):
            ctx.log("站点提示签到流程已升级，改走 challenge 变体")
            return _challenge_checkin(ctx)
        raise


def _challenge_with_fallback(ctx: Any) -> Any:
    try:
        return _challenge_checkin(ctx)
    except TaskError as exc:
        text = f"{exc.message} {exc.payload}"
        # Node challenge 用独立的 fetch/TLS 指纹，可能被 WAF 单独挑战，而同站 legacy
        # 仍可由 Python 客户端访问；辅助脚本连不上站点时也值得回落——那只说明「新版端点
        # 这次没探到」，legacy 仍值得一试。
        if (
            exc.status in {404, 405}
            or guard.contains_any(text, CHALLENGE_UNSUPPORTED_PATTERNS)
            or guard.contains_any(text, CHALLENGE_NETWORK_PATTERNS)
            or guard.guard_kind(str(exc.payload)) is not guard.GuardKind.NONE
        ):
            ctx.log(f"challenge 变体不可用（{exc.message}），回落 legacy 接口")
            return verify.submit_checkin(ctx)
        raise


def _challenge_checkin(ctx: Any) -> Any:
    """新版 WASM PoW 签到：交给仓库内的 Node 辅助脚本执行。"""
    from config import paths

    helper = paths.REPO_ROOT / "checkin_challenge.js"
    if not helper.exists():
        raise ConfigError(f"缺少新版签到辅助脚本：{helper}")
    if "node" not in ctx.capabilities:
        raise ConfigError(
            "challenge 变体需要 Node.js（执行 WASM PoW）。请安装 Node.js 并确保在 PATH 中，"
            "或把该任务的 args.variant 设为 legacy。"
        )
    from config.settings import Timeouts

    headers = dict(ctx.http.headers)
    env = os.environ.copy()
    env.update(
        {
            "NEWAPI_BASE_URL": ctx.account.base_url,
            "NEWAPI_COOKIE": headers.get("Cookie", ""),
            "NEWAPI_ACCESS_TOKEN": headers.get("Authorization", "").removeprefix("Bearer ").strip(),
            "NEWAPI_USER_ID": headers.get("New-Api-User", ""),
            "NEWAPI_REFERER": headers.get("Referer", ctx.account.base_url + "/"),
            "NEWAPI_USER_AGENT": ctx.http.config.user_agent,
        }
    )
    try:
        completed = subprocess.run(
            ["node", str(helper)],
            cwd=str(paths.REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=Timeouts.NODE_CHALLENGE,
        )
    except FileNotFoundError as exc:
        raise ConfigError(
            "未找到 Node.js（challenge 新版签到需要 node 执行 WASM PoW）。"
            "请安装 Node.js 并确保在 PATH 中，或把 args.variant 设为 legacy。"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise TransientError(
            f"新版签到辅助脚本执行超时（>{Timeouts.NODE_CHALLENGE}s），"
            "可能是 PoW 难度过高或网络异常，请稍后重试。"
        ) from exc

    output = (completed.stdout or completed.stderr or "").strip()
    # Node 辅助脚本的原始输出必须落日志：整段跑在子进程里，不打出来的话
    # 「PoW 失败」「WASM 拉取失败」「站点回执」三种情况在上层都只是一句签到失败。
    ctx.log(f"challenge 辅助脚本 rc={completed.returncode} → {output[:600] or '（无输出）'}")
    import json

    try:
        payload = json.loads(output) if output else None
    except json.JSONDecodeError as exc:
        raise TaskError(f"新版签到辅助脚本返回非 JSON：{output[:300]}", payload=output[:300]) from exc
    if completed.returncode != 0 or (isinstance(payload, dict) and payload.get("success") is False):
        raise TaskError(extract_message(payload), payload=payload)
    return unwrap_data(payload)


async def _submit_and_parse(ctx: Any, submit: Any) -> Outcome:
    quota_before = await _read_quota(ctx)
    try:
        data = submit()
    except TaskError as exc:
        return _outcome_from_error(exc)
    outcome = _reward_outcome(ctx, data)
    if outcome.reason == "unconfirmed" and quota_before is not None:
        outcome = outcome.with_data(quota_before=quota_before)
    return outcome


def _reward_outcome(ctx: Any, data: Any) -> Outcome:
    detail: dict[str, Any] = {"source": "http_api"}
    if isinstance(data, dict):
        detail.update(data)
    awarded = _first(detail, ("quota_awarded", "awarded_quota", "award_quota", "reward_quota"))
    current = _first(detail, ("quota", "current_quota", "remain_quota", "balance"))
    if awarded is not None:
        detail["quota_awarded"] = awarded

    if isinstance(data, dict) and (data.get("checked_in_today") or data.get("already_checked_in")):
        return already_done("今日已签到。", data=detail).with_display(_display_raw(current))
    if has_awarded(awarded):
        return success(f"签到成功，获得额度：{format_usd(awarded)}", data=detail).with_display(
            _display_raw(current, awarded=awarded)
        )
    if awarded is not None or _first(detail, ("consecutive_days", "total_checkins")) is not None:
        return success("签到成功（站点未返回本次获得额度）。", data=detail).with_display(
            _display_raw(current)
        )
    # 没有任何正面证据：交给 confirm 阶段用余额差与状态回读交叉验证。
    return failed(
        "签到接口返回成功但未发放额度，站点也未标记今日已签到；"
        "该站点可能需要在网页手动签到，或签到接口已变更。",
        reason="unconfirmed",
        data=detail,
    )


# ── 分类与展示 ──────────────────────────────────────────────────────────────
def classify(exc: TaskError) -> str:
    """把异常归类。

    顺序是实测出来的，不能改：
    1. 未开放先于一切——服务端说没开门时，重试与浏览器兜底都不会改变结果；
    2. 已签到先于登录——「已领取」这类回执常带非零业务码，会被登录词表的「token」误伤；
    3. HTTP 401 是明确未授权，优先归 need_login；
    4. 验证特征先于登录词表——「Turnstile token 为空」含 "token"，否则会被误判为登录失效。
    """
    text = f"{exc.message} {exc.payload}"
    if exc.reason in {"not_open", "need_config"}:
        return exc.reason
    if guard.not_open_hint(text):
        return "not_open"
    if guard.contains_any(text, ALREADY_DONE_PATTERNS):
        return "already_done"
    if exc.status == 401:
        return "need_login"
    if guard.looks_like_verification(text) or guard.contains_any(
        text, (*CAPTCHA_REQUIRED_PATTERNS, *TURNSTILE_MISSING_PATTERNS)
    ):
        return "need_verification"
    if guard.contains_any(text, LOGIN_PATTERNS):
        return "need_login"
    return exc.reason or ""


def _outcome_from_error(exc: TaskError) -> Outcome:
    kind = classify(exc)
    message = exc.message or extract_message(exc.payload)
    if kind == "already_done":
        return already_done(message or "今日已签到。", data={"source": "http_api"})
    if kind == "not_open":
        return no_effect(message, reason="not_open")
    if kind == "need_verification":
        # 走到这里说明公开配置漏报了验证方式：给出可操作的机制列表，而不是一句「需验证」。
        hint = (
            "；可在该账号的 flow.verification 指定机制（turnstile / bitmap_code / "
            "string_captcha / click_shape），不确定时保留 auto"
        )
        return failed(message + hint, reason="need_verification", data={"source": "http_api"})
    if kind in {"need_login", "need_config"}:
        return failed(message, reason=kind)
    return exc.to_outcome()


async def _read_quota(ctx: Any) -> float | None:
    """读当前余额（美元）；失败返回 None。"""
    try:
        data = unwrap_data(ctx.http.get(USER_PATH)) or {}
    except TaskError:
        return None
    return quota_to_usd(_first(data, ("quota", "balance", "remain_quota")))


def _display(usd: float | None, *, awarded: Any = None) -> DisplaySpec:
    text = f"${usd:.2f}" if isinstance(usd, float) else ""
    extras = (("获得", format_usd(awarded)),) if has_awarded(awarded) else ()
    return DisplaySpec(text=text, text_label="额度" if text else "", extras=extras)


def _display_raw(current: Any, *, awarded: Any = None) -> DisplaySpec:
    return _display(quota_to_usd(current), awarded=awarded)


def _status_options(ctx: Any) -> dict[str, Any]:
    """读 ``/api/status`` 的公开配置（不需要登录态）。"""
    try:
        data = unwrap_data(ctx.http.get(STATUS_PATH))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _first(data: Any, keys: tuple[str, ...]) -> Any:
    if not isinstance(data, dict):
        return None
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return None
