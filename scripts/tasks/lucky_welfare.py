#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lucky 福利站签到模板。

账号的 ``base_url`` 保持 Lucky new-api 主站，签到实际发生在固定的福利站：

* 福利站只使用自己的同源 Cookie 会话，主站 Bearer/Cookie 不会被转发；
* 有已验证福利站 Cookie 时先走福利站原生 API；
* 纯 HTTP 不可用或无法确认时，才复用同一浏览器租约；
* 浏览器中仍先尝试同源 API，最后才在 ``#today-checkin`` 内点击签到按钮。

API、浏览器 API 和按钮点击刻意收敛在一个 ``run()``，避免引擎把回退路径学习成
独立候选而改变固定的 API → 浏览器顺序。
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Mapping
from http.cookiejar import Cookie, CookieJar
from typing import Any
from urllib.parse import urlsplit

from browser import bypass, oauth_flow, oauth_providers, storage_scope
from core.errors import (
    ConfigError,
    LoginRequired,
    NotApplicable,
    TaskError,
    TransientError,
    VerificationRequired,
)
from core.manifest import ArgSchema, ArgSpec, DisplayDefaults, LoginOption, TaskOption, TemplateManifest
from core.masking import mask_secrets, sanitize_data
from core.outcome import DisplaySpec, Outcome
from login.base import LoginState
from net import guard
from net.http import HttpClient, HttpConfig, extract_message, normalize_cookie, unwrap_data
from sdk import (
    already_done,
    failed,
    need_config,
    need_login,
    need_verification,
    no_effect,
    success,
)

SITE_LABEL = "Lucky 福利站"
FULI_ORIGIN = "https://fuli.lucky0625.qzz.io"
MAIN_ORIGIN = "https://new.lucky0625.qzz.io"

SELF_PATH = "/api/user/self"
CHECKIN_PATH = "/api/checkin"
OAUTH_PATH = "/api/oauth/linuxdo"

# 这个标记只用于确认 ctx.http 里的 Cookie 是本模板登录钩子放入的福利站 Cookie。
# 它不是认证凭据，也不会被复制到福利站客户端之外的请求。
SESSION_ORIGIN_HEADER = "X-Dailytask-Session-Origin"

# 页面签到区域的边界必须稳定；不能在整页寻找第一个 button。
CHECKIN_CONTAINER = "#today-checkin"
CHECKIN_BUTTON_SELECTORS = (
    "#today-checkin button:has-text('摘一片四叶草')",
    "#today-checkin button:has-text('签到')",
    "#today-checkin button",
)

_ALLOWED_API_PATHS = frozenset({SELF_PATH, CHECKIN_PATH})
_ALLOWED_BROWSER_PATHS = frozenset((*_ALLOWED_API_PATHS, OAUTH_PATH))
_GRANT_STATUSES = frozenset({"success", "pending", "failed"})
_AUTH_MARKERS = (
    "未登录",
    "请先登录",
    "登录后",
    "unauthorized",
    "authentication",
    "not authenticated",
    "invalid session",
    "session expired",
)
_NOT_OPEN_MARKERS = ("未开放", "暂未开放", "尚未开放", "not open", "disabled")
_TRUE_TEXT = frozenset({"1", "true", "yes", "y", "on", "是", "已"})
_FALSE_TEXT = frozenset({"0", "false", "no", "n", "off", "否", "未"})


MANIFEST = TemplateManifest(
    id="lucky_welfare",
    title="Lucky 福利站",
    description="Lucky new-api 主站账号对应的福利站签到（API 优先，浏览器点击兜底）",
    login=(
        # session_cookie 是福利站自己的 Cookie；不能把主站 access_token 当作福利站凭据。
        LoginOption("cookie", priority=10, title="福利站 Cookie"),
        LoginOption(
            "browser_state",
            priority=20,
            requires=frozenset({"browser"}),
            title="福利站浏览器登录态",
        ),
        LoginOption(
            "oauth",
            priority=30,
            requires=frozenset({"browser"}),
            title="LinuxDO 登录福利站",
        ),
    ),
    task=(
        TaskOption(
            "script",
            priority=10,
            title="福利站签到",
            # run() 固定管理 API → 浏览器 API → 按钮的顺序。
            owns=frozenset({"detect", "confirm"}),
            args=ArgSchema(
                (
                    ArgSpec(
                        "timeout_seconds",
                        kind="int",
                        default=30,
                        minimum=5,
                        maximum=120,
                        title="签到结果确认超时",
                    ),
                )
            ),
        ),
    ),
    display=DisplayDefaults(text_label="签到奖励"),
    endpoints={"self": SELF_PATH, "state": CHECKIN_PATH, "submit": CHECKIN_PATH},
)


class _ApiFallback(Exception):
    """纯 HTTP 不足以完成任务，应进入浏览器回退。"""

    def __init__(self, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.message = str(message)
        self.cause = cause


def _fallback_or_raise(message: str, exc: TaskError) -> None:
    """把可由浏览器补救的 HTTP 错误转成回退信号；封禁则直接终止。"""
    if exc.reason == "blocked":
        raise exc
    raise _ApiFallback(message, cause=exc) from exc


# ── URL / Cookie 隔离 ────────────────────────────────────────────────────────
def _origin(url: str) -> str:
    """只接受福利站 HTTPS origin，拒绝相似域名、HTTP 和非默认端口。"""
    try:
        parsed = urlsplit(str(url or ""))
        port = parsed.port
    except ValueError:
        return ""
    if parsed.scheme.lower() != "https":
        return ""
    if (parsed.hostname or "").casefold() != "fuli.lucky0625.qzz.io":
        return ""
    if port not in (None, 443):
        return ""
    return FULI_ORIGIN


def _target_url(path: str, *, browser: bool = False) -> str:
    """把 allowlist 内的相对路径解析到固定福利站，不接受任务参数改变 host。"""
    text = str(path or "").strip()
    allowed = _ALLOWED_BROWSER_PATHS if browser else _ALLOWED_API_PATHS
    if text not in allowed:
        raise ConfigError(f"{SITE_LABEL}拒绝未允许的路径：{text or '<空>'}")
    return f"{FULI_ORIGIN}{text}"


def _configured_cookie(ctx: Any, *, include_plain: bool = False) -> str:
    """取得已经被配置/覆盖层标记为福利站用途的 Cookie。

    ``session_cookie`` 可以由本模板/浏览器流程确认属于福利站；普通 ``cookie`` 只有
    在当前候选明确是 ``cookie`` 时才作为输入，避免把主站 Cookie 误送到福利站。
    """
    credentials = getattr(ctx, "credentials", None)
    session = normalize_cookie(getattr(credentials, "session_cookie", ""))
    if session:
        return session
    if include_plain:
        return normalize_cookie(getattr(credentials, "cookie", ""))
    account = getattr(ctx, "account", None)
    login = getattr(account, "login", None)
    method = str(getattr(login, "method", "") or "").strip().lower()
    if method == "cookie":
        return normalize_cookie(getattr(credentials, "cookie", ""))
    return ""


def _cookie_jar(cookie: str) -> CookieJar:
    """把福利站 Cookie 放入按域名过滤的 CookieJar。

    不能把福利站 Cookie 放进以主站为 base_url 的 ``ctx.http.headers``：引擎会把登录
    状态头注入主站客户端，后续多任务/续期请求容易串站。CookieJar 由 urllib 按目标
    URL 自动筛选，主站请求不会带福利站 Cookie，福利站专用客户端仍可显式展开它。
    """
    jar = CookieJar()
    host = urlsplit(FULI_ORIGIN).hostname or "fuli.lucky0625.qzz.io"
    for chunk in normalize_cookie(cookie).split(";"):
        name, separator, value = chunk.strip().partition("=")
        name, value = name.strip(), value.strip()
        if not separator or not name:
            continue
        jar.set_cookie(
            Cookie(
                version=0,
                name=name,
                value=value,
                port=None,
                port_specified=False,
                domain=host,
                domain_specified=True,
                domain_initial_dot=False,
                path="/",
                path_specified=True,
                secure=True,
                expires=None,
                discard=True,
                comment=None,
                comment_url=None,
                rest={},
                rfc2109=False,
            )
        )
    return jar


def _cookie_from_jar(jar: Any) -> str:
    if jar is None:
        return ""
    cookies: list[dict[str, Any]] = []
    try:
        for item in jar:
            cookies.append(
                {
                    "name": str(getattr(item, "name", "") or ""),
                    "value": str(getattr(item, "value", "") or ""),
                    "domain": str(getattr(item, "domain", "") or ""),
                    "path": str(getattr(item, "path", "/") or "/"),
                }
            )
    except Exception:
        return ""
    return normalize_cookie(storage_scope.site_cookie_string(cookies, FULI_ORIGIN))


def _ctx_cookie(ctx: Any) -> str:
    """读取福利站 CookieJar；仅兼容旧测试/旧调用的显式来源标记头。"""
    http = getattr(ctx, "http", None)
    jar_cookie = _cookie_from_jar(getattr(http, "cookie_jar", None))
    if jar_cookie:
        return jar_cookie
    headers = getattr(http, "headers", {}) or {}
    if str(headers.get(SESSION_ORIGIN_HEADER, "")).rstrip("/") == FULI_ORIGIN:
        return normalize_cookie(headers.get("Cookie", ""))
    return ""


def _session_headers(_cookie: str = "") -> dict[str, str]:
    """登录状态头不携带福利站认证；认证由 ``LoginState.cookie_jar`` 承载。"""
    return {"Accept": "application/json"}


def _target_client(ctx: Any, cookie: str = "") -> HttpClient:
    """构造独立福利站客户端，只复用网络配置，不复用主站认证头。"""
    source = normalize_cookie(cookie) or _ctx_cookie(ctx)
    source_http = getattr(ctx, "http", None)
    config = getattr(source_http, "config", None)
    if config is None:
        config = HttpConfig.from_settings()
    log = getattr(ctx, "log", None)
    return HttpClient(
        base_url=FULI_ORIGIN,
        config=config,
        headers={
            "Accept": "application/json",
            "Referer": FULI_ORIGIN + "/",
            **({"Cookie": source} if source else {}),
        },
        log=log if callable(log) else None,
        tag=f"{getattr(getattr(ctx, 'account', None), 'name', 'lucky')}:fuli",
    )


# ── 响应与结果 ──────────────────────────────────────────────────────────────
def _as_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _text(value: Any) -> str:
    return " ".join(str(value or "").split())


def _safe_text(value: Any, limit: int = 300) -> str:
    return mask_secrets(_text(value))[:limit]


def _message(payload: Any) -> str:
    return _text(extract_message(payload))


def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = _text(value).casefold()
    if text in _TRUE_TEXT:
        return True
    if text in _FALSE_TEXT:
        return False
    return None


def _looks_guard(value: Any) -> bool:
    if isinstance(value, Mapping):
        value = " ".join(str(item or "") for item in value.values())
    text = str(value or "")
    return guard.looks_like_html(text) or guard.guard_kind(text) is not guard.GuardKind.NONE


def _looks_auth(message: str, *, status: int | None = None, payload: Any = None) -> bool:
    # 403 的 Cloudflare/WAF HTML 是浏览器回退信号，不是登录失效；只有非防护页的
    # 401/403 JSON 才按认证失败处理。
    if status == 401:
        return True
    if status == 403 and not _looks_guard(payload) and not _looks_guard(message):
        return True
    lowered = _text(message).casefold()
    return any(marker.casefold() in lowered for marker in _AUTH_MARKERS)


def _looks_not_open(message: str) -> bool:
    lowered = _text(message).casefold()
    return any(marker.casefold() in lowered for marker in _NOT_OPEN_MARKERS)


def _unwrap_target(payload: Any, *, status: int | None = None) -> Any:
    """解开福利站响应信封并保留业务错误分类。"""
    if isinstance(payload, Mapping):
        success_value = _flag(payload.get("success"))
        code = payload.get("code")
        code_error = code not in (None, 0, "0", "") and success_value is not True
        if success_value is False or code_error:
            message = _message(payload) or "福利站请求被拒绝"
            if _looks_auth(message, status=status, payload=payload):
                raise LoginRequired(message, status=status, payload=dict(payload))
            if _looks_not_open(message):
                raise NotApplicable(message, status=status, payload=dict(payload))
            raise TaskError(message, status=status, payload=dict(payload))
    return unwrap_data(payload)


def _target_request(
    client: HttpClient,
    method: str,
    path: str,
    *,
    body: Mapping[str, Any] | None = None,
) -> Any:
    """发福利站 API 请求；只接受固定的相对路径。"""
    text = str(path or "").strip()
    if text not in _ALLOWED_API_PATHS:
        raise ConfigError(f"{SITE_LABEL}请求路径不在 allowlist 中：{path!r}")
    client_base = str(getattr(client, "base_url", "") or "").strip()
    if client_base and _origin(client_base) != FULI_ORIGIN:
        raise ConfigError(f"{SITE_LABEL}客户端 origin 不受信任：{client_base}")
    try:
        payload = client.request(
            method.upper(),
            text,
            json_body=dict(body or {}) if method.upper() in {"POST", "PUT", "PATCH"} else None,
            # 签到 POST 不允许因网络重试而重复提交。
            retry_non_idempotent=False,
        )
    except TaskError as exc:
        if exc.reason == "blocked":
            raise
        if _looks_auth(exc.message, status=exc.status, payload=exc.payload):
            raise LoginRequired(exc.message, status=exc.status, payload=exc.payload) from exc
        raise
    return _unwrap_target(payload)


def _self_info(payload: Any) -> dict[str, Any]:
    return _as_dict(payload)


def _bound(info: Mapping[str, Any]) -> bool | None:
    """从福利站 self 响应判断是否绑定主站；没有证据时返回 None。"""
    explicit_values: list[bool] = []
    empty_id_present = False
    id_values: list[Any] = []
    flag_keys = (
        "bound",
        "is_bound",
        "linked",
        "connected",
        "main_bound",
        "has_newapi",
        "has_new_api",
        "isConnected",
    )
    id_keys = ("newapi_user_id", "new_api_user_id", "newapiUserId", "newApiUserId")

    def inspect(source: Mapping[str, Any]) -> None:
        nonlocal empty_id_present
        for key in flag_keys:
            if key not in source:
                continue
            value = _flag(source.get(key))
            if value is not None:
                explicit_values.append(value)
        for key in id_keys:
            if key not in source:
                continue
            value = source.get(key)
            id_values.append(value)
            if value in (None, "", 0):
                empty_id_present = True

    inspect(info)
    for key in ("user", "profile", "account"):
        nested = info.get(key)
        if isinstance(nested, Mapping):
            inspect(nested)

    # 明确的 false 优先，避免接口同时带「connected=false」和旧的残留 id。
    if False in explicit_values:
        return False
    if True in explicit_values:
        return True
    if any(value not in (None, "", 0) for value in id_values):
        return True
    if empty_id_present:
        return False
    return None


def _check_bound(info: Mapping[str, Any]) -> None:
    bound = _bound(info)
    if bound is False:
        raise ConfigError(
            f"{SITE_LABEL}账号尚未绑定 new-api（{MAIN_ORIGIN}）。"
            "请用同一个 LinuxDO 账号登录主站后，再回到福利站完成账号连接。",
            payload={"bound": False},
        )
    if bound is None:
        raise ConfigError(
            f"{SITE_LABEL}无法从 /api/user/self 确认是否已绑定 new-api（{MAIN_ORIGIN}），"
            "为避免误发签到，已停止提交；请检查福利站接口或先完成同一 LinuxDO 账号绑定。",
            payload={"bound": None},
        )


def _checkin_view(payload: Any) -> dict[str, Any]:
    data = _as_dict(payload)
    today = _as_dict(data.get("today"))
    rules = _as_dict(data.get("rules"))
    return {**data, "today": today, "rules": rules}


def _checked(view: Mapping[str, Any]) -> bool:
    for source in (view, _as_dict(view.get("today"))):
        for key in ("checked_today", "checkedToday", "checked_in_today", "already", "done"):
            if key in source and _flag(source.get(key)) is True:
                return True
    return False


def _enabled(view: Mapping[str, Any]) -> bool | None:
    for source in (view, _as_dict(view.get("rules"))):
        for key in ("enabled", "opened", "open", "checkin_enabled"):
            if key in source:
                value = _flag(source.get(key))
                if value is not None:
                    return value
    return None


def _grant_status(*values: Any) -> str:
    for value in values:
        if isinstance(value, Mapping):
            value = value.get("grant_status") or value.get("grantStatus") or value.get("status")
        text = _text(value).casefold()
        if text in _GRANT_STATUSES:
            return text
    return ""


def _first_value(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def _quota_and_type(view: Mapping[str, Any], action: Mapping[str, Any] | None = None) -> tuple[Any, str]:
    action_map = _as_dict(action)
    today = _as_dict(view.get("today"))
    value = _first_value(
        today.get("quota"),
        view.get("quota"),
        action_map.get("quota"),
        today.get("balance"),
        view.get("balance"),
        action_map.get("balance"),
    )
    quota_type = _text(
        _first_value(
            today.get("quota_type"),
            view.get("quota_type"),
            action_map.get("quota_type"),
        )
    ).casefold()
    return value, quota_type


def _awarded(view: Mapping[str, Any], action: Mapping[str, Any] | None = None) -> Any:
    action_map = _as_dict(action)
    today = _as_dict(view.get("today"))
    # 福利站 /api/checkin 的 quota 是本次发放额，bonus 只是其中的额外奖励；
    # bonus=0 不能把一笔正常签到记成“获得 0”，更不能把 quota 当作账户余额。
    return _first_value(
        action_map.get("quota_awarded"),
        action_map.get("awarded"),
        action_map.get("quota"),
        today.get("quota_awarded"),
        today.get("awarded"),
        today.get("quota"),
        view.get("quota_awarded"),
        view.get("awarded"),
        view.get("quota"),
        action_map.get("bonus"),
        today.get("bonus"),
        view.get("bonus"),
    )


def _format_quota(value: Any, quota_type: str = "") -> str:
    number = _number(value)
    if number is None:
        return ""
    kind = str(quota_type or "").casefold()
    if kind in {"usd", "dollar", "dollars", "$"}:
        usd = number
    elif kind in {"raw", "points", "point", "credits", "credit"}:
        return f"{int(number)}" if number.is_integer() else f"{number:g}"
    else:
        # 福利站与主站均可能返回 New API 内部 quota；默认按内部单位展示。
        usd = number / 500_000
    return f"${usd:.2f}" if abs(usd) >= 0.01 else f"${usd:.4f}"


def _safe_detail(
    view: Mapping[str, Any],
    *,
    source: str,
    action: Mapping[str, Any] | None = None,
    completion_signal: str = "",
) -> dict[str, Any]:
    today = _as_dict(view.get("today"))
    rules = _as_dict(view.get("rules"))
    action_map = _as_dict(action)
    detail: dict[str, Any] = {
        "source": source,
        "completion_signal": completion_signal or source,
    }
    for key in ("checked_today", "streak", "quota_type", "grant_status"):
        value = _first_value(view.get(key), today.get(key), action_map.get(key))
        if value not in (None, ""):
            detail[key] = value
    quota, quota_type = _quota_and_type(view, action_map)
    if quota not in (None, ""):
        detail["quota"] = quota
    bonus = _awarded(view, action_map)
    if bonus not in (None, ""):
        detail["bonus"] = bonus
    if "enabled" in rules:
        detail["enabled"] = rules.get("enabled")
    if today:
        detail["today"] = {
            key: today.get(key)
            for key in ("quota", "bonus", "streak", "quota_type", "grant_status")
            if today.get(key) not in (None, "")
        }
    return sanitize_data({key: value for key, value in detail.items() if value not in (None, "")})


def _display(view: Mapping[str, Any], *, action: Mapping[str, Any] | None = None) -> DisplaySpec:
    quota, quota_type = _quota_and_type(view, action)
    text = _format_quota(quota, quota_type)
    extras: list[tuple[str, str]] = []
    awarded = _awarded(view, action)
    awarded_text = _format_quota(awarded, quota_type)
    if awarded_text and _number(awarded) not in (None, 0):
        extras.append(("获得", awarded_text))
    streak = _first_value(_as_dict(view.get("today")).get("streak"), view.get("streak"), _as_dict(action).get("streak"))
    if streak not in (None, ""):
        extras.append(("连续天数", str(streak)))
    status = _grant_status(
        _as_dict(action).get("grant_status"),
        _as_dict(view.get("today")).get("grant_status"),
        view.get("grant_status"),
    )
    if status == "pending":
        extras.append(("入账", "确认中"))
    elif status == "failed":
        extras.append(("入账", "失败"))
    return DisplaySpec(text=text, text_label="签到奖励" if text else "", extras=tuple(extras))


def _already_outcome(view: Mapping[str, Any], *, source: str) -> Outcome:
    detail = _safe_detail(view, source=source, completion_signal="checked_today")
    quota, quota_type = _quota_and_type(view)
    text = _format_quota(quota, quota_type)
    message = f"{SITE_LABEL}今日已签到" + (f"（{text}）" if text else "")
    return already_done(message, data=detail).with_display(_display(view))


def _success_outcome(
    view: Mapping[str, Any],
    *,
    source: str,
    action: Mapping[str, Any] | None = None,
    completion_signal: str = "checkin_response",
) -> Outcome:
    action_map = _as_dict(action)
    detail = _safe_detail(view, source=source, action=action_map, completion_signal=completion_signal)
    status = _grant_status(action_map, _as_dict(view.get("today")), view)
    if status:
        detail["grant_status"] = status
    awarded = _awarded(view, action_map)
    if awarded not in (None, ""):
        detail["awarded"] = awarded
    quota, quota_type = _quota_and_type(view, action_map)
    awarded_text = _format_quota(awarded, quota_type)
    suffix = f"，获得 {awarded_text}" if awarded_text and _number(awarded) not in (None, 0) else ""
    if status == "pending":
        suffix += "（到账确认中）"
    return success(f"{SITE_LABEL}签到成功{suffix}", data=detail).with_display(
        _display(view, action=action_map)
    )


def _failed_api_outcome(action: Mapping[str, Any]) -> Outcome:
    status = _grant_status(action)
    detail = {
        "source": "api_response",
        "completion_signal": "grant_status_failed",
        "grant_status": status or "failed",
    }
    for key in ("quota", "bonus", "streak", "quota_type"):
        if action.get(key) not in (None, ""):
            detail[key] = action.get(key)
    return failed(
        f"{SITE_LABEL}签到接口明确返回入账失败",
        reason="unconfirmed",
        data=sanitize_data(detail),
    ).with_display(_display(action, action=action))


# ── API 优先 ─────────────────────────────────────────────────────────────────
def _api_checkin(ctx: Any, client: HttpClient) -> Outcome:
    """纯 HTTP 路径；不可用/未确认时抛 ``_ApiFallback``。"""
    try:
        self_payload = _target_request(client, "GET", SELF_PATH)
        self_info = _self_info(self_payload)
        _check_bound(self_info)
    except ConfigError:
        raise
    except (LoginRequired, TransientError, TaskError) as exc:
        _fallback_or_raise(f"读取福利站登录态失败：{exc.message}", exc)

    try:
        before_payload = _target_request(client, "GET", CHECKIN_PATH)
    except NotApplicable as exc:
        return no_effect(
            f"{SITE_LABEL}今日签到暂未开放",
            reason="not_open",
            data={"source": "api_status", "message": exc.message},
        )
    except (LoginRequired, TransientError, TaskError) as exc:
        _fallback_or_raise(f"读取福利站签到状态失败：{exc.message}", exc)

    before = _checkin_view(before_payload)
    if _checked(before):
        return _already_outcome(before, source="api_status")
    if _enabled(before) is False or _flag(before.get("opened")) is False:
        return no_effect(
            f"{SITE_LABEL}今日签到暂未开放",
            reason="not_open",
            data={"source": "api_status", "completion_signal": "not_open"},
        )

    try:
        action_payload = _target_request(client, "POST", CHECKIN_PATH, body={})
    except (LoginRequired, TransientError, TaskError) as exc:
        if exc.reason == "blocked":
            raise
        # POST 的结果可能已经落账；只读确认，不重复提交。
        try:
            after = _checkin_view(_target_request(client, "GET", CHECKIN_PATH))
        except Exception:
            after = {}
        if after and _checked(after):
            return _already_outcome(after, source="api_recheck")
        raise _ApiFallback(f"福利站 API 签到提交失败：{exc.message}", cause=exc) from exc

    action = _as_dict(action_payload)
    status = _grant_status(action)
    if status == "failed":
        # 这是服务端给出的确定业务结论，不再盲目点一次按钮。
        return _failed_api_outcome(action)

    try:
        after = _checkin_view(_target_request(client, "GET", CHECKIN_PATH))
    except (LoginRequired, TransientError, TaskError) as exc:
        if exc.reason == "blocked":
            raise
        if status in {"success", "pending"}:
            return _success_outcome(
                {"today": action, **action},
                source="api_response",
                action=action,
                completion_signal="grant_status",
            )
        raise _ApiFallback(f"签到后状态确认失败：{exc.message}", cause=exc) from exc

    if _checked(after):
        return _success_outcome(after, source="api_response", action=action, completion_signal="checked_today")
    if status in {"success", "pending"}:
        return _success_outcome(after, source="api_response", action=action, completion_signal="grant_status")
    raise _ApiFallback("福利站 API 返回成功但状态接口未确认签到")


def _api_outcome_or_fallback(ctx: Any) -> Outcome | None:
    cookie = _ctx_cookie(ctx)
    if not cookie:
        _log(ctx, "没有已确认的福利站 Cookie，跳过纯 HTTP，准备浏览器回退")
        return None
    client = _target_client(ctx, cookie)
    try:
        outcome = _api_checkin(ctx, client)
    except ConfigError:
        raise
    except TaskError as exc:
        # WAF/IP 封禁等终止性结论不能再启动浏览器；其 reason/payload 直接交给引擎。
        return exc.to_outcome()
    except _ApiFallback as exc:
        _log(ctx, exc.message)
        return None
    _log(ctx, outcome.message)
    return outcome


# ── 浏览器同源请求与登录 ─────────────────────────────────────────────────────
def _page_origin(page: Any) -> str:
    return _origin(str(getattr(page, "url", "") or ""))


async def _page_json(
    page: Any,
    method: str,
    path: str,
    body: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """在福利站页面内发同源 fetch；不设置 Authorization。"""
    current_origin = _page_origin(page)
    if current_origin and current_origin != FULI_ORIGIN:
        raise ConfigError(f"{SITE_LABEL}浏览器页面 origin 不受信任：{getattr(page, 'url', '')}")
    url = _target_url(path)
    script = """async ([url, method, body]) => {
        try {
            const init = { method, credentials: 'include', headers: { Accept: 'application/json' } };
            if (body !== null) {
                init.headers['Content-Type'] = 'application/json';
                init.body = JSON.stringify(body);
            }
            const response = await fetch(url, init);
            const text = await response.text();
            let parsed = null;
            try { parsed = text ? JSON.parse(text) : null; } catch (_) {}
            return { ok: response.ok, status: response.status, body: parsed, text: text.slice(0, 500) };
        } catch (error) {
            return { ok: false, status: 0, body: null, text: String(error && error.name || 'fetch_error') };
        }
    }"""
    result = await page.evaluate(script, [url, method.upper(), dict(body) if body is not None else None])
    if isinstance(result, dict):
        return result
    return {"ok": False, "status": 0, "body": None, "text": "invalid browser result"}


def _browser_payload(result: Mapping[str, Any]) -> Any:
    try:
        status = int(result.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    body = result.get("body")
    raw_text = body if isinstance(body, str) else result.get("text")
    guard_kind = guard.guard_kind(str(raw_text or ""))
    if not bool(result.get("ok")):
        message = _message(body) or _text(result.get("text")) or f"HTTP {status or 0}"
        if guard_kind is guard.GuardKind.BLOCK:
            raise TaskError(
                message,
                reason="blocked",
                status=status or None,
                payload=mask_secrets(str(raw_text or message)[:300]),
            )
        if _looks_auth(message, status=status, payload=body):
            raise LoginRequired(message, status=status or None, payload=body)
        if _looks_not_open(message):
            raise NotApplicable(message, status=status or None, payload=body)
        raise TaskError(message, status=status or None, payload=body)
    return _unwrap_target(body, status=status)


async def _browser_self(page: Any) -> dict[str, Any]:
    return _self_info(_browser_payload(await _page_json(page, "GET", SELF_PATH)))


async def _browser_checkin_api(page: Any) -> Outcome:
    self_info = await _browser_self(page)
    _check_bound(self_info)
    try:
        before = _checkin_view(_browser_payload(await _page_json(page, "GET", CHECKIN_PATH)))
    except NotApplicable as exc:
        return no_effect(
            f"{SITE_LABEL}今日签到暂未开放",
            reason="not_open",
            data={"source": "browser_api_status", "message": exc.message},
        )
    if _checked(before):
        return _already_outcome(before, source="browser_api_status")
    if _enabled(before) is False or _flag(before.get("opened")) is False:
        return no_effect(
            f"{SITE_LABEL}今日签到暂未开放",
            reason="not_open",
            data={"source": "browser_api_status", "completion_signal": "not_open"},
        )

    try:
        action = _as_dict(_browser_payload(await _page_json(page, "POST", CHECKIN_PATH, {})))
        status = _grant_status(action)
        if status == "failed":
            # 服务端已经明确拒绝入账，不能再点击一次按钮造成重复副作用。
            return _failed_api_outcome(action)
        after = _checkin_view(_browser_payload(await _page_json(page, "GET", CHECKIN_PATH)))
    except (NotApplicable, LoginRequired):
        raise
    except TaskError:
        raise
    if _checked(after) or status in {"success", "pending"}:
        return _success_outcome(after, source="browser_api", action=action, completion_signal="checked_today")
    raise TaskError("福利站浏览器 API 未确认签到结果", payload={"action": action, "status": after})


async def _goto_fuli(page: Any) -> None:
    await page.goto(FULI_ORIGIN + "/", wait_until="domcontentloaded", timeout=60000)
    try:
        solved = await bypass.solve_cloudflare(page, log=lambda _message: None, wait_seconds=10)
        if solved is False:
            raise VerificationRequired(f"{SITE_LABEL}页面仍被 Cloudflare/人机验证拦截")
    except VerificationRequired:
        raise
    except Exception:
        # 浏览器依赖缺失或测试替身不提供防护页能力时，继续让后续会话/API给出结论。
        pass


async def _oauth_login_page(page: Any, log: Any) -> dict[str, Any]:
    """从福利站服务端入口启动 OAuth，再复用通用授权与同源回跳检查。"""
    provider = oauth_providers.get_oauth_provider("linuxdo")
    log_fn = log if callable(log) else (lambda _message: None)
    result: dict[str, Any] = {
        "clicked": False,
        "landed_back": False,
        "need_human": False,
        "cloudflare": False,
        "provider": provider.key,
    }
    try:
        # 福利站不是 new-api，没有 /api/status；通用前端选择器还可能误点游戏入口。
        # 必须访问 OAuth 发起端点（不是 callback），由服务端设置 Cookie、签发 state
        # 并重定向到 LinuxDO；始终在原浏览器上下文内完成，不拼接或复用授权 URL。
        log_fn(f"从 {SITE_LABEL}服务端入口启动 LinuxDO OAuth：{OAUTH_PATH}")
        await page.goto(
            _target_url(OAUTH_PATH, browser=True), wait_until="domcontentloaded", timeout=60000
        )
        return await oauth_flow.finish_oauth_authorization(
            page, FULI_ORIGIN, provider, result, log_fn
        )
    except TaskError:
        # 验证/封禁等结构化错误保留原结论，不伪装成共享登录态失效。
        raise
    except Exception as exc:
        return {**result, "error": type(exc).__name__}


def _oauth_failure(result: Mapping[str, Any]) -> TaskError:
    if result.get("cloudflare"):
        return VerificationRequired(
            f"{SITE_LABEL} LinuxDO 登录被 Cloudflare/人机验证拦截，请先在浏览器中完成验证。",
            data={"oauth": {key: result.get(key) for key in ("provider", "cloudflare", "need_human")}},
        )
    return LoginRequired(
        f"{SITE_LABEL} LinuxDO 登录未完成，请确认共享 LinuxDO 登录态有效。",
        data={"oauth": {key: result.get(key) for key in ("provider", "landed_back", "need_human", "error")}},
    )


def _cookie_header_pairs(cookie: str) -> list[dict[str, Any]]:
    host = urlsplit(FULI_ORIGIN).hostname or ""
    pairs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for chunk in normalize_cookie(cookie).split(";"):
        name, separator, value = chunk.strip().partition("=")
        name, value = name.strip(), value.strip()
        if not separator or not name or name in seen:
            continue
        seen.add(name)
        pairs.append({"name": name, "value": value, "domain": host, "path": "/", "secure": True})
    return pairs


async def _inject_site_cookie(context: Any, cookie: str) -> None:
    if context is None or not cookie:
        return
    cookies = _cookie_header_pairs(cookie)
    if not cookies:
        return
    try:
        await context.add_cookies(cookies)
        return
    except Exception:
        pass
    # 某一枚异常 Cookie 不应吞掉同站的 session；逐条补写是安全的兜底。
    for item in cookies:
        try:
            await context.add_cookies([item])
        except Exception:
            continue


async def _browser_session(
    ctx: Any,
    lease: Any,
    page: Any,
    *,
    allow_oauth: bool = False,
    cookie_hint: str = "",
) -> tuple[dict[str, Any], str]:
    """确保页面拥有福利站会话，返回 ``(self, 福利站 Cookie)``。"""
    await _goto_fuli(page)
    if _page_origin(page) not in {"", FULI_ORIGIN}:
        raise TaskError(f"浏览器未停留在 {SITE_LABEL} 同源页面", reason="unconfirmed")

    initial_cookie = normalize_cookie(cookie_hint) or _ctx_cookie(ctx) or _configured_cookie(ctx)
    if initial_cookie:
        await _inject_site_cookie(getattr(lease, "context", None), initial_cookie)
        if initial_cookie:
            # 注入 Cookie 后刷新一次，使页面前端/服务端都看到新会话。
            try:
                await page.reload(wait_until="domcontentloaded", timeout=60000)
            except Exception:
                pass

    try:
        info = await _browser_self(page)
    except VerificationRequired:
        raise
    except LoginRequired:
        info = {}
    except TaskError:
        info = {}

    if not info and allow_oauth:
        # 只有登录阶段有 LoginContext，能安全读取共享 OAuth state；任务阶段不凭空猜 state。
        credentials = getattr(ctx, "credentials", None)
        state_text = str(getattr(credentials, "browser_state", "") or "").strip()
        if not state_text:
            login_spec = getattr(getattr(ctx, "account", None), "login", None)
            provider = str(
                getattr(ctx, "args", {}).get("provider")
                or getattr(login_spec, "provider", "")
                or "linuxdo"
            ).strip().lower()
            account_name = str(
                getattr(ctx, "args", {}).get("account")
                or getattr(login_spec, "account", "")
                or "default"
            ).strip()
            oauth_state = getattr(ctx, "oauth_state", None)
            if callable(oauth_state):
                state_text = str(oauth_state(provider, account_name) or "").strip()
        if not state_text:
            raise LoginRequired(f"缺少 LinuxDO 共享登录态，无法登录 {SITE_LABEL}")
        result = await _oauth_login_page(page, getattr(ctx, "log", None))
        if not result.get("landed_back"):
            raise _oauth_failure(result)
        try:
            await page.goto(FULI_ORIGIN + "/", wait_until="domcontentloaded", timeout=60000)
        except Exception:
            pass
        try:
            info = await _browser_self(page)
        except TaskError as exc:
            raise LoginRequired(f"{SITE_LABEL} OAuth 回跳后仍未建立会话：{exc.message}") from exc

    if not info:
        raise LoginRequired(f"{SITE_LABEL}未建立有效会话")
    _check_bound(info)

    context = getattr(lease, "context", None)
    cookies: list[dict[str, Any]] = []
    if context is not None:
        try:
            cookies = await context.cookies(FULI_ORIGIN)
        except Exception:
            try:
                cookies = await context.cookies()
            except Exception:
                cookies = []
    cookie = storage_scope.site_cookie_string(cookies, FULI_ORIGIN) or initial_cookie
    if not cookie:
        raise LoginRequired(f"{SITE_LABEL}登录成功但没有导出福利站 Cookie")
    return info, normalize_cookie(cookie)


async def _browser_login(ctx: Any, option: LoginOption) -> LoginState:
    provider = str(ctx.args.get("provider") or ctx.account.login.provider or "linuxdo").strip().lower()
    if provider != "linuxdo":
        raise ConfigError(f"{SITE_LABEL}仅支持 linuxdo OAuth")

    if option.method == "browser_state":
        state_text = str(ctx.credentials.browser_state or "").strip()
        allow_oauth = False
    else:
        account_name = str(ctx.args.get("account") or ctx.account.login.account or "default").strip()
        state_text = str(ctx.credentials.browser_state or "").strip() or ctx.oauth_state(provider, account_name)
        allow_oauth = True
    if not state_text:
        raise LoginRequired(f"缺少 {provider} 共享登录态，请先捕获 LinuxDO 浏览器登录态")

    async with ctx.browser.lease(reason="lucky_welfare_login", state_text=state_text) as lease:
        page = await lease.new_page(guard_origin=FULI_ORIGIN)
        info, cookie = await _browser_session(
            ctx,
            lease,
            page,
            allow_oauth=allow_oauth,
            cookie_hint=_configured_cookie(ctx),
        )
        try:
            refreshed_state = await lease.export_state()
        except Exception:
            refreshed_state = state_text
        lease.mark_authenticated()

    return LoginState(
        method=option.method,
        headers=_session_headers(),
        credentials={"session_cookie": cookie, "browser_state": refreshed_state},
        cookie_jar=_cookie_jar(cookie),
        verified=True,
        origin="oauth" if option.method == "oauth" else "browser",
        note=f"已建立 {SITE_LABEL} 同源会话（{provider}）",
    )


def login(ctx: Any, option: LoginOption) -> Any:
    """接管福利站 Cookie / 浏览器态 / OAuth，避免通用登录方式污染主站认证。"""
    if option.method == "cookie":
        cookie = _configured_cookie(ctx, include_plain=True)
        if not cookie:
            # Broker 通常会先因 available=false 跳过；这里保留明确结论供直接调用。
            raise LoginRequired(f"{SITE_LABEL} Cookie 为空")
        client = _target_client(ctx, cookie)
        try:
            info = _self_info(_target_request(client, "GET", SELF_PATH))
            _check_bound(info)
        except ConfigError:
            raise
        except LoginRequired:
            raise
        except TransientError:
            raise
        except TaskError as exc:
            raise LoginRequired(f"{SITE_LABEL} Cookie 校验失败：{exc.message}", payload=exc.payload) from exc
        return LoginState(
            method="cookie",
            headers=_session_headers(),
            credentials={"session_cookie": cookie},
            cookie_jar=_cookie_jar(cookie),
            verified=True,
            origin="config",
            note="复用已验证的福利站 Cookie",
        )
    if option.method in {"browser_state", "oauth"}:
        return _browser_login(ctx, option)
    return None


# ── 浏览器点击兜底 ──────────────────────────────────────────────────────────
async def _click_checkin_button(page: Any, log: Any) -> bool:
    for selector in CHECKIN_BUTTON_SELECTORS:
        try:
            locator = page.locator(selector)
            count = await locator.count()
        except Exception:
            continue
        for index in range(count):
            button = locator.nth(index)
            try:
                if not await button.is_visible():
                    continue
                text = _text(await button.inner_text())
                if "签到" not in text and "摘一片四叶草" not in text:
                    continue
                if await button.is_disabled():
                    continue
            except Exception:
                continue
            for action in (
                lambda: button.click(timeout=8000),
                lambda: button.click(timeout=4000, force=True),
                lambda: button.dispatch_event("click"),
            ):
                try:
                    await action()
                    if callable(log):
                        log(f"已点击福利站签到按钮：{text[:60]}")
                    return True
                except Exception:
                    continue
    return False


async def _capture_evidence(ctx: Any, lease: Any, page: Any, name: str) -> str:
    try:
        return str(await lease.screenshot(name, page=page) or "")
    except Exception:
        try:
            return str(await ctx.evidence.capture(name, page=page) or "")
        except Exception:
            return ""


async def _browser_button_fallback(
    ctx: Any,
    lease: Any,
    page: Any,
    *,
    timeout_seconds: int,
) -> Outcome:
    clicked = await _click_checkin_button(page, getattr(ctx, "log", None))
    if not clicked:
        screenshot = await _capture_evidence(ctx, lease, page, "lucky-welfare-checkin-button-missing.png")
        data: dict[str, Any] = {
            "source": "browser_button",
            "completion_signal": "button_missing",
        }
        if screenshot:
            data["screenshot"] = screenshot
        return failed(f"{SITE_LABEL}未找到可点击的签到按钮", reason="unconfirmed", data=data)

    deadline = asyncio.get_running_loop().time() + max(5, int(timeout_seconds))
    last_text = ""
    while asyncio.get_running_loop().time() < deadline:
        try:
            await page.wait_for_timeout(500)
        except Exception:
            await asyncio.sleep(0.5)
        try:
            result = await _page_json(page, "GET", CHECKIN_PATH)
            view = _checkin_view(_browser_payload(result))
            if _checked(view):
                return _success_outcome(
                    view,
                    source="browser_button",
                    completion_signal="checked_today",
                )
        except (NotApplicable, LoginRequired):
            raise
        except TaskError as exc:
            if exc.reason == "blocked":
                raise
        except Exception:
            pass
        try:
            body = page.locator("body")
            last_text = _safe_text(await body.inner_text())
            if any(marker in last_text for marker in ("今天的叶子已经摘过啦", "今日已签到", "签到成功", "签到完成")):
                return success(
                    f"{SITE_LABEL}签到成功（页面已确认）",
                    data={
                        "source": "browser_button",
                        "completion_signal": "success_text",
                        "result_text": last_text,
                    },
                )
        except Exception:
            pass

    screenshot = await _capture_evidence(ctx, lease, page, "lucky-welfare-checkin-unconfirmed.png")
    data = {
        "source": "browser_button",
        "completion_signal": "unconfirmed",
        "result_text": last_text,
    }
    if screenshot:
        data["screenshot"] = screenshot
    return failed(
        f"{SITE_LABEL}按钮已点击，但未确认签到结果",
        reason="unconfirmed",
        data=data,
    )


async def _browser_checkin(ctx: Any) -> Outcome:
    async with ctx.browser.lease(reason="lucky_welfare_checkin") as lease:
        page = await lease.new_page(guard_origin=FULI_ORIGIN)
        # 登录阶段通常已经完成 OAuth；任务阶段只复用当前浏览器 context，不能凭空读取
        # TaskContext 不暴露的共享 OAuth state。
        _info, cookie = await _browser_session(
            ctx,
            lease,
            page,
            allow_oauth=False,
            cookie_hint=_ctx_cookie(ctx),
        )
        try:
            outcome = await _browser_checkin_api(page)
        except NotApplicable:
            raise
        except ConfigError:
            raise
        except TaskError as exc:
            if exc.reason == "blocked":
                raise
            _log(ctx, f"浏览器同源签到 API 不足：{exc.message}，回退模拟点击")
        else:
            lease.mark_authenticated()
            return outcome

        lease.mark_authenticated()
        return await _browser_button_fallback(
            ctx,
            lease,
            page,
            timeout_seconds=int(getattr(ctx, "args", {}).get("timeout_seconds") or 30),
        )


async def run(ctx: Any) -> Outcome:
    """固定顺序：福利站 API → 浏览器同源 API → ``#today-checkin`` 按钮。"""
    try:
        outcome = _api_outcome_or_fallback(ctx)
    except ConfigError as exc:
        return need_config(exc.message, data={"source": "api", "completion_signal": "config"})
    if outcome is not None:
        return outcome

    try:
        return await _browser_checkin(ctx)
    except ConfigError as exc:
        return need_config(exc.message, data={"source": "browser", "completion_signal": "config"})
    except NotApplicable as exc:
        return no_effect(exc.message, reason="not_open", data={"source": "browser"})
    except VerificationRequired as exc:
        return need_verification(exc.message, data=dict(exc.data))
    except LoginRequired as exc:
        return need_login(exc.message, data=dict(exc.data))
    except TaskError as exc:
        return exc.to_outcome()
    except RuntimeError as exc:
        # ctx.browser 在未安装/未启用时会以 RuntimeError 惰性报错；给用户配置结论。
        return need_config(f"{SITE_LABEL}浏览器回退不可用：{exc}")


def _log(ctx: Any, message: str) -> None:
    logger = getattr(ctx, "log", None)
    if callable(logger):
        logger(message)


__all__ = [
    "CHECKIN_BUTTON_SELECTORS",
    "CHECKIN_CONTAINER",
    "CHECKIN_PATH",
    "FULI_ORIGIN",
    "MAIN_ORIGIN",
    "MANIFEST",
    "OAUTH_PATH",
    "SELF_PATH",
    "_api_checkin",
    "_api_outcome_or_fallback",
    "_browser_checkin_api",
    "_check_bound",
    "_checkin_view",
    "_origin",
    "_page_json",
    "_target_client",
    "_target_request",
    "login",
    "run",
]
