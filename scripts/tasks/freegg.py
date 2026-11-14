#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""站点模板：FreeGG（freegg.app）每日津贴（Daily Allowance）自动领取。

FreeGG 基于 New API v1.0.0-rc.49：
- 标准签到（``/api/user/checkin``）已关闭（``checkin_enabled: false``）；
- 实际每日发放方式是站点开启的 **Daily Allowance（每日津贴）**：已登录用户每个自然日
  首次访问或刷新会话时，后端自动向账户发放固定额度（实测 $20.00），并在
  ``user.setting.allowance_date`` 写入当日日期 ``YYYY-MM-DD``，同时在
  ``/api/log/self?type=1`` 记一条 ``Daily allowance ...`` 系统日志。
- 认证不再写入 ``localStorage``：短效 15 分钟 JWT ``access_token`` 仅存在于内存，
  长效 30 天刷新令牌存于 HttpOnly Cookie ``new_api_refresh``（``Path=/api/user/auth``），
  通过 ``POST /api/user/auth/refresh``（需匹配站点 ``Origin`` / ``Referer``）滚动轮换。

本模板优先纯 HTTP（复用未过期的 ``access_token``，或用 ``new_api_refresh`` Cookie 调
``POST /api/user/auth/refresh`` 换新 JWT 并轮换 Cookie），失效或遇人机挑战时才回退
浏览器复用登录态或 GitHub 共享 OAuth 登录 ``https://freegg.app/wallet``。
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import replace
from typing import Any
from urllib.parse import urlsplit

from core.errors import LoginRequired, TaskError, TransientError
from core.timebase import business_date, parse_timestamp
from login._common import auth_headers
from login.base import LoginState
from net.http import (
    HttpClient,
    extract_message,
    normalize_access_token,
    normalize_cookie,
    unwrap_data,
)
from net.lifetime import cookie_ttl, credential_ttl
from sdk import (
    ChainStep,
    DetectSpec,
    DisplayDefaults,
    DisplaySpec,
    LoginOption,
    Outcome,
    TaskOption,
    TemplateManifest,
    already_done,
    failed,
    success,
)
from templates.builtin.newapi import QUOTA_UNIT, format_usd, quota_to_usd

SITE_LABEL = "FreeGG"
STATUS_PATH = "/api/status"
USER_PATH = "/api/user/self"
REFRESH_PATH = "/api/user/auth/refresh"
LOG_PATH = "/api/log/self?p=1&page_size=20&type=1"
NOTICE_PATH = "/api/notice"
TOPUP_INFO_PATH = "/api/user/topup/info"
WALLET_PATH = "/wallet"

REFRESH_COOKIE_NAME = "new_api_refresh"
DEFAULT_REFRESH_TTL_SECONDS = 30 * 86400
_CLOCK_WINDOW_SKEW_SECONDS = 120
_AMOUNT_RE = re.compile(r"[$＄￥¥]\s*([\d,]+(?:\.\d+)?)")
_ALLOWANCE_LINE_RE = re.compile(r"(?:daily\s+allowance|每日津贴)[^\d]*([\d,]+(?:\.\d+)?)", re.I)

MANIFEST = TemplateManifest(
    id="freegg",
    title="FreeGG",
    extends="newapi",
    description="FreeGG（New API v1.0 + Daily Allowance 每日津贴 + GitHub OAuth）",
    detect=DetectSpec(
        paths=(STATUS_PATH,),
        json_keys=("system_name", "github_client_id", "quota_per_unit"),
        markers=("freegg",),
        weight=1.5,
    ),
    login=(
        LoginOption("access_token", priority=10, title="Access Token"),
        LoginOption("cookie", priority=20, title="Refresh Cookie 续期"),
        LoginOption("browser_state", priority=40, requires=frozenset({"browser"}), title="浏览器登录态"),
        LoginOption("oauth", priority=50, requires=frozenset({"browser"}), title="GitHub OAuth 登录态"),
    ),
    task=(
        TaskOption(
            "script",
            priority=5,
            title="每日津贴签到",
            owns=frozenset({"detect", "confirm"}),
        ),
    ),
    display=DisplayDefaults(text_label="额度"),
    endpoints={
        "status": STATUS_PATH,
        "state": "",
        "submit": "",
        "user": USER_PATH,
        "refresh": REFRESH_PATH,
        "log": LOG_PATH,
        "notice": NOTICE_PATH,
        "topup_info": TOPUP_INFO_PATH,
        "login": "/api/user/login",
    },
    headers={
        "New-Api-User": "{user_id}",
        "Origin": "{origin}",
        "Referer": "{base_url}{referer_path}",
    },
    chain=(
        ChainStep(
            "http",
            "http",
            title="HTTP 刷新并领取每日津贴",
            login=("access_token", "cookie"),
            stop_on=("rate_limited", "blocked"),
        ),
        ChainStep(
            "browser",
            "browser",
            title="浏览器登录并领取每日津贴",
            login=("browser_state", "oauth"),
        ),
    ),
)


# ── 登录钩子：用 new_api_refresh Cookie 换取短效 JWT ──────────────────────────
def _has_refresh_cookie(cookie_header: str) -> bool:
    for part in str(cookie_header or "").split(";"):
        name, sep, value = part.partition("=")
        if sep and name.strip() == REFRESH_COOKIE_NAME and value.strip():
            return True
    return False


def _origin_of(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return str(url or "").rstrip("/")




def _access_token_ttl(data: dict[str, Any], token: str) -> int:
    # 覆盖层已有统一 JWT exp 解析；响应给出的到期时间只能缩短它，不能延长。
    ttl = credential_ttl("access_token", token, default=840)
    raw_exp = data.get("access_expires_at")
    if isinstance(raw_exp, str):
        parsed = parse_timestamp(raw_exp)
        raw_exp = parsed.timestamp() if parsed is not None else None
    if isinstance(raw_exp, (int, float)) and not isinstance(raw_exp, bool) and math.isfinite(raw_exp):
        ttl = min(ttl, max(1, int(raw_exp - time.time())))
    return ttl


def login(ctx: Any, option: Any) -> LoginState | None:
    """接管 ``cookie`` 候选：带上 ``new_api_refresh`` 调 ``POST /api/user/auth/refresh`` 换取 JWT。

    未携带 ``new_api_refresh`` 时返回 ``None`` 交给内置 ``CookieLogin``。
    """
    if getattr(option, "method", "") != "cookie":
        return None
    raw_cookie = normalize_cookie(ctx.credentials.cookie or ctx.credentials.session_cookie)
    if not _has_refresh_cookie(raw_cookie):
        return None

    origin = _origin_of(ctx.base_url)
    referer_path = str(getattr(ctx.account.network, "referer_path", "") or "").strip() or WALLET_PATH
    if not referer_path.startswith("/"):
        referer_path = "/" + referer_path
    refresh_headers = {
        "Accept": "application/json",
        "Cookie": raw_cookie,
        "Origin": origin,
        "Referer": f"{origin}{referer_path}",
    }
    captured_ttl: list[int] = []

    def on_rotated(_header: str, items: list[Any]) -> None:
        refresh_items = [item for item in items if item.name == REFRESH_COOKIE_NAME]
        if refresh_items:
            captured_ttl.append(cookie_ttl(refresh_items, default=DEFAULT_REFRESH_TTL_SECONDS))

    if hasattr(ctx.http, "with_auth"):
        base_client = ctx.http.with_auth(extra=refresh_headers, replace_auth=True)
        client = replace(
            base_client,
            config=replace(base_client.config, max_attempts=1),
            tag=f"{ctx.account.name}:refresh",
            on_cookie_rotated=on_rotated,
        )
    else:
        client = HttpClient(
            base_url=ctx.base_url,
            config=replace(ctx.http.config, max_attempts=1),
            headers=refresh_headers,
            log=ctx.log,
            tag=f"{ctx.account.name}:refresh",
            on_cookie_rotated=on_rotated,
        )
    refresh_path = ctx.endpoint("refresh", REFRESH_PATH)
    ctx.log(f"使用 {REFRESH_COOKIE_NAME} Cookie 纯 HTTP 刷新 FreeGG 会话（{refresh_path}）")

    try:
        # 刷新会轮换一次性 Cookie；传输中断也可能已在服务端成功，不能盲目重放。
        payload = client.request("POST", refresh_path, retry_non_idempotent=False)
    except TaskError as exc:
        translated = _translate_http_error(exc)
        if translated is exc:
            raise
        raise translated from exc

    if isinstance(payload, dict) and payload.get("success") is False:
        raise LoginRequired(extract_message(payload) or "FreeGG 刷新会话被拒绝", payload=payload)
    data = unwrap_data(payload)
    if not isinstance(data, dict):
        raise LoginRequired("FreeGG 会话刷新响应格式无效", payload=payload)

    access_token = normalize_access_token(data.get("access_token"))
    if not access_token:
        raise LoginRequired("FreeGG 会话刷新未返回有效 access_token", payload=payload)

    user = data.get("user") if isinstance(data.get("user"), dict) else {}
    uid = _positive_id(user.get("id") or user.get("user_id"))
    extra: dict[str, str] = {"Origin": origin, "Referer": f"{origin}{referer_path}"}
    if uid:
        extra["New-Api-User"] = uid
    rotated_cookie = normalize_cookie(client.headers.get("Cookie", raw_cookie))
    ttl_seconds = captured_ttl[-1] if captured_ttl else DEFAULT_REFRESH_TTL_SECONDS
    credentials = {"access_token": access_token, "session_cookie": rotated_cookie}
    ttl = {"access_token": _access_token_ttl(data, access_token), "session_cookie": ttl_seconds}
    # cookie 优先于 session_cookie；若最初来自手工 cookie，也必须更新其覆盖层值。
    if ctx.credentials.cookie:
        credentials["cookie"] = rotated_cookie
        ttl["cookie"] = ttl_seconds

    return LoginState(
        method="cookie",
        headers=auth_headers(ctx, access_token, extra=extra),
        credentials=credentials,
        ttl=ttl,
        verified=True,
        origin="refresh",
        identity={"user_id": uid} if uid else {},
        note=f"FreeGG refresh cookie 续期成功（{len(access_token)} 字符）",
    )


# ── 数据解析与结论判定 ────────────────────────────────────────────────────────
def _positive_id(value: Any) -> str:
    if isinstance(value, bool) or value is None:
        return ""
    if isinstance(value, (int, str)):
        text = str(value).strip()
        if text.isascii() and text.isdecimal() and int(text) > 0:
            return str(int(text))
    return ""


def _parse_setting(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        num = int(value)
    except (TypeError, ValueError):
        return None
    return num


def _format_usd_float(amount: float | None) -> str:
    if amount is None:
        return ""
    return f"${amount:.2f}" if abs(amount) >= 0.01 else f"${amount:.4f}"


def _parse_allowance_amount_usd(item: dict[str, Any]) -> float | None:
    other = _parse_setting(item.get("other"))
    parts = other.get("content_parts")
    if isinstance(parts, list):
        for part in parts:
            if not isinstance(part, dict):
                continue
            key = str(part.get("key") or "")
            if "allowance" not in key.lower() and "津贴" not in key:
                continue
            params = part.get("params")
            if isinstance(params, dict):
                for val in params.values():
                    m = _AMOUNT_RE.search(str(val or ""))
                    if m:
                        try:
                            return float(m.group(1).replace(",", ""))
                        except ValueError:
                            pass
    content = str(item.get("content") or "")
    m = _ALLOWANCE_LINE_RE.search(content) or _AMOUNT_RE.search(content)
    if m and ("allowance" in content.lower() or "津贴" in content):
        try:
            return float(m.group(1).replace(",", ""))
        except ValueError:
            return None
    return None


def _is_daily_allowance_log(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    if item.get("type") not in (1, "1", None):
        return False
    content = str(item.get("content") or "").lower()
    if "daily allowance" in content or "每日津贴" in content:
        return True
    other = _parse_setting(item.get("other"))
    parts = other.get("content_parts")
    if isinstance(parts, list):
        for part in parts:
            if isinstance(part, dict) and (
                "allowance" in str(part.get("key") or "").lower()
                or "津贴" in str(part.get("key") or "")
            ):
                return True
    return False


def _find_today_allowance_log(log_payload: Any, today: str) -> dict[str, Any] | None:
    data = unwrap_data(log_payload)
    items: Any = None
    if isinstance(data, dict):
        items = data.get("items")
    elif isinstance(data, list):
        items = data
    if not isinstance(items, list):
        return None
    from datetime import datetime, timezone

    for item in items:
        if not _is_daily_allowance_log(item):
            continue
        ts = _int_or_none(item.get("created_at"))
        if ts is None or ts <= 0:
            continue
        item_date = business_date(datetime.fromtimestamp(ts, tz=timezone.utc))
        if item_date == today:
            return item
    return None


def _unwrap_api_dict(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict) and payload.get("success") is False:
        msg = extract_message(payload) or "接口返回失败"
        lowered = msg.lower()
        if any(p in lowered for p in ("unauthorized", "not logged in", "未登录", "token", "expired")):
            raise LoginRequired(msg, payload=payload)
        raise TaskError(msg, payload=payload)
    data = unwrap_data(payload)
    return data if isinstance(data, dict) else {}


def _task_start_epoch(ctx: Any) -> float:
    clock = getattr(ctx, "clock", None)
    elapsed_fn = getattr(clock, "elapsed", None)
    if callable(elapsed_fn):
        try:
            elapsed = max(0.0, float(elapsed_fn()))
            return time.time() - elapsed
        except Exception:
            pass
    return time.time()


def _evaluate_allowance(
    ctx: Any,
    user_data: dict[str, Any],
    log_payload: Any,
    *,
    source: str,
    run_started_at: float,
) -> Outcome:
    today = business_date()
    uid = _positive_id(user_data.get("id") or user_data.get("user_id"))
    quota = user_data.get("quota")
    used_quota = user_data.get("used_quota")
    setting = _parse_setting(user_data.get("setting"))
    allowance_date = str(setting.get("allowance_date") or "").strip()

    today_log = _find_today_allowance_log(log_payload, today)
    granted_today = (allowance_date == today) or (today_log is not None)

    q_int = _int_or_none(quota)
    u_int = _int_or_none(used_quota)
    total_quota = (q_int + u_int) if (q_int is not None and u_int is not None) else None
    balance_text = format_usd(quota)

    store = getattr(ctx, "store", None)
    baseline = (store.get("allowance_baseline") if store is not None else None) or {}
    if not isinstance(baseline, dict):
        baseline = {}

    if not granted_today:
        display = DisplaySpec(text=balance_text, text_label="额度" if balance_text else "")
        return failed(
            f"{SITE_LABEL} 今日每日津贴尚未到账（allowance_date={allowance_date or '空'}）",
            reason="unconfirmed",
            data={
                "source": source,
                "allowance_date": allowance_date,
                "quota": quota,
                "used_quota": used_quota,
            },
        ).with_display(display)

    awarded_usd = _parse_allowance_amount_usd(today_log) if today_log is not None else None
    prev_total = _int_or_none(baseline.get("total_quota"))
    prev_date = str(baseline.get("date") or "")
    prev_uid = str(baseline.get("user_id") or "")
    prev_req_id = str(baseline.get("request_id") or "")
    same_user = (not prev_uid or not uid or prev_uid == uid)

    if awarded_usd is None and same_user and prev_date != today and total_quota is not None and prev_total is not None:
        if total_quota > prev_total:
            awarded_usd = (total_quota - prev_total) / QUOTA_UNIT

    req_id = str((today_log or {}).get("request_id") or "")
    created_at = _int_or_none((today_log or {}).get("created_at"))
    now_ts = time.time()

    freshly_granted = False
    if same_user and prev_date == today and (not req_id or req_id == prev_req_id):
        if total_quota is None or prev_total is None or total_quota <= prev_total:
            freshly_granted = False
    elif today_log is not None:
        if req_id and prev_req_id == req_id:
            freshly_granted = False
        elif created_at is not None and (run_started_at - _CLOCK_WINDOW_SKEW_SECONDS) <= created_at <= (now_ts + _CLOCK_WINDOW_SKEW_SECONDS):
            freshly_granted = True
        elif same_user and prev_date and prev_date != today and total_quota is not None and prev_total is not None and total_quota > prev_total:
            freshly_granted = True
    elif same_user and prev_date != today and total_quota is not None and prev_total is not None and total_quota > prev_total:
        freshly_granted = True

    if store is not None:
        try:
            store.put(
                "allowance_baseline",
                {
                    "date": allowance_date or today,
                    "quota": quota,
                    "used_quota": used_quota,
                    "total_quota": total_quota,
                    "request_id": req_id,
                    "user_id": uid,
                    "at": int(now_ts),
                },
            )
        except Exception:
            pass

    amount_text = _format_usd_float(awarded_usd)
    awarded_quota = round(awarded_usd * QUOTA_UNIT) if awarded_usd is not None else None
    detail: dict[str, Any] = {
        "source": source,
        "completion_signal": "daily_allowance",
        "allowance_date": allowance_date or today,
        "quota": quota,
        "used_quota": used_quota,
    }
    if awarded_quota is not None:
        detail["quota_awarded"] = awarded_quota
    if req_id:
        detail["request_id"] = req_id
    if created_at is not None:
        detail["granted_at"] = created_at

    extras: tuple[tuple[str, str], ...] = ()
    if freshly_granted:
        if amount_text:
            extras = (("获得", amount_text),)
        if allowance_date:
            extras += (("津贴日期", allowance_date),)
        msg = f"{SITE_LABEL} 每日津贴领取成功" + (f"，获得 {amount_text}" if amount_text else "")
        return success(msg, data=detail).with_display(
            DisplaySpec(text=balance_text, text_label="额度" if balance_text else "", extras=extras)
        )

    if amount_text:
        extras = (("今日津贴", amount_text),)
    if allowance_date:
        extras += (("津贴日期", allowance_date),)
    msg = f"{SITE_LABEL} 今日已领取每日津贴" + (f"（今日津贴 {amount_text}）" if amount_text else "")
    return already_done(msg, data=detail).with_display(
        DisplaySpec(text=balance_text, text_label="额度" if balance_text else "", extras=extras)
    )


# ── 纯 HTTP 步骤 ─────────────────────────────────────────────────────────────
def _translate_http_error(exc: TaskError) -> TaskError:
    if exc.status == 429:
        return TransientError(
            f"{SITE_LABEL} 请求触发站点限流（429），请稍后重试",
            reason="rate_limited",
            status=429,
            payload=exc.payload,
        )
    return exc


async def _http_flow(ctx: Any, *, run_started_at: float) -> Outcome:
    today = business_date()
    try:
        user_data = _unwrap_api_dict(ctx.http.get(USER_PATH))
    except TaskError as exc:
        raise _translate_http_error(exc) from exc

    setting = _parse_setting(user_data.get("setting"))
    allowance_date = str(setting.get("allowance_date") or "").strip()
    if allowance_date != today:
        # 模拟打开 /wallet 时前端发出的辅助只读接口，确保不漏任何可能触发津贴的接口。
        for extra_path in (NOTICE_PATH, TOPUP_INFO_PATH):
            try:
                ctx.http.get(extra_path)
            except TaskError:
                pass
        try:
            user_data = _unwrap_api_dict(ctx.http.get(USER_PATH))
        except TaskError as exc:
            raise _translate_http_error(exc) from exc
        setting = _parse_setting(user_data.get("setting"))
        allowance_date = str(setting.get("allowance_date") or "").strip()

        # 若仍未发放且手头的 token 是先前缓存、未触发过本次刷新的，尝试一次 refresh 续期。
        if allowance_date != today:
            handle = getattr(ctx, "login", None)
            renew = getattr(handle, "renew", None)
            if callable(renew):
                try:
                    if await renew():
                        user_data = _unwrap_api_dict(ctx.http.get(USER_PATH))
                except TaskError as exc:
                    if exc.status == 429:
                        raise _translate_http_error(exc) from exc

    log_payload: Any = None
    try:
        log_payload = ctx.http.get(LOG_PATH)
    except TaskError as exc:
        ctx.log(f"读取每日津贴日志未成功（{exc.message}），仅依据用户配置日期判断")

    return _evaluate_allowance(ctx, user_data, log_payload, source="http_api", run_started_at=run_started_at)


async def run_http(ctx: Any) -> Outcome:
    """访问链 HTTP 步骤：纯 HTTP 刷新/查询并核实 Daily Allowance。"""
    started = _task_start_epoch(ctx)
    try:
        return await _http_flow(ctx, run_started_at=started)
    except TaskError as exc:
        return _translate_http_error(exc).to_outcome()


async def fetch_state(ctx: Any) -> dict[str, Any]:
    """覆盖父模板 newapi 的 /api/user/checkin 探测：改查 /api/user/self 津贴日期。"""
    user_data = _unwrap_api_dict(ctx.http.get(USER_PATH))
    setting = _parse_setting(user_data.get("setting"))
    today = business_date()
    allowance_date = str(setting.get("allowance_date") or "").strip()
    return {
        "checked_in_today": allowance_date == today,
        "allowance_date": allowance_date,
        "quota": user_data.get("quota"),
    }


async def confirm(ctx: Any, outcome: Outcome) -> Outcome:
    """覆盖父模板 newapi.confirm：FreeGG 已自行核对津贴日志与日期，禁止回查关闭的 /api/user/checkin。"""
    return outcome


# ── 浏览器兜底步骤 ───────────────────────────────────────────────────────────
_BROWSER_INSPECT_JS = r"""async ([baseUrl, userPath, logPath, noticePath, topupPath, initialToken, initialUid, today, timeoutMs]) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const headers = {Accept:'application/json'};
    if (initialToken) headers.Authorization = 'Bearer ' + initialToken;
    if (initialUid) headers['New-Api-User'] = String(initialUid);
    const read = async path => {
        const r = await fetch(baseUrl + path, {credentials:'include', headers, signal:controller.signal});
        const text = await r.text();
        if (/^\s*</.test(text) || /aliyun_waf|slidecaptcha|acw_sc__|Just a moment|cf-challenge/i.test(text)) {
            return {status:r.status, error:'challenge_html'};
        }
        if (r.status === 429) return {status:429, error:'rate_limited'};
        if (r.status === 401 || r.status === 403) return {status:r.status, error:'unauthorized'};
        if (!r.ok) return {status:r.status, error:'http_error'};
        let body;
        try {body = JSON.parse(text);} catch (_) {return {status:r.status, error:'not_json'};}
        if (!body || body.success === false) return {status:r.status, error:'api_error'};
        return {status:r.status, body};
    };
    try {
        let user = await read(userPath);
        if (user.error) return user;
        let data = user.body.data || user.body;
        let setting = {};
        try {setting = typeof data.setting === 'string' ? JSON.parse(data.setting) : (data.setting || {});} catch (_) {}
        if (setting.allowance_date !== today) {
            await read(noticePath);
            await read(topupPath);
            user = await read(userPath);
            if (user.error) return user;
            data = user.body.data || user.body;
        }
        const logs = await read(logPath).catch(() => null);
        return {status:200, user:data, logs:logs && !logs.error ? logs.body : null};
    } catch (e) {
        return {status:0, error:e && e.name === 'AbortError' ? 'fetch_timeout' : 'fetch_error'};
    } finally {
        clearTimeout(timer);
    }
}"""


async def _browser_flow(ctx: Any, *, run_started_at: float) -> Outcome:
    from browser import bypass, storage_scope, waf

    if ctx.browser is None:
        return failed("FreeGG 浏览器步骤需要启用浏览器", reason="need_config")

    origin = _origin_of(ctx.account.base_url)
    today = business_date()
    initial_token = normalize_access_token(ctx.http.headers.get("Authorization", ""))
    initial_uid = _positive_id(ctx.http.headers.get("New-Api-User", ""))
    async with ctx.browser.lease(reason="freegg_inspect") as lease:
        page = await lease.new_page()
        # 登录阶段已统一处理 refresh 与发布；此处只打开同源 JSON 文档，避免 SPA
        # 自动刷新轮换 Cookie 后，覆盖层仍保存旧 session_cookie。
        await lease.goto(STATUS_PATH, page=page, wait_until="domcontentloaded", timeout=30000)
        try:
            await lease.dismiss_popups(page=page)
        except Exception:
            pass
        if await waf.is_waf_html(page):
            if not await waf.solve_waf(page, origin, ctx.log, rounds=2):
                return failed("FreeGG 页面防护挑战未通过", reason="need_verification")
        if await bypass.has_cloudflare_challenge(page):
            cf = await bypass.TurnstileBypass(log=ctx.log).solve_result(page, mode="page_access", timeout=20)
            if not cf.ok:
                return failed(cf.message or "FreeGG Cloudflare 验证尚未通过", reason="need_verification")
        if not storage_scope.same_origin(str(getattr(page, "url", "") or ""), origin):
            return failed("FreeGG 页面未停留在本站，未向页面交付认证信息", reason="need_login")

        remaining = ctx.remaining_seconds() if callable(getattr(ctx, "remaining_seconds", None)) else None
        timeout_ms = max(5000, min(25000, int(remaining * 1000))) if remaining is not None else 20000
        res = await page.evaluate(
            _BROWSER_INSPECT_JS,
            [origin, USER_PATH, LOG_PATH, NOTICE_PATH, TOPUP_INFO_PATH, initial_token, initial_uid, today, timeout_ms],
        )
        if not isinstance(res, dict):
            return failed("浏览器页面内读取 FreeGG 状态异常", reason="unconfirmed")
        error = str(res.get("error") or "")
        status = int(res.get("status") or 0)
        if error == "challenge_html":
            return failed("FreeGG 接口返回防护挑战页", reason="need_verification")
        if status == 429 or error == "rate_limited":
            return failed("FreeGG 浏览器刷新触发站点限流（429），请稍后重试", reason="rate_limited")
        if status in (401, 403) or error == "unauthorized":
            return failed("FreeGG 浏览器会话未登录或已过期", reason="need_login")
        user_data = res.get("user")
        if not isinstance(user_data, dict) or not _positive_id(user_data.get("id") or user_data.get("user_id")):
            return failed(f"浏览器内未能读取 FreeGG 用户信息（{error or status or 'unknown'}）", reason="unconfirmed")

        uid = _positive_id(user_data.get("id") or user_data.get("user_id"))
        lease.mark_authenticated(identity={"user_id": uid})
        return _evaluate_allowance(ctx, user_data, res.get("logs"), source="browser_flow", run_started_at=run_started_at)


async def run_browser(ctx: Any) -> Outcome:
    """浏览器登录已由引擎完成；先用新认证查询，避免再次打开 SPA 无谓轮换 Cookie。"""
    started = _task_start_epoch(ctx)
    outcome = await run_http(ctx)
    if outcome.ok or outcome.reason in {"rate_limited", "blocked", "need_login"}:
        return outcome
    return await _browser_flow(ctx, run_started_at=started)


async def run(ctx: Any) -> Outcome:
    """兼容未配置访问链的任务执行入口：优先纯 HTTP，必要时回退浏览器。"""
    started = _task_start_epoch(ctx)
    try:
        outcome = await _http_flow(ctx, run_started_at=started)
        if outcome.ok:
            return outcome
    except TaskError as exc:
        outcome = _translate_http_error(exc).to_outcome()

    if outcome.reason in {"rate_limited", "blocked", "not_open"}:
        return outcome
    if ctx.browser is not None and "browser" in getattr(ctx, "capabilities", ()):
        if outcome.reason == "need_login":
            recover = getattr(getattr(ctx, "login", None), "recover", None)
            if callable(recover):
                try:
                    if await recover():
                        return await _http_flow(ctx, run_started_at=started)
                except TaskError as exc:
                    return _translate_http_error(exc).to_outcome()
        return await _browser_flow(ctx, run_started_at=started)
    return outcome


def render(outcome: Outcome) -> DisplaySpec:
    """余额展示沿用 New API 的内部 quota → 美元格式。"""
    current = outcome.data.get("quota")
    text = format_usd(current)
    extras = tuple(getattr(getattr(outcome, "display", None), "extras", ()) or ())
    if not extras:
        awarded = outcome.data.get("quota_awarded")
        if quota_to_usd(awarded):
            label = "获得" if outcome.verdict.value == "success" else "今日津贴"
            extras = ((label, format_usd(awarded)),)
    return DisplaySpec(text=text, text_label="额度" if text else "", extras=extras)
