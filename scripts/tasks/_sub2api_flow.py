#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sub2API 系站点 browser_script 的共享实现。

100xLabs 与极速蹬（jisudeng）都是 Sub2API 站点，登录/签到链路完全同构，
此前两个脚本各自维护了约 90% 逐字相同的代码（合计约 1890 行），任何接口
变更都要改两遍、测两遍。这里把同构部分收敛为一份，站点脚本只声明差异：

- 签到端点（100xLabs=/api/v1/check-in，极速蹬=/api/v1/play/checkin）
- 站点显示名（错误文案里的「百倍」/「极速蹬」）
- localStorage sentinel 键名（避免两站互相干扰）
- 按钮/文案候选词与默认入口路径

安全约定（与原实现一致，不放松）：
- 凭据只从 script_args 或环境变量读取，绝不写入配置、结果或日志；
- 只消费 Cloudflare 正常签发的 Turnstile 令牌，不伪造、不绕过；
- 回传的诊断信息不含邮箱/密码/token。
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


# Sub2API 前端统一用这些 localStorage 键存登录态。
AUTH_KEYS = ("auth_token", "refresh_token", "auth_user", "token_expires_at")

# 「关于本站的使用说明」模态框的 localStorage 标记（两站同源，键名一致）。
NOTICE_KEY = "sub2api_site_usage_notice_v1"


@dataclass(frozen=True)
class SiteSpec:
    """站点差异声明：共享逻辑靠它区分 100xLabs 与极速蹬。"""

    # 站点中文名，用于结果消息（「百倍…」/「极速蹬…」）。
    site_label: str
    # 该 fork 的签到端点（100xLabs=/api/v1/check-in，极速蹬=/api/v1/play/checkin）。
    checkin_path: str
    # localStorage sentinel 键名。两站同时启用时必须各自独立，否则一站登录成功会
    # 让另一站的 init script 提前停止清理 auth 键。
    login_reset_sentinel: str
    # 截图文件名前缀（<缓存目录>/browser_script/<prefix>-*.png）。
    screenshot_prefix: str
    # 只读的签到状态端点（GET）。实测百倍 /api/v1/check-in/status 稳定回
    # {"data":{"checked_in_today":true,"today_reward":5,"balance":897}}，用于在
    # 「靠页面文案判定已签到」时补出余额，让脚本路径与 API 路径的产出一致。
    # 留空表示该 fork 没有状态端点，此时结果照旧不带额度。
    status_path: str = ""
    default_start_path: str = "/check-in"
    email_env: str = ""
    password_env: str = ""
    checkin_texts: tuple[str, ...] = ()
    already_texts: tuple[str, ...] = ()
    success_texts: tuple[str, ...] = ()
    # 监听签到 POST 响应时匹配的 URL 片段。
    response_match: tuple[str, ...] = ()
    # 极速蹬的 /play/checkin/makeup 是补签接口，监听签到响应时必须排除。
    response_exclude: tuple[str, ...] = ()
    # 已签到判定过于宽泛的词（如 "today"）只在按钮被禁用时才作准。
    weak_already_texts: tuple[str, ...] = ("today",)
    success_message: str = "签到成功"
    # detail.completion_signal 的标签。两站历史取值不同（100xLabs 用
    # button_state/page_text，极速蹬用 already_state），这些值会进结果 JSON 与
    # 报表，抽取公共逻辑时必须保持各自原样，不能统一，否则等于变更对外契约。
    signal_already_control: str = "button_state"
    signal_already_text: str = "page_text"
    signal_post_click_text: str = "already_text"
    # Turnstile token 在登录请求体里的字段名。各 fork 不一致，且发错字段时站点
    # 只回一句 turnstile verification failed，看不出是字段名错了还是验证真没过，
    # 所以让站点自己声明（实测百倍与极速蹬都用 turnstile_token）。
    turnstile_field_name: str = "turnstile_token"
    # 仅适用于已确认的新签到协议；默认关闭，保持其他 fork 的历史行为。
    strict_checkin: bool = False


@dataclass
class ScriptOptions:
    """从 script_args 解析出的运行参数。"""

    checkin_texts: list[str] = field(default_factory=list)
    already_texts: list[str] = field(default_factory=list)
    success_texts: list[str] = field(default_factory=list)
    goto_timeout: int = 60000
    ready_timeout: int = 10000
    click_timeout: int = 5000
    button_wait_ms: int = 25000
    completion_timeout_ms: int = 10000
    poll_interval_ms: int = 100
    login_timeout_ms: int = 60000
    login_fallback: bool = True
    email: str = ""
    password: str = ""
    email_env: str = ""
    password_env: str = ""
    start_target: str = ""
    wait_until: str = "commit"


def _as_list(value: Any, default: tuple[str, ...]) -> list[str]:
    if isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
        return items or list(default)
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return list(default)


def _as_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().casefold() not in {"0", "false", "no", "off"}
    return bool(value)


def _as_int(value: Any, default: int, minimum: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= minimum else default


def parse_options(spec: SiteSpec, script_args: Any) -> ScriptOptions:
    """把 script_args 规范化为 ScriptOptions；缺省值取自 SiteSpec。"""
    # script_args 可能是 dict 或 mappingproxy，统一转成 dict
    try:
        args = dict(script_args) if script_args else {}
    except (TypeError, ValueError):
        args = {}
    start = (
        str(args.get("start_url") or args.get("url") or "").strip()
        or str(args.get("start_path") or args.get("path") or "").strip()
        or spec.default_start_path
    )
    completion = args.get("completion_timeout_ms", args.get("after_click_wait_ms", 10000))
    return ScriptOptions(
        checkin_texts=_as_list(args.get("checkin_text"), spec.checkin_texts),
        already_texts=_as_list(args.get("already_text"), spec.already_texts),
        success_texts=_as_list(args.get("success_text"), spec.success_texts),
        goto_timeout=_as_int(args.get("goto_timeout", 60000), 60000, 1),
        ready_timeout=_as_int(args.get("ready_timeout", 10000), 10000, 1),
        click_timeout=_as_int(args.get("click_timeout", 5000), 5000, 1),
        button_wait_ms=_as_int(args.get("button_wait_ms", 25000), 25000),
        completion_timeout_ms=_as_int(completion, 10000),
        poll_interval_ms=max(20, _as_int(args.get("poll_interval_ms", 100), 100, 1)),
        login_timeout_ms=max(1000, _as_int(args.get("login_timeout_ms", 60000), 60000, 1)),
        login_fallback=_as_bool(args.get("login_fallback", True), True),
        email=str(args.get("email") or "").strip(),
        password=str(args.get("password") or ""),
        email_env=str(args.get("email_env") or spec.email_env).strip() or spec.email_env,
        password_env=str(args.get("password_env") or spec.password_env).strip() or spec.password_env,
        start_target=start,
        wait_until=str(args.get("wait_until") or "commit"),
    )


# ── 页面探测原语 ────────────────────────────────────────────────────────────

def log(helpers: Any, message: str) -> None:
    """输出一行进度日志；helpers 没有 log 方法时静默跳过。

    browser_script 会跑几十秒（等 SPA 渲染、过 Turnstile、账密登录、API 兜底），
    没有过程日志时失败只剩一行结论，无法定位卡在哪一步。
    """
    fn = getattr(helpers, "log", None)
    if callable(fn):
        try:
            fn(message)
        except Exception:
            pass


async def is_visible(locator: Any) -> bool:
    try:
        return bool(await locator.is_visible())
    except Exception:
        return False


async def is_disabled(locator: Any) -> bool:
    try:
        return bool(await locator.is_disabled())
    except Exception:
        return False


async def visible_text(page: Any, text: str) -> bool:
    try:
        return await is_visible(page.get_by_text(text, exact=False).first)
    except Exception:
        return False


async def on_login_page(page: Any) -> bool:
    """是否停在登录页。

    URL 含 /login 即判定；URL 未刷新时用登录页特有的密码输入框兜底。
    注意不能用「欢迎回来」这类文本判断——dashboard 概览页也含该文案。
    """
    url = str(getattr(page, "url", "") or "").casefold()
    if "/login" in url:
        return True
    try:
        return bool(await page.locator('input[type="password"]').first.is_visible())
    except Exception:
        return False


# ── 登录态验证 / 刷新 ───────────────────────────────────────────────────────

# authenticated / query_status / api_checkin 都在页面上下文发带 Bearer token 的请求。
# 统一由这段状态机读取 token、刷新并重试原请求，避免三个调用点各自维护略有差异的
# refresh 实现。每次 page.evaluate 创建一个 requester；它在整个操作中最多 refresh 一次。
_PAGE_AUTH_REQUEST_HELPERS_JS = """
    const parseBody = async (response) => {
        const text = await response.text();
        let raw = null;
        try { raw = JSON.parse(text); } catch (_) { /* 非 JSON */ }
        return raw;
    };
    let token = String(localStorage.getItem('auth_token') || '').trim();
    let refreshAttempted = false;
    const refreshOnce = async () => {
        if (refreshAttempted) return '';
        refreshAttempted = true;
        const refreshToken = String(localStorage.getItem('refresh_token') || '').trim();
        if (!refreshToken) return '';
        try {
            const response = await fetch(baseUrl + '/api/v1/auth/refresh', {
                method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000),
                credentials: 'include',
                headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: refreshToken }),
            });
            if (!response.ok) return '';
            const raw = await parseBody(response);
            const payload = raw && typeof raw.data === 'object' && raw.data ? raw.data : raw;
            const accessToken = payload && typeof payload.access_token === 'string'
                ? payload.access_token.trim()
                : '';
            if (!accessToken) return '';
            token = accessToken;
            localStorage.setItem('auth_token', accessToken);
            const newRefreshToken = payload && typeof payload.refresh_token === 'string'
                ? payload.refresh_token.trim()
                : '';
            if (newRefreshToken) localStorage.setItem('refresh_token', newRefreshToken);
            const expiresIn = Number(payload && payload.expires_in);
            if (Number.isFinite(expiresIn) && expiresIn > 0) {
                localStorage.setItem('token_expires_at', String(Date.now() + expiresIn * 1000));
            }
            return accessToken;
        } catch (_) {
            return '';
        }
    };
    const requestWithAuth = async (request) => {
        if (!token) await refreshOnce();
        if (!token) return null;
        let response = await request(token);
        if (response.status === 401) {
            const refreshed = await refreshOnce();
            if (refreshed) response = await request(token);
        }
        return response;
    };
"""


def _page_auth_script(operation_js: str) -> str:
    """把一次页内鉴权操作包进同源 token/refresh 状态机。"""
    return (
        "async (baseUrl) => {\n"
        "if (typeof location !== 'undefined' && location.origin !== new URL(baseUrl).origin) "
        "return {ok: false, reason: 'unconfirmed', status: 0};\n"
        + _PAGE_AUTH_REQUEST_HELPERS_JS + operation_js + "\n}"
    )


_AUTH_PROBE_JS = """
    const probe = {ok: false, reason: 'need_login', status: 0};
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
        const response = await requestWithAuth((accessToken) => fetch(baseUrl + '/api/v1/auth/me', {
            credentials: 'include', redirect: 'error', cache: 'no-store', signal: controller.signal,
            headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
        }));
        if (!response) return probe;
        probe.status = response.status;
        const text = await response.text();
        let raw = null;
        try { raw = JSON.parse(text); } catch (_) { /* HTML/验证页不构成认证证据 */ }
        const data = raw && typeof raw.data === 'object' && raw.data ? raw.data : raw;
        const user = data && typeof data.user === 'object' && data.user ? data.user : data;
        const code = raw && raw.code;
        const refused = raw && (raw.success === false ||
            (code !== undefined && code !== 0 && code !== 200 && code !== '0' && code !== '200'));
        const identified = user && !Array.isArray(user) &&
            ((typeof user.id === 'number' && Number.isFinite(user.id) && user.id > 0) ||
             (typeof user.id === 'string' && /^[1-9][0-9]*$/.test(user.id)));
        if (response.ok && !refused && identified) {
            if (localStorage.getItem('auth_token') === token) {
                localStorage.setItem('auth_user', JSON.stringify(user));
            }
            return {ok: true, reason: '', status: response.status};
        }
        if (response.status === 401 || code === 401 || code === '401') return probe;
        if (/cf-chl-|challenge-platform|just a moment|cloudflare|turnstile/i.test(text)) {
            probe.reason = 'need_verification';
        } else if (response.status === 429 || response.status >= 500) {
            probe.reason = 'network_error';
        } else {
            probe.reason = 'unconfirmed';
        }
        return probe;
    } catch (_) {
        return {ok: false, reason: 'network_error', status: 0};
    } finally {
        clearTimeout(timer);
    }
"""
_AUTHENTICATED_JS = _page_auth_script(_AUTH_PROBE_JS)


async def authenticated(page: Any, origin: str, *, diagnostics: dict[str, Any] | None = None) -> bool:
    """只接受同源 /auth/me 的有效 JSON 身份；刷新、验证页和网络失败有不同结论。"""
    probe: dict[str, Any] = {"ok": False, "reason": "unconfirmed", "status": 0}
    current_url = str(getattr(page, "url", "") or "")
    if not origin_of(origin) or (
        current_url and current_url != "about:blank" and origin_of(current_url) != origin_of(origin)
    ):
        if diagnostics is not None:
            diagnostics.update(probe)
        return False
    for attempt in range(3):
        try:
            result = await asyncio.wait_for(page.evaluate(_AUTHENTICATED_JS, origin), timeout=12.0)
            if isinstance(result, dict):
                probe.update(result)
            break
        except Exception:
            probe["reason"] = "network_error"
            if attempt >= 2:
                break
            await asyncio.sleep(0.2)
    if diagnostics is not None:
        diagnostics.update(probe)
    return probe.get("ok") is True


async def _authenticated_with_probe(
    page: Any, origin: str, diagnostics: dict[str, Any],
) -> bool:
    """保留可替换认证探针的旧两参数调用契约，同时让真实实现输出诊断。"""
    if getattr(authenticated, "__module__", None) == __name__:
        return await authenticated(page, origin, diagnostics=diagnostics)
    diagnostics.clear()
    return await authenticated(page, origin)


_DISMISS_NOTICE_JS = """() => {
    try { localStorage.setItem('%s', 'accepted'); } catch (_) {}
    const buttons = Array.from(document.querySelectorAll('button'));
    for (const btn of buttons) {
        const text = String(btn.textContent || '').trim();
        if (text === '确认' || text === '确定' || /^(confirm|ok|agree)$/i.test(text)) {
            btn.click();
            return true;
        }
    }
    return false;
}""" % NOTICE_KEY


async def dismiss_notice(page: Any) -> None:
    """关闭「关于本站的使用说明」模态框：它遮住登录表单和 Turnstile。

    该模态框由 localStorage 的 sub2api_site_usage_notice_v1 控制：未置为
    accepted 就每次进站弹出。init script 已在导航前预置该标记；这里再做运行时
    兜底——主动写标记，并点击可见的「确认」按钮关闭已弹出的模态框。
    """
    try:
        await page.evaluate(_DISMISS_NOTICE_JS)
    except Exception:
        pass


_FILL_LOGIN_JS = """([email, password]) => {
    const assign = (selector, value) => {
        const el = document.querySelector(selector);
        if (!(el instanceof HTMLInputElement)) return false;
        const desc = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype, 'value'
        );
        if (!desc || typeof desc.set !== 'function') return false;
        desc.set.call(el, value);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
    };
    const okEmail = assign('#email', email) || assign('input[type="email"]', email);
    const okPass = assign('#password', password) || assign('input[type="password"]', password);
    return Boolean(okEmail && okPass);
}"""


async def fill_login_form(page: Any, email: str, password: str) -> bool:
    """填写站点真实登录页的邮箱/密码受控输入框（触发前端框架的 input 事件）。"""
    try:
        return bool(await page.evaluate(_FILL_LOGIN_JS, [email, password]))
    except Exception:
        return False


_SUBMIT_LOGIN_JS = """async ([baseUrl, email, password, turnstileToken, turnstileFieldName]) => {
    const stashKey = __SUB2API_STASH_KEY__;
    const shortMessage = (v) => String(v || '').replace(/[\\r\\n]/g, ' ').slice(0, 160);
    try {
        const body = { email, password };
        const fieldName = turnstileFieldName || 'turnstile_token';
        body[fieldName] = turnstileToken;
        const response = await fetch(baseUrl + '/api/v1/auth/login', {
            method: 'POST',
            credentials: 'include',
            headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const text = await response.text();
        let raw = null;
        try { raw = JSON.parse(text); } catch (_) { /* 非 JSON */ }
        const payload = raw && typeof raw.data === 'object' && raw.data ? raw.data : raw;
        const accessToken = payload && typeof payload.access_token === 'string'
            ? payload.access_token.trim() : '';
        const refreshToken = payload && typeof payload.refresh_token === 'string'
            ? payload.refresh_token.trim() : '';
        const user = payload && payload.user && typeof payload.user === 'object'
            ? payload.user : null;
        if (response.ok && accessToken) {
            localStorage.setItem('auth_token', accessToken);
            if (refreshToken) localStorage.setItem('refresh_token', refreshToken);
            if (user) localStorage.setItem('auth_user', JSON.stringify(user));
            const expiresIn = Number(payload && payload.expires_in);
            if (Number.isFinite(expiresIn) && expiresIn > 0) {
                localStorage.setItem('token_expires_at', String(Date.now() + expiresIn * 1000));
            } else {
                // 站点没回 expires_in 时，上一轮的过期时间戳会残留在 localStorage 里，
                // preflight init script 下次导航就会把这份新 token 当过期货清掉。
                localStorage.removeItem('token_expires_at');
            }
            // 另存一份到前端不认识的暗格：站点 401 拦截器会清掉上面这几个键。
            if (stashKey) {
                const saved = {};
                for (const key of ['auth_token', 'refresh_token', 'auth_user', 'token_expires_at']) {
                    const value = localStorage.getItem(key);
                    if (typeof value === 'string' && value) saved[key] = value;
                }
                localStorage.setItem(stashKey, JSON.stringify(saved));
            }
        }
        const message = raw && typeof raw === 'object'
            ? (raw.message || raw.detail || (payload && payload.message) || '') : '';
        const twoFactor = Boolean(payload && (payload.temp_token || payload.two_factor_required));
        return {
            ok: Boolean(response.ok && accessToken),
            status: response.status,
            two_factor: twoFactor,
            message: shortMessage(message),
        };
    } catch (error) {
        return {
            ok: false,
            status: 0,
            two_factor: false,
            message: shortMessage(error && error.name === 'AbortError' ? 'fetch timeout' : error),
        };
    }
}"""


async def submit_login(
    page: Any,
    origin: str,
    email: str,
    password: str,
    turnstile_token: str,
    stash_key: str = "",
    turnstile_field_name: str = "turnstile_token",
) -> dict[str, Any] | None:
    """调用站点公开登录接口，写入返回的 token，只回传非敏感诊断。

    token 同时另存进浏览器内的暗格（stash_key），Python 侧不接触任何 token 明文。
    """
    try:
        script = _SUBMIT_LOGIN_JS.replace(
            "__SUB2API_STASH_KEY__", json.dumps(stash_key, ensure_ascii=True)
        )
        result = await page.evaluate(
            script, [origin, email, password, turnstile_token, turnstile_field_name]
        )
        return result if isinstance(result, dict) else None
    except Exception as exc:
        # evaluate 本身失败（多为 Turnstile 回调触发表单提交、页面导航销毁执行上下文）。
        # 与 fetch 内部失败区分开，便于诊断；不含凭据。
        return {"ok": False, "status": 0, "two_factor": False, "message": f"evaluate: {type(exc).__name__}"}


def session_stash_key(sentinel: str) -> str:
    """登录态暗格键名：站点前端登出时只清 AUTH_KEYS，不会碰这个键。

    Sub2API 前端的 axios 响应拦截器一旦收到 401（refresh 也失败时同样走这条路），
    会 removeItem auth_token / refresh_token / auth_user / token_expires_at 并
    `window.location.href = '/login'`。账密登录刚拿到的 token 就是这样被前端清掉的。
    把同一份登录态另存一份到前端不认识的键里，导航时即可原样恢复。
    """
    return f"{sentinel}_session" if sentinel else ""


def preflight_init_script(
    stash_key: str = "", *, preserve_refresh: bool = False, origin: str = "",
) -> str:
    """仅清理本站明确过期的 AT；严格模式保留 RT，未知过期时间不猜测清除。"""
    keys = [key for key in AUTH_KEYS if not preserve_refresh or key != "refresh_token"]
    params = json.dumps([origin, stash_key, keys, NOTICE_KEY])
    return """
        (() => {
            const [origin, stash, keys, notice] = %s;
            if (origin && typeof location !== 'undefined' && location.origin !== origin) return;
            try {
                const exp = Number(localStorage.getItem('token_expires_at') || '0');
                if (Number.isFinite(exp) && exp > 0 && Date.now() >= exp) {
                    for (const key of keys) localStorage.removeItem(key);
                    if (stash) {
                        let saved = null;
                        try { saved = JSON.parse(localStorage.getItem(stash) || 'null'); } catch (_) {}
                        const savedExp = Number(saved && saved.token_expires_at || '0');
                        // 旧活跃 token 过期不能连带删除本次仍有效的新副本。
                        if (!saved || (Number.isFinite(savedExp) && savedExp > 0 && Date.now() >= savedExp)) {
                            localStorage.removeItem(stash);
                        }
                    }
                    sessionStorage.removeItem('auth_expired');
                }
                localStorage.setItem(notice, 'accepted');
            } catch (_) { /* 不可解析的旧暗格不影响页面加载 */ }
        })();
    """ % params


def login_reset_init_script(sentinel: str, *, origin: str = "", attempt: str = "") -> str:
    """只清理本页、本 origin、本次仍待登录的认证；旧尝试的脚本不会再生效。"""
    params = json.dumps([origin, sentinel, attempt, list(AUTH_KEYS), NOTICE_KEY])
    return """
        (() => {
            const [origin, sentinel, attempt, keys, notice] = %s;
            if (origin && typeof location !== 'undefined' && location.origin !== origin) return;
            try {
                const current = localStorage.getItem(sentinel);
                const reset = attempt ? current !== attempt + ':done' : current !== 'done';
                if (reset) {
                    for (const key of keys) localStorage.removeItem(key);
                    sessionStorage.removeItem('auth_expired');
                }
                localStorage.setItem(notice, 'accepted');
            } catch (_) { /* 当前文档不可写时交由登录确认收敛 */ }
        })();
    """ % params


def session_restore_init_script(
    stash_key: str, *, origin: str = "", sentinel: str = "", attempt: str = "",
) -> str:
    """只恢复本次已经确认的未过期会话，不依赖其他 init script 的注册顺序。"""
    params = json.dumps([origin, stash_key, sentinel, attempt, list(AUTH_KEYS)])
    return """
        (() => {
            const [origin, key, sentinel, attempt, keys] = %s;
            if (origin && typeof location !== 'undefined' && location.origin !== origin) return;
            try {
                if (attempt && localStorage.getItem(sentinel) !== attempt + ':done') return;
                const saved = JSON.parse(localStorage.getItem(key) || 'null');
                if (!saved || !saved.auth_token || (attempt && saved.__attempt !== attempt)) return;
                const exp = Number(saved.token_expires_at || '0');
                if (Number.isFinite(exp) && exp > 0 && Date.now() >= exp) return;
                if (String(localStorage.getItem('auth_token') || '').trim()) return;
                for (const name of keys) {
                    if (typeof saved[name] === 'string' && saved[name]) localStorage.setItem(name, saved[name]);
                }
                sessionStorage.removeItem('auth_expired');
            } catch (_) { /* 无可验证暗格时不猜测恢复 */ }
        })();
    """ % params


async def add_init_script(context: Any, script: str) -> None:
    if context is None:
        return
    try:
        await context.add_init_script(script)
    except Exception:
        pass


async def mark_login_done(page: Any, sentinel: str, *, origin: str = "", attempt: str = "") -> bool:
    """当前尝试的已确认会话才停止清理；写入失败不继续导航去清掉新凭据。"""
    for _ in range(3):
        try:
            done = await page.evaluate("""([origin, sentinel, attempt]) => {
                if (origin && typeof location !== 'undefined' && location.origin !== origin) return false;
                const value = attempt ? attempt + ':done' : 'done';
                localStorage.setItem(sentinel, value);
                return localStorage.getItem(sentinel) === value;
            }""", [origin, sentinel, attempt])
            if done is True:
                return True
        except Exception:
            pass
        await asyncio.sleep(0.2)
    return False


async def stash_session(page: Any, stash_key: str, *, origin: str = "", attempt: str = "") -> bool:
    """为刚由服务端确认的会话暂存恢复副本，并绑定当前登录尝试。"""
    if not stash_key:
        return False
    try:
        return await page.evaluate("""([origin, key, attempt, keys]) => {
            if (origin && typeof location !== 'undefined' && location.origin !== origin) return false;
            try {
                const saved = {__attempt: attempt};
                for (const name of keys) {
                    const value = localStorage.getItem(name);
                    if (typeof value === 'string' && value) saved[name] = value;
                }
                if (!saved.auth_token) return false;
                localStorage.setItem(key, JSON.stringify(saved));
                return true;
            } catch (_) { return false; }
        }""", [origin, stash_key, attempt, list(AUTH_KEYS)]) is True
    except Exception:
        return False


async def restore_session(
    page: Any, stash_key: str, *, origin: str = "", sentinel: str = "", attempt: str = "",
    replace_rejected: bool = False,
) -> bool:
    """只恢复当前已确认且未过期的副本；非空 token 仅在服务端明确拒绝后可替换。"""
    if not stash_key:
        return False
    try:
        return await page.evaluate("""([origin, key, sentinel, attempt, replaceRejected, keys]) => {
            if (origin && typeof location !== 'undefined' && location.origin !== origin) return false;
            try {
                if (attempt && localStorage.getItem(sentinel) !== attempt + ':done') return false;
                const saved = JSON.parse(localStorage.getItem(key) || 'null');
                if (!saved || !saved.auth_token || (attempt && saved.__attempt !== attempt)) return false;
                const exp = Number(saved.token_expires_at || '0');
                if (Number.isFinite(exp) && exp > 0 && Date.now() >= exp) return false;
                const current = String(localStorage.getItem('auth_token') || '').trim();
                if (current === saved.auth_token || (current && (!replaceRejected || !attempt))) return false;
                for (const name of keys) {
                    const value = saved[name];
                    if (typeof value === 'string' && value) localStorage.setItem(name, value);
                    else localStorage.removeItem(name);
                }
                sessionStorage.removeItem('auth_expired');
                return true;
            } catch (_) { return false; }
        }""", [origin, stash_key, sentinel, attempt, replace_rejected, list(AUTH_KEYS)]) is True
    except Exception:
        return False


_READ_TOKENS_JS = _page_auth_script(
    "const verified = await (async () => {\n" + _AUTH_PROBE_JS + "\n})();\n"
    "if (!verified.ok || localStorage.getItem('auth_token') !== token) return null;\n"
    "return {access_token: token, refresh_token: String(localStorage.getItem('refresh_token') || '').trim()};"
)


async def _record_new_tokens(page: Any, helpers: Any, ctx: Any, origin: str) -> None:
    """把同一请求验证过的 token 交给引擎；不再写没有读取方的学习数据。"""
    accept = getattr(ctx, "accept_browser_credentials", None)
    if not callable(accept) or origin_of(str(getattr(page, "url", ""))) != origin_of(origin):
        return
    try:
        result = await asyncio.wait_for(page.evaluate(_READ_TOKENS_JS, origin), timeout=12.0)
        if not isinstance(result, dict) or not result.get("access_token"):
            return
        if accept(result, verified=True):
            log(helpers, "新认证已交接给当前 HTTP 会话及后续任务（遵循覆盖层写入策略）")
    except Exception as exc:
        # 文件锁、只读策略等不能否定已经确认的登录；异常只记录类型，绝不含凭据。
        log(helpers, f"新认证交接未完成（{type(exc).__name__}），继续使用当前浏览器会话")


async def keep_waf_cookies(context: Any) -> None:
    """只清会话 cookie，保留 Cloudflare 放行 cookie（cf_clearance 等）。

    整站清 cookie 会连 cf_clearance 一起删掉，Cloudflare 随即拦截，/login 渲染为
    纯空白页（既无 dashboard 也无登录表单），会被误判为「持续重定向」。
    """
    if context is None:
        return
    try:
        cookies = await context.cookies()
    except Exception:
        cookies = []
    keep = [c for c in cookies if str(c.get("name", "")).startswith(("cf_", "__cf"))]
    try:
        await context.clear_cookies()
    except Exception:
        pass
    if keep:
        try:
            await context.add_cookies(keep)
        except Exception:
            pass


# ── 账密登录兜底 ────────────────────────────────────────────────────────────

async def _login_turnstile_enabled(page: Any, origin: str) -> bool | None:
    """只读同源公开配置；仅明确的布尔 False 才允许省略登录验证码。"""
    if origin_of(str(getattr(page, "url", "") or "")) != origin:
        return None
    try:
        result = await asyncio.wait_for(page.evaluate(
            """async (origin) => {
                if (typeof location !== 'undefined' && location.origin !== origin) return null;
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), 4000);
                try {
                    const response = await fetch(origin + '/api/v1/settings/public', {
                        method: 'GET', credentials: 'omit', redirect: 'error', signal: controller.signal
                    });
                    if (!response.ok || (typeof location !== 'undefined' && location.origin !== origin)) return null;
                    return await response.json();
                } catch (_) { return null; }
                finally { clearTimeout(timer); }
            }""", origin), timeout=5)
    except Exception:
        return None
    if not isinstance(result, dict) or result.get("success") is False:
        return None
    if result.get("code") not in (None, 0, 200, "0", "200"):
        return None
    data = result.get("data", result)
    flag = data.get("turnstile_enabled") if isinstance(data, dict) else None
    return flag if isinstance(flag, bool) else None


async def _begin_login_attempt(page: Any, origin: str, sentinel: str, attempt: str, stash_key: str) -> bool:
    try:
        await page.evaluate("""([origin, sentinel, attempt, stash]) => {
            if (typeof location !== 'undefined' && location.origin !== origin) return false;
            localStorage.setItem(sentinel, attempt + ':pending');
            localStorage.removeItem(stash);
            return localStorage.getItem(sentinel) === attempt + ':pending';
        }""", [origin, sentinel, attempt, stash_key])
    except Exception:
        # 页面正在导航时 evaluate 可能没有执行；后续 init script 仍会清理旧态，
        # 登录成功后 mark_login_done 会再次确认停止清理。
        pass
    # 这是保护性准备步骤，不应因页面替身或一次导航竞态阻断账密提交。
    return True


def _authentication_failure(helpers: Any, spec: SiteSpec, probe: dict[str, Any], detail: dict[str, Any]) -> Any:
    from core.outcome import failed, need_login, need_verification

    reason = str(probe.get("reason") or "need_login")
    data = {**detail, "auth_response_status": int(probe.get("status") or 0)}

    def build(method: str, message: str, fallback, *, custom_reason: str | None = None) -> Any:
        handler = getattr(helpers, method, None)
        if callable(handler):
            result = handler(message, data)
        else:
            result = fallback(message, data=data)
        if custom_reason and hasattr(result, "as_reason"):
            result = result.as_reason(custom_reason)
        return result

    if reason == "need_login":
        return build("need_login", f"{spec.site_label}登录未通过服务端确认，请重新登录", need_login)
    if reason == "need_verification":
        return build("need_verification", f"{spec.site_label}认证复查被人机验证拦截，已保留原认证", need_verification)
    message = "认证复查遇到网络异常" if reason == "network_error" else "认证响应未包含有效身份"
    return build("error", f"{spec.site_label}{message}，未将当前状态判为登录成功或失效", failed,
                 custom_reason=reason)


async def confirm_login_session(
    page: Any, helpers: Any, spec: SiteSpec, origin: str, login_detail: dict[str, Any],
) -> Any:
    """daily 与灵台共用的登录后确认：有界复查、当前尝试恢复、最后再交接新凭据。"""
    probe: dict[str, Any] = {}
    remaining = getattr(getattr(helpers, "ctx", None), "remaining_seconds", lambda: None)()
    seconds = min(12.0, remaining) if isinstance(remaining, (int, float)) else 12.0
    if seconds <= 0:
        return _authentication_failure(helpers, spec, {"reason": "network_error"}, login_detail)
    try:
        async with asyncio.timeout(seconds):
            for retry in range(3):
                probe.clear()
                if await _authenticated_with_probe(page, origin, probe):
                    login_detail["auth_verified"] = True
                    return None
                # 缺失 token 或明确 401 才尝试恢复；验证页/网络问题不能触发换凭据。
                reason = probe.get("reason") or "need_login"
                attempt = str(login_detail.get("auth_attempt") or "")
                previously_verified = login_detail.get("auth_verified") is True
                if previously_verified and retry == 0:
                    restored = await restore_session(
                        page, session_stash_key(spec.login_reset_sentinel), origin=origin,
                        sentinel=spec.login_reset_sentinel, attempt=attempt, replace_rejected=True,
                    )
                    if restored:
                        login_detail["login_state_restored"] = True
                        login_detail["auth_recheck_deferred"] = True
                        log(helpers, "已恢复本次登录验证过的会话，沿用已确认的新登录态")
                        return None
                    # 已由登录阶段服务端确认的新会话，复查若没有明确的 401，
                    # 不因一次导航后的 Cloudflare/网络假阴性被降级为 need_login。
                    if not probe or int(probe.get("status") or 0) == 0 or reason != "need_login":
                        login_detail["auth_recheck_deferred"] = True
                        return None
                if reason == "need_login":
                    break
                if retry < 2:
                    await asyncio.sleep(0.2)
    except TimeoutError:
        probe = {"reason": "network_error", "status": 0}
    return _authentication_failure(helpers, spec, probe, login_detail)


async def login_with_password(
    page: Any,
    context: Any,
    helpers: Any,
    spec: SiteSpec,
    opts: ScriptOptions,
    resolved_url: str,
    origin: str,
    login_detail: dict[str, Any],
) -> dict[str, Any] | None:
    """登录态失效时，用凭据在真实 /login 页完成一次自动登录。

    停留在站点真实登录页（不合成页面、不注入组件），只消费 Cloudflare 正常签发
    的 Turnstile 令牌；凭据只从 script_args/环境变量读取，不写入配置或日志。
    成功返回 None（继续签到主流程），失败返回结果 dict。
    """
    name = spec.site_label
    log(helpers, f"检测到未登录，开始{name}账密登录兜底")
    if not opts.login_fallback:
        return helpers.need_login(
            f"{name}登录态已失效，且账号密码登录兜底已禁用，请重新捕获 browser_state",
            {"target_url": resolved_url, "login_fallback": "disabled"},
        )

    email = opts.email or os.getenv(opts.email_env, "").strip()
    password = opts.password or os.getenv(opts.password_env, "")
    if not email or not password:
        return helpers.need_login(
            f"{name}登录态已失效；请在 script_args 填写 email/password（或配置环境变量），"
            "或重新捕获 browser_state",
            {
                "target_url": resolved_url,
                "login_fallback": "missing_credentials",
                "email_env": opts.email_env,
                "password_env": opts.password_env,
            },
        )

    loop = asyncio.get_running_loop()
    form_wait_ms = opts.login_timeout_ms if spec.strict_checkin else min(opts.login_timeout_ms, 30000)
    login_deadline = loop.time() + form_wait_ms / 1000
    # 给失败诊断保留一个很小的收尾窗口；它仍属于 login_timeout_ms，绝不扩张总预算。
    diagnostic_reserve = min(2.0, max(0.1, form_wait_ms / 1000 * 0.1))
    work_deadline = login_deadline - diagnostic_reserve
    login_detail["login_timeout_ms"] = form_wait_ms

    async def _bounded_login(awaitable: Any, stage: str, *, deadline: float = work_deadline) -> Any:
        """让登录阶段的每个可等待操作继承同一个绝对截止点。"""
        login_detail["login_stage"] = stage
        remaining = deadline - loop.time()
        if remaining <= 0:
            close = getattr(awaitable, "close", None)
            if callable(close):
                close()
            raise TimeoutError(stage)
        wait_for = getattr(asyncio, "wait_for", None)
        if callable(wait_for):
            try:
                return await wait_for(awaitable, timeout=remaining)
            except TimeoutError as exc:
                raise TimeoutError(stage) from exc
        # 测试替身可能只提供 get_running_loop；生产 asyncio 有 wait_for，
        # 因而不会绕过真实运行时的 deadline。
        return await awaitable

    def _login_timeout(cap_ms: int) -> int:
        remaining = work_deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError("login_deadline")
        return max(1, min(cap_ms, int(remaining * 1000)))

    async def _login_screenshot(filename: str) -> str:
        if login_deadline - loop.time() <= 0:
            return ""
        try:
            return str(await _bounded_login(
                helpers.screenshot(filename), "diagnostic_screenshot", deadline=login_deadline,
            ) or "")
        except Exception:
            return ""

    attempt = uuid4().hex
    stash_key = session_stash_key(spec.login_reset_sentinel)
    try:
        prepared = await _bounded_login(
            _begin_login_attempt(page, origin, spec.login_reset_sentinel, attempt, stash_key),
            "begin_login_attempt",
        )
    except TimeoutError:
        return helpers.error(f"{name}登录页状态未能在预算内就绪，未提交账号密码", {}).as_reason("unconfirmed")
    if not prepared:
        return helpers.error(f"{name}登录页状态未能就绪，未提交账号密码", {}).as_reason("unconfirmed")
    login_detail["auth_attempt"] = attempt
    # 限定到本次流程的页面，不能清理另一个任务或快照恢复临时页的状态。
    try:
        await _bounded_login(
            add_init_script(context, login_reset_init_script(spec.login_reset_sentinel, origin=origin, attempt=attempt)),
            "install_login_guard",
        )
    except TimeoutError:
        return helpers.error(f"{name}登录保护未能在预算内安装，未提交账号密码", {}).as_reason("unconfirmed")

    async def _open_login_and_confirm() -> bool:
        await _bounded_login(keep_waf_cookies(context), "preserve_waf_cookies")
        await _bounded_login(
            helpers.goto(
                f"/login?redirect={spec.default_start_path}",
                timeout=_login_timeout(opts.goto_timeout),
                wait_until="commit",
            ),
            "login_navigation",
        )
        try:
            await _bounded_login(
                page.wait_for_load_state("domcontentloaded", timeout=_login_timeout(opts.ready_timeout)),
                "login_ready",
            )
        except TimeoutError:
            raise
        except Exception:
            pass
        # 整页导航后 store 从（应已空的）localStorage 初始化；确认 auth_user 已空。
        try:
            lingering = await _bounded_login(
                page.evaluate("() => Boolean(String(localStorage.getItem('auth_user') || '').trim())"),
                "login_state_probe",
            )
        except TimeoutError:
            raise
        except Exception:
            lingering = False
        return not bool(lingering)

    opened = False
    for _ in range(3):
        if loop.time() >= work_deadline:
            break
        if await _open_login_and_confirm():
            opened = True
            break
        if loop.time() >= work_deadline:
            break
        await _bounded_login(
            page.wait_for_timeout(min(max(opts.poll_interval_ms, 300), _login_timeout(800))),
            "login_page_retry_wait",
        )

    if not opened:
        screenshot = await _login_screenshot(f"{spec.screenshot_prefix}-login-form-unavailable.png")
        if spec.strict_checkin:
            return helpers.error(
                f"{name}登录页未能就绪，请稍后重试",
                {"target_url": resolved_url, "login_fallback": "login_page_unavailable", "screenshot": screenshot},
            ).as_reason("unconfirmed")
        return helpers.need_config(
            f"{name}登录页持续被重定向，无法进入登录表单（登录态残留未清除）",
            {
                "target_url": resolved_url,
                "login_fallback": "login_page_unavailable",
                "screenshot": screenshot,
            },
        )

    # 轮询等待登录表单渲染（SPA 首次进入 /login 时密码框异步挂载）。
    # 每轮先关掉「使用说明」模态框，否则它遮住表单，填写会失败；这里继续使用
    # work_deadline，不能因为进入表单阶段就重新获得一份完整 login_timeout_ms。
    form_filled = False
    while loop.time() < work_deadline:
        await _bounded_login(dismiss_notice(page), "dismiss_login_notice")
        if await _bounded_login(fill_login_form(page, email, password), "fill_login_form"):
            form_filled = True
            break
        if loop.time() >= work_deadline:
            break
        await _bounded_login(
            page.wait_for_timeout(min(max(opts.poll_interval_ms, 300), _login_timeout(800))),
            "login_form_retry_wait",
        )

    if not form_filled:
        screenshot = await _login_screenshot(f"{spec.screenshot_prefix}-login-form-unavailable.png")
        if spec.strict_checkin:
            return helpers.error(
                f"{name}登录页字段未在等待时间内就绪，请稍后重试",
                {"target_url": resolved_url, "login_fallback": "form_unavailable",
                 "login_timeout_ms": form_wait_ms, "screenshot": screenshot},
            ).as_reason("unconfirmed")
        return helpers.need_config(
            f"{name}登录页字段未就绪，无法自动填写邮箱和密码",
            {"target_url": resolved_url, "login_fallback": "form_unavailable", "screenshot": screenshot},
        )

    # 公开配置明确关闭验证码时不能等待不存在的 widget；未知/开启均保留原验证流程。
    await _bounded_login(dismiss_notice(page), "dismiss_login_notice_before_submit")
    token = ""
    setting: bool | None
    try:
        setting = await _bounded_login(_login_turnstile_enabled(page, origin), "read_turnstile_setting")
    except TimeoutError:
        setting = None
    if setting is False:
        log(helpers, "站点公开配置已关闭登录 Turnstile，直接提交一次账密登录")
    else:
        log(helpers, "等待 Cloudflare Turnstile 令牌（必要时真实点击复选框）...")
        remaining = max(0.0, work_deadline - loop.time())
        if remaining <= 0:
            screenshot = await _login_screenshot(f"{spec.screenshot_prefix}-turnstile-timeout.png")
            return helpers.need_verification(
                f"{name}登录验证预算已耗尽，未提交账号密码。"
                "验证码可能尚未加载、正在验证或需要人工操作；不能仅凭超时判断出口 IP 被封禁。",
                {"target_url": resolved_url, "login_fallback": "login_timeout",
                 "login_timeout_ms": form_wait_ms, "turnstile_reason": "deadline_exceeded",
                 "screenshot": screenshot},
            )
        try:
            solved = await _bounded_login(
                helpers.solve(
                    "turnstile",
                    budget=remaining,
                    poll_interval_ms=opts.poll_interval_ms,
                ),
                "turnstile_solve",
            )
        except TimeoutError:
            solved = None
        token = str(getattr(solved, "value", "") or "").strip()
        if not token:
            reason = str(getattr(solved, "reason", "") or "") if solved is not None else "timeout"
            log(helpers, f"Turnstile 未在剩余登录预算内签发令牌（reason={reason or '未知'}）")
            screenshot = await _login_screenshot(f"{spec.screenshot_prefix}-turnstile-timeout.png")
            return helpers.need_verification(
                f"{name} Cloudflare Turnstile 未能自动签发令牌，登录中止。"
                "验证码可能尚未加载、正在验证或需要人工操作；不能仅凭超时判断出口 IP 被封禁。"
                "请检查站点验证提示或在有头浏览器完成验证后重试。",
                {
                    "target_url": resolved_url,
                    "login_fallback": "turnstile_timeout",
                    "login_timeout_ms": form_wait_ms,
                    "turnstile_reason": reason or "timeout",
                    "screenshot": screenshot,
                },
            )

    # 人工完成 Turnstile 后页面可能还在同步表单状态；给前端一个很短的稳定窗口，
    # 避免刚读到令牌就提交导致站点仍拿到旧表单值。该窗口也受同一截止点约束。
    try:
        await _bounded_login(
            page.wait_for_timeout(min(max(opts.poll_interval_ms, 50), _login_timeout(250))),
            "turnstile_stabilize",
        )
    except TimeoutError:
        return helpers.need_verification(
            f"{name}登录验证后剩余预算不足，未提交账号密码。",
            {"target_url": resolved_url, "login_fallback": "login_timeout",
             "login_timeout_ms": form_wait_ms, "turnstile_reason": "deadline_exceeded"},
        )
    stash_key = session_stash_key(spec.login_reset_sentinel)
    try:
        result = await _bounded_login(
            submit_login(page, origin, email, password, token, stash_key, spec.turnstile_field_name),
            "submit_login",
        )
    except TimeoutError:
        return helpers.need_verification(
            f"{name}登录请求未能在预算内完成，未确认登录结果。",
            {"target_url": resolved_url, "login_fallback": "login_timeout",
             "login_timeout_ms": form_wait_ms},
        )
    status = int((result or {}).get("status") or 0)
    if bool((result or {}).get("two_factor")):
        return helpers.need_login(
            f"{name}账号启用了两步验证，需先在浏览器中完成验证码登录后重新捕获 browser_state",
            {"target_url": resolved_url, "login_fallback": "two_factor", "response_status": status},
        )
    if not bool((result or {}).get("ok")):
        detail = "" if spec.strict_checkin else str((result or {}).get("message") or "")
        log(helpers, f"登录接口未成功：HTTP {status or 0}{'，' + detail if detail else ''}")
        if not status:
            # HTTP 0 常见于 Turnstile 回调已触发站点自身的表单提交、页面正在导航；
            # 站点若已自行登录成功，/auth/me 会通过，直接沿用即可。
            try:
                await _bounded_login(
                    page.wait_for_load_state("domcontentloaded", timeout=_login_timeout(opts.ready_timeout)),
                    "login_navigation_after_submit",
                )
            except TimeoutError:
                pass
            except Exception:
                pass
            try:
                authenticated_now = await _bounded_login(
                    authenticated(page, origin), "auth_probe_after_navigation"
                )
            except TimeoutError:
                authenticated_now = False
            if authenticated_now:
                log(helpers, "站点自身已完成登录（登录接口调用被导航打断），沿用当前登录态")
                result = {"ok": True, "status": status}
    if not bool((result or {}).get("ok")):
        if status in {400, 403, 429}:
            return helpers.need_verification(
                f"{name}登录未通过验证（HTTP {status or 0}）",
                {"target_url": resolved_url, "login_fallback": "login_rejected", "response_status": status},
            )
        return helpers.need_login(
            f"{name}账号密码登录失败（HTTP {status or 0}）",
            {"target_url": resolved_url, "login_fallback": "login_failed", "response_status": status},
        )

    auth_probe: dict[str, Any] = {}
    try:
        auth_confirmed = await _bounded_login(
            _authenticated_with_probe(page, origin, auth_probe), "auth_confirmation"
        )
    except TimeoutError:
        auth_probe.update(reason="network_error", status=0)
        auth_confirmed = False
    if not auth_confirmed:
        return _authentication_failure(
            helpers, spec, auth_probe,
            {"target_url": resolved_url, "login_fallback": "auth_verification_failed"},
        )

    log(helpers, "账密登录成功，已验证登录态")
    try:
        stashed = await _bounded_login(
            stash_session(page, stash_key, origin=origin, attempt=attempt), "stash_login_session"
        )
        marked = await _bounded_login(
            mark_login_done(page, spec.login_reset_sentinel, origin=origin, attempt=attempt),
            "mark_login_done",
        )
    except TimeoutError:
        stashed = marked = False
    if not stashed or not marked:
        return helpers.error(
            f"{name}登录已验证，但导航保护未能确认，停止导航以保留当前会话",
            {"target_url": resolved_url, "login_fallback": "session_guard_unconfirmed"},
        ).as_reason("unconfirmed")
    try:
        await _bounded_login(
            add_init_script(page, session_restore_init_script(
                stash_key, origin=origin, sentinel=spec.login_reset_sentinel, attempt=attempt,
            )),
            "install_session_restore_guard",
        )
    except TimeoutError:
        return helpers.error(
            f"{name}登录已验证，但会话保护未能在预算内安装，停止导航以保留当前会话",
            {"target_url": resolved_url, "login_fallback": "session_guard_unconfirmed"},
        ).as_reason("unconfirmed")
    log(helpers, "本次登录态保护已确认（同源、尝试隔离，不依赖初始化脚本顺序）")

    # 先保存在当前浏览器；导航后的统一确认通过后，再由调用方交接正式凭据。
    login_detail.update(
        {
            "login_fallback": "password",
            "login_response_status": status,
            "auth_verified": True,
        }
    )
    return None


# ── API 签到兜底 ────────────────────────────────────────────────────────────

def _checkin_flag(value: Any) -> bool | None:
    """接口布尔值只接受明确的真假，不能把字符串 'false' 当真。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        return {"true": True, "false": False, "1": True, "0": False}.get(value.strip().casefold())
    return None


def _checkin_number(data: dict[str, Any], *keys: str) -> float | None:
    from math import isfinite

    for key in keys:
        value = _as_number(data.get(key))
        if value is not None and isfinite(value):
            return value
    return None


def _checkin_failure(reason: str, status: int = 0) -> dict[str, Any]:
    return {"ok": False, "already": False, "reason": reason, "status": status}


def _checkin_reason(raw: Any, status: int) -> str:
    """只用服务端文案分类，不把可能回显凭据的原始内容带入结果或日志。"""
    text = ""
    if isinstance(raw, dict):
        data = raw.get("data")
        for part in (raw, data if isinstance(data, dict) else {}):
            text += " ".join(str(part.get(key) or "") for key in ("code", "message", "error")) + " "
    text = text.casefold()
    if status == 401 or any(word in text for word in ("unauthorized", "token_expired", "token expired", "未登录")):
        return "need_login"
    if any(word in text for word in ("turnstile", "captcha", "verification", "验证码", "人机验证")):
        return "need_verification"
    if status == 0 or status == 429 or status >= 500:
        return "network_error"
    return "checkin_failed"


def _strict_checkin_response(raw: Any, status: int = 200, *, state: bool = False) -> dict[str, Any]:
    """三条严格路径共用的白名单解析器：HTTP 成功不等于业务成功。"""
    if not 200 <= status < 300:
        return _checkin_failure(_checkin_reason(raw, status), status)
    if not isinstance(raw, dict) or not raw:
        return _checkin_failure("unconfirmed", status)
    data = raw.get("data", raw)
    affirmative = False
    for part in (raw, data if isinstance(data, dict) else {}):
        if part.get("error"):
            return _checkin_failure(_checkin_reason(raw, status), status)
        if "success" in part:
            if _checkin_flag(part["success"]) is not True:
                return _checkin_failure(_checkin_reason(raw, status), status)
            affirmative = True
        if "code" in part:
            code = part["code"]
            if isinstance(code, bool) or str(code).strip().casefold() not in {"0", "200", "ok", "success"}:
                return _checkin_failure(_checkin_reason(raw, status), status)
            affirmative = True
    if not isinstance(data, dict) or not data:
        return _checkin_failure("unconfirmed", status)
    checked = _checkin_flag(data.get("checked_in_today", data.get("today_checked")))
    already = _checkin_flag(data.get("already_checked_in", raw.get("already_checked_in"))) is True
    reward = _checkin_number(data, "reward_amount", "balance_added", "today_reward", "reward", "amount")
    result = {
        "ok": True,
        "already": checked is True if state else already,
        "status": status,
        "balance": _checkin_number(data, "balance", "free_balance", "remaining", "current_balance"),
        "reward": reward,
        "checked_in_today": checked,
    }
    if state:
        result.update({
            "enabled": _checkin_flag(data.get("enabled")),
            "turnstile_required": _checkin_flag(data.get("turnstile_required")),
            "turnstile_site_key": data.get("turnstile_site_key") if isinstance(data.get("turnstile_site_key"), str) else "",
            "today_reward": reward,
            "current_streak": _checkin_number(data, "current_streak"),
            "total_check_in_days": _checkin_number(data, "total_check_in_days"),
        })
        if checked is None and result["enabled"] is not False:
            return _checkin_failure("unconfirmed", status)
    elif not (affirmative or already or checked is True or reward is not None):
        return _checkin_failure("unconfirmed", status)
    return result


def _strict_preflight(state: dict[str, Any]) -> dict[str, Any] | None:
    if state.get("ok") is not True:
        return state or _checkin_failure("unconfirmed")
    if state.get("checked_in_today") is True:
        return {**state, "already": True}
    if state.get("enabled") is False:
        return _checkin_failure("not_open", int(state.get("status") or 0))
    if state.get("turnstile_required") not in (True, False):
        return _checkin_failure("unconfirmed", int(state.get("status") or 0))
    return None


def _confirm_strict_checkin(result: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    if state.get("ok") is not True or state.get("checked_in_today") is not True:
        return _checkin_failure(state.get("reason") or "unconfirmed", int(state.get("status") or 0))
    return {
        **result,
        "checked_in_today": True,
        "balance": result.get("balance") if result.get("balance") is not None else state.get("balance"),
    }


def _strict_browser_outcome(helpers: Any, spec: SiteSpec, result: dict[str, Any], detail: dict[str, Any]) -> Any:
    detail = {**detail, "response_status": result.get("status", 0)}
    if result.get("ok") is True:
        detail["checked_in_today"] = True
        if result.get("already") is True:
            return helpers.already_done("今日已签到", detail, quota=result.get("balance"))
        return helpers.success(spec.success_message, detail, quota=result.get("balance"), awarded=result.get("reward"))
    reason = result.get("reason") or "unconfirmed"
    if reason == "need_login":
        return helpers.need_login(f"{spec.site_label}签到登录态已失效，自动刷新未能恢复", detail)
    if reason == "need_verification":
        return helpers.need_verification(f"{spec.site_label}签到需要 Turnstile 验证，本次未能完成", detail)
    if reason == "not_open":
        return helpers.not_open(f"{spec.site_label}签到功能未开放", detail)
    return helpers.error(f"{spec.site_label}签到未获服务端确认", detail).as_reason(reason)


async def _strict_browser_checkin(
    page: Any, helpers: Any, spec: SiteSpec, opts: ScriptOptions, origin: str, detail: dict[str, Any],
) -> Any:
    state = await query_status(page, spec, origin)
    early = _strict_preflight(state)
    if early is not None:
        return _strict_browser_outcome(helpers, spec, early, detail)
    token = ""
    if state.get("turnstile_required") is True:
        await dismiss_notice(page)
        log(helpers, "签到需要 Turnstile 验证，等待站点正常签发令牌")
        try:
            solved = await helpers.solve("turnstile", budget=opts.login_timeout_ms / 1000)
            value = getattr(solved, "value", None)
            if getattr(solved, "ok", True) is not False and isinstance(value, str):
                token = value.strip()
        except Exception:
            pass
        if not token:
            return _strict_browser_outcome(helpers, spec, _checkin_failure("need_verification"), detail)
    result = await api_checkin(page, spec, origin, turnstile_token=token)
    return _strict_browser_outcome(helpers, spec, result or _checkin_failure("unconfirmed"), detail)


def _api_checkin_js(checkin_path: str, strict_checkin: bool = False) -> str:
    """生成调用站点签到接口的 JS。各 fork 端点不同，由 SiteSpec 指定。"""
    if strict_checkin:
        # token 只通过 evaluate 参数传入，避免拼进脚本/异常消息；沿用同一鉴权刷新器。
        operation = """
    try {
        const response = await requestWithAuth((accessToken) => fetch(baseUrl + %s, {
            method: 'POST', credentials: 'include',
            headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json', 'Content-Type': 'application/json' },
            body: JSON.stringify({turnstile_token: turnstileToken || ''}),
        }));
        return response ? {status: response.status, raw: await parseBody(response)} : {status: 401, raw: null};
    } catch (_) { return {status: 0, raw: null}; }
""" % json.dumps(checkin_path)
        return ("async ({origin: baseUrl, turnstile_token: turnstileToken}) => {\n"
                + _PAGE_AUTH_REQUEST_HELPERS_JS + operation + "\n}")
    return _page_auth_script(
        """
    const doCheckin = (accessToken) => fetch(baseUrl + '%s', {
        method: 'POST',
        credentials: 'include',
        headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/json',
            'Content-Type': 'application/json',
        },
        body: '{}',
    });
    const readOutcome = async (response) => {
        const raw = await parseBody(response);
        const payload = raw && typeof raw.data === 'object' && raw.data ? raw.data : raw;
        const code = raw && typeof raw === 'object'
            ? String(raw.code ?? (payload && payload.code) ?? '')
            : '';
        const message = raw && typeof raw === 'object'
            ? String(raw.message || raw.detail || (payload && payload.message) || '')
            : '';
        const checkedFlag = Boolean(
            payload && (payload.checked_in_today || payload.today_checked)
        );
        const already = response.status === 409
            || checkedFlag
            || /已签到|今日已|already/i.test(message + ' ' + code);
        const businessOk = !raw || typeof raw !== 'object'
            ? response.ok
            : raw.success !== false && !(/^[1-9]\\d*$/.test(code));
        // 站点签到响应通常带 reward_amount / balance（实测极速蹬回
        // {"reward_amount":0.5,"balance_added":0.5,"streak_count":2}）。
        // 回传它们，让脚本结果能直接携带额度，无需再多打一次查询接口。
        const pickNum = (v) => (typeof v === 'number' && isFinite(v)) ? v : null;
        const reward = pickNum(payload && (payload.reward_amount ?? payload.balance_added ?? payload.today_reward));
        const balance = pickNum(payload && (payload.balance ?? payload.remaining ?? payload.current_balance));
        return {
            ok: Boolean(response.ok && businessOk && !already),
            status: response.status,
            reward,
            balance,
            already,
            code: code.slice(0, 80),
            message: message.replace(/[\\r\\n]/g, ' ').slice(0, 160),
        };
    };
    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    try {
        let response = await requestWithAuth(doCheckin);
        if (!response) {
            return { ok: false, status: 401, already: false, code: 'NO_TOKEN', message: '' };
        }
        let outcome = await readOutcome(response);
        // 502/503/504 等网关错误是服务端瞬时故障（非端点变更），重试至多两次。
        // 所有重试复用同一个 requester，因此整次签到最多 refresh 一次。
        for (let i = 0; i < 2 && outcome.status >= 502 && outcome.status <= 504; i++) {
            await sleep(1500 * (i + 1));
            response = await requestWithAuth(doCheckin);
            if (!response) break;
            outcome = await readOutcome(response);
        }
        return outcome;
    } catch (_) {
        return { ok: false, status: 0, already: false, code: 'FETCH_ERROR', message: '' };
    }
"""
        % checkin_path
    )


async def api_checkin(
    page: Any, spec: SiteSpec, origin: str, turnstile_token: str | None = None,
) -> dict[str, Any] | None:
    """用已有登录态签到；严格模式先校验状态、验证码，再只提交一次并复查。

    三参数旧调用兼容。过期认证仍由共享 requestWithAuth 刷新，不重新账密登录。
    """
    if spec.strict_checkin:
        state = await query_status(page, spec, origin)
        early = _strict_preflight(state)
        if early is not None:
            return early
        token = turnstile_token.strip() if isinstance(turnstile_token, str) else ""
        if state.get("turnstile_required") is True and not token:
            return _checkin_failure("need_verification", int(state.get("status") or 0))
        try:
            response = await page.evaluate(
                _api_checkin_js(spec.checkin_path, True),
                {"origin": origin, "turnstile_token": token},
            )
        except Exception:
            return _checkin_failure("network_error")
        if not isinstance(response, dict):
            return _checkin_failure("unconfirmed")
        status = int(response.get("status") or 0)
        result = _strict_checkin_response(response.get("raw"), status)
        if status == 409:
            confirmed = await query_status(page, spec, origin)
            if confirmed.get("ok") is True and confirmed.get("checked_in_today") is True:
                return {**confirmed, "already": True}
        if result.get("ok") is not True:
            return result
        return _confirm_strict_checkin(result, await query_status(page, spec, origin))
    try:
        result = await page.evaluate(_api_checkin_js(spec.checkin_path), origin)
        return result if isinstance(result, dict) else None
    except Exception:
        return None


def _query_status_js(status_path: str, strict_checkin: bool = False) -> str:
    """生成只读状态查询脚本：GET 站点自己的签到状态端点。

    端点选择经实测确定：百倍的 GET /api/v1/check-in/status 稳定返回
    {"data":{"checked_in_today":true,"today_reward":5,"balance":897,...}}，
    而 /api/v1/user/profile 实测读超时（HTTP 0）。签到状态端点本就是这条链路的
    自然数据源，余额、今日奖励、连续天数一次拿齐，无需再猜别的端点。

    不签到；共享鉴权器可正常续期。兼容模式失败返回 null，严格模式保留 HTTP
    状态与 JSON 信封，交给 Python 的共用解析器校验业务状态。
    """
    if strict_checkin:
        return _page_auth_script("""
    try {
        const response = await requestWithAuth((accessToken) => fetch(baseUrl + %s, {
            credentials: 'include', headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
        }));
        return response ? {status: response.status, raw: await parseBody(response)} : {status: 401, raw: null};
    } catch (_) { return {status: 0, raw: null}; }
""" % json.dumps(status_path))
    return _page_auth_script(
        """
    const num = (value) => (typeof value === 'number' && isFinite(value)) ? value : null;
    const flag = (value) => value === true || value === 1 || value === 'true' || value === '1'
        ? true : value === false || value === 0 || value === 'false' || value === '0' ? false : null;
    try {
        const response = await requestWithAuth((accessToken) => fetch(baseUrl + '%s', {
            credentials: 'include',
            headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
        }));
        if (!response || !response.ok) return null;
        const raw = await parseBody(response);
        const data = raw && typeof raw.data === 'object' && raw.data ? raw.data : raw;
        if (!data || typeof data !== 'object') return null;
        return {
            balance: num(data.balance ?? data.free_balance ?? data.remaining ?? data.current_balance),
            today_reward: num(data.today_reward ?? data.reward_amount),
            checked_in_today: flag(data.checked_in_today ?? data.today_checked),
            enabled: flag(data.enabled),
            turnstile_required: flag(data.turnstile_required),
            turnstile_site_key: typeof data.turnstile_site_key === 'string' ? data.turnstile_site_key : '',
            current_streak: num(data.current_streak),
            total_check_in_days: num(data.total_check_in_days),
        };
    } catch (_) {
        return null;
    }
"""
        % status_path
    )


def origin_of(url: str) -> str:
    """从任意站内 URL 取出 scheme://host 形式的 origin。

    只为省掉给 wait_for_checkin_control 加一个 origin 参数：调用方本来就把
    resolved_url 传进来了，而页内 fetch 只需要 origin。
    """
    text = str(url or "").strip()
    scheme, sep, rest = text.partition("://")
    if not sep:
        return text.rstrip("/")
    return f"{scheme}://{rest.split('/', 1)[0]}"


async def query_status(page: Any, spec: SiteSpec, origin: str) -> dict[str, Any]:
    """查询签到状态及验证要求；严格模式同时返回 ok/status/reason，旧模式失败返回 {}。

    「今日已签到」由页面文案或按钮状态判定时（wait_for_checkin_control 的两个
    分支、点击后的 409），流程里没有任何签到响应可读，此前这类结果一律不带额度，
    GUI 与汇总只能显示「今日已签到」而看不到余额——而 API 路径同样场景会输出
    「今日已签=True 余额=$607.51」。补这一次只读查询让两条路径产出一致。
    """
    if not spec.status_path:
        return _checkin_failure("need_config") if spec.strict_checkin else {}
    try:
        data = await page.evaluate(_query_status_js(spec.status_path, spec.strict_checkin), origin)
    except Exception:
        return _checkin_failure("network_error") if spec.strict_checkin else {}
    if spec.strict_checkin:
        if not isinstance(data, dict):
            return _checkin_failure("unconfirmed")
        return _strict_checkin_response(data.get("raw"), int(data.get("status") or 0), state=True)
    return data if isinstance(data, dict) else {}


# ── 签到控件定位 ────────────────────────────────────────────────────────────
async def find_already_control(page: Any, spec: SiteSpec, opts: ScriptOptions) -> tuple[str, Any] | None:
    """找到表示「今日已签到」的控件；未命中返回 None。

    weak_already_texts 里的词（如 "today"）过于宽泛，只有在按钮被禁用时才采信，
    否则页面标题/日期里的 today 会被误判成已签到。
    """
    weak = {text.strip().casefold() for text in spec.weak_already_texts}
    for text in opts.already_texts:
        try:
            locator = page.get_by_role("button", name=text, exact=False).first
        except Exception:
            continue
        if not await is_visible(locator):
            continue
        if text.strip().casefold() not in weak or await is_disabled(locator):
            return text, locator
    return None


async def find_already_text(page: Any, spec: SiteSpec, opts: ScriptOptions) -> str:
    """在页面可见文本里找「已签到」提示；宽泛词不参与，避免误判。"""
    weak = {text.strip().casefold() for text in spec.weak_already_texts}
    for text in opts.already_texts:
        if text.strip().casefold() in weak:
            continue
        if await visible_text(page, text):
            return text
    return ""


async def find_checkin_control(page: Any, opts: ScriptOptions) -> tuple[str, Any, str] | None:
    """找到可见且未禁用的签到控件（不点击）；返回 (文案, locator, 控件类型)。

    按 button → link → 纯文本顺序尝试：先扫语义化控件，避免宽松文本候选点到
    页面标题；纯文本兜底兼容没有语义化标签的旧页面。
    """
    for role in ("button", "link"):
        for text in opts.checkin_texts:
            try:
                locator = page.get_by_role(role, name=text, exact=False).first
            except Exception:
                continue
            if not await is_visible(locator) or await is_disabled(locator):
                continue
            return text, locator, role
    for text in opts.checkin_texts:
        try:
            locator = page.get_by_text(text, exact=False).first
        except Exception:
            continue
        if not await is_visible(locator):
            continue
        return text, locator, "text"
    return None


async def page_control_snapshot(page: Any) -> list[dict[str, Any]]:
    """读取当前可见按钮/链接的脱敏快照，仅用于定位签到控件的过程日志。"""
    script = r"""() => Array.from(document.querySelectorAll('button, a[href]'))
        .slice(0, 30)
        .map((el) => ({
            tag: String(el.tagName || '').toLowerCase(),
            text: String(el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 80),
            disabled: Boolean(el.disabled || el.getAttribute('aria-disabled') === 'true'),
            hidden: !(el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden'),
        }))"""
    try:
        items = await page.evaluate(script)
    except Exception:
        return []
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def format_control_snapshot(items: list[dict[str, Any]]) -> str:
    """把控件快照压成一行，不输出 DOM/属性等无关信息。"""
    rendered: list[str] = []
    for item in items[:12]:
        text = str(item.get("text") or "").strip() or "<无文案>"
        flags: list[str] = []
        if bool(item.get("disabled")):
            flags.append("禁用")
        if bool(item.get("hidden")):
            flags.append("隐藏")
        suffix = f"/{'/'.join(flags)}" if flags else ""
        rendered.append(f"{item.get('tag') or 'control'}:「{text}」{suffix}")
    return "；".join(rendered) if rendered else "未读取到按钮/链接"


async def click_checkin(
    page: Any,
    helpers: Any,
    opts: ScriptOptions,
    initial: tuple[str, Any, str] | None = None,
) -> tuple[str, Any, str, str]:
    """多轮重新定位并点击，抵抗 SPA 重渲染、遮罩与元素抖动。

    逐级降级：普通点击 → force → dispatch_event → DOM click。元素可能在点击
    期间被前端替换，因此每轮都重新定位。返回 (文案, 元素, 类型, 生效策略)；
    全部失败返回空文案。
    """
    log(helpers, "开始点击签到按钮：最多重新定位 3 轮，每轮依次尝试 normal/force/dispatch/dom")
    for attempt in range(3):
        round_no = attempt + 1
        control = initial if attempt == 0 and initial is not None else await find_checkin_control(page, opts)
        if control is None:
            log(helpers, f"签到点击第 {round_no}/3 轮：未找到可点击控件，等待后重新定位")
            await page.wait_for_timeout(min(150, opts.poll_interval_ms))
            continue
        text, locator, kind = control
        log(helpers, f"签到点击第 {round_no}/3 轮：定位到「{text}」（{kind}）")
        try:
            element = await locator.element_handle()
        except Exception:
            element = None
        try:
            await locator.scroll_into_view_if_needed(timeout=opts.click_timeout)
            log(helpers, f"签到点击第 {round_no}/3 轮：控件已滚动到可视区域")
        except Exception as exc:
            log(helpers, f"签到点击第 {round_no}/3 轮：滚动定位未完成（{type(exc).__name__}），继续点击")
        strategies = (
            ("normal", lambda: locator.click(timeout=opts.click_timeout)),
            ("force", lambda: locator.click(timeout=opts.click_timeout, force=True)),
            ("dispatch", lambda: locator.dispatch_event("click")),
            ("dom", lambda: locator.evaluate("el => el.click()")),
        )
        for strategy, do_click in strategies:
            log(helpers, f"签到点击第 {round_no}/3 轮：尝试 {strategy} 策略")
            try:
                await do_click()
                log(helpers, f"签到点击第 {round_no}/3 轮：{strategy} 策略已触发点击事件")
                return text, element or locator, kind, strategy
            except Exception as exc:
                message = str(exc).replace("\r", " ").replace("\n", " ").strip()[:120]
                reason = f"{type(exc).__name__}: {message}" if message else type(exc).__name__
                log(helpers, f"签到点击第 {round_no}/3 轮：{strategy} 策略失败（{reason}）")
        log(helpers, f"签到点击第 {round_no}/3 轮：全部点击策略失败，准备重新定位控件")
        await page.wait_for_timeout(min(200, max(50, opts.poll_interval_ms)))
    log(helpers, "签到按钮点击流程结束：3 轮均未能触发点击")
    return "", None, "", ""


# ── 页面就绪 ────────────────────────────────────────────────────────────────
async def navigate_and_settle(page: Any, helpers: Any, target: str, opts: ScriptOptions) -> None:
    """导航到目标页并尽力等待 SPA 首屏数据落地。

    先等 domcontentloaded，再尽力等一次 networkidle：签到按钮要等前端 XHR 拉完
    数据才渲染，等待能显著降低「按钮刚要渲染、轮询窗口就到点」的竞态。两者
    超时都不致命，后续仍有 button_wait_ms 轮询兜底。
    """
    await helpers.goto(target, timeout=opts.goto_timeout, wait_until=opts.wait_until)
    for state, timeout in (
        ("domcontentloaded", opts.ready_timeout),
        ("networkidle", min(opts.ready_timeout, 8000)),
    ):
        try:
            await page.wait_for_load_state(state, timeout=timeout)
        except Exception:
            pass


# ── 纯 API 兜底 ─────────────────────────────────────────────────────────────
async def api_fallback(
    page: Any,
    helpers: Any,
    spec: SiteSpec,
    opts: ScriptOptions,
    origin: str,
    resolved_url: str,
    login_attempted: bool,
    do_login: Any,
    extra_detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """SPA 未渲染签到按钮时的接口兜底（含一次账密登录重试）。

    页面没渲染 ≠ 需要人工签到：登录态有效时直接打站点签到接口。401/403 或
    HTTP 0（页面空白导致 fetch 发不出）说明会话确实无效，此时若还没试过账密
    登录就登录一次并重试；login_attempted 守卫确保只重试一次，不会死循环。
    """
    if spec.strict_checkin:
        return await _strict_browser_checkin(
            page, helpers, spec, opts, origin,
            {"target_url": resolved_url, "completion_signal": "api_fallback", **dict(extra_detail or {})},
        )
    log(helpers, f"页面未渲染签到按钮，改用接口兜底 POST {spec.checkin_path}")
    result = await api_checkin(page, spec, origin)
    status = int((result or {}).get("status") or 0)
    log(helpers, f"签到接口返回 HTTP {status or 0}")
    detail = {
        "target_url": resolved_url,
        "completion_signal": "api_fallback",
        "response_status": status,
        **dict(extra_detail or {}),
    }
    # 签到接口通常回传 balance / reward_amount，透出去让 GUI 与汇总直接显示额度，
    # 免得「签到成功」却看不到到账多少（此前这些数字被丢弃）。
    quota = (result or {}).get("balance")
    awarded = (result or {}).get("reward")
    if bool((result or {}).get("already")):
        return helpers.already_done("今日已签到", detail, quota=quota)
    if bool((result or {}).get("ok")):
        return helpers.success(spec.success_message, detail, quota=quota, awarded=awarded)

    if (status in {401, 403} or status == 0) and not login_attempted:
        login_result = await do_login()
        if login_result is not None:
            return login_result
        retry = await api_checkin(page, spec, origin)
        status = int((retry or {}).get("status") or 0)
        detail = {
            "target_url": resolved_url,
            "completion_signal": "api_fallback_after_login",
            "response_status": status,
            **dict(extra_detail or {}),
        }
        retry_quota = (retry or {}).get("balance")
        retry_awarded = (retry or {}).get("reward")
        if bool((retry or {}).get("already")):
            return helpers.already_done("今日已签到", detail, quota=retry_quota)
        if bool((retry or {}).get("ok")):
            return helpers.success(spec.success_message, detail, quota=retry_quota, awarded=retry_awarded)

    if status in {401, 403}:
        return helpers.need_login(f"{spec.site_label}签到登录态已失效，请重新捕获 browser_state", detail)

    screenshot = await helpers.screenshot(f"{spec.screenshot_prefix}-no-checkin-button.png")
    return helpers.need_config(
        f"{spec.site_label}页面未渲染签到按钮，且签到接口不可用（HTTP {status or 0}）",
        {
            "checkin_texts": opts.checkin_texts,
            "target_url": resolved_url,
            "button_wait_ms": opts.button_wait_ms,
            "response_status": status,
            "screenshot": screenshot,
            # 带上登录诊断（含 auth_verified）：本站签到入口失效不代表登录失败，
            # 已验证的登录态不该因为这个结论被丢弃。
            **dict(extra_detail or {}),
        },
    )


async def click_and_confirm(
    page: Any,
    helpers: Any,
    spec: SiteSpec,
    opts: ScriptOptions,
    control: tuple[str, Any, str],
    *,
    resolved_url: str,
    extra_detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """点击签到控件并轮询确认完成信号。

    点击与确认必须放在一起：SPA 会在「发现按钮」和「点击按钮」之间重渲染 DOM，
    点击器需重新定位并逐级降级；确认阶段也要多路取证，只认可信信号，避免把
    「按钮文案变成 Loading」这类中间态误判为签到成功。

    完成信号（按可信度排序）：
    1. 签到接口响应状态码（最可信，直接来自服务端）；
    2. 页面出现成功文案；
    3. 按钮切换为「已签到」状态或已签文案出现；
    4. 按钮消失。
    全部拿不到则返回 error 并截图，不谎报成功。
    """
    base_extra = dict(extra_detail or {})
    if spec.strict_checkin:
        state = await query_status(page, spec, origin_of(resolved_url))
        early = _strict_preflight(state)
        detail = {"target_url": resolved_url, "completion_signal": "checkin_status", **base_extra}
        if early is not None:
            return _strict_browser_outcome(helpers, spec, early, detail)
        if state.get("turnstile_required") is True:
            return await _strict_browser_checkin(page, helpers, spec, opts, origin_of(resolved_url), detail)
    response: dict[str, Any] = {}
    body_tasks: list[Any] = []

    async def _read_amounts(item: Any) -> None:
        """读签到响应体里的 reward_amount / balance，写进 response。

        点击路径此前只记录 status/url、从不读 body，站点明明回了
        {"reward_amount":0.5,"balance":26.55} 也全被丢掉，结果只能显示
        「签到成功」而无额度——api_fallback 路径早就在读这些字段了，两条路径
        的产出不一致。读 body 失败一律忽略：额度是附加信息，不能影响签到结论。
        """
        try:
            payload = await item.json()
        except Exception:
            if spec.strict_checkin:
                response.update(_checkin_failure("unconfirmed", int(getattr(item, "status", 0) or 0)))
                response["body_read"] = True
            return
        if spec.strict_checkin:
            response.update(_strict_checkin_response(payload, int(getattr(item, "status", 0) or 0)))
            response["body_read"] = True
            return
        data = payload.get("data") if isinstance(payload, dict) else None
        source = data if isinstance(data, dict) else payload
        if not isinstance(source, dict):
            return

        def _num(*keys: str) -> float | None:
            for key in keys:
                value = source.get(key)
                if isinstance(value, bool) or value is None:
                    continue
                if isinstance(value, (int, float)):
                    return float(value)
            return None

        reward = _num("reward_amount", "balance_added", "today_reward", "quota_awarded")
        balance = _num("balance", "remaining", "current_balance", "current_quota")
        if reward is not None:
            response["reward"] = reward
        if balance is not None:
            response["balance"] = balance

    def _capture(item: Any) -> None:
        try:
            request = getattr(item, "request", None)
            if str(getattr(request, "method", "") or "").upper() != "POST":
                return
            url = str(getattr(item, "url", "") or "")
            lowered = url.casefold()
            if spec.strict_checkin:
                from urllib.parse import urlsplit

                parsed = urlsplit(url)
                expected = urlsplit(origin_of(resolved_url) + spec.checkin_path)
                if (parsed.scheme, parsed.netloc, parsed.path) != (expected.scheme, expected.netloc, expected.path):
                    return
            elif not any(marker in lowered for marker in spec.response_match):
                return
            if any(bad in lowered for bad in spec.response_exclude):
                return
            captured_status = int(getattr(item, "status", 0) or 0)
            response.update({"status": captured_status, "url": url})
            safe_url = url.split("?", 1)[0]
            log(helpers, f"捕获签到 POST 响应：HTTP {captured_status or 0} {safe_url}")
            # 监听回调是同步的，读 body 必须 await：丢到后台任务里，轮询循环
            # 每轮都会看一眼是否已填好额度。
            body_tasks.append(asyncio.ensure_future(_read_amounts(item)))
        except Exception:
            return

    listener_registered = False
    try:
        page.on("response", _capture)
        listener_registered = True
    except Exception:
        pass

    try:
        clicked_text, clicked_locator, clicked_kind, strategy = await click_checkin(
            page, helpers, opts, initial=control
        )
        if clicked_text:
            log(helpers, f"已点击签到控件「{clicked_text}」（{clicked_kind} / {strategy}），等待完成信号...")
        if not clicked_text:
            screenshot = await helpers.screenshot(f"{spec.screenshot_prefix}-click-failed.png")
            return helpers.error(
                "定位到签到按钮但点击失败，请稍后重试",
                {
                    "checkin_texts": opts.checkin_texts,
                    "target_url": resolved_url,
                    "screenshot": screenshot,
                    **base_extra,
                },
            )

        base_detail = {
            "clicked_text": clicked_text,
            "clicked_kind": clicked_kind,
            "click_strategy": strategy,
            "target_url": resolved_url,
            **base_extra,
        }

        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0, opts.completion_timeout_ms) / 1000

        async def _settle_amounts() -> None:
            """等已派发的 body 读取任务收尾，让额度尽量赶上本次返回。"""
            if not body_tasks:
                return
            pending = [task for task in body_tasks if not task.done()]
            if not pending:
                return
            try:
                await asyncio.wait(pending, timeout=2)
            except Exception:
                pass

        while True:
            status = int(response.get("status", 0) or 0)
            if spec.strict_checkin:
                await _settle_amounts()
                detail = {**base_detail, "completion_signal": "checkin_response" if response else "checkin_status"}
                if response:
                    if not response.get("body_read"):
                        return _strict_browser_outcome(helpers, spec, _checkin_failure("unconfirmed", status), detail)
                    if response.get("ok") is True:
                        confirmed = await query_status(page, spec, origin_of(resolved_url))
                        return _strict_browser_outcome(helpers, spec, _confirm_strict_checkin(response, confirmed), detail)
                    if status != 409:
                        return _strict_browser_outcome(helpers, spec, response, detail)
                confirmed = await query_status(page, spec, origin_of(resolved_url))
                if confirmed.get("ok") is True and confirmed.get("checked_in_today") is True:
                    return _strict_browser_outcome(helpers, spec, {**confirmed, "already": status == 409}, detail)
                if response:
                    return _strict_browser_outcome(helpers, spec, response, detail)
                if confirmed.get("reason"):
                    return _strict_browser_outcome(helpers, spec, confirmed, detail)
                if loop.time() >= deadline:
                    return _strict_browser_outcome(helpers, spec, _checkin_failure("unconfirmed"), detail)
                remaining_ms = max(1, int((deadline - loop.time()) * 1000))
                await page.wait_for_timeout(min(max(opts.poll_interval_ms, 300), remaining_ms))
                continue
            if 200 <= status < 300:
                log(helpers, f"签到完成信号：监听到签到接口成功响应 HTTP {status}")
                await _settle_amounts()
                return helpers.success(
                    spec.success_message,
                    {
                        **base_detail,
                        "completion_signal": "checkin_response",
                        "response_status": status,
                        "response_url": response.get("url", ""),
                    },
                    quota=response.get("balance"),
                    awarded=response.get("reward"),
                )
            if status == 409:
                log(helpers, "签到完成信号：接口返回 HTTP 409，服务端确认今日已签到")
                # 409 = 今日已签到。响应体里可能就带余额；没有则补一次只读状态查询，
                # 让「已签到」结果也能报出余额，与 API 路径的产出保持一致。
                await _settle_amounts()
                balance = response.get("balance")
                extra: dict[str, Any] = {}
                if balance is None:
                    info = await query_status(page, spec, origin_of(resolved_url))
                    balance = info.get("balance")
                    if info.get("current_streak") is not None:
                        extra["consecutive_days"] = info["current_streak"]
                    if info.get("total_check_in_days") is not None:
                        extra["total_checkins"] = info["total_check_in_days"]
                return helpers.already_done(
                    "今日已签到",
                    {
                        **base_detail,
                        "completion_signal": "checkin_response",
                        "response_status": status,
                        **extra,
                    },
                    quota=balance,
                )
            if status >= 400:
                log(helpers, f"签到完成信号：接口返回错误 HTTP {status}")
                return helpers.error(
                    f"签到接口返回错误（HTTP {status}）",
                    {
                        **base_detail,
                        "completion_signal": "checkin_response",
                        "response_status": status,
                        "response_url": response.get("url", ""),
                    },
                )

            # 以下几路信号同样带上额度：签到响应可能已经回来（body 里有
            # reward_amount/balance），只是状态码分支恰好没命中（例如成功文案
            # 先渲染出来）。不带的话同一次签到会因命中的信号不同而时有时无额度。
            for text in opts.success_texts:
                if await visible_text(page, text):
                    log(helpers, f"签到完成信号：页面出现成功文案「{text}」")
                    await _settle_amounts()
                    return helpers.success(
                        spec.success_message,
                        {**base_detail, "completion_signal": "success_text", "matched_text": text},
                        quota=response.get("balance"),
                        awarded=response.get("reward"),
                    )

            already_control = await find_already_control(page, spec, opts)
            if already_control:
                text, _locator = already_control
                log(helpers, f"签到完成信号：按钮切换为已签到状态「{text}」")
                await _settle_amounts()
                return helpers.success(
                    spec.success_message,
                    {**base_detail, "completion_signal": spec.signal_already_control, "matched_text": text},
                    quota=response.get("balance"),
                    awarded=response.get("reward"),
                )

            matched_already = await find_already_text(page, spec, opts)
            if matched_already:
                log(helpers, f"签到完成信号：页面出现已签到文案「{matched_already}」")
                await _settle_amounts()
                return helpers.success(
                    spec.success_message,
                    {**base_detail, "completion_signal": spec.signal_post_click_text, "matched_text": matched_already},
                    quota=response.get("balance"),
                    awarded=response.get("reward"),
                )

            if clicked_locator is not None and not await is_visible(clicked_locator):
                log(helpers, "签到完成信号：原签到控件已从页面隐藏/移除")
                await _settle_amounts()
                return helpers.success(
                    spec.success_message,
                    {**base_detail, "completion_signal": "button_hidden"},
                    quota=response.get("balance"),
                    awarded=response.get("reward"),
                )

            if loop.time() >= deadline:
                break
            remaining_ms = max(1, int((deadline - loop.time()) * 1000))
            await page.wait_for_timeout(min(opts.poll_interval_ms, remaining_ms))

        log(
            helpers,
            f"签到确认超时：点击后等待 {opts.completion_timeout_ms}ms，"
            "未捕获接口响应、成功文案、已签到状态或按钮消失",
        )
        screenshot = await helpers.screenshot(f"{spec.screenshot_prefix}-after-click.png")
        return helpers.error(
            "已点击签到按钮，但未检测到签到完成信号",
            {
                **base_detail,
                "completion_timeout_ms": opts.completion_timeout_ms,
                "screenshot": screenshot,
            },
        )
    finally:
        if listener_registered:
            try:
                page.remove_listener("response", _capture)
            except Exception:
                pass
        # 取消仍在读 body 的后台任务：页面即将关闭，未 await 的任务会在事件循环
        # 收尾时抛「Task was destroyed but it is pending」噪声日志。
        for task in body_tasks:
            if not task.done():
                task.cancel()


async def wait_for_checkin_control(
    page: Any,
    helpers: Any,
    spec: SiteSpec,
    opts: ScriptOptions,
    *,
    resolved_url: str,
    login_detail: dict[str, Any],
) -> tuple[tuple[str, Any, str] | None, dict[str, Any] | None]:
    """轮询等待「已签到状态」或「可点击的签到按钮」出现。

    SPA 的签到按钮要等前端拉完签到数据后才渲染，goto 完成时通常还没出现，
    立即扫描会扑空。返回 (签到控件, 提前结束的结果)：
    - 命中已签到状态 → (None, already_done 结果)，调用方直接返回；
    - 找到可点击按钮 → (控件, None)，调用方继续点击；
    - 超时都没等到 → (None, None)，调用方走 API 兜底。
    """
    log(helpers, f"等待签到按钮渲染（最多 {opts.button_wait_ms}ms）...")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0, opts.button_wait_ms) / 1000

    async def _already(matched_text: str, signal: str) -> dict[str, Any]:
        """组装「今日已签到」结果，并补上余额与连续天数。

        这两个分支是在点击签到之前由页面文案/控件状态判定的，手上没有任何签到
        响应可读，此前只能返回一句「今日已签到」而不带额度——同一个站点走 API
        路径时却能报出「今日已签=True 余额=$607.51」，两条路径的信息量不对等。
        这里主动查一次状态端点，查不到就照常返回（额度是附加信息，不影响结论）。
        """
        status = await query_status(page, spec, origin_of(resolved_url))
        if spec.strict_checkin and not (status.get("ok") is True and status.get("checked_in_today") is True):
            return None
        balance = status.get("balance")
        detail: dict[str, Any] = {
            "matched_text": matched_text,
            "completion_signal": signal,
            "target_url": resolved_url,
            **login_detail,
        }
        # 连续天数/累计签到与 API 路径用同一批标准键，汇总层直接就能展示。
        if status.get("current_streak") is not None:
            detail["consecutive_days"] = status["current_streak"]
        if status.get("total_check_in_days") is not None:
            detail["total_checkins"] = status["total_check_in_days"]
        if status.get("checked_in_today") is not None:
            detail["checked_in_today"] = bool(status["checked_in_today"])
        if balance is not None:
            log(helpers, f"今日已签到，当前余额 ${balance:.2f}")
        return helpers.already_done("今日已签到", detail, quota=balance)

    while True:
        already = await find_already_control(page, spec, opts)
        if already:
            text, _locator = already
            log(helpers, f"签到按钮扫描结果：发现已签到控件「{text}」，无需点击")
            return None, await _already(text, spec.signal_already_control)
        matched_text = await find_already_text(page, spec, opts)
        if matched_text:
            log(helpers, f"签到按钮扫描结果：页面已显示「{matched_text}」，无需点击")
            return None, await _already(matched_text, spec.signal_already_text)

        control = await find_checkin_control(page, opts)
        if control is not None:
            log(helpers, f"签到按钮扫描结果：发现可点击控件「{control[0]}」（{control[2]}）")
            return control, None

        if loop.time() >= deadline:
            snapshot = format_control_snapshot(await page_control_snapshot(page))
            log(helpers, f"签到按钮等待超时，当前页面控件快照：{snapshot}")
            return None, None
        remaining_ms = max(1, int((deadline - loop.time()) * 1000))
        await page.wait_for_timeout(min(opts.poll_interval_ms * 3, remaining_ms))


async def run_flow(ctx: Any, lease: Any, spec: SiteSpec) -> Any:
    """Sub2API 登录、导航后统一确认与签到；页面路由不代替服务端认证结论。"""
    from sdk import PageHelpers

    page = lease.page
    context = lease.context
    helpers = PageHelpers(ctx, lease, page)
    opts = parse_options(spec, ctx.args)
    start_target = opts.start_target or spec.default_start_path
    resolved_url = helpers.resolve_url(start_target)
    origin = origin_of(helpers.resolve_url("/"))
    login_detail: dict[str, Any] = {}

    async def do_login() -> Any:
        return await login_with_password(
            page, context, helpers, spec, opts, resolved_url=resolved_url,
            origin=origin, login_detail=login_detail,
        )

    stash_key = session_stash_key(spec.login_reset_sentinel)
    await add_init_script(context, preflight_init_script(
        stash_key, preserve_refresh=spec.strict_checkin, origin=origin,
    ))
    await navigate_and_settle(page, helpers, start_target, opts)
    login_attempted = False
    login_route = await on_login_page(page)
    verified = False
    initial_probe: dict[str, Any] = {}
    if spec.strict_checkin or not login_route:
        verified = await _authenticated_with_probe(page, origin, initial_probe)
        if not verified and initial_probe.get("reason") not in {None, "need_login"}:
            return _authentication_failure(helpers, spec, initial_probe, {"target_url": resolved_url})
    if not verified and (login_route or spec.strict_checkin):
        login_attempted = True
        failure = await do_login()
        if failure is not None:
            return failure
        login_detail.setdefault("auth_verified", True)
    if login_route or login_attempted:
        await navigate_and_settle(page, helpers, start_target, opts)
        if login_attempted:
            failure = await confirm_login_session(page, helpers, spec, origin, login_detail)
            if failure is not None:
                return failure
            verified = True

    if verified:
        login_detail["auth_verified"] = True
        await _record_new_tokens(page, helpers, ctx, origin)
        lease.mark_authenticated()
        if spec.strict_checkin:
            return await _strict_browser_checkin(
                page, helpers, spec, opts, origin,
                {"target_url": resolved_url, "completion_signal": "api_after_auth", **login_detail},
            )
        # 兼容模板仍保留原有 API 优先、页面按钮兜底，不将 DOM 当严格模式的成功证据。
        pre_result = await api_checkin(page, spec, origin)
        pre_status = int((pre_result or {}).get("status") or 0)
        if bool((pre_result or {}).get("already")):
            return helpers.already_done(
                "今日已签到",
                {"target_url": resolved_url, "completion_signal": "api_after_auth", **login_detail},
                quota=(pre_result or {}).get("balance"),
            )
        if bool((pre_result or {}).get("ok")):
            return helpers.success(
                spec.success_message,
                {"target_url": resolved_url, "completion_signal": "api_after_auth",
                 "response_status": pre_status, **login_detail},
                quota=(pre_result or {}).get("balance"), awarded=(pre_result or {}).get("reward"),
            )
        log(helpers, f"登录验证后 API 签到未成功（HTTP {pre_status}），改为等待页面按钮")

    control, early_result = await wait_for_checkin_control(
        page, helpers, spec, opts, resolved_url=resolved_url, login_detail=login_detail,
    )
    if early_result is not None:
        return early_result
    if control is None:
        return await api_fallback(
            page, helpers, spec, opts, origin=origin, resolved_url=resolved_url,
            login_attempted=login_attempted, do_login=do_login, extra_detail=login_detail,
        )
    return await click_and_confirm(
        page, helpers, spec, opts, control, resolved_url=resolved_url, extra_detail=login_detail,
    )


# ── 纯 HTTP 首选路径 ────────────────────────────────────────────────────────
async def http_attempt(ctx: Any, spec: SiteSpec) -> Any:
    """不启动浏览器，直接用已注入认证的 ``ctx.http`` 试一次签到，总是给出结论。

    为什么值得单独有这一步：token 仍然有效的日子里，一次 GET + 一次 POST 就能完成
    签到，而启动 Camoufox 要十几秒、在 CI 里还常撞上风控。访问链的 HTTP 步骤直接调用
    它，失败带着真实子结果交给引擎，由访问链决定是否回退到浏览器步骤。

    失败分两种，与拆分前 ``http_first`` 的两类返回一一对应：

    - 这条路没走通、应交给浏览器（旧实现返回 None）→ 普通失败，访问链会回退；
    - 已拿到服务端结论、换浏览器只会重复提交（旧实现直接返回失败）→ 用
      ``chain_final`` 标成终局，访问链不再回退。
    """
    from core.errors import TaskError
    from core.outcome import DisplaySpec, already_done, success
    from net.http import unwrap_data

    if not ctx.http.headers.get("Authorization"):
        ctx.log("没有可用的接口凭据，跳过纯 HTTP 首选路径")
        return _handoff("没有可用的接口凭据，纯 HTTP 签到未执行", reason="need_login")

    def _display(balance: Any, awarded: Any = None) -> DisplaySpec:
        text = ""
        value = _as_number(balance)
        if value is not None:
            text = f"${value:.2f}" if abs(value) >= 0.01 else f"${value:.4f}"
        extras: tuple[tuple[str, str], ...] = ()
        gained = _as_number(awarded)
        if gained is not None and abs(gained) > 0:
            extras = (("获得", f"${gained:.2f}" if abs(gained) >= 0.01 else f"${gained:.4f}"),)
        return DisplaySpec(text=text, text_label="额度" if text else "", extras=extras)

    if spec.strict_checkin:
        return _strict_http_attempt(ctx, spec, _display)

    if spec.status_path:
        try:
            state = unwrap_data(ctx.http.get(spec.status_path)) or {}
        except TaskError as exc:
            ctx.log(f"纯 HTTP 读状态失败（{exc.message}），改走浏览器流程")
            return _handoff("纯 HTTP 读取签到状态失败", error=exc)
        if isinstance(state, dict) and state.get("checked_in_today"):
            balance = state.get("balance")
            return already_done("今日已签到", data={"source": "http_first", **state}).with_display(
                _display(balance)
            )

    try:
        data = unwrap_data(ctx.http.request("POST", spec.checkin_path, json_body={}, retry_non_idempotent=True))
    except TaskError as exc:
        text = f"{exc.message} {exc.payload}"
        if any(marker in text for marker in ALREADY_DONE_MARKERS):
            return already_done("今日已签到", data={"source": "http_first"})
        ctx.log(f"纯 HTTP 签到未完成（{exc.message}），改走浏览器流程")
        return _handoff("纯 HTTP 签到未完成", error=exc)

    payload = data if isinstance(data, dict) else {}
    awarded = payload.get("today_reward") or payload.get("reward") or payload.get("amount")
    balance = payload.get("balance") or payload.get("credits")
    return success(spec.success_message, data={"source": "http_first", **payload}).with_display(
        _display(balance, awarded)
    )


async def http_first(ctx: Any, spec: SiteSpec) -> Any:
    """旧入口（未配置访问链的任务仍走它）：该交给浏览器时返回 None，其余原样返回。

    行为与拆分前完全一致：``http_attempt`` 的普通失败就是旧实现的 None 分支，
    终局失败就是旧实现直接返回、不开浏览器的那些失败。
    """
    from core.chain import is_final, strip_control
    from core.outcome import Verdict

    outcome = await http_attempt(ctx, spec)
    if outcome.verdict is Verdict.FAILED and not is_final(outcome):
        return None
    return strip_control(outcome)


def _handoff(message: str, *, reason: str = "", error: Any = None) -> Any:
    """「纯 HTTP 没走通、应交给浏览器」的失败结论。

    子结果取自异常（登录失效 / 需验证 / 网络错误……），访问链与界面据此说明原因。
    不把异常正文写进结论：服务端回执可能回显凭据，正文只进已脱敏的日志。
    """
    from core.outcome import Verdict, failed

    data: dict[str, Any] = {"source": "http_first", "handoff": "browser"}
    if error is not None:
        if getattr(error, "verdict", Verdict.FAILED) is Verdict.FAILED:
            reason = reason or str(getattr(error, "reason", "") or "")
        status = getattr(error, "status", None)
        if status is not None:
            data["http_status"] = status
    return failed(f"{message}，改由浏览器完成", reason=reason, data=data)


def _strict_http_attempt(ctx: Any, spec: SiteSpec, display: Any) -> Any:
    from core.chain import final
    from core.errors import TaskError
    from core.outcome import already_done, failed, no_effect, success

    def outcome(result: dict[str, Any]) -> Any:
        detail = {"source": "http_first", "response_status": result.get("status", 0)}
        if result.get("ok") is True:
            detail["checked_in_today"] = True
            for key in ("balance", "reward"):
                if result.get(key) is not None:
                    detail[key] = result[key]
            factory = already_done if result.get("already") is True else success
            message = "今日已签到" if result.get("already") is True else spec.success_message
            return factory(message, data=detail).with_display(
                display(result.get("balance"), None if result.get("already") is True else result.get("reward"))
            )
        reason = result.get("reason") or "unconfirmed"
        if reason == "not_open":
            return no_effect(f"{spec.site_label}签到功能未开放", reason=reason, data=detail)
        # 服务端已给出结论（或签到已提交）：换浏览器只会重复提交，访问链不再回退。
        return final(failed(f"{spec.site_label}签到未获服务端确认", reason=reason, data=detail))

    if not spec.status_path:
        return outcome(_checkin_failure("need_config"))
    try:
        state = _strict_checkin_response(ctx.http.get(spec.status_path), state=True)
    except TaskError as exc:
        # ctx.http 自己负责认证续期；不打印可能回显凭据的异常，不重复实现登录。
        ctx.log("纯 HTTP 状态查询未完成，改走浏览器流程")
        return _handoff("纯 HTTP 状态查询未完成", error=exc)
    early = _strict_preflight(state)
    if early is not None:
        return outcome(early)
    if state.get("turnstile_required") is True:
        ctx.log("签到需要 Turnstile 验证，交给浏览器获取令牌")
        return _handoff("签到需要 Turnstile 验证", reason="need_verification")

    try:
        raw = ctx.http.request(
            "POST", spec.checkin_path, json_body={"turnstile_token": ""}, retry_non_idempotent=False,
        )
    except TaskError as exc:
        if exc.status == 409:
            try:
                confirmed = _strict_checkin_response(ctx.http.get(spec.status_path), state=True)
            except TaskError:
                confirmed = {}
            if confirmed.get("ok") is True and confirmed.get("checked_in_today") is True:
                return outcome({**confirmed, "already": True})
        reason = exc.reason or (_checkin_reason(exc.payload, exc.status) if exc.status is not None else "unconfirmed")
        if reason == "need_verification":
            ctx.log("签到验证要求已变化，改走浏览器流程")
            return _handoff("签到验证要求已变化", reason="need_verification")
        return outcome(_checkin_failure(reason, exc.status or 0))
    result = _strict_checkin_response(raw)
    if result.get("ok") is not True:
        return outcome(result)
    try:
        confirmed = _strict_checkin_response(ctx.http.get(spec.status_path), state=True)
    except TaskError as exc:
        return outcome(_checkin_failure(exc.reason or "unconfirmed", exc.status or 0))
    return outcome(_confirm_strict_checkin(result, confirmed))


#: 「今日已签到」在 Sub2API 系回执里的常见说法。
ALREADY_DONE_MARKERS = ("ALREADY", "already", "已签到", "今日已")


def _as_number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
