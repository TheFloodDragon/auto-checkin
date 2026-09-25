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
                method: 'POST',
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
    """把一次页内鉴权操作包进共享 token/refresh 状态机。"""
    return "async (baseUrl) => {\n" + _PAGE_AUTH_REQUEST_HELPERS_JS + operation_js + "\n}"


_AUTHENTICATED_JS = _page_auth_script(
    """
    try {
        const response = await requestWithAuth((accessToken) => fetch(baseUrl + '/api/v1/auth/me', {
            credentials: 'include',
            headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
        }));
        return Boolean(response && response.ok);
    } catch (_) {
        return false;
    }
"""
)


async def authenticated(page: Any, origin: str) -> bool:
    """确认登录态是否有效。

    与站点前端一致：先用 auth_token 调 /api/v1/auth/me；access_token 过期时，
    若 localStorage 存在 refresh_token 则先调 /api/v1/auth/refresh 刷新再重试。
    只有 refresh 也失败才判定未登录，避免把「仅 access_token 过期、会话仍有效」
    误判为需要账号密码重新登录。

    登录后 SPA 可能同时发生路由跳转，page.evaluate 会因 execution context destroyed
    瞬时失败。不能把一次 evaluate 异常直接等价为认证失败，短暂重试后才下结论。
    """
    for attempt in range(3):
        try:
            return bool(await page.evaluate(_AUTHENTICATED_JS, origin))
        except Exception:
            if attempt >= 2:
                break
            try:
                await page.wait_for_timeout(200)
            except Exception:
                break
    return False


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


def preflight_init_script(stash_key: str = "", *, preserve_refresh: bool = False) -> str:
    """token 已过期时在 document_start 清理旧登录态，避免 /login↔/dashboard 互踢。

    根因：token 过期但 localStorage 残留 auth_user 时，/dashboard 守卫判「未登录」
    踢去 /login，/login 守卫判「已登录」又踢回 /dashboard，两个守卫互踢形成无限
    跳转，且跳转期间页面执行上下文反复销毁、evaluate 全部失效。对策是在 SPA 路由
    守卫读取 localStorage 之前，把登录态一致地归零，让页面干净停在 /login。
    token 未过期则完全不动，保住有效会话。

    过期时连暗格一起清掉：否则 restore init script 会把过期 token 恢复回去，
    重新形成互踢。严格模式只清旧 access token、用户缓存和过期时间，保留
    refresh_token 给现有鉴权器正常续期；兼容模式仍按历史行为清空全部 auth 键。
    """
    keys = ", ".join(f"'{key}'" for key in AUTH_KEYS if not preserve_refresh or key != "refresh_token")
    stash_line = f"localStorage.removeItem('{stash_key}');" if stash_key else ""
    return f"""
        try {{
            const exp = Number(localStorage.getItem('token_expires_at') || '0');
            if (Number.isFinite(exp) && exp > 0 && Date.now() >= exp) {{
                for (const key of [{keys}]) {{
                    localStorage.removeItem(key);
                }}
                {stash_line}
                sessionStorage.removeItem('auth_expired');
            }}
            localStorage.setItem('{NOTICE_KEY}', 'accepted');
        }} catch (_) {{ /* ignore */ }}
    """


def login_reset_init_script(sentinel: str) -> str:
    """账密登录期间在 document_start 无条件清空 auth 键。

    用 page.evaluate 在导航「前」清 localStorage 赶不上——goto 后 SPA 的 auth
    store 会从持久化值重新写回 auth_user，导致 /login 又被弹回 dashboard。必须用
    add_init_script 在每次导航的 document_start（早于框架读取 localStorage）清理。
    sentinel 守护：登录成功后置为 'done' 即停止清理，避免把新拿到的 token 也清掉。
    暗格不能在这里同步清理：若 sentinel 写入恰逢导航而失败，下一次 document_start
    仍需靠最后注册的 restore init script 从暗格救回新 token。
    """
    keys = ", ".join(f"'{key}'" for key in AUTH_KEYS)
    return f"""
        try {{
            if (localStorage.getItem('{sentinel}') !== 'done') {{
                for (const key of [{keys}]) {{
                    localStorage.removeItem(key);
                }}
                sessionStorage.removeItem('auth_expired');
            }}
            localStorage.setItem('{NOTICE_KEY}', 'accepted');
        }} catch (_) {{ /* ignore */ }}
    """


def session_restore_init_script(stash_key: str) -> str:
    """document_start 时把被前端清掉的登录态从暗格恢复回 localStorage。

    只在账密登录成功（且 /auth/me 已验证）之后注册。站点前端一旦把 auth_token
    清掉并跳回 /login，下一次导航就在 SPA 读 localStorage 之前恢复，签到流程不会
    因为「前端自己登出了」而误判成登录态失效。

    只恢复未过期的登录态：暗格里的 token_expires_at 已过期就把暗格删掉，
    避免恢复出一个死 token 反复互踢。
    """
    keys = ", ".join(f"'{key}'" for key in AUTH_KEYS)
    return f"""
        try {{
            const raw = localStorage.getItem('{stash_key}');
            if (raw) {{
                const saved = JSON.parse(raw);
                const exp = Number((saved && saved.token_expires_at) || '0');
                if (Number.isFinite(exp) && exp > 0 && Date.now() >= exp) {{
                    localStorage.removeItem('{stash_key}');
                }} else if (!String(localStorage.getItem('auth_token') || '').trim()) {{
                    for (const key of [{keys}]) {{
                        const value = saved && saved[key];
                        if (typeof value === 'string' && value) {{
                            localStorage.setItem(key, value);
                        }}
                    }}
                    sessionStorage.removeItem('auth_expired');
                }}
            }}
        }} catch (_) {{ /* ignore */ }}
    """


async def add_init_script(context: Any, script: str) -> None:
    if context is None:
        return
    try:
        await context.add_init_script(script)
    except Exception:
        pass


async def mark_login_done(page: Any, sentinel: str) -> bool:
    """置位 sentinel，停止 init script 清理（否则会清掉刚登录拿到的 token）。

    必须写成并读回确认：这次 evaluate 紧跟在登录之后，站点前端此刻可能正在
    `window.location.href='/login'`，执行上下文被销毁会让 evaluate 直接抛异常。
    此前异常被静默吞掉，sentinel 没写上，下一次导航的 login_reset init script
    就把刚拿到的 token 全清了——表现为「登录成功却立刻判定登录态失效」。
    """
    for _ in range(3):
        try:
            done = await page.evaluate(
                f"() => {{ localStorage.setItem('{sentinel}', 'done');"
                f" return localStorage.getItem('{sentinel}') === 'done'; }}"
            )
            if bool(done):
                return True
        except Exception:
            pass
        try:
            await page.wait_for_timeout(200)
        except Exception:
            return False
    return False


async def stash_session(page: Any, stash_key: str) -> bool:
    """把当前 localStorage 里的登录态复制进暗格，供导航后恢复。"""
    if not stash_key:
        return False
    keys = ", ".join(f"'{key}'" for key in AUTH_KEYS)
    script = f"""() => {{
        try {{
            const saved = {{}};
            for (const key of [{keys}]) {{
                const value = localStorage.getItem(key);
                if (typeof value === 'string' && value) saved[key] = value;
            }}
            if (!saved.auth_token) return false;
            localStorage.setItem('{stash_key}', JSON.stringify(saved));
            return true;
        }} catch (_) {{ return false; }}
    }}"""
    try:
        return bool(await page.evaluate(script))
    except Exception:
        return False


async def restore_session(page: Any, stash_key: str) -> bool:
    """运行期恢复：前端把 auth 键清掉后，从暗格补回来。返回是否补过。"""
    if not stash_key:
        return False
    keys = ", ".join(f"'{key}'" for key in AUTH_KEYS)
    script = f"""() => {{
        try {{
            const raw = localStorage.getItem('{stash_key}');
            if (!raw) return false;
            const saved = JSON.parse(raw);
            if (!saved || typeof saved !== 'object' || !saved.auth_token) return false;
            const exp = Number(saved.token_expires_at || '0');
            if (Number.isFinite(exp) && exp > 0 && Date.now() >= exp) return false;
            if (String(localStorage.getItem('auth_token') || '').trim()) return false;
            for (const key of [{keys}]) {{
                const value = saved[key];
                if (typeof value === 'string' && value) localStorage.setItem(key, value);
            }}
            sessionStorage.removeItem('auth_expired');
            return true;
        }} catch (_) {{ return false; }}
    }}"""
    try:
        return bool(await page.evaluate(script))
    except Exception:
        return False


_READ_TOKENS_JS = """() => {
    try {
        const at = String(localStorage.getItem('auth_token') || '').trim();
        const rt = String(localStorage.getItem('refresh_token') || '').trim();
        return { access_token: at, refresh_token: rt };
    } catch (_) {
        return { access_token: '', refresh_token: '' };
    }
}"""


async def _record_new_tokens(
    page: Any,
    helpers: Any,
    ctx: Any,
    origin: str,
) -> None:
    """浏览器登录成功后，把新 token 写回覆盖层，让下次 http_first 可直接用。

    只读取 localStorage；不把 token 值写入日志或结果。
    写入失败（策略 READONLY 或文件锁超时）是非致命的：顶多下次仍走浏览器流程。
    """
    try:
        result = await page.evaluate(_READ_TOKENS_JS)
    except Exception:
        return
    if not isinstance(result, dict):
        return
    access_token = str(result.get("access_token") or "").strip()
    refresh_token = str(result.get("refresh_token") or "").strip()
    if not access_token:
        return
    # ctx.store._overlay 是 Overlay 实例；ctx.account.id 是稳定账号 id。
    overlay = getattr(getattr(ctx, "store", None), "_overlay", None)
    account_id = getattr(getattr(ctx, "account", None), "id", "")
    if overlay is None or not account_id:
        return
    # record_credentials 需要 AccountSpec；从 overlay 自身 entry 里取 spec 不可行，
    # 直接用底层 _update 写入 FieldEntry 更直接，但那是私有 API。
    # 退而求其次：用 put_learning 存到专用命名空间，引擎在下次启动时从这里预填 http 头。
    # 如果 overlay 暴露了 record_credentials，优先走公开接口。
    record_fn = getattr(overlay, "record_credentials", None)
    if callable(record_fn):
        spec = getattr(getattr(ctx, "store", None), "_spec", None)
        if spec is None:
            # 没有 spec 引用时，通过学习存储暂存，运行期引擎可在下次叠加覆盖。
            store = getattr(ctx, "store", None)
            if store is not None:
                kv: dict[str, str] = {"access_token": access_token}
                if refresh_token:
                    kv["refresh_token"] = refresh_token
                store.scoped("_token_refresh").put("latest", kv)
                log(helpers, f"新 token 已暂存到覆盖层学习数据（{len(access_token)} 字符），下次运行将优先使用")
        else:
            kwargs: dict[str, str] = {"access_token": access_token}
            if refresh_token:
                kwargs["refresh_token"] = refresh_token
            record_fn(spec, origin="browser", **kwargs)
            log(helpers, f"新 access_token 已写回覆盖层（{len(access_token)} 字符）")
    else:
        store = getattr(ctx, "store", None)
        if store is not None:
            kv_data: dict[str, str] = {"access_token": access_token}
            if refresh_token:
                kv_data["refresh_token"] = refresh_token
            store.scoped("_token_refresh").put("latest", kv_data)
            log(helpers, f"新 token 已暂存到学习数据（{len(access_token)} 字符）")


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

    await add_init_script(context, login_reset_init_script(spec.login_reset_sentinel))

    async def _open_login_and_confirm() -> bool:
        await keep_waf_cookies(context)
        await helpers.goto(
            f"/login?redirect={spec.default_start_path}",
            timeout=opts.goto_timeout,
            wait_until="commit",
        )
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=opts.ready_timeout)
        except Exception:
            pass
        # 整页导航后 store 从（应已空的）localStorage 初始化；确认 auth_user 已空。
        try:
            lingering = await page.evaluate(
                "() => Boolean(String(localStorage.getItem('auth_user') || '').trim())"
            )
        except Exception:
            lingering = False
        return not bool(lingering)

    loop = asyncio.get_running_loop()
    form_wait_ms = opts.login_timeout_ms if spec.strict_checkin else min(opts.login_timeout_ms, 30000)
    deadline = loop.time() + form_wait_ms / 1000
    opened = False
    for _ in range(3):
        if await _open_login_and_confirm():
            opened = True
            break
        if loop.time() >= deadline:
            break
        await page.wait_for_timeout(min(max(opts.poll_interval_ms, 300), 800))

    if not opened:
        screenshot = await helpers.screenshot(f"{spec.screenshot_prefix}-login-form-unavailable.png")
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
    # 每轮先关掉「使用说明」模态框，否则它遮住表单，填写会失败。
    form_deadline = loop.time() + form_wait_ms / 1000
    form_filled = False
    while True:
        await dismiss_notice(page)
        if await fill_login_form(page, email, password):
            form_filled = True
            break
        if loop.time() >= form_deadline:
            break
        await page.wait_for_timeout(min(max(opts.poll_interval_ms, 300), 800))

    if not form_filled:
        screenshot = await helpers.screenshot(f"{spec.screenshot_prefix}-login-form-unavailable.png")
        if spec.strict_checkin:
            return helpers.error(
                f"{name}登录页字段未在等待时间内就绪，请稍后重试",
                {"target_url": resolved_url, "login_fallback": "form_unavailable",
                 "login_timeout_ms": opts.login_timeout_ms, "screenshot": screenshot},
            ).as_reason("unconfirmed")
        return helpers.need_config(
            f"{name}登录页字段未就绪，无法自动填写邮箱和密码",
            {"target_url": resolved_url, "login_fallback": "form_unavailable", "screenshot": screenshot},
        )

    # 获取 Cloudflare Turnstile 令牌：交互式 widget 被动等待不签发，必须真实鼠标
    # 点击复选框（isTrusted 事件），逻辑封装在 browser.turnstile。
    await dismiss_notice(page)
    log(helpers, "等待 Cloudflare Turnstile 令牌（必要时真实点击复选框）...")
    solved = await helpers.solve(
        "turnstile",
        budget=opts.login_timeout_ms / 1000,
        poll_interval_ms=opts.poll_interval_ms,
    )
    token = solved.value
    if not token:
        # 令牌拿不到有两类成因，指向的动作完全不同，不能一律甩「重新捕获 browser_state」：
        # 令牌属于 Cloudflare 人机验证，和站点登录态（browser_state）没有关系，重新捕获
        # 对它毫无帮助。真正的成因是——
        #   1) 出口 IP 信誉低：Turnstile widget 直接拒绝渲染/签发（实测数据中心 IP 下
        #      登录页只挂一个 1×1 的空 iframe，既没有复选框也不下发令牌），换住宅代理才有用；
        #   2) 需要人工点选：有头环境下 widget 渲染了但要人点一下，此时应在浏览器里完成。
        # solve 的 reason 能把这两类区分开（refused/timeout 多为 IP 风控），据此给出可操作的提示。
        reason = str(getattr(solved, "reason", "") or "")
        detail_msg = str(getattr(solved, "message", "") or "")
        log(helpers, f"Turnstile 未在等待时间内签发令牌（reason={reason or '未知'}）")
        screenshot = await helpers.screenshot(f"{spec.screenshot_prefix}-turnstile-timeout.png")
        return helpers.need_verification(
            f"{name} Cloudflare Turnstile 未能自动签发令牌，登录中止。"
            "这多为当前出口 IP 信誉过低导致人机验证无法通过（与 browser_state 无关，"
            "重新捕获登录态不会解决）；请为该账号配置住宅代理后重试，或在有头浏览器中人工完成验证。",
            {
                "target_url": resolved_url,
                "login_fallback": "turnstile_timeout",
                "login_timeout_ms": opts.login_timeout_ms,
                "turnstile_reason": reason,
                "turnstile_message": detail_msg,
                "screenshot": screenshot,
            },
        )

    # 人工完成 Turnstile 后页面可能还在同步表单状态；给前端一个很短的稳定窗口，
    # 避免刚读到令牌就提交导致站点仍拿到旧表单值。令牌读取本身已是密集轮询，
    # 这里只增加最多 250ms 的提交前缓冲。
    try:
        await page.wait_for_timeout(min(max(opts.poll_interval_ms, 50), 250))
    except Exception:
        pass
    stash_key = session_stash_key(spec.login_reset_sentinel)
    result = await submit_login(page, origin, email, password, token, stash_key, spec.turnstile_field_name)
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
                await page.wait_for_load_state("domcontentloaded", timeout=opts.ready_timeout)
            except Exception:
                pass
            if await authenticated(page, origin):
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

    if not await authenticated(page, origin):
        return helpers.need_login(
            f"{name}登录接口成功但 /auth/me 验证未通过，请重试",
            {"target_url": resolved_url, "login_fallback": "auth_verification_failed"},
        )

    log(helpers, "账密登录成功，已验证登录态")
    # 登录接口 JS 已经写过暗格，这里再读当前 localStorage 复核一次；两次都不向
    # Python 返回 token 明文。随后把 restore 脚本注册在 login_reset 之后：即使
    # sentinel 写入恰逢导航而失败，下一份 document 也会先清理、再恢复新 token。
    stashed = await stash_session(page, stash_key)
    marked = await mark_login_done(page, spec.login_reset_sentinel)
    await add_init_script(context, session_restore_init_script(stash_key))
    log(
        helpers,
        "登录态防丢保护已启用"
        f"（暗格={'已确认' if stashed else '由登录接口写入'}，"
        f"清理哨兵={'已确认' if marked else '写入未确认，将由暗格恢复兜底'}）",
    )

    # ── 把新 token 写回覆盖层，让下次运行的 http_first 能直接用 ──────────────
    # 浏览器登录后新 access_token / refresh_token 只活在 localStorage；Python 侧
    # ctx.http 始终拿配置里的旧 token，不刷新就每次都要开浏览器。这里用一次只读
    # evaluate 把它们取出来写进 overlay.json，不向日志或结果暴露值本身。
    await _record_new_tokens(page, helpers, helpers.ctx, origin)

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
    """执行 Sub2API 站点的统一登录、状态探测、点击与 API 兜底流程。

    调用方只需开一个租约；页面、helper 与站点参数都在这里组装。
    """
    from sdk import PageHelpers

    page = lease.page
    context = lease.context
    helpers = PageHelpers(ctx, lease, page)
    opts = parse_options(spec, ctx.args)
    start_target = opts.start_target or spec.default_start_path
    resolved_url = helpers.resolve_url(start_target)
    origin = helpers.resolve_url("/").rstrip("/")
    login_detail: dict[str, Any] = {}

    async def do_login() -> dict[str, Any] | None:
        return await login_with_password(
            page,
            context,
            helpers,
            spec,
            opts,
            resolved_url=resolved_url,
            origin=origin,
            login_detail=login_detail,
        )

    stash_key = session_stash_key(spec.login_reset_sentinel)
    await add_init_script(context, preflight_init_script(stash_key, preserve_refresh=spec.strict_checkin))
    await navigate_and_settle(page, helpers, start_target, opts)

    login_attempted = False
    if await on_login_page(page):
        if spec.strict_checkin and await authenticated(page, origin):
            # SPA 可先因旧 access_token 跳 /login；必须先让现有 refresh 状态机
            # 续期，不能先清空 localStorage 再从头账密登录。
            login_detail["auth_verified"] = True
            lease.mark_authenticated()
            await navigate_and_settle(page, helpers, start_target, opts)
            return await _strict_browser_checkin(
                page, helpers, spec, opts, origin,
                {"target_url": resolved_url, "completion_signal": "api_after_auth", **login_detail},
            )
        login_attempted = True
        failure = await do_login()
        if failure is not None:
            return failure
        await navigate_and_settle(page, helpers, start_target, opts)
        if await on_login_page(page):
            # URL/密码框只是 SPA 路由表现，服务端 /auth/me 才是认证权威。
            # 站点前端的 401 拦截器会主动清空 localStorage 并跳回 /login；而这枚
            # token 在登录后已经通过 /auth/me。先从暗格恢复，再做认证复查，不能把
            # 前端自己的登出动作反向覆盖为「账密登录失败」。
            log(helpers, "登录后仍停留/返回登录页，开始复查并恢复可能被前端清空的登录态")
            verified = await authenticated(page, origin)
            restored = False
            if not verified:
                restored = await restore_session(page, stash_key)
                if restored:
                    log(helpers, "检测到 auth_token 被前端清空，已从登录态暗格恢复并重新验证")
                verified = await authenticated(page, origin)
            if verified:
                log(helpers, "登录已由 /auth/me 验证，但页面路由仍显示登录页，直接使用有效 token 接口签到")
                login_detail["login_route_stale"] = True
                if restored:
                    login_detail["login_state_restored"] = True
                lease.mark_authenticated()
                return await api_fallback(
                    page,
                    helpers,
                    spec,
                    opts,
                    origin=origin,
                    resolved_url=resolved_url,
                    login_attempted=True,
                    do_login=do_login,
                    extra_detail=login_detail,
                )
            return helpers.need_login(
                f"{spec.site_label}登录接口成功但认证复查未通过，请检查凭据或稍后重试",
                {"target_url": resolved_url, "login_fallback": "redirect_failed", **login_detail},
            )

    if await authenticated(page, origin):
        # 登录态成立就立刻续存，并让 runner 知道本次认证已验证：后续签到即使失败
        # （验证码、风控、异常），这份登录态也不该被当成登出态丢掉。
        login_detail["auth_verified"] = True
        lease.mark_authenticated()
        if spec.strict_checkin:
            return await _strict_browser_checkin(
                page, helpers, spec, opts, origin,
                {"target_url": resolved_url, "completion_signal": "api_after_auth", **login_detail},
            )
        # ── 步骤 3：先用新 token 试一次 API 签到，省去等待按钮渲染的时间 ──────
        # 浏览器已有有效 token（browser_state 注入或密码登录拿到），在等按钮渲染
        # 之前先直接打签到接口：token 有效时十几毫秒就能拿到结论，不用跑完整个
        # 25 秒的按钮轮询窗口。失败或无 token 时静默降级，不影响后续按钮路径。
        pre_result = await api_checkin(page, spec, origin)
        pre_status = int((pre_result or {}).get("status") or 0)
        if bool((pre_result or {}).get("already")):
            log(helpers, f"登录验证后 API 签到：今日已签到（HTTP {pre_status}），无需点击按钮")
            quota = (pre_result or {}).get("balance")
            return helpers.already_done(
                "今日已签到",
                {"target_url": resolved_url, "completion_signal": "api_after_auth", **login_detail},
                quota=quota,
            )
        if bool((pre_result or {}).get("ok")):
            log(helpers, f"登录验证后 API 签到成功（HTTP {pre_status}），无需点击按钮")
            quota = (pre_result or {}).get("balance")
            awarded = (pre_result or {}).get("reward")
            return helpers.success(
                spec.success_message,
                {"target_url": resolved_url, "completion_signal": "api_after_auth",
                 "response_status": pre_status, **login_detail},
                quota=quota,
                awarded=awarded,
            )
        log(helpers, f"登录验证后 API 签到未成功（HTTP {pre_status}），改为等待页面按钮")
    else:
        log(helpers, "当前页面未通过 /auth/me 认证复查，跳过脚本内登录态快照")
        if spec.strict_checkin:
            # SPA 尚未重定向时也不能先空等签到按钮；认证恢复属于现有登录流程。
            if not login_attempted:
                login_attempted = True
                failure = await do_login()
                if failure is not None:
                    return failure
                await navigate_and_settle(page, helpers, start_target, opts)
                if await authenticated(page, origin):
                    login_detail["auth_verified"] = True
                    lease.mark_authenticated()
                    return await _strict_browser_checkin(
                        page, helpers, spec, opts, origin,
                        {"target_url": resolved_url, "completion_signal": "api_after_auth", **login_detail},
                    )
            return helpers.need_login(
                f"{spec.site_label}登录态未能恢复，请检查登录凭据",
                {"target_url": resolved_url, **login_detail},
            )
    control, early_result = await wait_for_checkin_control(
        page,
        helpers,
        spec,
        opts,
        resolved_url=resolved_url,
        login_detail=login_detail,
    )
    if early_result is not None:
        return early_result
    if control is None:
        return await api_fallback(
            page,
            helpers,
            spec,
            opts,
            origin=origin,
            resolved_url=resolved_url,
            login_attempted=login_attempted,
            do_login=do_login,
            extra_detail=login_detail,
        )
    return await click_and_confirm(
        page,
        helpers,
        spec,
        opts,
        control,
        resolved_url=resolved_url,
        extra_detail=login_detail,
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
