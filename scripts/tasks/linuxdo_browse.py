"""LinuxDO 刷帖任务。

访问 linux.do 论坛，使用共享浏览器登录态，模拟人类化浏览帖子：
- 随机点进帖子，每篇停留随机可控时长
- 贝塞尔曲线平滑鼠标移动 + 分段随机滚动，模拟真实阅读节奏
- 每篇读完后返回首页刷新，获取新帖列表

使用方式：将本脚本路径填入账号 template 字段，并捕获 LinuxDO 浏览器登录态。
"""

from __future__ import annotations

import asyncio
import random
import sys
import time
from math import isfinite
from contextvars import ContextVar
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

_HERE = Path(__file__).resolve().parent   # scripts/tasks
_REPO_ROOT = _HERE.parents[1]            # 仓库根
for _path in (_HERE, _REPO_ROOT):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from browser import bypass  # noqa: E402
from browser.service import decode_state, encode_state  # noqa: E402
from core.outcome import DisplaySpec  # noqa: E402
from login.base import LoginState  # noqa: E402
from sdk import (  # noqa: E402
    ArgSchema,
    ArgSpec,
    ConfigError,
    DisplayDefaults,
    LoginOption,
    LoginRequired,
    Outcome,
    PageHelpers,
    TaskOption,
    TemplateManifest,
    TransientError,
    VerificationRequired,
    already_done,
    failed,
    ok,
)
from core.timebase import business_date  # noqa: E402

LINUXDO_URL = "https://linux.do"
STORE_KEY = "linuxdo_browse"
# 保持论坛态复用与现有私有函数签名；上下文只在本次协程内传递同一预算。
_FLOW: ContextVar[dict[str, Any] | None] = ContextVar("linuxdo_flow", default=None)


def _flow_timeout(cap_ms: int, notes: dict[str, Any] | None = None) -> int:
    notes = notes if notes is not None else (_FLOW.get() or {})
    deadline = notes.get("deadline")
    if deadline is None:
        return cap_ms
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return max(1, min(cap_ms, int(remaining * 1000)))


def _flow_evidence(notes: dict[str, Any]) -> dict[str, Any]:
    keys = ("stage", "cf_diagnostics", "timeout_stage", "session_probe", "state_source", "state_diagnostics")
    return {key: notes[key] for key in keys if key in notes}


async def _clear_challenge(page: Any, log: Any, notes: dict[str, Any], stage: str) -> bool:
    deadline = notes.get("deadline")
    if deadline is not None and deadline <= time.monotonic():
        raise TimeoutError
    notes["stage"] = stage + "_probe"
    async with asyncio.timeout_at(deadline):
        notes["challenge_active"] = await _is_challenge(page)
    if not notes["challenge_active"]:
        return True
    notes.update(challenge_seen=True, stage=stage)
    diagnostics = {
        "stage": stage, "target_kind": "unknown", "clicked": False, "timeout_stage": "", "reason": "",
    }
    notes["cf_diagnostics"] = diagnostics
    remaining = 50.0 if deadline is None else max(0.0, min(50.0, deadline - time.monotonic()))
    try:
        async with asyncio.timeout_at(deadline):
            cleared = await bypass.solve_cloudflare(
                page, log=log, wait_seconds=remaining, deadline=deadline, diagnostics=diagnostics,
            )
    finally:
        diagnostics["stage"] = stage
    notes["challenge_active"] = not cleared
    if not cleared and not diagnostics.get("reason"):
        diagnostics["reason"] = "challenge_unresolved"
    return cleared

_LOGIN_ARGS = ArgSchema(
    (
        ArgSpec(
            "github_fallback",
            kind="bool",
            default=False,
            title="失效时用 GitHub 重新登录",
            help="LinuxDO 登录态未通过校验时，用共享 GitHub 登录态登录 linux.do，并把新登录态写入运行期覆盖层",
        ),
        ArgSpec(
            "github_account",
            kind="str",
            default="default",
            title="GitHub 共享账号名",
            help="oauth_states.github.accounts 下的账号名",
        ),
    )
)

MANIFEST = TemplateManifest(
    id="linuxdo_browse",
    title="LinuxDO 刷帖",
    description="访问 linux.do 论坛，模拟人类化随机浏览帖子，保持账号活跃度",
    login=(
        LoginOption(
            "browser_state",
            priority=10,
            requires=frozenset({"browser"}),
            title="浏览器登录态（LinuxDO）",
            args=_LOGIN_ARGS,
        ),
        LoginOption(
            "oauth",
            priority=20,
            requires=frozenset({"browser"}),
            title="共享 LinuxDO 登录态",
            args=_LOGIN_ARGS,
        ),
    ),
    task=(
        TaskOption(
            "browser_flow",
            priority=10,
            requires=frozenset({"browser"}),
            owns=frozenset({"detect", "confirm"}),
            title="模拟刷帖",
            args=ArgSchema(
                (
                    ArgSpec(
                        "post_count",
                        kind="int",
                        default=5,
                        minimum=1,
                        maximum=30,
                        title="浏览帖子数",
                        help="每次必须实际读完的不同主题数；未达到该数量不记录为每日完成",
                    ),
                    ArgSpec(
                        "min_read_seconds",
                        kind="int",
                        default=8,
                        minimum=3,
                        maximum=120,
                        title="最短阅读秒数",
                        help="每篇帖子最少停留的秒数",
                    ),
                    ArgSpec(
                        "max_read_seconds",
                        kind="int",
                        default=30,
                        minimum=5,
                        maximum=300,
                        title="最长阅读秒数",
                        help="每篇帖子最多停留的秒数",
                    ),
                    ArgSpec(
                        "once_per_day",
                        kind="bool",
                        default=False,
                        title="每日只刷一次",
                        help="启用后，当天已刷过则跳过（返回 already_done）",
                    ),
                )
            ),
        ),
    ),
    display=DisplayDefaults(text_label="浏览帖数"),
    endpoints={"user": "/session/current.json"},
)


# ── 人类化鼠标 / 滚动辅助 ────────────────────────────────────────────────────

async def _bezier_move(
    page: Any,
    x0: float, y0: float,
    x1: float, y1: float,
    steps: int = 22,
) -> None:
    """二阶贝塞尔曲线平滑鼠标移动，模拟人类手腕弧线轨迹。

    控制点随机偏移，让每次路径略有不同；速度在中段最快、两端最慢，
    与真实鼠标加速度曲线一致。
    """
    cx = random.uniform(min(x0, x1) - 60, max(x0, x1) + 60)
    cy = random.uniform(min(y0, y1) - 60, max(y0, y1) + 60)
    for i in range(steps + 1):
        t = i / steps
        x = (1 - t) ** 2 * x0 + 2 * (1 - t) * t * cx + t**2 * x1
        y = (1 - t) ** 2 * y0 + 2 * (1 - t) * t * cy + t**2 * y1
        await page.mouse.move(x, y)
        # 两端慢（ease-in-out 曲线）：t 越靠近 0 / 1 越慢
        ease = 4 * t * (1 - t)          # 0→1→0，中间最大
        delay = random.uniform(0.006, 0.018) * (1.6 - ease)
        await asyncio.sleep(delay)


async def _human_scroll(page: Any, total_px: int) -> None:
    """分段下滑，每段随机长度并随机停顿，模拟人类阅读节奏。"""
    scrolled = 0
    while scrolled < total_px:
        chunk = random.randint(90, 320)
        chunk = min(chunk, total_px - scrolled)
        await page.mouse.wheel(0, chunk)
        scrolled += chunk
        await asyncio.sleep(random.uniform(0.25, 1.2))


async def _simulate_read(page: Any, read_seconds: float) -> float:
    """正常滚动阅读，并按真实经过时间计时，而不是累加预估的停顿。"""
    loop = asyncio.get_running_loop()
    started = loop.time()
    deadline = started + read_seconds
    try:
        vp = await page.evaluate(
            "() => ({ w: window.innerWidth, h: window.innerHeight })"
        )
        vw = vp.get("w", 1280)
        vh = vp.get("h", 800)
    except Exception:
        vw, vh = 1280, 800

    # 初始落点：正文区域中部偏左。操作本身的耗时也计入阅读时间。
    await _bezier_move(
        page,
        vw * 0.5, vh * 0.5,
        random.uniform(vw * 0.25, vw * 0.65),
        random.uniform(vh * 0.35, vh * 0.65),
        steps=8,
    )
    await asyncio.sleep(min(random.uniform(1.0, 2.5), max(0.0, deadline - loop.time())))

    while loop.time() < deadline:
        await page.mouse.wheel(0, random.randint(110, 380))
        remaining = max(0.0, deadline - loop.time())
        await asyncio.sleep(min(random.uniform(0.7, 2.8), remaining))
        if loop.time() < deadline and random.random() < 0.35:
            await page.mouse.move(
                random.uniform(vw * 0.2, vw * 0.75),
                random.uniform(vh * 0.25, vh * 0.75),
            )
    return loop.time() - started


# ── LinuxDO Discourse 页面选择器 ─────────────────────────────────────────────

_TOPIC_SELECTORS = [
    "tr.topic-list-item a.raw-topic-link",
    "tr.topic-list-item a.title",
    ".topic-list-item .main-link a",
    ".topic-list .title a",
]
_LOADED_MARKERS = [
    "#main-outlet",
    ".topic-list",
    ".d-header",
]


async def _wait_loaded(page: Any, timeout: int = 20000) -> bool:
    """所有候选共享一个超时，避免三个选择器分别等待而超出预算。"""
    try:
        await page.wait_for_selector(
            ", ".join(_LOADED_MARKERS), state="visible", timeout=timeout
        )
        return True
    except Exception:
        return False


def _normalize_topic_url(value: str) -> str:
    """只接受 LinuxDO 主题链接，并按主题 ID 去重分页、查询参数和不同 slug。"""
    try:
        parsed = urlsplit(urljoin(LINUXDO_URL, str(value or "")))
        if parsed.scheme != "https" or parsed.netloc.casefold() != "linux.do":
            return ""
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2 or parts[0] != "t":
            return ""
        number = parts[2] if len(parts) >= 3 else parts[1]
        if not number.isascii() or not number.isdecimal() or int(number) <= 0:
            return ""
        return f"{LINUXDO_URL}/t/{int(number)}"
    except (TypeError, ValueError):
        return ""


async def _collect_topic_links(page: Any) -> list[str]:
    """等主题链接真正渲染后再收集，页面外壳或页头出现不代表列表已经就绪。"""
    try:
        await page.wait_for_selector(
            ", ".join(_TOPIC_SELECTORS), state="visible", timeout=_flow_timeout(20000),
        )
        hrefs = await page.evaluate(
            "selectors => Array.from(document.querySelectorAll(selectors)).map(a => a.href)",
            ", ".join(_TOPIC_SELECTORS),
        )
    except Exception:
        return []
    if not isinstance(hrefs, list):
        return []
    return list(dict.fromkeys(url for item in hrefs if (url := _normalize_topic_url(item))))


#: 刷帖循环里遇到限流/无法判定时的退避与最大重试次数。窗口通常几十秒就过去，
#: 退避重试远好过把已读进度丢掉、回报一个假的「登录失效」。
_THROTTLE_BACKOFF_SECONDS = 20.0
_MAX_THROTTLE_RETRIES = 3


_SESSION_PROBE_SCRIPT = r"""async () => {
    const endpoint = 'https://linux.do/session/current.json';
    if (location.origin !== 'https://linux.do') {
        return {authenticated:false, anonymous:false, status:0, format:'wrong_origin'};
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
        const r = await fetch(endpoint, {
            credentials:'include', cache:'no-store',
            headers:{Accept:'application/json', 'X-Requested-With':'XMLHttpRequest',
                     'Discourse-Present':'true'},
            signal:controller.signal
        });
        const text = await r.text();
        const body = text.trim();
        const contentType = (r.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
        const sameEndpoint = !r.redirected && r.url === endpoint;
        let data = null, format = body ? 'text' : 'empty';
        if (body) {
            try { data = JSON.parse(body); format = 'json'; }
            catch (_) { if (/^\s*(?:<!doctype\s+html|<html\b)/i.test(body)) format = 'html'; }
        }
        // 不以 Server: cloudflare 或状态码猜测挑战；普通响应也会经过 Cloudflare。
        const challenged = r.headers.get('cf-mitigated') === 'challenge' || (
            format !== 'json' && /window\._cf_chl_opt|<title>\s*Just a moment[.\s]*<\/title>/i.test(body)
        );
        const authenticated = sameEndpoint && !challenged && r.ok && data &&
            data.current_user && Number.isInteger(data.current_user.id) && data.current_user.id > 0;
        // Discourse SessionController#current 对匿名返回 404 + 空正文，不是 JSON。
        // 普通 404 HTML / JSON 错误、任意 JSON 中缺少 current_user 都不足以证明登出。
        const anonymous = sameEndpoint && !challenged && (
            (r.status === 404 && text.length === 0) ||
            (r.ok && data && Object.hasOwn(data, 'current_user') && data.current_user === null) ||
            ([401, 403, 404].includes(r.status) && data && data.error_type === 'not_logged_in')
        );
        return {
            authenticated:Boolean(authenticated), anonymous:Boolean(anonymous), status:r.status, format,
            challenged, same_endpoint:sameEndpoint, body_length:text.length,
            content_type:/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(contentType) ? contentType : 'unknown'
        };
    } catch (e) {
        return {authenticated:false, anonymous:false, status:0,
                format:e.name === 'AbortError' ? 'timeout' : 'network_error'};
    } finally { clearTimeout(timer); }
}"""


def _probe_summary(probe: dict[str, Any]) -> str:
    """只输出状态与固定原因，不记录正文、用户资料、Cookie 或响应 URL。"""
    status = probe.get('status', 0)
    reason = probe.get('reason')
    if not reason:
        reason = 'rate_limited' if status == 429 else 'server_error' if status >= 500 else 'unexpected_response'
    label = {
        'authenticated': '已登录', 'anonymous': '服务端确认匿名会话',
        'anonymous_unconfirmed': '匿名响应未能复核，登录态仍无法判定',
        'rate_limited': '接口限流', 'server_error': '服务端错误',
        'challenge': '接口返回 Cloudflare 挑战', 'network_error': '网络请求未完成',
        'unexpected_response': '响应无法判定登录态', 'wrong_origin': '校验页面不在 LinuxDO',
    }.get(reason, '响应无法判定登录态')
    details = [f'HTTP {status}', label]
    if probe.get('format'):
        details.append(f"format={probe['format']}")
    if 'body_length' in probe:
        details.append(f"body_length={probe['body_length']}")
    return '，'.join(details)


async def _session_probe(page: Any, log: Any = None) -> dict[str, Any]:
    """区分确认登录、确认匿名和无法判定；保留 throttled 兼容旧调用方的重试分支。

    404 空正文是 Discourse 的匿名答复；404 HTML、挑战、429/5xx（包括 JSON）
    都不能据此判定登录失效。只把脱敏元数据带回 Python，不导出响应正文。
    """
    try:
        result = await page.evaluate(_SESSION_PROBE_SCRIPT)
    except Exception:
        result = None
    if not isinstance(result, dict):
        result = {'status': 0, 'format': 'network_error'}
    status = result.get('status')
    status = status if type(status) is int and 0 <= status <= 599 else 0
    if result.get('challenged') is True:
        reason = 'challenge'
    elif status == 429:
        reason = 'rate_limited'
    elif status >= 500:
        reason = 'server_error'
    elif result.get('format') == 'wrong_origin':
        reason = 'wrong_origin'
    elif not status:
        reason = 'network_error'
    elif result.get('same_endpoint') is False:
        reason = 'unexpected_response'
    elif result.get('authenticated') is True and 200 <= status < 300:
        reason = 'authenticated'
    elif result.get('anonymous') is True:
        reason = 'anonymous'
    else:
        reason = 'unexpected_response'
    probe = {
        'authenticated': reason == 'authenticated', 'status': status,
        'throttled': reason not in {'authenticated', 'anonymous'}, 'reason': reason,
        **{key: result[key] for key in ('format', 'body_length', 'content_type', 'challenged', 'same_endpoint')
           if key in result},
    }
    if probe['throttled'] and reason != 'wrong_origin' and await _dom_logged_in(page):
        probe.update(authenticated=True, throttled=False, reason='authenticated', source='dom')
    if callable(log):
        log('LinuxDO 会话校验：' + _probe_summary(probe))
    return probe


async def _logged_in(page: Any, log: Any = None) -> bool:
    """``_session_probe`` 的布尔视图，供不关心限流原因的调用方使用。"""
    return bool((await _session_probe(page, log))["authenticated"])


async def _dom_logged_in(page: Any) -> bool:
    """Discourse 头部：已登录才渲染当前用户头像按钮；未登录渲染「登录」按钮。"""
    try:
        return bool(await page.evaluate("""() => {
            if (location.origin !== 'https://linux.do') return false;
            const user = document.querySelector('#current-user, .header-dropdown-toggle.current-user, #toggle-current-user');
            const login = document.querySelector('.d-header .login-button, .d-header button.login-button');
            return Boolean(user) && !login;
        }"""))
    except Exception:
        return False


async def _is_challenge(page: Any) -> bool:
    # 不能只看 Just a moment 标题：CF 可在普通标题页面延迟挂载 frame/shadow 控件。
    return await bypass.has_cloudflare_challenge(page)


def _shared_browser_state(state_text: str) -> str:
    """共享快照保留论坛认证，但不复制绑定旧浏览器/出口的 Cloudflare 放行 Cookie。"""
    state = decode_state(state_text)
    original = state.get("cookies", [])
    state["cookies"] = [
        cookie for cookie in original
        if not (
            str(cookie.get("domain", "")).lstrip(".").casefold() == "linux.do"
            and str(cookie.get("name", "")).startswith(("cf_", "_cf", "__cf"))
        )
    ]
    return encode_state(state) if len(state["cookies"]) != len(original) else state_text


def _state_evidence(state_text: str) -> dict[str, Any]:
    """只检查快照中论坛认证 Cookie 的存在/过期情况，绝不记录值或摘要。"""
    try:
        cookies = decode_state(state_text).get('cookies', [])
        auth = [cookie for cookie in cookies if cookie.get('name') == '_t'
                and str(cookie.get('domain', '')).lstrip('.').casefold() == 'linux.do'
                and cookie.get('value')]
        now = time.time()
        expired = sum(1 for cookie in auth if isinstance(cookie.get('expires'), (float, int))
                      and 0 < cookie['expires'] <= now)
        return {'auth_cookie_count': len(auth), 'expired_auth_cookie_count': expired}
    except (TypeError, ValueError, AttributeError, LoginRequired):
        return {'snapshot_unreadable': True}


def _same_browser_state(first: str, second: str) -> bool:
    """压缩方式不同也不重复尝试同一快照；调用前已排除旧 CF Cookie。"""
    if first == second:
        return True
    try:
        return decode_state(first) == decode_state(second)
    except (TypeError, ValueError, LoginRequired):
        return False


def login(ctx: Any, option: LoginOption) -> Any:
    """论坛自身只需恢复会话，不能再向 linux.do 发起通用 OAuth 回跳。"""
    if option.method in {"oauth", "browser_state"}:
        return _restore_login(ctx, option.method)
    return None


async def _settle(page: Any, timeout: int = 15000) -> None:
    """等导航稳定：Cloudflare 放行后会自行跳转，期间 evaluate/goto 都会被打断。"""
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=_flow_timeout(timeout))
    except Exception:
        pass


async def _safe_goto(lease: Any, page: Any, url: str) -> None:
    """导航被站点自身的跳转打断不算错误，等它落地即可。"""
    try:
        await lease.goto(url, page=page, wait_until="domcontentloaded", timeout=_flow_timeout(30000))
    except Exception as exc:
        if "interrupted by another navigation" not in str(exc):
            raise
    await _settle(page)


def _driver_closed(exc: BaseException) -> bool:
    from browser import runtime_loop

    return runtime_loop.is_driver_closed_error(exc)


def _brief_error(exc: BaseException) -> str:
    from browser import runtime_loop

    return runtime_loop.brief_navigation_error(exc) or type(exc).__name__


async def _verify_session(
    ctx: Any, lease: Any, page: Any, observed: dict[str, Any] | None = None
) -> tuple[bool, bool, bool]:
    """打开 /latest 并确认登录。返回 (已登录, 人机验证已通过, 无法判定)。

    无法判定要单独报给调用方，不能笼统称为限流；明确匿名也须重载复核，
    避免放行后导航未稳定的一次答复直接触发换态。

    ``observed`` 用于把「这次到底卡在哪」带出函数：外层可能因整体预算超时而中断，
    那时异常里没有任何上下文，只知道「超时了」。记录是否见过人机验证挑战，才能把
    「与挑战搏斗到超时」归类成 need_verification，而不是诬告登录态失效。
    """
    notes = observed if observed is not None else (_FLOW.get() or {})
    notes["stage"] = "session_navigation"
    notes.pop("session_probe", None)
    notes["throttled"] = True  # 尚未得到答复；导航超时也不能据此判为登录失效。
    await _safe_goto(lease, page, f"{LINUXDO_URL}/latest")
    challenge_cleared = True
    throttled = False
    anonymous_hits = 0
    for attempt in range(3):
        challenge_cleared = await _clear_challenge(page, ctx.log, notes, "session_cf")
        if not challenge_cleared:
            anonymous_hits = 0
            # 熔断已经表示本页面/本站点的有限失败预算耗尽；此时不能再重载制造新挑战。
            # 这只是本次流程的验证终止状态，不是对出口 IP 或账号状态的结论。
            cf_diagnostics = notes.get("cf_diagnostics") or {}
            if cf_diagnostics.get("reason") == "circuit_open":
                notes.update(challenge_active=True, cf_circuit_open=True, stage="session_cf_circuit_open")
                break
            # CF 本轮未在预算内放行（常见：Turnstile 卡在「Verifying…」不签发）。同一张挑战
            # 再等多半仍不过，但换一张新挑战常能过——在剩余预算够的前提下重载页面拿新挑战再试。
            deadline = notes.get("deadline")
            if attempt < 2 and (deadline is None or deadline - time.monotonic() > 20.0):
                notes["stage"] = "session_cf_reload"
                ctx.log("Cloudflare 本轮未放行，重载页面换一张新挑战重试")
                await asyncio.sleep(1.0)
                try:
                    await _safe_goto(lease, page, f"{LINUXDO_URL}/latest")
                except Exception as exc:
                    # 重载挑战页被 CF/出口直接拒绝（NS_ERROR_NET_ERROR_RESPONSE 等）时，
                    # 我们仍停在「人机验证未通过」，不能让原始导航异常冒泡成登录失效。
                    if _driver_closed(exc):
                        raise
                    notes.setdefault("cf_diagnostics", {}).update(
                        reason="reload_rejected", stage="session_cf_reload", error=_brief_error(exc),
                    )
                    ctx.log(f"重载挑战页失败（{_brief_error(exc)}），按人机验证未通过处理")
                    break
                continue
            break
        notes["stage"] = "session_verification"
        await _wait_loaded(page, timeout=_flow_timeout(20000))
        await lease.dismiss_popups(page=page)
        probe = await _session_probe(page, ctx.log)
        notes["session_probe"] = probe
        notes["throttled"] = bool(probe["throttled"])
        if probe["authenticated"]:
            notes["challenge_active"] = await _is_challenge(page)
            if not notes["challenge_active"]:
                return True, True, False
            notes.update(challenge_seen=True, stage="session_cf")
            notes.setdefault("cf_diagnostics", {}).update(reason="challenge_reappeared", stage="session_cf")
            challenge_cleared = False
            anonymous_hits = 0
            continue
        throttled = bool(probe["throttled"])
        page_challenge = await _is_challenge(page)
        notes["challenge_active"] = page_challenge or probe.get("reason") == "challenge"
        if notes["challenge_active"]:
            notes["challenge_seen"] = True
            challenge_cleared = False
            anonymous_hits = 0
            if page_challenge:
                continue
        anonymous_hits = anonymous_hits + 1 if not throttled else 0
        if anonymous_hits >= 2:
            return False, True, False
        if anonymous_hits:
            # 复核前的等待/导航也可能超时，此时不能把第一次匿名当成已确认失效。
            notes["throttled"] = True
            notes["session_probe"] = {**probe, "throttled": True, "reason": "anonymous_unconfirmed"}
        # 重试次数耗尽后不再导航；否则浪费预算，还会丢失最后响应对应的页面证据。
        if attempt < 2:
            await asyncio.sleep(6.0 if throttled else 1.5)
            await _safe_goto(lease, page, f"{LINUXDO_URL}/latest")
    if not throttled and anonymous_hits < 2 and challenge_cleared:
        throttled = True
        notes["throttled"] = True
        notes["session_probe"] = {**notes.get("session_probe", {}), "throttled": True,
                                  "reason": "anonymous_unconfirmed"}
    return False, challenge_cleared, throttled


_GITHUB_ENTRY_SELECTORS = (
    "button.btn-social.github",
    ".btn-social.github",
    'button[title*="GitHub" i]',
    'a[href="/auth/github"]',
    'form[action="/auth/github"] button',
)


async def _github_relogin(ctx: Any, lease: Any, page: Any, github_account: str) -> str:
    """用共享 GitHub 登录态登录 linux.do，成功后返回新的站点登录态快照。"""
    github_state = str(ctx.oauth_state("github", github_account) or "").strip()
    if not github_state:
        raise LoginRequired(
            f"LinuxDO 登录态已失效，且缺少 github:{github_account} 的共享登录态，无法回退登录。"
        )
    ctx.log(f"LinuxDO 登录态失效，回退到 GitHub（{github_account}）登录 linux.do")
    await lease.restore_state(github_state)

    notes = _FLOW.get() or {"deadline": time.monotonic() + 90}
    notes["stage"] = "github_entry_navigation"
    await _safe_goto(lease, page, f"{LINUXDO_URL}/login")
    if not await _clear_challenge(page, ctx.log, notes, "github_entry_cf"):
        raise VerificationRequired(
            "linux.do 登录页的人机验证未通过，无法用 GitHub 回退登录。", data=_flow_evidence(notes),
        )
    await _wait_loaded(page, timeout=_flow_timeout(20000))
    await lease.dismiss_popups(page=page)
    # 已登录用户访问 /login 会直接跳回首页。
    if await _logged_in(page):
        return await lease.export_state()

    clicked = False
    for selector in _GITHUB_ENTRY_SELECTORS:
        try:
            button = await page.wait_for_selector(selector, state="visible", timeout=_flow_timeout(6000))
        except Exception:
            continue
        if button is None:
            continue
        try:
            await button.click(timeout=_flow_timeout(5000))
            clicked = True
            break
        except Exception as exc:
            ctx.log(f"GitHub 登录按钮点击未成功（{type(exc).__name__}），尝试下一个入口")
    if not clicked:
        raise LoginRequired("linux.do 登录页未找到 GitHub 登录入口，无法回退登录。")

    # GitHub 侧：已授权则自动回跳；首次需点「Authorize」。
    loop = asyncio.get_running_loop()
    deadline = min(loop.time() + 90, notes["deadline"])
    authorized = False
    while loop.time() < deadline:
        await asyncio.sleep(1.0)
        try:
            url = page.url
        except Exception:
            url = ""
        parsed = urlsplit(url)
        host = (parsed.hostname or "").casefold()
        trusted = parsed.scheme == "https" and not parsed.username and not parsed.password
        if trusted and host == "linux.do" and parsed.port in (None, 443):
            if not await _clear_challenge(page, ctx.log, notes, "github_callback_cf"):
                raise VerificationRequired("GitHub 回站后的人机验证未通过。", data=_flow_evidence(notes))
            if "/login" not in urlsplit(url).path and "/auth/" not in urlsplit(url).path:
                authorized = True
                break
            continue
        if trusted and (host == "github.com" or host.endswith(".github.com")):
            if not await _clear_challenge(page, ctx.log, notes, "github_provider_cf"):
                raise VerificationRequired("GitHub 授权页的人机验证未通过。", data=_flow_evidence(notes))
            notes["stage"] = "github_approval"
            if "/login" in urlsplit(url).path and "/login/oauth/authorize" not in url:
                raise LoginRequired("GitHub 共享登录态已失效（停在 GitHub 登录页），请重新捕获 github 登录态。")
            for selector in ('button[name="authorize"][value="1"]', 'button#js-oauth-authorize-btn'):
                try:
                    button = await page.query_selector(selector)
                    if button is not None and await button.is_visible():
                        ctx.log("GitHub 授权页：点击 Authorize")
                        await button.click(timeout=_flow_timeout(5000))
                        break
                except Exception:
                    pass
    if not authorized:
        raise LoginRequired("GitHub 登录 linux.do 未在预期时间内跳回论坛，回退登录失败。")

    await _settle(page)
    await _wait_loaded(page)
    await lease.dismiss_popups(page=page)
    if not await _logged_in(page, ctx.log):
        await _safe_goto(lease, page, f"{LINUXDO_URL}/latest")
        await _wait_loaded(page)
        if not await _logged_in(page, ctx.log):
            raise LoginRequired("GitHub 已跳回 linux.do，但服务端会话仍未确认登录。")
    ctx.log("已通过 GitHub 重新登录 linux.do")
    return await lease.export_state()


async def _restore_login(ctx: Any, method: str) -> LoginState:
    provider = str(ctx.args.get("provider") or ctx.account.login.provider or "linuxdo").strip().lower()
    if provider != "linuxdo" or ctx.base_url.rstrip("/") != LINUXDO_URL:
        raise ConfigError("LinuxDO 刷帖只支持 https://linux.do 和 linuxdo 登录态。")
    account_name = str(ctx.args.get("account") or ctx.account.login.account or "default").strip()
    github_fallback = bool(ctx.args.get("github_fallback"))
    github_account = str(ctx.args.get("github_account") or "default").strip() or "default"
    state_text = str(ctx.credentials.browser_state or "").strip()
    has_account_state = bool(state_text)
    state_source = "account_snapshot" if has_account_state else "shared_snapshot"
    if not state_text:
        state_text = str(ctx.oauth_state("linuxdo", account_name) or "").strip()
    if state_text:
        # 账号缓存与共享快照都来自上一次浏览器；保留认证，不跨实例复用 CF 放行 Cookie。
        state_text = _shared_browser_state(state_text)
        ctx.log("恢复 LinuxDO 认证，清除上次浏览器的 Cloudflare 放行 Cookie")
    if not state_text and not github_fallback:
        raise LoginRequired(f"缺少 linuxdo:{account_name} 的登录态，请先捕获或开启 github_fallback。")
    remaining = ctx.deadline.remaining() if ctx.deadline is not None else None
    limit = 240.0 if github_fallback else 120.0
    budget = limit if remaining is None else max(0.0, min(limit, remaining - 20.0))
    if budget <= 0:
        raise LoginRequired("LinuxDO 登录校验没有剩余时间预算。")
    evidence: dict[str, Any] = {}
    deadline = time.monotonic() + budget
    observed: dict[str, Any] = {
        "deadline": deadline, "stage": "browser_startup", "log": ctx.log,
        "state_source": state_source, "state_diagnostics": _state_evidence(state_text),
    }
    ctx.log(f"LinuxDO 登录态来源：{state_source}；认证 Cookie 检查：{observed['state_diagnostics']}")
    token = _FLOW.set(observed)
    try:
        async with asyncio.timeout_at(deadline):
            async with ctx.browser.lease(reason="linuxdo_login", state_text=state_text) as lease:
                page = await lease.new_page()
                verified, challenge_cleared, throttled = (False, True, False)
                if state_text:
                    verified, challenge_cleared, throttled = await _verify_session(
                        ctx, lease, page, observed
                    )
                # CI 账号覆盖层独立于共享态：仅更新 Secret 的共享态不会失效旧账号缓存。
                # 只在明确匿名（非挑战/限流/未知响应）后补试同一共享账号，仍用原始总预算。
                if not verified and challenge_cleared and not throttled and has_account_state:
                    shared = str(ctx.oauth_state("linuxdo", account_name) or "").strip()
                    if shared:
                        shared = _shared_browser_state(shared)
                    if shared and not _same_browser_state(state_text, shared):
                        observed.update(
                            stage="shared_state_restore", state_source="shared_snapshot_fallback",
                            state_diagnostics=_state_evidence(shared),
                        )
                        ctx.log("账号快照已确认匿名，尝试同一 LinuxDO 共享账号的另一份快照（不重置时间预算）")
                        ctx.log(f"共享快照认证 Cookie 检查：{observed['state_diagnostics']}")
                        observed.pop("session_probe", None)
                        observed["throttled"] = True
                        await lease.restore_state(shared)
                        verified, challenge_cleared, throttled = await _verify_session(ctx, lease, page, observed)
                if verified:
                    lease.mark_authenticated()
                    return LoginState(
                        method=method, verified=True, origin="browser", note="已恢复并验证 LinuxDO 论坛会话"
                    )
                try:
                    async with asyncio.timeout(5):
                        evidence["screenshot"] = await lease.screenshot("linuxdo-login-failed.png", page=page)
                except Exception:
                    pass
                evidence.update(_flow_evidence(observed))
                if not challenge_cleared:
                    raise VerificationRequired(
                        "LinuxDO 页面或会话接口的人机验证尚未通过；已保留登录态，请完成验证或检查代理路由后重试。",
                        data=evidence
                    )
                if throttled:
                    # 限流时我们不知道登录态好不好，既不能说它失效，也不该用 GitHub
                    # 重登去覆盖一份可能完好的登录态。报瞬时错误，下轮重试即可。
                    raise TransientError(
                        f"LinuxDO 会话校验未完成（{_probe_summary(observed.get('session_probe', {}))}）；"
                        "已保留现有登录态，请根据响应诊断检查网络或稍后重试。",
                        data=evidence,
                    )
                if not github_fallback:
                    raise LoginRequired(
                        "LinuxDO 服务端复核为匿名会话。请重新捕获供 CI 专用的 linuxdo 登录态并更新 ACCOUNTS Secret，"
                        "或配置 github_fallback；相同代理订阅不代表相同登录会话。",
                        data=evidence,
                    )
                new_state = await _github_relogin(ctx, lease, page, github_account)
                lease.mark_authenticated()
                # 新登录态写入运行期覆盖层 browser_state（origin=oauth），下次直接覆写共享态。
                return LoginState(
                    method=method,
                    verified=True,
                    origin="oauth",
                    credentials={"browser_state": new_state},
                    note=f"LinuxDO 登录态失效，已用 GitHub（{github_account}）重新登录并续存",
                )
    except TimeoutError as exc:
        observed["timeout_stage"] = observed.get("stage", "session_verification")
        if observed.get("challenge_active", observed.get("challenge_seen", False)):
            diagnostics = observed.setdefault("cf_diagnostics", {})
            diagnostics.update(timeout_stage=observed["timeout_stage"], reason="deadline_exceeded")
            evidence.update(_flow_evidence(observed))
            raise VerificationRequired(
                "LinuxDO 人机验证未能在预算内通过；已保留共享登录态，可完成验证后重试。",
                data=evidence,
            ) from exc
        evidence.update(_flow_evidence(observed))
        if observed.get("throttled"):
            raise TransientError(
                f"LinuxDO 会话校验超时（{_probe_summary(observed.get('session_probe', {}))}）；已保留现有登录态。",
                data=evidence,
            ) from exc
        raise LoginRequired("LinuxDO 页面或登录校验超时，请检查网络或人机验证。", data=evidence) from exc
    finally:
        _FLOW.reset(token)


async def _open_topic(
    lease: Any, page: Any, link: str, *, notes: dict[str, Any] | None = None,
) -> bool:
    """主题正文和 CF 放行都确认后才允许开始阅读。"""
    notes = notes if notes is not None else (_FLOW.get() or {})
    notes["stage"] = "topic_navigation"
    try:
        response = await lease.goto(
            link, page=page, wait_until="domcontentloaded", timeout=_flow_timeout(25000, notes), ignore_timeout=False,
        )
        challenged = await _is_challenge(page)
        if challenged and not await _clear_challenge(page, notes.get("log", lambda _msg: None), notes, "topic_cf"):
            raise VerificationRequired("LinuxDO 主题页人机验证未通过，未计入阅读数。", data=_flow_evidence(notes))
        if not challenged and response is not None and response.status >= 400:
            return False
        notes["stage"] = "topic_load"
        await page.wait_for_selector(
            "article .cooked, .post-stream .cooked", state="visible", timeout=_flow_timeout(18000, notes),
        )
        return bool(_normalize_topic_url(link)) and _normalize_topic_url(page.url) == _normalize_topic_url(link)
    except VerificationRequired:
        raise
    except Exception:
        return False


# ── 主流程 ───────────────────────────────────────────────────────────────────

def _resume_progress(value: Any, today: str, min_secs: int) -> dict[str, Any] | None:
    """仅续读同一天、同等阅读要求且带有效主题明细的已完成阅读；不采信半途打开的帖子。"""
    if not isinstance(value, dict) or value.get("date") != today:
        return None
    count = value.get("posts_read")
    minimum = value.get("min_read_seconds")
    elapsed = value.get("reading_seconds")
    urls = value.get("topic_urls")
    if (type(count) is not int or count <= 0 or type(minimum) is not int or minimum < min_secs
            or not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool)
            or not isfinite(elapsed) or elapsed < count * minimum
            or not isinstance(urls, list) or len(urls) != count
            or not all(isinstance(url, str) for url in urls)):
        return None
    normalized = [_normalize_topic_url(url) for url in urls]
    if not all(normalized) or len(set(normalized)) != count:
        return None
    return {"posts_read": count, "topic_urls": normalized, "reading_seconds": float(elapsed)}


async def run(ctx: Any) -> Outcome:
    """按实际加载和阅读结果计数；只在达到本轮目标后记录每日完成。"""
    args = MANIFEST.task_option("browser_flow").args.resolve(ctx.args)
    max_posts = int(args["post_count"])
    min_secs = int(args["min_read_seconds"])
    max_secs = int(args["max_read_seconds"])
    if min_secs > max_secs:
        raise ConfigError("min_read_seconds 不能大于 max_read_seconds。")
    today = business_date()
    baseline: Any = None

    if args["once_per_day"]:
        baseline = ctx.store.get(STORE_KEY) or {}
        if isinstance(baseline, dict) and baseline.get("date") == today and baseline.get("completed") is True:
            try:
                count = int(baseline.get("posts_read") or 0)
            except (TypeError, ValueError):
                count = 0
            if count >= max_posts:
                return already_done(
                    f"今日已完成浏览（共 {count} 篇）", data=baseline
                ).with_display(DisplaySpec(text=str(count)))

    target_count = max_posts
    progress: dict[str, Any] = {
        "date": today, "target_count": target_count, "posts_read": 0,
        "topic_urls": [], "reading_seconds": 0.0, "completed": False, "min_read_seconds": min_secs,
    }
    resumed = _resume_progress(baseline, today, min_secs) if args["once_per_day"] else None
    if resumed:
        progress.update(resumed)
        ctx.log(f"恢复今日已完成阅读 {progress['posts_read']}/{target_count} 篇，仅补足剩余不同主题")
    ctx.log(f"目标浏览 {target_count} 篇帖子，每篇 {min_secs}~{max_secs} 秒")
    remaining = ctx.remaining_seconds()
    budget = 600.0 if remaining is None else max(0.0, remaining - 20.0)
    issue = "没有足够的可访问帖子"
    if budget <= 0:
        return failed("LinuxDO 浏览任务没有剩余时间预算", reason="unconfirmed", data=progress)

    deadline = time.monotonic() + budget
    notes: dict[str, Any] = {"deadline": deadline, "log": ctx.log, "stage": "browser_startup"}
    async with ctx.browser.lease(reason="linuxdo_browse") as lease:
        page = await lease.new_page()
        helpers = PageHelpers(ctx, lease, page)
        attempted: set[str] = set(progress["topic_urls"])
        throttle_hits = 0
        try:
            async with asyncio.timeout_at(deadline):
                # 失败主题不反复访问；每轮重新读取列表，让刷新后的新主题真正进入候选。
                for browse_attempt in range(target_count * 2):
                    if progress["posts_read"] >= target_count:
                        break
                    notes["stage"] = "list_navigation"
                    await lease.goto(
                        f"{LINUXDO_URL}/latest", page=page, wait_until="domcontentloaded",
                        timeout=_flow_timeout(25000, notes),
                    )
                    if not await _clear_challenge(page, ctx.log, notes, "list_cf"):
                        raise VerificationRequired("LinuxDO 列表页人机验证未通过。", data=_flow_evidence(notes))
                    notes["stage"] = "list_load"
                    if not await _wait_loaded(page, timeout=_flow_timeout(20000, notes)):
                        issue = "LinuxDO 列表加载超时"
                        break
                    await lease.dismiss_popups(page=page)
                    probe = await _session_probe(page, ctx.log)
                    notes["session_probe"] = probe
                    notes["challenge_active"] = probe.get("reason") == "challenge"
                    progress.update(_flow_evidence(notes))
                    if not probe["authenticated"]:
                        # 限流不是登录失效；也不能在最后一轮退避后落成「没有可访问帖子」。
                        can_retry = throttle_hits < _MAX_THROTTLE_RETRIES and browse_attempt + 1 < target_count * 2
                        if probe["throttled"] and can_retry:
                            throttle_hits += 1
                            ctx.log(
                                f"LinuxDO 会话校验暂不可用（{_probe_summary(probe)}），"
                                f"退避 {_THROTTLE_BACKOFF_SECONDS:.0f}s 后重试"
                                f"（第 {throttle_hits}/{_MAX_THROTTLE_RETRIES} 次）"
                            )
                            await asyncio.sleep(_THROTTLE_BACKOFF_SECONDS)
                            continue
                        if probe["throttled"]:
                            if probe.get("reason") == "challenge":
                                raise VerificationRequired(
                                    "LinuxDO 会话接口持续返回 Cloudflare 挑战，已保留登录态。",
                                    data=_flow_evidence(notes),
                                )
                            issue = f"LinuxDO 会话校验持续不可用（{_probe_summary(probe)}）"
                            progress.update(_flow_evidence(notes))
                            break
                        return helpers.need_login("LinuxDO 会话未通过服务端校验，请重新捕获登录态", detail=progress)
                    if not attempted:
                        lease.mark_authenticated()
                    candidates = [url for url in await _collect_topic_links(page) if url not in attempted]
                    if not candidates:
                        break
                    link = random.choice(candidates)
                    attempted.add(link)
                    read_secs = random.randint(min_secs, max_secs)
                    ctx.log(f"[{progress['posts_read'] + 1}/{target_count}] 打开帖子，阅读 {read_secs} 秒：{link}")
                    if not await _open_topic(lease, page, link, notes=notes):
                        ctx.log(f"帖子未正确加载，跳过：{link}")
                        continue
                    notes["stage"] = "topic_read"
                    elapsed = await _simulate_read(page, read_secs)
                    if await _is_challenge(page):
                        if not await _clear_challenge(page, ctx.log, notes, "reading_cf"):
                            raise VerificationRequired("LinuxDO 阅读被人机验证中断。", data=_flow_evidence(notes))
                        # 即使随后放行，这段时间也不能当作阅读了主题正文。
                        continue
                    progress["posts_read"] += 1
                    progress["topic_urls"].append(link)
                    progress["reading_seconds"] = round(progress["reading_seconds"] + elapsed, 2)
                    ctx.log(f"已完成阅读 {progress['posts_read']}/{target_count} 篇")
                    if args["once_per_day"] and not ctx.store.put(
                        STORE_KEY, {**progress, "topic_urls": list(progress["topic_urls"])},
                    ):
                        ctx.log("已读进度未能保存，本轮继续；未达到目标不会记录为每日完成")
                    if progress["posts_read"] < target_count:
                        await asyncio.sleep(random.uniform(1.0, 4.0))
        except VerificationRequired as exc:
            return failed(str(exc), reason="need_verification", data={**progress, **exc.data}).with_display(
                DisplaySpec(text=str(progress["posts_read"])),
            )
        except TimeoutError:
            notes["timeout_stage"] = notes.get("stage", "browse")
            progress.update(_flow_evidence(notes))
            if notes.get("challenge_active"):
                diagnostics = notes.setdefault("cf_diagnostics", {})
                diagnostics.update(timeout_stage=notes["timeout_stage"], reason="deadline_exceeded")
                progress.update(_flow_evidence(notes))
                return failed(
                    "LinuxDO 人机验证未能在预算内通过，未记录浏览完成。",
                    reason="need_verification", data=progress,
                ).with_display(DisplaySpec(text=str(progress["posts_read"])))
            issue = "已达到本轮时间预算"
        if progress["posts_read"] < target_count:
            try:
                async with asyncio.timeout(5):
                    progress["screenshot"] = await helpers.screenshot("linuxdo-browse-incomplete.png")
            except Exception:
                pass
            return failed(
                f"LinuxDO 浏览未完成：{issue}，实际阅读 {progress['posts_read']}/{target_count} 篇",
                reason="unconfirmed", data=progress,
            ).with_display(DisplaySpec(text=str(progress["posts_read"])))

    progress["completed"] = True
    if not ctx.store.put(STORE_KEY, progress):
        ctx.log("阅读已完成，但本次记录未能写入缓存")
    newly_read = progress["posts_read"] - (resumed["posts_read"] if resumed else 0)
    msg = f"LinuxDO 浏览完成，已读满 {progress['posts_read']}/{target_count} 篇，本轮实际阅读 {newly_read} 篇"
    ctx.log(msg)
    return ok(msg, data=progress).with_display(DisplaySpec(text=str(progress["posts_read"])))
