"""LinuxDO 刷帖任务。

访问 linux.do 论坛，使用共享浏览器登录态，模拟人类化浏览帖子：
- 随机点进帖子，每篇停留随机可控时长
- 贝塞尔曲线平滑鼠标移动 + 分段随机滚动，模拟真实阅读节奏
- 每篇读完后在 Discourse 站内路由回到最新列表，获取新帖；整页导航只用于首轮与故障恢复
  （每次整页导航都可能触发一次 Cloudflare 托管挑战，单篇耗时会从十几秒涨到近一分钟）

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
from login.oauth import oauth_state_update  # noqa: E402
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
    notes["stage"] = stage
    notes["challenge_seen"] = True
    diagnostics = {
        "stage": stage, "target_kind": "unknown", "clicked": False, "timeout_stage": "", "reason": "",
    }
    notes["cf_diagnostics"] = diagnostics
    remaining = 50.0 if deadline is None else max(0.0, min(50.0, deadline - time.monotonic()))
    try:
        async with asyncio.timeout_at(deadline):
            result = await bypass.TurnstileBypass(log=log).solve_result(
                page, mode="page_access", timeout=remaining, deadline=deadline, diagnostics=diagnostics,
            )
            from runtime.events import challenge_data, emit_challenge
            diagnostics.update(challenge_data(result))
            emit_challenge(result)
            cleared = result.ok
    finally:
        diagnostics["flow_stage"] = stage
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
                        maximum=300,
                        title="浏览帖子数",
                        help="每次必须实际读完的不同主题数；超过列表一页时会自动翻页取候选，未达到该数量不记录为每日完成",
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
#: 列表页加载超时的重试上限。列表页只是一次普通导航，单次超时多为挑战抖动；
#: 之前一次失败就 break，会把剩余预算整段丢掉，只读一两篇就收工。
_MAX_LIST_LOAD_RETRIES = 3

#: 列表单页大约几十条主题。目标篇数超过一页时只看第一页，已读主题被排除后候选
#: 很快耗尽，任务只能以「没有足够的可访问帖子」收尾；因此候选取尽后要往后翻页。
#: 翻页数按目标篇数推算，并用上限兜住目标被抬得过高的情况。
_TOPICS_PER_PAGE = 30
_MAX_LIST_PAGES = 8

#: 列表页 CF 挑战的换页重试次数。一次未放行（包括点击后未确认、预算耗尽）就整轮失败
#: 会让长任务永远停在开头几篇；在总预算内重载换一张新挑战通常能过。只有受信拒绝或
#: 熔断才立即终止。
_MAX_LIST_CF_RETRIES = 3
#: 主题页（整页兜底导航时）CF 未放行的累计容忍次数；超过才以 need_verification 结束。
_MAX_TOPIC_CF_RETRIES = 2
#: 候选池低于该数量时，先在当前列表滚动加载更多，而不是整页翻页。
_POOL_LOW_WATERMARK = 3

# ── Discourse 站内（SPA）导航 ────────────────────────────────────────────────
# 实测：整页 goto 几乎每次都触发 CF 托管挑战（30-50s）；站内路由只走 XHR，进入主题约 2s。

#: 列表页就绪：路径确为最新列表，且主列表已渲染主题链接（主题页底部的「推荐话题」不算）。
_LIST_READY_JS = r"""() => {
    if (location.origin !== 'https://linux.do') return false;
    if (!/^\/(latest|new|top|unread)?\/?$/.test(location.pathname)) return false;
    return Boolean(document.querySelector(
        '#main-outlet .topic-list tr.topic-list-item a.raw-topic-link, #main-outlet .topic-list tr.topic-list-item a.title'));
}"""

#: 主题就绪判定：URL 和正文都必须属于目标主题 ID，避免把上一篇残留的正文当作新主题。
_TOPIC_STATE_JS = r"""(topicId) => {
    if (location.origin !== 'https://linux.do') return 'pending';
    const parts = location.pathname.replace(/^\/+|\/+$/g, '').split('/');
    if (parts[0] !== 't') return 'pending';
    const id = /^\d+$/.test(parts[2] || '') ? parts[2] : parts[1];
    if (String(id) !== String(topicId)) return 'pending';
    const visible = el => Boolean(el && el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden');
    const root = document.querySelector('#topic[data-topic-id="' + topicId + '"]');
    if (root) {
        const body = root.querySelector('#post_1 .cooked, .topic-post .cooked, article .cooked');
        if (visible(body)) return 'ready';
    } else if (!document.querySelector('#topic[data-topic-id]')) {
        // 旧版布局没有 data-topic-id：URL 已核对主题 ID，正文只认主帖流。
        if (visible(document.querySelector('.post-stream #post_1 .cooked, .post-stream article .cooked'))) return 'ready';
    }
    if (document.querySelector('#main-outlet .page-not-found, .page-not-found')) return 'missing';
    if (document.querySelector('#main-outlet .topic-error, .topic-error')) return 'error';
    return 'pending';
}"""

#: 在页面主世界触发 Discourse 路由；拿不到路由模块时退化为让 Discourse 拦截一次站内链接点击。
_SPA_ROUTE_JS = r"""(path) => {
    if (location.origin !== 'https://linux.do' || typeof path !== 'string' || !path.startsWith('/')) return 'blocked';
    try {
        const req = window.require || window.requirejs;
        if (typeof req === 'function') {
            const mod = req('discourse/lib/url');
            const api = (mod && mod.default) || mod;
            if (api && typeof api.routeTo === 'function') { api.routeTo(path); return 'route'; }
        }
    } catch (_) {}
    const outlet = document.querySelector('#main-outlet') || document.body;
    if (!outlet) return 'unavailable';
    const a = document.createElement('a');
    a.href = path;
    a.style.display = 'none';
    outlet.appendChild(a);
    try { a.click(); } finally { a.remove(); }
    return 'anchor';
}"""

#: 列表里指向目标主题的可见链接序号，供真实鼠标点击；按主题 ID 匹配，不信任 slug。
_TOPIC_ANCHOR_JS = r"""([selectors, topicId]) => {
    const nodes = Array.from(document.querySelectorAll(selectors));
    return nodes.findIndex(a => {
        let url;
        try { url = new URL(a.href, location.href); } catch (_) { return false; }
        if (url.origin !== 'https://linux.do') return false;
        const parts = url.pathname.replace(/^\/+|\/+$/g, '').split('/');
        const id = /^\d+$/.test(parts[2] || '') ? parts[2] : parts[1];
        return parts[0] === 't' && String(id) === String(topicId) && a.getClientRects().length > 0;
    });
}"""

_LIST_ROWS_JS = "() => document.querySelectorAll('#main-outlet .topic-list tr.topic-list-item').length"


def _topic_id(link: str) -> str:
    normalized = _normalize_topic_url(link)
    return normalized.rsplit("/", 1)[-1] if normalized else ""


async def _evaluate(page: Any, script: str, arg: Any = None, *, seconds: float = 5.0) -> Any:
    """单次页面脚本调用有界：导航中途的 evaluate 可能挂起，不能吃掉整轮预算。"""
    call = page.evaluate(script) if arg is None else page.evaluate(script, arg)
    return await asyncio.wait_for(call, timeout=max(0.05, min(seconds, _flow_timeout(int(seconds * 1000)) / 1000)))


async def _poll(page: Any, script: str, arg: Any, accept: Any, timeout_ms: int, interval: float = 0.3) -> Any:
    """轮询页面状态直到 accept(value) 为真或超时；单次读取失败（导航中）按未就绪处理。"""
    loop = asyncio.get_running_loop()
    stop = loop.time() + max(0, timeout_ms) / 1000
    value: Any = None
    while True:
        try:
            value = await _evaluate(page, script, arg, seconds=min(5.0, max(0.05, stop - loop.time())))
        except Exception:
            deadline = (_FLOW.get() or {}).get("deadline")
            if deadline is not None and deadline <= time.monotonic():
                raise TimeoutError from None
            value = None
        if accept(value):
            return value
        if loop.time() >= stop:
            return value
        await asyncio.sleep(min(interval, max(0.0, stop - loop.time())))


async def _wait_list_ready(page: Any, timeout: int = 20000) -> bool:
    """列表页真正渲染出主列表主题链接；页头/外壳出现不算，CF 挑战页也不算。"""
    value = await _poll(page, _LIST_READY_JS, None, lambda v: v is True, _flow_timeout(timeout))
    return value is True


async def _spa_route(page: Any, path: str) -> str:
    try:
        result = await _evaluate(page, _SPA_ROUTE_JS, path)
    except Exception:
        return "unavailable"
    return result if isinstance(result, str) else "unavailable"


async def _return_to_list(page: Any, timeout: int = 15000) -> bool:
    """站内路由回到最新列表（不重载文档、不触发新的整页 CF 挑战）。"""
    if await _spa_route(page, "/latest") not in {"route", "anchor"}:
        return False
    return await _wait_list_ready(page, timeout=timeout)


async def _load_more_topics(page: Any, timeout: int = 12000) -> bool:
    """在列表页像真人一样往下滚，让 Discourse 自己的无限滚动通过 XHR 追加主题。"""
    try:
        before = int(await _evaluate(page, _LIST_ROWS_JS) or 0)
    except Exception:
        return False
    loop = asyncio.get_running_loop()
    stop = loop.time() + _flow_timeout(timeout) / 1000
    while loop.time() < stop:
        try:
            await page.mouse.wheel(0, random.randint(1800, 3200))
        except Exception:
            return False
        await asyncio.sleep(random.uniform(0.6, 1.2))
        try:
            if int(await _evaluate(page, _LIST_ROWS_JS) or 0) > before:
                await asyncio.sleep(random.uniform(0.5, 1.0))  # 让追加的整批行渲染完
                return True
        except Exception:
            pass
    return False


async def _click_topic_link(page: Any, topic_id: str) -> bool:
    """列表上有该主题的可见链接时用真实鼠标点击进入；找不到或点不动就交给路由兜底。"""
    selectors = ", ".join(_TOPIC_SELECTORS)
    try:
        index = await _evaluate(page, _TOPIC_ANCHOR_JS, [selectors, topic_id])
        if type(index) is not int or index < 0:
            return False
        await page.locator(selectors).nth(index).click(timeout=_flow_timeout(5000))
        return True
    except Exception:
        return False


async def _spa_open_topic(page: Any, topic_id: str, *, from_list: bool) -> str:
    """返回触发方式：click / route / anchor；无法触发站内导航时返回空串。"""
    if from_list and await _click_topic_link(page, topic_id):
        return "click"
    method = await _spa_route(page, f"/t/topic/{topic_id}")
    return method if method in {"route", "anchor"} else ""


async def _topic_state(page: Any, topic_id: str, timeout: int) -> str:
    value = await _poll(page, _TOPIC_STATE_JS, topic_id, lambda v: v in {"ready", "missing", "error"}, timeout)
    return value if value in {"ready", "missing", "error"} else "timeout"


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
            if cf_diagnostics.get("preserve_page", True) or not cf_diagnostics.get("retry_allowed", False):
                notes["stage"] = "session_cf_preserved"
                break
            # 仅结构化结果明确允许重试时，才可以在原总预算内导航。
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
    from browser import storage_scope
    from browser.oauth_providers import GitHubProvider

    resolver = getattr(ctx, "resolve_oauth", None)
    if callable(resolver):
        github_state, github_source = resolver("github", github_account)
    else:
        github_state, github_source = ctx.oauth_state("github", github_account), None
    github_state = str(github_state or "").strip()
    if not github_state:
        raise LoginRequired(
            f"LinuxDO 登录态已失效，且缺少 github:{github_account} 的共享登录态，无法回退登录。"
        )
    # 不把共享快照里混杂的 LinuxDO 身份/站点存储导入论坛；来源固定为此次解析的 revision。
    scoped = GitHubProvider().keepalive_storage_state(decode_state(github_state))
    ctx.log(f"LinuxDO 登录态失效，回退到 GitHub（{github_account}）登录 linux.do")
    restored = await lease.restore_state(encode_state(scoped))
    if restored is False:
        raise TransientError("GitHub 提供商态未重新安装，保留现有共享登录态，稍后重试。")
    track = getattr(lease, "track_shared", None)

    notes = _FLOW.get() or {"deadline": time.monotonic() + 90}
    notes.pop("_github_updates", None)
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
    # _logged_in 兼容 DOM 兜底以便任务继续，但它不能授权共享态写回或收尾同步。
    confirmed = False
    if github_source is not None:
        probe = await _session_probe(page, ctx.log)
        confirmed = (probe.get("reason") == "authenticated" and probe.get("source") != "dom"
                     and type(probe.get("status")) is int and 200 <= probe["status"] < 300)
    if confirmed and callable(track):
        track("github", github_account, storage_scope.provider_auth_values(scoped, "github"))
    new_state = await lease.export_state()
    # 只发布本次 GitHub 来源的服务端轮换；新论坛身份只能进入账号级缓存，不能替换原 LinuxDO 共享账号。
    update = oauth_state_update(
        github_source, decode_state(new_state), "github", base_url=LINUXDO_URL, fresh_authorization=True,
    ) if confirmed else None
    if update is not None:
        notes["_github_updates"] = (update,)
    return new_state


def _fresher_state(ctx: Any, account_name: str, account_state: str) -> tuple[str, Any, str]:
    """账号快照 vs 共享态：返回 (改用的共享态, 其来源, 需登记谱系的态)。

    - 两者 _t 相同：仍用账号快照，但它就是共享会话，登记谱系以便收尾同步轮换；
    - 共享态 _t 更晚到期（或账号快照读不出到期时间）：改用共享态；
    - 其余（账号快照更新、或共享态缺失/损坏）：维持原有账号优先。
    """
    from browser import storage_scope

    resolver = getattr(ctx, "resolve_oauth", None)
    if not callable(resolver):
        return "", None, ""
    try:
        shared_text, source = resolver("linuxdo", account_name)
        shared_text = str(shared_text or "").strip()
        if not shared_text:
            return "", None, ""
        shared = storage_scope.provider_storage_state(decode_state(shared_text), "linuxdo")
        account = decode_state(account_state)
    except Exception:
        return "", None, ""
    shared_values = storage_scope.provider_auth_values(shared, "linuxdo")
    if not shared_values:
        return "", None, ""
    if shared_values == storage_scope.provider_auth_values(account, "linuxdo"):
        return "", None, account_state
    shared_expiry = storage_scope.provider_auth_expiry(shared, "linuxdo")
    account_expiry = storage_scope.provider_auth_expiry(account, "linuxdo")
    if shared_expiry is not None and (account_expiry is None or shared_expiry > account_expiry):
        encoded = encode_state(shared)
        return encoded, source, encoded
    return "", None, ""


def _track_lineage(lease: Any, account_name: str, state_text: str) -> None:
    """登记本上下文的论坛会话属于共享态 linuxdo:<账号>，收尾时同步其轮换。"""
    track = getattr(lease, "track_shared", None)
    if not state_text or not callable(track):
        return
    try:
        from browser import storage_scope

        track("linuxdo", account_name, storage_scope.provider_auth_values(decode_state(state_text), "linuxdo"))
    except Exception:
        pass


async def _restore_login(ctx: Any, method: str) -> LoginState:
    provider = str(ctx.args.get("provider") or ctx.account.login.provider or "linuxdo").strip().lower()
    if provider != "linuxdo" or ctx.base_url.rstrip("/") != LINUXDO_URL:
        raise ConfigError("LinuxDO 刷帖只支持 https://linux.do 和 linuxdo 登录态。")
    account_name = str(ctx.args.get("account") or ctx.account.login.account or "default").strip()
    github_fallback = str(ctx.args.get("github_fallback") or "").strip().lower() in {"1", "true", "yes", "y", "on"}
    github_account = str(ctx.args.get("github_account") or "default").strip() or "default"
    state_text = str(ctx.credentials.browser_state or "").strip()
    has_account_state = bool(state_text)
    state_source = "account_snapshot" if has_account_state else "shared_snapshot"
    shared_source = None
    if not state_text:
        resolver = getattr(ctx, "resolve_oauth", None)
        if callable(resolver):
            state_text, shared_source = resolver("linuxdo", account_name)
            state_text = str(state_text or "").strip()
            if shared_source is not None and state_text:
                from browser.storage_scope import provider_storage_state

                state_text = encode_state(provider_storage_state(decode_state(state_text), "linuxdo"))
            if bool(getattr(ctx.browser, "started", False)):
                shared_source = None
        else:
            state_text = str(ctx.oauth_state("linuxdo", account_name) or "").strip()
    lineage = ""
    if has_account_state:
        # 账号快照与共享态可能是同一会话的两份副本；论坛滚动轮换 _t 后旧值只有约一分钟
        # 宽限。按静态到期时间择新：共享态更新（保活或别的任务刚续过）就直接用它。
        chosen, chosen_source, lineage = _fresher_state(ctx, account_name, state_text)
        if chosen:
            state_text, shared_source = chosen, chosen_source
            state_source, has_account_state = "shared_snapshot", False
            if bool(getattr(ctx.browser, "started", False)):
                shared_source = None
            ctx.log("共享 LinuxDO 登录态比账号快照更新，改用共享登录态")
    elif shared_source is not None or state_text:
        lineage = state_text
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
                _track_lineage(lease, account_name, lineage)
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
                        _track_lineage(lease, account_name, shared)
                        verified, challenge_cleared, throttled = await _verify_session(ctx, lease, page, observed)
                if verified:
                    lease.mark_authenticated()
                    updates = ()
                    # 只有直接使用同一个共享 LinuxDO 身份、且服务端确认后，才尝试
                    # 以 provider-only 快照轮换共享 Cookie；账号级站点快照、GitHub
                    # fallback 和本地过期复活都不能覆盖共享态。
                    probe = observed.get("session_probe") or {}
                    confirmed_shared = (
                        shared_source is not None and state_source == "shared_snapshot"
                        and probe.get("reason") == "authenticated" and probe.get("source") != "dom"
                        and type(probe.get("status")) is int and 200 <= probe["status"] < 300
                    )
                    if confirmed_shared:
                        try:
                            remaining = max(0.001, min(8.0, deadline - time.monotonic()))
                            snapshot = await asyncio.wait_for(lease.context.storage_state(), timeout=remaining)
                            rotated = oauth_state_update(
                                shared_source, snapshot, "linuxdo", base_url="", same_identity=True,
                            )
                            if rotated is not None:
                                updates = (rotated,)
                        except Exception:
                            updates = ()
                    return LoginState(
                        method=method,
                        verified=True,
                        origin="browser",
                        oauth_updates=updates,
                        note="已恢复并验证 LinuxDO 论坛会话",
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
                # 论坛身份仅更新账号级 browser_state；共享更新只来自本次 GitHub 的原始来源。
                return LoginState(
                    method=method,
                    verified=True,
                    origin="oauth",
                    credentials={"browser_state": new_state},
                    oauth_updates=observed.get("_github_updates", ()),
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


async def keepalive_session(lease: Any, *, log: Any, deadline: float) -> tuple[str, dict[str, Any] | None]:
    """像真人回访论坛一样续期共享会话：打开 /latest，经服务端确认登录后导出新快照。

    Discourse 在已登录的页面请求上滚动轮换 ``_t`` 并重置其有效期，因此一次被服务端
    认账的正常访问本身就是续期。返回 ``(结论, storage_state)``，结论取值：
    ``authenticated``（仅此时带快照）/ ``anonymous``（服务端确认登录态已失效）/
    ``challenge``（人机验证未过）/ ``undetermined``（限流、网络等无法判定）。
    """
    ctx = type("KeepaliveCtx", (), {"log": staticmethod(log)})()
    observed: dict[str, Any] = {"deadline": deadline, "stage": "keepalive", "log": log}
    token = _FLOW.set(observed)
    try:
        async with asyncio.timeout_at(deadline):
            page = await lease.new_page()
            verified, challenge_cleared, throttled = await _verify_session(ctx, lease, page, observed)
            probe = observed.get("session_probe") or {}
            # DOM 兜底只能说明页面渲染了头像，不能证明会话接口认账；续期写回必须要后者。
            if verified and probe.get("source") != "dom" and probe.get("reason") == "authenticated":
                lease.mark_authenticated()
                remaining = max(0.001, min(8.0, deadline - time.monotonic()))
                state = await asyncio.wait_for(lease.context.storage_state(), timeout=remaining)
                return "authenticated", state
            if not challenge_cleared:
                return "challenge", None
            if throttled or verified:
                return "undetermined", None
            # 判失效要求两条证据同时成立：会话接口说匿名，且页面本身也不像已登录。
            # 保活恢复的是 provider 范围的态，缺少 cf_clearance 时 CF 边缘对 XHR
            # 可能直接回 404 空正文，与 Discourse 匿名答复同形；只看接口就断言
            # 「登录态已失效」会把一份本来有效的态判死，让用户白跑一次重捕。
            if await _dom_logged_in(page):
                log("LinuxDO 会话接口报匿名但页面仍显示已登录，按无法判定处理，保留现有登录态")
                return "undetermined", None
            return "anonymous", None
    except TimeoutError:
        return ("challenge" if observed.get("challenge_active") else "undetermined"), None
    finally:
        _FLOW.reset(token)


async def _open_topic(
    lease: Any, page: Any, link: str, *, notes: dict[str, Any] | None = None,
    spa: bool = True, from_list: bool = False,
) -> bool:
    """主题正文和 CF 放行都确认后才允许开始阅读。失败原因写入 notes["topic_failure"]。

    优先站内导航（列表上真实点击 → Discourse 路由），只有站内导航触发不了或卡住时才整页
    打开；整页打开可能遇到 CF 挑战，未放行时抛 VerificationRequired，由调用方决定是否恢复。
    明确的「主题不存在/无权访问」不再整页重试。
    """
    notes = notes if notes is not None else (_FLOW.get() or {})
    notes["stage"] = "topic_navigation"
    notes.pop("topic_failure", None)
    notes.pop("topic_via", None)
    started = time.monotonic()
    topic_id = _topic_id(link)
    log = notes.get("log", lambda _msg: None)

    def fail(reason: str) -> bool:
        notes["topic_failure"] = f"{reason}（{time.monotonic() - started:.1f}s）"
        return False

    if not topic_id:
        return fail("主题链接无效")
    spa_note = ""
    try:
        if spa:
            notes["stage"] = "topic_spa_navigation"
            method = await _spa_open_topic(page, topic_id, from_list=from_list)
            if method:
                notes["stage"] = "topic_spa_load"
                state = await _topic_state(page, topic_id, _flow_timeout(15000, notes))
                if state == "ready" and _normalize_topic_url(page.url) == _normalize_topic_url(link):
                    notes["topic_via"] = method
                    return True
                if state == "missing":
                    return fail("主题不存在或无权访问")
                spa_note = f"站内导航（{method}）{'加载出错' if state == 'error' else '未就绪'}，改为整页打开；"
            else:
                spa_note = "站内导航不可用，改为整页打开；"
        notes["stage"] = "topic_navigation"
        response = await lease.goto(
            link, page=page, wait_until="domcontentloaded", timeout=_flow_timeout(25000, notes), ignore_timeout=False,
        )
        challenged = await _is_challenge(page)
        if challenged and not await _clear_challenge(page, log, notes, "topic_cf"):
            raise VerificationRequired("LinuxDO 主题页人机验证未通过，未计入阅读数。", data=_flow_evidence(notes))
        status = getattr(response, "status", None)
        if not challenged and type(status) is int and status >= 400:
            return fail(f"{spa_note}HTTP {status}")
        notes["stage"] = "topic_load"
        state = await _topic_state(page, topic_id, _flow_timeout(18000, notes))
        if state == "timeout" and await _is_challenge(page):
            # domcontentloaded 时挑战可能尚未挂载；正文迟迟不出现时复查一次同一页面。
            if not await _clear_challenge(page, log, notes, "topic_cf"):
                raise VerificationRequired("LinuxDO 主题页人机验证未通过，未计入阅读数。", data=_flow_evidence(notes))
            notes["stage"] = "topic_load"
            state = await _topic_state(page, topic_id, _flow_timeout(18000, notes))
        if state != "ready":
            return fail(f"{spa_note}{'主题不存在或无权访问' if state == 'missing' else 'topic_load ' + state}")
        if _normalize_topic_url(page.url) != _normalize_topic_url(link):
            return fail(f"{spa_note}页面落到其他地址")
        notes["topic_via"] = "goto"
        return True
    except VerificationRequired:
        raise
    except TimeoutError:
        if notes.get("deadline") is not None and notes["deadline"] <= time.monotonic():
            raise
        return fail(f"{spa_note}{notes.get('stage')} 超时")
    except Exception as exc:
        if "Timeout" in type(exc).__name__:
            return fail(f"{spa_note}{notes.get('stage')} 超时")
        return fail(f"{spa_note}{notes.get('stage')} {_brief_error(exc)}")


async def _load_list(lease: Any, page: Any, url: str, log: Any, notes: dict[str, Any]) -> bool:
    """整页打开列表并等主列表真正渲染。CF 未确认/列表未出现都在总预算内有限恢复。

    返回 False 表示多次重载后列表仍未就绪（调用方按「列表加载超时」收尾）；CF 受信拒绝、
    熔断或重试耗尽抛 VerificationRequired；总预算耗尽抛 TimeoutError（已读进度由调用方保留）。
    """
    cf_failures = 0
    load_failures = 0
    while True:
        notes["stage"] = "list_navigation"
        await lease.goto(url, page=page, wait_until="domcontentloaded", timeout=_flow_timeout(25000, notes))
        settled = False
        for _round in range(2):
            if not await _clear_challenge(page, log, notes, "list_cf"):
                break
            notes["stage"] = "list_load"
            if await _wait_list_ready(page, timeout=_flow_timeout(20000, notes)):
                return True
            # 放行判定后列表仍未出现：常见是 CF 放行后的自跳转或新挂载的挑战。先在同一页面
            # 复查，不立刻重载——重载只会换来一张新的托管挑战。
            if not await _is_challenge(page):
                settled = True
                break
        else:
            settled = True
        if settled:
            load_failures += 1
            if load_failures > _MAX_LIST_LOAD_RETRIES:
                return False
            log(f"LinuxDO 列表加载超时，重载重试（第 {load_failures}/{_MAX_LIST_LOAD_RETRIES} 次）")
            await asyncio.sleep(2.0)
            continue
        diagnostics = notes.get("cf_diagnostics") or {}
        if diagnostics.get("reason") == "circuit_open" or diagnostics.get("status") == "rejected":
            raise VerificationRequired(
                "LinuxDO 列表页人机验证被明确拒绝或本轮求解预算已耗尽，已保留登录态。",
                data=_flow_evidence(notes),
            )
        cf_failures += 1
        if cf_failures >= _MAX_LIST_CF_RETRIES:
            raise VerificationRequired("LinuxDO 列表页人机验证多次未通过，已保留登录态与已读进度。", data=_flow_evidence(notes))
        # 点击后未确认 / 原预算耗尽：同一张挑战已不会再给预算，重载换一张新挑战。
        log(f"列表页 Cloudflare 未确认放行，重载换一张新挑战重试（第 {cf_failures + 1}/{_MAX_LIST_CF_RETRIES} 次）")
        await asyncio.sleep(1.0)


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
    flow_token = _FLOW.set(notes)
    try:
        async with ctx.browser.lease(reason="linuxdo_browse") as lease:
            page = await lease.new_page()
            helpers = PageHelpers(ctx, lease, page)
            attempted: set[str] = set(progress["topic_urls"])
            #: 已收集但还没打开过的候选。一次列表加载就攒够候选，后续不必每篇都重开列表。
            pool: list[str] = []
            throttle_hits = 0
            topic_cf_failures = 0
            #: 只有首轮、故障恢复和翻页才整页打开列表；其余都在站内路由回列表。
            need_full_list = True
            on_list = False
            list_page = 0
            max_list_page = max(1, min(_MAX_LIST_PAGES, -(-target_count // _TOPICS_PER_PAGE)))
            max_cycles = (target_count * 3 + max_list_page + _MAX_THROTTLE_RETRIES
                          + _MAX_TOPIC_CF_RETRIES + _MAX_LIST_LOAD_RETRIES)
            try:
                async with asyncio.timeout_at(deadline):
                    for browse_attempt in range(max_cycles):
                        if progress["posts_read"] >= target_count:
                            break
                        cycle_started = time.monotonic()
                        fresh: list[str] = []
                        if not need_full_list and not on_list:
                            notes["stage"] = "list_spa_navigation"
                            on_list = await _return_to_list(page, timeout=_flow_timeout(15000, notes))
                            if not on_list and not pool:
                                ctx.log("站内返回列表未就绪，改为整页打开列表")
                                need_full_list = True
                        if need_full_list:
                            list_url = f"{LINUXDO_URL}/latest" + (f"?page={list_page}" if list_page else "")
                            if not await _load_list(lease, page, list_url, ctx.log, notes):
                                issue = "LinuxDO 列表加载超时"
                                break
                            need_full_list = False
                            on_list = True
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
                                need_full_list = True
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
                        if on_list:
                            fresh = [url for url in await _collect_topic_links(page) if url not in attempted]
                            remaining_need = target_count - progress["posts_read"]
                            if len(set(fresh) | set(pool)) < min(remaining_need, _POOL_LOW_WATERMARK) or (
                                    not fresh and not pool):
                                notes["stage"] = "list_more"
                                if await _load_more_topics(page, timeout=_flow_timeout(12000, notes)):
                                    fresh = [url for url in await _collect_topic_links(page) if url not in attempted]
                            pool = list(dict.fromkeys([*fresh, *(url for url in pool if url not in attempted)]))
                            ctx.log(
                                f"列表就绪耗时 {time.monotonic() - cycle_started:.1f}s，"
                                f"本页候选 {len(fresh)} 篇，候选池 {len(pool)} 篇"
                            )
                        candidates = [url for url in (fresh or pool) if url not in attempted]
                        if not candidates:
                            # 当前列表滚动也取不到新主题：整页翻到下一页，翻到上限才收尾。
                            if list_page + 1 < max_list_page:
                                list_page += 1
                                need_full_list = True
                                continue
                            break
                        link = random.choice(candidates)
                        attempted.add(link)
                        pool = [url for url in pool if url != link]
                        read_secs = random.randint(min_secs, max_secs)
                        ctx.log(f"[{progress['posts_read'] + 1}/{target_count}] 打开帖子，阅读 {read_secs} 秒：{link}")
                        from_list = on_list
                        on_list = False
                        topic_started = time.monotonic()
                        try:
                            opened = await _open_topic(lease, page, link, notes=notes, from_list=from_list)
                        except VerificationRequired:
                            diagnostics = notes.get("cf_diagnostics") or {}
                            topic_cf_failures += 1
                            if (topic_cf_failures > _MAX_TOPIC_CF_RETRIES or diagnostics.get("reason") == "circuit_open"
                                    or diagnostics.get("status") == "rejected"):
                                raise
                            ctx.log(f"帖子页 Cloudflare 未放行，未计入阅读；整页重开列表继续"
                                    f"（第 {topic_cf_failures}/{_MAX_TOPIC_CF_RETRIES} 次）：{link}")
                            need_full_list = True
                            continue
                        if not opened:
                            ctx.log(f"帖子未正确加载（{notes.get('topic_failure') or '原因未知'}），跳过：{link}")
                            continue
                        ctx.log(f"帖子已就绪（{notes.get('topic_via') or '已加载'}，{time.monotonic() - topic_started:.1f}s）")
                        notes["stage"] = "topic_read"
                        elapsed = await _simulate_read(page, read_secs)
                        if await _is_challenge(page):
                            # 即使随后放行，这段时间也不能当作阅读了主题正文。
                            cleared = await _clear_challenge(page, ctx.log, notes, "reading_cf")
                            if not cleared:
                                topic_cf_failures += 1
                                if topic_cf_failures > _MAX_TOPIC_CF_RETRIES:
                                    raise VerificationRequired("LinuxDO 阅读被人机验证中断。", data=_flow_evidence(notes))
                            ctx.log(f"阅读期间出现 Cloudflare 挑战，本篇不计入：{link}")
                            need_full_list = True
                            continue
                        progress["posts_read"] += 1
                        progress["topic_urls"].append(link)
                        progress["reading_seconds"] = round(progress["reading_seconds"] + elapsed, 2)
                        ctx.log(
                            f"已完成阅读 {progress['posts_read']}/{target_count} 篇"
                            f"（本篇耗时 {time.monotonic() - cycle_started:.1f}s）"
                        )
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
    finally:
        _FLOW.reset(flow_token)

    progress["completed"] = True
    if not ctx.store.put(STORE_KEY, progress):
        ctx.log("阅读已完成，但本次记录未能写入缓存")
    newly_read = progress["posts_read"] - (resumed["posts_read"] if resumed else 0)
    msg = f"LinuxDO 浏览完成，已读满 {progress['posts_read']}/{target_count} 篇，本轮实际阅读 {newly_read} 篇"
    ctx.log(msg)
    return ok(msg, data=progress).with_display(DisplaySpec(text=str(progress["posts_read"])))
