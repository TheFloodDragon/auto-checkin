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
                        help="每次随机浏览上限一半（向上取整）到上限之间的帖子数",
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
    """收集当前列表的站内主题，排除外站链接并按主题去重。"""
    try:
        hrefs = await page.evaluate(
            "selectors => Array.from(document.querySelectorAll(selectors)).map(a => a.href)",
            ", ".join(_TOPIC_SELECTORS),
        )
    except Exception:
        return []
    if not isinstance(hrefs, list):
        return []
    return list(dict.fromkeys(url for item in hrefs if (url := _normalize_topic_url(item))))


#: 服务端「这次答不了」的状态码。限流与网关错误都是瞬时的，和登录态有效性无关：
#: 把它们当成 need_login 会催用户白白重新捕获一份其实还好用的登录态。
_TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504, 520, 521, 522, 523, 524})

#: 刷帖循环里遇到限流时的退避与最大重试次数。限流窗口通常几十秒就过去，
#: 退避重试远好过把已读进度丢掉、回报一个假的「登录失效」。
_THROTTLE_BACKOFF_SECONDS = 20.0
_MAX_THROTTLE_RETRIES = 3


async def _session_probe(page: Any, log: Any = None) -> dict[str, Any]:
    """探测服务端当前会话，返回结构化判定；不泄露用户资料或 Cookie。

    先用页面上下文的 fetch（带浏览器指纹与 Cookie）请求 ``/session/current.json``；
    Discourse 对匿名请求返回 404（不是 401），已登录才返回 ``current_user``。
    fetch 因 Cloudflare 挑战/CSP 拿不到 JSON 时，退回 DOM 上的当前用户头像判断，
    避免把「页面已登录但接口被拦」误判成登录失效。

    返回 ``{"authenticated": bool, "status": int, "throttled": bool}``。
    ``throttled`` 为真表示服务端在限流/故障，本次**无法判定**登录态 —— 调用方
    必须把它与「确认未登录」区别对待。
    """
    try:
        result = await page.evaluate("""async () => {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 10000);
            try {
                const r = await fetch('/session/current.json', {
                    credentials: 'include', cache: 'no-store',
                    headers: {Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest',
                              'Discourse-Present': 'true'},
                    signal: controller.signal
                });
                let data;
                try { data = await r.json(); }
                catch (_) { return {authenticated:false, status:r.status, format:'html'}; }
                return {
                    authenticated: Boolean(r.ok && data && data.current_user && Number(data.current_user.id) > 0),
                    status:r.status, format:'json'
                };
            } catch (e) { return {authenticated:false, status:0, format:e.name}; }
            finally { clearTimeout(timer); }
        }""")
    except Exception as exc:
        if callable(log):
            log(f"LinuxDO 会话校验未完成：{type(exc).__name__}")
        result = None

    if not isinstance(result, dict):
        return {"authenticated": await _dom_logged_in(page), "status": 0, "throttled": False}

    status = int(result.get("status") or 0)
    if result.get("authenticated") is True:
        return {"authenticated": True, "status": status, "throttled": False}
    if result.get("format") == "json":
        # 服务端明确回答了（404 = 匿名），DOM 不可能更权威。
        if callable(log):
            log(f"LinuxDO 会话校验：HTTP {status}，服务端判定未登录")
        return {"authenticated": False, "status": status, "throttled": False}

    # 非 JSON 响应：可能是挑战页，也可能是限流/故障页。先看 DOM 还认不认账号。
    if callable(log):
        log(f"LinuxDO 会话校验：HTTP {status}，响应类型 {result.get('format', 'unknown')}，改用页面元素判断")
    authenticated = await _dom_logged_in(page)
    # DOM 已确认登录时不必再提限流：这次判定是成功的。
    throttled = not authenticated and status in _TRANSIENT_STATUSES
    return {"authenticated": authenticated, "status": status, "throttled": throttled}


async def _logged_in(page: Any, log: Any = None) -> bool:
    """``_session_probe`` 的布尔视图，供不关心限流原因的调用方使用。"""
    return bool((await _session_probe(page, log))["authenticated"])


async def _dom_logged_in(page: Any) -> bool:
    """Discourse 头部：已登录才渲染当前用户头像按钮；未登录渲染「登录」按钮。"""
    try:
        return bool(await page.evaluate("""() => {
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


def login(ctx: Any, option: LoginOption) -> Any:
    """论坛自身只需恢复会话，不能再向 linux.do 发起通用 OAuth 回跳。"""
    if option.method in {"oauth", "browser_state"}:
        return _restore_login(ctx, option.method)
    return None


async def _settle(page: Any, timeout: int = 15000) -> None:
    """等导航稳定：Cloudflare 放行后会自行跳转，期间 evaluate/goto 都会被打断。"""
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=timeout)
    except Exception:
        pass


async def _safe_goto(lease: Any, page: Any, url: str) -> None:
    """导航被站点自身的跳转打断不算错误，等它落地即可。"""
    try:
        await lease.goto(url, page=page, wait_until="domcontentloaded", timeout=30000)
    except Exception as exc:
        if "interrupted by another navigation" not in str(exc):
            raise
    await _settle(page)


async def _verify_session(
    ctx: Any, lease: Any, page: Any, observed: dict[str, Any] | None = None
) -> tuple[bool, bool, bool]:
    """打开 /latest 并确认登录。返回 (已登录, 人机验证已通过, 服务端限流)。

    限流要单独报给调用方：HTTP 429/5xx 时我们**没有**得到「登录态失效」的答案，
    只是这次问不出来。实测 CI 连续多轮把限流当成失效，反复要求重新捕获登录态。

    ``observed`` 用于把「这次到底卡在哪」带出函数：外层可能因整体预算超时而中断，
    那时异常里没有任何上下文，只知道「超时了」。记录是否见过人机验证挑战，才能把
    「与挑战搏斗到超时」归类成 need_verification，而不是诬告登录态失效。
    """
    notes = observed if observed is not None else {}
    await _safe_goto(lease, page, f"{LINUXDO_URL}/latest")
    challenge_cleared = True
    throttled = False
    for attempt in range(3):
        if await _is_challenge(page):
            notes["challenge_seen"] = True
            challenge_cleared = await bypass.solve_cloudflare(page, log=ctx.log)
            await _settle(page)
            if not challenge_cleared:
                break
        await _wait_loaded(page)
        await lease.dismiss_popups(page=page)
        probe = await _session_probe(page, ctx.log)
        if probe["authenticated"]:
            return True, True, False
        # 只记录最后一次的限流状态：中途恢复（后续轮次拿到明确答案）就不该再算限流。
        throttled = bool(probe["throttled"])
        notes["throttled"] = throttled
        if await _is_challenge(page):
            notes["challenge_seen"] = True
            continue
        # 首屏可能还没把 Cookie 带上，或放行后的跳转打断了校验；重载一次再判。
        # 限流时退避久一点，立刻重试只会撞上同一个速率窗口。
        await asyncio.sleep(6.0 if throttled else 1.5)
        await _safe_goto(lease, page, f"{LINUXDO_URL}/latest")
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

    await _safe_goto(lease, page, f"{LINUXDO_URL}/login")
    if await _is_challenge(page):
        if not await bypass.solve_cloudflare(page, log=ctx.log):
            raise VerificationRequired("linux.do 登录页的人机验证未通过，无法用 GitHub 回退登录。")
        await _settle(page)
    await _wait_loaded(page)
    await lease.dismiss_popups(page=page)
    # 已登录用户访问 /login 会直接跳回首页。
    if await _logged_in(page):
        return await lease.export_state()

    clicked = False
    for selector in _GITHUB_ENTRY_SELECTORS:
        try:
            button = await page.wait_for_selector(selector, state="visible", timeout=6000)
        except Exception:
            continue
        if button is None:
            continue
        try:
            await button.click(timeout=5000)
            clicked = True
            break
        except Exception as exc:
            ctx.log(f"GitHub 登录按钮点击未成功（{type(exc).__name__}），尝试下一个入口")
    if not clicked:
        raise LoginRequired("linux.do 登录页未找到 GitHub 登录入口，无法回退登录。")

    # GitHub 侧：已授权则自动回跳；首次需点「Authorize」。
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 90
    authorized = False
    while loop.time() < deadline:
        await asyncio.sleep(1.0)
        try:
            url = page.url
        except Exception:
            url = ""
        host = urlsplit(url).netloc.casefold()
        if host == "linux.do":
            if await _is_challenge(page):
                await bypass.solve_cloudflare(page, log=ctx.log)
                continue
            if "/login" not in urlsplit(url).path and "/auth/" not in urlsplit(url).path:
                authorized = True
                break
            continue
        if host.endswith("github.com"):
            if "/login" in urlsplit(url).path and "/login/oauth/authorize" not in url:
                raise LoginRequired("GitHub 共享登录态已失效（停在 GitHub 登录页），请重新捕获 github 登录态。")
            for selector in ('button[name="authorize"][value="1"]', 'button#js-oauth-authorize-btn'):
                try:
                    button = await page.query_selector(selector)
                    if button is not None and await button.is_visible():
                        ctx.log("GitHub 授权页：点击 Authorize")
                        await button.click(timeout=5000)
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
    if not state_text:
        state_text = _shared_browser_state(ctx.oauth_state("linuxdo", account_name))
        if state_text:
            ctx.log("复用共享 LinuxDO 认证，不沿用其他浏览器的 Cloudflare 放行 Cookie")
    if not state_text and not github_fallback:
        raise LoginRequired(f"缺少 linuxdo:{account_name} 的登录态，请先捕获或开启 github_fallback。")
    remaining = ctx.deadline.remaining() if ctx.deadline is not None else None
    limit = 240.0 if github_fallback else 120.0
    budget = limit if remaining is None else max(0.0, min(limit, remaining - 20.0))
    if budget <= 0:
        raise LoginRequired("LinuxDO 登录校验没有剩余时间预算。")
    evidence: dict[str, Any] = {}
    # 超时会从 asyncio.timeout 抛出，异常本身不带任何现场信息。这里记录「见过挑战吗、
    # 被限流了吗」，让超时也能落到正确的结论上。
    observed: dict[str, Any] = {}
    try:
        async with asyncio.timeout(budget):
            async with ctx.browser.lease(reason="linuxdo_login", state_text=state_text) as lease:
                page = await lease.new_page()
                verified, challenge_cleared, throttled = (False, True, False)
                if state_text:
                    verified, challenge_cleared, throttled = await _verify_session(
                        ctx, lease, page, observed
                    )
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
                if not challenge_cleared:
                    raise VerificationRequired(
                        "LinuxDO 人机验证尚未通过，请完成验证后重新捕获共享登录态。", data=evidence
                    )
                if throttled:
                    # 限流时我们不知道登录态好不好，既不能说它失效，也不该用 GitHub
                    # 重登去覆盖一份可能完好的登录态。报瞬时错误，下轮重试即可。
                    raise TransientError(
                        "LinuxDO 服务端限流（HTTP 429/5xx），本次无法判定登录态，"
                        "已保留现有登录态，稍后重试即可。",
                        data=evidence,
                    )
                if not github_fallback:
                    raise LoginRequired(
                        "LinuxDO 共享登录态未通过服务端校验，请重新捕获 linuxdo 登录态或开启 github_fallback。",
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
        # 超时的归因取决于卡在哪：与 Cloudflare 搏斗到超时是人机验证问题，
        # 限流到超时是瞬时问题，两者都不该催用户重新捕获登录态。实测本机跑
        # linux.do 时 ClickSolver 反复报 "Cloudflare iframes not found"，
        # 240s 预算耗尽后旧实现一律报 need_login，误导性很强。
        if observed.get("challenge_seen"):
            raise VerificationRequired(
                "LinuxDO 人机验证未能在预算内通过（Cloudflare 挑战反复出现）；"
                "当前出口 IP 可能被风控，可更换代理节点或稍后重试。",
                data=evidence,
            ) from exc
        if observed.get("throttled"):
            raise TransientError(
                "LinuxDO 服务端限流且未能在预算内完成校验，已保留现有登录态，稍后重试即可。",
                data=evidence,
            ) from exc
        raise LoginRequired("LinuxDO 页面或登录校验超时，请检查网络或人机验证。", data=evidence) from exc


async def _open_topic(lease: Any, page: Any, link: str) -> bool:
    """打开确定的站内主题，URL 与正文都确认后才允许计入阅读数。"""
    try:
        response = await lease.goto(
            link, page=page, wait_until="domcontentloaded", timeout=25000, ignore_timeout=False
        )
        if response is not None and response.status >= 400:
            return False
        await page.wait_for_selector("article .cooked, .post-stream .cooked", state="visible", timeout=18000)
        return bool(_normalize_topic_url(link)) and _normalize_topic_url(page.url) == _normalize_topic_url(link)
    except Exception:
        return False


# ── 主流程 ───────────────────────────────────────────────────────────────────

async def run(ctx: Any) -> Outcome:
    """按实际加载和阅读结果计数；只在达到本轮目标后记录每日完成。"""
    args = MANIFEST.task_option("browser_flow").args.resolve(ctx.args)
    max_posts = int(args["post_count"])
    min_secs = int(args["min_read_seconds"])
    max_secs = int(args["max_read_seconds"])
    if min_secs > max_secs:
        raise ConfigError("min_read_seconds 不能大于 max_read_seconds。")
    today = business_date()

    if args["once_per_day"]:
        baseline = ctx.store.get(STORE_KEY) or {}
        if isinstance(baseline, dict) and baseline.get("date") == today and baseline.get("completed") is True:
            try:
                count = int(baseline.get("posts_read") or 0)
            except (TypeError, ValueError):
                count = 0
            if count > 0:
                return already_done(
                    f"今日已完成浏览（共 {count} 篇）", data=baseline
                ).with_display(DisplaySpec(text=str(count)))

    target_count = random.randint(max(1, (max_posts + 1) // 2), max_posts)
    progress: dict[str, Any] = {
        "date": today, "target_count": target_count, "posts_read": 0,
        "topic_urls": [], "reading_seconds": 0.0, "completed": False,
    }
    ctx.log(f"目标浏览 {target_count} 篇帖子，每篇 {min_secs}~{max_secs} 秒")
    remaining = ctx.remaining_seconds()
    budget = 600.0 if remaining is None else max(0.0, remaining - 20.0)
    issue = "没有足够的可访问帖子"
    if budget <= 0:
        return failed("LinuxDO 浏览任务没有剩余时间预算", reason="unconfirmed", data=progress)

    async with ctx.browser.lease(reason="linuxdo_browse") as lease:
        page = await lease.new_page()
        helpers = PageHelpers(ctx, lease, page)
        attempted: set[str] = set()
        throttle_hits = 0
        try:
            async with asyncio.timeout(budget):
                # 失败主题不反复访问；每轮重新读取列表，让刷新后的新主题真正进入候选。
                for _ in range(target_count * 2):
                    if progress["posts_read"] >= target_count:
                        break
                    await lease.goto(
                        f"{LINUXDO_URL}/latest", page=page, wait_until="domcontentloaded", timeout=25000
                    )
                    if not await _wait_loaded(page, timeout=20000):
                        issue = "LinuxDO 列表加载超时"
                        break
                    await lease.dismiss_popups(page=page)
                    probe = await _session_probe(page)
                    if not probe["authenticated"]:
                        # 限流不是登录失效：退避后重试，别把已读的进度丢成 need_login。
                        if probe["throttled"] and throttle_hits < _MAX_THROTTLE_RETRIES:
                            throttle_hits += 1
                            ctx.log(
                                f"LinuxDO 会话校验被限流（HTTP {probe['status']}），"
                                f"退避 {_THROTTLE_BACKOFF_SECONDS:.0f}s 后重试"
                                f"（第 {throttle_hits}/{_MAX_THROTTLE_RETRIES} 次）"
                            )
                            await asyncio.sleep(_THROTTLE_BACKOFF_SECONDS)
                            continue
                        if probe["throttled"]:
                            issue = f"LinuxDO 会话校验持续被限流（HTTP {probe['status']}）"
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
                    if not await _open_topic(lease, page, link):
                        ctx.log(f"帖子未正确加载，跳过：{link}")
                        continue
                    elapsed = await _simulate_read(page, read_secs)
                    progress["posts_read"] += 1
                    progress["topic_urls"].append(link)
                    progress["reading_seconds"] = round(progress["reading_seconds"] + elapsed, 2)
                    ctx.log(f"已完成阅读 {progress['posts_read']}/{target_count} 篇")
                    if progress["posts_read"] < target_count:
                        await asyncio.sleep(random.uniform(1.0, 4.0))
        except TimeoutError:
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
    msg = f"LinuxDO 浏览完成，本次实际阅读 {progress['posts_read']} 篇帖子"
    ctx.log(msg)
    return ok(msg, data=progress).with_display(DisplaySpec(text=str(progress["posts_read"])))
