#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""反检测与绕过引擎：Camoufox + Cloudflare + 阿里云 WAF + 滑块验证。

集成 Camoufox（反检测浏览器）+ playwright-captcha（验证码破解）+ 
阿里云 WAF cookie 获取（acw_tc/cdn_sec_tc/acw_sc__v2），绕过公益站
常见的反爬措施。

核心功能：
1. launch_camoufox：启动反检测浏览器，支持 headless/humanize/proxy/geo。
2. get_cf_clearance：自动破解 Cloudflare Interstitial 拿 cf_clearance。
3. get_waf_cookies：预加载页面获取阿里云 WAF 三件套（acw_tc/cdn_sec_tc/acw_sc__v2）。
4. aliyun_captcha_solver：阿里云滑块拖拽（mouse 模拟，带人类化延迟和抖动）。

依赖：
- camoufox[geoip]：Firefox 反检测浏览器，绕过 webdriver 检测。
- playwright-captcha：Cloudflare/reCAPTCHA 破解（ClickSolver/SyncSolver）。
"""

from __future__ import annotations

import asyncio
import random
from copy import deepcopy
from typing import Any

try:
    from camoufox.async_api import AsyncCamoufox
    from playwright.async_api import Page, Browser, BrowserContext
    from playwright_captcha import ClickSolver, CaptchaType, FrameworkType
    CAMOUFOX_AVAILABLE = True
except ImportError as e:
    CAMOUFOX_AVAILABLE = False
    IMPORT_ERROR = str(e)
    # 占位类型，避免类型检查错误
    Page = Any  # type: ignore
    Browser = Any  # type: ignore
    BrowserContext = Any  # type: ignore


def _check_camoufox() -> None:
    """检查 Camoufox 是否已安装，未安装则抛出友好错误提示。"""
    if not CAMOUFOX_AVAILABLE:
        raise RuntimeError(
            f"Camoufox 未安装或导入失败：{IMPORT_ERROR}\n\n"
            "请安装依赖：\n"
            "  pip install camoufox[geoip]>=0.4.11 curl-cffi>=0.7.3 playwright-captcha>=0.1.0\n"
            "  python -m camoufox fetch\n\n"
            "或使用 uv（推荐）：\n"
            "  cd checkin && uv sync && uv run python -m camoufox fetch"
        )


def _normalize_proxy(proxy: Any) -> dict[str, str] | None:
    """保留内部字典接口；字符串统一解析认证和 IPv6，不复述无效 URL。"""
    if not proxy:
        return None
    if isinstance(proxy, dict):
        return {key: value for key, value in proxy.items() if value not in (None, "")} or None
    if not isinstance(proxy, str) or not proxy.strip():
        return None
    from config.proxies import parse_proxy_url

    return parse_proxy_url(proxy, allow_bare=True).browser_proxy()


# ────────────────────────────── Camoufox 启动 ──────────────────────────────
def _geoip_lookup_failed(exc: BaseException) -> bool:
    """只识别自动出口 IP 探测失败，不把无效代理/显式 IP 等配置错误当成可降级错误。"""
    return type(exc).__name__ == "InvalidIP" and "failed to get ip address" in str(exc).lower()


async def _start_camoufox(options: dict[str, Any]) -> Any:
    """启动失败也释放 Playwright 驱动，避免 GeoIP 回退或启动重试留下子进程。"""
    # Camoufox 会就地填充 config；失败后的半成品指纹不能当成下一次的用户配置。
    manager = AsyncCamoufox(**{**options, "config": deepcopy(options.get("config"))})
    try:
        return await manager.start()
    except BaseException as exc:
        try:
            await asyncio.wait_for(manager.__aexit__(type(exc), exc, exc.__traceback__), timeout=5)
        except Exception:
            pass
        raise


async def launch_camoufox(
    headless: bool = True,
    proxy: str | None = None,
    humanize: bool = True,
    geoip: bool = True,
    locale: str = "en-US",
    timeout: int = 30000,
    os_fingerprint: str = "macos",
    log: Any = None,
    **kwargs: Any,
) -> tuple[Browser, BrowserContext]:
    """启动 Camoufox 反检测浏览器（基于 Firefox）。

    Args:
        headless: 无头模式（CI 用 True，本地调试用 False）。
        proxy: 代理 URL（如 "http://user:pass@host:port"）。
        humanize: 人类化行为模拟（随机延迟、鼠标轨迹）。
        geoip: 根据代理 IP 自动设置地理位置和时区；自动探测失败时保留代理并关闭 GeoIP 重试一次。
        log: 可选的运行日志回调；降级信息不包含代理凭据。
        locale: 浏览器语言（默认 en-US，CF/linux.do 对其更友好）。
        timeout: 启动超时（毫秒）。
        os_fingerprint: 强制操作系统指纹（默认 macos，避免 CI Windows
            下 navigator.platform 与 UA 不一致被风控识破）。
        **kwargs: 传给 AsyncCamoufox().start() 的额外参数（addons、viewport 等）。

    Returns:
        (browser, context) 元组。context 已配置好反检测参数。

    Raises:
        RuntimeError: Camoufox 未安装。
        Exception: 启动失败（如 camoufox 未安装、网络问题等）。
    """
    _check_camoufox()

    launch_options: dict[str, Any] = {
        "headless": headless,
        "humanize": humanize,
        "geoip": geoip,
        "locale": locale,
        "timeout": timeout,
        # 强制 OS 指纹：CI Windows 下用 macos 指纹避免 platform/UA 不一致
        "os": os_fingerprint,
        # forceScopeAccess：playwright-captcha 需要访问页面 JS 作用域
        "config": {"forceScopeAccess": True},
        "addons": kwargs.pop("addons", []),
    }

    proxy_dict = _normalize_proxy(proxy)
    if proxy_dict:
        # Camoufox 内部对 proxy 做 **proxy，必须是 dict（server/username/password）
        launch_options["proxy"] = proxy_dict

    # 合并用户自定义参数
    launch_options.update(kwargs)

    # geoip=True 时 Camoufox 会按需下载 65MB 的 GeoLite2-City.mmdb，但它只用
    # exists() 判断、且直接写最终路径。批量签到组间并发启动浏览器时，后启动的进程
    # 会读到仍在写入的半成品，报「Is this a valid MaxMind DB file?」。这里用文件锁
    # 加原子替换先把数据库准备好，并顺带修复此前已被写坏的缓存。
    if launch_options.get("geoip"):
        try:
            from .geoip_cache import ensure_geoip_database

            ensure_geoip_database()
        except Exception:
            pass

    # Firefox 驱动会因缺失 pageError.location 在 Node 侧崩溃（表现为随后的
    # "Connection closed while reading from the driver"）。该上报由 Firefox 的
    # _onUncaughtError 触发，与是否注册 pageerror 监听无关，页面内吞错脚本也晚于
    # 它，因此必须在启动前修补驱动本身。补丁幂等，失败不影响启动。
    try:
        from .driver_patch import patch_firefox_page_error

        patch_firefox_page_error()
    except Exception:
        pass

    # GeoIP 的公共 IP 查询不是浏览器运行的前提。CI/代理可能只拦住这些查询站点，
    # 不能把它误报成「浏览器未安装」，更不能偷偷移除代理改走直连。
    try:
        browser = await _start_camoufox(launch_options)
    except Exception as exc:
        if launch_options.get("geoip") is not True or not _geoip_lookup_failed(exc):
            raise
        message = "GeoIP 出口 IP 探测失败，保留原代理，关闭自动定位及 WebRTC 后重试浏览器启动"
        if callable(log):
            log(message)
        else:
            import sys

            print(f"[browser] {message}", file=sys.stderr, flush=True)
        browser = await _start_camoufox({**launch_options, "geoip": False, "block_webrtc": True})
    # 某些 Camoufox/Playwright 组合不会预创建 context；直接 browser.new_context()
    # 会发送默认 viewport.isMobile=false，而当前 Firefox 协议 schema 不接受该字段。
    context = browser.contexts[0] if browser.contexts else await browser.new_context(no_viewport=True)
    
    # 不注册 context/pageerror 监听：Playwright Firefox 驱动在部分页面错误缺少
    # location.url 时会在 Node 侧崩溃（Cannot read properties of undefined）。同时在页面
    # 早期屏蔽未处理错误的默认上报，避免 Firefox 把这类错误继续转给 Playwright。
    try:
        await context.add_init_script(
            """(() => {
                const swallow = event => {
                    try { event.preventDefault(); } catch (_) {}
                    try { event.stopImmediatePropagation(); } catch (_) {}
                };
                try { window.addEventListener('error', swallow, true); } catch (_) {}
                try { window.addEventListener('unhandledrejection', swallow, true); } catch (_) {}
                try { window.onerror = () => true; } catch (_) {}
                try { window.onunhandledrejection = event => { try { event.preventDefault(); } catch (_) {} return true; }; } catch (_) {}
            })();"""
        )
    except Exception:
        pass
    return browser, context


# ──────────────────────── Cloudflare 挑战求解 ───────────────────────────

# CF 挑战页特征。旧实现只认 "Just a moment" / "Checking your browser" 两条，
# 漏判新版 managed challenge（"Verifying you are human"）、JS/cookie 提示页、
# 以及内嵌 challenge-platform / cf-chl widget 的页面。漏判的后果比求解失败更糟：
# solve_cloudflare 会直接 return True，调用方误以为已通过，实际仍停在挑战页。
CF_TITLE_PATTERNS = (
    "just a moment",
    "attention required",
    "access denied",
    "please wait",
)
# 仅出现在「真正的挑战/拦截页」上的结构标记。挑战页会渲染 CF 自己的容器与表单，
# 正常页面即使受 Cloudflare 保护也不会有这些节点。
CF_STRUCTURAL_PATTERNS = (
    "cf-wrapper",
    "cf-error-details",
    "id=\"challenge-form\"",
    "id='challenge-form'",
    "cf-challenge-running",
    "cf_chl_opt",
    "_cf_chl",
    "cf-chl-bypass",
    # 挑战 widget 的实际容器节点（区别于 challenge-platform 那类环境脚本）。
    "cf-chl-widget",
    "id=\"cf-challenge\"",
    "class=\"cf-challenge\"",
)
# 挑战页会对用户显示的可见文案。这些是人读得懂的拦截提示，正常页面不会出现。
#
# 已移除 "challenges.cloudflare.com" / "challenge-platform" / "cf-challenge" /
# "cf-chl"：它们同样出现在「受 Cloudflare 保护的正常页面」以及 Turnstile/hCaptcha
# widget 的常规脚本里。实测 Linux DO 授权页（title="authorize - linux do connect"，
# 无任何 CF 容器）仅因含 challenge-platform 就被判为挑战页，于是日志报「检测到
# Cloudflare 挑战」并白跑一轮 ClickSolver。结构性标记见 CF_STRUCTURAL_PATTERNS。
CF_CONTENT_PATTERNS = (
    "checking your browser",
    "verifying you are human",
    "verify you are human",
    "needs to review the security of your connection",
    "enable javascript and cookies to continue",
)

# 交互式 Turnstile widget 特征：这类挑战不会自动签发令牌，必须用真实鼠标点击
# 复选框（Cloudflare 校验事件的 isTrusted），ClickSolver 的 interstitial 策略无效。
CF_INTERACTIVE_PATTERNS = (
    "cf-turnstile-response",
    "challenges.cloudflare.com/turnstile",
    "turnstile-container",
    "turnstile-wrapper",
)


async def _page_signals(page) -> tuple[str, str]:
    """取当前页面的 title 与 HTML（失败返回空串）。"""
    try:
        title = (await page.title()) or ""
    except Exception:
        title = ""
    try:
        content = (await page.content()) or ""
    except Exception:
        content = ""
    return title.lower(), content.lower()


def _is_cf_challenge(title_low: str, content_low: str) -> bool:
    """页面是否为 Cloudflare 挑战/拦截页。

    判据必须是「这是一张挑战页」，而不是「这页和 Cloudflare 有关」：受 CF 保护的
    正常页面同样会加载 challenge-platform 之类的脚本。三类证据任一成立即判定：
    标题为已知拦截标题、渲染了 CF 自己的容器/表单、或显示了面向用户的拦截文案。
    """
    if any(pattern in title_low for pattern in CF_TITLE_PATTERNS):
        return True
    if any(pattern in content_low for pattern in CF_STRUCTURAL_PATTERNS):
        return True
    return any(pattern in content_low for pattern in CF_CONTENT_PATTERNS)


def _has_interactive_widget(content_low: str) -> bool:
    """页面是否内嵌需要人工点击的 Turnstile widget。"""
    return any(pattern in content_low for pattern in CF_INTERACTIVE_PATTERNS)


async def _wait_until_challenge_clears(page: Any, timeout_seconds: int, log) -> bool:
    """在令牌签发后等待页面真正脱离挑战页，兼容异步跳转/刷新。"""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0, timeout_seconds)
    while True:
        title_low, content_low = await _page_signals(page)
        if not _is_cf_challenge(title_low, content_low):
            return True
        now = loop.time()
        if now >= deadline:
            return False
        remaining_ms = max(1, int((deadline - now) * 1000))
        try:
            await page.wait_for_timeout(min(250, remaining_ms))
        except Exception:
            await asyncio.sleep(min(0.25, remaining_ms / 1000))


# 同一出口 IP 对同一站点连续这么多次「确认未通过」后熔断，后续调用立即返回 False。
#
# 为什么必须有：一次完整求解要走「被动等待 wait_seconds → 真实点击等令牌 → ClickSolver
# 5 次尝试 → 再点一次」，单轮可达 1~2 分钟。而 OAuth 流程里 solve_cloudflare 会被调用
# 四五次（授权页入口、点击后、轮询里的 "just a moment" 分支、回跳失败后的复查）。出口 IP
# 真被风控时每一次都注定失败，实测 AgentRouter(L) 因此耗尽 360 秒账号预算，最终报
# 「账号执行超时」——把一个本该是「需人机验证/换代理」的结论盖成了看不出原因的超时，
# 还连带拖垮同批次其它账号的时间预算。
#
# 与 waf.py 的 waf_circuit 同构：那里已经用同样的手段解决了阿里云 WAF 的重复求解问题。
CF_BLOCK_THRESHOLD = 2


async def _page_origin(page: Any) -> str:
    """取当前页面的 scheme://host，用于按站点隔离熔断状态（失败返回空串）。"""
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(str(page.url or ""))
        return f"{parts.scheme}://{parts.netloc}" if parts.netloc else ""
    except Exception:
        return ""


def cf_circuit(page: Any) -> dict[str, int]:
    """返回附着在 page 上、按 origin 记录连续失败次数的熔断状态。"""
    circuit = getattr(page, "_cf_circuit_state", None)
    if not isinstance(circuit, dict):
        circuit = {}
        try:
            setattr(page, "_cf_circuit_state", circuit)
        except Exception:
            # FakePage / __slots__ 页面对象拿不到属性：退化为「不熔断」，行为与旧版一致。
            return {}
    return circuit


def cf_is_blocked(page: Any, origin: str) -> bool:
    """该站点的 Cloudflare 挑战是否已被判定为「这个出口 IP 过不去」。"""
    return int(cf_circuit(page).get(origin, 0)) >= CF_BLOCK_THRESHOLD


def cf_note_success(page: Any, origin: str) -> None:
    """求解成功：清零该站点的失败计数（IP 显然没被封）。"""
    circuit = cf_circuit(page)
    if origin in circuit:
        circuit.pop(origin, None)


def cf_note_failure(page: Any, origin: str, log: Any = None) -> None:
    """记录一次「确认未通过」，达到阈值即熔断并说明原因。"""
    circuit = cf_circuit(page)
    if circuit is None:
        return
    fails = int(circuit.get(origin, 0)) + 1
    circuit[origin] = fails
    if fails >= CF_BLOCK_THRESHOLD and callable(log):
        log(
            f"Cloudflare 挑战连续 {fails} 次未通过（{origin or '当前站点'}），"
            "判定当前出口 IP 无法通过该站验证，后续跳过重复求解以免耗尽任务预算"
        )


async def solve_cloudflare(page, log=None, wait_seconds: int = 10) -> bool:
    """破解当前页面的 Cloudflare 挑战，并对同站连续失败做熔断。

    真正的求解逻辑在 ``_solve_cloudflare_once``；这一层只做两件事：
    1. 页面没有挑战时立即返回（零成本，调用方可以放心无脑调用）；
    2. 同一站点已连续失败 ``CF_BLOCK_THRESHOLD`` 次时直接返回 False，不再重复那套
       「等待 → 点击 → ClickSolver」的昂贵流程——出口 IP 被风控时它注定失败，重复
       只会吃掉整个任务预算并把结论盖成「超时」。
    """
    _check_camoufox()

    def _log(msg: str) -> None:
        if log:
            log(msg)

    title_low, content_low = await _page_signals(page)
    if not _is_cf_challenge(title_low, content_low) and not _has_interactive_widget(content_low):
        return True  # 无 CF 挑战

    origin = await _page_origin(page)
    if cf_is_blocked(page, origin):
        _log(
            f"Cloudflare 挑战已熔断（{origin or '当前站点'} 的出口 IP 连续未通过），"
            "跳过重复求解；请更换代理节点或稍后重试"
        )
        return False

    passed = await _solve_cloudflare_once(page, log=log, wait_seconds=wait_seconds)
    if passed:
        cf_note_success(page, origin)
    else:
        cf_note_failure(page, origin, _log)
    return passed


async def _solve_cloudflare_once(page, log=None, wait_seconds: int = 10) -> bool:
    """执行一轮完整的 Cloudflare 挑战求解（interstitial + 交互式 Turnstile）。

    两级策略：
    1. ClickSolver（playwright-captcha）处理经典 interstitial "Just a moment" 页；
    2. 若页面内嵌交互式 Turnstile widget，或 ClickSolver 之后挑战仍未消失，
       改用 browser.turnstile 的真实鼠标点击（Cloudflare 校验 isTrusted，
       JS click 与被动等待都拿不到令牌）。

    最后回读页面确认挑战确实消失才返回 True——ClickSolver 不抛异常并不等于
    挑战已通过，旧实现据此报成功，导致调用方在仍被拦截的页面上继续操作。

    Args:
        page: Camoufox/Playwright Page 对象。
        log: 可选日志回调。
        wait_seconds: 求解后的额外等待（秒）。

    Returns:
        True 表示无 CF 挑战或已确认通过，False 表示仍被拦截。
    """
    _check_camoufox()

    def _log(msg: str) -> None:
        if log:
            log(msg)

    title_low, content_low = await _page_signals(page)
    interactive = _has_interactive_widget(content_low)
    interstitial = _is_cf_challenge(title_low, content_low)

    if not interstitial and not interactive:
        return True  # 无 CF 挑战

    from . import turnstile as _turnstile

    # 全屏 interstitial（"Just a moment" 类 managed challenge）优先纯被动等待：
    # 这类页面内嵌的 turnstile 由 Cloudflare 自动执行，放行体现为页面级跳转/刷新，
    # 不写入 cf-turnstile-response 字段。实测 connect.linux.do 授权页约 40 秒自行
    # 放行；此时若去点击那个自动 widget，反而可能重置校验、错过放行窗口（生产日志
    # 表现为反复「已点击复选框…挑战未通过」最终 need_verification）。因此先在
    # wait_seconds 预算内等待自动放行，过不了再回落到点击 / ClickSolver 策略。
    if interstitial:
        _log(f"检测到 Cloudflare 挑战页，先等待自动放行（最长 {max(wait_seconds, 1)}s）...")
        if await _wait_until_challenge_clears(page, max(wait_seconds, 1), _log):
            _log("Cloudflare 挑战已通过（被动等待自动放行）")
            return True
        # 被动窗口内没放行：重新评估页面，可能已切换成需要人工点击的 widget。
        title_low, content_low = await _page_signals(page)
        interactive = _has_interactive_widget(content_low)
        _log("被动等待未放行，转入交互式 / ClickSolver 策略")

    # 交互式 widget：真实鼠标点击（Cloudflare 校验事件 isTrusted）。
    if interactive:
        _log("检测到交互式 Cloudflare Turnstile，真实鼠标点击复选框...")
        token = await _turnstile.solve(
            page,
            timeout_ms=max(wait_seconds, 30) * 1000,
            log=_log,
        )
        if token:
            _log("Turnstile 令牌已签发，等待页面完成异步放行...")
            # 令牌签发 ≠ 页面已放行：interstitial 可能需要跳转/刷新，不能只做一次
            # 即时检查；在短窗口内持续读取页面状态，人工完成后的异步放行也算成功。
            if await _wait_until_challenge_clears(page, max(wait_seconds, 1), _log):
                return True
            _log("令牌已签发但页面仍为挑战页，继续尝试 interstitial 策略")
        else:
            _log("Turnstile 未在等待时间内签发令牌")
        # 未通行也继续往下：部分页面同时挂着 interstitial，仍可能被 ClickSolver 解开。


    if _is_cf_challenge(title_low, content_low):
        _log("检测到 Cloudflare 挑战，ClickSolver 自动破解中...")
        try:
            async with ClickSolver(
                framework=FrameworkType.CAMOUFOX, page=page, max_attempts=5, attempt_delay=3
            ) as solver:
                await solver.solve_captcha(
                    captcha_container=page,
                    captcha_type=CaptchaType.CLOUDFLARE_INTERSTITIAL,
                )
            if await _wait_until_challenge_clears(page, max(wait_seconds, 1), _log):
                _log("Cloudflare 挑战已通过")
                return True
        except Exception as exc:
            _log(f"ClickSolver 破解失败：{exc}")

    # 回读确认：ClickSolver 不报错 ≠ 挑战已通过。
    title_low, content_low = await _page_signals(page)
    if not _is_cf_challenge(title_low, content_low):
        _log("Cloudflare 挑战已通过")
        return True

    # interstitial 仍在：最后再尝试一次真实点击（部分 managed challenge 会在
    # interstitial 内嵌复选框，等待期结束后才渲染出来）。
    if _has_interactive_widget(content_low):
        _log("挑战仍在，尝试真实鼠标点击 Turnstile 复选框...")
        if await _turnstile.solve(
            page,
            timeout_ms=max(wait_seconds, 20) * 1000,
            log=_log,
        ) and await _wait_until_challenge_clears(page, max(wait_seconds, 1), _log):
            _log("Cloudflare 挑战已通过（真实点击）")
            return True

    _log("Cloudflare 挑战未能通过（页面仍为挑战页）")
    return False


async def get_cf_clearance(
    page: Page,
    url: str,
    wait_seconds: int = 10,
    max_attempts: int = 3,
) -> dict[str, str]:
    """破解 Cloudflare 挑战并返回包含 cf_clearance 的 cookies（兼容旧接口）。"""
    _check_camoufox()
    try:
        if page.url != url:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
    except Exception:
        pass
    await solve_cloudflare(page, wait_seconds=wait_seconds)
    try:
        cookies = await page.context.cookies()
        return {c["name"]: c["value"] for c in cookies}
    except Exception:
        return {}


# ───────────────────────── 阿里云 WAF cookies ────────────────────────────
async def get_waf_cookies(
    page: Page,
    url: str,
    wait_seconds: int = 5,
) -> dict[str, str]:
    """预加载页面获取阿里云 WAF cookies（acw_tc / cdn_sec_tc / acw_sc__v2）。

    阿里云 WAF 会在首次访问时通过 JavaScript 动态生成这些 cookies，后续请求
    必须携带才能通过。本函数用浏览器预加载页面，等待 cookies 生成后返回。

    Args:
        page: Playwright Page 对象。
        url: 目标 URL（通常是站点首页或登录页）。
        wait_seconds: 等待 cookies 生成的时间（秒）。

    Returns:
        包含 WAF cookies 的字典，如 {"acw_tc": "xxx", "cdn_sec_tc": "yyy", ...}。
        若未检测到 WAF 则返回空字典。

    Raises:
        Exception: 页面加载失败。
    """
    try:
        # 用 domcontentloaded（networkidle 在 WAF 挑战页会一直不空闲而超时）
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        await asyncio.sleep(wait_seconds)

        # 提取所有 cookies
        cookies = await page.context.cookies()
        cookie_dict = {c["name"]: c["value"] for c in cookies}

        # 过滤出 WAF cookies（阿里云 WAF 三件套）
        waf_keys = {"acw_tc", "cdn_sec_tc", "acw_sc__v2"}
        waf_cookies = {k: v for k, v in cookie_dict.items() if k in waf_keys}

        return waf_cookies

    except Exception as exc:
        raise Exception(f"获取 WAF cookies 失败：{exc}") from exc


# ───────────────────────── 阿里云滑块拖拽 ────────────────────────────────
async def aliyun_captcha_solver(
    page: Page,
    wait_seconds: int = 15,
    log=None,
) -> bool:
    """阿里云滑块验证码自动拖拽（人类化鼠标轨迹）。

    检测阿里云验证码页（#traceid），定位滑块手柄（#nocaptcha .btn_slide）
    和轨道（#nocaptcha .nc_scale），用 mouse API 模拟人类拖动绕过行为检测。
    选择器参考 aceHubert/newapi-ai-check-in 的 aliyun_captcha_check。

    Args:
        page: Camoufox/Playwright Page 对象。
        wait_seconds: 拖拽后等待验证结果的时间（秒）。
        log: 可选日志回调。

    Returns:
        True 表示无验证码或拖拽成功，False 表示失败。
    """
    def _log(msg: str) -> None:
        if log:
            log(msg)

    # 检测是否为阿里云验证码页（traceid）
    try:
        traceid = await page.evaluate(
            """() => {
                const el = document.getElementById('traceid');
                if (el) {
                    const t = el.innerText || el.textContent || '';
                    const m = t.match(/TraceID:\\s*([a-f0-9]+)/i);
                    return m ? m[1] : (t || null);
                }
                return null;
            }"""
        )
    except Exception:
        traceid = None

    if not traceid:
        return True  # 无阿里云验证码

    _log(f"检测到阿里云滑块验证码（traceid={traceid}），尝试自动拖拽...")
    try:
        await page.wait_for_selector("#nocaptcha", timeout=60000)
        scale = await page.query_selector("#nocaptcha .nc_scale")
        handle = await page.query_selector("#nocaptcha .btn_slide")
        if not scale or not handle:
            _log("未找到滑块轨道或手柄")
            return False

        track = await scale.bounding_box()
        grip = await handle.bounding_box()
        if not track or not grip:
            _log("滑块元素无边界框")
            return False

        start_x = grip["x"] + grip["width"] / 2
        start_y = grip["y"] + grip["height"] / 2
        # 拖到轨道末端（参考项目用 handle.x + scale.width）
        end_x = grip["x"] + track["width"]

        await page.mouse.move(start_x, start_y)
        await asyncio.sleep(random.uniform(0.1, 0.3))
        await page.mouse.down()
        await asyncio.sleep(random.uniform(0.05, 0.15))

        # 分段拖动（ease-in-out + 抖动）
        steps = random.randint(15, 25)
        for i in range(steps):
            progress = (i + 1) / steps
            easing = 0.5 - 0.5 * ((2 * progress - 1) ** 3)
            cx = start_x + (end_x - start_x) * easing
            await page.mouse.move(cx + random.uniform(-2, 2), start_y + random.uniform(-1, 1))
            await asyncio.sleep(random.uniform(0.01, 0.03))

        await asyncio.sleep(random.uniform(0.1, 0.2))
        await page.mouse.up()
        await asyncio.sleep(wait_seconds)

        # 成功判定：traceid 元素消失或验证码容器隐藏
        still = await page.query_selector("#nocaptcha .btn_slide")
        ok = still is None
        _log("滑块验证" + ("通过" if ok else "可能未通过"))
        return ok
    except Exception as exc:
        _log(f"滑块拖拽失败：{exc}")
        return False

