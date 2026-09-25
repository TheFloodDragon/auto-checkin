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
import math
import random
from copy import deepcopy
from html.parser import HTMLParser
from typing import Any

try:
    from camoufox.async_api import AsyncCamoufox
    from playwright.async_api import Page, Browser, BrowserContext
    # 保留旧模块导出；CF 主流程不再调用追加独立预算的 ClickSolver。
    from playwright_captcha import (
        ClickSolver as ClickSolver, CaptchaType as CaptchaType, FrameworkType as FrameworkType,
    )
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
#
# 已移除 "_cf_chl" / "cf-chl-widget"：实测它们并非「拦截页专属」，而是 Cloudflare
# Turnstile widget 的通用标记——linux.do 论坛的**正常登录后页面**（title="LINUX DO"、
# 已渲染 topic-list、正文数百 KB）就内嵌了 cf-turnstile + cf-chl-widget，导致
# _is_cf_challenge 在 CF 早已放行、页面完全可用之后仍持续判为 interstitial，
# solve_cloudflare 永不返回 clear，最终把一次成功的会话误报成「人机验证未通过」。
# 真正的全屏挑战由标题（CF_TITLE_PATTERNS）、可见拦截文案（CF_CONTENT_PATTERNS）与
# cf_chl_opt 等仍在此的结构标记识别；widget 容器交给 CF_INTERACTIVE_PATTERNS 分类。
CF_STRUCTURAL_PATTERNS = (
    "cf-wrapper",
    "cf-error-details",
    "id=\"challenge-form\"",
    "id='challenge-form'",
    "cf-challenge-running",
    "cf_chl_opt",
    "cf-chl-bypass",
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
# 含 "cf-chl-widget"：它是 Turnstile / managed-challenge 的 widget 容器，可能是拦截
# 页的挑战框，也可能是正常页内嵌的（已放行/隐藏）widget——具体是否拦截，由
# _challenge_state 结合「是否有可交互目标」与「真实页面内容是否已渲染」判定。
CF_INTERACTIVE_PATTERNS = (
    "cf-turnstile",
    "challenges.cloudflare.com/turnstile",
    "turnstile-container",
    "turnstile-wrapper",
    "cf-chl-widget",
)


async def _page_signals(page, diagnostics=None) -> tuple[str, str, bool]:
    """同一剩余预算内读标题和内容；任一读取失败均不能作为放行证据。"""
    from . import turnstile

    values = []
    valid = True
    for name in ("title", "content"):
        try:
            value = await turnstile._operation(getattr(page, name)(), "page_state", diagnostics)
            valid = valid and isinstance(value, str)
            values.append(value.lower() if isinstance(value, str) else "")
        except Exception:
            valid = False
            values.append("")
    return values[0], values[1], valid


class _PageEvidence(HTMLParser):
    """排除空 HTML、仅标题变化和脚本壳；不把它们误当已进入业务页面。"""

    def __init__(self) -> None:
        super().__init__()
        self.ignored = 0
        self.meaningful = False

    def handle_starttag(self, tag, attrs) -> None:
        if tag in {"head", "title", "script", "style", "template"}:
            self.ignored += 1
        if not self.ignored and tag in {"input", "button", "a", "form", "article", "table", "img", "canvas"}:
            self.meaningful = True

    def handle_endtag(self, tag) -> None:
        if tag in {"head", "title", "script", "style", "template"}:
            self.ignored = max(0, self.ignored - 1)

    def handle_data(self, data) -> None:
        if not self.ignored and data.strip():
            self.meaningful = True


def _has_page_evidence(content: str) -> bool:
    parser = _PageEvidence()
    try:
        parser.feed(content)
        return parser.meaningful
    except Exception:
        return False


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


async def _challenge_state(page: Any, *, diagnostics=None) -> tuple[str, dict[str, Any]]:
    """每轮只完整 probe 一次；managed 和普通表单复用同一安全目标和状态。"""
    from . import turnstile

    title, content, valid = await _page_signals(page, diagnostics)
    result = await turnstile.probe(page, diagnostics=diagnostics)
    if _is_cf_challenge(title, content):
        return "interstitial", result
    if not valid:
        turnstile._diagnose(diagnostics, reason="page_query_failed")
        return "unknown", result
    # 有可点击的挑战目标：拿到令牌算通过，否则待交互（真实交互式 Turnstile）。
    if result.get("target") is not None:
        if await turnstile.read_token(page, diagnostics=diagnostics):
            return "clear", result
        return "interactive", result
    # 没有可交互目标。真实站点内容已渲染、且没有可见的 CF 拦截信号（标题/文案/拦截结构
    # 已在上面排除）时判为放行：内嵌或已放行的 Turnstile widget 不拦截访问。
    # 关键：即便 probe 读不到 widget 状态也照此判断——linux.do 论坛正常页内嵌
    # challenges.cloudflare.com 的 Turnstile iframe，跨域 evaluate 常挂起（probe_timeout），
    # 但页面本身完全可用、会话已登录。否则会把这张页永远当成「挑战未通过」空等到超时，
    # 误报 need_verification。仅 probe_failed（驱动异常、状态不可知）才继续 fail-closed。
    if _has_page_evidence(content) and result["reason"] != "probe_failed":
        return "clear", result
    if result["reason"] in {"probe_failed", "probe_timeout"}:
        return "unknown", result
    if _has_interactive_widget(content) or result["present"]:
        if await turnstile.read_token(page, diagnostics=diagnostics):
            return "clear", result
        return "interactive", result
    turnstile._diagnose(diagnostics, reason="page_empty")
    return "unknown", result


async def has_cloudflare_challenge(page: Any) -> bool:
    """统一实时检测：普通标题、延迟 widget 和 shadow/frame 内复选框也可识别。"""
    state, _probe = await _challenge_state(page)
    return state != "clear"


async def _challenge_cleared(page: Any) -> bool:
    state, _checkbox = await _challenge_state(page)
    return state == "clear"


async def _wait_until_challenge_clears(page: Any, timeout_seconds: int, log) -> bool:
    """有界确认实际放行，取消不等待卡住的驱动清理。"""
    from . import turnstile

    context = turnstile._DEADLINE.set(turnstile._deadline(max(0, timeout_seconds)))

    async def observe():
        while not await _challenge_cleared(page):
            await turnstile._pause(page, 250, {}, stage="page_wait")
        return True

    try:
        return await turnstile._bounded(observe(), turnstile._remaining())
    except TimeoutError:
        return False
    finally:
        turnstile._DEADLINE.reset(context)


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
    """该站点是否已达到连续验证失败阈值（不据此断言 IP 被封）。"""
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
            "后续暂停重复求解以免耗尽任务预算；请检查验证页面和网络状态"
        )


async def solve_cloudflare(page, log=None, wait_seconds: float = 60, *, deadline: float | None = None,
                           diagnostics: dict[str, Any] | None = None) -> bool:
    """一份总预算处理 CF，布尔契约不变；deadline 使用 asyncio loop 的单调时钟。

    diagnostics: stage、target_kind、clicked、timeout_stage、reason；另有 moved、
    click_started、attempts、processing、probe_reason，不包含令牌或原始驱动异常。
    """
    from . import turnstile

    _check_camoufox()
    data = diagnostics if diagnostics is not None else {}
    turnstile._init_diagnostics(data)
    budget = min(max(0.0, float(wait_seconds)), turnstile._remaining(deadline))
    if not math.isfinite(budget) or budget <= 0:
        turnstile._diagnose(data, reason="invalid_budget" if not math.isfinite(budget) else "timeout",
                           timeout_stage="page_state")
        return False
    stop = turnstile._deadline(budget, deadline)
    context = turnstile._DEADLINE.set(stop)
    origin = await _page_origin(page)

    async def attempt() -> bool:
        initial = await _challenge_state(page, diagnostics=data)
        if initial[0] == "clear":
            turnstile._diagnose(data, stage="complete", reason="page_cleared", timeout_stage=None)
            return True
        if cf_is_blocked(page, origin):
            turnstile._diagnose(data, stage="blocked", reason="circuit_open")
            turnstile._log(log, "Cloudflare 挑战连续未通过，暂停重复求解；请检查验证页面和网络状态")
            return False
        return await _solve_cloudflare_once(page, log=log, wait_seconds=turnstile._remaining(),
                                            deadline=stop, diagnostics=data, initial_state=initial)

    try:
        passed = await turnstile._bounded(attempt(), turnstile._remaining())
    except TimeoutError:
        turnstile._diagnose(data, timeout_stage=data.get("timeout_stage") or data.get("stage"), reason="timeout")
        turnstile._log(log, f"Cloudflare 挑战未能通过：已达到 {budget:g}s 总预算，停止等待")
        passed = False
    except asyncio.CancelledError:
        turnstile._diagnose(data, reason="cancelled")
        raise
    except Exception:
        turnstile._diagnose(data, reason="driver_error")
        turnstile._log(log, "Cloudflare 挑战未能通过：页面状态读取或交互失败")
        passed = False
    finally:
        turnstile._DEADLINE.reset(context)
    if passed:
        cf_note_success(page, origin)
    elif data.get("reason") != "circuit_open":
        turnstile._log(log, "Cloudflare 挑战未能通过，停止本轮求解；请检查验证页面和网络状态")
        cf_note_failure(page, origin, log)
    return passed


async def _solve_cloudflare_once(page, log=None, wait_seconds: float = 60, *, deadline: float | None = None,
                                 diagnostics: dict[str, Any] | None = None,
                                 initial_state: tuple[str, dict[str, Any]] | None = None) -> bool:
    """共享一轮 probe 的结果，不嵌套 solve/新预算；页面放行立即结束，无需 token。"""
    from . import turnstile

    data = diagnostics if diagnostics is not None else {}
    context = turnstile._DEADLINE.set(turnstile._deadline(max(0, wait_seconds), deadline))
    session = turnstile._ClickSession()

    async def observe() -> bool:
        current = initial_state
        announced_wait = False
        bridge_installed = False
        while turnstile._remaining() > 0:
            if current is None:
                current = await _challenge_state(page, diagnostics=data)
            state, result = current
            current = None
            if state == "clear":
                turnstile._diagnose(data, stage="complete", reason="page_cleared", timeout_stage=None)
                turnstile._log(log, "Cloudflare 挑战已通过（页面放行）" if data.get("clicked")
                               else "Cloudflare 挑战已通过（自动放行）")
                return True
            # 导航/读取失败状态下不以旧坐标点击；有明确 CF 页面或 widget 才交互。
            if state in {"interactive", "interstitial"}:
                if await session.attempt(page, result, data, log):
                    continue
                if state == "interactive" and not bridge_installed:
                    await turnstile.install_token_bridge(page, diagnostics=data)
                    bridge_installed = True
            if not announced_wait:
                turnstile._log(log, f"等待 Cloudflare 自动放行（整轮最多 {wait_seconds:g}s）；发现可点击目标会立即处理")
                announced_wait = True
            await turnstile._pause(page, 250, data, stage="page_wait")
        return False

    try:
        passed = await turnstile._bounded(observe(), turnstile._remaining())
        if not passed:
            turnstile._diagnose(data, timeout_stage=data.get("timeout_stage") or data.get("stage"), reason="timeout")
        return passed
    except TimeoutError:
        turnstile._diagnose(data, timeout_stage=data.get("timeout_stage") or data.get("stage"), reason="timeout")
        turnstile._log(log, "Cloudflare 挑战未能通过（总预算已耗尽），不追加求解轮次")
        return False
    finally:
        turnstile._DEADLINE.reset(context)


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

