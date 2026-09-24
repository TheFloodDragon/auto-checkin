#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloudflare Turnstile 交互式验证：读取令牌 + 真实鼠标点击复选框。

Sub2API 系站点（极速蹬 / 百倍等）的登录页嵌入 Cloudflare Turnstile 交互式
widget（"Verify you are human" 复选框）。被动等待不会签发令牌，必须用真实
鼠标事件点击复选框（Cloudflare 校验 isTrusted，JS click 无效）。

定位策略：
1. 优先通过可信 CF frame / 开放 shadow tree 找到真实复选框并取主 viewport bbox；
2. 真实复选框点中心；旧 widget 回退仍按左侧约 30px、垂直居中点击；
3. 只使用 page.mouse 真实事件，所有查询和整体等待都有有限预算。

本模块只与页面交互、不伪造/篡改令牌，也不处理任何账号凭据。
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

# 所有浏览器 RPC、单 frame 探测及整轮定位都有独立预算；不等待取消清理完成。
_OPERATION_TIMEOUT_SECONDS = 2.0
# 一个 frame 需要多次定位/可见性 RPC；Windows 上不能用亚秒预算误杀正常查询。
_FRAME_TIMEOUT_SECONDS = 3.0
_QUERY_TIMEOUT_SECONDS = 8.0
_MAX_FRAMES = 16

# widget 左边缘到复选框中心的水平偏移（像素）。
_CHECKBOX_X_OFFSET = 30

# 没找到 widget 时的观察间隔（秒）。此时不该反复尝试点击：widget 可能尚未挂载，
# 也可能已经变成「验证成功」态或正由人工操作，继续观察令牌即可。
_RETRY_GAP_SECONDS = 1.0

# 读取页面中所有 Turnstile 响应字段的当前值。
#
# 令牌有三处落点，必须都读：
# 1. 标准隐藏域 `cf-turnstile-response`（隐式渲染 `.cf-turnstile` 默认生成）；
# 2. 带 widgetId 后缀的 `cf-turnstile-response-<id>`（explicit render 生成，
#    因此用前缀匹配而不是精确匹配 —— 精确匹配会整个漏掉这类字段）；
# 3. 主世界桥接写到 <html> 的 data 属性：站点若用 explicit render + JS callback
#    （Vue/React 常见做法，令牌进框架状态而不写任何隐藏域），前两处都读不到，
#    只能靠 install_token_bridge 注入的主世界脚本把 window.turnstile.getResponse()
#    的结果搬到共享 DOM。实测 Camoufox 的 page.evaluate 跑在隔离世界，读不到页面
#    的 window.turnstile，故必须经 DOM 属性桥接。
#
# 页面可能同时保留多个 widget 或旧字段；只读第一个字段会一直读到空值，即使人工
# 已经在后续 widget 完成验证。三处任一非空即视为已签发。
_READ_TOKEN_JS = """() => {
    const fields = Array.from(document.querySelectorAll(
        'input[name^="cf-turnstile-response"], textarea[name^="cf-turnstile-response"]'
    ));
    for (const field of fields) {
        const value = typeof field.value === 'string'
            ? field.value
            : String(field.textContent || '');
        if (value.trim()) return value.trim();
    }
    const bridged = document.documentElement.getAttribute('data-ck-ts-token');
    if (bridged && bridged.trim()) return bridged.trim();
    return '';
}"""

# 主世界桥接：把 window.turnstile.getResponse() 的结果周期性写到 <html> 的
# data-ck-ts-token 属性，让隔离世界的 page.evaluate 读得到 callback-only 的令牌。
# 只搬运 Cloudflare 正常签发的令牌，不伪造、不篡改。脚本自带 __ckTsBridge 守卫，
# 重复注入无副作用。
_BRIDGE_ATTR = "data-ck-ts-token"
_BRIDGE_JS = """
(() => {
  if (window.__ckTsBridge) return;
  window.__ckTsBridge = true;
  const write = () => {
    try {
      const ts = window.turnstile;
      if (!ts || typeof ts.getResponse !== 'function') return;
      let token = '';
      try { token = ts.getResponse() || ''; } catch (_) { token = ''; }
      if (typeof token === 'string' && token.trim()) {
        document.documentElement.setAttribute('data-ck-ts-token', token.trim());
      }
    } catch (_) {}
  };
  write();
  setInterval(write, 300);
})();
"""

# 只遍历已经开放的 shadow tree，不修改 attachShadow。主文档中的裸 checkbox、
# data-sitekey（hCaptcha/reCAPTCHA 也使用它）、iframe title 均不是 CF 身份凭证。
_DOM_HELPERS_JS = """
    const containerSelector = '.cf-turnstile, .turnstile-container, .turnstile-wrapper, '
        + '#cf-chl-widget, [id^="cf-chl-widget-"]';
    const checkboxSelector = 'input[type="checkbox"], [role="checkbox"]';
    const responseSelector = 'input[name^="cf-turnstile-response"], textarea[name^="cf-turnstile-response"]';
    const busySelector = '[aria-busy="true"], [role="progressbar"], [data-state="processing"], '
        + '[data-state="verifying"], [data-state="success"], #verifying, #success, #success-text';
    const parentOf = el => el.parentElement || (el.getRootNode && el.getRootNode().host) || null;
    const trustedURL = value => {
        try {
            const url = new URL(value, document.baseURI);
            return ['https:', 'http:'].includes(url.protocol)
                && url.hostname === 'challenges.cloudflare.com' && !url.username && !url.password;
        } catch (_) { return false; }
    };
    // 限制节点/深度，避免异常页面把一个同步 DOM 查询变成无界遍历。
    const elements = root => {
        const result = [];
        const pending = [root];
        while (pending.length && result.length < 6000) {
            const node = pending.pop();
            if (node.nodeType === 1) result.push(node);
            for (const children of [node.children, node.shadowRoot && node.shadowRoot.children]) {
                if (!children) continue;
                for (let i = children.length - 1; i >= 0 && pending.length < 6000; i--) {
                    pending.push(children[i]);
                }
            }
        }
        return result;
    };
    const visible = el => {
        if (!el || !el.isConnected) return false;
        let node = el;
        for (let depth = 0; node && depth < 128; depth++, node = parentOf(node)) {
            const style = window.getComputedStyle(node);
            if (node.hidden || node.inert || node.getAttribute('aria-hidden') === 'true'
                || style.display === 'none' || ['hidden', 'collapse'].includes(style.visibility)
                || Number(style.opacity) === 0 || style.pointerEvents === 'none') return false;
        }
        if (node) return false;
        const r = el.getBoundingClientRect();
        const x = r.x + r.width / 2, y = r.y + r.height / 2;
        return r.width >= 2 && r.height >= 2 && x >= 0 && y >= 0
            && x < window.innerWidth && y < window.innerHeight;
    };
    const busy = nodes => nodes.some(el => el.matches(busySelector) && visible(el));
    const actionable = el => {
        if (!visible(el) || el.disabled || el.matches(':disabled') || el.checked || el.indeterminate) return false;
        const checked = el.getAttribute('aria-checked');
        if (checked && checked !== 'false') return false;
        if (el.getAttribute('role') === 'checkbox' && checked !== 'false') return false;
        for (let node = el, depth = 0; node && depth < 128; depth++, node = parentOf(node)) {
            if (node.getAttribute('aria-disabled') === 'true' || node.getAttribute('aria-busy') === 'true') return false;
        }
        return true;
    };
    const hasForeignFrame = nodes => nodes.some(el => el.matches('iframe') && !trustedURL(el.src));
    const canFallback = nodes => !nodes.some(el => el.matches(checkboxSelector)) && !busy(nodes);
"""

_FIND_CHECKBOX_JS = (
    """trustedFrame => {"""
    + _DOM_HELPERS_JS
    + """
    if (trustedFrame && !trustedURL(window.location.href)) return null;
    const nodes = elements(document);
    if (trustedFrame && busy(nodes)) return null;
    for (const el of nodes) {
        if (!el.matches(checkboxSelector) || !actionable(el)) continue;
        if (trustedFrame) return el;
        for (let scope = parentOf(el), depth = 0; scope && depth < 128; depth++, scope = parentOf(scope)) {
            if (!scope.matches(containerSelector)) continue;
            const scoped = elements(scope);
            if (!busy(scoped) && !hasForeignFrame(scoped)) return el;
            break;
        }
    }
    return null;
}"""
)

_VISIBLE_ELEMENT_JS = """el => {""" + _DOM_HELPERS_JS + """return visible(el); }"""
_ACTIONABLE_ELEMENT_JS = """el => {""" + _DOM_HELPERS_JS + """return actionable(el); }"""
_FRAME_CAN_FALLBACK_JS = (
    """() => {"""
    + _DOM_HELPERS_JS
    + """
    return trustedURL(window.location.href) && canFallback(elements(document));
}"""
)
_FIND_BOX_JS = (
    """scanIframes => {"""
    + _DOM_HELPERS_JS
    + """
    const nodes = elements(document);
    const candidates = [];
    const add = (el, priority) => {
        if (!visible(el)) return;
        const inside = elements(el);
        // frame 内存在已选/隐藏 checkbox 时不得从父页面绕过检查再次点 owner。
        if (!scanIframes && inside.some(node => node.matches('iframe'))) return;
        if (!canFallback(inside) || hasForeignFrame(inside)) return;
        const r = el.getBoundingClientRect();
        if (r.width < 32 || r.height < 10) return;
        candidates.push({priority, box: {x: r.x, y: r.y, width: r.width, height: r.height}});
    };
    for (const el of nodes) {
        if (scanIframes && el.matches('iframe') && trustedURL(el.src)) add(el, 0);
        if (el.matches(containerSelector)) add(el, 1);
        if (el.matches(responseSelector)) {
            // 保留旧响应字段父容器回退，但不把整个登录表单当成 widget。
            const parent = parentOf(el);
            if (parent) {
                const r = parent.getBoundingClientRect();
                if (r.width <= 600 && r.height <= 150) add(parent, 2);
            }
        }
    }
    candidates.sort((left, right) => left.priority - right.priority);
    return candidates.length ? candidates[0].box : null;
}"""
)


def _consume_task(task: asyncio.Future) -> None:
    if not task.cancelled():
        task.exception()


async def _bounded(awaitable: Awaitable, seconds: float) -> Any:
    """硬限时：取消超时任务，但不等待可能卡住的 RPC 取消清理。"""
    task = asyncio.ensure_future(awaitable)
    try:
        done, _ = await asyncio.wait({task}, timeout=max(0, seconds))
        if task in done:
            return task.result()
        raise TimeoutError
    finally:
        if not task.done():
            task.cancel()
        task.add_done_callback(_consume_task)


async def _dispose(handle: Any) -> None:
    if handle is not None:
        try:
            await _bounded(handle.dispose(), 0.05)
        except Exception:
            pass


def _trusted_frame(frame: Any) -> bool:
    try:
        url = urlsplit(frame.url)
        return (
            url.scheme in {"https", "http"}
            and url.hostname == "challenges.cloudflare.com"
            and not url.username
            and not url.password
            and not frame.is_detached()
        )
    except Exception:
        return False


def _frames(page: Any) -> list[Any]:
    return [frame for frame in getattr(page, "frames", ()) if _trusted_frame(frame)][:_MAX_FRAMES]


def _box(page: Any, value: Any, *, checkbox: bool = False) -> dict[str, Any] | None:
    """拒绝非有限/退化坐标；点击点必须在框内及已知的主 viewport 内。"""
    if not isinstance(value, dict):
        return None
    rect = {}
    for key in ("x", "y", "width", "height"):
        item = value.get(key)
        if isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item):
            return None
        rect[key] = float(item)
    if not (2 <= rect["width"] <= 10000 and 2 <= rect["height"] <= 10000):
        return None
    checkbox = checkbox or value.get("kind") == "checkbox"
    x = rect["x"] + (rect["width"] / 2 if checkbox else _CHECKBOX_X_OFFSET)
    y = rect["y"] + rect["height"] / 2
    if not (0 <= x <= 100000 and 0 <= y <= 100000 and rect["x"] <= x < rect["x"] + rect["width"]):
        return None
    viewport = getattr(page, "viewport_size", None)
    if isinstance(viewport, dict) and (x >= viewport["width"] or y >= viewport["height"]):
        return None
    if checkbox:
        rect["kind"] = "checkbox"
    return rect


async def _checkbox_in(scope: Any, page: Any, *, trusted: bool) -> dict[str, Any] | None:
    handle = None
    try:
        handle = await scope.evaluate_handle(_FIND_CHECKBOX_JS, trusted)
        element = handle.as_element()
        if element is None:
            return None
        # bounding_box 使用主 viewport；绝不返回 frame 内的 getBoundingClientRect。
        box = _box(page, await element.bounding_box(), checkbox=True)
        if box and await element.evaluate(_ACTIONABLE_ELEMENT_JS):
            return box
        return None
    finally:
        await _dispose(handle)


async def _owners_visible(frame: Any, box: dict[str, Any]) -> bool:
    """frame_element 可定位父页面 closed shadow 中的 owner，无需打破封装。"""
    x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    for _ in range(8):
        if frame.parent_frame is None:
            return True
        handle = None
        try:
            handle = await frame.frame_element()
            if not await handle.evaluate(_VISIBLE_ELEMENT_JS):
                return False
            owner = await handle.bounding_box()
            if not owner or not (
                owner["x"] <= x < owner["x"] + owner["width"] and owner["y"] <= y < owner["y"] + owner["height"]
            ):
                return False
        finally:
            await _dispose(handle)
        frame = frame.parent_frame
    return False


async def _frame_checkbox(frame: Any, page: Any) -> dict[str, Any] | None:
    if not _trusted_frame(frame):
        return None
    box = await _checkbox_in(frame, page, trusted=True)
    if box and await _owners_visible(frame, box) and _trusted_frame(frame):
        return box
    return None


async def _frame_fallback(frame: Any, page: Any) -> dict[str, Any] | None:
    if not _trusted_frame(frame) or frame.parent_frame is None:
        return None
    if not await frame.evaluate(_FRAME_CAN_FALLBACK_JS):
        return None
    handle = None
    try:
        handle = await frame.frame_element()
        if not await handle.evaluate(_VISIBLE_ELEMENT_JS):
            return None
        box = _box(page, await handle.bounding_box())
        if box and await _owners_visible(frame, box) and _trusted_frame(frame):
            return box
        return None
    finally:
        await _dispose(handle)


async def install_token_bridge(page: Any) -> None:
    """注入主世界脚本，把 window.turnstile.getResponse() 的令牌搬到共享 DOM 属性。

    Camoufox 的 page.evaluate 跑在隔离世界，读不到页面的 window.turnstile；而站点用
    explicit render + JS callback 时，令牌只进框架状态、不写任何隐藏域，隔离世界因此
    永远读不到（表现为「用户完成验证了却报未签发」）。用 add_script_tag 在主世界周期性
    把 getResponse() 的结果写到 <html> 的 data 属性，read_token 再从属性读回来。

    幂等且尽力而为：脚本自带守卫，重复注入无副作用；注入失败（CSP 限制等）也不抛，
    read_token 仍会回退到隐藏域，功能不因此变差。
    """
    try:
        await _bounded(page.add_script_tag(content=_BRIDGE_JS), _OPERATION_TIMEOUT_SECONDS)
    except Exception:
        pass


async def read_token(page: Any) -> str:
    """读取 Cloudflare 正常签发的 Turnstile 令牌（不伪造、不篡改）。为空表示尚未签发。"""
    try:
        value = await _bounded(page.evaluate(_READ_TOKEN_JS), _OPERATION_TIMEOUT_SECONDS)
        return value.strip() if isinstance(value, str) else ""
    except Exception:
        return ""


async def find_checkbox(page: Any) -> dict[str, Any] | None:
    """只定位可信 CF、可见且可交互的未选复选框；坐标属于主 viewport。

    优先直接访问 page.frames，包含 owner 藏在 closed shadow root 中的 frame；
    主页面则只允许明确 Turnstile 容器内的复选框。每个 frame 与整轮查询均有限时。
    """

    async def locate() -> dict[str, Any] | None:
        for frame in _frames(page):
            try:
                box = await _bounded(_frame_checkbox(frame, page), _FRAME_TIMEOUT_SECONDS)
                if box:
                    return box
            except Exception:
                continue
        try:
            return await _bounded(_checkbox_in(page, page, trusted=False), _FRAME_TIMEOUT_SECONDS)
        except Exception:
            return None

    try:
        return await _bounded(locate(), _QUERY_TIMEOUT_SECONDS)
    except Exception:
        return None


async def find_box(page: Any) -> dict[str, Any] | None:
    """兼容旧 API：优先 checkbox，其次可信 frame owner / 开放树中的 widget。"""

    async def locate() -> dict[str, Any] | None:
        box = await find_checkbox(page)
        if box:
            return box
        for frame in _frames(page):
            try:
                box = await _bounded(_frame_fallback(frame, page), _FRAME_TIMEOUT_SECONDS)
                if box:
                    return box
            except Exception:
                continue
        value = await _bounded(page.evaluate(_FIND_BOX_JS, not hasattr(page, "frames")), _OPERATION_TIMEOUT_SECONDS)
        return _box(page, value)

    try:
        return await _bounded(locate(), _QUERY_TIMEOUT_SECONDS)
    except Exception:
        return None


async def click(page: Any, *, box: dict[str, Any] | None = None) -> bool:
    """真实鼠标点击：checkbox 点中心，旧 widget 保留左侧 30px 偏移。"""

    async def perform() -> bool:
        target = _box(page, box if box is not None else await find_box(page))
        if target is None:
            return False
        click_x = target["x"] + (target["width"] / 2 if target.get("kind") == "checkbox" else _CHECKBOX_X_OFFSET)
        click_y = target["y"] + target["height"] / 2
        await page.mouse.move(max(0, click_x - 60), max(0, click_y - 20), steps=8)
        await page.wait_for_timeout(200)
        await page.mouse.move(click_x, click_y, steps=12)
        await page.wait_for_timeout(150)
        await page.mouse.click(click_x, click_y)
        return True

    try:
        return await _bounded(perform(), _QUERY_TIMEOUT_SECONDS + 1.0)
    except Exception:
        return False


async def solve(
    page: Any,
    *,
    timeout_ms: int,
    poll_interval_ms: int = 1000,
    log: Any = None,
    completed: Callable[[], Awaitable[bool]] | None = None,
) -> str:
    """等待真实令牌，或由无参异步 completed 确认页面已放行后返回空串。

    timeout_ms 包含注入、查询、点击、predicate 和等待的全部时间，是硬上限。
    一次点击成功后只观察，不再点击处理中 widget；未挂载时短间隔重新定位。
    所有入口均保留 CancelledError，绝不把页面放行转换为伪令牌。
    """

    def _log(message: str) -> None:
        if callable(log):
            try:
                log(message)
            except Exception:
                pass

    loop = asyncio.get_running_loop()
    seconds = max(0, timeout_ms) / 1000
    if seconds == 0:
        return ""
    deadline = loop.time() + seconds
    step = min(max(poll_interval_ms, 100), 500)

    async def observe() -> str:
        await install_token_bridge(page)
        clicked = False
        logged_waiting = False
        next_attempt = 0.0
        while loop.time() < deadline:
            token = await read_token(page)
            if token:
                _log("Turnstile 令牌已签发" if clicked else "Turnstile 验证已完成（令牌由页面自行签发）")
                return token
            if completed is not None:
                try:
                    if await _bounded(completed(), _OPERATION_TIMEOUT_SECONDS):
                        _log("页面已放行，结束 Turnstile 令牌等待")
                        return ""
                except Exception:
                    pass
            if not clicked and loop.time() >= next_attempt:
                clicked = await click(page)
                if clicked:
                    _log("已点击 Turnstile 复选框，持续等待 Cloudflare 令牌（可人工完成验证）...")
                    # 点击可能立即签发；不额外空等一次轮询。
                    continue
                if not logged_waiting:
                    _log("未定位到 Turnstile 复选框，持续等待令牌（可人工完成验证）...")
                    logged_waiting = True
                next_attempt = loop.time() + _RETRY_GAP_SECONDS
            remaining_ms = (deadline - loop.time()) * 1000
            if remaining_ms <= 0:
                break
            wait_ms = int(min(step, max(1, remaining_ms)))
            try:
                await _bounded(page.wait_for_timeout(wait_ms), wait_ms / 1000 + 0.1)
            except Exception:
                await asyncio.sleep(min(wait_ms / 1000, max(0, deadline - loop.time())))
        return ""

    try:
        return await _bounded(observe(), seconds)
    except TimeoutError:
        return ""
