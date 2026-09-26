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
import inspect
from contextvars import ContextVar
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

# 所有浏览器 RPC、单 frame 探测及整轮定位都有独立预算；不等待取消清理完成。
_OPERATION_TIMEOUT_SECONDS = 2.0
# 一个 frame 需要多次定位/可见性 RPC；Windows 上不能用亚秒预算误杀正常查询。
_FRAME_TIMEOUT_SECONDS = 3.0
_QUERY_TIMEOUT_SECONDS = 8.0
_MAX_FRAMES = 16
_MAX_CLICK_ATTEMPTS = 2
# 子操作继承同一单调时钟截止；即使取消清理卡住也不扩张调用方预算。
_DEADLINE: ContextVar[float | None] = ContextVar("turnstile_deadline", default=None)

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
            return url.protocol === 'https:' && (!url.port || url.port === '443')
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

# 无可交互 checkbox 时仍保留拒绝原因。空容器不是可点击目标，只有已读取
# 内容状态的可信 CF frame 才能回退到可见 owner（包括 closed shadow owner）。
_PROBE_STATE_JS = (
    """trustedFrame => {""" + _DOM_HELPERS_JS + """
    if (trustedFrame && !trustedURL(window.location.href))
        return {present: false, processing: false, reason: 'untrusted_frame'};
    const all = elements(document);
    const scopes = trustedFrame ? [all] : all.filter(el => el.matches(containerSelector))
        .map(el => elements(el)).filter(nodes => !hasForeignFrame(nodes));
    const nodes = scopes.flat();
    const boxes = nodes.filter(el => el.matches(checkboxSelector));
    const processing = scopes.some(busy) || boxes.some(el => el.checked || el.indeterminate
        || ['true', 'mixed'].includes(el.getAttribute('aria-checked')));
    const ready = scopes.some(nodes => !busy(nodes)
        && nodes.some(el => el.matches(checkboxSelector) && actionable(el)));
    const reason = processing ? 'processing' : ready ? 'ready' : boxes.length
        ? 'checkbox_unusable' : trustedFrame ? 'frame_owner_ready' : 'target_not_found';
    return {present: trustedFrame || scopes.length > 0, processing, actionable: ready,
        fallback_allowed: trustedFrame && !boxes.length && !processing && !hasForeignFrame(all), reason};
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


def _remaining(deadline: float | None = None) -> float:
    limits = [value for value in (deadline, _DEADLINE.get()) if value is not None]
    return max(0.0, min(limits) - asyncio.get_running_loop().time()) if limits else float("inf")


def _deadline(seconds: float, deadline: float | None = None) -> float:
    return asyncio.get_running_loop().time() + min(max(0.0, seconds), _remaining(deadline))


def _diagnose(diagnostics: dict[str, Any] | None, **values: Any) -> None:
    if diagnostics is not None:
        diagnostics.update(values)


def _init_diagnostics(diagnostics: dict[str, Any]) -> None:
    diagnostics.update(stage="probe", target_kind=None, clicked=False, click_started=False,
                       moved=False, timeout_stage=None, reason="", attempts=0)


def _log(log: Any, message: str) -> None:
    if callable(log):
        try:
            log(message)
        except Exception:
            pass


async def _bounded(awaitable: Awaitable, seconds: float) -> Any:
    """硬限时：裁剪到剩余预算，取消任务但不等待卡住的 RPC 取消清理。"""
    seconds = min(max(0.0, seconds), _remaining())
    if seconds <= 0:
        if inspect.iscoroutine(awaitable):
            awaitable.close()
        elif isinstance(awaitable, asyncio.Future):
            awaitable.cancel()
        raise TimeoutError
    task = asyncio.ensure_future(awaitable)
    try:
        done, _ = await asyncio.wait({task}, timeout=seconds)
        if task in done:
            return task.result()
        raise TimeoutError
    finally:
        if not task.done():
            task.cancel()
        task.add_done_callback(_consume_task)


async def _operation(awaitable: Awaitable, stage: str, diagnostics: dict[str, Any] | None,
                     seconds: float | None = None) -> Any:
    _diagnose(diagnostics, stage=stage)
    try:
        return await _bounded(awaitable, _OPERATION_TIMEOUT_SECONDS if seconds is None else seconds)
    except TimeoutError:
        _diagnose(diagnostics, timeout_stage=(diagnostics or {}).get("timeout_stage") or stage, reason="timeout")
        raise


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
            url.scheme == "https" and url.port in {None, 443}
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
        handle = await _bounded(scope.evaluate_handle(_FIND_CHECKBOX_JS, trusted), _OPERATION_TIMEOUT_SECONDS)
        element = handle.as_element()
        if element is None:
            return None
        # bounding_box 使用主 viewport；绝不返回 frame 内的 getBoundingClientRect。
        box = _box(page, await _bounded(element.bounding_box(), _OPERATION_TIMEOUT_SECONDS), checkbox=True)
        if box and await _bounded(element.evaluate(_ACTIONABLE_ELEMENT_JS), _OPERATION_TIMEOUT_SECONDS):
            return box
        return None
    finally:
        await _dispose(handle)


async def _owners_visible(frame: Any, box: dict[str, Any]) -> bool:
    """frame_element 可定位父页面 closed shadow 中的 owner，无需打破封装。"""
    x = box["x"] + (box["width"] / 2 if box.get("kind") == "checkbox" else _CHECKBOX_X_OFFSET)
    y = box["y"] + box["height"] / 2
    for _ in range(8):
        if frame.parent_frame is None:
            return True
        handle = None
        try:
            handle = await _bounded(frame.frame_element(), _OPERATION_TIMEOUT_SECONDS)
            if not await _bounded(handle.evaluate(_ACTIONABLE_ELEMENT_JS), _OPERATION_TIMEOUT_SECONDS):
                return False
            owner = await _bounded(handle.bounding_box(), _OPERATION_TIMEOUT_SECONDS)
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
    handle = None
    try:
        handle = await _bounded(frame.frame_element(), _OPERATION_TIMEOUT_SECONDS)
        if not await _bounded(handle.evaluate(_ACTIONABLE_ELEMENT_JS), _OPERATION_TIMEOUT_SECONDS):
            return None
        box = _box(page, await _bounded(handle.bounding_box(), _OPERATION_TIMEOUT_SECONDS))
        if box and await _owners_visible(frame, box) and _trusted_frame(frame):
            return box
        return None
    finally:
        await _dispose(handle)


async def install_token_bridge(page: Any, *, diagnostics: dict[str, Any] | None = None) -> None:
    """注入主世界脚本，把 window.turnstile.getResponse() 的令牌搬到共享 DOM 属性。

    Camoufox 的 page.evaluate 跑在隔离世界，读不到页面的 window.turnstile；而站点用
    explicit render + JS callback 时，令牌只进框架状态、不写任何隐藏域，隔离世界因此
    永远读不到（表现为「用户完成验证了却报未签发」）。用 add_script_tag 在主世界周期性
    把 getResponse() 的结果写到 <html> 的 data 属性，read_token 再从属性读回来。

    幂等且尽力而为：脚本自带守卫，重复注入无副作用；注入失败（CSP 限制等）也不抛，
    read_token 仍会回退到隐藏域，功能不因此变差。
    """
    try:
        await _operation(page.add_script_tag(content=_BRIDGE_JS), "bridge", diagnostics)
    except Exception:
        pass


async def read_token(page: Any, *, diagnostics: dict[str, Any] | None = None) -> str:
    """读取 Cloudflare 正常签发的 Turnstile 令牌（不伪造、不篡改）。为空表示尚未签发。"""
    try:
        value = await _operation(page.evaluate(_READ_TOKEN_JS), "token_wait", diagnostics)
        return value.strip() if isinstance(value, str) else ""
    except Exception:
        return ""


def _probe_result(reason: str = "target_not_found", *, processing: bool = False,
                  present: bool = False, **values: Any) -> dict[str, Any]:
    return {"target": None, "target_kind": None, "target_id": None,
            "processing": processing, "present": present, "reason": reason, **values}


async def _scope_state(scope: Any, *, trusted: bool) -> dict[str, Any]:
    value = await _bounded(scope.evaluate(_PROBE_STATE_JS, trusted), _OPERATION_TIMEOUT_SECONDS)
    if not isinstance(value, dict) or not isinstance(value.get("processing"), bool):
        raise ValueError("invalid probe state")
    return value


async def probe(page: Any, *, timeout_ms: int | None = None, deadline: float | None = None,
                diagnostics: dict[str, Any] | None = None) -> dict[str, Any]:
    """一次有界探测：真实 checkbox 优先，其次已核实的可信可见 CF frame owner。

    target 是主 viewport bbox（checkbox 含 kind='checkbox'）；另返回 target_kind、
    target_id、processing、present、reason。下划线字段仅供 click 重验，不应序列化。
    无法读取 frame 内容、已选/禁用/隐藏 checkbox、处理中、空容器均不能盲点。
    """
    seconds = _QUERY_TIMEOUT_SECONDS if timeout_ms is None else max(0, timeout_ms) / 1000
    stop = _deadline(min(seconds, _QUERY_TIMEOUT_SECONDS), deadline)
    context = _DEADLINE.set(stop)
    failure = _probe_result()

    def reject(reason: str, *, present: bool = True, processing: bool = False) -> None:
        nonlocal failure
        severity = {"target_not_found": 0, "frame_owner_ready": 1, "frame_owner_hidden": 2,
                    "checkbox_unusable": 3, "processing": 4, "probe_failed": 5, "probe_timeout": 6}
        if severity.get(reason, 3) < severity.get(failure["reason"], 3):
            reason = failure["reason"]
        failure = _probe_result(reason, present=present or failure["present"],
                                processing=processing or failure["processing"])

    async def locate() -> dict[str, Any]:
        fallback_frames = []
        blocked = False
        for frame in _frames(page):
            try:
                box = await _bounded(_frame_checkbox(frame, page), _FRAME_TIMEOUT_SECONDS)
                if box:
                    return _probe_result("ready", present=True, target=box, target_kind="checkbox",
                                         target_id=f"frame:{id(frame)}", _frame=frame, _url=frame.url)
                state = await _scope_state(frame, trusted=True)
                reject(state.get("reason", "checkbox_unusable"), processing=bool(state["processing"]))
                blocked = blocked or state["processing"] or state.get("reason") == "checkbox_unusable"
                if state.get("fallback_allowed") is True and _trusted_frame(frame):
                    fallback_frames.append(frame)
            except TimeoutError:
                reject("probe_timeout")
                blocked = True  # 未读完的 frame 不能从父容器绕过安全检查。
            except Exception:
                reject("probe_failed")
                blocked = True
        try:
            box = await _bounded(_checkbox_in(page, page, trusted=False), _FRAME_TIMEOUT_SECONDS)
            if box:
                return _probe_result("ready", present=True, target=box, target_kind="checkbox", target_id="main")
            state = await _scope_state(page, trusted=False)
            if state.get("present"):
                blocked = blocked or state["processing"] or state.get("reason") == "checkbox_unusable"
                reject(state.get("reason", "target_not_found"), processing=bool(state["processing"]))
        except TimeoutError:
            reject("probe_timeout", present=failure["present"])
            blocked = True
        except Exception:
            reject("probe_failed", present=failure["present"])
            blocked = True
        if not blocked:
            for frame in fallback_frames:
                try:
                    box = await _bounded(_frame_fallback(frame, page), _FRAME_TIMEOUT_SECONDS)
                    if box:
                        return _probe_result("ready", present=True, target=box, target_kind="frame_owner",
                                             target_id=f"frame:{id(frame)}", _frame=frame, _url=frame.url)
                    reject("frame_owner_hidden")
                except TimeoutError:
                    reject("probe_timeout")
                except Exception:
                    reject("probe_failed")
        return failure

    try:
        _diagnose(diagnostics, stage="probe")
        result = await _bounded(locate(), _remaining())
    except TimeoutError:
        result = _probe_result("probe_timeout", present=failure["present"])
    except Exception:
        result = _probe_result("probe_failed", present=failure["present"])
    finally:
        _DEADLINE.reset(context)
    _diagnose(diagnostics, probe_reason=result["reason"], processing=result["processing"])
    if result["target"] is not None:
        _diagnose(diagnostics, stage="located", target_kind=result["target_kind"], reason="ready")
    elif result["reason"] == "probe_timeout":
        _diagnose(diagnostics, timeout_stage="probe", reason="timeout")
    else:
        _diagnose(diagnostics, reason=result["reason"])
    return result


async def find_checkbox(page: Any) -> dict[str, Any] | None:
    """旧 API：只返回可交互真实 checkbox bbox 或 None（主 viewport 坐标）。"""
    result = await probe(page)
    return result["target"] if result["target_kind"] == "checkbox" else None


async def find_box(page: Any) -> dict[str, Any] | None:
    """旧 API：返回 checkbox / 可信 frame owner bbox 或 None，不点击空容器。"""
    return (await probe(page))["target"]


async def _target_still_ready(page: Any, result: dict[str, Any]) -> bool:
    frame = result.get("_frame")
    if frame is not None:
        if not _trusted_frame(frame) or frame.url != result.get("_url"):
            return False
        state = await _scope_state(frame, trusted=True)
        fallback = result["target_kind"] == "frame_owner"
        allowed = state.get("fallback_allowed") if fallback else state.get("actionable")
        if not allowed or state["processing"]:
            return False
        # 只重验刚才选中的 frame，不再遍历其他 frame 或完整 probe；移动期间的位置
        # 变化必须重新定位，不能拿旧的偏移点点击另一个控件。
        current = await (_frame_fallback(frame, page) if fallback else _frame_checkbox(frame, page))
        return current == result["target"] and _trusted_frame(frame) and frame.url == result.get("_url")
    state = await _scope_state(page, trusted=False)
    if not state.get("actionable") or state["processing"]:
        return False
    return await _checkbox_in(page, page, trusted=False) == result["target"]


async def click(page: Any, *, box: dict[str, Any] | None = None,
                target: dict[str, Any] | None = None, timeout_ms: int | None = None,
                deadline: float | None = None, diagnostics: dict[str, Any] | None = None,
                log: Any = None) -> bool:
    """有界真实鼠标输入；复用 probe 的 target 避免同轮完整重查。

    一次有界移动（CF 偏好开启时最多 CF_MOVE_STEPS 步，否则单步），然后单独执行
    click；只有 RPC 返回后 clicked 才为 True。
    click_started=True 但 clicked=False 表示结果不确定，不能盲目重试。
    box 保留旧调用方的已测量 bbox 契约，新调用方应传 target=probe(...)。
    """
    data = diagnostics if diagnostics is not None else {}
    data.setdefault("clicked", False)
    _diagnose(data, moved=False, click_started=False)
    seconds = _QUERY_TIMEOUT_SECONDS + 2 * _OPERATION_TIMEOUT_SECONDS if timeout_ms is None else max(0, timeout_ms) / 1000
    context = _DEADLINE.set(_deadline(seconds, deadline))

    async def perform() -> bool:
        result = target
        if result is None and box is None:
            result = await probe(page, diagnostics=data)
        measured = _box(page, box if box is not None else (result or {}).get("target"))
        if measured is None or (result is not None and result.get("processing")):
            _diagnose(data, reason=(result or {}).get("reason", "invalid_target"))
            return False
        kind = (result or {}).get("target_kind") or ("checkbox" if measured.get("kind") else "frame_owner")
        _diagnose(data, stage="located", target_kind=kind, reason="ready")
        _log(log, f"已定位 Cloudflare 点击目标（{kind}，主视口坐标）")
        x = measured["x"] + (measured["width"] / 2 if measured.get("kind") == "checkbox" else _CHECKBOX_X_OFFSET)
        y = measured["y"] + measured["height"] / 2
        # 只有 CF 验证目标允许有限多步移动；普通点击在浏览器层已直接落点。
        await _operation(page.mouse.move(x, y, steps=cf_move_steps(page)), "move", data)
        _diagnose(data, stage="moved", moved=True)
        _log(log, "Cloudflare 鼠标移动已完成；尚未执行点击")
        if result is not None and not await _operation(_target_still_ready(page, result), "validate", data):
            _diagnose(data, reason="target_changed")
            return False
        # 截止已过时不能连 click 协程都开始，更不能把已定位/已移动记成已点击。
        if _remaining() <= 0:
            _diagnose(data, timeout_stage="click", reason="timeout")
            return False
        _diagnose(data, click_started=True)
        await _operation(page.mouse.click(x, y), "click", data)
        _diagnose(data, stage="clicked", clicked=True, reason="click_completed", timeout_stage=None)
        _log(log, "Cloudflare 真实鼠标点击已完成")
        return True

    try:
        return await _bounded(perform(), _remaining())
    except TimeoutError:
        _diagnose(data, timeout_stage=data.get("timeout_stage") or data.get("stage", "click"), reason="timeout")
        return False
    except asyncio.CancelledError:
        if _remaining() <= 0:
            _diagnose(data, reason="timeout", timeout_stage=data.get("timeout_stage") or data.get("stage"))
        else:
            _diagnose(data, reason="cancelled")
        raise
    except Exception:
        _diagnose(data, reason="click_uncertain" if data.get("click_started") else "not_clicked")
        return False
    finally:
        _DEADLINE.reset(context)


#: 点击前的多步定位仅用于 CF 验证；拖拽和 LinuxDO 读帖曲线各自保留。
#: Playwright 逐点发送，整体仍受调用方 deadline 约束。
CF_MOVE_STEPS = 8
#: context 上的私有运行期属性，不修改浏览器全局输入行为。
_CF_HUMANIZE_ATTR = "_checkin_cf_humanize"


def set_cf_humanize(context: Any, enabled: bool) -> None:
    """记录 CF 专用移动偏好；拿不到属性的对象（测试替身等）静默跳过。"""
    try:
        setattr(context, _CF_HUMANIZE_ATTR, bool(enabled))
    except Exception:
        pass


def cf_humanize_enabled(page: Any) -> bool:
    """读取页面所在 context 的 CF 移动偏好；缺失时按关闭处理（单步真实输入）。"""
    try:
        value = getattr(getattr(page, "context", None), _CF_HUMANIZE_ATTR, False)
    except Exception:
        return False
    return value is True


def cf_move_steps(page: Any) -> int:
    """CF 验证目标的移动步数：偏好开启时有限多步，否则单步直达。"""
    return CF_MOVE_STEPS if cf_humanize_enabled(page) else 1


class _ClickSession:
    """共享点击策略：只对延迟出现、已替换 frame 或明确未 click 的目标有限尝试。"""

    def __init__(self) -> None:
        self.attempts = 0
        self.handled: set[str] = set()
        self.previous_frame: Any = None
        self.next_attempt = 0.0

    async def attempt(self, page: Any, result: dict[str, Any], diagnostics: dict[str, Any], log: Any) -> bool:
        key = result.get("target_id")
        if (result.get("target") is None or result.get("processing") or key in self.handled
                or self.attempts >= _MAX_CLICK_ATTEMPTS or asyncio.get_running_loop().time() < self.next_attempt):
            return False
        if self.handled and (self.previous_frame is None or self.previous_frame in _frames(page)):
            return False
        self.attempts += 1
        diagnostics["attempts"] = self.attempts
        clicked = await click(page, target=result, diagnostics=diagnostics, log=log)
        if clicked or diagnostics.get("click_started"):
            self.handled.add(key)
            self.previous_frame = result.get("_frame")
        self.next_attempt = asyncio.get_running_loop().time() + _RETRY_GAP_SECONDS
        return clicked


async def _pause(page: Any, milliseconds: int, diagnostics: dict[str, Any], *, stage: str) -> None:
    seconds = min(max(0, milliseconds) / 1000, _remaining())
    if seconds <= 0:
        raise TimeoutError
    try:
        await _operation(page.wait_for_timeout(max(1, int(seconds * 1000))), stage, diagnostics,
                         seconds=min(seconds + 0.1, _remaining()))
    except TimeoutError:
        raise
    except Exception:
        await _bounded(asyncio.sleep(min(seconds, _remaining())), _remaining())


async def solve(
    page: Any,
    *,
    timeout_ms: int,
    poll_interval_ms: int = 1000,
    log: Any = None,
    completed: Callable[[], Awaitable[bool]] | None = None,
    deadline: float | None = None,
    diagnostics: dict[str, Any] | None = None,
) -> str:
    """总预算内等待真实令牌；completed 确认页面放行后立即返回空串而不伪造令牌。

    diagnostics 的 stage/target_kind/clicked/timeout_stage/reason 不包含令牌或原始异常。
    处理中不再点击/reset；只允许 frame 替换或明确尚未 click 时至多两次尝试。
    """
    data = diagnostics if diagnostics is not None else {}
    _init_diagnostics(data)
    seconds = min(max(0, timeout_ms) / 1000, _remaining(deadline))
    if not math.isfinite(seconds) or seconds <= 0:
        _diagnose(data, reason="invalid_budget" if not math.isfinite(seconds) else "timeout", timeout_stage="probe")
        return ""
    context = _DEADLINE.set(_deadline(seconds, deadline))
    session = _ClickSession()
    step = min(max(poll_interval_ms, 100), 500)

    async def observe() -> str:
        logged_waiting = False
        bridge_installed = False
        next_probe = 0.0
        while _remaining() > 0:
            # 放行检查必须在 token RPC 之前：无 response 字段的 managed 导航不能等空 token。
            if completed is not None:
                try:
                    if await _operation(completed(), "page_state", data):
                        _diagnose(data, stage="complete", reason="page_cleared", timeout_stage=None)
                        _log(log, "页面已放行，结束 Turnstile 令牌等待")
                        return ""
                except Exception:
                    pass
            if not bridge_installed:
                await install_token_bridge(page, diagnostics=data)
                bridge_installed = True
            token = await read_token(page, diagnostics=data)
            if token:
                _diagnose(data, stage="complete", reason="token_issued", timeout_stage=None)
                _log(log, "Turnstile 验证已完成（令牌已签发）")
                return token
            now = asyncio.get_running_loop().time()
            if now >= next_probe:
                result = await probe(page, diagnostics=data)
                next_probe = asyncio.get_running_loop().time() + _RETRY_GAP_SECONDS
                if await session.attempt(page, result, data, log):
                    _log(log, "已点击验证框，持续等待 Cloudflare 令牌（可人工完成验证）...")
                    continue
                if not logged_waiting:
                    _log(log, "持续观察 Turnstile 令牌，不盲点或重置处理中控件（可人工完成验证）...")
                    logged_waiting = True
            await _pause(page, step, data, stage="token_wait")
        return ""

    try:
        value = await _bounded(observe(), seconds)
        if not value and data.get("reason") != "page_cleared":
            _diagnose(data, timeout_stage=data.get("timeout_stage") or data.get("stage"), reason="timeout")
        return value
    except TimeoutError:
        _diagnose(data, timeout_stage=data.get("timeout_stage") or data.get("stage"), reason="timeout")
        return ""
    except asyncio.CancelledError:
        if _remaining() <= 0:
            _diagnose(data, reason="timeout", timeout_stage=data.get("timeout_stage") or data.get("stage"))
        else:
            _diagnose(data, reason="cancelled")
        raise
    finally:
        _DEADLINE.reset(context)
