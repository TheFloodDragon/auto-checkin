#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloudflare Turnstile 交互式验证：读取令牌 + 真实鼠标点击复选框。

Sub2API 系站点（极速蹬 / 百倍等）的登录页嵌入 Cloudflare Turnstile 交互式
widget（"Verify you are human" 复选框）。被动等待不会签发令牌，必须用真实
鼠标事件点击复选框（Cloudflare 校验 isTrusted，JS click 无效）。

定位策略：
1. 优先通过可信 CF frame / 开放 shadow tree 找到真实复选框并取主 viewport bbox；
2. 仅点击有同节点身份、可见可用且无遮挡证据的真实复选框中心；
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
_READ_TOKEN_JS = """(target = null) => {
    const trusted = frame => {
        try {
            const url = new URL(frame.src, document.baseURI);
            return frame.isConnected && url.protocol === 'https:'
                && url.hostname === 'challenges.cloudflare.com' && (!url.port || url.port === '443')
                && !url.username && !url.password && Boolean(frame.id);
        } catch (_) { return false; }
    };
    const normalize = id => String(id || '').replace(/^cf-chl-widget-/, '')
        .replace(/_response$/, '').replace(/^cf-turnstile-response-/, '');
    const frames = Array.from(document.querySelectorAll('iframe[src]')).filter(trusted);
    const fields = Array.from(document.querySelectorAll(
        'input[name^="cf-turnstile-response"], textarea[name^="cf-turnstile-response"]'
    )).filter(field => field.isConnected);
    // 通用 name 不是唯一 widget 目标，两个同名字段绝不取首个非空值。
    if (target && fields.filter(field => field.name === target || field.id === target).length > 1) return '';
    if (!target && frames.length !== 1) return '';
    const bound = [];
    for (const field of fields) {
        const owner = field.closest('.cf-turnstile, [id^="cf-chl-widget"], #ck-ts-host');
        const local = owner && owner.isConnected
            ? Array.from(owner.querySelectorAll('iframe[src]')).filter(trusted) : [];
        const linked = frames.filter(frame => (field.id && normalize(field.id) === normalize(frame.id))
            || (field.name !== 'cf-turnstile-response' && normalize(field.name) === normalize(frame.id)));
        // 同容器不等于同 generation：重 render 可能保留旧 hidden field。
        // 必须以 CF 生成的字段 widget-id 对应当前 iframe-id；仅 owner/通用 name
        // 或站点自定义 field-id 都不是签发归属证据，callback-only 请使用桥接。
        const candidates = linked.filter(frame => !owner || local.includes(frame));
        if (candidates.length !== 1) continue;
        const frame = candidates[0];
        if (target && field.name !== target && field.id !== target
                && normalize(frame.id) !== normalize(target)) continue;
        bound.push(field);
    }
    if (bound.length === 1) {
        const field = bound[0];
        const value = typeof field.value === 'string' ? field.value : String(field.textContent || '');
        if (value.trim()) return value.trim();
    } else if (bound.length > 1) return '';
    // callback-only 也必须绑定一个当前 live widget-id，不能拿遗留桥接属性放行。
    const bridged = document.documentElement.getAttribute('data-ck-ts-token');
    const bridgeTarget = document.documentElement.getAttribute('data-ck-ts-widget');
    const live = frames.filter(frame => normalize(frame.id) === normalize(bridgeTarget));
    if (bridgeTarget && live.length === 1 && (!target || normalize(target) === normalize(bridgeTarget))
            && bridged && bridged.trim()) return bridged.trim();
    return '';
}"""

# 主世界桥接：记录 explicit render 返回的 widget id，并包装站点自己的 callback，
# 同时周期性读取 getResponse(widget_id)。这样 callback-only 的令牌即使不写隐藏域，
# 也能通过 <html> 的 data 属性交给隔离世界；所有值都来自页面真实 Turnstile API。
# 脚本自带 __ckTsBridge 守卫，重复注入无副作用。
_BRIDGE_ATTR = "data-ck-ts-token"
_BRIDGE_JS = """
(() => {
  if (window.__ckTsBridge) return;
  const state = { ids: [], installed: true };
  window.__ckTsBridge = state;
  const attr = 'data-ck-ts-token';
  const root = () => document.documentElement;
  const write = token => {
    try {
      const value = typeof token === 'string' ? token.trim() : '';
      if (value && state.ids.length <= 1) {
        root().setAttribute(attr, value);
        root().setAttribute('data-ck-ts-widget', String(state.ids[0] ?? ''));
      } else {
        root().removeAttribute(attr);
        root().removeAttribute('data-ck-ts-widget');
      }
    } catch (_) {}
  };
  const remember = id => {
    if (id !== undefined && id !== null && !state.ids.some(item => item === id)) {
      state.ids.push(id);
    }
  };
  const wrapCallback = (name, callback) => {
    if (typeof callback !== 'function') return callback;
    return function(...args) {
      if (name === 'callback') write(args[0]);
      else if (name === 'expired-callback' || name === 'error-callback'
               || name === 'timeout-callback') write('');
      return callback.apply(this, args);
    };
  };
  const wrapOptions = options => {
    if (!options || typeof options !== 'object') return options;
    const copy = Object.assign({}, options);
    for (const name of ['callback', 'expired-callback', 'error-callback', 'timeout-callback']) {
      if (typeof options[name] === 'function') copy[name] = wrapCallback(name, options[name]);
    }
    return copy;
  };
  const install = () => {
    try {
      const ts = window.turnstile;
      if (!ts || typeof ts.getResponse !== 'function') return;
      for (const method of ['reset', 'remove']) {
        if (typeof ts[method] !== 'function' || ts[method].__ckTsWrapped) continue;
        const original = ts[method];
        const wrapped = function(id, ...args) {
          write('');
          root().setAttribute('data-ck-ts-generation', String(Number(root().getAttribute('data-ck-ts-generation') || 0) + 1));
          if (method === 'remove') state.ids = state.ids.filter(item => item !== id);
          return original.call(this, id, ...args);
        };
        wrapped.__ckTsWrapped = true;
        ts[method] = wrapped;
      }
      if (typeof ts.render === 'function' && !ts.render.__ckTsWrapped) {
        const original = ts.render;
        const wrapped = function(container, options) {
          const id = original.call(this, container, wrapOptions(options));
          remember(id);
          return id;
        };
        wrapped.__ckTsWrapped = true;
        wrapped.__ckTsOriginal = original;
        try { ts.render = wrapped; } catch (_) {}
      }
    } catch (_) {}
  };
  const read = () => {
    try {
      const ts = window.turnstile;
      if (!ts || typeof ts.getResponse !== 'function') return;
      let token = '';
      for (const id of state.ids) {
        try { token = ts.getResponse(id) || ''; } catch (_) { token = ''; }
        if (typeof token === 'string' && token.trim()) break;
      }
      // 桥接安装前已 render 的 callback-only widget 也从唯一 live iframe-id
      // 获取指定 widget 响应；绝不调用可能指向遗留 widget 的 getResponse() 默认项。
      if (!state.ids.length) {
        const live = Array.from(document.querySelectorAll('iframe[src]')).filter(frame => {
          try {
            const url = new URL(frame.src, document.baseURI);
            return frame.isConnected && /^cf-chl-widget-/.test(frame.id || '')
              && url.protocol === 'https:' && url.hostname === 'challenges.cloudflare.com'
              && (!url.port || url.port === '443') && !url.username && !url.password;
          } catch (_) { return false; }
        });
        if (live.length === 1) {
          const id = live[0].id.replace(/^cf-chl-widget-/, '');
          remember(id);
          try { token = ts.getResponse(id) || ''; } catch (_) { token = ''; }
        }
      }
      write(token);
    } catch (_) {}
  };
  const tick = () => { install(); read(); };
  tick();
  state.timer = setInterval(tick, 300);
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
    const visible = (el, point = null) => {
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
        const x = r.x + (point ? point.dx : r.width / 2), y = r.y + (point ? point.dy : r.height / 2);
        let hit = document.elementFromPoint(x, y);
        for (let depth = 0; hit && hit.shadowRoot && depth < 16; depth++) {
            const inner = hit.shadowRoot.elementFromPoint(x, y);
            if (!inner || inner === hit) break;
            hit = inner;
        }
        const root = el.getRootNode();
        if (root.host && hit === root.host && typeof root.elementFromPoint === 'function') {
            const localHit = root.elementFromPoint(x, y);
            if (localHit) hit = localHit;
        }
        const unobscured = hit && (hit === el || el.contains(hit)
            || (el.getRootNode().host && hit === el.getRootNode().host));
        return r.width >= 2 && r.height >= 2 && x >= 0 && y >= 0
            && x < window.innerWidth && y < window.innerHeight && Boolean(unobscured);
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
    const rejected = trustedFrame && nodes.some(el => visible(el) && (
        el.matches('[data-state="rejected"], #challenge-failed, #failure-text')
        && /verification failed|access denied|you have been blocked|验证失败|访问被拒绝/i.test(el.textContent || '')));
    const reason = rejected ? 'rejected' : processing ? 'processing' : ready ? 'ready' : boxes.length
        ? 'checkbox_unusable' : 'target_not_found';
    return {present: trustedFrame || scopes.length > 0, processing, actionable: ready,
        rejected, fallback_allowed: false, reason};
}"""
)

_VISIBLE_ELEMENT_JS = """el => {""" + _DOM_HELPERS_JS + """return visible(el); }"""
_ACTIONABLE_ELEMENT_JS = """el => {""" + _DOM_HELPERS_JS + """return actionable(el); }"""
_OWNER_HIT_JS = """(el, point) => {""" + _DOM_HELPERS_JS + """return visible(el, point); }"""
_ELEMENT_ID_JS = """el => {
    const doc = el.ownerDocument;
    if (!doc.__ckCheckboxIds) doc.__ckCheckboxIds = {id: crypto.randomUUID(), map: new WeakMap(), next: 0};
    const state = doc.__ckCheckboxIds;
    if (!state.map.has(el)) state.map.set(el, ++state.next);
    return state.id + ':' + state.map.get(el);
}"""
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
            identity = await _bounded(element.evaluate(_ELEMENT_ID_JS), _OPERATION_TIMEOUT_SECONDS)
            if not isinstance(identity, str) or not identity:
                return None
            setattr(scope, '_ck_cf_checkbox_identity', identity)
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
            if not await _bounded(handle.evaluate(_OWNER_HIT_JS,
                    {'dx': x - owner['x'], 'dy': y - owner['y']}), _OPERATION_TIMEOUT_SECONDS):
                return False
        finally:
            await _dispose(handle)
        frame = frame.parent_frame
    return False


async def _chromium_frame_probe(frame: Any, page: Any) -> dict[str, Any] | None:
    """用 Chromium 只读 DOM 接口定位 closed shadow 内的真实 checkbox。

    不修改 attachShadow 或验证组件。空/未加载的 frame 不再靠 owner 偏移盲点；
    Firefox 没有 CDP 时返回 None，保留其既有查询路径。
    """
    context = getattr(page, "context", None)
    browser = getattr(context, "browser", None)
    browser_type = getattr(browser, "browser_type", None)
    if getattr(browser_type, "name", "") != "chromium":
        return None
    if not _trusted_frame(frame):
        return _probe_result("untrusted_frame")
    session = None
    owner = None
    try:
        session = await _bounded(context.new_cdp_session(frame), _OPERATION_TIMEOUT_SECONDS)
        tree = await _bounded(session.send("DOM.getDocument", {"depth": -1, "pierce": True}),
                              _OPERATION_TIMEOUT_SECONDS)
        pending = [tree.get("root", {})]
        candidates = []
        visited = 0
        while pending and visited < 6000:
            node = pending.pop()
            visited += 1
            attributes = node.get("attributes", [])
            attrs = dict(zip(attributes[::2], attributes[1::2]))
            if ((node.get("nodeName") == "INPUT" and attrs.get("type") == "checkbox")
                    or attrs.get("role") == "checkbox"):
                candidates.append((node['nodeId'], node.get('backendNodeId', node['nodeId'])))
            pending.extend(node.get("children", []))
            pending.extend(node.get("shadowRoots", []))
        if pending:
            return _probe_result("probe_failed", present=True)
        result = _probe_result("target_not_found", present=True)
        for node_id, backend_id in candidates[:8]:
            resolved = await _bounded(session.send("DOM.resolveNode", {"nodeId": node_id}),
                                      _OPERATION_TIMEOUT_SECONDS)
            object_id = resolved.get("object", {}).get("objectId")
            if not object_id:
                continue
            try:
                inspected = await _bounded(session.send("Runtime.callFunctionOn", {
                    "objectId": object_id,
                    "functionDeclaration": "function() {" + _DOM_HELPERS_JS + """
                        // document 遍历不能穿透 closed shadow；从真实 checkbox 的 root
                        // 开始只读遍历，识别可见 verifying/progress/busy 再决定可点击性。
                        const trusted = trustedURL(window.location.href);
                        const processing = trusted && Boolean(this.checked || this.indeterminate
                            || ['true', 'mixed'].includes(this.getAttribute('aria-checked'))
                            || busy(elements(document)) || busy(elements(this.getRootNode())));
                        let target = this;
                        const label = this.closest('label');
                        const style = window.getComputedStyle(this);
                        // CF 的真实 input 是 opacity:0 覆盖层，方框由关联 label 的
                        // span 绘制；只接受这个已核实关系，不点击任意隐藏 input。
                        if (!visible(this) && label && visible(label) && Number(style.opacity) === 0
                            && style.display !== 'none' && style.visibility === 'visible'
                            && style.pointerEvents !== 'none') {
                            target = Array.from(label.children).find(el => {
                                if (el === this || !visible(el)) return false;
                                const r = el.getBoundingClientRect();
                                return r.width >= 10 && r.width <= 40 && Math.abs(r.width - r.height) <= 2;
                            }) || label;
                        }
                        const r = target.getBoundingClientRect();
                        return {actionable: trustedURL(window.location.href) && !processing && !this.disabled && !this.matches(':disabled')
                                && this.getAttribute('aria-disabled') !== 'true' && actionable(target),
                            processing, x: r.x, y: r.y, width: r.width, height: r.height};
                    }""",
                    "returnByValue": True,
                }), _OPERATION_TIMEOUT_SECONDS)
                state = inspected.get("result", {}).get("value", {})
            finally:
                await _bounded(session.send("Runtime.releaseObject", {"objectId": object_id}),
                               _OPERATION_TIMEOUT_SECONDS)
            if state.get("processing"):
                return _probe_result("processing", present=True, processing=True)
            if not state.get("actionable"):
                result = _probe_result("checkbox_unusable", present=True)
                continue
            owner = await _bounded(frame.frame_element(), _OPERATION_TIMEOUT_SECONDS)
            owner_box = await _bounded(owner.bounding_box(), _OPERATION_TIMEOUT_SECONDS)
            if not isinstance(owner_box, dict):
                return _probe_result("frame_owner_hidden", present=True)
            box = _box(page, {"x": owner_box["x"] + state["x"],
                              "y": owner_box["y"] + state["y"],
                              "width": state["width"], "height": state["height"]}, checkbox=True)
            if box and await _owners_visible(frame, box) and _trusted_frame(frame):
                return _probe_result("ready", present=True, target=box, target_kind="checkbox",
                                     target_id=f"frame:{id(frame)}", _frame=frame, _url=frame.url,
                                     _cdp=True, _backend_id=backend_id)
            result = _probe_result("checkbox_unusable", present=True)
        return result
    finally:
        await _dispose(owner)
        if session is not None:
            try:
                await _bounded(session.detach(), _OPERATION_TIMEOUT_SECONDS)
            except Exception:
                pass


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
    """读取站点正常签发的令牌；兼容 callback-only widget 与严格 CSP。

    优先用 script tag 在主世界安装桥接，兼容 Camoufox 的隔离世界。
    严格 CSP 可能禁止内联 script tag；此时回退到浏览器驱动的 evaluate，
    不关闭 CSP、不改写验证结果，仍只调用真实 Turnstile API。
    所有操作继承同一截止点；两条路径都失败时继续读取标准响应字段。
    """
    try:
        await _operation(page.add_script_tag(content=_BRIDGE_JS), "bridge", diagnostics)
        _diagnose(diagnostics, bridge_installed=True, bridge_method="script_tag")
        return
    except Exception:
        pass
    try:
        await _operation(page.evaluate(_BRIDGE_JS), "bridge", diagnostics)
        _diagnose(diagnostics, bridge_installed=True, bridge_method="evaluate")
    except Exception:
        _diagnose(diagnostics, bridge_installed=False, bridge_reason="install_failed")


async def read_token(page: Any, *, diagnostics: dict[str, Any] | None = None,
                     widget_target: str | None = None) -> str:
    """读取 Cloudflare 正常签发的 Turnstile 令牌（不伪造、不篡改）。为空表示尚未签发。"""
    try:
        operation = page.evaluate(_READ_TOKEN_JS, widget_target) if widget_target else page.evaluate(_READ_TOKEN_JS)
        value = await _operation(operation, 'token_wait', diagnostics)
        token = value.strip() if isinstance(value, str) else ""
        if token:
            _diagnose(diagnostics, token_observed=True)
        return token
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
        blocked = False
        for frame in _frames(page):
            try:
                box = await _bounded(_frame_checkbox(frame, page), _FRAME_TIMEOUT_SECONDS)
                if box:
                    return _probe_result("ready", present=True, target=box, target_kind="checkbox",
                                         target_id=f"frame:{id(frame)}", _frame=frame, _url=frame.url,
                                         _identity=getattr(frame, '_ck_cf_checkbox_identity', None))
                chromium = await _bounded(_chromium_frame_probe(frame, page), _FRAME_TIMEOUT_SECONDS)
                if chromium is not None:
                    if chromium.get("target") is not None:
                        return chromium
                    reject(chromium["reason"], processing=bool(chromium["processing"]))
                    blocked = True  # CDP 已读到空/不可用控件，不得改点 owner 猜测位置。
                    continue
                state = await _scope_state(frame, trusted=True)
                reject(state.get("reason", "checkbox_unusable"), processing=bool(state["processing"]))
                blocked = blocked or state["processing"] or state.get("reason") == "checkbox_unusable"
                # 可见 iframe owner 不是 checkbox 证据；Firefox/Camoufox 不猜偏移点。
                # Chromium closed shadow 仅使用上面的只读 CDP 真 checkbox。
                if state.get("rejected") is True:
                    return _probe_result("rejected", present=True, rejected=True)
            except TimeoutError:
                reject("probe_timeout")
                blocked = True  # 未读完的 frame 不能从父容器绕过安全检查。
            except Exception:
                reject("probe_failed")
                blocked = True
        try:
            box = await _bounded(_checkbox_in(page, page, trusted=False), _FRAME_TIMEOUT_SECONDS)
            if box:
                return _probe_result("ready", present=True, target=box, target_kind="checkbox", target_id="main",
                                     _identity=getattr(page, '_ck_cf_checkbox_identity', None))
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
    _diagnose(
        diagnostics,
        probe_reason=result["reason"],
        processing=result["processing"],
        present=result["present"],
    )
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
        if result.get("_cdp"):
            current = await _chromium_frame_probe(frame, page)
            return (current is not None and not current["processing"]
                    and current.get("target") == result["target"]
                    and current.get('_backend_id') == result.get('_backend_id') and _trusted_frame(frame)
                    and frame.url == result.get("_url"))
        state = await _scope_state(frame, trusted=True)
        fallback = result["target_kind"] == "frame_owner"
        allowed = state.get("fallback_allowed") if fallback else state.get("actionable")
        if not allowed or state["processing"]:
            return False
        # 只重验刚才选中的 frame，不再遍历其他 frame 或完整 probe；移动期间的位置
        # 变化必须重新定位，不能拿旧的偏移点点击另一个控件。
        current = await (_frame_fallback(frame, page) if fallback else _frame_checkbox(frame, page))
        return (current == result["target"] and _trusted_frame(frame) and frame.url == result.get("_url")
                and getattr(frame, '_ck_cf_checkbox_identity', None) == result.get('_identity'))
    state = await _scope_state(page, trusted=False)
    if not state.get("actionable") or state["processing"]:
        return False
    current = await _checkbox_in(page, page, trusted=False)
    return current == result['target'] and getattr(page, '_ck_cf_checkbox_identity', None) == result.get('_identity')


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
        if box is not None:
            explicit = _box(page, box)
            if explicit is None or explicit.get('kind') != 'checkbox':
                _diagnose(data, reason='unverified_target')
                return False
            if result is None:
                result = await probe(page, diagnostics=data)
            if result.get('target_kind') != 'checkbox' or result.get('target') != explicit:
                _diagnose(data, reason='target_changed')
                return False
        elif result is None:
            result = await probe(page, diagnostics=data)
        measured = _box(page, box if box is not None else (result or {}).get("target"))
        if measured is None or (result is not None and result.get("processing")):
            _diagnose(data, reason=(result or {}).get("reason", "invalid_target"))
            return False
        for_check = (result or {}).get('_token_reader')
        if for_check is not None and await _operation(for_check(), 'token_before_input', data):
            _diagnose(data, reason='token_issued')
            return False
        expected_generation = (result or {}).get('_generation')
        if expected_generation is not None and await generation(page) != expected_generation:
            _diagnose(data, reason='target_changed')
            return False
        kind = (result or {}).get("target_kind") or ("checkbox" if measured.get("kind") else "frame_owner")
        _diagnose(data, stage="located", target_kind=kind, reason="ready")
        _log(log, f"已定位 Cloudflare 点击目标（{kind}，主视口坐标）")
        if result is not None and not await _operation(_target_still_ready(page, result), "validate", data):
            _diagnose(data, reason="target_changed")
            return False
        x = measured["x"] + (measured["width"] / 2 if measured.get("kind") == "checkbox" else _CHECKBOX_X_OFFSET)
        y = measured["y"] + measured["height"] / 2
        # 只有 CF 验证目标允许有限多步移动；普通点击在浏览器层已直接落点。
        await _operation(page.mouse.move(x, y, steps=cf_move_steps(page)), "move", data)
        _diagnose(data, stage="moved", moved=True)
        _log(log, "Cloudflare 鼠标移动已完成；尚未执行点击")
        if for_check is not None and await _operation(for_check(), 'token_after_move', data):
            _diagnose(data, reason='token_issued')
            return False
        if expected_generation is not None and await generation(page) != expected_generation:
            _diagnose(data, reason='target_changed')
            return False
        if result is not None and not await _operation(_target_still_ready(page, result), "validate", data):
            _diagnose(data, reason="target_changed")
            return False
        # 截止已过时不能连 click 协程都开始，更不能把已定位/已移动记成已点击。
        if _remaining() <= 0:
            _diagnose(data, timeout_stage="click", reason="timeout")
            return False
        _diagnose(data, click_started=True, input_generation=expected_generation)
        await _operation(page.mouse.click(x, y), "click", data)
        _diagnose(data, stage="input_dispatched", clicked=True, input_dispatched=True,
                  status="click_unconfirmed", reason="input_dispatched", timeout_stage=None)
        _log(log, "Cloudflare 真实鼠标点击已完成（仅输入发出，尚无接收反馈）")
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
    # 旧字符串 API 的 page-completed 回调只允许提前返回空串，不能生成
    # widget-token SolveResult.ok=True。生产结构化接口完全不消费此布尔回调。
    if completed is not None:
        legacy_stop = _deadline(max(0, timeout_ms) / 1000, deadline)
        legacy_context = _DEADLINE.set(legacy_stop)
        try:
            if await _operation(completed(), 'page_state', diagnostics):
                _diagnose(diagnostics, stage='complete', reason='page_cleared', status='passed')
                return ''
        except TimeoutError:
            _diagnose(diagnostics, reason='timeout', timeout_stage='page_state')
            return ''
        finally:
            _DEADLINE.reset(legacy_context)
        deadline = legacy_stop
    result = await solve_result(
        page, mode='widget_token', timeout_ms=timeout_ms, poll_interval_ms=poll_interval_ms,
        log=log, deadline=deadline, diagnostics=diagnostics, _legacy_page_completed=completed,
    )
    if diagnostics is not None:
        diagnostics.update(result.data.get('diagnostics', {}))
        diagnostics.update(result.data)
    return result.value if result.ok and result.value != 'passed' else ''


# 每个文档拥有独立 opaque id；同 URL reload 及原地重新 render 都产生新 generation。
# WeakMap 不把节点标识写入页面 DOM，也不记录 URL、sitekey 或令牌。
_GENERATION_JS = """() => {
    const root = document;
    if (!root.__ckCFGeneration) root.__ckCFGeneration = {
        id: crypto.randomUUID(), nodes: new WeakMap(), next: 0
    };
    const state = root.__ckCFGeneration;
    const nodes = Array.from(document.querySelectorAll(
        '.cf-turnstile, [id^="cf-chl-widget"], #ck-ts-host, '
        + 'iframe[src*="challenges.cloudflare.com"], input[name^="cf-turnstile-response"]'
    ));
    return state.id + ':' + (document.documentElement.getAttribute('data-ck-ts-generation') || '0') + ':' + nodes.map(node => {
        if (!state.nodes.has(node)) state.nodes.set(node, ++state.next);
        return state.nodes.get(node) + ':' + (node.getAttribute('data-generation') || '')
            + ':' + (node.getAttribute('data-widget-id') || '');
    }).join(',');
}"""


async def generation(page: Any) -> str:
    try:
        value = await _operation(page.evaluate(_GENERATION_JS), "generation", None)
        if isinstance(value, str) and ':' in value and '://' not in value:
            return value
    except Exception:
        # 截止已到而没读到新身份：按超时上报，不能用兼容回退值冒充「文档已变化」。
        if _remaining() <= 0:
            raise TimeoutError from None
    # 简单插件/FakePage 无文档 evaluate 时的兼容，不用于真实浏览器认证证据。
    from hashlib import sha256
    value = str((getattr(page, 'url', ''), getattr(page, '_cf_document_generation', 0),
                 tuple((id(frame), getattr(frame, 'url', '')) for frame in _frames(page))))
    return sha256(value.encode()).hexdigest()[:24]


def _document_hint(page: Any) -> tuple[Any, ...]:
    return (id(page), getattr(page, '_cf_document_generation', 0),
            getattr(page, '_ck_cf_document_epoch', 0))


def _observation_hint(page: Any) -> tuple[Any, ...]:
    return (getattr(page, 'url', ''), _document_hint(page),
            getattr(page, '_ck_cf_navigation_epoch', 0),
            tuple((id(frame), getattr(frame, 'url', '')) for frame in _frames(page)))


def _document_key(page: Any, widget_generation: str) -> str:
    if ':' in widget_generation:
        return widget_generation.split(':', 1)[0]
    # 不支持 generation JS 的旧插件/FakePage 用明确 document hint，绝不以 frame 列表
    # 当文档身份；iframe/widget 替换不能创建新锁或新增时间预算。
    from hashlib import sha256
    return sha256(repr(_document_hint(page)).encode()).hexdigest()[:24]


class _ChallengeSession:
    def __init__(self, key: str, deadline: float, *, lock: Any = None):
        self.generation = key
        self.document_key = ''
        self.document_hint: Any = None
        self.deadline = deadline
        self.lock = lock if lock is not None else asyncio.Lock()
        self.clicks = _ClickSession()
        self.data: dict[str, Any] = {}
        _init_diagnostics(self.data)
        self.data.update(status="waiting", input_dispatched=False, widget_acknowledged=False)
        self.results: dict[str, Any] = {}
        self.announced: set[str] = set()
        self.delivered_token_digests: set[str] = set()
        self._acknowledged_observations: dict[str, bool] = {}


def _safe_result(session: _ChallengeSession, mode: str, status: str, value: str = ""):
    from solvers.registry import SolveResult

    raw = session.data
    if status == 'passed' and mode == 'widget_token' and not value:
        status = 'observation_error'
    pending = bool(raw.get("click_started") or raw.get("processing")
                   or raw.get("widget_acknowledged"))
    preserve = status not in {"passed", "rejected"} and pending
    diagnostics = {key: raw[key] for key in (
        "stage", "reason", "probe_reason", "page_state", "page_state_reason", "present",
        "target_kind", "clicked", "moved", "click_started", "processing", "timeout_stage", "attempts",
    ) if key in raw}
    stage = str(raw.get("stage") or "observation")
    if (status not in {"passed", "rejected", "token_already_delivered"} and raw.get("click_started")
            and raw.get("status") == "verifying" and not raw.get("widget_acknowledged")):
        # 处理中的是另一代 widget：本次输入仍未确认，后续轮询阶段不能覆盖它。
        stage = "click_unconfirmed"
    data = {
        "status": status, "stage": stage, "mode": mode,
        'generation': session.generation, 'document_generation': session.document_key,
        'input_generation': raw.get('input_generation'),
        'observation_generation': raw.get('observation_generation') or session.generation,
        "input_dispatched": bool(raw.get("input_dispatched")),
        "widget_acknowledged": bool(raw.get("widget_acknowledged")),
        "observation_status": str(raw.get("status") or "waiting"),
        "preserve_page": preserve, "retry_allowed": status not in {"passed", "rejected"} and not preserve,
        "challenge_observed": bool(raw.get("challenge_observed") or raw.get("present")),
        "diagnostics": diagnostics,
    }
    if status in {'timeout', 'rejected', 'observation_error', 'cancelled'}:
        diagnostics['reason'] = status
        if status == 'timeout':
            diagnostics['timeout_stage'] = raw.get('timeout_stage') or raw.get('stage') or 'observation'
    if status == "passed":
        return SolveResult.solved(value or "passed", attempts=session.clicks.attempts, data=data)
    if status == 'token_already_delivered':
        # 单用令牌已交给首个调用方：widget 状态仍为已通过，但不重复交付、不允许
        # 外层重载/重开预算；摘要仅留在私有 Session 内存，不进 data/log。
        data.update(status='passed', observation_status='passed', preserve_page=True, retry_allowed=False)
        diagnostics['reason'] = status
        return SolveResult.failure(status, 'Turnstile 令牌已交付给先前调用方',
                                   attempts=session.clicks.attempts, data=data)
    return SolveResult.failure(status, "Cloudflare 验证未完成；保留当前挑战上下文" if preserve
                               else "Cloudflare 验证未完成", attempts=session.clicks.attempts, data=data)


async def solve_result(page: Any, *, mode: str = "widget_token", timeout_ms: int = 45000,
                       deadline: float | None = None, log: Any = None,
                       diagnostics: dict[str, Any] | None = None,
                       poll_interval_ms: int = 250, token_reader: Any = None,
                       completed: Any = None, widget_target: str | None = None,
                       _legacy_page_completed: Any = None):
    """结构化 CF 求解。同一 document 共用锁、输入记录及首次 absolute deadline。

    widget generation 变化只更新目标绑定，不为 pending/input-unconfirmed 创建新预算。
    status 为最终状态；observation_status 保留 ready/verifying/click_unconfirmed 等阶段。
    cancelled 仍传播 CancelledError，diagnostics 保留取消与输入不确定性。
    """
    if mode not in {"page_access", "widget_token"}:
        raise ValueError("unsupported Cloudflare mode")
    seconds = max(0.0, float(timeout_ms) / 1000)
    stop = _deadline(seconds if math.isfinite(seconds) else 0, deadline)
    outer = _DEADLINE.set(stop)
    cache_key = mode + ':' + str(widget_target or '')
    session = None
    acquired = False
    try:
        hint = _observation_hint(page)
        document_hint = _document_hint(page)
        session = getattr(page, '_ck_cf_session', None)
        if not isinstance(session, _ChallengeSession):
            # 首次 await 前发布协调器；并发调用不能各自创建锁或独立截止。
            session = _ChallengeSession('unobserved', stop)
            session.document_hint = document_hint
            session.page_hint = hint
            setattr(page, '_ck_cf_session', session)
        if callable(getattr(page, 'on', None)) and not getattr(page, '_ck_cf_navigation_listener', False):
            def document_changed(frame=None, *_args):
                page._ck_cf_navigation_epoch = getattr(page, '_ck_cf_navigation_epoch', 0) + 1
                if frame is getattr(page, 'main_frame', None):
                    page._ck_cf_document_epoch = getattr(page, '_ck_cf_document_epoch', 0) + 1
            for event in ('framenavigated', 'frameattached', 'framedetached'):
                page.on(event, document_changed)
            page._ck_cf_navigation_listener = True
        if session.document_hint == document_hint:
            _DEADLINE.set(min(stop, session.deadline))
            if _remaining() <= 0:
                confirmed = session.results.get(cache_key)
                if (mode == 'page_access' and confirmed is not None and confirmed.ok
                        and getattr(session, 'page_hint', None) == hint
                        and confirmed.data.get('generation') == session.generation):
                    return confirmed
                if (mode == 'widget_token' and confirmed is not None and confirmed.ok
                        and session.delivered_token_digests
                        and getattr(session, 'page_hint', None) == hint):
                    # 预算已尽但同一 widget 的单用令牌已交付：明确告知，不伪装超时触发重载。
                    return _safe_result(session, mode, 'token_already_delivered')
                return _safe_result(session, mode, 'timeout')
        await _bounded(session.lock.acquire(), _remaining())
        acquired = True
        # 等锁期间另一个调用可能已确认新文档；始终采用同一 page 协调锁。
        session = getattr(page, '_ck_cf_session', session)
        if session.document_hint == document_hint:
            _DEADLINE.set(min(stop, session.deadline))
        key = await generation(page)
        document_key = _document_key(page, key)
        if session.document_key and session.document_key != document_key:
            session = _ChallengeSession(key, stop, lock=session.lock)
            setattr(page, '_ck_cf_session', session)
        session.document_key = document_key
        session.document_hint = document_hint
        session.page_hint = hint
        # widget 替换只更新观察身份，绝不更换 document 锁、deadline 或已输入记录。
        if session.generation != key:
            session.results.clear()
            if not session.data.get('click_started') and not session.data.get('widget_acknowledged'):
                session.generation = key
        _DEADLINE.set(min(session.deadline, stop))
        if _remaining() <= 0:
            return _safe_result(session, mode, 'timeout')
        data = session.data
        data['observation_generation'] = key
        bridge_installed = False
        legacy_first_observation = True
        announced = session.announced
        while _remaining() > 0:
            if mode == "page_access":
                from .bypass import _challenge_state
                before = await generation(page)
                state, result = await _bounded(_challenge_state(page, diagnostics=data), _remaining())
                after = await generation(page)
                data['observation_generation'] = after
                if before != after:
                    await _pause(page, min(500, max(100, poll_interval_ms)), data, stage='document_settling')
                    continue
                if state == "clear":
                    session.generation = after
                    session.document_key = _document_key(page, after)
                    session.document_hint = _document_hint(page)
                    session.page_hint = _observation_hint(page)
                    data.update(status="passed", stage="complete", reason="page_cleared")
                    if data.get('challenge_observed'):
                        _log(log, 'Cloudflare 挑战已通过（页面放行）' if data.get('click_started')
                             else 'Cloudflare 挑战已通过（自动放行）')
                    outcome = _safe_result(session, mode, "passed")
                    session.results[cache_key] = outcome
                    return outcome
                if state == "rejected":
                    data.update(status="rejected", stage="page_state", reason="trusted_rejection")
                    outcome = _safe_result(session, mode, "rejected")
                    session.results[cache_key] = outcome
                    return outcome
            else:
                # 仅旧字符串 API 通过私有接缝提前空返回；结构化结果仍为未完成，
                # 公开 completed/page_access 回调从不变成 widget-token 成功证据。
                if (not legacy_first_observation and _legacy_page_completed is not None
                        and await _operation(_legacy_page_completed(), 'page_state', data)):
                    data.update(status='waiting', stage='complete', reason='page_cleared')
                    return _safe_result(session, mode, 'waiting')
                legacy_first_observation = False
                if not bridge_installed and token_reader is None:
                    await install_token_bridge(page, diagnostics=data)
                    bridge_installed = True
                before = await generation(page)
                try:
                    token = await _operation(token_reader() if token_reader else read_token(
                        page, diagnostics=data, widget_target=widget_target), 'token_wait', data)
                except TimeoutError:
                    if _remaining() <= 0:
                        raise
                    data.update(status='observation_error')
                    await _pause(page, min(500, max(100, poll_interval_ms)), data, stage='observation')
                    continue
                after = await generation(page)
                data['observation_generation'] = after
                if before == after and not data.get('click_started') and not data.get('widget_acknowledged'):
                    # 首次挂载/自动 render 可更新身份，但始终保留原 deadline。
                    session.generation = before
                if _document_key(page, after) != session.document_key:
                    data.update(status='observation_error', reason='document_changed')
                    return _safe_result(session, mode, 'observation_error')
                if token and before == after:
                    from hashlib import sha256
                    token_digest = sha256(str(token).encode()).hexdigest()
                    if token_digest in session.delivered_token_digests:
                        # 单用令牌重复交付：已确认由前一个调用方交付。
                        return _safe_result(session, mode, 'token_already_delivered')
                    session.delivered_token_digests.add(token_digest)
                    session.generation = after
                    session.page_hint = _observation_hint(page)
                    data.update(status="passed", stage="complete", reason="token_issued")
                    _log(log, "Turnstile 验证已完成（当前 widget 令牌已签发）")
                    outcome = _safe_result(session, mode, "passed", str(token))
                    session.results[cache_key] = outcome
                    return outcome
                observed = {key: data[key] for key in ("processing", "present") if key in data}
                result = await _bounded(probe(page, diagnostics=data), _remaining())
                if result.get("reason") == "probe_timeout" and _remaining() <= 0:
                    # 被截止打断的探测不是观察结果：保留上一次完整观察，按超时收尾。
                    data.update(observed)
                    raise TimeoutError
            if result.get("rejected"):
                data.update(status="rejected", stage="probe", reason="trusted_rejection")
                return _safe_result(session, mode, "rejected")
            if result.get("processing"):
                # 仅当处理中的观察 generation 与已发出输入的 generation 相同时，
                # 才算作 widget 确认：widget 替换或不同时保留 click_unconfirmed stage。
                same_generation = (data.get('input_generation') == data.get('observation_generation'))
                data.update(status="verifying", widget_acknowledged=same_generation)
                if data.get('click_started') and not same_generation:
                    data['stage'] = 'click_unconfirmed'
            elif data.get("click_started"):
                data.update(status="click_unconfirmed")
            elif result.get("target") is not None:
                data.update(status="ready")
            elif result.get("reason") in {"probe_failed", "probe_timeout"}:
                data.update(status="observation_error")
            else:
                data.update(status="not_ready")
            # 一旦输入可能已发出而无明确反馈，不对替换 owner 进行补点。
            if not data.get("click_started") and not data.get("widget_acknowledged"):
                input_generation = await generation(page)
                if _document_key(page, input_generation) != session.document_key:
                    data.update(status='observation_error', reason='document_changed')
                    return _safe_result(session, mode, 'observation_error')
                # probe 期间新挂载的 widget 必须在同一 document 锁中、首次输入前
                # 原子绑定到目标 generation；deadline 和历史输入预算完全不变。
                session.generation = input_generation
                data['observation_generation'] = input_generation
                session.page_hint = _observation_hint(page)
                result['_generation'] = input_generation
                if mode == 'widget_token':
                    result['_token_reader'] = token_reader or (lambda: read_token(page, diagnostics=data, widget_target=widget_target))
                if await session.clicks.attempt(page, result, data, log):
                    continue
            status = data["status"]
            if status not in announced:
                _log(log, f"Cloudflare 状态：{status}；持续观察，可人工完成验证")
                announced.add(status)
            await _pause(page, min(500, max(100, poll_interval_ms)), data, stage="observation")
        return _safe_result(session, mode, "timeout")
    except TimeoutError:
        if session is None:
            session = _ChallengeSession("unobserved", stop)
        return _safe_result(session, mode, "timeout")
    except asyncio.CancelledError:
        if session is not None:
            session.data.update(status="cancelled", reason="cancelled")
        raise
    except Exception:
        if session is None:
            session = _ChallengeSession("unobserved", stop)
        session.data.update(status="observation_error", reason="observation_error")
        return _safe_result(session, mode, "observation_error")
    finally:
        if session is not None and diagnostics is not None:
            diagnostics.update(session.data)
            confirmed = session.results.get(cache_key)
            if session.data.get('status') == 'passed' and confirmed is not None and confirmed.ok:
                diagnostics.update(confirmed.data)
            else:
                diagnostics.update(_safe_result(session, mode, str(session.data.get('status') or 'waiting')).data)
        if acquired:
            session.lock.release()
        _DEADLINE.reset(outer)
