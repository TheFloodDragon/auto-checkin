#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloudflare Turnstile 交互式验证：读取令牌 + 真实鼠标点击复选框。

Sub2API 系站点（极速蹬 / 百倍等）的登录页嵌入 Cloudflare Turnstile widget。
托管挑战可自动签发；要求交互时才用真实鼠标事件点击 "Verify you are human"
复选框（Cloudflare 校验 isTrusted，JS click 无效）。

定位策略：
1. 优先通过可信 CF frame 找到真实复选框并取主 viewport bbox。CF 把复选框放在
   frame body 的 closed shadow 里：Firefox/Camoufox 经驱动世界只读的
   openOrClosedShadowRoot 进入，Chromium 经 CDP 只读 DOM 穿透；
2. 真实 checkbox 是盖在方框上的 opacity:0 覆盖层，点击同一 label 内可见方框
   （其次 label）的中心，并由命中检查证实落点就是该 checkbox；
3. 只使用 page.mouse 真实事件，所有查询和整体等待都有有限预算。

令牌按 widget-id 绑定：响应字段 id（cf-chl-widget-<id>_response）必须对应一个
当前存活的 widget iframe；iframe 挂在 closed shadow 内时由驱动层经 frame owner
读取其 id，不再因 document 查询不到 iframe 而永远读空。

本模块只与页面交互、不伪造/篡改令牌，也不处理任何账号凭据。
"""

from __future__ import annotations

import asyncio
import math
import inspect
import re
from contextvars import ContextVar
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

# 所有浏览器 RPC、单 frame 探测及整轮定位都有独立预算；不等待取消清理完成。
_OPERATION_TIMEOUT_SECONDS = 2.0
# 一个 frame 需要多次定位/可见性 RPC；Windows 上不能用亚秒预算误杀正常查询。
_FRAME_TIMEOUT_SECONDS = 3.0
_QUERY_TIMEOUT_SECONDS = 8.0
# 读令牌前经 frame owner 收集 live widget-id 的总预算（结果按 frame 缓存）。
_WIDGET_ID_TIMEOUT_SECONDS = 1.0
_WIDGET_ID_RE = re.compile(r"^cf-chl-widget-[A-Za-z0-9_-]{1,64}$")
_MAX_FRAMES = 16
# 同一 document 的点击预算：发出输入前的失败（复验不通过、移动失败）可有限重试；
# 已发出输入后只有观察到 widget 复位证据才补点，且补点次数单独封顶。
_MAX_PRE_INPUT_FAILURES = 4
_MAX_RESET_CLICKS = 2
_MAX_CLICK_ATTEMPTS = 1 + _MAX_PRE_INPUT_FAILURES + _MAX_RESET_CLICKS
# widget 复位后重新出现的可点击 checkbox 需稳定这么久才补点，避免 CF 切换视图时误点。
_RESET_SETTLE_SECONDS = 1.5
# CF frame 在场但没有可点 checkbox（托管挑战计算中/验证中）时降低 frame 内探测频率：
# 实测林夕登录页每 ~350ms 探测一次时令牌 22–28s 才签发，不探测时 12–16s。读令牌
# 只读主文档，仍按原轮询间隔进行。探测超时说明 frame 正忙，退避更久。
_BUSY_PROBE_GAP_SECONDS = 2.5
_STALLED_PROBE_GAP_SECONDS = 4.0
# 已确认送达的点击之后，同一 checkbox 原样可点、从未进入处理中这么久，视为输入未被接收。
_UNRECEIVED_INPUT_SECONDS = 12.0
# page_access：点击后 CF 挑战页常整页替换（放行跳转，或换发一张新挑战页）。同一次调用、
# 同一绝对截止点内最多跟随这么多次文档替换；新文档必须重新观察，checkbox 稳定
# _RESET_SETTLE_SECONDS 后才允许首点，处理中/未稳定绝不点击；点击总数仍受
# _MAX_CLICK_ATTEMPTS 约束（跨文档累计）。超过次数仍按 observation_error 收尾。
_MAX_DOCUMENT_REBINDS = 3
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
#
# 归属按 widget-id：字段 id/name 中 CF 生成的 widget-id 必须对应唯一一个当前存活的
# widget。新版 CF 把 iframe 挂在 widget 容器的 closed shadow 里，document 查询
# 看不到它；驱动层经 frame owner 读到的 live id 通过 {live: [...]} 传入。参数仍兼容
# 旧的字符串 target。
_READ_TOKEN_JS = """(arg = null) => {
    const options = arg && typeof arg === 'object' ? arg : {target: arg};
    const target = options.target || null;
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
    const unique = items => Array.from(new Set(items));
    const frames = Array.from(document.querySelectorAll('iframe[src]')).filter(trusted);
    const lightIds = frames.map(frame => normalize(frame.id));
    // 只有 document 看不到的 live widget 才走「仅 id」绑定；可见 iframe 仍要求同容器。
    const hidden = unique((Array.isArray(options.live) ? options.live : []).map(normalize)
        .filter(id => id && !lightIds.includes(id)));
    const liveIds = unique(lightIds.concat(hidden));
    try {
        // 主世界桥接据此按 widget-id 读取响应；closed shadow 内的 widget 它自己找不到。
        const root = document.documentElement, hint = liveIds.join(' ');
        if (hint && root.getAttribute('data-ck-ts-live') !== hint) root.setAttribute('data-ck-ts-live', hint);
        else if (!hint && root.getAttribute('data-ck-ts-live')) root.removeAttribute('data-ck-ts-live');
    } catch (_) {}
    const fields = Array.from(document.querySelectorAll(
        'input[name^="cf-turnstile-response"], textarea[name^="cf-turnstile-response"]'
    )).filter(field => field.isConnected);
    // 通用 name 不是唯一 widget 目标，两个同名字段绝不取首个非空值。
    if (target && fields.filter(field => field.name === target || field.id === target).length > 1) return '';
    if (!target && frames.length + hidden.length !== 1) return '';
    const bound = [];
    for (const field of fields) {
        // 从父节点找容器：字段自身的 id 也以 cf-chl-widget 开头，不能把它当容器。
        const start = field.parentElement || field;
        const owner = typeof start.closest === 'function'
            ? start.closest('.cf-turnstile, [id^="cf-chl-widget"], #ck-ts-host') : null;
        const local = owner && owner.isConnected
            ? Array.from(owner.querySelectorAll('iframe[src]')).filter(trusted) : [];
        const owns = id => Boolean(id) && ((field.id && normalize(field.id) === id)
            || (field.name !== 'cf-turnstile-response' && normalize(field.name) === id));
        // 同容器不等于同 generation：重 render 可能保留旧 hidden field。
        // 必须以 CF 生成的字段 widget-id 对应当前 widget-id；仅 owner/通用 name
        // 或站点自定义 field-id 都不是签发归属证据，callback-only 请使用桥接。
        const candidates = unique(frames.filter(frame => owns(normalize(frame.id))
            && (!owner || local.includes(frame))).map(frame => normalize(frame.id))
            .concat(hidden.filter(owns)));
        if (candidates.length !== 1) continue;
        if (target && field.name !== target && field.id !== target
                && candidates[0] !== normalize(target)) continue;
        bound.push(field);
    }
    if (bound.length === 1) {
        const field = bound[0];
        const value = typeof field.value === 'string' ? field.value : String(field.textContent || '');
        if (value.trim()) return value.trim();
    } else if (bound.length > 1) return '';
    // callback-only 也必须绑定一个当前 live widget-id，不能拿遗留桥接属性放行。
    const bridged = document.documentElement.getAttribute('data-ck-ts-token');
    const bridgeTarget = normalize(document.documentElement.getAttribute('data-ck-ts-widget'));
    if (bridgeTarget && liveIds.includes(bridgeTarget) && (!target || normalize(target) === bridgeTarget)
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
  const write = (token, id) => {
    try {
      const value = typeof token === 'string' ? token.trim() : '';
      if (value && state.ids.length <= 1) {
        root().setAttribute(attr, value);
        root().setAttribute('data-ck-ts-widget', String(id ?? state.ids[0] ?? ''));
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
      // 桥接安装前已 render 的 callback-only widget 也从唯一 live widget-id
      // 获取指定 widget 响应；绝不调用可能指向遗留 widget 的 getResponse() 默认项。
      // iframe 在 closed shadow 内时 document 查不到它，依次改用驱动写入的 live
      // 提示（data-ck-ts-live）和 CF 生成的响应字段 id（cf-chl-widget-<id>_response）。
      if (!state.ids.length) {
        const clean = value => String(value || '').replace(/^cf-chl-widget-/, '').replace(/_response$/, '');
        const live = Array.from(document.querySelectorAll('iframe[src]')).filter(frame => {
          try {
            const url = new URL(frame.src, document.baseURI);
            return frame.isConnected && /^cf-chl-widget-/.test(frame.id || '')
              && url.protocol === 'https:' && url.hostname === 'challenges.cloudflare.com'
              && (!url.port || url.port === '443') && !url.username && !url.password;
          } catch (_) { return false; }
        }).map(frame => clean(frame.id));
        const hinted = String(root().getAttribute('data-ck-ts-live') || '').split(/\\s+/).map(clean).filter(Boolean);
        const fielded = Array.from(document.querySelectorAll(
          'input[name^="cf-turnstile-response"], textarea[name^="cf-turnstile-response"]'
        )).filter(field => field.isConnected && /^cf-chl-widget-.+_response$/.test(field.id || ''))
          .map(field => clean(field.id));
        const pool = Array.from(new Set(hinted.length ? hinted : live.length ? live : fielded));
        if (pool.length === 1) {
          if (live.includes(pool[0])) remember(pool[0]);
          try { token = ts.getResponse(pool[0]) || ''; } catch (_) { token = ''; }
          write(token, pool[0]);
          return;
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

# 只读遍历 shadow tree，不修改 attachShadow。Firefox/Camoufox 的驱动世界可读
# openOrClosedShadowRoot（CF frame 的 body 是 closed shadow）；页面脚本与 Chromium
# 拿不到该属性，自动退回开放 shadowRoot。主文档中的裸 checkbox、data-sitekey
# （hCaptcha/reCAPTCHA 也使用它）、iframe title 均不是 CF 身份凭证。
_DOM_HELPERS_JS = """
    const containerSelector = '.cf-turnstile, .turnstile-container, .turnstile-wrapper, '
        + '#cf-chl-widget, [id^="cf-chl-widget-"]';
    const checkboxSelector = 'input[type="checkbox"], [role="checkbox"]';
    const responseSelector = 'input[name^="cf-turnstile-response"], textarea[name^="cf-turnstile-response"]';
    const busySelector = '[aria-busy="true"], [role="progressbar"], [data-state="processing"], '
        + '[data-state="verifying"], [data-state="success"], #verifying, #success, #success-text';
    const parentOf = el => el.parentElement || (el.getRootNode && el.getRootNode().host) || null;
    const shadowOf = node => {
        try { return node.openOrClosedShadowRoot || node.shadowRoot || null; } catch (_) { return null; }
    };
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
            const shadow = node.nodeType === 1 ? shadowOf(node) : null;
            for (const children of [node.children, shadow && shadow.children]) {
                if (!children) continue;
                for (let i = children.length - 1; i >= 0 && pending.length < 6000; i--) {
                    pending.push(children[i]);
                }
            }
        }
        return result;
    };
    // checkbox 所属 label（含自身）；只沿同一棵树的 parentElement，不跨 shadow 边界。
    const labelOf = el => {
        for (let node = el, depth = 0; node && depth < 16; depth++, node = node.parentElement) {
            if (typeof node.matches === 'function' && node.matches('label')) return node;
        }
        return null;
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
        for (let depth = 0; hit && depth < 16; depth++) {
            const shadow = shadowOf(hit);
            if (!shadow || typeof shadow.elementFromPoint !== 'function') break;
            const inner = shadow.elementFromPoint(x, y);
            if (!inner || inner === hit) break;
            hit = inner;
        }
        const root = el.getRootNode();
        if (root.host && hit === root.host && typeof root.elementFromPoint === 'function') {
            const localHit = root.elementFromPoint(x, y);
            if (localHit) hit = localHit;
        }
        // CF 的真实 checkbox 是盖在方框上的透明覆盖层：命中同一 label 内的 checkbox
        // 本身就是点击要落到的控件，不算遮挡。其他任何覆盖物仍判为被遮挡。
        const label = labelOf(el);
        const through = Boolean(hit && hit !== el && label && typeof hit.matches === 'function'
            && hit.matches(checkboxSelector) && labelOf(hit) === label);
        const unobscured = hit && (hit === el || el.contains(hit) || through
            || (el.getRootNode().host && hit === el.getRootNode().host));
        return r.width >= 2 && r.height >= 2 && x >= 0 && y >= 0
            && x < window.innerWidth && y < window.innerHeight && Boolean(unobscured);
    };
    const busy = nodes => nodes.some(el => el.matches(busySelector) && visible(el));
    // 元素代表的真实 checkbox：自身，或其 label 内的 checkbox（label/方框 span 没有勾选态）。
    const controlOf = el => {
        if (el.matches(checkboxSelector)) return el;
        const label = labelOf(el);
        return label && typeof label.querySelector === 'function' ? label.querySelector(checkboxSelector) : null;
    };
    const controlUsable = el => {
        if (!el.isConnected || el.disabled || el.matches(':disabled') || el.checked || el.indeterminate
            || el.getAttribute('aria-disabled') === 'true' || el.getAttribute('aria-busy') === 'true') return false;
        const checked = el.getAttribute('aria-checked');
        if (checked && checked !== 'false') return false;
        return !(el.getAttribute('role') === 'checkbox' && checked !== 'false');
    };
    const actionable = el => {
        if (!visible(el) || el.disabled || el.matches(':disabled') || el.checked || el.indeterminate) return false;
        const checked = el.getAttribute('aria-checked');
        if (checked && checked !== 'false') return false;
        if (el.getAttribute('role') === 'checkbox' && checked !== 'false') return false;
        const control = controlOf(el);
        if (control && control !== el && !controlUsable(control)) return false;
        for (let node = el, depth = 0; node && depth < 128; depth++, node = parentOf(node)) {
            if (node.getAttribute('aria-disabled') === 'true' || node.getAttribute('aria-busy') === 'true') return false;
        }
        return true;
    };
    const squareSized = el => {
        const r = el.getBoundingClientRect();
        return r.width >= 10 && r.width <= 40 && Math.abs(r.width - r.height) <= 2;
    };
    // checkbox 的点击落点：同 label 内可见方框 > checkbox 自身 > label。只返回已证实
    // 可见、可用且命中检查落在该 checkbox 上的元素；方框仍在动画中（1px）时退回 label。
    const clickTarget = el => {
        if (!controlUsable(el)) return null;
        if (actionable(el)) return el;
        const label = labelOf(el), style = window.getComputedStyle(el);
        // 只为实际覆盖在 label 上的透明 input 取关联落点；display:none/不可命中 input
        // 不能借可见 label 绕过检查，也不能把同一 label 下的另一个 input 当成目标。
        if (!label || controlOf(label) !== el || Number(style.opacity) !== 0
            || style.display === 'none' || style.visibility !== 'visible' || style.pointerEvents === 'none') return null;
        const boxes = Array.from(label.children || [])
            .filter(child => child !== el && !child.matches(checkboxSelector) && squareSized(child));
        for (const candidate of boxes.concat([label])) {
            if (!actionable(candidate)) continue;
            const r = candidate.getBoundingClientRect(), root = el.getRootNode();
            const hitRoot = root.host && typeof root.elementFromPoint === 'function' ? root : document;
            if (hitRoot.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2) === el) return candidate;
        }
        return null;
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
        if (!el.matches(checkboxSelector)) continue;
        const target = clickTarget(el);
        if (!target) continue;
        if (trustedFrame) return target;
        for (let scope = parentOf(el), depth = 0; scope && depth < 128; depth++, scope = parentOf(scope)) {
            if (!scope.matches(containerSelector)) continue;
            const scoped = elements(scope);
            if (!busy(scoped) && !hasForeignFrame(scoped)) return target;
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
        && nodes.some(el => el.matches(checkboxSelector) && Boolean(clickTarget(el))));
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
_ELEMENT_ID_JS = """el => {""" + _DOM_HELPERS_JS + """
    // 返回 label/span 时也绑定真实 checkbox；相同落点下 input 被替换不能沿用旧身份。
    const control = controlOf(el) || el;
    const doc = control.ownerDocument;
    if (!doc.__ckCheckboxIds) doc.__ckCheckboxIds = {id: crypto.randomUUID(), map: new WeakMap(), next: 0};
    const state = doc.__ckCheckboxIds;
    if (!state.map.has(control)) state.map.set(control, ++state.next);
    return state.id + ':' + state.map.get(control);
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
                        // CF 的真实 input 是 opacity:0 覆盖层，方框由同 label 的 span 绘制；
                        // 与 Firefox 路径共用 clickTarget，只接受命中检查落在该 input 上的目标。
                        const target = trusted && !processing ? clickTarget(this) : null;
                        const r = (target || this).getBoundingClientRect();
                        return {actionable: Boolean(target) && this.getAttribute('aria-disabled') !== 'true',
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


async def _frame_widget_id(frame: Any) -> str:
    """读 widget iframe 自身的 id（cf-chl-widget-<id>）；按 frame 缓存，不重复 RPC。

    frame_element 能定位父页面 closed shadow 中的 owner，无需打破封装。只缓存成功读取
    的 id；临时 RPC 失败或尚未设置 id 时允许后续有界观察重读。
    """
    cached = getattr(frame, "_ck_cf_widget_id", None)
    if isinstance(cached, str):
        return cached
    handle = None
    value = ""
    try:
        handle = await _bounded(frame.frame_element(), _OPERATION_TIMEOUT_SECONDS)
        raw = await _bounded(handle.get_attribute("id"), _OPERATION_TIMEOUT_SECONDS)
        value = raw if isinstance(raw, str) and _WIDGET_ID_RE.match(raw) else ""
    except TimeoutError:
        raise
    except Exception:
        value = ""
    finally:
        await _dispose(handle)
    if value:
        try:
            setattr(frame, "_ck_cf_widget_id", value)
        except Exception:
            pass
    return value


async def _live_widget_ids(page: Any) -> list[str]:
    """主文档直属的可信 CF widget iframe id，含挂在 closed shadow 内、document 查不到的。"""
    main = getattr(page, "main_frame", None)
    ids: list[str] = []
    for frame in _frames(page):
        parent = getattr(frame, "parent_frame", None)
        if parent is None or (main is not None and parent is not main):
            continue  # 嵌套 frame 的令牌字段不在主文档里，不能当作主文档 widget。
        try:
            value = await _frame_widget_id(frame)
        except TimeoutError:
            break
        if (value and value not in ids and _trusted_frame(frame)
                and getattr(frame, "parent_frame", None) is parent):
            ids.append(value)
    return ids


async def read_token(page: Any, *, diagnostics: dict[str, Any] | None = None,
                     widget_target: str | None = None) -> str:
    """读取 Cloudflare 正常签发的 Turnstile 令牌（不伪造、不篡改）。为空表示尚未签发。"""
    try:
        try:
            live = await _bounded(_live_widget_ids(page), _WIDGET_ID_TIMEOUT_SECONDS)
        except TimeoutError:
            live = []  # 读不到 live id 时仍按 document 可见的 iframe 读取，不阻断令牌观察。
        if live:
            operation = page.evaluate(_READ_TOKEN_JS, {"target": widget_target, "live": live})
        elif widget_target:
            operation = page.evaluate(_READ_TOKEN_JS, widget_target)
        else:
            operation = page.evaluate(_READ_TOKEN_JS)
        value = await _operation(operation, 'token_wait', diagnostics)
        token = value.strip() if isinstance(value, str) else ""
        if token:
            _diagnose(diagnostics, token_observed=True)
        return token
    except Exception:
        _unknown_observation(page)
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
        if expected_generation is not None and not await _same_generation(page, expected_generation, data):
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
        if expected_generation is not None and not await _same_generation(page, expected_generation, data):
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
    """同一 document 的共享点击策略。

    - 首次输入：目标就绪即点；发出输入前就失败（复验不通过、移动失败）可有限重试；
    - 已发出输入：结果未知时不补点（处理中再点会重置 challenge），只在两种证据下
      有限补点：① 观察到 widget 进入处理中后重新出现可点击 checkbox 并稳定
      _RESET_SETTLE_SECONDS（CF 失败后自动复位，隐藏/遮挡不算此证据）；② 已确认送达的点击
      之后同一 checkbox 原样可点、从未进入处理中超过 _UNRECEIVED_INPUT_SECONDS（输入
      未被接收）。点击结果不确定（click_started 但 RPC 未返回）只认证据 ①。
    """

    def __init__(self) -> None:
        self.attempts = 0
        self.pre_input_failures = 0
        self.dispatched = 0
        self.reset_clicks = 0
        self.next_attempt = 0.0
        self.input_target: Any = None
        self.input_confirmed = False
        self.left_ready = False
        self.ready_since: float | None = None
        self.ready_target: Any = None
        # 文档替换后的新挑战页：首点前也要求可点击 checkbox 稳定 _RESET_SETTLE_SECONDS。
        self.settle_first = False

    @staticmethod
    def _identity(result: dict[str, Any]) -> Any:
        target = result.get("target")
        box = tuple(sorted(target.items())) if isinstance(target, dict) else None
        return (result.get("target_id"), result.get("_identity"), result.get("_backend_id"), box)

    def observe(self, result: dict[str, Any]) -> None:
        """记录一次完整观察；探测超时/失败不是状态证据，不改变复位判断。"""
        if not self.dispatched and not self.settle_first:
            return
        if result.get("reason") in {"probe_timeout", "probe_failed"}:
            # 观察未知不能计入可点击稳定时长；恢复后的完整观察必须重新计时。
            self.ready_since = self.ready_target = None
            return
        now = asyncio.get_running_loop().time()
        if result.get("target") is not None and not result.get("processing"):
            identity = self._identity(result)
            if self.ready_since is None or identity != self.ready_target:
                self.ready_since, self.ready_target = now, identity
            return
        # 隐藏、遮挡或暂时没有 checkbox 并不证明输入被接收，更不证明 widget 已复位。
        # 只有实际观察到处理中，之后重新出现可点击控件，才开放有限补点。
        if result.get("processing"):
            self.left_ready = True
        self.ready_since = self.ready_target = None

    def due(self, result: dict[str, Any]) -> bool:
        if result.get("target") is None or result.get("processing"):
            return False
        now = asyncio.get_running_loop().time()
        if self.attempts >= _MAX_CLICK_ATTEMPTS or now < self.next_attempt:
            return False
        if not self.dispatched:
            if self.pre_input_failures > _MAX_PRE_INPUT_FAILURES:
                return False
            if self.settle_first:
                return (self.ready_since is not None
                        and now - self.ready_since >= _RESET_SETTLE_SECONDS)
            return True
        if self.reset_clicks >= _MAX_RESET_CLICKS or self.ready_since is None:
            return False
        settled = now - self.ready_since
        if self.left_ready:
            return settled >= _RESET_SETTLE_SECONDS
        return (self.input_confirmed and self.ready_target == self.input_target
                and settled >= _UNRECEIVED_INPUT_SECONDS)

    async def attempt(self, page: Any, result: dict[str, Any], diagnostics: dict[str, Any], log: Any) -> bool:
        if not self.due(result):
            return False
        reclick = self.dispatched > 0
        if reclick:
            _log(log, "Cloudflare widget 已复位为可点击状态，补点一次" if self.left_ready
                 else "Cloudflare 未响应上次点击（checkbox 仍原样可点），补点一次")
        self.attempts += 1
        diagnostics["attempts"] = self.attempts
        clicked = await click(page, target=result, diagnostics=diagnostics, log=log)
        self.next_attempt = asyncio.get_running_loop().time() + _RETRY_GAP_SECONDS
        if diagnostics.get("click_started"):
            self.dispatched += 1
            if reclick:
                self.reset_clicks += 1
                diagnostics["reset_clicks"] = self.reset_clicks
                diagnostics["widget_acknowledged"] = False
            self.input_target = self._identity(result)
            self.input_confirmed = bool(clicked)
            self.left_ready = False
            self.ready_since = self.ready_target = None
        else:
            self.pre_input_failures += 1
            if reclick:
                # 补点在发出输入前就中止：上一次输入仍可能在处理中，保留其不确定性。
                diagnostics["click_started"] = True
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
    处理中不再点击/reset；输入前失败可有限重试，复位后的有限补点由共享 _ClickSession 控制。
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


class _GenerationUnavailable(RuntimeError):
    """真实页面本次没读到 generation（evaluate 超时/异常），不是「文档已变化」。"""


async def generation(page: Any) -> str:
    try:
        value = await _operation(page.evaluate(_GENERATION_JS), "generation", None)
        if isinstance(value, str) and ':' in value and '://' not in value:
            try:
                page._ck_cf_generation_supported = True
            except Exception:
                pass
            return value
    except Exception:
        # 截止已到而没读到新身份：按超时上报，不能用兼容回退值冒充「文档已变化」。
        if _remaining() <= 0:
            raise TimeoutError from None
    # 已读到过真实 generation 的页面，一次读取失败（主机繁忙、导航中）只是「未知」；
    # 改返回兼容 hash 会让 document key 变化，把同一文档误判成 document_changed。
    if getattr(page, '_ck_cf_generation_supported', False) is True:
        raise _GenerationUnavailable("generation 暂不可读")
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


def _document_changed(session: Any, page: Any, widget_generation: str) -> bool:
    """当前 generation 是否属于另一个 document。

    会话若只凭兼容 hint 建立（首次读取 generation 失败），之后第一次读到真实 document
    id 只是补全身份：导航/重载已由 document hint（main frame 导航计数）覆盖，不能
    因此误判 document_changed。
    """
    key = _document_key(page, widget_generation)
    if key == session.document_key:
        return False
    if (':' in widget_generation and getattr(session, 'document_from_hint', False)
            and session.document_hint == _document_hint(page)):
        session.document_key = key
        session.document_from_hint = False
        return False
    return True


def _unknown_observation(page: Any) -> None:
    """任何未知观察均中断可点击稳定计时，保留既有输入记录与绝对截止点。"""
    clicks = getattr(getattr(page, '_ck_cf_session', None), 'clicks', None)
    if isinstance(clicks, _ClickSession):
        clicks.ready_since = clicks.ready_target = None


async def _read_generation(page: Any, data: dict[str, Any], poll_interval_ms: int) -> str | None:
    """读 widget generation；暂不可读时有界暂停并返回 None，由调用方重试本轮观察。"""
    try:
        return await generation(page)
    except _GenerationUnavailable:
        _unknown_observation(page)
        await _pause(page, min(500, max(100, poll_interval_ms)), data, stage='observation')
        return None


async def _same_generation(page: Any, expected: str, data: dict[str, Any]) -> bool:
    """点击前后复验 generation：读不到按「未确认」处理，不发出输入。"""
    try:
        if await generation(page) == expected:
            return True
        _diagnose(data, reason='target_changed')
    except _GenerationUnavailable:
        _unknown_observation(page)
        _diagnose(data, reason='generation_unavailable')
    return False


class _ChallengeSession:
    def __init__(self, key: str, deadline: float, *, lock: Any = None):
        self.generation = key
        self.document_key = ''
        # document_key 只来自兼容 hint（generation 首读失败）时，首个真实 id 可补全身份。
        self.document_from_hint = False
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
        # widget-token 模式下一次 frame 内探测的最早时间（见 _BUSY_PROBE_GAP_SECONDS）。
        self.next_probe = 0.0


def _rebind_document(page: Any, session: _ChallengeSession, key: str, log: Any) -> _ChallengeSession | None:
    """page_access：挑战页被整页替换后，在同一锁、同一绝对截止点内绑定新文档。

    新文档的 widget 是另一张挑战，旧 widget 的「处理中/未确认」不适用于它；但它仍须
    重新观察：首点前 checkbox 必须稳定（settle_first），点击总数跨文档累计封顶。
    旧文档已发出的输入记为 prior_input_dispatched，未通过时仍保留页面、不允许外层重载。
    超过 _MAX_DOCUMENT_REBINDS 返回 None，由调用方按 observation_error 收尾。
    """
    old = session.data
    rebinds = int(old.get('document_rebinds') or 0) + 1
    if rebinds > _MAX_DOCUMENT_REBINDS:
        return None
    fresh = _ChallengeSession(key, session.deadline, lock=session.lock)
    fresh.document_key = _document_key(page, key)
    fresh.document_from_hint = ':' not in key
    fresh.document_hint = _document_hint(page)
    fresh.page_hint = _observation_hint(page)
    fresh.announced = session.announced
    fresh.delivered_token_digests = session.delivered_token_digests
    fresh.clicks.attempts = session.clicks.attempts
    fresh.clicks.settle_first = True
    prior_input = bool(old.get('input_dispatched') or old.get('click_started')
                       or old.get('prior_input_dispatched'))
    fresh.data.update(document_rebinds=rebinds, attempts=session.clicks.attempts,
                      observation_generation=key, prior_input_dispatched=prior_input,
                      challenge_observed=bool(old.get('challenge_observed') or old.get('present')))
    setattr(page, '_ck_cf_session', fresh)
    _log(log, f'Cloudflare 挑战页已整页替换（第 {rebinds} 次），在原预算内重新观察新页面')
    return fresh


def _safe_result(session: _ChallengeSession, mode: str, status: str, value: str = ""):
    from solvers.registry import SolveResult

    raw = session.data
    if status == 'passed' and mode == 'widget_token' and not value:
        status = 'observation_error'
    # prior_input_dispatched：同一调用里被替换掉的旧挑战文档已发出过真实输入；新文档
    # 未通过时仍按「输入结果未知」保留页面，外层不得据此重载授权页或重开预算。
    pending = bool(raw.get("click_started") or raw.get("processing")
                   or raw.get("widget_acknowledged") or raw.get("prior_input_dispatched"))
    preserve = status not in {"passed", "rejected"} and pending
    diagnostics = {key: raw[key] for key in (
        "stage", "reason", "probe_reason", "page_state", "page_state_reason", "present",
        "target_kind", "clicked", "moved", "click_started", "processing", "timeout_stage", "attempts",
        "reset_clicks", "document_rebinds", "error_type",
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
        "input_dispatched": bool(raw.get("input_dispatched") or raw.get("prior_input_dispatched")),
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
        while True:
            try:
                key = await generation(page)
                break
            except _GenerationUnavailable:
                _unknown_observation(page)
                await _pause(page, min(500, max(100, poll_interval_ms)), session.data, stage='observation')
        if session.document_key and _document_changed(session, page, key):
            session = _ChallengeSession(key, stop, lock=session.lock)
            setattr(page, '_ck_cf_session', session)
        session.document_key = _document_key(page, key)
        session.document_from_hint = ':' not in key
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
                before = await _read_generation(page, data, poll_interval_ms)
                if before is None:
                    continue
                state, result = await _bounded(_challenge_state(page, diagnostics=data), _remaining())
                after = await _read_generation(page, data, poll_interval_ms)
                if after is None:
                    continue
                data['observation_generation'] = after
                if before != after:
                    await _pause(page, min(500, max(100, poll_interval_ms)), data, stage='document_settling')
                    continue
                if state == "clear":
                    session.generation = after
                    session.document_key = _document_key(page, after)
                    session.document_from_hint = ':' not in after
                    session.document_hint = _document_hint(page)
                    session.page_hint = _observation_hint(page)
                    data.update(status="passed", stage="complete", reason="page_cleared")
                    if data.get('challenge_observed'):
                        _log(log, 'Cloudflare 挑战已通过（页面放行）'
                             if data.get('click_started') or data.get('prior_input_dispatched')
                             else 'Cloudflare 挑战已通过（自动放行）')
                    outcome = _safe_result(session, mode, "passed")
                    session.results[cache_key] = outcome
                    return outcome
                if state == "rejected":
                    data.update(status="rejected", stage="page_state", reason="trusted_rejection")
                    outcome = _safe_result(session, mode, "rejected")
                    session.results[cache_key] = outcome
                    return outcome
                if _document_changed(session, page, after):
                    # 点击后挑战页整页替换（放行跳转中或换发新挑战）是进展而不是观察错误：
                    # 在原绝对截止点内改为观察新文档；本轮探测属于旧/过渡文档，不据此点击。
                    fresh = _rebind_document(page, session, after, log)
                    if fresh is None:
                        data.update(status='observation_error', reason='document_changed')
                        return _safe_result(session, mode, 'observation_error')
                    session, data = fresh, fresh.data
                    await _pause(page, min(500, max(100, poll_interval_ms)), data, stage='document_settling')
                    continue
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
                before = await _read_generation(page, data, poll_interval_ms)
                if before is None:
                    continue
                try:
                    token = await _operation(token_reader() if token_reader else read_token(
                        page, diagnostics=data, widget_target=widget_target), 'token_wait', data)
                except TimeoutError:
                    if _remaining() <= 0:
                        raise
                    data.update(status='observation_error')
                    _unknown_observation(page)
                    await _pause(page, min(500, max(100, poll_interval_ms)), data, stage='observation')
                    continue
                # 读不到 generation 时无法确认令牌属于同一 widget：本轮作废重读，令牌仍在字段里。
                after = await _read_generation(page, data, poll_interval_ms)
                if after is None:
                    continue
                data['observation_generation'] = after
                if before == after and not data.get('click_started') and not data.get('widget_acknowledged'):
                    # 首次挂载/自动 render 可更新身份，但始终保留原 deadline。
                    session.generation = before
                if _document_changed(session, page, after):
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
                if asyncio.get_running_loop().time() < session.next_probe:
                    # 退避期内只读令牌：不改状态、不复用旧探测结果做点击判断。
                    await _pause(page, min(500, max(100, poll_interval_ms)), data, stage="observation")
                    continue
                observed = {key: data[key] for key in ("processing", "present") if key in data}
                result = await _bounded(probe(page, diagnostics=data), _remaining())
                if result.get("reason") == "probe_timeout" and _remaining() <= 0:
                    # 被截止打断的探测不是观察结果：保留上一次完整观察，按超时收尾。
                    data.update(observed)
                    raise TimeoutError
                if result.get("reason") in {"probe_timeout", "probe_failed"}:
                    gap = _STALLED_PROBE_GAP_SECONDS
                elif result.get("target") is None and result.get("present") and _frames(page):
                    gap = _BUSY_PROBE_GAP_SECONDS
                else:
                    gap = 0.0
                session.next_probe = asyncio.get_running_loop().time() + gap
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
            # 输入可能已发出而无明确反馈时不补点；只有 _ClickSession 观察到 widget
            # 复位（或确认送达的输入长期未被接收）的证据才有限补点。
            session.clicks.observe(result)
            if session.clicks.due(result):
                input_generation = await _read_generation(page, data, poll_interval_ms)
                if input_generation is None:
                    continue
                if _document_changed(session, page, input_generation):
                    fresh = (_rebind_document(page, session, input_generation, log)
                             if mode == 'page_access' else None)
                    if fresh is None:
                        data.update(status='observation_error', reason='document_changed')
                        return _safe_result(session, mode, 'observation_error')
                    # 探测与输入之间文档被替换：本轮目标属于旧文档，绝不点击，重新观察新文档。
                    session, data = fresh, fresh.data
                    await _pause(page, min(500, max(100, poll_interval_ms)), data, stage='document_settling')
                    continue
                # probe 期间新挂载/复位的 widget 必须在同一 document 锁中、输入前
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
    except Exception as exc:
        if session is None:
            session = _ChallengeSession("unobserved", stop)
        # 只记录异常类型名（不含消息/URL/页面内容），便于区分驱动异常与文档替换。
        session.data.update(status="observation_error", reason="observation_error",
                            error_type=type(exc).__name__[:60])
        _log(log, f"Cloudflare 观察异常（{type(exc).__name__}），停止本轮观察")
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
