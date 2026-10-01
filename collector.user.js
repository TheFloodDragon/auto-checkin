// ==UserScript==
// @name         auto-checkin 站点采集器
// @namespace    auto-checkin
// @version      2.0.0
// @description  自动识别 New API/Sub2API，悬浮按钮只读采集并复制账号信息。
// @match        *://*/*
// @run-at       document-start
// @noframes
// @grant        none
// ==/UserScript==

(function installAutoCheckinCollector() {
  'use strict';

  const root = globalThis;
  if (root.autoCheckinAuthBridge && root.autoCheckinSiteCollector) return;

  const REQUEST_MS = 2500;
  const MAX_BODY = 1024 * 1024;
  const MAX_AUTHORIZATION = 4096;
  const diagnostics = [];
  const state = {
    family: 'unknown',
    settings: null,
    selectedToken: null,
    user: {},
    entry: null,
    busy: false,
  };
  let latestAuthorization = '';
  let latestUserId = '';
  let panel = null;

  const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
  const own = (value, key) => object(value) && Object.prototype.hasOwnProperty.call(value, key);
  const text = (value, max = 160) => typeof value === 'string' ? value.trim().slice(0, max) : '';
  const number = (value) => {
    if (typeof value !== 'number' && typeof value !== 'string') return null;
    if (typeof value === 'string' && !/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(value.trim())) return null;
    const result = Number(value);
    return Number.isFinite(result) ? result : null;
  };
  const bool = (value) => {
    if (value === true || value === 1 || value === 'true' || value === '1') return true;
    if (value === false || value === 0 || value === 'false' || value === '0') return false;
    return null;
  };
  const identifier = (value) => {
    if (typeof value === 'number') return Number.isSafeInteger(value) && value > 0 ? String(value) : '';
    if (typeof value !== 'string' || !/^[\w.@-]{1,128}$/.test(value.trim())) return '';
    const result = value.trim();
    return /^\d+$/.test(result) && (result.startsWith('0') || result === '0') ? '' : result;
  };
  const nodes = (rootValue) => {
    const result = [];
    const visit = (value, depth) => {
      if (!object(value) || depth > 4) return;
      result.push(value);
      for (const key of ['data', 'user', 'profile', 'user_info', 'stats']) visit(value[key], depth + 1);
    };
    visit(rootValue, 0);
    return result;
  };
  const first = (rootValue, keys, parser) => {
    for (const node of nodes(rootValue)) {
      for (const key of keys) {
        if (!own(node, key)) continue;
        const value = parser(node[key]);
        if (value !== null && value !== '') return { value, field: key, node };
      }
    }
    return null;
  };
  const secret = (value) => {
    if (typeof value !== 'string') return '';
    const result = value.trim().replace(/^Bearer\s+/i, '').trim();
    return result && result.length <= MAX_AUTHORIZATION && !/[\r\n]/.test(result) ? result : '';
  };
  const sameOrigin = (value) => {
    try { return new URL(String(value), location.href).origin === location.origin; } catch (_) { return false; }
  };
  const validAuthorization = (value) => {
    if (typeof value !== 'string') return '';
    const result = value.trim();
    return /^Bearer\s+\S+$/i.test(result) && result.length <= MAX_AUTHORIZATION ? result : '';
  };
  const headerValue = (headers, name) => {
    if (!headers) return '';
    try {
      if (typeof headers.get === 'function') return headers.get(name) || '';
      if (Array.isArray(headers)) {
        const item = headers.find((pair) => Array.isArray(pair)
          && String(pair[0]).toLowerCase() === name.toLowerCase());
        return item ? item[1] : '';
      }
      if (typeof headers === 'object') {
        const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
        return key ? headers[key] : '';
      }
    } catch (_) {}
    return '';
  };
  const capture = (url, value) => {
    if (!sameOrigin(url)) return;
    const authorization = validAuthorization(value);
    if (authorization) latestAuthorization = authorization;
  };
  const captureUserId = (name, value) => {
    if (String(name).toLowerCase() !== 'new-api-user') return;
    const userId = identifier(value);
    if (userId) latestUserId = userId;
  };
  const addDiagnostic = (source, status, extra = {}) => diagnostics.push({ source, status, ...extra });

  const nativeFetch = root.fetch;
  if (typeof nativeFetch === 'function') {
    root.fetch = function autoCheckinFetch(input, init) {
      let url = input;
      let inheritedHeaders = null;
      try {
        if (input && typeof input === 'object') {
          url = input.url || input;
          inheritedHeaders = input.headers;
        }
      } catch (_) {}
      const headers = init?.headers || inheritedHeaders;
      capture(url, headerValue(headers, 'Authorization'));
      captureUserId('New-Api-User', headerValue(headers, 'New-Api-User'));
      return nativeFetch.apply(this, arguments);
    };
  }
  const NativeXHR = root.XMLHttpRequest;
  if (NativeXHR?.prototype) {
    const xhrOrigins = new WeakMap();
    const nativeOpen = NativeXHR.prototype.open;
    const nativeSetRequestHeader = NativeXHR.prototype.setRequestHeader;
    NativeXHR.prototype.open = function autoCheckinOpen(method, url) {
      const result = nativeOpen.apply(this, arguments);
      xhrOrigins.set(this, sameOrigin(url));
      return result;
    };
    NativeXHR.prototype.setRequestHeader = function autoCheckinSetRequestHeader(name, value) {
      if (xhrOrigins.get(this)) {
        capture(location.origin, String(name).toLowerCase() === 'authorization' ? value : '');
        captureUserId(name, value);
      }
      return nativeSetRequestHeader.apply(this, arguments);
    };
  }

  const getStoredTokens = () => {
    const values = [];
    const add = (value, source) => {
      const token = secret(value);
      if (token && !values.some((item) => item.value === token)) values.push({ value: token, source });
    };
    for (const storeName of ['localStorage', 'sessionStorage']) {
      for (const key of ['auth_token', 'access_token', 'token', 'jwt']) {
        try { add(root[storeName]?.getItem(key), `${storeName}:${key}`); } catch (_) { addDiagnostic(storeName, 'unavailable'); }
      }
    }
    return values;
  };
  const getUserIdFromStorage = () => {
    for (const storeName of ['localStorage', 'sessionStorage']) {
      try {
        const raw = root[storeName]?.getItem('user') || root[storeName]?.getItem('user_info');
        if (raw) {
          const parsed = JSON.parse(raw);
          const id = first(parsed, ['id', 'user_id'], identifier);
          if (id) return id.value;
        }
      } catch (_) {}
    }
    return '';
  };

  const getJson = async (path, authorization = '') => {
    const controller = new AbortController();
    const headers = { Accept: 'application/json' };
    const token = validAuthorization(authorization);
    if (token) headers.Authorization = token;
    if (latestUserId) headers['New-Api-User'] = latestUserId;
    const credentials = token ? 'omit' : 'same-origin';
    let timer;
    try {
      const request = fetch(new URL(path, location.origin).href, {
        method: 'GET', credentials, mode: 'same-origin', redirect: 'error', cache: 'no-store', headers,
        signal: controller.signal,
      }).then(async (response) => {
        if (response.url && new URL(response.url).origin !== location.origin) return { ok: false, status: 'redirect_blocked' };
        const contentLength = number(response.headers.get('content-length'));
        if (contentLength !== null && contentLength > MAX_BODY) return { ok: false, status: 'response_too_large' };
        const raw = await response.text();
        if (raw.length > MAX_BODY) return { ok: false, status: 'response_too_large' };
        if (response.status === 401) return { ok: false, status: 'unauthenticated', http_status: 401 };
        if (response.status === 404) return { ok: false, status: 'not_found', http_status: 404 };
        if (!response.ok) return { ok: false, status: 'http_error', http_status: response.status };
        let data;
        try { data = JSON.parse(raw); } catch (_) { return { ok: false, status: 'invalid_json' }; }
        if (!object(data)) return { ok: false, status: 'invalid_shape' };
        return { ok: true, data, http_status: response.status };
      });
      const timeout = new Promise((resolve) => {
        timer = setTimeout(() => { controller.abort(); resolve({ ok: false, status: 'timeout' }); }, REQUEST_MS);
      });
      const result = await Promise.race([request, timeout]);
      addDiagnostic(path, result.status, { auth: token ? 'token' : 'cookie' });
      return result;
    } catch (_) {
      addDiagnostic(path, controller.signal.aborted ? 'timeout' : 'network_error', { auth: token ? 'token' : 'cookie' });
      return { ok: false, status: 'network_error' };
    } finally { clearTimeout(timer); }
  };

  const identify = async () => {
    const [newSettings, subSettings] = await Promise.all([
      getJson('/api/status'), getJson('/api/v1/settings/public'),
    ]);
    const newData = newSettings.ok ? newSettings.data : null;
    const subData = subSettings.ok ? subSettings.data : null;
    const newMarkers = ['system_name', 'quota_per_unit', 'checkin_enabled', 'turnstile_check'];
    const subMarkers = ['site_name', 'registration_enabled', 'email_verify_enabled', 'turnstile_enabled'];
    const hasMarker = (data, markers) => data && nodes(data).some((node) => markers.some((key) => own(node, key)));
    const newFound = hasMarker(newData, newMarkers);
    const subFound = hasMarker(subData, subMarkers);
    state.family = newFound && !subFound ? 'newapi' : subFound && !newFound ? 'sub2api' : newFound ? 'newapi' : 'unknown';
    state.settings = state.family === 'newapi' ? newData : state.family === 'sub2api' ? subData : null;
    if (state.family === 'unknown') latestAuthorization = '';
    updatePanel();
    return state.family;
  };

  const collect = async () => {
    if (state.busy) return null;
    state.busy = true;
    updatePanel('正在只读采集…');
    try {
      if (state.family === 'unknown') await identify();
      if (state.family === 'unknown') throw new Error('无法识别站点类型');
      const candidates = [];
      const addCandidate = (value, source) => {
        const token = secret(value);
        if (token && !candidates.some((item) => item.value === token)) candidates.push({ value: token, source });
      };
      addCandidate(latestAuthorization, 'auth-bridge');
      for (const item of getStoredTokens()) addCandidate(item.value, item.source);
      const userId = getUserIdFromStorage();
      const profiles = [];
      const profilePaths = state.family === 'newapi'
        ? ['/api/user/self'] : ['/api/v1/user/profile', '/api/v1/auth/me'];
      const tryProfile = async (authorization) => {
        for (const path of profilePaths) {
          const result = await getJson(path, authorization);
          if (result.ok) {
            const id = first(result.data, ['id', 'user_id'], identifier);
            const identity = first(result.data, ['username', 'email'], text);
            if (id || identity) profiles.push({ data: result.data, source: path, authorization });
            if (id) return id.value;
          }
        }
        return '';
      };
      let confirmedId = '';
      let selected = null;
      for (const candidate of candidates.slice(0, 3)) {
        const id = await tryProfile(`Bearer ${candidate.value}`);
        if (id) { confirmedId = id; selected = candidate; break; }
      }
      if (!selected) {
        const id = await tryProfile('');
        if (id) confirmedId = id;
      }
      const auth = selected ? `Bearer ${selected.value}` : '';
      const statusPaths = state.family === 'newapi'
        ? [`/api/user/checkin?month=${new Date().toISOString().slice(0, 7)}`]
        : ['/api/v1/check-in/status', '/api/v1/play/checkin/status'];
      const statusResults = [];
      for (const path of statusPaths) {
        const result = await getJson(path, auth);
        if (result.ok) statusResults.push({ path, data: result.data });
      }
      const profileData = profiles[0]?.data || {};
      const user = {
        id: confirmedId || first(profileData, ['id', 'user_id'], identifier)?.value || null,
        username: first(profileData, ['username', 'email', 'display_name'], text)?.value || null,
      };
      const balanceFound = first(profileData, ['balance', 'remaining', 'credit', 'credits', 'quota', 'remain_quota'], number);
      const balance = {
        value: balanceFound ? balanceFound.value : null,
        unit: balanceFound && ['quota', 'remain_quota'].includes(balanceFound.field) ? 'quota'
          : state.family === 'sub2api' && balanceFound ? 'USD' : 'unknown',
        field: balanceFound?.field || null,
        source: balanceFound ? profiles[0]?.source || null : null,
      };
      const checked = first(statusResults[0]?.data, ['checked_in_today', 'checked_in', 'today_checked', 'has_checked_in'], bool);
      const enabledFound = first(statusResults[0]?.data, ['checkin_enabled', 'enabled'], bool);
      const turnstile = first(state.settings, ['turnstile_check', 'turnstile_enabled'], bool);
      const checkin = {
        available: statusResults.length > 0,
        checked_in_today: checked?.value ?? null,
        enabled: enabledFound?.value ?? first(state.settings, ['checkin_enabled'], bool)?.value ?? null,
        turnstile_required: turnstile?.value ?? null,
        endpoints: statusResults.map((item) => ({ status_path: item.path, available: true })),
      };
      const authConfirmed = !!selected && !!user.id;
      const enabled = authConfirmed && checkin.available && checkin.enabled !== false && checkin.turnstile_required !== true;
      const siteName = first(state.settings, ['system_name', 'site_name', 'name', 'title'], text)?.value
        || text(document.title).replace(/[-–|].*$/, '').trim() || location.host;
      const credentials = {};
      if (selected) credentials.access_token = selected.value;
      if (typeof document.cookie === 'string' && document.cookie.trim()) credentials.cookie = document.cookie.trim();
      if (state.family === 'sub2api') {
        for (const storeName of ['localStorage', 'sessionStorage']) {
          try {
            const refresh = secret(root[storeName]?.getItem('refresh_token'));
            if (refresh) { credentials.refresh_token = refresh; break; }
          } catch (_) {}
        }
      }
      const info = {
        version: 1,
        family: { value: state.family, confidence: 'confirmed', evidence: { [state.family]: [state.family === 'newapi' ? '/api/status' : '/api/v1/settings/public'] } },
        authentication: {
          browser_session: selected ? 'unknown' : 'confirmed',
          exported_credentials: authConfirmed ? 'confirmed' : 'unknown',
          access_token: { present: !!selected, source: selected?.source || null, verified: authConfirmed },
          refresh_token: { present: !!credentials.refresh_token, verified: false },
          cookie: { present: !!document.cookie, completeness: 'unknown', http_only_accessible: false },
        },
        user, balance,
        features: { checkin_enabled: { value: checkin.enabled, source: state.family === 'newapi' ? '/api/status' : '/api/v1/settings/public' } },
        checkin,
        diagnostics: diagnostics.slice(-40),
        warnings: authConfirmed ? [] : ['未确认可导出的有效凭据；请刷新页面并触发一次已登录 API 请求。'],
        requires_review: !enabled,
        export_kind: 'full',
        collection: { read_only: true, request_timeout_ms: REQUEST_MS, requests: diagnostics.length },
      };
      state.entry = {
        id: location.host.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
        name: siteName,
        base_url: location.origin,
        template: state.family,
        enabled,
        login: selected ? { method: 'access_token', ...(state.family === 'newapi' && user.id ? { args: { user_id: user.id } } : {}) } : { method: 'cookie' },
        tasks: [{ id: 'daily', method: 'http_api', enabled }],
        credentials,
        collected_info: info,
      };
      updatePanel(enabled ? '采集完成，可复制账号 JSON' : '采集完成，但账号仍需核实');
      return state.entry;
    } finally {
      state.busy = false;
      updatePanel();
    }
  };

  const copyEntry = async () => {
    const entry = state.entry || await collect();
    if (!entry) return false;
    const value = JSON.stringify(entry, null, 2);
    try {
      await navigator.clipboard.writeText(value);
      updatePanel('完整账号 JSON 已复制；请立即导入，不要分享剪贴板内容');
      return true;
    } catch (_) {
      updatePanel('剪贴板写入失败，请检查浏览器权限');
      return false;
    }
  };

  const clear = () => {
    latestAuthorization = '';
    latestUserId = '';
    state.family = 'unknown';
    state.settings = null;
    state.selectedToken = null;
    state.entry = null;
    diagnostics.length = 0;
    updatePanel('已清除内存中的临时凭据');
  };

  root.autoCheckinAuthBridge = Object.freeze({
    getAuthorization: () => latestAuthorization,
    clear: () => { latestAuthorization = ''; },
  });
  root.autoCheckinSiteCollector = Object.freeze({ identify, collect, copy: copyEntry, clear });

  const mountPanel = () => {
    if (panel || typeof document === 'undefined' || !document.documentElement) return;
    const host = document.createElement('div');
    host.id = 'auto-checkin-site-collector';
    host.style.cssText = 'all:initial;position:fixed;z-index:2147483647;right:18px;bottom:18px;';
    document.documentElement.appendChild(host);
    const shadow = host.attachShadow({ mode: 'closed' });
    shadow.innerHTML = `<style>
      :host{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
      .box{width:260px;color:#e5e7eb;background:#111827;border:1px solid #374151;border-radius:12px;box-shadow:0 10px 30px #0008;padding:12px;font-size:13px}
      .title{font-weight:700;font-size:14px;margin-bottom:6px}.meta{color:#9ca3af;line-height:1.45;margin-bottom:8px}.status{min-height:34px;color:#d1d5db;margin-bottom:8px;line-height:1.4}.actions{display:flex;gap:6px;flex-wrap:wrap}button{border:0;border-radius:7px;padding:7px 9px;color:#fff;background:#2563eb;cursor:pointer;font:inherit}button.secondary{background:#374151}button:disabled{opacity:.5;cursor:wait}.hint{font-size:11px;color:#9ca3af;margin-top:8px;line-height:1.4}</style>
      <div class="box" role="region" aria-label="auto-checkin 站点采集器">
        <div class="title">auto-checkin 站点采集器</div>
        <div class="meta"></div><div class="status" aria-live="polite">正在识别站点…</div>
        <div class="actions"><button class="identify">识别/刷新</button><button class="copy">获取并复制</button><button class="clear secondary">清除</button></div>
        <div class="hint">只读 GET；凭据只保存在内存，不会续期或写入存储。</div>
      </div>`;
    panel = {
      host, meta: shadow.querySelector('.meta'), status: shadow.querySelector('.status'),
      identify: shadow.querySelector('.identify'), copy: shadow.querySelector('.copy'), clear: shadow.querySelector('.clear'),
    };
    panel.identify.onclick = () => identify().catch((error) => updatePanel(`识别失败：${error.message || '未知错误'}`));
    panel.copy.onclick = () => copyEntry().catch((error) => updatePanel(`复制失败：${error.message || '未知错误'}`));
    panel.clear.onclick = clear;
    updatePanel();
    identify().catch((error) => updatePanel(`识别失败：${error.message || '未知错误'}`));
  };
  const updatePanel = (message = '') => {
    if (!panel) return;
    panel.meta.textContent = `${location.host} · 模板：${state.family}`;
    panel.status.textContent = message || (state.busy ? '正在只读采集…' : latestAuthorization ? '已捕获临时 Bearer，可获取账号信息' : '未捕获 Bearer，请刷新页面或打开个人中心');
    panel.identify.disabled = state.busy;
    panel.copy.disabled = state.busy || state.family === 'unknown';
  };
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mountPanel, { once: true });
    else mountPanel();
  }
})();
