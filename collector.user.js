// ==UserScript==
// @name         auto-checkin 站点采集器
// @namespace    auto-checkin
// @version      2.1.0
// @description  严格识别 New API/Sub2API，展示账号详情，验证管理页访问令牌后显式导出。
// @match        http://*/*
// @match        https://*/*
// @run-at       document-start
// @noframes
// @grant        none
// @sandbox      raw
// @inject-into  page
// ==/UserScript==

(function installAutoCheckinCollector() {
  'use strict';
  const root = globalThis;
  const VERSION = '2.1.0';
  if (root.autoCheckinSiteCollector?.version === VERSION || !/^https?:$/.test(location.protocol)) return;
  if (root.top && root.top !== root.self) return;
  const ORIGIN = location.origin;
  const nativeFetch = root.fetch;
  if (typeof nativeFetch !== 'function') return;

  const REQUEST_MS = 2500, TOTAL_MS = 16000, MAX_REQUESTS = 18, MAX_BODY = 1024 * 1024;
  const PUBLIC_PATHS = ['/api/status', '/api/v1/settings/public'];
  const PROFILES = { newapi: ['/api/user/self'], sub2api: ['/api/v1/user/profile', '/api/v1/auth/me'] };
  const STATUS_PATHS = { newapi: ['/api/user/checkin'], sub2api: ['/api/v1/check-in/status', '/api/v1/play/checkin/status'] };
  const READ_PATHS = new Set([...PUBLIC_PATHS, ...Object.values(PROFILES).flat(), ...Object.values(STATUS_PATHS).flat(), '/api/v1/usage']);
  const state = {
    family: 'unknown', detection: 'pending', evidence: { newapi: [], sub2api: [] }, settings: null,
    session: '', userId: '', access: null, revision: 0, entry: null, preview: null,
    diagnostics: [], active: null, paused: false, message: '正在识别站点（仅访问公开接口）…',
  };
  const controllers = new Set();
  const sensitive = new Set();
  let ui = null;

  function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
  function own(value, key) { return object(value) && Object.prototype.hasOwnProperty.call(value, key); }
  function text(value, max = 160) { return typeof value === 'string' ? value.trim().slice(0, max) : ''; }
  function number(value) {
    if (typeof value !== 'number' && typeof value !== 'string') return null;
    if (typeof value === 'string' && !/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(value.trim())) return null;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  function bool(value) {
    if (value === true || value === 1) return true;
    if (value === false || value === 0) return false;
    if (typeof value === 'string' && /^(true|1)$/i.test(value.trim())) return true;
    if (typeof value === 'string' && /^(false|0)$/i.test(value.trim())) return false;
    return null;
  }
  function identifier(value) {
    if (typeof value === 'number') return Number.isSafeInteger(value) && value > 0 ? String(value) : '';
    if (typeof value !== 'string' || !/^[\w.@-]{1,128}$/.test(value.trim())) return '';
    const id = value.trim();
    if (/^[+-]?\d+(?:\.\d+)?$/.test(id) && (!/^\d+$/.test(id) || /^0+$/.test(id))) return '';
    return id;
  }
  function nodes(value, depth = 0) {
    if (!object(value) || depth > 4) return [];
    return [value, ...['data', 'user', 'profile', 'user_info', 'stats'].flatMap((key) => nodes(value[key], depth + 1))];
  }
  function first(value, keys, parse = text) {
    for (const node of nodes(value)) for (const key of keys) {
      if (!own(node, key)) continue;
      const parsed = parse(node[key]);
      if (parsed !== null && parsed !== '') return { value: parsed, field: key, node };
    }
    return null;
  }
  function token(value) {
    if (typeof value !== 'string' || /[\r\n]/.test(value)) return '';
    let parsed = value.trim();
    if (parsed.startsWith('"')) {
      try { parsed = JSON.parse(parsed); } catch (_) { return ''; }
    }
    if (typeof parsed !== 'string') return '';
    parsed = parsed.replace(/^Bearer[ \t]+/i, '').trim();
    return parsed && parsed.length <= 4096 && !/\s/.test(parsed) ? parsed : '';
  }
  function bearer(value) {
    return typeof value === 'string' && /^Bearer[ \t]+\S+$/i.test(value.trim()) ? token(value) : '';
  }
  function tokenInfo(value) {
    // JWT claims are display hints only; identity is always confirmed by the server.
    try {
      const parts = value.split('.');
      if (parts.length !== 3 || !root.atob) return { kind: 'opaque', expires_at: null };
      const encoded = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      const claims = JSON.parse(root.atob(encoded.padEnd(Math.ceil(encoded.length / 4) * 4, '=')));
      const exp = typeof claims.exp === 'number' && Number.isFinite(claims.exp) ? claims.exp * 1000 : NaN;
      const session = claims.token_use === 'access' && (claims.sid || [claims.aud].flat().includes('new-api-dashboard'));
      return { kind: session ? 'session_jwt' : 'jwt', expires_at: Number.isFinite(exp) ? new Date(exp).toISOString() : null };
    } catch (_) { return { kind: 'unknown', expires_at: null }; }
  }
  function remember(value) { if (value && sensitive.size < 128) sensitive.add(String(value)); }
  function scrub(value) {
    if (typeof value === 'string') {
      for (const secret of [...sensitive].sort((a, b) => b.length - a.length)) {
        if (secret.length >= 4) value = value.split(secret).join('[redacted]');
        else {
          const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          value = value.replace(new RegExp(`(^|[^\\w])${escaped}(?=$|[^\\w])`, 'g'), '$1[redacted]');
        }
      }
      return value;
    }
    if (Array.isArray(value)) return value.map(scrub);
    if (object(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, scrub(item)]));
    return value;
  }
  function localURL(value) {
    try {
      const url = new URL(value, location.href);
      return url.origin === ORIGIN && /^https?:$/.test(url.protocol) && !url.username && !url.password ? url : null;
    } catch (_) { return null; }
  }
  function usableFamily() { return state.detection === 'confirmed' && !state.paused; }
  function invalidate() {
    state.revision += 1;
    state.entry = null;
    state.preview = null;
    for (const controller of controllers) controller.abort();
  }
  function setMessage(message) { state.message = message; render(); }
  function assertCurrent(run) {
    if (run.revision !== state.revision || state.paused) throw new Error('cancelled');
  }
  function record(run, source, status, extra = {}) {
    if (run.revision !== state.revision) return;
    run.diagnostics.push({ source, status, ...extra });
    state.diagnostics = run.diagnostics;
    render();
  }
  function rejection(body) {
    for (const node of nodes(body)) {
      const message = [node.code, node.message, node.msg, node.error].filter((v) => typeof v === 'string').join(' ');
      if (/unauthori[sz]ed|not.?logged|token.?expired|未登录|登录已过期/i.test(message)) return 'unauthenticated';
      if (/captcha|turnstile|人机验证|验证码/i.test(message)) return 'verification_required';
      if (/not.?enabled|disabled|not.?open|未开放|未开启|未启用/i.test(message)) return 'not_open';
      if (own(node, 'success') && bool(node.success) !== true) return 'business_rejected';
      if (own(node, 'code') && ![0, 200].includes(number(node.code))) return 'business_rejected';
      if (own(node, 'error') && ![null, '', false, 0].includes(node.error)) return 'business_rejected';
    }
    return '';
  }
  async function readBody(response) {
    const size = number(response.headers.get('content-length'));
    if (size !== null && size > MAX_BODY) throw new Error('response_too_large');
    if (!response.body?.getReader || !root.TextDecoder) {
      const raw = await response.text();
      if (raw.length > MAX_BODY) throw new Error('response_too_large');
      return raw;
    }
    const reader = response.body.getReader(), decoder = new TextDecoder();
    let total = 0, raw = '';
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        total += chunk.value.byteLength;
        if (total > MAX_BODY) { await reader.cancel(); throw new Error('response_too_large'); }
        raw += decoder.decode(chunk.value, { stream: true });
      }
      return raw + decoder.decode();
    } finally { reader.releaseLock(); }
  }
  async function getJson(run, path, auth = { mode: 'public' }) {
    assertCurrent(run);
    const url = localURL(path), remaining = TOTAL_MS - (Date.now() - run.started);
    if (!url || !READ_PATHS.has(url.pathname)) { record(run, path, 'invalid_path'); return null; }
    if (remaining <= 0 || run.requests >= MAX_REQUESTS) { record(run, path, 'budget_exhausted'); return null; }
    const isPublic = PUBLIC_PATHS.includes(url.pathname);
    if (!isPublic && !usableFamily()) { record(run, path, 'unconfirmed_family'); return null; }
    const mode = isPublic ? 'public' : auth.mode;
    const headers = { Accept: 'application/json' };
    if (!isPublic && auth.token) headers.Authorization = `Bearer ${auth.token}`;
    if (!isPublic && state.family === 'newapi' && identifier(auth.userId)) headers['New-Api-User'] = identifier(auth.userId);
    const controller = new AbortController(), started = Date.now();
    controllers.add(controller);
    run.requests += 1;
    let timer, http_status = null;
    const request = async () => {
      const response = await nativeFetch.call(root, url.href, {
        method: 'GET', mode: 'same-origin', redirect: 'error', cache: 'no-store', headers,
        credentials: mode === 'cookie' ? 'same-origin' : 'omit', signal: controller.signal,
      });
      http_status = response.status;
      if (response.redirected || response.type === 'opaqueredirect' || (response.url && !localURL(response.url))) return { status: 'redirect_blocked' };
      if (response.status === 401) return { status: 'unauthenticated' };
      if (response.status === 404) return { status: 'not_found' };
      if (response.status === 429) return { status: 'rate_limited' };
      const raw = await readBody(response);
      if (response.status >= 500) return { status: 'server_error' };
      if (/html/i.test(response.headers.get('content-type') || '') || /^\s*</.test(raw)) return { status: 'html_response' };
      if (response.status === 403) return { status: 'forbidden' };
      if (!response.ok) return { status: 'http_error' };
      let data;
      try { data = JSON.parse(raw); } catch (_) { return { status: 'invalid_json' }; }
      if (!object(data)) return { status: 'invalid_shape' };
      return { status: rejection(data) || 'ok', data };
    };
    try {
      const result = await Promise.race([request(), new Promise((resolve) => {
        timer = setTimeout(() => { controller.abort(); resolve({ status: 'timeout' }); }, Math.min(REQUEST_MS, remaining));
      })]);
      assertCurrent(run);
      record(run, path, result.status, { auth: mode, http_status, elapsed_ms: Date.now() - started });
      return result.status === 'ok' ? result.data : null;
    } catch (error) {
      assertCurrent(run);
      const status = error.message === 'response_too_large' ? error.message : controller.signal.aborted ? 'timeout' : 'network_error';
      record(run, path, status, { auth: mode, http_status, elapsed_ms: Date.now() - started });
      return null;
    } finally { clearTimeout(timer); controllers.delete(controller); }
  }

  async function detect(run) {
    const previousFamily = state.family;
    state.detection = 'detecting';
    const [newPayload, subPayload] = await Promise.all(PUBLIC_PATHS.map((path) => getJson(run, path)));
    assertCurrent(run);
    const n = newPayload?.data, s = subPayload?.data;
    const newMatch = newPayload?.success === true && object(n) && text(n.system_name)
      && number(n.quota_per_unit) > 0 && ['turnstile_check', 'checkin_enabled'].some((key) => bool(n[key]) !== null);
    const subMatch = object(s) && (subPayload?.success === true || [0, 200].includes(number(subPayload?.code)))
      && text(s.site_name) && ['registration_enabled', 'email_verify_enabled', 'turnstile_enabled'].filter((key) => bool(s[key]) !== null).length >= 2;
    state.evidence = {
      newapi: newMatch ? ['/api/status: success + system_name + quota_per_unit + 家族配置'] : [],
      sub2api: subMatch ? ['/api/v1/settings/public: 成功响应 + site_name + 多项配置'] : [],
    };
    state.family = !!newMatch === !!subMatch ? 'unknown' : newMatch ? 'newapi' : 'sub2api';
    state.detection = newMatch && subMatch ? 'conflict' : state.family === 'unknown' ? 'unknown' : 'confirmed';
    state.settings = state.family === 'newapi' ? newPayload : state.family === 'sub2api' ? subPayload : null;
    if (state.family === 'unknown' || (previousFamily !== 'unknown' && previousFamily !== state.family)) {
      state.session = ''; state.userId = ''; state.access = null; sensitive.clear();
    }
    setMessage(state.detection === 'conflict' ? '两类接口证据冲突，不选择模板、不采集凭据。'
      : state.family === 'unknown' ? '未匹配到完整站点指纹；没有尝试读取账号凭据。'
        : `已确认 ${state.family}。点击“刷新资料”；访问令牌请在网站管理页生成。`);
  }
  async function operation(label, action) {
    if (state.active || state.paused) return null;
    const run = { revision: state.revision, started: Date.now(), requests: 0, diagnostics: [] };
    state.active = run; state.diagnostics = run.diagnostics; state.entry = null; state.preview = null;
    setMessage(label);
    try { return await action(run); }
    catch (_) { setMessage(run.revision !== state.revision || state.paused ? '采集已取消，旧结果已丢弃。' : '采集未完成，请查看请求诊断后重试。'); return null; }
    finally { if (state.active === run) state.active = null; render(); }
  }

  function readStorage(run) {
    // Only called after a strong family match, never enumerate unrelated storage keys.
    const candidates = [], users = [], stores = {};
    const add = (value, source) => {
      const parsed = token(value);
      if (parsed && !candidates.some((item) => item.value === parsed)) { remember(parsed); candidates.push({ value: parsed, source }); }
    };
    for (const storeName of ['localStorage', 'sessionStorage']) {
      stores[storeName] = {};
      for (const key of ['user', 'user_info', 'auth_user', 'auth_token', 'access_token', 'token', 'jwt', 'refresh_token']) {
        try {
          const value = root[storeName]?.getItem(key);
          if (typeof value !== 'string' || value.length > MAX_BODY) continue;
          stores[storeName][key] = value;
          if (['user', 'user_info', 'auth_user'].includes(key)) {
            try {
              const data = JSON.parse(value);
              if (object(data)) { users.push({ data, source: `${storeName}:${key}` }); for (const node of nodes(data)) add(node.access_token, `${storeName}:${key}.access_token`); }
            } catch (_) { record(run, `${storeName}:${key}`, 'invalid_json'); }
          } else if (key !== 'refresh_token') add(value, `${storeName}:${key}`);
        } catch (_) {
          record(run, storeName, 'unavailable');
          break;
        }
      }
    }
    const hint = users.map((item) => ({ id: first(item.data, ['id', 'user_id'], identifier)?.value, source: item.source })).find((item) => item.id);
    let cookie = '';
    try { cookie = typeof document.cookie === 'string' ? document.cookie.trim() : ''; } catch (_) {}
    if (cookie.length > MAX_BODY) cookie = '';
    remember(cookie);
    for (const part of cookie.split(';')) { const index = part.indexOf('='); if (index >= 0) remember(part.slice(index + 1).trim()); }
    return { candidates, hint, stores, cookie };
  }
  async function profiles(run, auth) {
    const rows = []; let id = '', mismatch = false;
    for (const path of PROFILES[state.family]) {
      const data = await getJson(run, path, auth);
      if (!data) continue;
      const found = first(data, ['id', 'user_id'], identifier);
      if (found && id && found.value !== id) { mismatch = true; record(run, path, 'user_mismatch', { auth: auth.mode }); continue; }
      if (found) id = found.value;
      else record(run, path, 'missing_user_id', { auth: auth.mode });
      rows.push({ data, source: path });
    }
    return { id, rows, mismatch, auth };
  }
  function userDetails(profile, hint) {
    const user = { id: profile.id || hint?.id || null, source: profile.id ? profile.rows.find((row) => first(row.data, ['id', 'user_id'], identifier))?.source : hint?.source || null,
      verified: !!profile.id && !profile.mismatch, fields: {} };
    user.fields.id = user.source;
    for (const [key, parse] of Object.entries({ username: text, display_name: text, email: text, group: text,
      role: (v) => number(v) ?? (text(v) || null), status: (v) => number(v) ?? (text(v) || null),
      used_quota: number, request_count: number })) {
      for (const row of profile.rows) {
        const found = first(row.data, [key], parse);
        if (found) { user[key] = found.value; user.fields[key] = row.source; break; }
      }
    }
    return user;
  }
  function balanceDetails(rows) {
    const currencies = new Set(['USD', 'CNY', 'EUR', 'GBP', 'JPY', 'KRW', 'HKD', 'TWD', 'AUD', 'CAD', 'SGD']);
    const currency = (v) => currencies.has(text(v).toUpperCase()) ? text(v).toUpperCase() : '';
    for (const row of rows) {
      const found = first(row.data, ['balance', 'remaining', 'credit', 'credits', 'quota', 'remain_quota'], number);
      if (!found) continue;
      const isQuota = ['quota', 'remain_quota'].includes(found.field);
      const explicit = first(found.node, ['currency', 'balance_currency', 'unit'], currency) || first(row.data, ['currency', 'balance_currency'], currency);
      const unit = isQuota ? 'quota' : explicit?.value || (state.family === 'sub2api' && ['balance', 'remaining', 'credit'].includes(found.field) ? 'USD' : 'unknown');
      const result = { value: found.value, unit, field: found.field, source: row.source };
      const ratio = first(state.settings, ['quota_per_unit'], number)?.value;
      const displayCurrency = first(state.settings, ['quota_display_type', 'currency'], currency)?.value;
      if (isQuota && ratio > 0) {
        result.quota_per_unit = ratio;
        if (displayCurrency && Number.isFinite(found.value / ratio)) result.converted = { value: found.value / ratio, unit: displayCurrency };
      }
      return result;
    }
    return { value: null, unit: 'unknown', field: null, source: null };
  }
  async function checkinDetails(run, auth, authenticated) {
    const publicEnabled = first(state.settings, ['checkin_enabled'], bool)?.value ?? null;
    const result = { available: null, enabled: publicEnabled, checked_in_today: null, turnstile_required: null,
      streak: null, total_checkins: null, endpoints: [], conflicting: false };
    if (!authenticated) { record(run, 'checkin', 'skipped_unauthenticated'); return result; }
    const paths = STATUS_PATHS[state.family].map((path) => state.family === 'newapi' ? `${path}?month=${new Date().toISOString().slice(0, 7)}` : path);
    for (const path of paths) {
      const data = await getJson(run, path, auth);
      if (!data) {
        if (run.diagnostics.some((row) => row.source === path && row.status === 'not_open')) result.enabled = false;
        continue;
      }
      const checked = first(data, ['checked_in_today', 'checked_in', 'today_checked', 'has_checked_in', 'is_checked_in', 'checked'], bool);
      const enabled = first(data, ['checkin_enabled', 'enabled'], bool);
      if (!checked && enabled?.value !== false) { record(run, path, 'missing_checkin_fields'); continue; }
      const required = first(data, ['turnstile_required', 'require_turnstile'], bool);
      const streak = first(data, ['consecutive_days', 'continuous_days', 'current_streak'], number);
      const total = first(data, ['total_checkins', 'checkin_count', 'checked_days'], number);
      const endpoint = { status_path: path, checked_in_today: checked?.value ?? null, enabled: enabled?.value ?? null,
        turnstile_required: required?.value ?? null, streak: streak?.value ?? null, total_checkins: total?.value ?? null };
      result.endpoints.push(endpoint); result.available = true;
      if (checked) {
        if (result.checked_in_today !== null && result.checked_in_today !== checked.value) result.conflicting = true;
        result.checked_in_today = checked.value;
      }
      if (enabled?.value === false) result.enabled = false;
      else if (enabled && result.enabled === null) result.enabled = enabled.value;
      if (required?.value === true) result.turnstile_required = true;
      else if (required && result.turnstile_required === null) result.turnstile_required = required.value;
      if (streak) result.streak = streak.value;
      if (total) result.total_checkins = total.value;
    }
    if (!result.endpoints.length && paths.every((path) => run.diagnostics.some((row) => row.source === path && row.status === 'not_found'))) result.available = false;
    return result;
  }
  async function collectData(run) {
    if (!usableFamily()) await detect(run);
    if (!usableFamily()) return null;
    const stored = readStorage(run), hint = state.userId ? { id: state.userId, source: 'same-origin:New-Api-User' } : stored.hint;
    const currentSession = state.session;
    const candidates = currentSession ? [{ value: currentSession, source: 'page-session', kind: 'page_session' }] : [];
    for (const candidate of stored.candidates) {
      if (!candidates.some((item) => item.value === candidate.value)) candidates.push({ ...candidate, kind: 'storage_candidate' });
    }
    let profile = { id: '', rows: [], mismatch: false, auth: { mode: 'cookie', userId: hint?.id || '' } };
    let selectedSession = null;
    for (const candidate of candidates.slice(0, 3)) {
      const result = await profiles(run, { mode: 'session', token: candidate.value, userId: hint?.id || '' });
      if (result.id || result.mismatch) {
        profile = result;
        if (candidate.kind === 'page_session') selectedSession = candidate;
        break;
      }
      if (!profile.rows.length) profile = result;
    }
    if (!profile.id && !profile.mismatch) {
      const cookieProfile = await profiles(run, { mode: 'cookie', userId: hint?.id || '' });
      if (cookieProfile.rows.length) profile = cookieProfile;
    }
    let exportToken = null, exportVerified = false, mismatch = profile.mismatch;
    // A profile response may echo a session token or an unrelated credential. It is never
    // promoted to an export candidate; only the management page or explicit user input can set state.access.
    const supplied = state.access;
    if (supplied) {
      const tokenKind = tokenInfo(supplied.value).kind;
      if (state.family === 'newapi' && tokenKind === 'session_jwt') {
        record(run, 'access-token', 'temporary_session_token');
      } else {
        // state.access is populated only by the management-page observer or explicit user input.
        // Claims are hints; the independent profile request is still the source of truth.
        const verified = await profiles(run, { mode: 'access_token', token: supplied.value, userId: profile.id || hint?.id || '' });
        mismatch ||= verified.mismatch || !!(profile.id && verified.id && profile.id !== verified.id);
        if (mismatch) record(run, 'access-token', 'user_mismatch');
        if (verified.id && !mismatch) {
          exportToken = supplied; exportVerified = true;
          profile = { ...verified, rows: [...verified.rows, ...profile.rows] };
        }
      }
    }
    const user = userDetails(profile, hint);
    let balance = balanceDetails(profile.rows);
    if (state.family === 'sub2api' && balance.value === null && profile.id && !mismatch) {
      const path = '/api/v1/usage?page=1&page_size=1&sort_by=created_at&sort_order=desc';
      const data = await getJson(run, path, profile.auth);
      for (const node of nodes(data)) for (const item of Array.isArray(node.items) ? node.items.slice(0, 1) : []) {
        if (identifier(item?.user?.id) === profile.id) balance = balanceDetails([{ data: item.user, source: path }]);
        else record(run, path, 'unconfirmed_usage_user');
      }
    }
    const auth = exportVerified ? { mode: 'access_token', token: exportToken.value, userId: profile.id }
      : { ...profile.auth, userId: profile.id || hint?.id || '' };
    const checkin = await checkinDetails(run, auth, !!profile.id && !mismatch);
    assertCurrent(run);
    const expired = exportToken && tokenInfo(exportToken.value).expires_at && Date.parse(tokenInfo(exportToken.value).expires_at) <= Date.now();
    const enabled = exportVerified && !mismatch && !expired && checkin.available === true && checkin.enabled !== false
      && checkin.turnstile_required !== true && !checkin.conflicting;
    const warnings = [];
    if (!exportVerified) warnings.push(state.family === 'newapi'
      ? '尚无验证通过的管理页访问令牌；页面 Bearer 仅用于读取资料，不作为 AccessToken 导出。'
      : '尚无经独立验证的可导入访问令牌；页面会话或存储候选仅用于读取资料，不作为 AccessToken 导出。');
    if (!profile.id) warnings.push('用户 ID 未经服务端确认；存储/请求头中的 ID 仅为提示，不代表登录有效。');
    if (mismatch) warnings.push('资料接口或访问令牌属于不同用户，已停止启用账号，请核对登录账号。');
    if (expired) warnings.push('令牌包含已过期的时间声明，账号已禁用。');
    if (checkin.available !== true) warnings.push('尚未确认签到状态接口；不能根据 HTTP 200 或空对象推断支持签到。');
    if (checkin.enabled === false) warnings.push('站点明确表示未开放签到。');
    if (checkin.turnstile_required === true) warnings.push('签到状态接口要求 Turnstile，需核实执行方式。');
    if (checkin.conflicting) warnings.push('多个签到接口返回冲突状态，账号已禁用。');
    if (balance.value === null) warnings.push('没有取得有效余额；未知不代表零。');
    if (stored.cookie) warnings.push('仅包含 JS 可见 Cookie，不包含 HttpOnly Cookie，不保证可独立恢复登录。');
    const credentials = {};
    if (exportVerified) credentials.access_token = exportToken.value;
    if (stored.cookie) credentials.cookie = stored.cookie;
    // Export a refresh token only when its storage pairs with the verified access token.
    if (state.family === 'sub2api' && exportVerified) for (const values of Object.values(stored.stores)) {
      if (['auth_token', 'access_token', 'token', 'jwt'].some((key) => token(values[key]) === exportToken.value)) {
        const refresh = token(values.refresh_token);
        if (refresh) { remember(refresh); credentials.refresh_token = refresh; break; }
      }
    }
    const settingsPath = state.family === 'newapi' ? PUBLIC_PATHS[0] : PUBLIC_PATHS[1];
    const name = first(state.settings, ['system_name', 'site_name'])?.value || location.host;
    const authInfo = exportToken ? tokenInfo(exportToken.value) : { kind: null, expires_at: null };
    const info = {
      version: 2, generated_at: new Date().toISOString(),
      family: { value: state.family, confidence: state.detection, evidence: state.evidence },
      authentication: {
        browser_session: profile.id && profile.auth.mode === 'cookie' ? 'confirmed' : 'unknown',
        page_session: { present: !!currentSession, verified: !!profile.id && selectedSession?.source === 'page-session' && !mismatch,
          source: selectedSession?.source || (currentSession ? 'page-session' : null),
          kind: currentSession ? tokenInfo(currentSession).kind : null, expires_at: currentSession ? tokenInfo(currentSession).expires_at : null },
        exported_credentials: exportVerified && !mismatch ? 'confirmed' : 'unknown',
        access_token: { present: !!credentials.access_token, candidate_present: !!state.access, source: exportToken?.source || state.access?.source || null,
          verified: exportVerified && !mismatch, ...authInfo },
        refresh_token: { present: !!credentials.refresh_token, verified: false },
        cookie: { present: !!stored.cookie, completeness: 'unknown', http_only_accessible: false },
      },
      user, balance, checkin,
      features: Object.fromEntries(Object.entries({ checkin_enabled: ['checkin_enabled'], turnstile_enabled: ['turnstile_enabled', 'turnstile_check'],
        registration_enabled: ['registration_enabled', 'register_enabled'], email_verification_enabled: ['email_verify_enabled', 'email_verification'] }).map(([key, keys]) => {
        const value = first(state.settings, keys, bool); return [key, { value: value?.value ?? null, source: value ? settingsPath : null }];
      })),
      diagnostics: run.diagnostics, warnings, requires_review: !enabled, export_kind: 'full',
      collection: { read_only: true, request_timeout_ms: REQUEST_MS, total_budget_ms: TOTAL_MS, requests: run.requests },
    };
    const entry = {
      id: location.host.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''), name: scrub(name), base_url: ORIGIN,
      template: state.family, enabled, login: { method: exportVerified ? 'access_token' : 'cookie',
        ...(state.family === 'newapi' && user.verified ? { args: { user_id: user.id } } : {}) },
      tasks: [{ id: 'daily', method: 'http_api', enabled }], credentials, collected_info: scrub(info),
    };
    state.entry = entry;
    state.preview = scrub({ ...entry, credentials: undefined, enabled: false, tasks: entry.tasks.map((task) => ({ ...task, enabled: false })),
      collected_info: { ...entry.collected_info, export_kind: 'preview', requires_review: true } });
    setMessage(enabled ? '资料与访问令牌验证完成，可以导出启用账号。' : '资料已更新；账号保持禁用，请查看下面的具体原因。');
    return JSON.parse(JSON.stringify(state.preview));
  }

  function allowedObservation(url) {
    if (!usableFamily() || !url) return false;
    return [...PROFILES[state.family], ...STATUS_PATHS[state.family], ...(state.family === 'newapi' ? ['/api/user/token'] : [])].includes(url.pathname);
  }
  function observeHeaders(url, headers) {
    if (!allowedObservation(url)) return;
    const session = bearer(headers.get('authorization') || '');
    const id = state.family === 'newapi' ? identifier(headers.get('new-api-user')) : '';
    if ((session && session !== state.session) || (id && id !== state.userId)) {
      invalidate();
      if (session) { state.session = session; remember(session); }
      if (id) state.userId = id;
      if (state.active) setMessage('页面登录信息已变化，正在丢弃旧采集结果，请重试。');
      else setMessage('已捕获本站会话信息。可刷新资料；AccessToken 仍需在访问令牌页生成/验证。');
    }
  }
  function acceptGenerated(data, revision) {
    if (revision !== state.revision || !usableFamily() || state.family !== 'newapi' || data?.success !== true || rejection(data)) return;
    const candidate = token(typeof data.data === 'string' ? data.data : data.data?.access_token || data.data?.token);
    if (!candidate) return;
    invalidate(); remember(candidate);
    state.access = { value: candidate, source: 'access-token-page' };
    setMessage('已收到访问令牌页面的生成结果（未显示明文）。点击“刷新资料”验证所属用户后导出。');
  }
  function requestInfo(input, init) {
    const url = localURL(typeof input === 'string' || input instanceof URL ? input : input?.url);
    const headers = new Headers(init?.headers !== undefined ? init.headers : input?.headers);
    const method = String(init?.method || input?.method || 'GET').toUpperCase();
    return { url, headers, method };
  }
  function wrappedFetch(input, init) {
    const result = nativeFetch.apply(this, arguments);
    try {
      const { url, headers, method } = requestInfo(input, init);
      observeHeaders(url, headers);
      const revision = state.revision;
      if (allowedObservation(url) && url.pathname === '/api/user/token' && ['GET', 'POST'].includes(method)) {
        // Observe the user's native token-page request only; never generate/reset a token ourselves.
        Promise.resolve(result).then(async (response) => {
          if (!response.ok || response.redirected || !localURL(response.url)) return;
          const raw = await readBody(response.clone());
          acceptGenerated(JSON.parse(raw), revision);
        }).catch(() => {});
      }
    } catch (_) { /* Observation must never change the native request's result or error. */ }
    return result;
  }
  root.fetch = wrappedFetch;
  const xhrPrototype = root.XMLHttpRequest?.prototype;
  const xhrRequests = new WeakMap(), xhrListeners = new WeakSet();
  const nativeOpen = xhrPrototype?.open, nativeHeader = xhrPrototype?.setRequestHeader, nativeSend = xhrPrototype?.send;
  if (nativeOpen && nativeHeader && nativeSend) {
    xhrPrototype.open = function open(method, url) {
      const result = nativeOpen.apply(this, arguments);
      try {
        xhrRequests.set(this, { url: localURL(url), method: String(method).toUpperCase(), headers: new Headers(), revision: state.revision });
        if (!xhrListeners.has(this)) {
          xhrListeners.add(this);
          this.addEventListener('loadend', () => {
            try {
              const request = xhrRequests.get(this);
              if (!allowedObservation(request?.url) || request.url.pathname !== '/api/user/token' || !['GET', 'POST'].includes(request.method)
                  || this.status < 200 || this.status >= 300 || !localURL(this.responseURL)) return;
              const data = this.responseType === 'json' ? this.response : this.responseText.length <= MAX_BODY ? JSON.parse(this.responseText) : null;
              acceptGenerated(data, request.revision);
            } catch (_) {}
          });
        }
      } catch (_) {}
      return result;
    };
    xhrPrototype.setRequestHeader = function setRequestHeader(name, value) {
      const result = nativeHeader.apply(this, arguments);
      try { xhrRequests.get(this)?.headers.append(name, value); } catch (_) {}
      return result;
    };
    xhrPrototype.send = function send() {
      const request = xhrRequests.get(this);
      const result = nativeSend.apply(this, arguments);
      try {
        observeHeaders(request?.url, request?.headers);
        if (request) request.revision = state.revision;
      } catch (_) {}
      return result;
    };
  }

  async function identify() { return operation('正在重新识别站点…', async (run) => { await detect(run); return state.family; }); }
  async function collect() { return operation('正在读取并核对用户资料…', collectData); }
  function clear() {
    invalidate(); state.session = ''; state.userId = ''; state.access = null; sensitive.clear(); state.diagnostics = [];
    if (ui) ui.token.value = '';
    setMessage('已清除本脚本内存中的凭据和结果；网站自身的登录状态未改变。');
  }
  async function useAccessToken(value) {
    if (!usableFamily()) { setMessage('站点尚未被可靠识别，不能读取或验证访问令牌。'); return null; }
    const parsed = token(value);
    if (!parsed) { setMessage('访问令牌格式无效（仅接受长度受限的单行值）。'); return null; }
    invalidate(); remember(parsed); state.access = { value: parsed, source: 'manual-access-token' };
    return collect();
  }
  async function copyResult() {
    if (!state.entry || state.active) { setMessage('没有可复制的新结果，请先刷新资料。'); return false; }
    const revision = state.revision;
    try {
      await navigator.clipboard.writeText(JSON.stringify(state.entry, null, 2));
      if (revision !== state.revision) return false;
      setMessage('完整账号 JSON 已复制（包含凭据）。仅导入可信管理界面，不要分享。');
      return true;
    } catch (_) { setMessage('剪贴板写入失败。可在本页面再次点击“复制本次结果”授予权限；凭据未输出到日志。'); return false; }
  }
  async function copy() { return await collect() ? copyResult() : false; }
  function tokenPage() {
    if (state.family !== 'newapi' || !usableFamily()) return;
    const links = [...document.querySelectorAll('a[href]')].slice(0, 1000);
    const link = links.find((item) => /访问令牌|access\s*token/i.test(item.textContent || '') && localURL(item.href) && !localURL(item.href).pathname.startsWith('/api/'));
    if (link) { link.click(); setMessage('请在网站自己的访问令牌页面生成；生成成功后本面板会接收结果，也可粘贴验证。'); }
    else setMessage('请进入网站“个人设置/安全设置 → 访问令牌”生成令牌，再粘贴到下方验证。不要使用模型 API Key 或页面临时 JWT；本脚本不会自动重置令牌。');
  }
  root.autoCheckinAuthBridge = Object.freeze({
    getAuthorization: () => usableFamily() && state.session ? `Bearer ${state.session}` : '',
    getAccessToken: () => usableFamily() ? state.access?.value || '' : '',
    getUserId: () => usableFamily() ? state.userId : '', clear,
  });
  root.autoCheckinSiteCollector = Object.freeze({ version: VERSION, identify, collect, copy, copyResult, useAccessToken, clear,
    inspect: () => JSON.parse(JSON.stringify(scrub({ family: state.family, detection: state.detection, evidence: state.evidence,
      busy: !!state.active, message: state.message, result: state.preview, diagnostics: state.diagnostics }))),
  });

  const STATUS_LABELS = {
    ok: '成功', unauthenticated: '未登录/认证失败', forbidden: '无权限', not_found: '接口不存在', rate_limited: '请求限流',
    html_response: '返回 HTML 而非 JSON', invalid_json: 'JSON 无效', invalid_shape: '响应结构无效', business_rejected: '业务拒绝',
    server_error: '服务端错误', verification_required: '需要验证', not_open: '未开放', timeout: '请求超时', network_error: '网络失败',
    response_too_large: '响应过大', budget_exhausted: '采集预算已耗尽', user_mismatch: '用户身份不一致', missing_user_id: '缺少有效用户 ID',
    missing_checkin_fields: '未返回签到状态字段', skipped_unauthenticated: '未确认身份，跳过签到查询', temporary_session_token: '临时会话 JWT 不是管理页访问令牌',
    unconfirmed_usage_user: '用量记录用户未匹配', redirect_blocked: '重定向被阻止',
  };
  function display(value) { return value === null || value === undefined || value === '' ? '未知' : typeof value === 'boolean' ? value ? '是' : '否' : String(value); }
  function section(title, values) {
    const details = document.createElement('details'); details.open = true;
    const summary = document.createElement('summary'); summary.textContent = title; details.appendChild(summary);
    const list = document.createElement('dl');
    for (const [label, value, source] of values) {
      const key = document.createElement('dt'), item = document.createElement('dd');
      key.textContent = label; item.textContent = scrub(display(value));
      if (source) { const small = document.createElement('small'); small.textContent = scrub(`来源：${source}`); item.appendChild(small); }
      list.appendChild(key); list.appendChild(item);
    }
    details.appendChild(list); return details;
  }
  function render() {
    if (!ui) return;
    const labels = { pending: '识别中', detecting: '识别中', confirmed: state.family === 'newapi' ? 'New API' : 'Sub2API', conflict: '证据冲突', unknown: '未识别' };
    ui.launcher.textContent = `签到采集 · ${labels[state.detection]}`;
    ui.meta.textContent = `${location.host} · ${labels[state.detection]} · v${VERSION}`;
    ui.status.textContent = scrub(state.message);
    ui.identify.disabled = !!state.active;
    ui.collect.disabled = !!state.active || !usableFamily(); ui.copy.disabled = ui.collect.disabled;
    ui.copyResult.disabled = !!state.active || !state.entry;
    ui.verify.disabled = !!state.active || !usableFamily(); ui.tokenPage.disabled = !!state.active || state.family !== 'newapi';
    ui.content.replaceChildren();
    const data = state.entry?.collected_info, user = data?.user || {}, balance = data?.balance || {}, checkin = data?.checkin || {}, auth = data?.authentication || {};
    ui.content.appendChild(section('站点与识别依据', [
      ['站点', first(state.settings, ['system_name', 'site_name'])?.value || location.host],
      ['模板', state.family], ['识别依据', [...state.evidence.newapi, ...state.evidence.sub2api].join('；') || '无完整指纹'],
      ['可启用导出', state.entry ? state.entry.enabled : null], ['资料时间', data?.generated_at],
    ]));
    ui.content.appendChild(section('用户资料', [
      ['用户 ID', user.id, user.source], ['身份已确认', user.verified],
      ...['username', 'display_name', 'email', 'group', 'role', 'status'].map((key, index) => [['用户名', '显示名称', '邮箱', '分组', '角色', '账号状态'][index], user[key], user.fields?.[key]]),
    ]));
    ui.content.appendChild(section('余额与用量', [
      ['原始余额', balance.value, balance.source], ['单位', balance.unit], ['原始字段', balance.field],
      ['换算金额', balance.converted ? `${balance.converted.value} ${balance.converted.unit}` : null], ['额度换算比例', balance.quota_per_unit],
      ['已用额度', user.used_quota, user.fields?.used_quota], ['请求次数', user.request_count, user.fields?.request_count],
    ]));
    ui.content.appendChild(section('签到情况', [
      ['接口可用', checkin.available], ['签到已启用', checkin.enabled], ['今日已签到', checkin.checked_in_today],
      ['连续天数', checkin.streak], ['累计次数', checkin.total_checkins], ['签到要求验证', checkin.turnstile_required],
      ['站点 Turnstile 开关', data?.features?.turnstile_enabled?.value], ['接口', checkin.endpoints?.map((row) => row.status_path).join('；')],
    ]));
    ui.content.appendChild(section('认证与访问令牌（不显示明文）', [
      ['页面 Bearer 已捕获', !!state.session], ['页面会话类型', auth.page_session?.kind], ['页面会话到期', auth.page_session?.expires_at],
      ['访问令牌候选', !!state.access], ['AccessToken 验证通过', auth.access_token?.verified],
      ['访问令牌来源', auth.access_token?.source || state.access?.source], ['访问令牌类型', auth.access_token?.kind],
      ['令牌到期提示', auth.access_token?.expires_at || '未知，以站点管理页为准'], ['可见 Cookie', auth.cookie?.present], ['可读取 HttpOnly', false],
    ]));
    if (data?.warnings?.length) ui.content.appendChild(section('需要处理', data.warnings.map((warning, index) => [`${index + 1}`, warning])));
    const diagnostics = document.createElement('details'); diagnostics.open = true;
    const summary = document.createElement('summary'); summary.textContent = `请求诊断（${state.diagnostics.length}）`; diagnostics.appendChild(summary);
    const list = document.createElement('ul');
    for (const row of state.diagnostics) {
      const item = document.createElement('li');
      item.textContent = `${row.source} · ${STATUS_LABELS[row.status] || row.status} · HTTP ${row.http_status ?? '—'} · ${row.auth || '—'} · ${row.elapsed_ms ?? '—'}ms`;
      list.appendChild(item);
    }
    diagnostics.appendChild(list); ui.content.appendChild(diagnostics);
  }
  function mount() {
    if (ui || !document.documentElement) return;
    const host = document.createElement('div'); host.id = 'auto-checkin-site-collector';
    host.style.cssText = 'all:initial;position:fixed;right:16px;bottom:16px;z-index:2147483647;';
    const shadow = host.attachShadow({ mode: 'closed' });
    shadow.innerHTML = `<style>
      :host{font:13px/1.5 system-ui,sans-serif;color:#edf2f7}*{box-sizing:border-box}[hidden]{display:none!important}
      button,input{font:inherit}button{border:1px solid #43516c;background:#24334d;color:#fff;border-radius:7px;padding:7px 10px;cursor:pointer}
      button:disabled{opacity:.45;cursor:not-allowed}button:focus-visible,input:focus-visible{outline:2px solid #60a5fa;outline-offset:2px}
      .launcher,.primary{background:#1d4ed8}.launcher{float:right;box-shadow:0 6px 20px #0006}
      .panel{width:min(440px,calc(100vw - 32px));max-height:80vh;overflow:auto;background:#111b2c;border:1px solid #3c4b66;border-radius:12px;padding:14px;margin-bottom:8px;box-shadow:0 8px 30px #0008}
      .header,.actions{display:flex;gap:7px;flex-wrap:wrap;align-items:center}.header{justify-content:space-between}.header strong{font-size:15px}
      .meta,.hint,small{color:#aebbd0;font-size:11px}.status{padding:9px;background:#1b2b45;border-radius:7px;overflow-wrap:anywhere}
      .actions{margin:9px 0}input{width:100%;padding:8px;border:1px solid #43516c;border-radius:6px;background:#0c1524;color:#fff}
      details{border-top:1px solid #33435d;margin-top:10px;padding-top:8px}summary{font-weight:650;cursor:pointer}dl{display:grid;grid-template-columns:105px minmax(0,1fr);gap:6px 10px;margin:9px 0}
      dt{color:#aebbd0}dd{margin:0;overflow-wrap:anywhere}small{display:block}ul{padding-left:18px}li{margin:6px 0;overflow-wrap:anywhere}
    </style>
    <div class="panel" hidden role="region" aria-label="账号采集详情">
      <div class="header"><strong>账号采集详情</strong><button class="close" type="button" aria-label="关闭并清除凭据">关闭并清除</button></div>
      <p class="meta"></p><p class="status" role="status" aria-live="polite"></p>
      <div class="actions"><button class="identify" type="button">重新识别</button><button class="collect" type="button">刷新资料</button><button class="copy primary" type="button">获取并复制</button><button class="copy-result" type="button">复制本次结果</button><button class="clear" type="button">清除</button></div>
      <details open><summary>管理页访问令牌</summary>
        <p class="hint">页面临时 JWT 仅用于读取资料。请在网站自己的“访问令牌”页面生成，而不是模型 API Key。生成结果可自动接收，也可粘贴验证；本脚本不会自动生成或重置令牌。</p>
        <button class="token-page" type="button">访问令牌入口/指引</button>
        <p><label>已生成的 AccessToken<input class="token" type="password" autocomplete="off" spellcheck="false" placeholder="仅保存在内存，验证后清空输入框"></label></p>
        <button class="verify" type="button">使用并验证</button>
      </details>
      <div class="content"></div><p class="hint">只读 GET；未知字段不等于零。完整导出包含凭据，请勿截图或分享。</p>
    </div><button class="launcher" type="button" aria-label="展开或收起采集详情" aria-expanded="false">签到采集 · 识别中</button>`;
    document.documentElement.appendChild(host);
    const query = (selector) => shadow.querySelector(selector);
    ui = { host, panel: query('.panel'), launcher: query('.launcher'), meta: query('.meta'), status: query('.status'), content: query('.content'),
      identify: query('.identify'), collect: query('.collect'), copy: query('.copy'), copyResult: query('.copy-result'), clear: query('.clear'),
      tokenPage: query('.token-page'), token: query('.token'), verify: query('.verify'), close: query('.close') };
    ui.launcher.addEventListener('click', () => { state.paused = false; ui.panel.hidden = !ui.panel.hidden; ui.launcher.setAttribute('aria-expanded', String(!ui.panel.hidden)); render(); });
    ui.identify.addEventListener('click', identify); ui.collect.addEventListener('click', collect); ui.copy.addEventListener('click', copy);
    ui.copyResult.addEventListener('click', copyResult); ui.clear.addEventListener('click', clear); ui.tokenPage.addEventListener('click', tokenPage);
    ui.verify.addEventListener('click', () => { const value = ui.token.value; ui.token.value = ''; return useAccessToken(value); });
    ui.close.addEventListener('click', () => { clear(); state.paused = true; ui.panel.hidden = true; ui.launcher.setAttribute('aria-expanded', 'false'); });
    render();
  }
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount, { once: true });
    else mount();
  }
  identify();
})();
