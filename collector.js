/**
 * NewAPI / Sub2API 只读采集器：在已登录站点的 Console 中粘贴整个文件。
 * 所有请求均为有时限的同源 GET；不会签到、登录、续期或生成凭据。
 *
 * 返回值是禁用且不含凭据的标准 v3 预览账号，避免 Console 自动展开泄密。
 * 完整账号只保存在闭包，必须明确复制：
 *   await autoCheckinCollector.copy()       // Clipboard API
 *   await autoCheckinCollector.copy(copy)   // DevTools copy；权限失败时的后备
 *   copy(autoCheckinCollector.exportJSON()) // 明确导出完整 JSON 的手动后备
 * 不要单独执行 exportJSON() 后截图/分享 Console；其返回值含完整凭据。
 * JS 无法读取 HttpOnly Cookie；浏览器会话成功不代表导出的 Cookie 可复用。
 */
(async () => {
  'use strict';
  const REQUEST_MS = 2500;
  const TOTAL_MS = 16000;
  const MAX_REQUESTS = 18;
  const MAX_BODY = 1024 * 1024;
  const started = Date.now();
  const diagnostics = [];
  const warnings = [];
  const evidence = { newapi: [], sub2api: [] };
  const record = (source, status, extra = {}) => {
    diagnostics.push({ source, status, ...extra });
  };
  const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  const own = (v, key) => object(v) && Object.prototype.hasOwnProperty.call(v, key);
  const bool = (v) => {
    if (v === true || v === 1) return true;
    if (v === false || v === 0) return false;
    if (typeof v === 'string') {
      if (/^(true|1)$/i.test(v.trim())) return true;
      if (/^(false|0)$/i.test(v.trim())) return false;
    }
    return null;
  };
  const number = (v) => {
    if (typeof v !== 'number' && typeof v !== 'string') return null;
    if (typeof v === 'string' && !/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i.test(v.trim())) return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  };
  const text = (v, max = 160) => typeof v === 'string' ? v.trim().slice(0, max) : '';
  const identifier = (v) => {
    if (typeof v === 'number') return Number.isSafeInteger(v) && v > 0 ? String(v) : '';
    if (typeof v !== 'string' || !/^[\w.@-]{1,128}$/.test(v.trim())) return '';
    const value = v.trim();
    if (/^-?\d+$/.test(value) && (value.startsWith('-') || /^0+$/.test(value))) return '';
    return value;
  };
  // Only documented user wrappers, never arbitrary recursive scans of storage/responses.
  const nodes = (root) => {
    const result = [];
    const visit = (v, depth) => {
      if (!object(v) || depth > 4) return;
      result.push(v);
      for (const key of ['data', 'user', 'profile', 'user_info', 'stats']) visit(v[key], depth + 1);
    };
    visit(root, 0);
    return result;
  };
  const direct = (node, keys, parse) => {
    for (const key of keys) {
      if (!own(node, key)) continue;
      const value = parse(node[key]);
      if (value !== null && value !== '') return { value, field: key, node };
    }
    return null;
  };
  const first = (root, keys, parse) => {
    for (const node of nodes(root)) {
      const found = direct(node, keys, parse);
      if (found) return found;
    }
    return null;
  };
  const secret = (v) => {
    if (typeof v !== 'string') return '';
    let value = v.trim();
    if (value.startsWith('"')) {
      try { value = JSON.parse(value); } catch (_) { return ''; }
    }
    return typeof value === 'string' && value.length <= 65536 && !/[\r\n]/.test(value)
      ? value.replace(/^Bearer\s+/i, '').trim() : '';
  };
  let baseUrl = '';
  try {
    const origin = new URL(location.origin);
    if (/^https?:$/.test(origin.protocol) && !origin.username && !origin.password) baseUrl = origin.origin;
  } catch (_) { /* No requests on file:, opaque origins or invalid URLs. */ }

  const allowedPaths = new Set([
    '/api/status', '/api/user/self', '/api/user/checkin', '/api/v1/settings/public',
    '/api/v1/user/profile', '/api/v1/auth/me', '/api/v1/usage',
    '/api/v1/check-in/status', '/api/v1/play/checkin/status',
  ]);
  let requestCount = 0;
  const originError = (value) => /cloudflare could not establish a tcp connection to the origin server|the origin web server returned an invalid or incomplete response to cloudflare|the host is configured as a cloudflare tunnel, but cloudflare is currently unable to reach it/i.test(value);
  const verificationTransportError = (value) => /challenges\.cloudflare\.com\/turnstile\/v0\/siteverify/i.test(value) && /unexpected eof/i.test(value);
  const challengeHTML = (value) => /just a moment|checking your browser|verifying you are human|verify you are human|cf_chl_opt|cf-challenge-running|challenge-form/i.test(value);
  const rejection = (body) => {
    // Never export server messages: they can echo credentials or personal data.
    for (const node of nodes(body)) {
      const message = [node.code, node.message, node.msg, node.error, node.detail]
        .filter((v) => typeof v === 'string').join(' ').toLowerCase();
      if (originError(message)) return 'server_error';
      if (verificationTransportError(message)) return 'network_error';
      if (/unauthori[sz]ed|not.?logged|token.?expired|invalid.?token|未登录|登录已过期/.test(message)) return 'unauthenticated';
      if (/cloudflare (?:verification|challenge)|turnstile|captcha|人机验证|验证码|安全验证/.test(message)) return 'verification_required';
      if (/not.?enabled|disabled|not.?open|未开放|未开启|未启用/.test(message)) return 'not_open';
      if (own(node, 'success') && bool(node.success) !== true) return 'business_rejected';
      if (own(node, 'code') && ![0, 200].includes(number(node.code))) return 'business_rejected';
      if (own(node, 'error') && ![null, '', false, 0].includes(node.error)) return 'business_rejected';
    }
    return null;
  };
  const get = async (path, auth = { mode: 'public' }) => {
    const source = path;
    const remaining = TOTAL_MS - (Date.now() - started);
    if (remaining <= 0 || requestCount >= MAX_REQUESTS) {
      record(source, 'budget_exhausted');
      return null;
    }
    let url;
    try {
      url = new URL(path, baseUrl);
      if (!baseUrl || url.origin !== baseUrl || !allowedPaths.has(url.pathname)) throw new Error();
    } catch (_) { record(source, 'invalid_origin'); return null; }
    requestCount += 1;
    const controller = new AbortController();
    let timer;
    const headers = { Accept: 'application/json' };
    if (auth.mode === 'token') headers.Authorization = `Bearer ${auth.token}`;
    if (auth.mode !== 'public' && auth.userId) headers['New-Api-User'] = auth.userId;
    const request = async () => {
      const response = await fetch(url.href, {
        method: 'GET', credentials: auth.mode === 'token' || auth.mode === 'public' ? 'omit' : 'same-origin',
        mode: 'same-origin', redirect: 'error', cache: 'no-store', headers, signal: controller.signal,
      });
      if (response.redirected || response.type === 'opaqueredirect'
          || (response.url && new URL(response.url).origin !== baseUrl)) return { status: 'redirect_blocked' };
      const http_status = response.status;
      if (http_status === 404) return { status: 'not_found', http_status };
      if (http_status === 401) return { status: 'unauthenticated', http_status };
      if (http_status === 429) return { status: 'rate_limited', http_status };
      const contentType = response.headers.get('content-type') || '';
      const size = number(response.headers.get('content-length'));
      if (size !== null && size > MAX_BODY) return { status: 'response_too_large', http_status };
      const raw = await response.text();
      if (raw.length > MAX_BODY) return { status: 'response_too_large', http_status };
      if ([520, 521, 522, 523, 524, 525, 526, 530].includes(http_status)) return { status: 'server_error', http_status };
      if (originError(raw) && (http_status >= 400 || /^\s*</.test(raw))) return { status: 'server_error', http_status };
      if (verificationTransportError(raw) && http_status >= 400) return { status: 'network_error', http_status };
      if (challengeHTML(raw) && /^\s*</.test(raw)) {
        return { status: 'verification_required', http_status };
      }
      if (http_status >= 500) return { status: 'server_error', http_status };
      if (/html/i.test(contentType) || /^\s*</.test(raw)) return { status: 'html_response', http_status };
      if (http_status === 403) return { status: 'forbidden', http_status };
      if (http_status >= 500) return { status: 'server_error', http_status };
      if (!response.ok) return { status: 'http_error', http_status };
      let data;
      try { data = JSON.parse(raw); } catch (_) { return { status: 'invalid_json', http_status }; }
      if (!object(data)) return { status: 'invalid_shape', http_status };
      const rejected = rejection(data);
      if (rejected) return { status: rejected, http_status };
      return { status: 'ok', http_status, data };
    };
    try {
      const result = await Promise.race([
        request(),
        new Promise((resolve) => {
          timer = setTimeout(() => {
            controller.abort();
            resolve({ status: remaining < REQUEST_MS ? 'budget_exhausted' : 'timeout' });
          }, Math.min(REQUEST_MS, remaining));
        }),
      ]);
      record(source, result.status, { auth: auth.mode, ...(result.http_status ? { http_status: result.http_status } : {}) });
      return result.status === 'ok' ? result.data : null;
    } catch (_) {
      record(source, controller.signal.aborted ? 'timeout' : 'network_error', { auth: auth.mode });
      return null;
    } finally { clearTimeout(timer); }
  };
  const noteFamily = (family, source) => {
    if (!evidence[family].includes(source)) evidence[family].push(source);
  };
  const [newSettings, subSettings] = await Promise.all([get('/api/status'), get('/api/v1/settings/public')]);
  // Family evidence comes only from successful public schemas, all at data's own level.
  const newData = newSettings && object(newSettings.data) ? newSettings.data : null;
  const subData = subSettings && object(subSettings.data) ? subSettings.data : null;
  if (newSettings?.success === true && newData && text(newData.system_name)
      && number(newData.quota_per_unit) !== null && number(newData.quota_per_unit) > 0
      && ['turnstile_check', 'checkin_enabled'].some((key) => own(newData, key) && bool(newData[key]) !== null)) {
    noteFamily('newapi', '/api/status');
  }
  if (subSettings && (subSettings.success === true || [0, 200].includes(number(subSettings.code)))
      && subData && text(subData.site_name)
      && ['registration_enabled', 'email_verify_enabled', 'turnstile_enabled']
        .filter((key) => own(subData, key) && bool(subData[key]) !== null).length >= 2) {
    noteFamily('sub2api', '/api/v1/settings/public');
  }
  const families = Object.keys(evidence).filter((key) => evidence[key].length);
  const family = families.length === 1 ? families[0] : 'unknown';
  const settings = family === 'newapi' ? newData : family === 'sub2api' ? subData : null;
  const settingsSource = family === 'newapi' ? '/api/status' : '/api/v1/settings/public';

  const stored = {}, storedSources = {};
  const localUsers = [], tokens = [];
  const addToken = (value, source, kind = 'storage_candidate') => {
    const token = secret(value);
    if (kind === 'storage_candidate' && tokens.some((item) => item.kind === 'page_session' && item.value === token)) return;
    if (token && !tokens.some((item) => item.value === token && item.kind === kind)) {
      tokens.push({ value: token, source, kind });
    }
  };
  let userId = '', userIdSource = null, visibleCookie = '';
  // Do not touch storage, bridge getters or visible cookies on unknown/conflicting sites.
  if (family !== 'unknown') {
    let bridge = null;
    try { bridge = globalThis.autoCheckinAuthBridge; }
    catch (_) { record('auth-bridge', 'unavailable'); }
    const fromBridge = (method) => {
      try { return bridge && typeof bridge[method] === 'function' ? bridge[method]() : null; }
      catch (_) { record(`auth-bridge:${method}`, 'unavailable'); return null; }
    };
    // Explicitly generated/pasted access tokens take precedence over sessions and stale storage.
    const accessToken = secret(fromBridge('getAccessToken'));
    if (accessToken && accessToken.length <= 4096 && /^\S+$/.test(accessToken)) {
      addToken(accessToken, 'auth-bridge:getAccessToken', 'management_access_token');
    }
    const authorization = fromBridge('getAuthorization');
    if (typeof authorization === 'string' && /^Bearer\s+\S+$/i.test(authorization.trim())
        && authorization.trim().length <= 4096) {
      addToken(authorization, 'auth-bridge:getAuthorization', 'page_session');
    }
    const observedId = identifier(fromBridge('getUserId'));
    if (observedId) { userId = observedId; userIdSource = 'auth-bridge:getUserId'; }
    for (const storeName of ['localStorage', 'sessionStorage']) {
      for (const key of ['user', 'user_info', 'auth_user', 'auth_token', 'access_token', 'token', 'jwt', 'refresh_token']) {
        try {
          const value = globalThis[storeName].getItem(key);
          if (typeof value === 'string' && value.trim() && !stored[key]) {
            stored[key] = value;
            storedSources[key] = `${storeName}:${key}`;
          }
        } catch (_) {
          if (!diagnostics.some((d) => d.source === storeName)) record(storeName, 'unavailable');
          break;
        }
      }
    }
    for (const key of ['user', 'user_info', 'auth_user']) {
      try {
        if (stored[key] && stored[key].length <= MAX_BODY) {
          const parsed = JSON.parse(stored[key]);
          if (object(parsed)) localUsers.push({ data: parsed, key, source: storedSources[key] });
        }
      } catch (_) { record(storedSources[key], 'invalid_json'); }
    }
    for (const key of ['auth_token', 'access_token', 'token', 'jwt']) addToken(stored[key], storedSources[key]);
    for (const item of localUsers) {
      const id = item.key === 'user' ? identifier(item.data.id) : '';
      if (!userId && id) { userId = id; userIdSource = item.source; }
      for (const node of nodes(item.data)) addToken(node.access_token, item.source);
    }
    try {
      const cookie = document.cookie;
      visibleCookie = typeof cookie === 'string' ? cookie.trim() : '';
    } catch (_) { record('document.cookie', 'unavailable'); }
  }

  const profiles = { newapi: [], sub2api: [] };
  const confirmedTokens = { newapi: null, sub2api: null };
  const confirmedSessions = { newapi: null, sub2api: null };
  const confirmedUserIds = { newapi: '', sub2api: '' };
  const browserSession = { newapi: false, sub2api: false };
  const profileInfo = (data) => {
    const id = first(data, ['id', 'user_id'], identifier);
    const identity = first(data, ['username', 'email'], text);
    const balance = first(data, ['balance', 'remaining', 'credit', 'credits', 'quota', 'remain_quota'], number);
    return id || (identity && balance);
  };
  const inspectProfile = async (family, path, auth) => {
    const data = await get(path, auth);
    if (!data) return false;
    const confirmedIdentity = first(data, ['id', 'user_id'], identifier);
    const expectedId = family === 'newapi' ? userId : confirmedUserIds[family];
    if (confirmedIdentity && expectedId && confirmedIdentity.value !== expectedId) {
      record(path, 'user_mismatch', { auth: auth.mode });
      return false;
    }
    if (!profileInfo(data)) {
      record(path, 'missing_user_fields');
      // Preserve recognized partial values without claiming identity/authentication.
      if (first(data, ['balance', 'remaining', 'credit', 'credits', 'quota', 'remain_quota'], number)) {
        profiles[family].push({ data, source: path, auth: auth.mode });
      }
      return false;
    }
    profiles[family].push({ data, source: path, auth: auth.mode });
    if (confirmedIdentity) {
      confirmedUserIds[family] = confirmedIdentity.value;
      if (auth.mode === 'token') {
        const candidate = { value: auth.token, source: auth.source, kind: auth.kind };
        if (auth.kind === 'page_session') {
          confirmedSessions[family] = candidate;
          browserSession[family] = true;
        } else confirmedTokens[family] = candidate;
      }
      if (auth.mode === 'cookie') browserSession[family] = true;
      if (family === 'newapi') {
        if (!userId) { userId = confirmedIdentity.value; userIdSource = path; }
        for (const node of nodes(data)) addToken(node.access_token, path);
      }
    }
    return !!confirmedIdentity;
  };
  // Unknown/ambiguous sites stop at the two public probes, without private fallback scans.
  if (family !== 'unknown') {
    const paths = family === 'newapi' ? ['/api/user/self'] : ['/api/v1/user/profile', '/api/v1/auth/me'];
    for (const path of paths) {
      if (family === 'newapi' || !tokens.length) {
        await inspectProfile(family, path, { mode: 'cookie', userId: family === 'newapi' ? userId : '' });
      }
      let verified = false;
      // Bounded exportable candidates first; a page session is a separate metadata fallback.
      for (const candidate of tokens.filter((item) => item.kind !== 'page_session').slice(0, 2)) {
        verified = await inspectProfile(family, path, {
          mode: 'token', token: candidate.value, source: candidate.source, kind: candidate.kind,
          userId: family === 'newapi' ? userId : '',
        });
        if (verified) break;
      }
      const session = tokens.find((item) => item.kind === 'page_session');
      if (!verified && session) {
        await inspectProfile(family, path, {
          mode: 'token', token: session.value, source: session.source, kind: session.kind,
          userId: family === 'newapi' ? userId : '',
        });
      }
      // Both Sub2API routes are read even when profile exists without a balance.
    }
  }
  const selectedProfiles = profiles[family] || [];
  const selectedToken = confirmedTokens[family] || null;
  const selectedSession = confirmedSessions[family] || null;
  const requestToken = selectedToken || selectedSession;
  const auth = requestToken ? { mode: 'token', token: requestToken.value, source: requestToken.source }
    : { mode: 'cookie' };
  if (family === 'newapi' && userId) auth.userId = userId;

  let balance = { value: null, unit: 'unknown', field: null, source: null };
  const currencies = new Set(['USD', 'CNY', 'EUR', 'GBP', 'JPY', 'KRW', 'HKD', 'TWD', 'AUD', 'CAD', 'SGD']);
  const currency = (v) => currencies.has(text(v).toUpperCase()) ? text(v).toUpperCase() : '';
  const captureBalance = (data, source, expectedId = '') => {
    if (balance.value !== null) return;
    const id = first(data, ['id', 'user_id'], identifier);
    if (expectedId && id && id.value !== expectedId) { record(source, 'user_mismatch'); return; }
    const found = first(data, ['balance', 'remaining', 'credit', 'credits', 'quota', 'remain_quota'], number);
    if (!found) return;
    const explicitUnit = first(found.node, ['currency', 'balance_currency', 'unit'], currency)
      || first(data, ['currency', 'balance_currency'], currency);
    const isQuota = ['quota', 'remain_quota'].includes(found.field);
    const unit = isQuota ? 'quota' : explicitUnit ? explicitUnit.value
      : family === 'sub2api' && ['balance', 'remaining', 'credit'].includes(found.field) ? 'USD' : 'unknown';
    balance = { value: found.value, unit, field: found.field, source,
      unit_source: isQuota ? 'field' : explicitUnit ? 'response' : unit === 'USD' ? 'sub2api_protocol' : 'unknown' };
    const ratio = first(settings, ['quota_per_unit'], number);
    const displayCurrency = first(settings, ['quota_display_type', 'currency'], currency);
    if (isQuota && ratio && ratio.value > 0) {
      balance.quota_per_unit = ratio.value;
      if (displayCurrency && Number.isFinite(found.value / ratio.value)) {
        balance.converted = { value: found.value / ratio.value, unit: displayCurrency.value, source: settingsSource };
      }
    }
  };
  const user = { id: null, source: null, verified: false };
  for (const profile of selectedProfiles) {
    const id = first(profile.data, ['id', 'user_id'], identifier);
    if (id && user.id && id.value !== user.id) { record(profile.source, 'user_mismatch'); continue; }
    if (id) { user.id = id.value; user.source = profile.source; user.verified = true; }
    for (const key of ['username', 'display_name', 'email', 'group']) {
      const found = first(profile.data, [key], text);
      if (found && !user[key]) user[key] = found.value;
    }
    for (const key of ['role', 'status']) {
      const found = first(profile.data, [key], (v) => number(v) ?? (text(v) || null));
      if (found && !own(user, key)) user[key] = found.value;
    }
    captureBalance(profile.data, profile.source, user.id || '');
  }
  if (!user.id && family === 'newapi' && userId) { user.id = userId; user.source = userIdSource; }
  if (family === 'sub2api' && balance.value === null && selectedProfiles.length) {
    const usagePath = '/api/v1/usage?page=1&page_size=1&sort_by=created_at&sort_order=desc';
    const usage = await get(usagePath, auth);
    if (usage) {
      // Only an explicitly matching user on a usage row can supply an account balance.
      for (const node of nodes(usage)) {
        if (!Array.isArray(node.items)) continue;
        for (const item of node.items.slice(0, 1)) {
          if (!object(item) || !object(item.user)) continue;
          const id = first(item.user, ['id', 'user_id'], identifier);
          if (user.id && id && id.value === user.id) captureBalance(item.user, usagePath, user.id);
          else record(usagePath, 'unconfirmed_usage_user');
        }
      }
    }
  }
  const features = {};
  for (const [name, keys] of Object.entries({
    turnstile_enabled: ['turnstile_enabled', 'turnstile_check'],
    registration_enabled: ['registration_enabled', 'register_enabled'],
    email_verification_enabled: ['email_verify_enabled', 'email_verification_enabled'],
    checkin_enabled: ['checkin_enabled'],
  })) {
    const found = first(settings, keys, bool);
    features[name] = { value: found ? found.value : null, source: found ? settingsSource : null };
  }
  const checkin = { available: null, enabled: features.checkin_enabled.value, checked_in_today: null,
    turnstile_required: null, streak: null, total_checkins: null, endpoints: [] };
  const statusPaths = family === 'newapi'
    ? [`/api/user/checkin?month=${new Date().toISOString().slice(0, 7)}`]
    : family === 'sub2api' ? ['/api/v1/check-in/status', '/api/v1/play/checkin/status'] : [];
  for (const path of statusPaths) {
    const data = await get(path, auth);
    if (!data) {
      if (diagnostics.some((d) => d.source === path && d.status === 'not_open')) checkin.enabled = false;
      continue;
    }
    const checked = first(data, ['checked_in_today', 'checked_in', 'today_checked', 'has_checked_in', 'is_checked_in', 'checked'], bool);
    const enabled = first(data, ['checkin_enabled', 'enabled'], bool);
    if (!checked && (!enabled || enabled.value !== false)) { record(path, 'missing_checkin_fields'); continue; }
    const required = first(data, ['turnstile_required', 'require_turnstile'], bool);
    const streak = first(data, ['consecutive_days', 'continuous_days', 'current_streak'], number);
    const total = first(data, ['total_checkins', 'checkin_count', 'checked_days'], number);
    const endpoint = { status_path: path, available: true, checked_in_today: checked ? checked.value : null,
      enabled: enabled ? enabled.value : null, turnstile_required: required ? required.value : null,
      streak: streak ? streak.value : null, total_checkins: total ? total.value : null };
    checkin.endpoints.push(endpoint);
    checkin.available = true;
    if (enabled && checkin.enabled !== false) checkin.enabled = enabled.value;
    if (checked) checkin.checked_in_today = checked.value;
    if (required && checkin.turnstile_required !== true) checkin.turnstile_required = required.value;
    if (streak) checkin.streak = streak.value;
    if (total) checkin.total_checkins = total.value;
    // Keep probing dialects; conflicting explicit statuses require manual review.
    captureBalance(data, path, user.id || '');
  }
  if (statusPaths.length && statusPaths.every((path) => diagnostics.some((d) => d.source === path && d.status === 'not_found'))) {
    checkin.available = false;
  }
  if (balance.value === null) record('balance', 'missing_fields');
  if (checkin.enabled === false) record('checkin', 'not_open');
  if (checkin.available === null) record('checkin', 'unconfirmed');

  const credentials = {};
  // Export only an exportable candidate: page-session Authorization is metadata-only.
  // Only an independently verified non-session candidate is exportable. Unverified storage
  // candidates remain diagnostic material and must not be imported as an AccessToken.
  const exportToken = selectedToken;
  const pageSessionToken = selectedSession || (family !== 'unknown'
    ? tokens.find((candidate) => candidate.kind === 'page_session') || null : null);
  if (exportToken) credentials.access_token = exportToken.value;
  let refresh = '', refreshSource = null;
  if (family === 'sub2api' && selectedToken) {
    refresh = secret(stored.refresh_token);
    refreshSource = storedSources.refresh_token || null;
    if (!refresh) {
      for (const localUser of localUsers) {
        const found = first(localUser.data, ['refresh_token'], secret);
        if (found) { refresh = found.value; refreshSource = localUser.source; break; }
      }
    }
    if (refresh) credentials.refresh_token = refresh;
  }
  if (visibleCookie) credentials.cookie = visibleCookie;
  const userMismatch = diagnostics.some((d) => d.status === 'user_mismatch');
  const authConfirmed = !!selectedToken && !!user.id && !userMismatch;
  const pageSessionConfirmed = !!selectedSession && !!user.id && !userMismatch;
  const conflictingCheckin = checkin.endpoints.some((e) => e.checked_in_today !== null
    && e.checked_in_today !== checkin.checked_in_today);
  const enabled = family !== 'unknown' && authConfirmed && checkin.available === true
    && checkin.enabled !== false && checkin.turnstile_required !== true && !conflictingCheckin;
  // Some New API forks (session refresh token in an HttpOnly cookie, access token kept only in
  // in-memory JS state) never expose a bearer token to storage and never accept cookie auth on
  // API routes either. Cookie-mode profile calls then 401 even though the browser is logged in.
  // Naming this explicitly saves a manual re-diagnosis of the same generic "unconfirmed" message.
  const cookieRejected = family !== 'unknown' && diagnostics.some((d) =>
    d.auth === 'cookie' && d.status === 'unauthenticated'
    && (family === 'newapi' ? d.source === '/api/user/self' : d.source.startsWith('/api/v1/')));
  const noReadableToken = !tokens.length;
  if (family === 'unknown') warnings.push('站点族未知或证据冲突；账号已禁用，请核实模板。');
  if (!authConfirmed && noReadableToken && cookieRejected) {
    warnings.push('未找到可读凭据（localStorage/sessionStorage 均无 token），且 Cookie 认证被拒绝（401）；'
      + '该站点可能仅接受 Authorization: Bearer 头且将令牌保留在内存中（不写入可读存储），'
      + '需要手动在开发者工具网络面板复制请求头中的 Authorization 值，账号已禁用。');
  } else if (!authConfirmed) {
    warnings.push('导出凭据的可用性未确认；浏览器会话与可导出认证不同，账号已禁用。');
  }
  if (visibleCookie || browserSession[family]) warnings.push('仅采集 JS 可见 Cookie；HttpOnly Cookie 无法读取，不能保证导出后可登录。');
  if (checkin.available !== true) warnings.push('未确认可用签到状态接口；不会据此推断登录发奖或 OAuth 提供方。');
  if (checkin.enabled === false) warnings.push('站点明确表示未开放签到，账号已禁用。');
  if (conflictingCheckin) warnings.push('签到端点状态冲突，账号已禁用，请手动核实。');
  if (checkin.turnstile_required === true) warnings.push('签到接口要求 Turnstile 验证，账号已禁用，请核实执行方式。');
  if (balance.value === null) warnings.push('余额未知；其他已取得信息仍保留。');
  if (diagnostics.some((d) => ['timeout', 'budget_exhausted', 'verification_required', 'network_error'].includes(d.status))) {
    warnings.push('部分请求超时、受验证或网络限制；未知字段不代表零余额或已签到。');
  }
  let siteName = first(settings, ['system_name', 'site_name', 'name', 'title'], text)?.value || '';
  if (!siteName) {
    try { siteName = text(document.title).replace(/[-–|].*$/, '').trim(); } catch (_) { /* Optional title. */ }
  }
  siteName = siteName || (baseUrl ? new URL(baseUrl).host : '待核实站点');
  const info = {
    version: 1,
    family: { value: family, confidence: family === 'unknown' ? 'unknown' : 'confirmed', evidence },
    authentication: {
      browser_session: browserSession[family] ? 'confirmed' : 'unknown',
      page_session: { present: !!pageSessionToken, source: pageSessionToken ? pageSessionToken.source : null, verified: pageSessionConfirmed },
      exported_credentials: authConfirmed ? 'confirmed' : 'unknown',
      access_token: { present: !!credentials.access_token, source: exportToken ? exportToken.source : null, verified: !!selectedToken },
      refresh_token: { present: !!credentials.refresh_token, source: refreshSource, verified: false },
      cookie: { present: !!visibleCookie, completeness: 'unknown', http_only_accessible: false },
    },
    user, balance, features, checkin, diagnostics, warnings,
    requires_review: !enabled, export_kind: 'full',
    collection: { read_only: true, request_timeout_ms: REQUEST_MS, total_budget_ms: TOTAL_MS, requests: requestCount },
  };
  const login = { method: selectedToken ? 'access_token' : 'cookie' };
  if (family === 'newapi' && user.id && user.verified) login.args = { user_id: user.id };
  const entry = {
    id: (baseUrl ? new URL(baseUrl).host : 'unknown-site').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
    name: siteName, base_url: baseUrl, template: family === 'unknown' ? 'auto' : family,
    enabled, login, tasks: [{ id: 'daily', method: 'http_api', enabled }], credentials, collected_info: info,
  };
  // Metadata and preview never carry credential values, even if a response echoes one in a whitelisted label.
  const cookieValues = visibleCookie.split(';').map((part) => {
    const separator = part.indexOf('=');
    return separator < 0 ? '' : part.slice(separator + 1).trim();
  });
  const sensitive = [...new Set([...tokens.map((t) => t.value), ...Object.values(credentials), ...cookieValues])]
    .filter(Boolean).sort((a, b) => b.length - a.length);
  const scrub = (value) => {
    if (typeof value === 'string') {
      for (const item of sensitive) {
        if (item.length >= 4) value = value.split(item).join('[redacted]');
        else {
          const escaped = item.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          value = value.replace(new RegExp(`(^|[^\\w])${escaped}(?=$|[^\\w])`, 'g'), '$1[redacted]');
        }
      }
      return value;
    }
    if (Array.isArray(value)) return value.map(scrub);
    if (object(value)) return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrub(v)]));
    return value;
  };
  entry.name = scrub(entry.name);
  entry.collected_info = scrub(info);
  const preview = JSON.parse(JSON.stringify({ ...entry, credentials: {} }));
  if (preview.login.args) preview.login.args = scrub(preview.login.args);
  delete preview.credentials;
  preview.enabled = false;
  preview.tasks.forEach((task) => { task.enabled = false; });
  preview.collected_info.export_kind = 'preview';
  preview.collected_info.requires_review = true;
  const exportJSON = () => JSON.stringify(entry, null, 2);
  const copyAccount = async (copyFunction) => {
    try {
      if (typeof copyFunction === 'function') await copyFunction(exportJSON());
      else await navigator.clipboard.writeText(exportJSON());
      console.log('完整 v3 账号已复制（包含凭据），请仅导入可信管理界面。');
      return true;
    } catch (_) {
      console.warn('无法写入剪贴板。请在 Console 显式执行 autoCheckinCollector.copy(copy)，或 copy(autoCheckinCollector.exportJSON())。');
      return false;
    }
  };
  globalThis.autoCheckinCollector = Object.freeze({ copy: copyAccount, exportJSON });
  console.log(`只读采集完成：模板 ${entry.template}；导出账号${enabled ? '具备已验证认证和状态接口' : '已禁用，待核实'}。`);
  console.log('下方返回值仅为无凭据、禁用的 v3 预览；导入请显式执行 await autoCheckinCollector.copy()。');
  for (const warning of warnings) console.warn(warning);
  return preview;
})();
