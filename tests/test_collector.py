"""只读采集器：Node VM 合成站点，无网络、真实配置或浏览器存储访问。"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from gui import core


ROOT = Path(__file__).resolve().parents[1]
ACCESS = "synthetic-access-secret-value"
REFRESH = "synthetic-refresh-secret-value"
COOKIE = "session=synthetic-cookie-secret-value"


@pytest.fixture(scope="module")
def node_executable():
    node = shutil.which("node")
    if not node:
        try:
            from playwright._impl._driver import compute_driver_executable
            node = compute_driver_executable()[0]
        except ImportError:
            pytest.skip("Node.js 或 Playwright 自带 Node 运行时不可用")
    if not Path(node).is_file():
        pytest.skip("Node.js 运行时不可用")
    return str(node)


USER_BRIDGE_HARNESS = r"""
const vm = require('node:vm');
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const requests = [];
const xhrRequests = [];
const nativeFetch = function(input, init) {
  requests.push({input: String(input), init: init || null});
  return Promise.resolve('native-fetch-result');
};
class FakeXHR {
  open(method, url) {
    this.method = method;
    this.url = url;
    xhrRequests.push({kind: 'open', method, url});
  }
  setRequestHeader(name, value) {
    xhrRequests.push({kind: 'header', name, value});
  }
}
const context = {
  URL,
  location: {href: 'https://happycoding.xyz/console', origin: 'https://happycoding.xyz'},
  fetch: nativeFetch,
  XMLHttpRequest: FakeXHR,
  console,
};
context.globalThis = context;
vm.runInNewContext(input.source, context, {timeout: 2000});
(async () => {
  const fetchResult = await context.fetch('/api/user/self', {headers: {authorization: 'Bearer fetch-secret'}});
  await context.fetch('https://third-party.invalid/api', {headers: {Authorization: 'Bearer cross-origin-secret'}});
  const xhr = new context.XMLHttpRequest();
  xhr.open('GET', '/api/user/self');
  xhr.setRequestHeader('Authorization', 'Bearer xhr-secret');
  const captured = context.autoCheckinAuthBridge.getAuthorization();
  context.autoCheckinAuthBridge.clear();
  process.stdout.write(JSON.stringify({fetchResult, captured, afterClear: context.autoCheckinAuthBridge.getAuthorization(), requests, xhrRequests}));
})().catch((error) => { process.stderr.write(String(error)); process.exitCode = 1; });
"""


HARNESS = r"""
const vm = require('node:vm');
const fs = require('node:fs');
const {inspect} = require('node:util');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const {scenario, source} = input;
const requests = [], reads = [], logs = [], copied = [], timers = new Set();
const authBridge = scenario.authBridgeAuthorization === undefined ? null : {
  getAuthorization: () => scenario.authBridgeAuthorization,
  clear: () => {},
};
let clock = 0, aborts = 0;
class FakeDate extends Date {
  constructor(...args) { super(...(args.length ? args : [1900000000000 + clock])); }
  static now() { return 1900000000000 + clock; }
}
const storage = (name) => ({
  getItem(key) {
    reads.push([name, key]);
    if ((scenario.denied || []).includes(name)) throw new Error('synthetic-denied-secret');
    return Object.prototype.hasOwnProperty.call(scenario[name] || {}, key) ? scenario[name][key] : null;
  },
  setItem() { throw new Error('Storage writes forbidden'); },
  removeItem() { throw new Error('Storage writes forbidden'); },
  key() { throw new Error('Storage enumeration forbidden'); },
  get length() { throw new Error('Storage enumeration forbidden'); },
});
const context = {
  URL, AbortController, Date: FakeDate,
  location: {origin: scenario.origin || 'https://example.test'},
  document: {title: scenario.title || '模拟站点 - 控制台', cookie: scenario.cookie || ''},
  autoCheckinAuthBridge: authBridge,
  localStorage: storage('localStorage'), sessionStorage: storage('sessionStorage'),
  navigator: {clipboard: {writeText: async (value) => {
    if (scenario.clipboardDenied) throw new Error('synthetic-clipboard-secret');
    copied.push(value);
  }}},
  setTimeout(fn, ms) {
    const timer = setTimeout(() => { timers.delete(timer); clock += ms; fn(); }, 1);
    timers.add(timer);
    return timer;
  },
  clearTimeout(timer) { timers.delete(timer); clearTimeout(timer); },
  console: Object.fromEntries(['log', 'warn', 'error'].map((key) => [key, (...args) => {
    logs.push(args.map((arg) => typeof arg === 'string' ? arg : inspect(arg)).join(' '));
  }])),
  fetch: async (url, options) => {
    const parsed = new URL(url);
    requests.push({url, path: parsed.pathname, ...options, signal: undefined});
    if (parsed.origin !== context.location.origin || options.method !== 'GET'
        || options.mode !== 'same-origin' || options.redirect !== 'error'
        || !['omit', 'same-origin'].includes(options.credentials)) throw new Error('Unsafe request');
    options.signal.addEventListener('abort', () => { aborts += 1; });
    let reply = (scenario.routes || {})[parsed.pathname + parsed.search]
      || (scenario.routes || {})[parsed.pathname] || {status: 404};
    if (Array.isArray(reply)) reply = reply.length > 1 ? reply.shift() : reply[0];
    if (reply.by_token) reply = reply.by_token[options.headers.Authorization || 'cookie'] || {status: 401};
    clock += reply.advance || 0;
    if (reply.error) throw new Error('synthetic-fetch-secret');
    if (reply.hang) return new Promise(() => {});
    const status = reply.status || 200;
    return {
      status, ok: status >= 200 && status < 300, url: reply.url || url,
      redirected: !!reply.redirected, type: reply.type || 'basic',
      headers: {get: (key) => key === 'content-type' ? reply.contentType || 'application/json'
        : key === 'content-length' ? reply.contentLength || null : null},
      text: async () => {
        if (reply.bodyHang) return new Promise(() => {});
        return Object.prototype.hasOwnProperty.call(reply, 'text') ? reply.text : JSON.stringify(reply.body || {});
      },
    };
  },
};
context.window = context;
(async () => {
  const preview = await vm.runInNewContext(source, context, {timeout: 2000});
  const automaticCopies = copied.length;
  const beforeExport = JSON.stringify({logs, preview});
  let copyResult = null;
  if (scenario.copyAction === 'clipboard') copyResult = await context.autoCheckinCollector.copy();
  if (scenario.copyAction === 'callback') copyResult = await context.autoCheckinCollector.copy((value) => copied.push(value));
  // Explicit export requested by this harness, never by the collector itself.
  const exported = JSON.parse(context.autoCheckinCollector.exportJSON());
  process.stdout.write(JSON.stringify({preview, exported, requests, reads, logs, copied,
    automaticCopies, beforeExport, copyResult, clock, aborts, pendingTimers: timers.size}));
})().catch(() => { process.stderr.write('Collector VM failed'); process.exitCode = 1; });
"""


def run_user_bridge(node):
    result = subprocess.run(
        [node, "-e", USER_BRIDGE_HARNESS],
        input=json.dumps({"source": (ROOT / "collector.user.js").read_text(encoding="utf-8")}),
        capture_output=True, text=True, encoding="utf-8", timeout=15,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def collect(node, **scenario):
    result = subprocess.run(
        [node, "-e", HARNESS],
        input=json.dumps({"source": (ROOT / "collector.js").read_text(encoding="utf-8"), "scenario": scenario}),
        capture_output=True, text=True, encoding="utf-8", timeout=15,
    )
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    assert output["automaticCopies"] == 0
    assert output["pendingTimers"] == 0
    assert "credentials" not in output["preview"]
    assert output["preview"]["enabled"] is False
    assert output["preview"]["collected_info"]["export_kind"] == "preview"
    assert output["exported"]["collected_info"]["export_kind"] == "full"
    assert all(request["method"] == "GET" for request in output["requests"])
    assert all(request["mode"] == "same-origin" and request["redirect"] == "error" for request in output["requests"])
    assert len(output["requests"]) <= 18
    for request in output["requests"]:
        if "Authorization" in request["headers"]:
            assert request["credentials"] == "omit"  # Cookie 不能冒充 Bearer 可用性。
    return output


def sub_routes():
    return {
        "/api/v1/settings/public": {"body": {"code": 0, "data": {
            "site_name": "模拟 Sub2API", "turnstile_enabled": "false",
        }}},
        "/api/v1/user/profile": {"body": {"code": 0, "data": {"user": {"id": 7, "username": "tester"}}}},
        "/api/v1/auth/me": {"body": {"code": 0, "data": {"user": {"id": 7, "balance": "0"}}}},
        "/api/v1/check-in/status": {"body": {"code": 0, "data": {"checked_in_today": "false", "enabled": True}}},
    }


def test_user_script_captures_same_origin_fetch_and_xhr_only(node_executable):
    result = run_user_bridge(node_executable)
    assert result["fetchResult"] == "native-fetch-result"
    assert result["captured"] == "Bearer xhr-secret"
    assert result["afterClear"] == ""
    assert result["requests"][0]["init"]["headers"]["authorization"] == "Bearer fetch-secret"
    assert len(result["requests"]) == 2
    assert result["xhrRequests"] == [
        {"kind": "open", "method": "GET", "url": "/api/user/self"},
        {"kind": "header", "name": "Authorization", "value": "Bearer xhr-secret"},
    ]


def test_sub2api_nested_profile_zero_balance_and_safe_export(node_executable):
    result = collect(node_executable, routes=sub_routes(), cookie=COOKIE,
                     localStorage={"access_token": ACCESS, "refresh_token": REFRESH}, copyAction="clipboard")
    entry = result["exported"]
    info = entry["collected_info"]
    assert entry["template"] == "sub2api" and entry["enabled"] is True
    assert info["user"]["id"] == "7"
    assert info["balance"]["value"] == 0 and info["balance"]["unit"] == "USD"
    assert info["balance"]["source"] == "/api/v1/auth/me"
    assert info["features"]["turnstile_enabled"]["value"] is False
    assert info["checkin"]["checked_in_today"] is False
    assert entry["login"]["method"] == "access_token"
    assert "args" not in entry["tasks"][0] and "args" not in entry["login"]
    assert entry["credentials"] == {"access_token": ACCESS, "refresh_token": REFRESH, "cookie": COOKIE}
    assert result["copyResult"] is True and json.loads(result["copied"][0]) == entry
    assert all(value not in result["beforeExport"] for value in [ACCESS, REFRESH, COOKIE, ACCESS[:8], "session="])
    assert all(value not in json.dumps(info) for value in [ACCESS, REFRESH, COOKIE])
    assert not any(request["path"] == "/api/v1/usage" for request in result["requests"])


def test_newapi_ignores_mixed_token_keys_and_preserves_quota_units(node_executable):
    routes = {
        "/api/status": {"body": {"success": True, "data": {"system_name": "模拟 NewAPI", "quota_per_unit": 500000}}},
        "/api/user/self": {"body": {"success": True, "data": {"id": 31, "quota": 0, "github_id": "bound", "password": ""}}},
        "/api/user/checkin": {"body": {"success": True, "data": {"stats": {"checked_in_today": "false"}}}},
    }
    result = collect(node_executable, routes=routes, localStorage={"token": ACCESS, "user": '{"id":31}'})
    entry = result["exported"]
    assert entry["template"] == "newapi"
    assert entry["login"] == {"method": "access_token", "args": {"user_id": "31"}}
    assert entry["collected_info"]["balance"]["value"] == 0
    assert entry["collected_info"]["balance"]["unit"] == "quota"
    assert "converted" not in entry["collected_info"]["balance"]
    requests = [item for item in result["requests"] if item["path"] == "/api/user/self"]
    assert requests[0]["headers"]["New-Api-User"] == "31"
    assert "provider" not in entry["login"] and entry["tasks"][0]["method"] == "http_api"
    assert not any(item["path"].startswith("/api/v1/user") for item in result["requests"])


@pytest.mark.parametrize("value,expected", [(False, False), ("false", False), (0, False), ("0", False),
                                            (True, True), ("true", True), (1, True), ("1", True)])
def test_newapi_auth_bridge_supplies_transient_bearer_without_storage_token(node_executable):
    routes = {
        "/api/status": {"body": {"success": True, "data": {
            "system_name": "模拟 NewAPI", "quota_per_unit": 500000, "checkin_enabled": True,
        }}},
        "/api/user/self": {"by_token": {
            "cookie": {"status": 401},
            f"Bearer {ACCESS}": {"body": {"success": True, "data": {"id": 31, "quota": 0}}},
        }},
        "/api/user/checkin": {"by_token": {
            f"Bearer {ACCESS}": {"body": {"success": True, "data": {
                "stats": {"checked_in_today": False},
            }}},
        }},
    }
    result = collect(node_executable, routes=routes, authBridgeAuthorization=f"Bearer {ACCESS}")
    entry = result["exported"]
    assert entry["enabled"] is True
    assert entry["credentials"] == {"access_token": ACCESS}
    assert entry["collected_info"]["authentication"]["access_token"] == {
        "present": True, "source": "auth-bridge", "verified": True,
    }
    assert all(ACCESS not in value for value in [result["beforeExport"], json.dumps(result["preview"])])
    self_requests = [item for item in result["requests"] if item["path"] == "/api/user/self"]
    assert self_requests[-1]["headers"]["Authorization"] == f"Bearer {ACCESS}"
    assert self_requests[-1]["credentials"] == "omit"


def test_invalid_auth_bridge_is_ignored(node_executable):
    routes = {
        "/api/status": {"body": {"success": True, "data": {"system_name": "模拟 NewAPI"}}},
        "/api/user/self": {"status": 401},
    }
    result = collect(node_executable, routes=routes, authBridgeAuthorization="Basic not-a-bearer")
    entry = result["exported"]
    assert entry["enabled"] is False
    assert "access_token" not in entry["credentials"]
    assert any("未找到可读凭据" in warning for warning in entry["collected_info"]["warnings"])


def test_explicit_boolean_dialects(node_executable, value, expected):
    routes = sub_routes()
    routes["/api/v1/check-in/status"] = {"body": {"code": "0", "data": {"checked_in_today": value}}}
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    assert result["exported"]["collected_info"]["checkin"]["checked_in_today"] is expected


@pytest.mark.parametrize("reply,status", [
    ({"status": 401}, "unauthenticated"), ({"status": 403}, "forbidden"),
    ({"status": 429}, "rate_limited"), ({"status": 503}, "server_error"),
    ({"status": 405}, "http_error"), ({"error": True}, "network_error"),
    ({"text": "<html>Cloudflare just a moment</html>", "status": 403}, "verification_required"),
    ({"text": "<html>Login synthetic-response-secret</html>"}, "html_response"),
    ({"body": {"success": "false", "data": {"checked_in_today": True}}}, "business_rejected"),
    ({"body": {"code": 9, "message": "synthetic-response-secret", "data": {"checked_in_today": True}}}, "business_rejected"),
    ({"body": {"code": 0, "data": {"success": False, "checked_in_today": True}}}, "business_rejected"),
    ({"body": {"code": True, "data": {"checked_in_today": True}}}, "business_rejected"),
    ({"body": {"code": "TOKEN_EXPIRED"}}, "unauthenticated"),
    ({"body": {"success": False, "message": "checkin disabled"}}, "not_open"),
    ({"body": {}}, "missing_checkin_fields"),
    ({"body": {"code": 0, "data": {"checked_in_today": "unknown"}}}, "missing_checkin_fields"),
    ({"text": "not-json synthetic-response-secret"}, "invalid_json"),
    ({"body": [1, 2]}, "invalid_shape"),
    ({"contentLength": "2000000"}, "response_too_large"),
    ({"redirected": True, "url": "https://foreign.invalid"}, "redirect_blocked"),
])
def test_failed_status_is_not_an_endpoint_confirmation(node_executable, reply, status):
    routes = sub_routes()
    routes["/api/v1/check-in/status"] = reply
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    entry = result["exported"]
    assert entry["enabled"] is False
    assert entry["collected_info"]["checkin"]["available"] is None
    assert entry["collected_info"]["checkin"]["checked_in_today"] is None
    assert entry["collected_info"]["balance"]["value"] == 0
    assert status in {item["status"] for item in entry["collected_info"]["diagnostics"]}
    assert "synthetic-response-secret" not in json.dumps(entry)


def test_unknown_family_is_disabled_and_storage_is_allowlisted(node_executable):
    result = collect(node_executable, localStorage={"token": ACCESS, "arbitrary-secret": "must-not-read"})
    entry = result["exported"]
    assert entry["template"] == "auto" and entry["enabled"] is False
    assert entry["collected_info"]["family"]["value"] == "unknown"
    assert entry["collected_info"]["balance"]["value"] is None
    assert entry["collected_info"]["checkin"]["available"] is None
    assert "access_token" not in entry["credentials"]
    assert all(key in {"user", "user_info", "auth_user", "auth_token", "access_token", "token", "jwt", "refresh_token"}
               for _, key in result["reads"])


def test_cookie_success_does_not_verify_exportable_auth_or_guess_oauth(node_executable):
    routes = {
        "/api/status": {"body": {"success": True, "data": {"system_name": "NewAPI"}}},
        "/api/user/self": {"body": {"success": True, "data": {"id": 1, "quota": 10, "password": "", "github_id": "bound"}}},
        "/api/user/checkin": {"body": {"success": True, "data": {"stats": {"checked_in_today": False}}}},
    }
    result = collect(node_executable, routes=routes, cookie=COOKIE)
    entry = result["exported"]
    assert entry["enabled"] is False
    assert entry["collected_info"]["authentication"]["browser_session"] == "confirmed"
    assert entry["collected_info"]["authentication"]["exported_credentials"] == "unknown"
    assert entry["login"]["method"] == "cookie" and "provider" not in entry["login"]
    assert entry["tasks"][0]["method"] != "relogin"
    assert not any(key in json.dumps(entry["collected_info"]) for key in ["github_id", '"password"'])


def test_newapi_cookie_only_auth_rejection_gets_a_specific_diagnostic(node_executable):
    """一些 New API fork 只认 Authorization Bearer 头、把 access token 只放内存不落盘，
    浏览器会话即便有效也无法通过采集器的 Cookie 探测。没有可读 token、且 Cookie 探测
    明确被拒绝（401）时，需要给出可操作的具体原因，而不是笼统的「未确认」。"""
    routes = {
        "/api/status": {"body": {"success": True, "data": {"system_name": "NewAPI"}}},
        "/api/user/self": {"status": 401},
    }
    result = collect(node_executable, routes=routes)
    entry = result["exported"]
    assert entry["collected_info"]["family"]["value"] == "newapi"
    assert entry["enabled"] is False
    assert entry["collected_info"]["authentication"]["exported_credentials"] == "unknown"
    warnings = entry["collected_info"]["warnings"]
    assert any("Authorization: Bearer" in warning and "内存" in warning for warning in warnings)
    # 若已发现存储凭据候选，就不该误报「无可读凭据」这条更具体的原因。
    result_with_token = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    assert not any("Authorization: Bearer" in warning for warning
                   in result_with_token["exported"]["collected_info"]["warnings"])


def test_failed_bearer_is_not_hidden_by_cookie_success(node_executable):
    routes = sub_routes()
    routes["/api/v1/user/profile"] = {"status": 401}
    routes["/api/v1/auth/me"] = {"status": 401}
    result = collect(node_executable, routes=routes, cookie=COOKIE, localStorage={"access_token": ACCESS})
    assert result["exported"]["enabled"] is False
    assert result["exported"]["collected_info"]["authentication"]["exported_credentials"] == "unknown"


@pytest.mark.parametrize("value", [True, False, None, "", " ", "NaN", "Infinity", "0x10", {}, []])
def test_invalid_balance_never_coerces_to_zero(node_executable, value):
    routes = sub_routes()
    routes["/api/v1/auth/me"]["body"]["data"]["user"]["balance"] = value
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    assert result["exported"]["collected_info"]["balance"]["value"] is None


def test_matching_usage_user_and_explicit_currency(node_executable):
    routes = sub_routes()
    routes["/api/v1/auth/me"] = {"status": 404}
    routes["/api/v1/usage"] = {"body": {"code": 0, "data": {"items": [{"user": {
        "id": 7, "balance": "2.50", "currency": "CNY",
    }}]}}}
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    assert result["exported"]["collected_info"]["balance"]["value"] == 2.5
    assert result["exported"]["collected_info"]["balance"]["unit"] == "CNY"
    routes["/api/v1/usage"]["body"]["data"]["items"][0]["user"]["id"] = 8
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    assert result["exported"]["collected_info"]["balance"]["value"] is None


def test_false_public_feature_and_conflicting_dialects_disable_account(node_executable):
    routes = sub_routes()
    routes["/api/v1/settings/public"]["body"]["data"]["checkin_enabled"] = "false"
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    assert result["exported"]["enabled"] is False
    assert result["exported"]["collected_info"]["checkin"]["enabled"] is False
    del routes["/api/v1/settings/public"]["body"]["data"]["checkin_enabled"]
    routes["/api/v1/play/checkin/status"] = {"body": {"code": 0, "data": {"checked_in_today": True}}}
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    assert result["exported"]["enabled"] is False
    assert len(result["exported"]["collected_info"]["checkin"]["endpoints"]) == 2


@pytest.mark.parametrize("reply", [{"hang": True}, {"bodyHang": True}])
def test_fetch_and_body_deadlines_retain_partial_data(node_executable, reply):
    routes = sub_routes()
    routes["/api/v1/auth/me"] = reply
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    info = result["exported"]["collected_info"]
    assert info["user"]["id"] == "7"
    assert info["balance"]["value"] is None
    assert any(item["status"] == "timeout" for item in info["diagnostics"])
    assert result["aborts"] >= 1


def test_total_budget_stops_new_requests(node_executable):
    routes = sub_routes()
    routes["/api/v1/user/profile"]["advance"] = 15500
    routes["/api/v1/auth/me"] = {"hang": True}
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    assert result["clock"] == 16000
    assert any(item["status"] == "budget_exhausted" for item in result["exported"]["collected_info"]["diagnostics"])
    assert not any(request["path"].endswith("/check-in/status") for request in result["requests"])


def test_session_storage_remains_available_when_local_storage_denied(node_executable):
    result = collect(node_executable, routes=sub_routes(), denied=["localStorage"],
                     sessionStorage={"access_token": json.dumps(ACCESS)})
    assert result["exported"]["credentials"]["access_token"] == ACCESS
    assert any(item["source"] == "localStorage" and item["status"] == "unavailable"
               for item in result["exported"]["collected_info"]["diagnostics"])


def test_clipboard_failure_is_safe_and_manual_callback_copies_full_v3(node_executable):
    result = collect(node_executable, routes=sub_routes(), localStorage={"access_token": ACCESS},
                     clipboardDenied=True, copyAction="clipboard")
    assert result["copyResult"] is False and result["copied"] == []
    assert ACCESS not in " ".join(result["logs"])
    assert "autoCheckinCollector.copy(copy)" in " ".join(result["logs"])
    result = collect(node_executable, routes=sub_routes(), localStorage={"access_token": ACCESS},
                     clipboardDenied=True, copyAction="callback")
    assert result["copyResult"] is True
    assert json.loads(result["copied"][0])["credentials"]["access_token"] == ACCESS


def test_mock_collector_output_roundtrips_gui_import_without_files(node_executable, tmp_path):
    result = collect(node_executable, routes=sub_routes(), localStorage={"access_token": ACCESS, "refresh_token": REFRESH})
    entry = result["exported"]
    payload = {"version": 3, "accounts": []}
    imported = core.import_accounts(payload, json.dumps(entry), path=tmp_path / "synthetic.json")
    assert imported["accounts"] == [entry]
    assert payload == {"version": 3, "accounts": []}
    assert not (tmp_path / "synthetic.json").exists()
    repeated = core.import_accounts(imported, json.dumps(entry), path=tmp_path / "synthetic.json")
    assert repeated["accounts"][1]["id"] != entry["id"]
    assert repeated["accounts"][1]["collected_info"] == entry["collected_info"]
    assert repeated["accounts"][1]["credentials"] == entry["credentials"]


def test_partial_profile_preserves_zero_without_claiming_authentication(node_executable):
    routes = sub_routes()
    routes["/api/v1/user/profile"] = {"body": {"code": 0, "data": {"balance": 0}}}
    routes["/api/v1/auth/me"] = {"status": 404}
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    entry = result["exported"]
    assert entry["collected_info"]["balance"]["value"] == 0
    assert entry["collected_info"]["user"]["id"] is None
    assert entry["enabled"] is False
    assert entry["collected_info"]["authentication"]["exported_credentials"] == "unknown"


def test_newapi_quota_conversion_requires_explicit_currency(node_executable):
    routes = {
        "/api/status": {"body": {"success": True, "data": {
            "system_name": "NewAPI", "quota_per_unit": "500000", "quota_display_type": "USD",
        }}},
        "/api/user/self": {"body": {"success": True, "data": {"user": {"id": 9, "quota": "250000"}}}},
    }
    result = collect(node_executable, routes=routes)
    balance = result["exported"]["collected_info"]["balance"]
    assert balance["value"] == 250000 and balance["unit"] == "quota"
    assert balance["converted"] == {"value": 0.5, "unit": "USD", "source": "/api/status"}
    assert result["exported"]["collected_info"]["checkin"]["available"] is False


def test_sub2api_quota_is_not_implicitly_usd(node_executable):
    routes = sub_routes()
    routes["/api/v1/auth/me"]["body"]["data"]["user"] = {"id": 7, "quota": "0"}
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    balance = result["exported"]["collected_info"]["balance"]
    assert balance["value"] == 0 and balance["unit"] == "quota"


def test_checkin_verification_and_counters_are_metadata_only(node_executable):
    routes = sub_routes()
    routes["/api/v1/check-in/status"]["body"]["data"].update({
        "turnstile_required": "true", "current_streak": "0", "total_checkins": "12",
    })
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    entry = result["exported"]
    checkin = entry["collected_info"]["checkin"]
    assert checkin["turnstile_required"] is True
    assert checkin["streak"] == 0 and checkin["total_checkins"] == 12
    assert entry["enabled"] is False and "args" not in entry["tasks"][0]


def test_conflicting_family_evidence_is_not_resolved_using_token_key(node_executable):
    routes = sub_routes()
    routes["/api/status"] = {"body": {"success": True, "data": {"system_name": "Other API"}}}
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    entry = result["exported"]
    assert entry["template"] == "auto" and entry["enabled"] is False
    assert entry["collected_info"]["family"]["value"] == "unknown"


@pytest.mark.parametrize("status", [520, 522, 524, 530])
def test_cf_origin_pages_are_server_errors_not_captcha(node_executable, status):
    routes = sub_routes()
    routes["/api/v1/check-in/status"] = {"status": status, "contentType": "text/html",
        "text": "<html><title>Cloudflare origin error</title><div id='cf-error-details'>Cloudflare</div></html>"}
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    info = result["exported"]["collected_info"]
    assert any(item["source"] == "/api/v1/check-in/status" and item["status"] == "server_error"
               for item in info["diagnostics"])
    assert result["exported"]["enabled"] is False


@pytest.mark.parametrize("message,status", [
    ("Cloudflare could not establish a TCP connection to the origin server.", "server_error"),
    ("The host is configured as a Cloudflare Tunnel, but Cloudflare is currently unable to reach it.", "server_error"),
    ('Post "https://challenges.cloudflare.com/turnstile/v0/siteverify": unexpected EOF', "network_error"),
])
def test_business_json_upstream_failures_are_not_verification(node_executable, message, status):
    routes = sub_routes()
    routes["/api/v1/check-in/status"] = {"body": {"success": False, "message": message}}
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    assert any(item["source"] == "/api/v1/check-in/status" and item["status"] == status
               for item in result["exported"]["collected_info"]["diagnostics"])


def test_real_cf_503_challenge_still_has_verification_diagnostic(node_executable):
    routes = sub_routes()
    routes["/api/v1/check-in/status"] = {"status": 503, "contentType": "text/html",
        "text": "<html><title>Just a moment...</title><body>cf_chl_opt</body></html>"}
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    assert any(item["source"] == "/api/v1/check-in/status" and item["status"] == "verification_required"
               for item in result["exported"]["collected_info"]["diagnostics"])


def test_stored_id_cannot_validate_an_anonymous_token_response(node_executable):
    routes = {
        "/api/status": {"body": {"success": True, "data": {"system_name": "NewAPI"}}},
        "/api/user/self": {"body": {"success": True, "data": {"id": 0, "username": "guest", "quota": 0}}},
        "/api/user/checkin": {"body": {"success": True, "data": {"checked_in_today": False}}},
    }
    result = collect(node_executable, routes=routes,
                     localStorage={"access_token": ACCESS, "user": json.dumps({"id": 99})})
    assert result["exported"]["enabled"] is False
    assert result["exported"]["collected_info"]["authentication"]["access_token"]["verified"] is False


def test_echoed_token_in_user_id_is_not_exposed_in_preview_args(node_executable):
    routes = {
        "/api/status": {"body": {"success": True, "data": {"system_name": "NewAPI"}}},
        "/api/user/self": {"body": {"success": True, "data": {"id": ACCESS, "quota": 0}}},
        "/api/user/checkin": {"body": {"success": True, "data": {"checked_in_today": False}}},
    }
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS})
    assert ACCESS not in result["beforeExport"]
    assert result["exported"]["credentials"]["access_token"] == ACCESS


def test_echoed_credentials_do_not_enter_metadata_or_preview(node_executable):
    routes = sub_routes()
    routes["/api/v1/settings/public"]["body"]["data"]["site_name"] = "Echo " + ACCESS
    routes["/api/v1/user/profile"]["body"]["data"]["user"].update({
        "display_name": ACCESS, "password": "synthetic-password-secret", "refresh_token": REFRESH,
    })
    result = collect(node_executable, routes=routes, localStorage={"access_token": ACCESS, "refresh_token": REFRESH})
    assert ACCESS not in result["beforeExport"] and REFRESH not in result["beforeExport"]
    assert "synthetic-password-secret" not in json.dumps(result["exported"])
    assert "[redacted]" in result["exported"]["name"]


@pytest.mark.parametrize("user_id", [0, "0", -1, "-1", "00"])
@pytest.mark.parametrize("family", ["newapi", "sub2api"])
def test_nonpositive_user_ids_never_verify_authentication(node_executable, user_id, family):
    if family == "sub2api":
        routes = sub_routes()
        routes["/api/v1/user/profile"]["body"]["data"]["user"]["id"] = user_id
        routes["/api/v1/auth/me"]["body"]["data"]["user"]["id"] = user_id
    else:
        routes = {
            "/api/status": {"body": {"success": True, "data": {"system_name": "NewAPI"}}},
            "/api/user/self": {"body": {"success": True, "data": {"id": user_id, "quota": 0}}},
            "/api/user/checkin": {"body": {"success": True, "data": {"checked_in_today": False}}},
        }
    result = collect(node_executable, routes=routes, localStorage={
        "access_token": ACCESS, "user": json.dumps({"id": user_id}),
    })
    entry = result["exported"]
    assert entry["enabled"] is False
    assert entry["collected_info"]["user"]["id"] is None
    assert entry["collected_info"]["authentication"]["exported_credentials"] == "unknown"
    assert entry["collected_info"]["balance"]["value"] == 0
    assert "user_id" not in entry["login"].get("args", {})


def test_cookie_subvalues_are_redacted_without_changing_full_credentials(node_executable):
    routes = sub_routes()
    session = "synthetic-session-secret=="
    csrf = "synthetic-csrf-secret"
    cookie = f"session={session}; csrf=  {csrf}  ; empty="
    routes["/api/v1/settings/public"]["body"]["data"]["site_name"] = "Site " + session
    routes["/api/v1/user/profile"]["body"]["data"]["user"].update({
        "username": csrf, "display_name": session,
    })
    result = collect(node_executable, routes=routes, cookie=cookie, localStorage={"access_token": ACCESS})
    entry = result["exported"]
    assert entry["credentials"]["cookie"] == cookie
    for value in [session, csrf]:
        assert value not in result["beforeExport"]
        assert value not in json.dumps(entry["collected_info"])
        assert value not in entry["name"]
    assert entry["name"] == "Site [redacted]"
    assert entry["collected_info"]["user"]["username"] == "[redacted]"


def test_short_cookie_values_only_redact_whole_words(node_executable):
    routes = sub_routes()
    routes["/api/v1/settings/public"]["body"]["data"]["site_name"] = "a Sample"
    routes["/api/v1/user/profile"]["body"]["data"]["user"]["username"] = "a"
    result = collect(node_executable, routes=routes, cookie="session=a", localStorage={"access_token": ACCESS})
    entry = result["exported"]
    assert entry["name"] == "[redacted] Sample"
    assert entry["collected_info"]["family"]["value"] == "sub2api"
    assert entry["collected_info"]["user"]["username"] == "[redacted]"
