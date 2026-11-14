from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from core.errors import TaskError, TransientError
from core.outcome import Verdict
from net.http import HttpClient
from scripts.tasks import freegg
from templates import registry as templates


def test_freegg_manifest_overrides_newapi_checkin_endpoints_and_confirm():
    template = templates.get("scripts/tasks/freegg.py")

    assert template.manifest.id == "freegg"
    assert template.manifest.endpoints["state"] == ""
    assert template.manifest.endpoints["submit"] == ""
    assert template.hook("confirm").__name__ == "confirm"
    assert template.hook("fetch_state").__name__ == "fetch_state"
    assert template.hook("confirm") is not templates.get("newapi").hook("confirm")
    assert [step.kind for step in template.manifest.chain] == ["http", "browser"]


@pytest.mark.parametrize("source", ["cookie", "session_cookie"])
def test_refresh_cookie_login_rotates_session_and_sets_specific_ttls(monkeypatch, source):
    requests = []
    old_cookie = "new_api_has_session=1; new_api_refresh=old-refresh-value"
    ctx = SimpleNamespace(
        base_url="https://freegg.app",
        credentials=SimpleNamespace(cookie="", session_cookie=""),
        account=SimpleNamespace(name="FreeGG", network=SimpleNamespace(referer_path="/wallet")),
        http=HttpClient(base_url="https://freegg.app"),
        endpoint=lambda _name, default="": default,
        base_headers=lambda: {}, log=lambda _message: None,
    )
    setattr(ctx.credentials, source, old_cookie)

    def fake_request(self, method, path, **kwargs):
        requests.append(dict(self.headers))
        assert method == "POST" and path == freegg.REFRESH_PATH
        assert kwargs["retry_non_idempotent"] is False
        assert self.config.max_attempts == 1
        assert self.auth_refresher is None
        headers = Message()
        headers.add_header("Set-Cookie", f"new_api_refresh=rotated-{len(requests)}; Max-Age=1728000; Path=/api/user/auth; HttpOnly")
        self._follow_set_cookie(self.base_url + path, headers)
        return {"success": True, "data": {"access_token": "test-access", "user": {"id": 1511}}}

    monkeypatch.setattr(HttpClient, "request", fake_request)
    first = freegg.login(ctx, SimpleNamespace(method="cookie"))
    assert first.credentials[source].endswith("new_api_refresh=rotated-1")
    assert first.ttl[source] == 1728000
    assert first.ttl["access_token"] == 840
    assert first.identity == {"user_id": "1511"}
    for name, value in first.credentials.items():
        setattr(ctx.credentials, name, value)
    second = freegg.login(ctx, SimpleNamespace(method="cookie"))
    assert second.credentials[source].endswith("new_api_refresh=rotated-2")
    assert requests[1]["Cookie"].endswith("new_api_refresh=rotated-1")
    assert requests[0]["Origin"] == "https://freegg.app"
    assert requests[0]["Referer"] == "https://freegg.app/wallet"
    assert "Authorization" not in requests[0]


def test_allowance_evidence_reports_success_then_already_done(monkeypatch):
    today = "2026-11-14"
    now = 1794612493
    monkeypatch.setattr(freegg, "business_date", lambda *_args: today)
    monkeypatch.setattr(freegg.time, "time", lambda: now)

    class Store:
        def __init__(self):
            self.values = {}

        def get(self, key):
            return self.values.get(key)

        def put(self, key, value):
            self.values[key] = value

    store = Store()
    ctx = SimpleNamespace(store=store)
    user = {
        "id": 1511,
        "quota": 10_039_517,
        "used_quota": 49_960_483,
        "setting": {"allowance_date": today},
    }
    log_payload = {
        "success": True,
        "data": {
            "items": [{
                "type": 1,
                "content": "Daily allowance $20.000000",
                "created_at": now,
                "request_id": "allowance-request-1",
            }],
        },
    }

    first = freegg._evaluate_allowance(
        ctx, user, log_payload, source="http_api", run_started_at=now - 10,
    )
    second = freegg._evaluate_allowance(
        ctx, user, log_payload, source="http_api", run_started_at=now + 3600,
    )

    assert first.verdict == Verdict.SUCCESS
    assert first.data["quota_awarded"] == 10_000_000
    assert second.verdict == Verdict.ALREADY_DONE


def test_freegg_confirm_does_not_call_inherited_checkin_endpoint():
    outcome = freegg.failed("unconfirmed", reason="unconfirmed")
    result = asyncio.run(freegg.confirm(SimpleNamespace(), outcome))
    assert result is outcome


@pytest.mark.parametrize("status", [None, 429])
def test_refresh_failure_is_not_replayed(monkeypatch, status):
    request = Mock(side_effect=TransientError("test failure", status=status))
    monkeypatch.setattr(HttpClient, "request", request)
    ctx = SimpleNamespace(
        base_url="https://freegg.app",
        credentials=SimpleNamespace(cookie="", session_cookie="new_api_refresh=old"),
        account=SimpleNamespace(name="FreeGG", network=SimpleNamespace(referer_path="/wallet")),
        http=HttpClient(base_url="https://freegg.app"),
        endpoint=lambda _name, default="": default,
        log=Mock(),
    )
    with pytest.raises(TaskError) as caught:
        freegg.login(ctx, SimpleNamespace(method="cookie"))
    assert request.call_count == 1
    if status == 429:
        assert caught.value.reason == "rate_limited"


@pytest.mark.parametrize("kind", ["probe", "confirm"])
@pytest.mark.parametrize("refresh_status,verdict", [(200, "ok"), (401, "rejected"), (429, "unknown"), (503, "unknown")])
def test_browser_refresh_javascript(kind, refresh_status, verdict):
    import playwright
    from login.browser_state import _PROBE_JS
    from login.oauth import _CONFIRM_LOGIN_JS

    script = """
    const x=JSON.parse(require('fs').readFileSync(0,'utf8'));
    global.localStorage={getItem:()=>null};
    global.document={cookie:'new_api_has_session=1'};
    let calls=[];
    global.fetch=async(url,opts)=>{
        calls.push({url,headers:opts.headers,method:opts.method||'GET'});
        let status=401, body={success:false};
        if(url.endsWith('/auth/refresh')) {
            status=x.status;
            body={success:status===200,data:{access_token:'memory-token',user:{id:42}}};
        } else if(opts.headers.Authorization==='Bearer memory-token') {
            if(opts.headers['New-Api-User']!=='42') throw Error('missing user');
            status=200; body={success:true,data:{id:42}};
        }
        return {ok:status===200,status,headers:{get:()=>null},text:async()=>JSON.stringify(body)};
    };
    (async()=>{const fn=eval('('+x.script+')');
        const result=await fn(['https://site.invalid','/api/user/self','',1000]);
        console.log(JSON.stringify({result,calls}));})();
    """
    node = shutil.which("node") or str(Path(playwright.__file__).parent / "driver" / "node.exe")
    result = subprocess.run(
        [node, "-e", script], input=json.dumps({"script": _PROBE_JS if kind == "probe" else _CONFIRM_LOGIN_JS, "status": refresh_status}),
        text=True, capture_output=True, check=True, timeout=10,
    )
    payload = json.loads(result.stdout)
    assert (payload["result"] if kind == "probe" else payload["result"]["status"]) == verdict
    assert sum(call["method"] == "POST" for call in payload["calls"]) == 1
    assert len(payload["calls"]) == (3 if refresh_status == 200 else 2)


@pytest.mark.parametrize("verdict", ["ok", "unknown"])
def test_browser_state_keeps_rotated_cookie_even_if_probe_is_unknown(monkeypatch, verdict):
    from contextlib import asynccontextmanager
    from login import browser_state
    from login.base import LoginContext

    async def run_case():
        initial = {"cookies": [{"name": "new_api_refresh", "value": "old", "domain": "site.invalid"}], "origins": []}
        rotated = {"cookies": [{"name": "new_api_refresh", "value": "new", "domain": "site.invalid", "expires": freegg.time.time() + 1728000}], "origins": []}
        context = SimpleNamespace(on=Mock(), remove_listener=Mock(), storage_state=AsyncMock(side_effect=[initial, rotated]))
        page = SimpleNamespace(url="https://site.invalid/")
        lease = SimpleNamespace(context=context, new_page=AsyncMock(return_value=page))

        @asynccontextmanager
        async def leasing(**_kwargs):
            yield lease

        async def probe(*_args):
            listener = context.on.call_args.args[1]
            listener(SimpleNamespace(url="https://site.invalid/api/user/auth/refresh", status=200,
                                     text=AsyncMock(return_value=json.dumps({"success": True, "data": {"access_token": "fresh", "user": {"id": 42}}}))))
            return verdict

        monkeypatch.setattr(browser_state, "settle_page", AsyncMock())
        monkeypatch.setattr(browser_state, "probe_server", probe)
        ctx = LoginContext(
            account=SimpleNamespace(base_url="https://site.invalid", origin="https://site.invalid",
                                    network=SimpleNamespace(referer_path="/"), credentials=SimpleNamespace(browser_state="state")),
            template=SimpleNamespace(manifest=SimpleNamespace(headers={})),
            http=SimpleNamespace(), browser=SimpleNamespace(lease=leasing),
        )
        state = await browser_state.BrowserStateLogin().authenticate(ctx)
        assert state.credentials["session_cookie"] == "new_api_refresh=new"
        assert state.credentials["access_token"] == "fresh"
        assert state.verified is (verdict == "ok")
        assert 1727990 < state.ttl["session_cookie"] <= 1728000
        assert context.storage_state.await_count == 2
        context.remove_listener.assert_called_once()

    asyncio.run(run_case())


def test_access_ttl_never_extends_expired_jwt(monkeypatch):
    import base64
    now = 1000000
    monkeypatch.setattr(freegg.time, "time", lambda: now)
    claims = base64.urlsafe_b64encode(json.dumps({"exp": now - 1}).encode()).decode().rstrip("=")
    assert freegg._access_token_ttl({"access_expires_at": now + 900}, f"e30.{claims}.signature") == 1



def test_browser_step_reuses_authenticated_http_without_new_navigation(monkeypatch):
    today = freegg.business_date()
    http = SimpleNamespace(get=Mock(side_effect=[
        {"success": True, "data": {"id": 42, "quota": 500000, "setting": {"allowance_date": today}}},
        {"success": True, "data": {"items": []}},
    ]))
    ctx = SimpleNamespace(http=http, log=Mock(), browser=Mock())
    outcome = asyncio.run(freegg.run_browser(ctx))
    assert outcome.verdict == Verdict.ALREADY_DONE
    ctx.browser.lease.assert_not_called()


@pytest.mark.parametrize("status", [401, 429, 503])
def test_browser_inspection_never_refreshes_or_replays_mutations(status):
    import playwright
    script = """
    const x=JSON.parse(require('fs').readFileSync(0,'utf8'));
    let calls=[];
    global.fetch=async(url,options)=>{
        calls.push({url,method:options.method||'GET'});
        return {ok:false,status:x.status,text:async()=>'{}'};
    };
    (async()=>{
        const result=await eval('('+x.script+')')(['https://site.invalid','/api/user/self','/logs','/notice','/topup','token','42','2026-11-14',1000]);
        console.log(JSON.stringify({result,calls}));
    })();
    """
    node = shutil.which("node") or str(Path(playwright.__file__).parent / "driver" / "node.exe")
    result = subprocess.run([node, "-e", script], input=json.dumps({"script": freegg._BROWSER_INSPECT_JS, "status": status}),
                            text=True, capture_output=True, check=True, timeout=10)
    payload = json.loads(result.stdout)
    assert payload["result"]["status"] == status
    assert payload["calls"] == [{"url": "https://site.invalid/api/user/self", "method": "GET"}]


def test_session_cookie_ttl_excludes_foreign_cookies_and_session_hints():
    from browser.storage_scope import site_session_cookie_ttl
    cookies = [
        {"name": "new_api_refresh", "value": "refresh", "domain": "freegg.app", "expires": 1729000},
        {"name": "new_api_has_session", "value": "1", "domain": "freegg.app", "expires": 1010},
        {"name": "cf_clearance", "value": "waf", "domain": "freegg.app", "expires": 1020},
        {"name": "session", "value": "foreign", "domain": "github.com", "expires": 1005},
    ]
    assert site_session_cookie_ttl(cookies, "https://freegg.app", now=1000) == 1728000
