"""浏览器登录态的服务端探测：只有「服务端明确拒绝」才该换下一种登录方式。

背景（实测 AnyRouter）：保存的 storage_state 里含一个**六天前就过期**的 ``session``
Cookie。它让浏览器照样过 WAF、照样拿到 Cookie，于是 ``browser_state`` 一路报「登录
成功」，接着每个业务请求都 401，而配置里排在它后面的 OAuth 兜底因为「已经登录成功」
永远不会被尝试。这里把三态判定钉死：rejected 才降级，unknown 保持原行为。
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from core.errors import LoginRequired
from login import browser_state as module
from login.base import LoginContext


BASE_URL = "https://example.test"


def make_ctx(*, page_result="rejected", user_path="/api/user/self", credentials="STATE") -> LoginContext:
    page = SimpleNamespace(
        url=BASE_URL + "/console",
        evaluate=AsyncMock(return_value=page_result),
    )
    lease = SimpleNamespace(
        new_page=AsyncMock(return_value=page),
        context=SimpleNamespace(
            storage_state=AsyncMock(return_value={
                "cookies": [{"name": "session", "value": "dead", "domain": "example.test"}],
                "origins": [],
            }),
        ),
    )
    browser = SimpleNamespace(lease=Mock(return_value=_AsyncCtx(lease)))
    template = SimpleNamespace(manifest=SimpleNamespace(endpoints={"user": user_path}))
    return LoginContext(
        account=SimpleNamespace(
            base_url=BASE_URL,
            credentials=SimpleNamespace(browser_state=credentials),
            network=SimpleNamespace(referer_path=""),
            origin=BASE_URL,
        ),
        template=template,
        http=SimpleNamespace(),
        args={},
        browser=browser,
        deadline=SimpleNamespace(remaining=lambda: 60.0),
        log=Mock(),
    )


class _AsyncCtx:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *exc):
        return False


def run(ctx):
    async def go():
        async def patched_settle(*_a, **_k):
            return None

        original = module.settle_page
        module.settle_page = patched_settle
        try:
            return await module.BrowserStateLogin().authenticate(ctx, None)
        finally:
            module.settle_page = original

    return asyncio.run(go())


@pytest.mark.parametrize("status", ["pending", "verifying", "click_unconfirmed", "rejected"])
def test_settle_cf_preserves_page_and_never_maps_to_expired_credentials(monkeypatch, status):
    from browser import bypass, waf
    from core.errors import VerificationRequired
    from solvers.registry import SolveResult

    page = SimpleNamespace(url=BASE_URL, content=AsyncMock(return_value="Just a moment"))
    lease = SimpleNamespace(goto=AsyncMock(), dismiss_popups=AsyncMock())
    result = SolveResult(False, reason=status, message="验证尚未完成", data={"status": status,
                         "stage": "observe", "preserve_page": True, "retry_allowed": False, "generation": "g1"})
    solver = AsyncMock(return_value=result)
    monkeypatch.setattr(bypass.TurnstileBypass, "solve_result", solver, raising=False)
    monkeypatch.setattr(waf, "is_waf_html", AsyncMock(return_value=False))
    with pytest.raises(VerificationRequired) as caught:
        asyncio.run(module.settle_page(make_ctx(), lease, page))
    assert caught.value.reason != "need_login"
    assert caught.value.data["preserve_page"] is True
    assert solver.await_count == 1


def test_waf_pending_stops_rounds_and_read_user_without_navigation_replay(monkeypatch):
    from browser import bypass, waf
    from solvers.registry import SolveResult

    page = SimpleNamespace(url=BASE_URL, content=AsyncMock(return_value="Just a moment"))
    goto = AsyncMock()
    result = SolveResult(False, reason="click_unconfirmed", data={"status": "click_unconfirmed",
                         "stage": "input", "preserve_page": True, "retry_allowed": False, "generation": "g1"})
    solver = AsyncMock(return_value=result)
    monkeypatch.setattr(bypass.TurnstileBypass, "solve_result", solver, raising=False)
    monkeypatch.setattr(waf, "safe_goto", goto)
    monkeypatch.setattr(waf, "fetch_self", AsyncMock(side_effect=AssertionError("未通过不能发请求")))
    assert asyncio.run(waf.read_user(page, BASE_URL)) is None
    assert goto.await_count <= 1
    assert solver.await_count == 1
    assert waf.waf_circuit(page)["fails"] == 0


def test_linuxdo_pending_stops_without_reload_or_github_fallback(monkeypatch):
    from scripts.tasks import linuxdo_browse as linuxdo
    from solvers.registry import SolveResult

    result = SolveResult(False, reason="verifying", data={"status": "verifying", "stage": "observe",
                         "preserve_page": True, "retry_allowed": False, "generation": "g1"})
    solver = AsyncMock(return_value=result)
    monkeypatch.setattr(linuxdo.bypass.TurnstileBypass, "solve_result", solver, raising=False)
    goto = AsyncMock()
    monkeypatch.setattr(linuxdo, "_safe_goto", goto)
    ctx = SimpleNamespace(log=Mock())
    notes = {}
    verdict = asyncio.run(linuxdo._verify_session(ctx, SimpleNamespace(), SimpleNamespace(), notes))
    assert verdict[:2] == (False, False)
    assert goto.await_count == 1
    assert solver.await_count == 1
    assert notes["cf_diagnostics"]["preserve_page"] is True


def test_challenge_event_inherits_scope_is_safe_and_rejected_flushes_once(capsys):
    from runtime.events import emit_challenge, event_scope, RunEvent
    from solvers.registry import SolveResult

    result = SolveResult(False, reason="rejected", data={"status": "rejected", "stage": "observe", "generation": "https://a.invalid/?state=private",
                         "token": "private", "url": "https://a.invalid/?state=private", "diagnostics": {"html": "private"}})
    with event_scope(account="a", task="daily", step="browser"):
        emit_challenge(result)
        emit_challenge(result, source="turnstile")
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert len(lines) == 1 and "private" not in lines[0]
    event = RunEvent.from_line(lines[0])
    assert (event.account, event.task, event.fields["step"], event.level) == ("a", "daily", "browser", "warning")


def test_rejected_session_raises_need_login_so_fallbacks_run():
    with pytest.raises(LoginRequired) as caught:
        run(make_ctx(page_result="rejected"))
    assert caught.value.reason == "need_login"


def test_unknown_probe_keeps_legacy_unverified_behaviour():
    state = run(make_ctx(page_result="unknown"))
    assert state.verified is False
    assert state.credentials["session_cookie"].startswith("session=dead")


def test_confirmed_session_is_marked_verified():
    state = run(make_ctx(page_result="ok"))
    assert state.verified is True


def test_missing_user_endpoint_never_probes():
    ctx = make_ctx(page_result="rejected", user_path="")
    state = run(ctx)
    assert state.verified is False


def test_probe_is_three_state_and_swallows_errors():
    from browser.storage_scope import same_origin

    # 页面不在站点 origin 时直接放弃判定，不发请求。
    ctx = make_ctx()
    page = SimpleNamespace(url="https://elsewhere.invalid/", evaluate=AsyncMock(side_effect=AssertionError))
    assert asyncio.run(module.probe_server(ctx, page)) == "unknown"
    page.evaluate.assert_not_called()
    assert same_origin(BASE_URL, BASE_URL)


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
        rotated = {"cookies": [{"name": "new_api_refresh", "value": "new", "domain": "site.invalid", "expires": time.time() + 1728000}], "origins": []}
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


def test_session_cookie_ttl_excludes_foreign_cookies_and_session_hints():
    from browser.storage_scope import site_session_cookie_ttl
    cookies = [
        {"name": "new_api_refresh", "value": "refresh", "domain": "site.invalid", "expires": 1729000},
        {"name": "new_api_has_session", "value": "1", "domain": "site.invalid", "expires": 1010},
        {"name": "cf_clearance", "value": "waf", "domain": "site.invalid", "expires": 1020},
        {"name": "session", "value": "foreign", "domain": "github.com", "expires": 1005},
    ]
    assert site_session_cookie_ttl(cookies, "https://site.invalid", now=1000) == 1728000
