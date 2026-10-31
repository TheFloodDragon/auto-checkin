"""浏览器认证代次、凭据交接和 HTTP 续期的离线回归；不连接真实账号。"""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from browser import bypass, popups, runtime_loop, state as browser_state
from browser.service import BrowserService, decode_state, encode_state
from config import schema
from config.overlay import CachePolicy, Overlay
from core.errors import LoginRequired
from core.flow import StageMode, StagePlan
from core.outcome import failed, success
from login import LOGINS
from login.base import LoginContext, LoginState, READY
from login.broker import LoginBroker
from net.http import HttpClient
from runtime import engine
from templates import registry as templates


BASE_URL = "https://renewal.invalid"
AT0 = "header.original.signature"
AT1 = "header.rotated.signature"
AT2 = "header.latest.signature"


def _storage(*, access=AT0, refresh="rt-original", cookie="session-original"):
    values = []
    if access:
        values.append({"name": "access_token", "value": access})
    if refresh:
        values.append({"name": "refresh_token", "value": refresh})
    return {
        "cookies": [{
            "name": "session", "value": cookie, "domain": "renewal.invalid", "path": "/",
            "expires": -1, "httpOnly": True, "secure": True, "sameSite": "Lax",
        }] if cookie else [],
        "origins": [{"origin": BASE_URL, "localStorage": values}] if values else [],
    }


@pytest.fixture
def memory_browser(monkeypatch):
    memory = SimpleNamespace(storage=_storage(), contexts=[])

    async def launch(**_kwargs):
        page = SimpleNamespace(url=BASE_URL, close=AsyncMock())
        context = SimpleNamespace(
            storage_state=AsyncMock(side_effect=lambda: deepcopy(memory.storage)),
            new_page=AsyncMock(return_value=page),
            close=AsyncMock(),
        )
        memory.contexts.append(context)
        return object(), context

    monkeypatch.setattr(bypass, "launch_camoufox", launch)
    monkeypatch.setattr(browser_state, "restore_storage_state", AsyncMock())
    monkeypatch.setattr(runtime_loop, "safe_close_browser", AsyncMock())
    monkeypatch.setattr(runtime_loop, "safe_close_page", AsyncMock())
    monkeypatch.setattr(popups, "setup_popup_guard", AsyncMock())
    return memory


def _case(tmp_path, *, browser=None, credentials=None, policy=CachePolicy.COMPATIBLE):
    spec = schema.parse_account({
        "id": "renewal-test", "name": "renewal-test", "base_url": BASE_URL,
        "template": "sub2api", "tasks": [{"id": "daily"}],
        "credentials": credentials or {
            "access_token": AT0, "refresh_token": "rt-original", "cookie": "manual=keep",
            "browser_state": encode_state(_storage()),
        },
    })
    overlay = Overlay(path=tmp_path / "overlay.json", policy=policy).load()
    holder = {"account": overlay.apply(spec)}
    http = HttpClient(base_url=BASE_URL)
    login_ctx = LoginContext(
        account=holder["account"], template=templates.get("sub2api"), http=http,
        browser=browser, capabilities=frozenset({"browser"}),
    )
    ctx = SimpleNamespace(http=http, login_handle=None, browser_service=browser)
    return spec, overlay, holder, login_ctx, ctx


def _plan(*methods):
    return StagePlan(stage="login", mode=StageMode.CHAIN, candidates=methods, source="chain")


@pytest.mark.parametrize("storage", [_storage(), _storage(access="", refresh=""), _storage(cookie="")])
def test_unverified_tokens_or_task_success_never_authorize_browser_persistence(memory_browser, storage):
    memory_browser.storage = storage
    saved = Mock()
    service = BrowserService(base_url=BASE_URL, persist=saved)

    async def scenario():
        service.note_outcome(success("HTTP 已成功"))
        async with service.lease():
            service.note_outcome(success("公开页面任务已成功"))
        await service.aclose()

    asyncio.run(scenario())
    saved.assert_not_called()
    memory_browser.contexts[0].storage_state.assert_not_awaited()


@pytest.mark.parametrize("reason", ["", "need_verification", "need_config", "network_error", "not_open"])
def test_confirmed_browser_session_survives_non_authentication_failures(memory_browser, reason):
    memory_browser.storage = _storage(access="", refresh="")
    saved = Mock()
    service = BrowserService(base_url=BASE_URL, persist=saved)

    async def scenario():
        async with service.lease() as lease:
            lease.mark_authenticated()
            service.note_outcome(failed("业务步骤失败", reason=reason) if reason else success("业务已完成"))
        await service.aclose()

    asyncio.run(scenario())
    saved.assert_called_once()
    session = saved.call_args.args[0]
    assert session.auth_verified
    assert decode_state(session.state_text) == memory_browser.storage
    assert not session.access_token and not session.refresh_token


@pytest.mark.parametrize("reconfirm", [False, True])
def test_need_login_revokes_evidence_until_explicit_reconfirmation(memory_browser, reconfirm):
    saved = Mock()
    service = BrowserService(base_url=BASE_URL, persist=saved)

    async def scenario():
        async with service.lease():
            service.mark_authenticated()
            service.note_outcome(failed("会话过期", reason="need_login"))
            service.note_outcome(success("另一个纯 HTTP 任务成功"))
            if reconfirm:
                service.mark_authenticated()
                service.note_outcome(failed("业务验证码未过", reason="need_verification"))
        await service.aclose()

    asyncio.run(scenario())
    assert saved.call_count == int(reconfirm)


@pytest.mark.parametrize("different_state", [False, True])
def test_only_actual_restore_invalidates_current_generation(memory_browser, different_state):
    saved = Mock()
    service = BrowserService(base_url=BASE_URL, persist=saved)
    original = encode_state(_storage())
    other = encode_state(_storage(access=AT1, refresh="rt-new")) if different_state else original

    async def scenario():
        async with service.lease(state_text=original):
            service.mark_authenticated()
        async with service.lease(state_text=other):
            service.note_outcome(success("本轮任务成功"))
        await service.aclose()

    asyncio.run(scenario())
    assert saved.call_count == int(not different_state)
    assert browser_state.restore_storage_state.await_count == (2 if different_state else 1)


def test_closing_and_reopening_does_not_reuse_authentication_proof(memory_browser):
    saved = Mock()
    service = BrowserService(base_url=BASE_URL, persist=saved)

    async def scenario():
        async with service.lease():
            service.mark_authenticated()
        await service.aclose(persist=False)
        async with service.lease():
            service.note_outcome(success("下一轮 HTTP 成功"))
        await service.aclose()

    asyncio.run(scenario())
    saved.assert_not_called()
    assert len(memory_browser.contexts) == 2
    for context in memory_browser.contexts:
        context.close.assert_awaited_once()


def test_authentication_change_during_export_discards_inflight_snapshot(memory_browser):
    saved = Mock()
    service = BrowserService(base_url=BASE_URL, persist=saved)

    async def export():
        service.note_outcome(failed("导出中途登录失效", reason="need_login"))
        service.mark_authenticated()
        return _storage()

    async def scenario():
        async with service.lease():
            service.mark_authenticated()
            memory_browser.contexts[0].storage_state.side_effect = export
        await service.aclose()

    asyncio.run(scenario())
    saved.assert_not_called()


@pytest.mark.parametrize("verified,browser_backed", [(False, True), (True, True), (True, False)])
def test_broker_only_propagates_verified_browser_evidence(memory_browser, tmp_path, verified, browser_backed):
    saved = Mock()
    service = BrowserService(base_url=BASE_URL, persist=saved)
    _spec, _overlay, _holder, login_ctx, _ctx = _case(tmp_path, browser=service)
    writer = Mock()

    class Method:
        id = "browser_state"
        requires = frozenset({"browser"}) if browser_backed else frozenset()

        def available(self, _ctx, _option):
            return READY

        def authenticate(self, _ctx, _option):
            return LoginState(
                method=self.id, verified=verified,
                credentials={"access_token": AT1}, origin="browser" if browser_backed else "refresh",
            )

    async def scenario():
        async with service.lease():
            result = await LoginBroker({"browser_state": Method()}).establish(
                login_ctx, _plan("browser_state"), on_credentials=writer,
            )
            assert result.state is not None
            service.note_outcome(failed("业务验证码", reason="need_verification"))
        await service.aclose()

    asyncio.run(scenario())
    assert saved.call_count == int(verified and browser_backed)
    assert writer.call_count == int(verified or not browser_backed)
    assert login_ctx.credentials.access_token == AT1
    assert login_ctx.credentials.refresh_token == "rt-original"


def test_server_confirmed_cached_oauth_cookie_is_persisted_after_business_challenge(memory_browser, tmp_path, monkeypatch):
    from login import oauth

    memory_browser.storage = _storage(access="", refresh="")
    spec, overlay, holder, login_ctx, _ctx = _case(tmp_path)
    spec = replace(spec, login=replace(spec.login, provider="linuxdo", account="shared"))
    holder["account"] = overlay.apply(spec)
    service = engine._make_browser(holder["account"], overlay, spec, log=lambda _m: None)
    login_ctx.account = holder["account"]
    login_ctx.browser = service
    login_ctx.oauth_state = lambda _provider, _account: encode_state({"cookies": [], "origins": []})
    _ctx.browser_service = service
    login_ctx.install_state = lambda attempt_ctx, prepared: engine._apply_login(
        _ctx, attempt_ctx, prepared, _plan("oauth"), spec, holder, overlay,
    )
    monkeypatch.setattr(HttpClient, "_send", lambda *_args, **_kwargs: {"id": 7, "quota": 100})
    monkeypatch.setattr(oauth, "settle_page", AsyncMock())
    monkeypatch.setattr(oauth, "_server_confirms_login", AsyncMock(return_value=True))

    async def scenario():
        result = await LOGINS.establish(
            login_ctx, _plan("oauth"),
            on_credentials=engine._credential_writer(spec, holder, overlay, browser=service),
        )
        assert result.state is not None and result.state.verified
        service.note_outcome(failed("业务验证码尚未通过", reason="need_verification"))
        await service.aclose()

    asyncio.run(scenario())
    resolved = Overlay(path=overlay.path).load().apply(spec)
    assert decode_state(resolved.credentials.browser_state) == memory_browser.storage
    assert resolved.credentials.session_cookie == "session=session-original"


@pytest.mark.parametrize("update", ["http", "other_process", "clear_refresh"])
def test_late_browser_snapshot_cannot_overwrite_new_credentials(memory_browser, tmp_path, update):
    spec, overlay, holder, _login_ctx, _ctx = _case(tmp_path)
    overlay.record_credentials(
        spec, access_token=AT0, refresh_token="rt-original", browser_state=encode_state(_storage()),
    )
    logs = []
    service = engine._make_browser(holder["account"], overlay, spec, log=logs.append)

    async def scenario():
        async with service.lease():
            service.mark_authenticated()
            if update == "http":
                engine._credential_writer(spec, holder, overlay)(
                    {"access_token": AT1, "refresh_token": "rt-new"}, "refresh",
                )
            else:
                external = Overlay(path=overlay.path).load()
                if update == "clear_refresh":
                    external.record_credentials(spec, access_token=AT1, clear=("refresh_token",))
                else:
                    external.record_credentials(spec, access_token=AT1, refresh_token="rt-new")
        before = overlay.path.read_bytes()
        await service.aclose()
        assert overlay.path.read_bytes() == before

    asyncio.run(scenario())
    resolved = Overlay(path=overlay.path).load().apply(spec)
    assert resolved.credentials.access_token == AT1
    assert resolved.credentials.refresh_token == ("" if update == "clear_refresh" else "rt-new")
    assert not any("已续存到" in line for line in logs)


@pytest.mark.parametrize("refresh", ["rt-new", ""])
def test_confirmed_browser_handoff_can_persist_its_own_new_snapshot(memory_browser, tmp_path, refresh):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path)
    service = engine._make_browser(holder["account"], overlay, spec, log=lambda _m: None)
    login_ctx.browser = ctx.browser_service = service
    accept = engine._browser_credential_writer(ctx, login_ctx, spec, holder, overlay, _plan("access_token", "refresh"))
    memory_browser.storage = _storage(access=AT1, refresh=refresh)

    async def scenario():
        async with service.lease():
            assert accept({"access_token": AT1, **({"refresh_token": refresh} if refresh else {})})
            service.mark_authenticated()
            service.note_outcome(failed("任务验证码", reason="need_verification"))
        await service.aclose()

    asyncio.run(scenario())
    resolved = Overlay(path=overlay.path).load().apply(spec)
    assert resolved.credentials.access_token == AT1
    assert resolved.credentials.refresh_token == refresh
    assert decode_state(resolved.credentials.browser_state) == memory_browser.storage
    assert ctx.http.headers["Authorization"] == f"Bearer {AT1}"
    assert ctx.http.auth_refresher is None
    assert login_ctx.credentials == holder["account"].credentials
    assert spec.credentials.refresh_token == "rt-original"


def test_browser_export_cannot_resurrect_refresh_token_cleared_by_handoff(memory_browser, tmp_path):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path)
    service = engine._make_browser(holder["account"], overlay, spec, log=lambda _m: None)
    login_ctx.browser = ctx.browser_service = service
    memory_browser.storage = _storage(access=AT1, refresh="rt-original")
    accept = engine._browser_credential_writer(ctx, login_ctx, spec, holder, overlay, _plan("access_token", "refresh"))

    async def scenario():
        async with service.lease():
            assert accept({"access_token": AT1})
            service.mark_authenticated()
        before = overlay.path.read_bytes()
        await service.aclose()
        assert overlay.path.read_bytes() == before

    asyncio.run(scenario())
    assert Overlay(path=overlay.path).load().apply(spec).credentials.refresh_token == ""


def test_readonly_or_missing_version_never_claims_successful_persistence(memory_browser, tmp_path):
    spec, overlay, holder, _login_ctx, _ctx = _case(tmp_path, policy=CachePolicy.READONLY)
    logs = []
    service = engine._make_browser(holder["account"], overlay, spec, log=logs.append)

    async def scenario():
        async with service.lease():
            service.mark_authenticated()
        await service.aclose()

    asyncio.run(scenario())
    assert not overlay.path.exists()
    assert not any("已续存到" in line for line in logs)


def test_initial_refresh_rotation_is_used_on_401_without_resetting_budget(tmp_path, monkeypatch):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path)
    original = spec.credentials
    plan = _plan("refresh", "access_token")
    refresh_requests = []
    auth_requests = []
    reject_all = False

    def send(client, method, path, **kwargs):
        if path == "/api/v1/auth/refresh":
            assert method == "POST" and client.auth_refresher is None
            refresh_requests.append(kwargs["json_body"]["refresh_token"])
            return {
                "access_token": AT1 if len(refresh_requests) == 1 else AT2,
                "refresh_token": "rt-rotated" if len(refresh_requests) == 1 else "rt-latest",
            }
        auth_requests.append(client.headers.get("Authorization"))
        if reject_all or client.headers.get("Authorization") != f"Bearer {AT2}":
            raise LoginRequired("access token 已过期", status=401)
        return {"ok": True}

    monkeypatch.setattr(HttpClient, "_send", send)
    result = asyncio.run(LOGINS.establish(
        login_ctx, plan, on_credentials=engine._credential_writer(spec, holder, overlay),
    ))
    assert result.state is not None and result.state.method == "refresh"
    engine._apply_login(ctx, login_ctx, result.state, plan, spec, holder, overlay)
    assert ctx.http.get("/protected") == {"ok": True}
    assert refresh_requests == ["rt-original", "rt-rotated"]
    assert auth_requests == [f"Bearer {AT1}", f"Bearer {AT2}"]
    assert login_ctx.credentials == holder["account"].credentials
    assert login_ctx.credentials.refresh_token == "rt-latest"
    assert ctx.login_handle.state.credentials["refresh_token"] == "rt-latest"
    assert ctx.login_handle.method == "refresh"
    assert spec.credentials == original
    reject_all = True
    with pytest.raises(LoginRequired):
        ctx.http.get("/protected")
    assert len(refresh_requests) == 2, "同一客户端续期成功后不得重新获得重放额度"
    assert Overlay(path=overlay.path).load().apply(spec).credentials.refresh_token == "rt-latest"


def test_renewal_reads_latest_holder_instead_of_captured_login_context(tmp_path, monkeypatch):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path)
    plan = _plan("access_token", "refresh")
    result = asyncio.run(LOGINS.establish(login_ctx, plan))
    engine._apply_login(ctx, login_ctx, result.state, plan, spec, holder, overlay)
    engine._credential_writer(spec, holder, overlay)({"access_token": AT1, "refresh_token": "rt-current"}, "refresh")
    assert login_ctx.credentials.refresh_token == "rt-original"
    used = []

    def send(client, _method, path, **kwargs):
        if path == "/api/v1/auth/refresh":
            used.append(kwargs["json_body"]["refresh_token"])
            return {"access_token": AT2}
        if client.headers.get("Authorization") != f"Bearer {AT2}":
            raise LoginRequired("旧 AT 失效", status=401)
        return {"ok": True}

    monkeypatch.setattr(HttpClient, "_send", send)
    assert ctx.http.get("/protected") == {"ok": True}
    assert used == ["rt-current"]
    assert login_ctx.credentials.refresh_token == "rt-current"
    assert login_ctx.credentials == holder["account"].credentials


# ── 跨运行与同运行的旧快照保护、未确认浏览器凭据的内存交接 ──
def _seed_then_rotate(tmp_path, *, clear_refresh: bool):
    """上一轮：浏览器快照 S0(AT0/RT0) 落盘，随后纯 HTTP 轮换出 AT1（并可能清除 RT）。"""
    spec, overlay, holder, _login_ctx, _ctx = _case(tmp_path)
    overlay.record_credentials(
        spec, origin="browser", browser_state=encode_state(_storage()),
        access_token=AT0, refresh_token="rt-original",
    )
    writer = engine._credential_writer(spec, holder, overlay)
    writer({"access_token": AT1, "refresh_token": "" if clear_refresh else "rt-new"}, "refresh")
    return spec


def _next_run(tmp_path, spec, memory, *, export):
    overlay = Overlay(path=tmp_path / "overlay.json").load()
    account = overlay.apply(spec)
    logs: list[str] = []
    service = engine._make_browser(account, overlay, spec, log=logs.append)
    memory.storage = export

    async def scenario():
        async with service.lease(state_text=account.credentials.browser_state):
            service.mark_authenticated()
        await service.aclose()

    asyncio.run(scenario())
    return Overlay(path=tmp_path / "overlay.json").load().apply(spec), logs


def test_next_run_restoring_old_snapshot_cannot_resurrect_cleared_refresh(memory_browser, tmp_path):
    spec = _seed_then_rotate(tmp_path, clear_refresh=True)
    before = (tmp_path / "overlay.json").read_bytes()
    resolved, logs = _next_run(tmp_path, spec, memory_browser, export=_storage())
    assert (tmp_path / "overlay.json").read_bytes() == before
    assert resolved.credentials.access_token == AT1
    assert resolved.credentials.refresh_token == ""
    assert not any("已续存到" in line for line in logs)


def test_next_run_restoring_old_snapshot_cannot_roll_back_rotated_refresh(memory_browser, tmp_path):
    spec = _seed_then_rotate(tmp_path, clear_refresh=False)
    resolved, _logs = _next_run(tmp_path, spec, memory_browser, export=_storage())
    assert resolved.credentials.access_token == AT1
    assert resolved.credentials.refresh_token == "rt-new"


def test_next_run_fresh_page_login_after_old_snapshot_is_persisted(memory_browser, tmp_path):
    spec = _seed_then_rotate(tmp_path, clear_refresh=True)
    fresh = _storage(access=AT2, refresh="rt-fresh", cookie="session-fresh")
    resolved, _logs = _next_run(tmp_path, spec, memory_browser, export=fresh)
    assert resolved.credentials.access_token == AT2
    assert resolved.credentials.refresh_token == "rt-fresh"
    assert decode_state(resolved.credentials.browser_state) == fresh


def test_same_run_http_rotation_does_not_block_later_fresh_browser_session(memory_browser, tmp_path):
    spec, overlay, holder, _login_ctx, _ctx = _case(tmp_path)
    overlay.record_credentials(spec, origin="browser", browser_state=encode_state(_storage()),
                               access_token=AT0, refresh_token="rt-original")
    holder["account"] = overlay.apply(spec)
    logs = []
    service = engine._make_browser(holder["account"], overlay, spec, log=logs.append)
    writer = engine._credential_writer(spec, holder, overlay, browser=service)
    writer({"access_token": AT1, "refresh_token": "rt-rotated"}, "refresh")
    fresh = _storage(access=AT2, refresh="rt-fresh")

    async def scenario():
        async with service.lease(state_text=encode_state(_storage())):
            memory_browser.storage = fresh
            service.mark_authenticated()
        await service.aclose()

    asyncio.run(scenario())
    resolved = Overlay(path=overlay.path).load().apply(spec)
    assert resolved.credentials.access_token == AT2, logs
    assert resolved.credentials.refresh_token == "rt-fresh"


def test_foreign_identity_write_before_same_run_rotation_still_blocks_browser_persist(memory_browser, tmp_path):
    spec, overlay, holder, _login_ctx, _ctx = _case(tmp_path)
    overlay.record_credentials(spec, origin="browser", browser_state=encode_state(_storage()),
                               access_token=AT0, refresh_token="rt-original")
    holder["account"] = overlay.apply(spec)
    logs = []
    service = engine._make_browser(holder["account"], overlay, spec, log=logs.append)
    # 另一进程只改身份元数据：各字段版本不变，只有整组版本变化。
    assert Overlay(path=overlay.path).load().record_credentials(spec, identity={"user_id": "999"})
    writer = engine._credential_writer(spec, holder, overlay, browser=service)
    writer({"access_token": AT1, "refresh_token": "rt-rotated"}, "refresh")

    async def scenario():
        async with service.lease(state_text=encode_state(_storage())):
            memory_browser.storage = _storage(access=AT2, refresh="rt-fresh")
            service.mark_authenticated()
        await service.aclose()

    asyncio.run(scenario())
    resolved = Overlay(path=overlay.path).load().apply(spec)
    assert resolved.credentials.access_token == AT1, logs
    assert resolved.credentials.refresh_token == "rt-rotated"
    assert any("未续存" in str(item) for item in logs), logs


def test_unverified_browser_refresh_token_is_used_in_memory_but_not_persisted(tmp_path, monkeypatch):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path)
    plan = _plan("browser_state", "refresh")

    class Snapshot:
        id = "browser_state"
        requires = frozenset({"browser"})

        def available(self, _ctx, _option):
            return READY

        async def authenticate(self, _ctx, _option):
            # 与真实 browser_state 一致是协程：请求中途的同步续期必须跳过它。
            return LoginState(
                method=self.id, verified=False, origin="browser",
                headers={"Authorization": f"Bearer {AT1}"},
                credentials={"access_token": AT1, "refresh_token": "rt-browser"},
            )

    broker = LoginBroker({"browser_state": Snapshot(), "refresh": LOGINS.get("refresh")})
    monkeypatch.setattr(engine, "LOGINS", broker)
    result = asyncio.run(broker.establish(
        login_ctx, plan, on_credentials=engine._credential_writer(spec, holder, overlay),
    ))
    assert result.state is not None
    assert not overlay.path.exists(), "未确认的浏览器凭据不得落盘"
    engine._apply_login(ctx, login_ctx, result.state, plan, spec, holder, overlay)
    assert holder["account"].credentials.refresh_token == "rt-browser"
    used = []

    def send(client, _method, path, **kwargs):
        if path == "/api/v1/auth/refresh":
            used.append(kwargs["json_body"]["refresh_token"])
            return {"access_token": AT2, "refresh_token": "rt-rotated"}
        if client.headers.get("Authorization") != f"Bearer {AT2}":
            raise LoginRequired("AT 已过期", status=401)
        return {"ok": True}

    monkeypatch.setattr(HttpClient, "_send", send)
    assert ctx.http.get("/protected") == {"ok": True}
    assert used == ["rt-browser"]
    assert Overlay(path=overlay.path).load().apply(spec).credentials.refresh_token == "rt-rotated"


def test_refresh_token_rejection_does_not_revoke_confirmed_browser_session(memory_browser, tmp_path, monkeypatch):
    saved = Mock(return_value=True)
    service = BrowserService(base_url=BASE_URL, persist=saved)
    _spec, _overlay, _holder, login_ctx, _ctx = _case(tmp_path, browser=service)

    def send(_client, _method, path, **_kwargs):
        raise LoginRequired("refresh token 无效", status=401)

    monkeypatch.setattr(HttpClient, "_send", send)

    async def scenario():
        async with service.lease():
            service.mark_authenticated()
            result = await LOGINS.establish(login_ctx, _plan("refresh", "access_token"))
            assert result.state is not None and result.state.method == "access_token"
        await service.aclose()

    asyncio.run(scenario())
    saved.assert_called_once()


def test_sdk_renew_installs_authentication_and_shares_http_recovery_budget(tmp_path, monkeypatch):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path)
    count = []

    def renew(_context, _plan, **_kwargs):
        count.append("renew")
        return LoginState("refresh", headers={"Authorization": "Bearer sdk-fresh"},
                          credentials={"access_token": "sdk-fresh"}, verified=True)

    monkeypatch.setattr(type(LOGINS), "renew_sync", lambda _self, *args, **kwargs: renew(*args, **kwargs))
    state = LoginState("access_token", headers={"Authorization": "Bearer old"})
    engine._apply_login(ctx, login_ctx, state, _plan("access_token", "refresh"), spec, holder, overlay)
    assert asyncio.run(ctx.login_handle.renew()) is True
    assert ctx.http.headers["Authorization"] == "Bearer sdk-fresh"
    assert asyncio.run(ctx.login_handle.renew()) is False
    assert count == ["renew"]


def test_new_oauth_group_tombstones_all_absent_old_authentication(tmp_path, monkeypatch):
    spec, overlay, holder, login_ctx, ctx = _case(tmp_path)
    monkeypatch.setattr(HttpClient, "_send", lambda *_args, **_kwargs: {"id": 7, "quota": 100})
    state = LoginState("oauth", headers={"Cookie": "session=fresh"}, credentials={"cookie": "session=fresh"},
                       identity={"user_id": "7"}, replace_credentials=True, verified=True)
    ctx.http.headers = {"Authorization": "Bearer old", "Cookie": "old=1", "New-Api-User": "old", "X-Fixed": "keep"}
    engine._apply_login(ctx, login_ctx, state, _plan("oauth"), spec, holder, overlay, replace_auth=True)
    assert "Authorization" not in ctx.http.headers
    assert ctx.http.headers["X-Fixed"] == "keep"
    assert holder["account"].credentials.access_token == ""
    assert holder["account"].credentials.refresh_token == ""
    assert holder["account"].credentials.browser_state == ""
    reopened = Overlay(overlay.path).load().apply(spec)
    assert reopened.credentials.access_token == ""
    assert reopened.credentials.refresh_token == ""
    assert reopened.credentials.cookie == "session=fresh"
    assert reopened.identity["user_id"] == "7"
