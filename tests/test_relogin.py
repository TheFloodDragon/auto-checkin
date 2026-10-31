"""隔离 OAuth 重登：真实引擎/登录服务配内存浏览器，绝不启动浏览器或访问网络。"""

from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from dataclasses import replace
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from browser import storage_scope
from browser.service import BrowserLease, BrowserService, decode_state, encode_state
from config import schema
from config.overlay import Overlay
from core.errors import LoginRequired, TaskError, TransientError
from core.outcome import Verdict, already_done, failed
from login.base import LoginContext
from login.oauth import OAuthLogin
from net.http import HttpClient
from runtime import engine
from runtime.budget import Deadline
from sdk.context import EvidenceCollector
from templates import registry as templates


BASE_URL = "https://demo.invalid"
OLD_TOKEN = "old.site.token"
NEW_TOKEN = "new.site.token"


def _cookie(name: str, domain: str, value: str = "test-session") -> dict[str, Any]:
    return {
        "name": name, "value": value, "domain": domain, "path": "/",
        "expires": -1, "httpOnly": True, "secure": True, "sameSite": "Lax",
    }


def _origin(url: str, value: str = "provider-storage") -> dict[str, Any]:
    return {"origin": url, "localStorage": [{"name": "auth_token", "value": value}]}


def _site_state(token: str = OLD_TOKEN, cookie: str = "old-site-session") -> dict[str, Any]:
    return {
        "cookies": [_cookie("session", "demo.invalid", cookie)],
        "origins": [_origin(BASE_URL, token)] if token else [],
    }


def _shared_state() -> dict[str, Any]:
    """共享捕获可能混有本站、其他 provider 和伪装域，重登必须重新划定边界。"""
    return {
        "cookies": [
            _cookie("_t", ".linux.do"),
            _cookie("connect_session", "connect.linux.do"),
            _cookie("user_session", ".github.com"),
            _cookie("session", "demo.invalid", "shared-but-stale-site"),
            _cookie("_t", "evil-linux.do"),
            _cookie("_t", "linux.do.evil.invalid"),
            _cookie("user_session", "github.com.evil.invalid"),
            _cookie("user_session", "evilgithub.com"),
            _cookie("_t", ".do"),
        ],
        "origins": [
            _origin("https://linux.do"),
            _origin("https://connect.linux.do"),
            _origin("https://github.com"),
            _origin(BASE_URL, "shared-old-site-token"),
            _origin("http://linux.do"),
            _origin("http://github.com"),
            _origin("https://evil-linux.do"),
            _origin("https://linux.do.evil.invalid"),
            _origin("https://github.com.evil.invalid"),
            _origin("https://github.com@evil.invalid"),
            _origin("https://evilgithub.com"),
        ],
    }


def _spec(**overrides: Any):
    payload = {
        "id": "relogin-demo",
        "name": "重登回归",
        "base_url": BASE_URL,
        "template": "newapi",
        "credentials": {
            "access_token": OLD_TOKEN,
            "session_cookie": "session=old-explicit-session",
            "browser_state": encode_state(_site_state()),
        },
        "login": {"method": "oauth", "provider": "github", "account": "configured"},
        "tasks": [{"id": "daily", "method": "relogin", "args": {"user_id": "42"}, "timeout": 120}],
    }
    payload.update(overrides)
    return schema.parse_account(payload)


class _MemoryPage:
    def __init__(self, harness: Any) -> None:
        self.harness = harness
        self.url = BASE_URL
        self.closed = False

    async def goto(self, url: str, **_kwargs: Any) -> None:
        # 模拟「导航没能提交到目标站点」：goto 吞掉超时后返回，页面仍停在 about:blank。
        self.harness.nav_attempts = getattr(self.harness, "nav_attempts", 0) + 1
        # commit_after=N：前 N-1 次不提交（停在 about:blank），第 N 次才提交，
        # 用于验证首跳未提交时的有界重载重试。nav_stalls=True 则永不提交。
        commit_after = getattr(self.harness, "nav_commit_after", 0)
        stalls = getattr(self.harness, "nav_stalls", False) or (
            commit_after and self.harness.nav_attempts < commit_after
        )
        self.url = "about:blank" if stalls else url

    async def evaluate(self, _script: str, args: Any = None) -> bool:
        self.harness.confirmations.append(args)
        return self.harness.confirmed

    async def close(self) -> None:
        self.closed = True


class _MemoryContext:
    def __init__(self, harness: Any) -> None:
        self.harness = harness
        self.state: dict[str, Any] = {"cookies": [], "origins": []}
        self.closed = False
        self.close_started = False
        self.close_cancelled = False
        self.pages: list[_MemoryPage] = []

    async def new_page(self) -> _MemoryPage:
        page = _MemoryPage(self.harness)
        self.pages.append(page)
        return page

    async def storage_state(self) -> dict[str, Any]:
        self.harness.storage_state_calls = getattr(self.harness, "storage_state_calls", 0) + 1
        return deepcopy(self.state)

    async def close(self) -> None:
        self.close_started = True
        if self.harness.hang_close:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.close_cancelled = True
                raise
        self.closed = True


@pytest.fixture
def memory_browser(monkeypatch):
    """只替换 I/O 边界，保留 BrowserService、租约、harvest 和真实 engine。"""
    from browser import bypass, popups
    from login import browser_state, oauth

    harness = SimpleNamespace(
        started=[], contexts=[], restores=[], oauth_calls=[], confirmations=[],
        confirmed=True, link={"landed_back": True, "fresh_authorization": True},
        fresh_state=_site_state(token="", cookie="fresh-site-session"),
        error=None, on_oauth=None, hang_close=False, nav_stalls=False, storage_state_calls=0,
        nav_attempts=0, nav_commit_after=0,
    )

    async def forbidden_launch(*_args: Any, **_kwargs: Any):
        raise AssertionError("测试不允许启动真实浏览器")

    def forbidden_http(*_args: Any, **_kwargs: Any):
        raise AssertionError("测试不允许真实 HTTP；应显式安装余额响应")

    async def ensure_started(service: BrowserService, *, reason: str) -> None:
        if service.started:
            return
        context = _MemoryContext(harness)
        service._context = context
        service._browser = None
        service._started = True
        harness.started.append(service)
        harness.contexts.append(context)

    async def restore(service: BrowserService, text: str) -> bool:
        state = decode_state(text)
        harness.restores.append((service, deepcopy(state)))
        service._context.state = deepcopy(state)
        return True

    async def no_popups(*_args: Any, **_kwargs: Any) -> int:
        return 0

    async def settle(_ctx: LoginContext, lease: BrowserLease, page: Any) -> None:
        await lease.goto("", page=page)

    async def oauth_call(lease: BrowserLease, provider: str, *, page=None, **kwargs: Any):
        call = {"service": lease.service, "provider": provider, "page": page, "at": time.monotonic(), **kwargs}
        harness.oauth_calls.append(call)
        if harness.on_oauth is not None:
            await harness.on_oauth(call)
        if harness.error is not None:
            raise harness.error
        lease.context.state = deepcopy(harness.fresh_state)
        return dict(harness.link)

    monkeypatch.setattr(bypass, "launch_camoufox", forbidden_launch)
    monkeypatch.setattr(bypass, "solve_cloudflare", AsyncMock(return_value=True))
    monkeypatch.setattr(HttpClient, "_send", forbidden_http)
    monkeypatch.setattr(BrowserService, "_ensure_started", ensure_started)
    monkeypatch.setattr(BrowserService, "_restore", restore)
    monkeypatch.setattr(BrowserLease, "oauth", oauth_call)
    monkeypatch.setattr(BrowserLease, "dismiss_popups", no_popups)
    monkeypatch.setattr(popups, "setup_popup_guard", no_popups)
    monkeypatch.setattr(browser_state, "settle_page", settle)
    monkeypatch.setattr(oauth, "settle_page", settle)
    monkeypatch.setattr(engine.caps_module, "detect", lambda _account: frozenset({"browser"}))
    monkeypatch.delenv("CHECKIN_PROXY", raising=False)
    return harness


def _context(tmp_path, *, spec=None, shared=None, args=None, persist=None) -> LoginContext:
    spec = spec or _spec()
    resolved = Overlay(path=tmp_path / "direct.json").load().apply(spec)
    current_browser = BrowserService(base_url=BASE_URL, persist=persist)
    return LoginContext(
        account=resolved,
        template=templates.get("newapi"),
        http=HttpClient(base_url=BASE_URL),
        browser=current_browser,
        args={"user_id": "42", **(args or {})},
        capabilities=frozenset({"browser"}),
        oauth_state=lambda _provider, _account: encode_state(_shared_state()) if shared is None else shared,
        deadline=Deadline(120),
    )


def _assert_provider_only(state: dict[str, Any], provider: str) -> None:
    if provider == "github":
        assert {item["domain"] for item in state["cookies"]} == {".github.com"}
        assert {item["origin"] for item in state["origins"]} == {"https://github.com"}
    else:
        assert {item["domain"] for item in state["cookies"]} == {".linux.do", "connect.linux.do"}
        assert {item["origin"] for item in state["origins"]} == {"https://linux.do", "https://connect.linux.do"}


@pytest.mark.parametrize("provider", ["linuxdo", "github"])
def test_provider_storage_state_filters_domain_boundaries_and_https(provider) -> None:
    source = _shared_state()
    before = deepcopy(source)
    filtered = storage_scope.provider_storage_state(source, provider, base_url=BASE_URL)
    _assert_provider_only(filtered, provider)
    assert source == before, "筛选不能原地修改供其他账号/provider复用的共享态"
    filtered["cookies"][0]["value"] = "changed"
    filtered["origins"][0]["localStorage"][0]["value"] = "changed"
    assert source == before, "返回值不能与共享态共用可变容器"


def test_provider_storage_state_excludes_site_even_under_provider_domain() -> None:
    source = _shared_state()
    source["cookies"].append(_cookie("site_session", "app.github.com"))
    source["origins"].append(_origin("https://app.github.com", "site-token"))
    filtered = storage_scope.provider_storage_state(source, "github", base_url="https://app.github.com")
    assert all(item["domain"] != "app.github.com" for item in filtered["cookies"])
    assert all(item["origin"] != "https://app.github.com" for item in filtered["origins"])


@pytest.mark.parametrize("status", ["unknown"])
def test_normal_oauth_unknown_session_does_not_replay(memory_browser, tmp_path, monkeypatch, status):
    from login import oauth
    ctx = _context(tmp_path)
    monkeypatch.setattr(oauth, "_server_confirms_login", AsyncMock(return_value={"status": status, "identity": {}}))
    with pytest.raises(TransientError):
        asyncio.run(OAuthLogin().authenticate(ctx))
    assert not memory_browser.oauth_calls
    asyncio.run(ctx.browser.aclose())


def test_relogin_prepared_candidate_carries_nested_identity_only(memory_browser, tmp_path):
    memory_browser.fresh_state = {"cookies": [], "origins": [{"origin": BASE_URL, "localStorage": [
        {"name": "auth_token", "value": NEW_TOKEN},
        {"name": "user", "value": json.dumps({"access_token": NEW_TOKEN, "id": 77})},
    ]}]}
    ctx = _context(tmp_path)
    state = asyncio.run(OAuthLogin().relogin(ctx))
    assert state.verified is False and state.replace_credentials is True
    assert state.identity == {"user_id": "77"}
    assert state.headers["New-Api-User"] == "77"
    assert "user_id" not in state.credentials
    assert state.credentials["access_token"] == NEW_TOKEN
    assert all(service._verified_generation is None for service in memory_browser.started)
    asyncio.run(ctx.browser.aclose())


def test_relogin_award_normalizes_id_alias_without_reauthorizing(monkeypatch):
    from task.relogin import ReloginTask
    responses = iter([{"success": True, "data": {"id": 42, "quota": 1_000_000}},
                      {"success": True, "data": {"user_id": "42", "quota": 1_500_000}}])
    http = HttpClient(base_url=BASE_URL, headers={"Cookie": "session=offline"})
    monkeypatch.setattr(HttpClient, "_send", lambda *_args, **_kwargs: next(responses))
    relogin = AsyncMock(return_value=True)
    ctx = SimpleNamespace(args={}, account=SimpleNamespace(oauth_provider="github", oauth_account="default"),
                          http=http, login=SimpleNamespace(relogin=relogin), remaining_seconds=lambda: None)
    outcome = asyncio.run(ReloginTask().run(ctx, templates.get("newapi")))
    assert outcome.verdict == Verdict.SUCCESS
    assert outcome.data["awarded"] == 500_000
    relogin.assert_awaited_once()


def test_provider_storage_state_rejects_unknown_provider() -> None:
    with pytest.raises((ValueError, TaskError)):
        storage_scope.provider_storage_state(_shared_state(), "githbu", base_url=BASE_URL)


@pytest.mark.parametrize("provider", ["linuxdo", "github"])
def test_relogin_uses_only_shared_provider_state_and_new_service(memory_browser, tmp_path, provider) -> None:
    saved = Mock()
    spec = _spec(
        login={"method": "oauth", "provider": provider, "account": "named"},
        network={"proxy": "http://127.0.0.1:18999", "proxy_mode": "custom"},
        policy={"headless": False, "humanize": False},
    )
    ctx = _context(tmp_path, spec=spec, persist=saved)
    getter = Mock(return_value=encode_state(_shared_state()))
    ctx.oauth_state = getter
    evidence = EvidenceCollector()
    before = ctx.credentials

    state = asyncio.run(OAuthLogin().relogin(ctx, evidence=evidence))

    getter.assert_called_once_with(provider, "named")
    assert not state.verified and state.replace_credentials and state.method == "oauth"
    assert state.headers["Cookie"] == "session=fresh-site-session"
    assert "Authorization" not in state.headers
    assert decode_state(state.credentials["browser_state"]) == memory_browser.fresh_state
    assert state.credentials["session_cookie"] == "session=fresh-site-session"
    assert ctx.credentials == before
    saved.assert_not_called()
    assert not ctx.browser.started
    assert len(memory_browser.started) == 1
    isolated = memory_browser.started[0]
    assert isolated is not ctx.browser
    assert isolated.proxy == ctx.account.network.proxy
    assert isolated.headless is False and isolated.humanize is False
    assert isolated.evidence is evidence and isolated.log is not None
    assert isolated._persist is None, "凭据持久化只由引擎在 HTTP 认证应用成功后负责"
    assert not isolated.started and memory_browser.contexts[0].closed
    assert memory_browser.confirmations, "OAuth 回跳后仍须由本站服务端确认认证"
    assert len(memory_browser.restores) == len(memory_browser.oauth_calls) == 1
    _assert_provider_only(memory_browser.restores[0][1], provider)
    call = memory_browser.oauth_calls[0]
    assert call["require_fresh"] is True
    assert call["at"] < call["deadline"] <= ctx.deadline.at
    assert 0 < call["deadline"] - call["at"] <= 120, "传给 OAuth 的必须是 monotonic 绝对截止点"


def test_relogin_captures_state_with_single_storage_read(memory_browser, tmp_path) -> None:
    """回站确认成功后，导出登录态只读一次 storage_state（凭据 + 快照复用同一次读取）。

    此前 harvest + export_state 各调一次 storage_state()（实测可达 8s+），叠加起来常拖过
    OAuth 截止点，把一次已确认成功的重登翻转成「state_export 阶段超时」而丢弃。回归：
    确认成功的重登只做一次状态读取，且仍返回正确的凭据与站点快照。"""
    ctx = _context(tmp_path)
    state = asyncio.run(OAuthLogin().relogin(ctx))

    assert not state.verified and state.replace_credentials and state.method == "oauth"
    assert decode_state(state.credentials["browser_state"]) == memory_browser.fresh_state
    assert state.credentials["session_cookie"] == "session=fresh-site-session"
    assert memory_browser.storage_state_calls == 1, "确认成功后只应读取一次 storage_state"


@pytest.mark.parametrize(
    ("shared", "reason"),
    [
        ("", "need_config"),
        (encode_state({"cookies": [], "origins": []}), "need_login"),
        (encode_state({"cookies": [_cookie("cf_clearance", ".github.com")], "origins": []}), "need_login"),
        (encode_state({"cookies": [_cookie("user_session", "github.com.evil.invalid")], "origins": []}), "need_login"),
        (encode_state({"cookies": [_cookie("user_session", ".github.com", "")], "origins": []}), "need_login"),
    ],
)
def test_relogin_rejects_missing_provider_auth_even_with_valid_site_cache(
    memory_browser, tmp_path, shared, reason,
) -> None:
    ctx = _context(tmp_path, shared=shared)
    with pytest.raises(TaskError) as exc:
        asyncio.run(OAuthLogin().relogin(ctx))
    assert exc.value.reason == reason
    assert not memory_browser.started
    assert not memory_browser.oauth_calls


def test_relogin_unknown_provider_does_not_fall_back_to_linuxdo(memory_browser, tmp_path) -> None:
    ctx = _context(tmp_path, args={"provider": "githbu"})
    with pytest.raises(TaskError) as exc:
        asyncio.run(OAuthLogin().relogin(ctx))
    assert exc.value.reason == "need_config"
    assert not memory_browser.started
    assert not memory_browser.oauth_calls


@pytest.mark.parametrize(
    ("link", "confirmed"),
    [
        ({"landed_back": True, "fresh_authorization": False}, True),
        ({"landed_back": False, "fresh_authorization": True}, True),
        ({"landed_back": True, "fresh_authorization": True}, False),
    ],
)
def test_relogin_requires_fresh_callback_and_server_confirmation(
    memory_browser, monkeypatch, tmp_path, link, confirmed,
) -> None:
    if not confirmed:
        from login import oauth

        monkeypatch.setattr(oauth, "_confirm_after_relogin", AsyncMock(return_value=False))
    saved = Mock()
    ctx = _context(tmp_path, persist=saved)
    before = ctx.credentials
    memory_browser.link = link
    memory_browser.confirmed = confirmed
    with pytest.raises(TaskError):
        asyncio.run(OAuthLogin().relogin(ctx))
    assert ctx.credentials == before
    saved.assert_not_called()
    assert len(memory_browser.started) == 1
    assert memory_browser.contexts[0].closed
    assert not memory_browser.started[0].started


def _http_balances(monkeypatch, *, old=1_000_000, new=1_500_000, old_id=42, new_id=42):
    calls = []

    def send(client, method, path, **_kwargs):
        assert method == "GET" and path == "/api/user/self", "重登不得签到、刷帖或调用额外接口"
        calls.append((client, dict(client.headers), client.cookie_jar, client.auth_refresher))
        headers = {key.lower(): value for key, value in client.headers.items()}
        fresh = headers.get("cookie") == "session=fresh-site-session" or headers.get("authorization") == f"Bearer {NEW_TOKEN}"
        value = new if fresh else old
        if isinstance(value, BaseException):
            raise value
        return {"success": True, "data": {"id": new_id if fresh else old_id, "quota": value}}

    monkeypatch.setattr(HttpClient, "_send", send)
    return calls


@pytest.mark.parametrize("cached_in_overlay", [False, True])
@pytest.mark.parametrize(
    ("task_args", "provider", "name"),
    [({}, "github", "configured"), ({"provider": "linuxdo", "account": "task-owner"}, "linuxdo", "task-owner")],
)
def test_engine_relogin_defers_login_and_never_restores_old_site_snapshot(
    memory_browser, monkeypatch, tmp_path, cached_in_overlay, task_args, provider, name,
) -> None:
    spec = _spec(tasks=[{"id": "daily", "method": "relogin", "args": {"user_id": "42", **task_args}}])
    overlay = Overlay(path=tmp_path / "engine.json").load()
    if cached_in_overlay:
        overlay.record_credentials(spec, browser_state=encode_state(_site_state("overlay.old.token")))
    assert overlay.apply(spec).credentials.browser_state
    shared = Mock(return_value=encode_state(_shared_state()))
    calls = _http_balances(monkeypatch)
    establish = Mock(side_effect=AssertionError("builtin relogin 首选时不得提前 establish/OAuth"))
    monkeypatch.setattr(type(engine.LOGINS), "establish", establish)
    # 本例验证重登所属 provider；共享态保活的独立预检由专门用例覆盖。
    monkeypatch.setattr(engine, "_keepalive_shared", AsyncMock())

    result = asyncio.run(engine.run_account(spec, overlay=overlay, oauth_state=shared))

    assert result.ok, result.records[0].outcome.message
    record = result.records[0]
    assert record.outcome.verdict is Verdict.SUCCESS
    assert record.outcome.data["awarded"] == 500_000
    assert "login:deferred_to_relogin" in record.outcome.evidence.stages
    establish.assert_not_called()
    shared.assert_called_once_with(provider, name)
    assert len(memory_browser.oauth_calls) == len(memory_browser.started) == 1
    _assert_provider_only(memory_browser.restores[0][1], provider)
    assert memory_browser.oauth_calls[0]["require_fresh"] is True
    assert len(calls) == 3
    assert calls[0][1].get("Authorization") == f"Bearer {OLD_TOKEN}"
    assert calls[0][1].get("New-Api-User") == "42"
    assert calls[0][3] is None, "旧余额基线禁止自动续期"
    assert calls[1][1].get("Cookie") == "session=fresh-site-session"
    assert not any(key.lower() == "authorization" for key in calls[1][1])
    resolved = overlay.apply(spec, auth_scope=engine.authentication_scope(spec, args=spec.tasks[0].args))
    assert resolved.credentials.session_cookie == "session=fresh-site-session"
    assert decode_state(resolved.credentials.browser_state) == memory_browser.fresh_state


@pytest.mark.parametrize("provider", ["github", "linuxdo"])
def test_engine_relogin_writes_rotated_shared_provider_state_after_http_adopt(
    memory_browser, monkeypatch, tmp_path, provider,
) -> None:
    """新 OAuth + 服务端确认 + 新 HTTP 身份安装后，才 CAS 写回共享 provider Cookie。"""
    case = _shared_runtime_case(tmp_path, provider)
    spec = _spec(login={"method": "oauth", "provider": provider, "account": "configured"})
    memory_browser.fresh_state = _rotated_state(provider)
    _http_balances(monkeypatch)
    config_before = case.config_path.read_bytes()

    result = asyncio.run(engine.run_account(spec, overlay=case.overlay, oauth_state=case.reader))

    assert result.ok, result.records[0].outcome.message
    resolution = engine._shared_oauth_resolver(case.overlay, case.reader)(provider, "configured")
    assert resolution.from_overlay
    renewed = decode_state(resolution.state)
    assert renewed == {"cookies": [_provider_cookie(provider, "renewed")], "origins": []}
    assert case.config_path.read_bytes() == config_before
    assert not engine._shared_oauth_resolver(case.overlay, case.reader)(provider, "other").from_overlay

    # 不同站点/账号浏览器必须从共享续期态新建，不得沿用第一站 context 或站点 token。
    second_url = "https://second.invalid"
    second = _spec(
        id="second-site", base_url=second_url,
        login={"method": "oauth", "provider": provider, "account": "configured"},
        credentials={"browser_state": encode_state(_site_state())},
    )
    memory_browser.fresh_state = _rotated_state(provider, base_url=second_url)
    result = asyncio.run(engine.run_account(second, overlay=case.overlay, oauth_state=case.reader))
    assert result.ok, result.records[0].outcome.message
    assert len(memory_browser.oauth_calls) == 2
    assert memory_browser.oauth_calls[0]["service"] is not memory_browser.oauth_calls[1]["service"]
    assert memory_browser.restores[1][1] == renewed
    assert all(context.closed for context in memory_browser.contexts)
    assert case.config_path.read_bytes() == config_before


def test_engine_old_balance_401_never_renews_or_claims_award(memory_browser, monkeypatch, tmp_path) -> None:
    calls = _http_balances(monkeypatch, old=LoginRequired("旧凭据过期", status=401))
    renew = Mock(side_effect=AssertionError("旧余额401不得触发renew"))
    monkeypatch.setattr(type(engine.LOGINS), "renew_sync", renew)
    spec = _spec()
    result = asyncio.run(engine.run_account(
        spec, overlay=Overlay(path=tmp_path / "unauthorized.json").load(),
        oauth_state=lambda _provider, _name: encode_state(_shared_state()),
    ))
    record = result.records[0]
    assert record.outcome.verdict is Verdict.ALREADY_DONE, record.outcome.message
    assert "awarded" not in record.outcome.data
    assert "无法确认" in record.outcome.message or "未知" in record.outcome.message
    assert "数值未变化" not in record.outcome.message
    assert len(calls) == 3 and len(memory_browser.oauth_calls) == 1
    renew.assert_not_called()


@pytest.mark.parametrize(
    ("before", "after", "verdict"),
    [
        (1_000_000, 1_000_000, Verdict.ALREADY_DONE),
        (1_000_000, 500_000, Verdict.ALREADY_DONE),
        ("unknown", 1_500_000, Verdict.ALREADY_DONE),
        (1_000_000, "unknown", Verdict.ALREADY_DONE),
        (None, None, Verdict.ALREADY_DONE),
        (True, 1_500_000, Verdict.ALREADY_DONE),
        (float("nan"), 1_500_000, Verdict.ALREADY_DONE),
        (1_000_000, float("inf"), Verdict.ALREADY_DONE),
        (-1e308, 1e308, Verdict.ALREADY_DONE),
        (1_000_000, 1_500_000, Verdict.SUCCESS),
    ],
)
def test_relogin_award_requires_positive_finite_numeric_delta(
    memory_browser, monkeypatch, tmp_path, before, after, verdict,
) -> None:
    _http_balances(monkeypatch, old=before, new=after)
    spec = _spec()
    result = asyncio.run(engine.run_account(
        spec, overlay=Overlay(path=tmp_path / "delta.json").load(),
        oauth_state=lambda _provider, _name: encode_state(_shared_state()),
    ))
    outcome = result.records[0].outcome
    assert outcome.verdict is verdict, outcome.message
    if verdict is not Verdict.SUCCESS:
        assert "awarded" not in outcome.data
        assert "今日已领取" not in outcome.message and "发放成功" not in outcome.message


@pytest.mark.parametrize(("old_id", "new_id"), [(42, 43), (None, 42), (42, None), (True, True)])
def test_relogin_award_requires_same_confirmed_site_user(
    memory_browser, monkeypatch, tmp_path, old_id, new_id,
) -> None:
    _http_balances(monkeypatch, old_id=old_id, new_id=new_id)
    result = asyncio.run(engine.run_account(
        _spec(), overlay=Overlay(path=tmp_path / "identity.json").load(),
        oauth_state=lambda _provider, _name: encode_state(_shared_state()),
    ))
    outcome = result.records[0].outcome
    if new_id is None or isinstance(new_id, bool):
        assert outcome.verdict is Verdict.FAILED
        assert outcome.reason == "authentication_unknown"
        assert "已完成重登" not in outcome.message
    else:
        assert outcome.verdict is Verdict.ALREADY_DONE
        assert outcome.data.get("identity_unconfirmed") is True
    assert "awarded" not in outcome.data and "发放成功" not in outcome.message


def test_engine_failed_fresh_oauth_preserves_existing_credentials(memory_browser, monkeypatch, tmp_path) -> None:
    _http_balances(monkeypatch)
    memory_browser.link = {"landed_back": False, "fresh_authorization": False, "need_human": True}
    spec = _spec()
    overlay = Overlay(path=tmp_path / "failed.json").load()
    overlay.record_credentials(spec, browser_state=encode_state(_site_state()), access_token=OLD_TOKEN)
    before = dict(overlay.entry(spec.id).fields)
    result = asyncio.run(engine.run_account(
        spec, overlay=overlay, oauth_state=lambda _provider, _name: encode_state(_shared_state()),
    ))
    assert not result.ok
    assert result.records[0].outcome.reason == "need_login"
    assert dict(overlay.entry(spec.id).fields) == before
    assert memory_browser.contexts[0].closed


def test_engine_relogin_isolated_from_browser_used_by_previous_task(memory_browser, monkeypatch, tmp_path) -> None:
    previous = []
    base_template = templates.get("newapi")

    async def previous_task(ctx):
        async with ctx.browser.lease(reason="previous", state_text=encode_state(_site_state())) as lease:
            await lease.new_page()
            previous.append((ctx.browser, deepcopy(lease.context.state)))
        return already_done("前序浏览器任务已完成")

    template = replace(base_template, hooks={"run": previous_task})
    monkeypatch.setattr(engine.templates, "get", lambda _ref: template)
    _http_balances(monkeypatch)
    spec = _spec(
        login={"method": "access_token", "provider": "github", "account": "configured"},
        tasks=[{"id": "first", "method": "http_api"}, {"id": "daily", "method": "relogin"}],
    )
    overlay = Overlay(path=tmp_path / "previous.json").load()
    result = asyncio.run(engine.run_account(
        spec, overlay=overlay, oauth_state=lambda _provider, _name: encode_state(_shared_state()),
    ))
    assert result.ok, [record.outcome.message for record in result.records]
    assert len(previous) == 1 and len(memory_browser.oauth_calls) == 1
    assert len(memory_browser.started) == 2
    isolated = memory_browser.oauth_calls[0]["service"]
    assert isolated is not previous[0][0]
    assert memory_browser.contexts[0].state == previous[0][1], "不得清空或混入已在用的站点 context"
    _assert_provider_only(memory_browser.restores[1][1], "github")
    assert all(context.closed for context in memory_browser.contexts)
    assert decode_state(overlay.apply(spec).credentials.browser_state) == memory_browser.fresh_state


def test_engine_auto_fallback_relogin_gets_capability_and_fresh_auth(memory_browser, monkeypatch, tmp_path) -> None:
    previous = []
    base_template = templates.get("newapi")

    async def unsupported_http(ctx):
        assert callable(ctx.login.relogin), "每个 TaskContext 都要注入重登能力，不限首选任务"
        async with ctx.browser.lease(reason="auto-first", state_text=encode_state(_site_state())) as lease:
            await lease.new_page()
            previous.append(ctx.browser)
        return failed("本站不支持接口签到", reason="need_config")

    monkeypatch.setattr(engine.templates, "get", lambda _ref: replace(base_template, hooks={"run": unsupported_http}))
    calls = _http_balances(monkeypatch, old=LoginRequired("旧余额401", status=401))
    renew = Mock(side_effect=AssertionError("AUTO 后备重登的旧余额不得自动 renew"))
    monkeypatch.setattr(type(engine.LOGINS), "renew_sync", renew)
    spec = _spec(
        login={"method": "access_token", "provider": "github", "account": "configured"},
        tasks=[{"id": "daily", "flow": {"execute": "auto"}}],
    )
    result = asyncio.run(engine.run_account(
        spec, overlay=Overlay(path=tmp_path / "auto.json").load(),
        oauth_state=lambda _provider, _name: encode_state(_shared_state()),
    ))
    assert result.ok, result.records[0].outcome.message
    assert previous and len(memory_browser.oauth_calls) == 1
    assert memory_browser.oauth_calls[0]["service"] is not previous[0]
    assert calls[0][3] is None
    renew.assert_not_called()


def test_relogin_cancel_closes_only_isolated_service_and_preserves_old_context(memory_browser, tmp_path) -> None:
    saved = Mock()
    ctx = _context(tmp_path, persist=saved)

    async def scenario():
        entered = asyncio.Event()

        async def pending(_call):
            entered.set()
            await asyncio.Event().wait()

        memory_browser.on_oauth = pending
        await ctx.browser._ensure_started(reason="earlier-task")
        ctx.browser._context.state = deepcopy(_site_state())
        original = ctx.browser._context
        task = asyncio.create_task(OAuthLogin().relogin(ctx))
        try:
            await asyncio.wait_for(entered.wait(), timeout=10)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=15)
            assert ctx.browser.started and not original.closed
            assert original.state == _site_state()
            assert memory_browser.contexts[1].closed
            assert not memory_browser.started[1].started
            saved.assert_not_called()
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            ctx.browser._persist = None
            await ctx.browser.aclose()

    asyncio.run(scenario())


def test_relogin_timeout_and_stalled_close_are_bounded(memory_browser, monkeypatch, tmp_path) -> None:
    from browser import runtime_loop

    ctx = _context(tmp_path)
    memory_browser.error = TimeoutError("模拟 OAuth 已到绝对截止点")
    memory_browser.hang_close = True
    monkeypatch.setattr(runtime_loop, "BROWSER_CLOSE_TIMEOUT_SECONDS", 1.0)

    async def scenario():
        task = asyncio.create_task(OAuthLogin().relogin(ctx))
        # 这是宽松的挂死保护，不断言亚秒墙钟；Windows 调度/杀毒扫描可占明显时间。
        done, _pending = await asyncio.wait({task}, timeout=15)
        if not done:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            pytest.fail("OAuth 超时后的关闭在宽松的15秒预算内仍未返回")
        with pytest.raises((TaskError, TimeoutError)):
            task.result()
        assert memory_browser.contexts[0].close_started
        assert memory_browser.contexts[0].close_cancelled
        assert not memory_browser.started[0].started

    asyncio.run(scenario())


def test_relogin_already_expired_deadline_never_starts_browser(memory_browser, tmp_path) -> None:
    ctx = _context(tmp_path)
    ctx.deadline = Deadline(120)
    ctx.deadline._start = time.monotonic() - 300
    with pytest.raises((TaskError, TimeoutError)):
        asyncio.run(OAuthLogin().relogin(ctx))
    assert not memory_browser.started
    assert not memory_browser.oauth_calls


def test_relogin_uncommitted_navigation_reports_retryable_transient(memory_browser, tmp_path) -> None:
    """导航没能提交到目标站点（page 仍停在 about:blank）时，立即按可重试的链路问题上报，
    不把空白页喂给 Cloudflare 求解、也不死等到外层总超时误报「site_navigation 阶段超时」。"""
    from core.errors import TransientError

    ctx = _context(tmp_path)
    memory_browser.nav_stalls = True

    with pytest.raises(TransientError) as excinfo:
        asyncio.run(OAuthLogin().relogin(ctx))

    assert excinfo.value.reason == "network_error"
    assert (excinfo.value.data or {}).get("stage") == "site_navigation"
    assert "代理" in excinfo.value.message or "链路" in excinfo.value.message
    # 连站点都没连上就不该继续触发 OAuth；隔离浏览器仍被收尾关闭，不残留子进程。
    assert not memory_browser.oauth_calls
    assert memory_browser.contexts and memory_browser.contexts[0].closed
    assert not memory_browser.started[0].started


def test_relogin_uncommitted_first_hop_reloads_and_recovers(memory_browser, tmp_path) -> None:
    """首跳导航未提交多是链路抖动：预算充足时重载再试一次，第二跳提交后继续到 OAuth。"""
    ctx = _context(tmp_path)
    memory_browser.nav_commit_after = 2  # 第 1 次停在 about:blank，第 2 次提交

    state = asyncio.run(OAuthLogin().relogin(ctx))

    assert not state.verified and state.replace_credentials
    assert memory_browser.nav_attempts == 2, "首跳未提交仅追加一次重载重试"
    assert memory_browser.oauth_calls, "第二跳提交后应继续走 OAuth"


def test_relogin_does_not_replay_navigation_after_redirect(memory_browser, tmp_path, monkeypatch) -> None:
    from core.errors import TransientError

    async def redirected(page, url, **kwargs):
        memory_browser.nav_attempts += 1
        page.url = "https://github.com/login/oauth/authorize"

    monkeypatch.setattr(_MemoryPage, "goto", redirected)
    with pytest.raises(TransientError):
        asyncio.run(OAuthLogin().relogin(_context(tmp_path)))
    assert memory_browser.nav_attempts == 1
    assert not memory_browser.oauth_calls


def test_relogin_late_commit_during_backoff_avoids_extra_navigation(memory_browser, tmp_path, monkeypatch) -> None:
    from login import oauth

    async def delayed_commit(delay):
        assert delay == oauth._NAV_RETRY_BACKOFF_SECONDS
        memory_browser.contexts[0].pages[0].url = BASE_URL

    monkeypatch.setattr(oauth.asyncio, "sleep", delayed_commit)
    memory_browser.nav_stalls = True
    state = asyncio.run(OAuthLogin().relogin(_context(tmp_path)))
    assert not state.verified and state.replace_credentials
    assert memory_browser.nav_attempts == 1
    assert len(memory_browser.oauth_calls) == 1


def test_relogin_nav_retry_is_bounded_when_budget_low(memory_browser, tmp_path, monkeypatch) -> None:
    """剩余预算不足以再跑一整跳时不追加重载，直接收敛为可重试的链路问题。"""
    from core.errors import TransientError
    from login import oauth

    # 把重载门槛抬到高于整轮预算，模拟「预算不足以再跑一整跳」。
    monkeypatch.setattr(oauth, "_NAV_RETRY_MIN_SECONDS", 10_000.0)
    ctx = _context(tmp_path)
    memory_browser.nav_stalls = True

    with pytest.raises(TransientError) as excinfo:
        asyncio.run(OAuthLogin().relogin(ctx))

    assert (excinfo.value.data or {}).get("stage") == "site_navigation"
    assert memory_browser.nav_attempts == 1, "预算不足时不重载重试"
    assert not memory_browser.oauth_calls


@pytest.mark.parametrize("explicit_cookie", ["", "session=explicit-old"])
def test_engine_baseline_never_extracts_auth_from_browser_snapshot(
    memory_browser, monkeypatch, tmp_path, explicit_cookie,
) -> None:
    spec = _spec(credentials={"browser_state": encode_state(_site_state()), "session_cookie": explicit_cookie})
    calls = _http_balances(monkeypatch)
    clients = []
    baselines = []
    original_make = engine._make_http

    def make_http(account, *, log):
        client = original_make(account, log=log)
        clients.append(client)
        return client

    async def capture_baseline(_call):
        baselines.append((dict(clients[0].headers), clients[0].auth_refresher))

    monkeypatch.setattr(engine, "_make_http", make_http)
    memory_browser.on_oauth = capture_baseline
    result = asyncio.run(engine.run_account(
        spec, overlay=Overlay(path=tmp_path / "baseline.json").load(),
        oauth_state=lambda _provider, _name: encode_state(_shared_state()),
    ))
    assert result.ok, result.records[0].outcome.message
    assert len(baselines) == 1
    baseline = {key.lower(): value for key, value in baselines[0][0].items()}
    assert "authorization" not in baseline
    assert baseline.get("cookie", "") == explicit_cookie
    assert baseline["new-api-user"] == "42"
    assert baselines[0][1] is None
    if explicit_cookie:
        assert len(calls) == 3 and calls[0][3] is None
    else:
        assert len(calls) == 2, "没有旧 HTTP 认证时仅确认新会话并查新余额，不从浏览器快照提取基线"
    assert len(memory_browser.restores) == 1
    _assert_provider_only(memory_browser.restores[0][1], "github")


@pytest.mark.parametrize("new_auth", ["cookie", "token"])
def test_engine_applies_clean_http_auth_before_persisting_relogin(
    memory_browser, monkeypatch, tmp_path, new_auth,
) -> None:
    """大小写变体认证头与旧 cookiejar 都不能混到新身份；落盘必须晚于 adopt。"""
    if new_auth == "token":
        memory_browser.fresh_state = _site_state(NEW_TOKEN, "fresh-site-session")
    calls = _http_balances(monkeypatch)
    clients = []
    original_make = engine._make_http
    stale_jar = object()

    def make_http(account, *, log):
        client = original_make(account, log=log)
        client.headers = {"authorization": "Bearer wrong.old.identity", "cOoKiE": "session=stale", "X-Test": "keep"}
        client.cookie_jar = stale_jar
        clients.append(client)
        return client

    monkeypatch.setattr(engine, "_make_http", make_http)
    spec = _spec()
    overlay = Overlay(path=tmp_path / "auth-before-write.json").load()
    writes = []
    original_write = Overlay.record_credentials

    def record_credentials(store, account_spec, **kwargs):
        if store is overlay and kwargs.get("browser_state"):
            headers = {key.lower(): value for key, value in clients[0].headers.items()}
            writes.append((headers, clients[0].cookie_jar))
        return original_write(store, account_spec, **kwargs)

    monkeypatch.setattr(Overlay, "record_credentials", record_credentials)
    result = asyncio.run(engine.run_account(
        spec, overlay=overlay, oauth_state=lambda _provider, _name: encode_state(_shared_state()),
    ))
    assert result.ok, result.records[0].outcome.message
    assert len(writes) == 1 and len(calls) == 3
    headers, jar = writes[0]
    assert jar is None and calls[1][2] is None
    assert headers["x-test"] == "keep"
    assert headers["new-api-user"] == "42"
    if new_auth == "cookie":
        assert "authorization" not in headers
        assert headers["cookie"] == "session=fresh-site-session"
    else:
        assert "cookie" not in headers
        assert headers["authorization"] == f"Bearer {NEW_TOKEN}"
    assert "new-api-user" not in {key.lower() for key in calls[1][1]}, "首次候选确认不能沿用旧配置UID"
    assert {key.lower(): value for key, value in calls[2][1].items()} == headers
    assert decode_state(overlay.apply(spec, auth_scope=engine.authentication_scope(spec, args=spec.tasks[0].args)).credentials.browser_state) == memory_browser.fresh_state


def test_relogin_deadline_interrupts_pending_oauth_and_closes(memory_browser, tmp_path) -> None:
    saved = Mock()
    ctx = _context(tmp_path, persist=saved)
    before = ctx.credentials

    async def scenario():
        entered = asyncio.Event()
        cancelled = asyncio.Event()

        async def pending(_call):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        memory_browser.on_oauth = pending
        # 5秒业务预算加20秒清理余量，外层再给20秒调度余量，不用亚秒墙钟断言。
        ctx.deadline = Deadline(25)
        task = asyncio.create_task(OAuthLogin().relogin(ctx))
        try:
            await asyncio.wait_for(entered.wait(), timeout=10)
            done, _pending = await asyncio.wait({task}, timeout=20)
            if not done:
                pytest.fail("relogin 没有以剩余预算中断永不返回的 OAuth")
            with pytest.raises(TaskError) as exc:
                task.result()
            assert exc.value.reason == "network_error"
            assert exc.value.data["timeout_stage"] == "oauth"
            assert cancelled.is_set()
            assert memory_browser.contexts[0].closed
            assert not memory_browser.started[0].started
            assert ctx.credentials == before
            saved.assert_not_called()
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())


def test_engine_http_auth_install_failure_does_not_persist_fresh_credentials(
    memory_browser, monkeypatch, tmp_path,
) -> None:
    calls = _http_balances(monkeypatch)
    spec = _spec()
    overlay = Overlay(path=tmp_path / "adopt-failed.json").load()
    overlay.record_credentials(spec, browser_state=encode_state(_site_state()), access_token=OLD_TOKEN)
    before = dict(overlay.entry(spec.id).fields)
    original_adopt = HttpClient.adopt

    def reject_new_auth(client, fresh):
        if fresh.headers.get("Cookie") == "session=fresh-site-session":
            raise TaskError("模拟新 HTTP 认证安装失败")
        original_adopt(client, fresh)

    monkeypatch.setattr(HttpClient, "adopt", reject_new_auth)
    result = asyncio.run(engine.run_account(
        spec, overlay=overlay, oauth_state=lambda _provider, _name: encode_state(_shared_state()),
    ))
    assert not result.ok
    assert "新 HTTP 认证安装失败" in result.records[0].outcome.message
    assert len(calls) == 1, "认证未应用成功时不得继续新余额请求"
    assert dict(overlay.entry(spec.id).fields) == before
    assert memory_browser.contexts[0].closed


def test_fresh_relogin_never_renews_into_old_cached_identity(memory_browser, monkeypatch, tmp_path) -> None:
    _http_balances(monkeypatch)
    captured = []
    original_execute = engine._execute

    async def execute(ctx, *args):
        captured.append(ctx)
        return await original_execute(ctx, *args)

    monkeypatch.setattr(engine, "_execute", execute)
    renew = Mock(side_effect=AssertionError("新 OAuth 不得回退到旧 token/refresh/cookie"))
    monkeypatch.setattr(type(engine.LOGINS), "renew_sync", renew)
    spec = _spec(credentials={
        "access_token": OLD_TOKEN, "refresh_token": "old-refresh",
        "cookie": "session=old-manual", "browser_state": encode_state(_site_state()),
    })
    result = asyncio.run(engine.run_account(
        spec, overlay=Overlay(path=tmp_path / "no-old-renew.json").load(),
        oauth_state=lambda _provider, _name: encode_state(_shared_state()),
    ))
    assert result.ok
    ctx = captured[0]
    assert ctx.http.auth_refresher is None
    assert asyncio.run(ctx.login.renew()) is False
    monkeypatch.setattr(HttpClient, "_send", Mock(side_effect=LoginRequired("新会话已失效")))
    with pytest.raises(LoginRequired):
        ctx.http.get("/api/user/self")
    renew.assert_not_called()


class _AuthorizationPage:
    """GitHub OAuth 内存事件页：不创建浏览器、不访问网络。"""

    def __init__(self, url=BASE_URL):
        self.url = url
        self.main_frame = SimpleNamespace(url=url, page=self)
        self.listeners = {}
        self.context = SimpleNamespace(cookies=AsyncMock(return_value=[]))
        self.query_selector = AsyncMock(return_value=None)
        self.query_selector_all = AsyncMock(return_value=[])
        self.goto = AsyncMock(side_effect=self.navigate)

    def on(self, event, callback):
        self.listeners.setdefault(event, []).append(callback)

    def remove_listener(self, event, callback):
        self.listeners[event].remove(callback)

    def emit(self, event, value):
        for callback in list(self.listeners.get(event, [])):
            callback(value)

    def navigate(self, url, **_kwargs):
        self.url = url
        self.main_frame.url = url
        self.emit("framenavigated", self.main_frame)

    def is_closed(self):
        return False


def _authorization_button(*, visible=True, enabled=True, kind="continue", identity="alice", current="alice"):
    return SimpleNamespace(
        is_visible=AsyncMock(return_value=visible), is_enabled=AsyncMock(return_value=enabled),
        evaluate=AsyncMock(return_value={"kind": kind, "identity": identity, "current": current}),
        click=AsyncMock(),
    )


@pytest.fixture
def github_authorization(monkeypatch):
    from browser import oauth_flow, oauth_providers

    page = _AuthorizationPage()
    clock = SimpleNamespace(now=time.monotonic(), callback_at=None)
    provider = oauth_providers.get_oauth_provider("github")
    logs = []
    entry = AsyncMock()
    state_fetch = AsyncMock(side_effect=AssertionError("已有授权链不能重取 state"))
    client_fetch = AsyncMock(side_effect=AssertionError("已有授权链不能另起直连"))
    case = SimpleNamespace(module=oauth_flow, page=page, active=page, clock=clock, logs=logs,
                           provider=provider, entry=entry, state_fetch=state_fetch, client_fetch=client_fetch)

    async def frontend(*_args, **_kwargs):
        case.active.navigate("https://github.com/login/oauth/authorize?state=private-state&client_id=private-client&redirect_uri=https%3A%2F%2Fdemo.invalid%2Fapi%2Foauth%2Fgithub")
        return case.active

    async def sleep(seconds, deadline):
        clock.now += min(seconds, max(0, deadline - clock.now))
        if clock.callback_at is not None and clock.now >= clock.callback_at:
            case.active.navigate(BASE_URL + "/api/oauth/github?code=private-code&state=private-state")
            clock.callback_at = None
        await asyncio.sleep(0)

    async def run(*, budget=180):
        return await oauth_flow.trigger_oauth(page, BASE_URL, "github", logs.append,
                                             require_fresh=True, deadline=clock.now + budget)

    entry.side_effect = frontend
    case.run = run
    monkeypatch.setattr(oauth_flow, "time", SimpleNamespace(monotonic=lambda: clock.now))
    monkeypatch.setattr(oauth_flow, "_oauth_sleep", sleep)
    monkeypatch.setattr(oauth_flow, "OAUTH_WAIT_SECONDS", 90)
    monkeypatch.setattr(oauth_flow, "click_site_oauth_entry", entry)
    monkeypatch.setattr(oauth_flow, "fetch_oauth_state", state_fetch)
    monkeypatch.setattr(oauth_flow, "fetch_oauth_client_id", client_fetch)
    monkeypatch.setattr(oauth_flow, "site_error_messages", AsyncMock(return_value=[]))
    monkeypatch.setattr(oauth_flow, "is_waf_html", AsyncMock(return_value=False))
    monkeypatch.setattr(oauth_flow, "waf_is_blocked", lambda _page: False)
    monkeypatch.setattr(oauth_flow.bypass, "solve_cloudflare", AsyncMock(return_value=True))
    monkeypatch.setattr(oauth_flow.bypass, "has_cloudflare_challenge", AsyncMock(return_value=False))
    return case


def test_github_intermediate_popup_then_real_authorization(github_authorization):
    case = github_authorization
    popup = _AuthorizationPage("https://github.com/login/oauth/authorize?state=private-state&client_id=private-client&redirect_uri=https%3A%2F%2Fdemo.invalid%2Fapi%2Foauth%2Fgithub")
    case.active = popup
    intermediate = _authorization_button()
    authorize = _authorization_button()
    phase = {"value": "continue"}

    async def frontend(*_args, **_kwargs):
        case.page.emit("popup", popup)
        return popup

    async def confirm(**kwargs):
        assert kwargs["no_wait_after"] is True
        phase["value"] = "authorization"

    async def approve(**kwargs):
        assert kwargs["no_wait_after"] is True
        case.clock.callback_at = case.clock.now + 1

    intermediate.click.side_effect = confirm
    authorize.click.side_effect = approve
    popup.query_selector_all.side_effect = lambda _selector: [intermediate] if phase["value"] == "continue" else []
    popup.query_selector.side_effect = lambda selector: authorize if (
        selector in case.provider.approve_selectors and phase["value"] == "authorization"
    ) else None
    case.entry.side_effect = frontend
    result = asyncio.run(case.run())
    assert result["clicked"] and result["intermediate_clicked"] and result["landed_back"]
    assert result["fresh_evidence"] == {"provider_observed": True, "callback_observed": True}
    intermediate.click.assert_awaited_once()
    authorize.click.assert_awaited_once()
    case.state_fetch.assert_not_awaited()
    case.client_fetch.assert_not_awaited()
    assert "非正式授权" in str(case.logs)
    assert "popup=True" in str(case.logs)
    for secret in ("private-code", "private-state", "https://"):
        assert secret not in str(result) + str(case.logs)


@pytest.mark.parametrize("kind", ["unrelated", "disabled", "hidden"])
def test_github_never_clicks_unrelated_or_unavailable_submit(github_authorization, monkeypatch, kind):
    case = github_authorization
    button = _authorization_button(visible=kind != "hidden", enabled=kind != "disabled")

    def query(selector):
        matches = selector == 'button[type="submit"]' if kind == "unrelated" else selector in case.provider.approve_selectors
        return button if matches else None

    case.page.query_selector.side_effect = query
    monkeypatch.setattr(case.module, "APPROVE_WAIT_SECONDS", 0.5)
    monkeypatch.setattr(case.module, "OAUTH_WAIT_SECONDS", 0.5)
    result = asyncio.run(case.run())
    assert not result["clicked"] and not result["landed_back"]
    button.click.assert_not_awaited()
    assert all(selector.startswith("form") for selector in case.provider.approve_selectors)


@pytest.mark.parametrize("identities,current,chosen", [
    (["alice"], "", 0),
    (["alice", "bob"], "bob", 1),
    (["alice", "bob"], "", None),
    ([""], "", None),
])
def test_github_intermediate_requires_unambiguous_identity(github_authorization, identities, current, chosen):
    case = github_authorization
    buttons = [_authorization_button(kind="account_selection", identity=identity, current=current)
               for identity in identities]
    case.page.query_selector_all.return_value = buttons
    kind, button, human = asyncio.run(case.provider.intermediate_action(case.page))
    assert kind == "account_selection"
    assert human is (chosen is None)
    assert button is (None if chosen is None else buttons[chosen])


def test_github_disabled_other_account_is_still_ambiguous(github_authorization):
    case = github_authorization
    buttons = [_authorization_button(identity="alice", current=""),
               _authorization_button(identity="bob", current="", enabled=False)]
    case.page.query_selector_all.return_value = buttons
    result = asyncio.run(case.run())
    assert result["need_human"] and result["human_reason"] == "account_selection"
    assert not result["clicked"]
    for button in buttons:
        button.click.assert_not_awaited()


@pytest.mark.parametrize("marker", ['input[type="password"]', 'input[autocomplete="one-time-code"]'])
def test_github_password_and_two_factor_require_human(github_authorization, marker):
    case = github_authorization
    human = _authorization_button()
    authorize = _authorization_button()
    case.page.query_selector.side_effect = lambda selector: (
        human if selector == marker else authorize if selector in case.provider.approve_selectors else None
    )
    result = asyncio.run(case.run())
    assert result["need_human"] and result["human_reason"] == "verification"
    authorize.click.assert_not_awaited()
    human.click.assert_not_awaited()


@pytest.mark.parametrize("raise_after_submit", [False, True])
def test_github_slow_callback_never_repeats_authorization(github_authorization, raise_after_submit):
    case = github_authorization
    button = _authorization_button()
    started = case.clock.now

    async def click(**kwargs):
        assert kwargs["no_wait_after"] is True
        case.clock.callback_at = case.clock.now + 50
        if raise_after_submit:
            raise TimeoutError("模拟已提交后驱动导航超时")

    button.click.side_effect = click
    case.page.query_selector.side_effect = lambda selector: button if selector in case.provider.approve_selectors else None
    result = asyncio.run(case.run())
    assert result["clicked"] and result["landed_back"] and result["fresh_authorization"]
    assert case.clock.now - started >= 50 - 1e-6
    button.click.assert_awaited_once()
    case.state_fetch.assert_not_awaited()


def test_github_intermediate_submit_timeout_is_not_replayed(github_authorization, monkeypatch):
    case = github_authorization
    intermediate = _authorization_button()
    intermediate.click.side_effect = TimeoutError("模拟确认已发送，但页面仍未变")
    case.page.query_selector_all.return_value = [intermediate]
    monkeypatch.setattr(case.module, "APPROVE_WAIT_SECONDS", 1)
    monkeypatch.setattr(case.module, "OAUTH_WAIT_SECONDS", 1)
    result = asyncio.run(case.run())
    assert result["intermediate_clicked"] and not result["clicked"]
    intermediate.click.assert_awaited_once()
    case.state_fetch.assert_not_awaited()


@pytest.mark.parametrize("budget,expected", [(180, "phase_cap"), (1, "overall")])
def test_github_callback_timeout_distinguishes_phase_and_overall(github_authorization, monkeypatch, budget, expected):
    case = github_authorization
    button = _authorization_button()
    case.page.query_selector.side_effect = lambda selector: button if selector in case.provider.approve_selectors else None
    monkeypatch.setattr(case.module, "OAUTH_WAIT_SECONDS", 2)
    result = asyncio.run(case.run(budget=budget))
    assert result["timeout_kind"] == expected
    assert result["timeout_stage"] == "callback"
    assert ("阶段等待上限已到" if expected == "phase_cap" else "总预算耗尽") in str(case.logs)
    button.click.assert_awaited_once()


def test_relogin_reserves_confirmation_export_and_close_budget(memory_browser, monkeypatch, tmp_path):
    from login import oauth

    ctx = _context(tmp_path)
    ctx.deadline = Deadline(500)
    observed = {}

    async def confirm(_ctx, _page, deadline, *, export_reserve, handoff=None):
        observed.update(deadline=deadline, export_reserve=export_reserve)
        return True

    monkeypatch.setattr(oauth, "_confirm_after_relogin", confirm)
    asyncio.run(OAuthLogin().relogin(ctx))
    call = memory_browser.oauth_calls[0]
    assert observed["deadline"] - call["deadline"] == pytest.approx(
        oauth._STATE_EXPORT_RESERVE + oauth._SERVER_CONFIRM_RESERVE,
    )
    assert observed["export_reserve"] == oauth._STATE_EXPORT_RESERVE
    assert observed["deadline"] <= call["at"] + 240 - oauth._RELOGIN_CLOSE_RESERVE
    assert call["require_fresh"] is True
    assert memory_browser.contexts[0].closed


def test_relogin_server_confirmation_cannot_consume_export_reserve(memory_browser, monkeypatch, tmp_path):
    from login import oauth

    ctx = _context(tmp_path)
    cancelled = []

    async def stalled(*_args):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    monkeypatch.setattr(oauth, "_server_confirms_login", stalled)

    async def scenario():
        deadline = time.monotonic() + 5.05
        assert not await oauth._confirm_after_relogin(ctx, _MemoryPage(memory_browser), deadline, export_reserve=5)
        assert deadline - time.monotonic() > 4

    asyncio.run(scenario())
    assert cancelled == [True]


@pytest.mark.parametrize("timeout_kind", ["phase_cap", "overall"])
def test_relogin_callback_failure_keeps_old_credentials(memory_browser, tmp_path, timeout_kind):
    saved = Mock()
    ctx = _context(tmp_path, persist=saved)
    before = ctx.credentials
    memory_browser.link = {"clicked": True, "landed_back": False, "fresh_authorization": False,
                           "timeout_stage": "callback", "timeout_kind": timeout_kind}
    with pytest.raises(TaskError) as error:
        asyncio.run(OAuthLogin().relogin(ctx))
    assert error.value.data["oauth"]["timeout_kind"] == timeout_kind
    assert ctx.credentials == before
    assert memory_browser.storage_state_calls == 0
    assert memory_browser.contexts[0].closed
    saved.assert_not_called()


@pytest.mark.parametrize("navigation", [None, {"state": "provider", "provider_observed": True, "load_error": "none"}])
def test_relogin_without_authorization_action_reports_login_required_and_keeps_old_credentials(
    memory_browser, tmp_path, navigation,
):
    saved = Mock()
    ctx = _context(tmp_path, persist=saved)
    before = ctx.credentials
    memory_browser.link = {
        "clicked": False, "intermediate_clicked": False, "landed_back": False,
        "fresh_authorization": False, "timeout_stage": "approval", "timeout_kind": "phase_cap",
        "page_kind": "unknown", "popup": True, "navigation": navigation,
    }
    with pytest.raises(LoginRequired) as error:
        asyncio.run(OAuthLogin().relogin(ctx))
    assert error.value.reason == "oauth_incomplete"
    assert "尚未完成可操作的授权动作" in str(error.value)
    assert "保留旧认证信息" in str(error.value)
    assert "授权页未能加载" not in str(error.value)
    assert error.value.data["oauth"]["timeout_stage"] == "approval"
    assert ctx.credentials == before
    assert memory_browser.storage_state_calls == 0
    assert memory_browser.contexts[0].closed
    saved.assert_not_called()


@pytest.mark.parametrize("navigation", [
    {"state": "blank", "provider_observed": False, "load_error": "none"},
    {"state": "uncommitted", "provider_observed": False, "provider_requested": True, "load_error": "none"},
    {"state": "load_failed", "provider_observed": False, "load_error": "network", "recovery_attempted": True},
])
def test_relogin_with_popup_that_never_loads_is_transient_not_human_action(memory_browser, tmp_path, navigation):
    """只有明确的导航证据可归因加载未完成，unknown DOM 或 popup 本身不能证明网络故障。"""
    saved = Mock()
    ctx = _context(tmp_path, persist=saved)
    before = ctx.credentials
    memory_browser.link = {
        "clicked": False, "intermediate_clicked": False, "landed_back": False,
        "fresh_authorization": False, "timeout_stage": "approval", "timeout_kind": "phase_cap",
        "page_kind": "unknown", "popup": True, "navigation": navigation,
    }
    with pytest.raises(TransientError) as error:
        asyncio.run(OAuthLogin().relogin(ctx))
    assert "授权页未能加载" in str(error.value)
    assert error.value.reason == "network_error"
    assert error.value.data["oauth"]["navigation"] == navigation
    assert error.value.data["oauth"]["popup"] is True
    assert ctx.credentials == before
    assert memory_browser.storage_state_calls == 0
    saved.assert_not_called()


def test_oauth_navigation_diagnostics_drop_unknown_fields_and_sensitive_values():
    from login.oauth import _oauth_error

    error = _oauth_error("github", "configured", {
        "timeout_stage": "approval", "page_kind": "unknown", "popup": True,
        "navigation": {
            "state": "https://github.com/login/oauth/authorize?state=private-state&client_id=private-client&redirect_uri=https%3A%2F%2Fdemo.invalid%2Fapi%2Foauth%2Fgithub",
            "provider_observed": True,
            "provider_requested": "private-code",
            "load_error": "net::ERR_RESET https://site.invalid?token=private-token",
            "authorize_url": "https://github.com/login/oauth/authorize?state=private-state&client_id=private-client&redirect_uri=https%3A%2F%2Fdemo.invalid%2Fapi%2Foauth%2Fgithub",
            "recovery_attempted": False,
        },
    })
    assert error.reason == "oauth_incomplete"
    assert error.data["oauth"]["navigation"] == {"provider_observed": True, "recovery_attempted": False}
    for secret in ("private-state", "private-code", "private-token", "https://"):
        assert secret not in str(error.data) + str(error)


def test_relogin_provider_cf_page_wait_never_implies_expired_or_ip_reputation(memory_browser, tmp_path):
    saved = Mock()
    ctx = _context(tmp_path, persist=saved)
    before = ctx.credentials
    memory_browser.link = {
        "landed_back": False, "cloudflare": True, "stage": "provider_cf",
        "navigation": {"state": "provider", "provider_observed": True, "recovery_attempted": True},
        "cf_diagnostics": {"stage": "provider_cf", "target_kind": "page", "clicked": False,
                           "timeout_stage": "page_wait", "reason": "challenge_unresolved"},
    }
    with pytest.raises(TaskError) as error:
        asyncio.run(OAuthLogin().relogin(ctx))
    assert error.value.reason == "need_verification"
    assert "page_wait" in str(error.value)
    assert "不能据此判断 IP 信誉" in str(error.value)
    assert ctx.credentials == before
    assert memory_browser.storage_state_calls == 0
    saved.assert_not_called()


@pytest.mark.parametrize("url", [
    "https://github.com.evil.invalid/login/oauth/authorize",
    "https://user-content.github.com/login/oauth/authorize",
    "http://github.com/login/oauth/authorize",
    "https://github.com:8443/login/oauth/authorize",
])
def test_github_authorization_requires_exact_provider_origin(github_authorization, monkeypatch, url):
    case = github_authorization
    button = _authorization_button()
    case.page.query_selector.side_effect = lambda selector: button if selector in case.provider.approve_selectors else None

    async def frontend(*_args, **_kwargs):
        case.page.navigate(url)
        return case.page

    case.entry.side_effect = frontend
    monkeypatch.setattr(case.module, "APPROVE_WAIT_SECONDS", 0.5)
    monkeypatch.setattr(case.module, "OAUTH_WAIT_SECONDS", 0.5)
    result = asyncio.run(case.run())
    assert not result["fresh_authorization"] and not result["clicked"]
    button.click.assert_not_awaited()


def test_oauth_callback_default_and_environment_override(monkeypatch):
    from pathlib import Path
    import runpy

    settings = Path(__file__).resolve().parents[1] / "config" / "settings.py"
    monkeypatch.delenv("CHECKIN_OAUTH_WAIT", raising=False)
    assert runpy.run_path(str(settings))["Timeouts"].OAUTH_WAIT == 90
    monkeypatch.setenv("CHECKIN_OAUTH_WAIT", "75")
    assert runpy.run_path(str(settings))["Timeouts"].OAUTH_WAIT == 75


def test_relogin_unlimited_account_still_has_bounded_confirmation(memory_browser, tmp_path):
    ctx = _context(tmp_path)
    ctx.deadline = Deadline()
    result = asyncio.run(OAuthLogin().relogin(ctx))
    assert not result.verified and result.replace_credentials
    assert memory_browser.oauth_calls[0]["deadline"] <= time.monotonic() + 240
    assert memory_browser.contexts[0].closed


def test_provider_renewal_state_is_provider_only_and_target_safe():
    source = {
        "cookies": [
            _cookie("user_session", ".github.com", "auth"),
            _cookie("CF_Clearance", ".github.com", "cf"),
            _cookie("site", "demo.invalid", "site"),
        ],
        "origins": [_origin("https://github.com", "secret")],
    }
    result = storage_scope.provider_renewal_state(source, "github", BASE_URL, now=100)
    assert result["origins"] == []
    assert result["cookies"] == [{
        "name": "user_session", "value": "auth", "domain": ".github.com", "path": "/",
        "expires": -1, "httpOnly": True, "secure": True, "sameSite": "Lax",
    }]
    result["cookies"][0]["value"] = "changed"
    assert source["cookies"][0]["value"] == "auth"


def test_provider_state_rotated_does_not_treat_local_expiry_revival_as_rotation():
    previous = {"cookies": [_cookie("user_session", ".github.com", "same")]}
    current = {"cookies": [_cookie("user_session", "github.com", "same")]}
    previous["cookies"][0]["expires"] = 200
    current["cookies"][0]["expires"] = -1
    assert not storage_scope.provider_state_rotated(previous, current, "github", now=100)
    current["cookies"][0]["value"] = "rotated"
    assert storage_scope.provider_state_rotated(previous, current, "github", now=100)


def test_oauth_state_update_requires_source_fresh_and_rotation():
    from login.oauth import oauth_state_update

    previous = {"cookies": [_cookie("user_session", "github.com", "old")]}
    source = SimpleNamespace(provider="github", state=encode_state(previous))
    current = {"cookies": [_cookie("user_session", ".github.com", "new")]}
    update = oauth_state_update(source, current, "github", base_url=BASE_URL, fresh_authorization=True)
    assert update is not None and update.source is source and update.fresh_authorization
    assert decode_state(update.state)["cookies"][0]["domain"] == ".github.com"
    assert oauth_state_update(None, current, "github", fresh_authorization=True) is None


def test_provider_renewal_state_rejects_subdomains_public_suffix_and_bad_expiry():
    source = {"cookies": [
        _cookie("user_session", "sub.github.com", "sub"),
        _cookie("user_session", "github.com.evil.invalid", "evil"),
        _cookie("user_session", "com", "public"),
        _cookie("user_session", ".github.com", "bad",),
        _cookie("other", ".github.com", "ok"),
    ], "origins": [{"origin": "https://github.com", "localStorage": [{"name": "x", "value": "y"}]}]}
    source["cookies"][3]["expires"] = "not-a-number"
    with pytest.raises(ValueError):
        storage_scope.provider_renewal_state(source, "github", now=100)
    source["cookies"].append(_cookie("user_session", ".github.com", "valid"))
    result = storage_scope.provider_renewal_state(source, "github", now=100)
    assert [item["name"] for item in result["cookies"]] == ["other", "user_session"]
    assert result["cookies"][0]["domain"] == ".github.com"
    assert result["origins"] == []


def test_provider_renewal_state_linuxdo_keeps_exact_domains_and_removes_target_cookies():
    source = {"cookies": [
        _cookie("_t", ".linux.do", "forum"),
        _cookie("connect_session", "connect.linux.do", "connect"),
        _cookie("_t", "sub.linux.do", "sub"),
        _cookie("_t", ".connect.linux.do", "subconnect"),
    ]}
    result = storage_scope.provider_renewal_state(source, "linuxdo", "https://demo.invalid", now=100)
    assert {item["domain"] for item in result["cookies"]} == {".linux.do", "connect.linux.do", ".connect.linux.do"}
    forum = storage_scope.provider_renewal_state(source, "linuxdo", "", now=100)
    assert {item["domain"] for item in forum["cookies"]} == {".linux.do", "connect.linux.do", ".connect.linux.do"}


def test_provider_state_rotated_accepts_session_to_future_expiry_extension():
    previous = {"cookies": [_cookie("user_session", ".github.com", "same")]}
    current = {"cookies": [_cookie("user_session", ".github.com", "same")]}
    current["cookies"][0]["expires"] = 200
    assert storage_scope.provider_state_rotated(previous, current, "github", now=100)
    current["cookies"][0]["value"] = ""
    assert not storage_scope.provider_state_rotated(previous, current, "github", now=100)


def _provider_cookie(provider, value):
    name, domain = ("user_session", ".github.com") if provider == "github" else ("_t", ".linux.do")
    return _cookie(name, domain, value)


def _rotated_state(provider, *, value="renewed", base_url=BASE_URL):
    from urllib.parse import urlsplit

    return {
        "cookies": [
            _provider_cookie(provider, value),
            _cookie("session", urlsplit(base_url).hostname, "fresh-site-session"),
            _cookie("cf_clearance", ".github.com" if provider == "github" else ".linux.do", "fresh-cf"),
            _provider_cookie("linuxdo" if provider == "github" else "github", "other-provider"),
        ],
        "origins": [_origin(base_url, NEW_TOKEN), _origin("https://github.com"), _origin("https://linux.do")],
    }


def _shared_runtime_case(tmp_path, provider="github", *, seed=False, configured_state=None):
    from config.schema import OAuthStateReader

    configured = configured_state or encode_state({"cookies": [_provider_cookie(provider, "configured")], "origins": []})
    raw = {
        "version": 3,
        "accounts": [{"id": "relogin-demo", "base_url": BASE_URL, "template": "newapi"}],
        "oauth_states": {provider: {"accounts": {
            "configured": {"state": configured, "updated_at": "capture-one"},
            "other": {"state": configured, "updated_at": "capture-other"},
        }}},
    }
    config_path = tmp_path / "ACCOUNTS.json"
    config_path.write_text(json.dumps(raw), encoding="utf-8")
    document = schema.parse_document(raw, path=config_path)
    reader = OAuthStateReader(document.oauth_states, config_path)
    path = tmp_path / "shared-runtime.json"
    overlay = Overlay(path, accounts_path=config_path).load()
    if seed:
        resolver = engine._shared_oauth_resolver(overlay, reader)
        seeded = encode_state({"cookies": [_provider_cookie(provider, "seeded")], "origins": []})
        assert overlay.record_oauth_state(resolver(provider, "configured"), seeded)
    return SimpleNamespace(configured=configured, raw=raw, config_path=config_path,
                           path=path, reader=reader, overlay=overlay, provider=provider)


def _oauth_cache_bytes(path):
    # 引擎仍会记录 health；逐字节比较独立 oauth_states 命名空间，排除无关健康元数据。
    return json.dumps(json.loads(path.read_bytes())["oauth_states"], sort_keys=True).encode()


@pytest.mark.parametrize("provider", ["github", "linuxdo"])
@pytest.mark.parametrize("failure", ["not_fresh", "not_confirmed", "cancel", "cancel_export", "export", "http_adopt"])
def test_shared_relogin_failure_preserves_cached_bytes_and_site_credentials(
    memory_browser, monkeypatch, tmp_path, provider, failure,
):
    from login import oauth

    case = _shared_runtime_case(tmp_path, provider, seed=True)
    spec = _spec(login={"method": "oauth", "provider": provider, "account": "configured"})
    case.overlay.record_credentials(spec, browser_state=encode_state(_site_state()), access_token=OLD_TOKEN)
    cache_before = _oauth_cache_bytes(case.path)
    site_before = dict(case.overlay.entry(spec.id).fields)
    config_before = case.config_path.read_bytes()
    memory_browser.fresh_state = _rotated_state(provider)
    _http_balances(monkeypatch)
    if failure == "not_fresh":
        memory_browser.link["fresh_authorization"] = False
    elif failure == "not_confirmed":
        monkeypatch.setattr(oauth, "_confirm_after_relogin", AsyncMock(return_value=False))
    elif failure == "cancel":
        memory_browser.error = asyncio.CancelledError()
    elif failure == "cancel_export":
        monkeypatch.setattr(_MemoryContext, "storage_state", AsyncMock(side_effect=asyncio.CancelledError()))
    elif failure == "export":
        monkeypatch.setattr(_MemoryContext, "storage_state", AsyncMock(side_effect=RuntimeError("export rejected")))
    else:
        original = HttpClient.adopt

        def reject(client, fresh):
            if (fresh.headers.get("Cookie") == "session=fresh-site-session"
                    or fresh.headers.get("Authorization") == f"Bearer {NEW_TOKEN}"):
                raise TaskError("HTTP adopt rejected")
            return original(client, fresh)

        monkeypatch.setattr(HttpClient, "adopt", reject)
    run = engine.run_account(spec, overlay=case.overlay, oauth_state=case.reader)
    if failure in {"cancel", "cancel_export"}:
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(run)
    else:
        assert not asyncio.run(run).ok
    assert _oauth_cache_bytes(case.path) == cache_before
    assert dict(case.overlay.entry(spec.id).fields) == site_before
    assert case.config_path.read_bytes() == config_before
    assert all(context.closed for context in memory_browser.contexts)


@pytest.mark.parametrize("provider", ["github", "linuxdo"])
@pytest.mark.parametrize("expires_change", ["removed", "session"])
def test_local_expiry_revival_never_refreshes_shared_ttl(
    memory_browser, monkeypatch, tmp_path, provider, expires_change,
):
    case = _shared_runtime_case(tmp_path, provider, seed=True)
    resolver = engine._shared_oauth_resolver(case.overlay, case.reader)
    source = resolver(provider, "configured")
    previous = decode_state(source.state)
    previous["cookies"][0]["expires"] = time.time() + 10_000
    assert case.overlay.record_oauth_state(source, encode_state(previous))
    cache_before = _oauth_cache_bytes(case.path)
    memory_browser.fresh_state = _rotated_state(provider, value="seeded")
    if expires_change == "removed":
        memory_browser.fresh_state["cookies"][0].pop("expires")
    _http_balances(monkeypatch)
    spec = _spec(login={"method": "oauth", "provider": provider, "account": "configured"})
    result = asyncio.run(engine.run_account(spec, overlay=case.overlay, oauth_state=case.reader))
    assert result.ok
    assert _oauth_cache_bytes(case.path) == cache_before, "删 expiry/改为 -1 不可续期共享 TTL"


def _shared_update(source, value):
    from login.base import LoginState
    from login.oauth import oauth_state_update

    update = oauth_state_update(source, _rotated_state(source.provider, value=value), source.provider,
                                base_url=BASE_URL, fresh_authorization=True)
    assert update is not None
    return LoginState("oauth", verified=True, oauth_updates=(update,))


def test_same_source_concurrent_publish_rejects_losing_cas(tmp_path):
    case = _shared_runtime_case(tmp_path, seed=True)
    left = engine._shared_oauth_resolver(case.overlay, case.reader)
    right_overlay = Overlay(case.path, accounts_path=case.config_path).load()
    right = engine._shared_oauth_resolver(right_overlay, case.reader)
    a, b = left("github", "configured"), right("github", "configured")
    assert a.revision == b.revision
    engine._record_oauth_updates(_shared_update(a, "winner"), case.overlay, left)
    winner_bytes = case.path.read_bytes()
    engine._record_oauth_updates(_shared_update(b, "loser"), right_overlay, right)
    assert case.path.read_bytes() == winner_bytes
    assert decode_state(left("github", "configured").state)["cookies"][0]["value"] == "winner"


@pytest.mark.parametrize("mutation", ["state", "updated_at", "account_deleted", "config_deleted",
                                      "config_corrupt", "cache_deleted", "cache_corrupt"])
def test_old_oauth_run_rejects_changed_capture_or_deleted_corrupt_file(tmp_path, mutation):
    case = _shared_runtime_case(tmp_path, seed=True)
    resolver = engine._shared_oauth_resolver(case.overlay, case.reader)
    state = _shared_update(resolver("github", "configured"), "stale-run")
    if mutation == "cache_deleted":
        case.path.unlink()
    elif mutation == "cache_corrupt":
        case.path.write_bytes(b"{broken cache")
    elif mutation == "config_deleted":
        case.config_path.unlink()
    elif mutation == "config_corrupt":
        case.config_path.write_bytes(b"{broken config")
    else:
        capture = case.raw["oauth_states"]["github"]["accounts"]
        if mutation == "account_deleted":
            del capture["configured"]
        elif mutation == "state":
            capture["configured"]["state"] = encode_state({"cookies": [_provider_cookie("github", "recaptured")]})
        else:
            capture["configured"]["updated_at"] = "capture-two"
        case.config_path.write_text(json.dumps(case.raw), encoding="utf-8")
    before = case.path.read_bytes() if case.path.exists() else None
    config_before = case.config_path.read_bytes() if case.config_path.exists() else None
    engine._record_oauth_updates(state, case.overlay, resolver)
    assert (case.path.read_bytes() if case.path.exists() else None) == before
    assert (case.config_path.read_bytes() if case.config_path.exists() else None) == config_before


@pytest.mark.parametrize("policy", ["ignore", "readonly"])
def test_engine_shared_updates_honor_no_write_policy(tmp_path, policy):
    case = _shared_runtime_case(tmp_path, seed=True)
    overlay = Overlay(case.path, accounts_path=case.config_path, policy=policy).load()
    resolver = engine._shared_oauth_resolver(overlay, case.reader)
    state = _shared_update(resolver("github", "configured"), "must-not-write")
    before = case.path.read_bytes()
    engine._record_oauth_updates(state, overlay, resolver)
    assert case.path.read_bytes() == before


@pytest.mark.parametrize("provider", ["github", "linuxdo"])
def test_normal_oauth_pristine_provider_source_yields_rotated_update(memory_browser, tmp_path, provider):
    # 即使共享捕获混有站点/另一 provider，本次导入也必须限定 provider。
    polluted = _shared_state()
    polluted["cookies"].append(_provider_cookie(provider, "configured"))
    case = _shared_runtime_case(tmp_path, provider, configured_state=encode_state(polluted))
    resolver = engine._shared_oauth_resolver(case.overlay, case.reader)
    ctx = _context(tmp_path, spec=_spec(credentials={}, login={"method": "oauth", "provider": provider,
                                                           "account": "configured"}))
    ctx.oauth_resolve = Mock(wraps=resolver)
    memory_browser.fresh_state = _rotated_state(provider)
    state = asyncio.run(OAuthLogin().authenticate(ctx))
    assert not state.verified and state.replace_credentials and len(state.oauth_updates) == 1
    update = state.oauth_updates[0]
    assert update.fresh_authorization and not update.same_identity
    assert decode_state(update.state) == {"cookies": [_provider_cookie(provider, "renewed")], "origins": []}
    restored = memory_browser.restores[0][1]
    assert all(cookie["domain"] != "demo.invalid" for cookie in restored["cookies"])
    assert all(origin["origin"] != BASE_URL for origin in restored["origins"])
    assert memory_browser.oauth_calls[0]["require_fresh"] is True
    asyncio.run(ctx.browser.aclose())


@pytest.mark.parametrize("shortcut,pending", [(False, False), (False, True), (True, False)])
def test_normal_oauth_site_snapshot_never_reads_or_updates_shared(
    memory_browser, monkeypatch, tmp_path, shortcut, pending,
):
    from login import oauth

    ctx = _context(tmp_path)
    # 站点快照路径会静态比较共享态是否更新；共享来源不可用时只能沿用快照，绝不写回。
    ctx.oauth_resolve = Mock(side_effect=AssertionError("共享来源不可用"))
    confirmations = [True] if shortcut else [False, False, True] if pending else [False, True]
    monkeypatch.setattr(oauth, "_server_confirms_login", AsyncMock(side_effect=confirmations))
    memory_browser.fresh_state = _rotated_state("github")
    restores_before = len(memory_browser.restores)
    state = asyncio.run(OAuthLogin().authenticate(ctx))
    assert not state.verified and state.replace_credentials and not state.oauth_updates
    assert len(memory_browser.restores) == restores_before + 1, "不得注入任何共享态"
    assert len(memory_browser.oauth_calls) == (0 if shortcut else 1)
    asyncio.run(ctx.browser.aclose())


def test_normal_oauth_already_started_provider_identity_is_not_shared_write_source(
    memory_browser, tmp_path,
):
    case = _shared_runtime_case(tmp_path)
    ctx = _context(tmp_path, spec=_spec(credentials={}))
    ctx.oauth_resolve = engine._shared_oauth_resolver(case.overlay, case.reader)
    memory_browser.fresh_state = _rotated_state("github")

    async def run():
        async with ctx.browser.lease(reason="earlier-provider", state_text=encode_state({
            "cookies": [_provider_cookie("github", "different-owner")], "origins": [],
        })):
            pass
        assert ctx.browser.started
        state = await OAuthLogin().authenticate(ctx)
        assert not state.verified and state.replace_credentials and not state.oauth_updates
        await ctx.browser.aclose()

    asyncio.run(run())


def test_shared_same_source_parallel_publish_has_exactly_one_cas_winner(monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier, Lock

    case = _shared_runtime_case(tmp_path, seed=True)
    overlays = [case.overlay, Overlay(case.path, accounts_path=case.config_path).load()]
    resolvers = [engine._shared_oauth_resolver(overlay, case.reader) for overlay in overlays]
    states = [_shared_update(resolver("github", "configured"), value)
              for resolver, value in zip(resolvers, ("parallel-a", "parallel-b"))]
    assert states[0].oauth_updates[0].source.revision == states[1].oauth_updates[0].source.revision
    gate, lock, accepted = Barrier(2), Lock(), []
    original = Overlay.record_oauth_state

    def record(overlay, *args, **kwargs):
        result = original(overlay, *args, **kwargs)
        with lock:
            accepted.append(result)
        return result

    monkeypatch.setattr(Overlay, "record_oauth_state", record)

    def publish(index):
        gate.wait(timeout=5)
        engine._record_oauth_updates(states[index], overlays[index], resolvers[index])

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(publish, index) for index in range(2)]
        for future in futures:
            future.result(timeout=10)
    assert sorted(accepted) == [False, True]
    winner = decode_state(resolvers[0]("github", "configured").state)
    assert winner["cookies"][0]["value"] in {"parallel-a", "parallel-b"}
    assert winner["origins"] == []


@pytest.mark.parametrize("gate", ["legacy_reader", "not_fresh", "not_confirmed"])
def test_normal_oauth_requires_known_source_fresh_chain_and_server_confirmation(
    memory_browser, monkeypatch, tmp_path, gate,
):
    from login import oauth

    case = _shared_runtime_case(tmp_path, seed=True)
    ctx = _context(tmp_path, spec=_spec(credentials={}))
    ctx.oauth_resolve = None if gate == "legacy_reader" else engine._shared_oauth_resolver(case.overlay, case.reader)
    ctx.oauth_state = case.reader
    memory_browser.fresh_state = _rotated_state("github")
    before = case.path.read_bytes()
    if gate == "not_fresh":
        memory_browser.link["fresh_authorization"] = False
    if gate == "not_confirmed":
        monkeypatch.setattr(oauth, "_server_confirms_login", AsyncMock(return_value=False))
        with pytest.raises(LoginRequired):
            asyncio.run(OAuthLogin().authenticate(ctx))
    else:
        state = asyncio.run(OAuthLogin().authenticate(ctx))
        assert not state.verified and state.replace_credentials and not state.oauth_updates
        engine._record_oauth_updates(state, case.overlay, ctx.oauth_resolve)
    assert case.path.read_bytes() == before
    asyncio.run(ctx.browser.aclose())


def test_provider_renewal_state_removes_provider_cookie_sent_to_target_subdomain():
    source = {"cookies": [_cookie("user_session", ".github.com", "auth")]}
    with pytest.raises(ValueError):
        storage_scope.provider_renewal_state(source, "github", "https://app.github.com", now=100)


def test_provider_renewal_state_rejects_bool_nonfinite_and_expired_auth_cookies():
    for expires in (True, float("nan"), float("inf"), 99):
        source = {"cookies": [_cookie("user_session", ".github.com", "auth")]}
        source["cookies"][0]["expires"] = expires
        with pytest.raises(ValueError):
            storage_scope.provider_renewal_state(source, "github", now=100)


def test_provider_state_rotated_ignores_domain_metadata_and_expiry_removal():
    previous = {"cookies": [_cookie("user_session", ".github.com", "same")]}
    current = {"cookies": [_cookie("user_session", "github.com", "same")]}
    previous["cookies"][0]["expires"] = 200
    current["cookies"][0]["expires"] = -1
    assert not storage_scope.provider_state_rotated(previous, current, "github", now=100)
