"""隔离 OAuth 重登：真实引擎/登录服务配内存浏览器，绝不启动浏览器或访问网络。"""

from __future__ import annotations

import asyncio
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
from core.errors import LoginRequired, TaskError
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
        self.url = "about:blank" if getattr(self.harness, "nav_stalls", False) else url

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
    assert state.verified and state.method == "oauth"
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

    assert state.verified and state.method == "oauth"
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
def test_relogin_requires_fresh_callback_and_server_confirmation(memory_browser, tmp_path, link, confirmed) -> None:
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
    assert len(calls) == 2
    assert calls[0][1].get("Authorization") == f"Bearer {OLD_TOKEN}"
    assert calls[0][1].get("New-Api-User") == "42"
    assert calls[0][3] is None, "旧余额基线禁止自动续期"
    assert calls[1][1].get("Cookie") == "session=fresh-site-session"
    assert not any(key.lower() == "authorization" for key in calls[1][1])
    resolved = overlay.apply(spec)
    assert resolved.credentials.session_cookie == "session=fresh-site-session"
    assert decode_state(resolved.credentials.browser_state) == memory_browser.fresh_state


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
    assert len(calls) == 2 and len(memory_browser.oauth_calls) == 1
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
        assert len(calls) == 2 and calls[0][3] is None
    else:
        assert len(calls) == 1, "没有旧 HTTP 认证时应跳过基线，而不是从浏览器快照提取凭据"
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
    assert len(writes) == 1 and len(calls) == 2
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
    assert {key.lower(): value for key, value in calls[1][1].items()} == headers
    assert decode_state(overlay.apply(spec).credentials.browser_state) == memory_browser.fresh_state


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
