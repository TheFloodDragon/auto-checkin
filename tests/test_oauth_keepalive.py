"""linux.do 共享登录态保活：任务前静态检查、到期前续期、多副本同步。离线，不开真实浏览器。"""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from browser import popups, runtime_loop, storage_scope, bypass, state as browser_state
from browser.service import BrowserService, decode_state, encode_state
from config import schema
from config.overlay import CachePolicy, Overlay
from config.schema import OAuthStateReader
from runtime import engine, keepalive
from templates import registry as templates

HOUR = 3600.0


def _state(value: str, expires_in: float | None) -> str:
    cookie = {"name": "_t", "value": value, "domain": ".linux.do", "path": "/",
              "expires": -1 if expires_in is None else time.time() + expires_in,
              "httpOnly": True, "secure": True, "sameSite": "Lax"}
    return encode_state({"cookies": [cookie], "origins": []})


def _case(tmp_path, *, state: str, policy=CachePolicy.COMPATIBLE):
    raw = {
        "version": 3,
        "accounts": [{"id": "forum", "base_url": "https://linux.do",
                      "template": "scripts/tasks/linuxdo_browse.py",
                      "login": {"method": "browser_state", "provider": "linuxdo", "account": "default"}}],
        "oauth_states": {"linuxdo": {"accounts": {"default": {"state": state, "updated_at": "capture"}}}},
    }
    path = tmp_path / "ACCOUNTS.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    document = schema.parse_document(raw, path=path)
    overlay = Overlay(path=tmp_path / "overlay.json", policy=policy).load()
    return document, overlay, OAuthStateReader(document.oauth_states, path)


def _current(overlay, reader, account="default"):
    return engine._shared_oauth_resolver(overlay, reader)("linuxdo", account)


@pytest.fixture
def fake_browser(monkeypatch):
    calls = SimpleNamespace(launched=0, verdict=("authenticated", None))

    async def launch(**_kwargs):
        calls.launched += 1
        context = SimpleNamespace(new_page=AsyncMock(return_value=SimpleNamespace(url="https://linux.do")),
                                  close=AsyncMock(), storage_state=AsyncMock(return_value={}))
        return object(), context

    async def session(lease, *, log, deadline):
        lease.mark_authenticated()
        return calls.verdict

    monkeypatch.setattr(bypass, "launch_camoufox", launch)
    monkeypatch.setattr(browser_state, "restore_storage_state", AsyncMock())
    monkeypatch.setattr(runtime_loop, "safe_close_browser", AsyncMock())
    monkeypatch.setattr(runtime_loop, "safe_close_page", AsyncMock())
    monkeypatch.setattr(popups, "setup_popup_guard", AsyncMock())
    module = templates.get("scripts/tasks/linuxdo_browse.py").module
    monkeypatch.setattr(module, "keepalive_session", session)
    return calls


@pytest.fixture(autouse=True)
def _lock(tmp_path, monkeypatch):
    monkeypatch.setattr(keepalive, "LOCK_PATH", tmp_path / "keepalive")


def _run(names, overlay, reader, **kwargs):
    logs: list[str] = []
    results = asyncio.run(keepalive.ensure_linuxdo_sessions(
        names, overlay=overlay, oauth_state=reader, log=logs.append, **kwargs,
    ))
    return results, logs


# ── 静态检查 ──
def test_window_is_configurable(monkeypatch):
    monkeypatch.delenv(keepalive.RENEW_HOURS_ENV, raising=False)
    assert keepalive.renew_window_seconds() == 30 * HOUR
    monkeypatch.setenv(keepalive.RENEW_HOURS_ENV, "48")
    assert keepalive.renew_window_seconds() == 48 * HOUR
    assert keepalive.renew_window_seconds(12) == 12 * HOUR
    assert keepalive.renew_window_seconds(0) == 0
    monkeypatch.setenv(keepalive.RENEW_HOURS_ENV, "garbage")
    assert keepalive.renew_window_seconds() == 30 * HOUR


def test_fresh_state_never_launches_a_browser(tmp_path, fake_browser):
    _doc, overlay, reader = _case(tmp_path, state=_state("t0", 10 * 86400))
    results, logs = _run(["default"], overlay, reader, window_seconds=30 * HOUR)
    assert [item.status for item in results] == ["fresh"] and fake_browser.launched == 0
    assert any("无需续期" in line for line in logs)


def test_unknown_expiry_is_skipped_without_browser(tmp_path, fake_browser):
    _doc, overlay, reader = _case(tmp_path, state=_state("t0", None))
    results, _ = _run(["default"], overlay, reader, window_seconds=30 * HOUR)
    assert results[0].status == "skipped" and fake_browser.launched == 0


# ── 续期 ──
def test_near_expiry_state_is_renewed_and_written_to_overlay(tmp_path, fake_browser):
    _doc, overlay, reader = _case(tmp_path, state=_state("t0", 5 * HOUR))
    renewed = decode_state(_state("t1", 60 * 86400))
    fake_browser.verdict = ("authenticated", renewed)
    results, _ = _run(["default"], overlay, reader, window_seconds=30 * HOUR)
    assert results[0].status == "renewed" and fake_browser.launched == 1
    current = _current(Overlay(path=overlay.path).load(), reader)
    assert current.from_overlay
    assert storage_scope.provider_auth_values(decode_state(current.state), "linuxdo") == {"t1"}
    raw = json.loads(overlay.path.read_text(encoding="utf-8"))["oauth_states"]["linuxdo"]["accounts"]["default"]
    assert abs(raw["ttl"] - 60 * 86400) <= 5, "缓存寿命应跟随新 _t 的到期时间"
    # 再跑一次：已续期，静态判断即可，不再开浏览器。
    again, _ = _run(["default"], Overlay(path=overlay.path).load(), reader, window_seconds=30 * HOUR)
    assert again[0].status == "fresh" and fake_browser.launched == 1


@pytest.mark.parametrize("verdict,status", [
    (("anonymous", None), "expired"),
    (("challenge", None), "challenge"),
    (("undetermined", None), "undetermined"),
])
def test_failed_renewal_never_touches_saved_state(tmp_path, fake_browser, verdict, status):
    original = _state("t0", 2 * HOUR)
    _doc, overlay, reader = _case(tmp_path, state=original)
    fake_browser.verdict = verdict
    results, _ = _run(["default"], overlay, reader, window_seconds=30 * HOUR)
    assert results[0].status == status
    assert not overlay.path.exists() or "oauth_states" not in json.loads(overlay.path.read_text(encoding="utf-8"))
    assert _current(overlay, reader).state == original


def test_readonly_overlay_skips_rotation(tmp_path, fake_browser):
    _doc, overlay, reader = _case(tmp_path, state=_state("t0", HOUR), policy=CachePolicy.READONLY)
    results, _ = _run(["default"], overlay, reader, window_seconds=30 * HOUR)
    assert results[0].status == "skipped" and fake_browser.launched == 0


def test_renewal_after_lock_rechecks_and_skips_if_already_renewed(tmp_path, fake_browser, monkeypatch):
    _doc, overlay, reader = _case(tmp_path, state=_state("t0", HOUR))
    calls = []
    original = keepalive.remaining_seconds

    def remaining(state_text, *, provider="linuxdo", now=None):
        calls.append(1)
        # 第二次（锁内）读取时，另一进程已续期。
        return original(state_text, provider=provider, now=now) if len(calls) == 1 else 50 * 86400

    monkeypatch.setattr(keepalive, "remaining_seconds", remaining)
    results, logs = _run(["default"], overlay, reader, window_seconds=30 * HOUR)
    assert results[0].status == "fresh" and fake_browser.launched == 0
    assert any("其他进程" in line for line in logs)


def test_preflight_without_browser_reports_and_continues(tmp_path, monkeypatch):
    document, overlay, reader = _case(tmp_path, state=_state("t0", HOUR))
    from runtime import capabilities

    monkeypatch.setattr(capabilities, "environment", lambda: frozenset())
    logs: list[str] = []
    results = asyncio.run(keepalive.preflight(
        ["default"], overlay=overlay, oauth_state=reader, network=document.accounts[0].network,
        window_seconds=30 * HOUR, log=logs.append,
    ))
    assert results[0].status == "skipped" and any("没有可用浏览器" in line for line in logs)


def test_account_references():
    forum = schema.parse_account({"id": "f", "base_url": "https://linux.do", "template": "x",
                                  "login": {"method": "browser_state", "account": "alt"}})
    site = schema.parse_account({"id": "s", "base_url": "https://site.invalid", "template": "x",
                                 "login": {"method": "oauth", "provider": "linuxdo"}})
    other = schema.parse_account({"id": "o", "base_url": "https://site.invalid", "template": "x",
                                  "login": {"method": "oauth", "provider": "github"}})
    assert keepalive.references_linuxdo(forum) == ("alt",)
    assert keepalive.references_linuxdo(site) == ("default",)
    assert keepalive.references_linuxdo(other) == ()


def test_batch_children_skip_after_parent_preflight(monkeypatch):
    from apps import batch

    monkeypatch.setattr(batch, "_KEEPALIVE_DONE", [False])
    assert keepalive.SKIP_ENV not in batch._child_env()
    batch._KEEPALIVE_DONE[0] = True
    assert batch._child_env()[keepalive.SKIP_ENV] == "1"


# ── 同一会话多副本同步 ──
def test_browser_close_syncs_rotation_back_to_shared_state(tmp_path, fake_browser):
    _doc, overlay, reader = _case(tmp_path, state=_state("t0", 10 * HOUR))
    writer = engine._shared_state_writer(overlay, reader, "https://linux.do")
    exported = decode_state(_state("t1", 60 * 86400))
    service = BrowserService(base_url="https://linux.do", shared_writer=writer, persist=None)

    async def scenario():
        async with service.lease(state_text=_state("t0", 10 * HOUR)) as lease:
            lease.track_shared("linuxdo", "default", {"t0"})
            service.mark_authenticated()
            service._context.storage_state = AsyncMock(return_value=exported)
        await service.aclose()

    asyncio.run(scenario())
    current = _current(Overlay(path=overlay.path).load(), reader)
    assert storage_scope.provider_auth_values(decode_state(current.state), "linuxdo") == {"t1"}


@pytest.mark.parametrize("scenario", ["foreign_lineage", "need_login", "restored_other_state"])
def test_browser_close_never_overwrites_shared_state_of_another_session(tmp_path, fake_browser, scenario):
    original = _state("t0", 10 * HOUR)
    _doc, overlay, reader = _case(tmp_path, state=original)
    writer = engine._shared_state_writer(overlay, reader, "https://linux.do")
    service = BrowserService(base_url="https://linux.do", shared_writer=writer, persist=None)

    async def run():
        async with service.lease(state_text=_state("other", 10 * HOUR)) as lease:
            lease.track_shared("linuxdo", "default", {"other" if scenario == "foreign_lineage" else "t0"})
            if scenario == "restored_other_state":
                await lease.restore_state(_state("github-relogin", 10 * HOUR))
            service.mark_authenticated()
            if scenario == "need_login":
                service.note_outcome(SimpleNamespace(reason="need_login"))
            service._context.storage_state = AsyncMock(return_value=decode_state(_state("t9", 60 * 86400)))
        await service.aclose()

    asyncio.run(run())
    assert _current(Overlay(path=overlay.path).load(), reader).state == original


def test_linuxdo_prefers_fresher_shared_state_over_stale_account_snapshot(tmp_path):
    module = templates.get("scripts/tasks/linuxdo_browse.py").module
    fresh, stale = _state("t-new", 50 * 86400), _state("t-old", 2 * HOUR)
    source = object()
    ctx = SimpleNamespace(resolve_oauth=lambda provider, account: (fresh, source))
    chosen, chosen_source, lineage = module._fresher_state(ctx, "default", stale)
    assert chosen and chosen_source is source and lineage == chosen
    assert storage_scope.provider_auth_values(decode_state(chosen), "linuxdo") == {"t-new"}
    # 账号快照更新时维持账号优先；两者是同一 _t 时沿用快照但登记谱系。
    assert module._fresher_state(SimpleNamespace(resolve_oauth=lambda *_: (stale, source)), "default", fresh)[0] == ""
    same = module._fresher_state(SimpleNamespace(resolve_oauth=lambda *_: (fresh, source)), "default", fresh)
    assert same == ("", None, fresh)


def test_oauth_cached_site_snapshot_gets_fresher_provider_cookies(tmp_path):
    from login import oauth

    restored = []
    tracked = []
    lease = SimpleNamespace(
        restore_state=AsyncMock(side_effect=lambda text: restored.append(text)),
        track_shared=lambda *args: tracked.append(args),
    )
    source = object()
    ctx = SimpleNamespace(base_url="https://site.invalid", log=lambda _m: None,
                          resolve_oauth=lambda *_: (_state("t-new", 50 * 86400), source))
    got = asyncio.run(oauth._refresh_provider_cookies(ctx, lease, "linuxdo", "default", _state("t-old", HOUR)))
    assert got is source and len(restored) == 1 and tracked[0][2] == {"t-new"}
    restored.clear()
    stale_shared = SimpleNamespace(base_url="https://site.invalid", log=lambda _m: None,
                                   resolve_oauth=lambda *_: (_state("t-old", HOUR), source))
    assert asyncio.run(oauth._refresh_provider_cookies(
        stale_shared, lease, "linuxdo", "default", _state("t-new", 50 * 86400))) is None
    assert restored == []


@pytest.mark.parametrize("verify,probe,expected", [
    ((True, True, False), {"reason": "authenticated"}, "authenticated"),
    ((True, True, False), {"reason": "authenticated", "source": "dom"}, "undetermined"),
    ((False, True, False), {"reason": "anonymous"}, "anonymous"),
    ((False, False, False), {}, "challenge"),
    ((False, True, True), {"reason": "rate_limited"}, "undetermined"),
])
def test_keepalive_session_requires_server_confirmation(monkeypatch, verify, probe, expected):
    module = templates.get("scripts/tasks/linuxdo_browse.py").module

    async def fake_verify(ctx, lease, page, observed):
        observed["session_probe"] = probe
        return verify

    monkeypatch.setattr(module, "_verify_session", fake_verify)
    marked = []
    lease = SimpleNamespace(
        new_page=AsyncMock(return_value=object()),
        mark_authenticated=lambda: marked.append(1),
        context=SimpleNamespace(storage_state=AsyncMock(return_value={"cookies": []})),
    )
    status, storage = asyncio.run(module.keepalive_session(lease, log=lambda _m: None, deadline=time.monotonic() + 30))
    assert status == expected
    assert (storage is not None) == (expected == "authenticated") == bool(marked)


def test_keepalive_does_not_declare_expiry_while_page_still_looks_logged_in(monkeypatch):
    """接口 404 空正文 + 页面显示已登录 → 无法判定，而不是判失效。

    保活恢复的是 provider 范围的态，缺少 cf_clearance 时 CF 边缘会对 XHR 直接回
    404 空正文，与 Discourse 的匿名答复同形。只看接口就断言失效，会让用户去重捕
    一份本来有效的登录态。
    """
    module = templates.get("scripts/tasks/linuxdo_browse.py").module

    async def fake_verify(ctx, lease, page, observed):
        observed["session_probe"] = {"reason": "anonymous", "status": 404, "format": "empty"}
        return False, True, False

    async def still_logged_in(page):
        return True

    monkeypatch.setattr(module, "_verify_session", fake_verify)
    monkeypatch.setattr(module, "_dom_logged_in", still_logged_in)
    lease = SimpleNamespace(
        new_page=AsyncMock(return_value=object()),
        mark_authenticated=lambda: None,
        context=SimpleNamespace(storage_state=AsyncMock(return_value={"cookies": []})),
    )
    logs = []

    status, storage = asyncio.run(module.keepalive_session(
        lease, log=logs.append, deadline=time.monotonic() + 30,
    ))

    assert status == "undetermined", "不能凭一次匿名探测就判定登录态失效"
    assert storage is None
    assert any("保留现有登录态" in message for message in logs)


GITHUB_AUTH_HTML = ('<html><head><meta name="user-login" content="fixture-user"></head>'
                    '<body class="logged-in"><form action="/logout" method="post"></form></body></html>')
GITHUB_LOGIN_HTML = ('<html><body class="logged-out"><form action="/session" method="post">'
                     '<input name="login"><input name="password" type="password"></form></body></html>')


def _github_state(value, expires_in, *, same_site=""):
    expiry = -1 if expires_in is None else time.time() + expires_in
    cookies = [{"name": "user_session", "value": value, "domain": ".github.com", "path": "/",
                "expires": expiry, "secure": True, "httpOnly": True}]
    if same_site:
        cookies.append({"name": "__Host-user_session_same_site", "value": same_site, "domain": "github.com",
                        "path": "/", "expires": expiry, "secure": True, "httpOnly": True})
    return encode_state({"cookies": cookies, "origins": []})


def _github_case(tmp_path, state, *, policy=CachePolicy.COMPATIBLE):
    raw = {"version": 3, "accounts": [{"id": "site", "base_url": "https://site.invalid", "template": "newapi",
            "login": {"method": "oauth", "provider": "github"}}],
           "oauth_states": {"github": {"accounts": {"default": {"state": state, "updated_at": "capture"}}}}}
    path = tmp_path / "github-fixture.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    document = schema.parse_document(raw, path=path)
    return document, Overlay(tmp_path / "shared-fixture.json", policy=policy).load(), OAuthStateReader(document.oauth_states, path)


@pytest.fixture
def fake_github(monkeypatch, fake_browser):
    from runtime import capabilities

    calls = SimpleNamespace(launched=0, restored=[], visits=[], status=200, html=GITHUB_AUTH_HTML,
                            url="https://github.com/settings/profile", response_url=None,
                            content_type="text/html; charset=utf-8", snapshot=None, error=None, on_navigation=None)
    page = SimpleNamespace(url="about:blank", click=AsyncMock(), fill=AsyncMock())

    async def navigate(url, **kwargs):
        calls.visits.append((url, kwargs))
        if calls.error:
            raise calls.error
        if calls.on_navigation:
            calls.on_navigation()
        page.url = calls.url
        return SimpleNamespace(url=calls.response_url or calls.url, status=calls.status,
                               headers={"content-type": calls.content_type}, text=AsyncMock(return_value=calls.html))

    page.goto = AsyncMock(side_effect=navigate)
    context = SimpleNamespace(new_page=AsyncMock(return_value=page), close=AsyncMock(),
                              storage_state=AsyncMock(side_effect=lambda: deepcopy(calls.snapshot or calls.restored[-1])))

    async def launch(**_kwargs):
        calls.launched += 1
        return object(), context

    async def restore(_context, state, **_kwargs):
        calls.restored.append(deepcopy(state))

    monkeypatch.setattr(bypass, "launch_camoufox", launch)
    monkeypatch.setattr(browser_state, "restore_storage_state", restore)
    monkeypatch.setattr(capabilities, "environment", lambda: frozenset({"browser"}))
    calls.page, calls.context = page, context
    return calls


def _run_github(overlay, reader, **kwargs):
    logs = []
    result = asyncio.run(keepalive.ensure_oauth_sessions(
        [("github", "default")], overlay=overlay, oauth_state=reader, log=logs.append, **kwargs,
    ))
    return result[0], logs


def test_github_reference_aliases_dedupe_per_provider_and_task_overrides():
    spec = schema.parse_account({
        "id": "forum", "base_url": "https://linux.do", "template": "linuxdo_browse",
        "login": {"method": "browser_state", "provider": "linuxdo", "account": "same",
                  "args": {"github_fallback": "true", "github_account": " same "},
                  "fallback": [{"method": "oauth", "provider": "github", "account": "same"}]},
        "tasks": [{"id": "refresh", "method": "relogin", "args": {"provider": "github", "account": "task-owner"}},
                  {"id": "disabled", "method": "relogin", "enabled": False,
                   "args": {"provider": "github", "account": "unused"}}],
    })
    assert keepalive.references_oauth(spec) == (("linuxdo", "same"), ("github", "same"), ("github", "task-owner"))
    assert keepalive.references_linuxdo(spec) == ("same",)
    captured = {provider: {"accounts": {"same": {"state": "fixture"}, "empty": {"state": ""}}}
                for provider in ("linuxdo", "github")}
    assert keepalive.oauth_accounts(captured) == (("linuxdo", "same"), ("github", "same"))


@pytest.mark.parametrize("value,enabled", [(False, False), ("false", False), ("0", False), (None, False),
                                            ("", False), (True, True), (" ON ", True)])
def test_github_fallback_reference_boolean_inheritance_and_override(value, enabled):
    base = {"id": "f", "base_url": "https://linux.do", "template": "linuxdo_browse",
            "login": {"method": "refresh_token", "args": {"github_fallback": True, "github_account": " named "},
                      "fallback": [{"method": "browser_state", "args": {"github_fallback": value}}]}}
    references = keepalive.references_oauth(schema.parse_account(base))
    assert (("github", "named") in references) is enabled
    base["login"]["fallback"][0]["args"] = {}
    assert ("github", "named") in keepalive.references_oauth(schema.parse_account(base))


@pytest.mark.parametrize("alias,expected", [(None, "default"), ("", "default"), (" ", "default"), (" work ", "work")])
def test_github_fallback_account_aliases(alias, expected):
    spec = schema.parse_account({"id": "f", "base_url": "https://linux.do", "template": "linuxdo_browse",
                                 "login": {"method": "browser_state", "args": {
                                     "github_fallback": True, "github_account": alias}}})
    assert ("github", expected) in keepalive.references_oauth(spec)


def test_explicit_relogin_task_reference_overrides_main_provider():
    spec = schema.parse_account({"id": "site", "base_url": "https://site.invalid", "template": "newapi",
        "login": {"method": "oauth", "provider": "github", "account": "configured"},
        "tasks": [{"id": "daily", "method": "relogin", "args": {"provider": "linuxdo", "account": "task-owner"}}]})
    assert keepalive.references_oauth(spec) == (("github", "configured"), ("linuxdo", "task-owner"))


def test_github_expiry_uses_earliest_auth_cookie_and_unknown_is_not_fresh():
    state = decode_state(_github_state("left", 100 * HOUR, same_site="right"))
    state["cookies"][1]["expires"] = time.time() + HOUR
    assert 0 < keepalive.remaining_seconds(encode_state(state), provider="github") <= HOUR
    state["cookies"][1]["expires"] = -1
    assert keepalive.remaining_seconds(encode_state(state), provider="github") is None
    assert keepalive.remaining_seconds(_github_state("left", HOUR), provider="not-a-provider") is None


def test_github_near_expiry_refresh_uses_isolated_state_and_real_server_ttl(tmp_path, fake_github):
    initial = decode_state(_github_state("before", HOUR, same_site="before-same-site"))
    initial["cookies"].extend(decode_state(_state("forum-secret", HOUR))["cookies"])
    initial["cookies"].extend([
        {"name": "cf_clearance", "value": "old-cf", "domain": ".github.com", "path": "/"},
        {"name": "user_session", "value": "other-host", "domain": "evil.github.com", "path": "/"},
    ])
    initial["origins"] = [{"origin": "https://github.com", "localStorage": [{"name": "auth", "value": "private"}]}]
    _doc, overlay, reader = _github_case(tmp_path, encode_state(initial))
    fake_github.snapshot = decode_state(_github_state("after", 60 * 86400, same_site="after-same-site"))
    fake_github.snapshot["cookies"].extend(decode_state(_state("other-provider", HOUR))["cookies"])
    fake_github.snapshot["origins"] = initial["origins"]
    result, logs = _run_github(overlay, reader)
    assert (result.provider, result.status) == ("github", "renewed")
    assert fake_github.visits[0][0] == "https://github.com/settings/profile"
    restored = fake_github.restored[0]
    assert restored["origins"] == []
    assert {cookie["value"] for cookie in restored["cookies"]} == {"before", "before-same-site"}
    current = engine._shared_oauth_resolver(Overlay(overlay.path).load(), reader)("github", "default")
    refreshed = decode_state(current.state)
    assert current.from_overlay and refreshed["origins"] == []
    assert storage_scope.provider_auth_values(refreshed, "github") == {"after", "after-same-site"}
    assert all(cookie["domain"].lstrip(".") == "github.com" for cookie in refreshed["cookies"])
    raw = json.loads(overlay.path.read_text(encoding="utf-8"))["oauth_states"]["github"]["accounts"]["default"]
    assert abs(raw["ttl"] - 60 * 86400) <= 5
    assert all(secret not in " ".join(logs) for secret in ("before-same-site", "after-same-site", "private"))
    fake_github.page.click.assert_not_awaited()
    fake_github.page.fill.assert_not_awaited()


@pytest.mark.parametrize("expiry", [None, 100 * HOUR])
def test_github_force_verifies_unknown_or_fresh_state_without_fabricating_rotation(tmp_path, fake_github, expiry):
    original = _github_state("same", expiry)
    document, overlay, reader = _github_case(tmp_path, original)
    static = asyncio.run(keepalive.preflight([("github", "default")], overlay=overlay, oauth_state=reader,
                                          network=document.accounts[0].network))
    assert static[0].status == ("skipped" if expiry is None else "fresh")
    assert fake_github.launched == 0
    forced = asyncio.run(keepalive.preflight([("github", "default")], overlay=overlay, oauth_state=reader,
                                           network=document.accounts[0].network, window_seconds=0, force_verify=True))
    assert forced[0].status == "unchanged" and fake_github.launched == 1
    assert not overlay.path.exists()
    assert engine._shared_oauth_resolver(overlay, reader)("github", "default").state == original


@pytest.mark.parametrize("policy", [CachePolicy.READONLY, CachePolicy.IGNORE])
def test_github_readonly_force_never_launches_or_writes(tmp_path, fake_github, policy):
    document, overlay, reader = _github_case(tmp_path, _github_state("same", HOUR), policy=policy)
    result = asyncio.run(keepalive.preflight([("github", "default")], overlay=overlay, oauth_state=reader,
                                           network=document.accounts[0].network, force_verify=True))
    assert result[0].status == "skipped" and fake_github.launched == 0 and not overlay.path.exists()


def test_expired_cookie_revived_only_in_memory_cannot_fake_github_renewal(tmp_path, fake_github):
    original = _github_state("expired-local", -HOUR)
    _doc, overlay, reader = _github_case(tmp_path, original)
    fake_github.snapshot = decode_state(original)
    fake_github.snapshot["cookies"][0]["expires"] = -1  # 恢复器的临时会话表示，不是服务端延寿。
    result, _ = _run_github(overlay, reader)
    assert result.status == "unchanged" and not overlay.path.exists()
    assert fake_github.restored[0]["cookies"][0]["expires"] < time.time()


def test_github_same_value_with_real_expiry_extension_is_renewed(tmp_path, fake_github):
    _doc, overlay, reader = _github_case(tmp_path, _github_state("same-value", HOUR))
    fake_github.snapshot = decode_state(_github_state("same-value", 40 * 86400))
    result, _ = _run_github(overlay, reader)
    assert result.status == "renewed" and result.remaining_hours > 900


@pytest.mark.parametrize("url,status,html,expected", [
    ("https://github.com/login", 200, GITHUB_LOGIN_HTML, "expired"),
    ("https://github.com/login", 200, '<input type="password">', "undetermined"),
    ("https://github.com/login", 429, GITHUB_LOGIN_HTML, "undetermined"),
    ("https://github.com/settings/profile", 503, GITHUB_AUTH_HTML, "undetermined"),
    ("https://github.com/settings/profile", 200, '<body class="logged-in">cached avatar</body>', "undetermined"),
    ("https://github.com/settings/profile", 200, '<script>localStorage.setItem("logged-in","yes")</script>', "undetermined"),
    ("https://github.com/settings/profile", 200, '<input autocomplete="one-time-code">', "challenge"),
    ("https://github.com/settings/profile", 403, '<div id="cf-chl-widget">', "challenge"),
    ("https://github.com/sessions/sudo", 200, GITHUB_LOGIN_HTML, "challenge"),
    ("https://github.com/sessions/two-factor/app", 200, GITHUB_LOGIN_HTML, "challenge"),
    ("https://github.com/settings/profile", 200, '<form action="/sessions/sudo" method="post">', "challenge"),
    ("https://github.com/login/oauth/authorize", 200, GITHUB_AUTH_HTML, "undetermined"),
    ("https://github.com.evil.invalid/settings/profile", 200, GITHUB_AUTH_HTML, "undetermined"),
    ("https://evil.github.com/settings/profile", 200, GITHUB_AUTH_HTML, "undetermined"),
    ("http://github.com/settings/profile", 200, GITHUB_AUTH_HTML, "undetermined"),
    ("https://github.com:8443/settings/profile", 200, GITHUB_AUTH_HTML, "undetermined"),
    ("https://user@github.com/settings/profile", 200, GITHUB_AUTH_HTML, "undetermined"),
])
def test_github_unconfirmed_response_keeps_original_bytes(tmp_path, fake_github, url, status, html, expected):
    original = _github_state("before", HOUR)
    _doc, overlay, reader = _github_case(tmp_path, original)
    source = engine._shared_oauth_resolver(overlay, reader)("github", "default")
    assert overlay.record_oauth_state(source, original)
    before = overlay.path.read_bytes()
    fake_github.url, fake_github.status, fake_github.html = url, status, html
    fake_github.snapshot = decode_state(_github_state("unconfirmed", 60 * 86400))
    result, _ = _run_github(overlay, reader)
    assert result.status == expected
    assert overlay.path.read_bytes() == before
    fake_github.context.storage_state.assert_not_awaited()
    fake_github.page.click.assert_not_awaited()
    fake_github.page.fill.assert_not_awaited()


@pytest.mark.parametrize("failure", ["navigation", "response_url", "content_type", "export"])
def test_github_navigation_response_or_export_errors_are_not_expiry(tmp_path, fake_github, failure):
    _doc, overlay, reader = _github_case(tmp_path, _github_state("before", HOUR))
    if failure == "navigation":
        fake_github.error = RuntimeError("fixture transport failure")
    elif failure == "response_url":
        fake_github.response_url = "https://github.com/login"
    elif failure == "content_type":
        fake_github.content_type = "application/json"
    else:
        fake_github.context.storage_state.side_effect = RuntimeError("fixture export failure")
    result, _ = _run_github(overlay, reader)
    assert result.status == "undetermined" and not overlay.path.exists()


@pytest.mark.parametrize("force_verify", [False, True])
def test_github_lock_reloads_latest_shared_revision(tmp_path, fake_github, monkeypatch, force_verify):
    _doc, overlay, reader = _github_case(tmp_path, _github_state("before", HOUR))
    source = engine._shared_oauth_resolver(overlay, reader)("github", "default")
    other = Overlay(overlay.path).load()
    actual_lock = keepalive.paths.file_lock

    @contextmanager
    def lock(path, **kwargs):
        with actual_lock(path, **kwargs):
            if path == keepalive.LOCK_PATH:
                assert other.record_oauth_state(source, _github_state("concurrent", 60 * 86400))
            yield

    monkeypatch.setattr(keepalive.paths, "file_lock", lock)
    result, logs = _run_github(overlay, reader, force_verify=force_verify)
    if force_verify:
        assert result.status == "unchanged" and fake_github.launched == 1
        assert storage_scope.provider_auth_values(fake_github.restored[0], "github") == {"concurrent"}
    else:
        assert result.status == "fresh" and fake_github.launched == 0
        assert any("其他进程" in line for line in logs)


def test_github_cas_conflict_does_not_rebase_and_replay_old_browser_result(tmp_path, fake_github):
    _doc, overlay, reader = _github_case(tmp_path, _github_state("before", HOUR))
    source = engine._shared_oauth_resolver(overlay, reader)("github", "default")
    concurrent = _github_state("concurrent", 60 * 86400)
    fake_github.on_navigation = lambda: Overlay(overlay.path).load().record_oauth_state(source, concurrent)
    fake_github.snapshot = decode_state(_github_state("obsolete-browser", 70 * 86400))
    result, _ = _run_github(overlay, reader)
    assert result.status == "error" and result.message == "写回失败"
    assert engine._shared_oauth_resolver(Overlay(overlay.path).load(), reader)("github", "default").state == concurrent


def test_preflight_missing_github_snapshot_is_skipped_not_fresh(tmp_path, fake_github):
    document, overlay, reader = _github_case(tmp_path, "")
    results = asyncio.run(keepalive.preflight([("github", "default")], overlay=overlay, oauth_state=reader,
                                            network=document.accounts[0].network, force_verify=True))
    assert results[0].status == "skipped" and results[0].message == "未捕获共享态"
    assert fake_github.launched == 0 and not overlay.path.exists()


def test_github_changed_config_rejects_browser_writeback(tmp_path, fake_github):
    document, overlay, reader = _github_case(tmp_path, _github_state("before", HOUR))

    def recapture():
        payload = document.to_payload()
        payload["oauth_states"]["github"]["accounts"]["default"]["state"] = _github_state("recaptured", 60 * 86400)
        document.path.write_text(json.dumps(payload), encoding="utf-8")

    fake_github.on_navigation = recapture
    fake_github.snapshot = decode_state(_github_state("obsolete-browser", 70 * 86400))
    result, _ = _run_github(overlay, reader)
    assert result.status == "error" and not overlay.path.exists()


def test_github_partial_two_cookie_lineage_cannot_rollback_concurrent_rotation(tmp_path):
    original = _github_state("old-left", HOUR, same_site="unchanged-right")
    _doc, overlay, reader = _github_case(tmp_path, original)
    writer = engine._shared_state_writer(overlay, reader, "https://site.invalid")
    source = engine._shared_oauth_resolver(overlay, reader)("github", "default")
    current = _github_state("new-left", 60 * 86400, same_site="unchanged-right")
    assert overlay.record_oauth_state(source, current)
    before = overlay.path.read_bytes()
    stale_export = decode_state(_github_state("old-left", 70 * 86400, same_site="browser-right"))
    assert not writer("github", "default", stale_export, frozenset({"old-left", "unchanged-right"}))
    assert overlay.path.read_bytes() == before


def test_provider_scoped_ensure_deduplicates_without_merging_same_account_name(tmp_path, monkeypatch):
    overlay = Overlay(tmp_path / "dedupe.json").load()
    ensure = AsyncMock(side_effect=lambda name, **kwargs: keepalive.KeepaliveResult(name, "unchanged", provider=kwargs["provider"]))
    monkeypatch.setattr(keepalive, "_ensure_one", ensure)
    results = asyncio.run(keepalive.ensure_oauth_sessions(
        [("github", "same"), ("linuxdo", "same"), ("github", "same"), ("untrusted", "same")],
        overlay=overlay, oauth_state=lambda *_: "fixture", force_verify=True,
    ))
    assert [(item.provider, item.account) for item in results] == [("github", "same"), ("linuxdo", "same")]
    assert ensure.await_count == 2


def test_engine_entry_uses_unified_preflight_and_skips_after_parent(tmp_path, monkeypatch):
    document, overlay, reader = _github_case(tmp_path, _github_state("before", HOUR))
    preflight = AsyncMock(return_value=[])
    monkeypatch.setattr(keepalive, "preflight", preflight)
    monkeypatch.delenv(keepalive.SKIP_ENV, raising=False)
    asyncio.run(engine._keepalive_shared(document.accounts[0], overlay, reader, "http://127.0.0.1:7890", Mock(),
                                        renew_hours=0, force_verify=True))
    assert preflight.await_args.args[0] == (("github", "default"),)
    assert preflight.await_args.kwargs["window_seconds"] == 0
    assert preflight.await_args.kwargs["force_verify"] is True
    assert preflight.await_args.kwargs["network"].proxy == "http://127.0.0.1:7890"
    monkeypatch.setenv(keepalive.SKIP_ENV, "1")
    asyncio.run(engine._keepalive_shared(document.accounts[0], overlay, reader, "", Mock(), force_verify=True))
    assert preflight.await_count == 1
