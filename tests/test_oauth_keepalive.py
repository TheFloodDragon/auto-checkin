"""linux.do 共享登录态保活：任务前静态检查、到期前续期、多副本同步。离线，不开真实浏览器。"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

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

    def remaining(state_text, *, now=None):
        calls.append(1)
        # 第二次（锁内）读取时，另一进程已续期。
        return original(state_text, now=now) if len(calls) == 1 else 50 * 86400

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
