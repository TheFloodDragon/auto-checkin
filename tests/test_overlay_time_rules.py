"""运行期覆盖层的时间规则真值表。

这是重构诉求 4 的核心验收：缓存与配置谁说了算，必须由**时间**而不是只由摘要决定，
且任何判定都不会删除缓存值。
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from config.overlay import TTL_DEFAULTS, CachePolicy, FieldEntry, Overlay
from core.account import CREDENTIAL_FIELDS, AccountSpec, CredentialSet
from core.flow import Discovery
from core.timebase import utc_iso, utc_now


_BROWSER_FIELDS = ("browser_state", "access_token", "refresh_token")


def _iso(**delta):
    return (
        (utc_now() + timedelta(**delta))
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _spec(**creds) -> AccountSpec:
    return AccountSpec(
        id="acct",
        name="测试站",
        base_url="https://example.com",
        credentials=CredentialSet(**creds),
    )


def _overlay(tmp_path, entries, *, accounts_mtime="", policy=CachePolicy.COMPATIBLE):
    path = tmp_path / "overlay.json"
    path.write_text(
        json.dumps({"version": 3, "entries": entries}, ensure_ascii=False), encoding="utf-8"
    )
    overlay = Overlay(path, policy=policy)
    # 直接注入 ACCOUNTS.json 的 mtime，避免测试依赖真实文件时间。
    overlay._accounts_mtime = accounts_mtime  # noqa: SLF001 - 测试专用注入点
    return overlay.load()


def _entry(field="access_token", *, value="CACHED", updated_at=None, ttl=None, config_hash="", **rest):
    return {
        "fields": {
            field: {
                "value": value,
                "updated_at": updated_at if updated_at is not None else utc_iso(),
                "ttl": TTL_DEFAULTS[field] if ttl is None else ttl,
                "origin": "refresh",
                "config_hash": config_hash,
            }
        },
        **rest,
    }


# ── 规则 1：ignore ──────────────────────────────────────────────────────────
def test_rule1_ignore_policy_never_applies_overlay(tmp_path):
    overlay = _overlay(tmp_path, {"acct": _entry()}, policy=CachePolicy.IGNORE)
    resolved = overlay.apply(_spec(access_token="FROM_CONFIG"))
    assert resolved.credentials.access_token == "FROM_CONFIG"
    assert resolved.origins["access_token"] == "config"


def test_rule1_ignore_also_hides_learned_flow(tmp_path):
    entry = _entry()
    entry["flow"] = {"login": {"value": "refresh", "probed_at": utc_iso()}}
    overlay = _overlay(tmp_path, {"acct": entry}, policy=CachePolicy.IGNORE)
    assert dict(overlay.apply(_spec()).learned_flow) == {}


# ── 规则 2：显式提供 ────────────────────────────────────────────────────────
def test_rule2_explicit_field_beats_overlay(tmp_path):
    overlay = _overlay(tmp_path, {"acct": _entry()})
    resolved = overlay.apply(_spec(access_token="EXPLICIT"), explicit=["access_token"])
    assert resolved.credentials.access_token == "EXPLICIT"


def test_rule2_explicit_empty_also_beats_overlay(tmp_path):
    """显式清空必须能生效，否则用户永远无法强制重新登录。"""
    overlay = _overlay(tmp_path, {"acct": _entry()})
    resolved = overlay.apply(_spec(access_token=""), explicit=["access_token"])
    assert resolved.credentials.access_token == ""


# ── 规则 3：TTL 过期 ────────────────────────────────────────────────────────
def test_rule3_expired_overlay_value_is_ignored(tmp_path):
    overlay = _overlay(
        tmp_path, {"acct": _entry(updated_at=_iso(days=-30), ttl=3600)}
    )
    resolved = overlay.apply(_spec(access_token="CONFIG"))
    assert resolved.credentials.access_token == "CONFIG"


def test_rule3_future_timestamp_is_distrusted(tmp_path):
    """时钟回拨或手工改缓存造成的未来时间戳不可信，按过期处理。"""
    overlay = _overlay(tmp_path, {"acct": _entry(updated_at=_iso(days=+2), ttl=3600)})
    assert overlay.apply(_spec(access_token="CONFIG")).credentials.access_token == "CONFIG"


def test_rule3_zero_ttl_never_expires(tmp_path):
    overlay = _overlay(tmp_path, {"acct": _entry(updated_at=_iso(days=-900), ttl=0)})
    assert overlay.apply(_spec()).credentials.access_token == "CACHED"


# ── 规则 4a：配置摘要变化 ───────────────────────────────────────────────────
def test_rule4a_config_changed_since_cache_write(tmp_path):
    from config.overlay import _hash

    overlay = _overlay(tmp_path, {"acct": _entry(config_hash=_hash("OLD_CONFIG"))})
    resolved = overlay.apply(_spec(access_token="NEW_CONFIG"))
    assert resolved.credentials.access_token == "NEW_CONFIG"
    assert "规则4a" in _rule(overlay, _spec(access_token="NEW_CONFIG"))


def test_rule4a_config_unchanged_keeps_overlay(tmp_path):
    from config.overlay import _hash

    overlay = _overlay(tmp_path, {"acct": _entry(config_hash=_hash("SAME"))})
    resolved = overlay.apply(_spec(access_token="SAME"))
    assert resolved.credentials.access_token == "CACHED"
    assert resolved.origins["access_token"] == "overlay:refresh"


def test_rule4a_config_cleared_by_user_wins(tmp_path):
    """用户把配置里的 token 删空，等于要求重新获取，缓存不该顶上来。"""
    from config.overlay import _hash

    overlay = _overlay(tmp_path, {"acct": _entry(config_hash=_hash("HAD_VALUE"))})
    assert overlay.apply(_spec(access_token="")).credentials.access_token == ""


# ── 规则 4b：无摘要的旧条目走时间比较 ───────────────────────────────────────
def test_rule4b_accounts_file_newer_than_cache_wins(tmp_path):
    overlay = _overlay(
        tmp_path,
        {"acct": _entry(updated_at=_iso(hours=-2), config_hash="")},
        accounts_mtime=_iso(hours=-1),
    )
    assert overlay.apply(_spec(access_token="CONFIG")).credentials.access_token == "CONFIG"


def test_rule4b_cache_newer_than_accounts_file_keeps_overlay(tmp_path):
    overlay = _overlay(
        tmp_path,
        {"acct": _entry(updated_at=_iso(hours=-1), config_hash="")},
        accounts_mtime=_iso(hours=-2),
    )
    assert overlay.apply(_spec(access_token="CONFIG")).credentials.access_token == "CACHED"


def test_rule4b_empty_config_always_yields_to_overlay(tmp_path):
    """配置本来就没填，就算文件刚被动过也该用缓存——否则等于没有缓存。"""
    overlay = _overlay(
        tmp_path,
        {"acct": _entry(updated_at=_iso(hours=-5), config_hash="")},
        accounts_mtime=_iso(minutes=-1),
    )
    assert overlay.apply(_spec()).credentials.access_token == "CACHED"


# ── 分组隔离 ────────────────────────────────────────────────────────────────
def test_credential_groups_are_independent(tmp_path):
    from config.overlay import _hash

    entry = {
        "fields": {
            "access_token": {
                "value": "T", "updated_at": utc_iso(), "ttl": 3600,
                "origin": "refresh", "config_hash": _hash("OLD_TOKEN"),
            },
            "browser_state": {
                "value": "S", "updated_at": utc_iso(), "ttl": 0,
                "origin": "browser", "config_hash": _hash(""),
            },
        }
    }
    overlay = _overlay(tmp_path, {"acct": entry})
    resolved = overlay.apply(_spec(access_token="NEW_TOKEN"))
    # token 组配置变了 → 用配置；state 组没变 → 继续用缓存。
    assert resolved.credentials.access_token == "NEW_TOKEN"
    assert resolved.credentials.browser_state == "S"


# ── 永不删除 ────────────────────────────────────────────────────────────────
def test_unusable_entry_is_never_deleted(tmp_path):
    """判定为不可用只是不采用；改回原凭据必须能重新命中。"""
    from config.overlay import _hash

    path = tmp_path / "overlay.json"
    path.write_text(
        json.dumps({"version": 3, "entries": {"acct": _entry(config_hash=_hash("A"))}}),
        encoding="utf-8",
    )
    overlay = Overlay(path)
    overlay._accounts_mtime = ""  # noqa: SLF001
    overlay.load()

    assert overlay.apply(_spec(access_token="B")).credentials.access_token == "B"
    # 文件未被改写，值仍在
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["entries"]["acct"]["fields"]["access_token"]["value"] == "CACHED"
    # 改回原值即重新命中
    assert overlay.apply(_spec(access_token="A")).credentials.access_token == "CACHED"


# ── 写入 ────────────────────────────────────────────────────────────────────
def test_record_credentials_roundtrip(tmp_path):
    overlay = Overlay(tmp_path / "overlay.json")
    spec = _spec(access_token="CONFIGURED")
    assert overlay.record_credentials(spec, origin="refresh", access_token="FRESH")

    reopened = Overlay(tmp_path / "overlay.json").load()
    reopened._accounts_mtime = ""  # noqa: SLF001
    entry = reopened.entry("acct").fields["access_token"]
    assert entry.value == "FRESH"
    assert entry.origin == "refresh"
    # 记录的是写入时的**配置值**摘要，用于下次判断配置有没有变。
    from config.overlay import _hash

    assert entry.config_hash == _hash("CONFIGURED")
    assert reopened.apply(spec).credentials.access_token == "FRESH"


@pytest.mark.parametrize("blank", ["", "  ", None])
def test_record_credentials_ignores_blank_fields(tmp_path, blank):
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    assert not overlay.record_credentials(_spec(), access_token=blank)
    assert not path.exists()
    assert overlay.record_credentials(_spec(), access_token="CACHED-AT", refresh_token="CACHED-RT")
    before = path.read_bytes()
    revisions = overlay.credential_revisions("acct")
    receipt = {"keep": "unchanged"}
    assert not overlay.record_credentials(
        _spec(), access_token=blank, refresh_token=blank, written_revisions=receipt,
    )
    assert path.read_bytes() == before
    assert overlay.credential_revisions("acct") == revisions
    assert receipt == {"keep": "unchanged"}


def test_concurrent_writers_do_not_clobber(tmp_path):
    """两个持有各自内存快照的写入者必须都保留下来（锁内重读）。"""
    path = tmp_path / "overlay.json"
    a = Overlay(path).load()
    b = Overlay(path).load()
    a.record_credentials(_spec(), access_token="A")
    b.record_credentials(
        AccountSpec(id="other", name="o", base_url="https://o.com"), access_token="B"
    )
    stored = json.loads(path.read_text(encoding="utf-8"))["entries"]
    assert stored["acct"]["fields"]["access_token"]["value"] == "A"
    assert stored["other"]["fields"]["access_token"]["value"] == "B"


def test_clear_refresh_token_survives_reload_and_never_expires(tmp_path):
    from config.overlay import _hash

    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    spec = _spec(access_token="CONFIG-AT", refresh_token="CONFIG-RT")
    assert overlay.record_credentials(spec, refresh_token="CACHED-RT")
    assert overlay.record_credentials(
        spec, origin="refresh", clear=("refresh_token",), ttl={"refresh_token": 1},
    )
    raw = json.loads(path.read_text(encoding="utf-8"))["entries"]["acct"]["fields"]["refresh_token"]
    assert raw["value"] == ""
    assert raw["tombstone"] is True
    assert raw["ttl"] == 0
    assert raw["config_hash"] == _hash("CONFIG-RT")
    assert raw["revision_nonce"]

    reopened = Overlay(path).load()
    entry = reopened.entry("acct").fields["refresh_token"]
    assert entry.tombstone
    assert FieldEntry.from_payload(entry.to_payload()) == entry
    for now in (utc_iso(), _iso(days=36600)):
        resolved = reopened.apply(spec, now_iso=now)
        assert resolved.credentials.refresh_token == ""
        assert resolved.credentials.access_token == "CONFIG-AT"
        assert resolved.origins["refresh_token"] == "overlay:refresh"


def test_tombstone_preserves_manual_config_and_explicit_priority(tmp_path):
    path = tmp_path / "overlay.json"
    original = _spec(refresh_token="CONFIG-RT")
    assert Overlay(path).record_credentials(original, clear=("refresh_token",))
    overlay = Overlay(path).load()
    for configured in ("MANUALLY-CHANGED-RT", ""):
        resolved = overlay.apply(_spec(refresh_token=configured))
        assert resolved.credentials.refresh_token == configured
        assert resolved.origins["refresh_token"] == "config"
    resolved = overlay.apply(original, explicit=("refresh_token",))
    assert resolved.credentials.refresh_token == "CONFIG-RT"
    assert resolved.origins["refresh_token"] == "explicit"
    assert overlay.apply(_spec(), explicit=("refresh_token",)).credentials.refresh_token == ""
    assert overlay.entry("acct").fields["refresh_token"].tombstone


def test_raw_blank_without_explicit_tombstone_does_not_clear_config(tmp_path):
    from config.overlay import _hash

    overlay = _overlay(tmp_path, {"acct": _entry(
        "refresh_token", value="", ttl=0, config_hash=_hash("CONFIG-RT"),
    )})
    assert overlay.apply(_spec(refresh_token="CONFIG-RT")).credentials.refresh_token == "CONFIG-RT"
    assert "refresh_token" not in overlay.entry("acct").fields


def test_tombstone_readonly_and_ignore_keep_existing_policy_semantics(tmp_path):
    path = tmp_path / "overlay.json"
    spec = _spec(access_token="CONFIG-AT", refresh_token="CONFIG-RT")
    compatible = Overlay(path)
    assert compatible.record_credentials(spec, clear=("refresh_token",))
    readonly = Overlay(path, policy=CachePolicy.READONLY).load()
    before = path.read_bytes()
    receipt = {"keep": "unchanged"}
    assert not readonly.record_credentials(spec, clear=("access_token",), written_revisions=receipt)
    assert not readonly.record_credentials(spec, refresh_token="REJECTED", written_revisions=receipt)
    assert path.read_bytes() == before
    assert receipt == {"keep": "unchanged"}
    assert readonly.apply(spec).credentials.refresh_token == ""

    ignored = Overlay(path, policy=CachePolicy.IGNORE).load()
    assert ignored.apply(spec).credentials.refresh_token == "CONFIG-RT"
    expected = ignored.credential_revisions("acct", fields=_BROWSER_FIELDS)
    assert expected == compatible.credential_revisions("acct", fields=_BROWSER_FIELDS)
    assert ignored.record_credentials(
        spec, clear=("refresh_token",), access_token="WORKER-AT", expected_revisions=expected,
    )
    resolved = Overlay(path).load().apply(spec)
    assert resolved.credentials.access_token == "WORKER-AT"
    assert resolved.credentials.refresh_token == ""
    assert ignored.apply(spec).credentials.access_token == "CONFIG-AT"


def test_new_refresh_token_overwrites_tombstone_and_clear_wins_same_call(tmp_path):
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    spec = _spec(refresh_token="CONFIG-RT")
    assert overlay.record_credentials(spec, refresh_token="IGNORED", clear=("refresh_token",))
    tombstone = overlay.credential_revisions("acct")
    assert Overlay(path).load().apply(spec).credentials.refresh_token == ""
    assert overlay.record_credentials(spec, refresh_token="NEW-RT", expected_revisions=tombstone)
    reopened = Overlay(path).load()
    assert reopened.apply(spec).credentials.refresh_token == "NEW-RT"
    entry = reopened.entry("acct").fields["refresh_token"]
    assert not entry.tombstone
    assert entry.ttl == TTL_DEFAULTS["refresh_token"]
    raw = json.loads(path.read_text(encoding="utf-8"))["entries"]["acct"]["fields"]["refresh_token"]
    assert not raw.get("tombstone")
    assert reopened.credential_revisions("acct")["refresh_token"] != tombstone["refresh_token"]


def test_credential_revisions_are_readonly_and_do_not_migrate_missing_cache(tmp_path, monkeypatch):
    from config import paths as paths_mod

    legacy = tmp_path / "token_cache.json"
    legacy.write_text(json.dumps({"tokens": {"k": {"access_token": "LEGACY-SECRET"}}}), encoding="utf-8")
    monkeypatch.setattr(paths_mod, "LEGACY_TOKEN_CACHE_PATH", legacy)
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    revisions = overlay.credential_revisions("acct")
    assert tuple(revisions) == CREDENTIAL_FIELDS
    assert all(isinstance(revision, str) and revision for revision in revisions.values())
    assert not path.exists()
    assert not overlay._loaded
    with pytest.raises(TypeError):
        revisions["access_token"] = "modified"
    subset = overlay.credential_revisions("acct", fields=iter(_BROWSER_FIELDS))
    assert tuple(subset) == _BROWSER_FIELDS
    assert subset == {name: revisions[name] for name in _BROWSER_FIELDS}


@pytest.mark.parametrize("changed_field", _BROWSER_FIELDS)
@pytest.mark.parametrize("clear", [False, True])
def test_stale_browser_group_cas_preserves_new_credentials_and_whole_document(tmp_path, changed_field, clear):
    path = tmp_path / "overlay.json"
    document = {
        "version": 3,
        "entries": {
            "acct": {"flow": {"keep": "flow"}, "health": {"keep": "health"},
                     "learning": {"keep": "learning"}, "extension": {"keep": True}},
            "other": {"fields": {"access_token": "OTHER"}, "extension": [1, 2]},
        },
        "oauth_states": {"extension": {"keep": "oauth"}},
        "future_top_level": {"keep": "top"},
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    spec = _spec(refresh_token="CONFIG-RT")
    original = {name: f"INITIAL-{name}" for name in _BROWSER_FIELDS}
    assert Overlay(path).record_credentials(spec, **original)
    stale = Overlay(path).load()
    expected = stale.credential_revisions("acct", fields=_BROWSER_FIELDS)
    fresh = Overlay(path).load()
    mutation = {"clear": (changed_field,)} if clear else {changed_field: "FRESH-VALUE"}
    assert fresh.record_credentials(spec, **mutation)
    before = path.read_bytes()
    assert not stale.record_credentials(
        spec, expected_revisions=expected, **{name: f"STALE-{name}" for name in _BROWSER_FIELDS},
    )
    assert path.read_bytes() == before
    reopened = Overlay(path).load()
    for name in _BROWSER_FIELDS:
        value = ("" if clear else "FRESH-VALUE") if name == changed_field else original[name]
        assert reopened.apply(spec).credentials.get(name) == value
    assert stale.credential_revisions("acct", fields=_BROWSER_FIELDS) == fresh.credential_revisions(
        "acct", fields=_BROWSER_FIELDS,
    )


@pytest.mark.parametrize("clear", [False, True])
def test_cas_checks_changed_guard_field_even_when_blank_input_is_ignored(tmp_path, clear):
    path = tmp_path / "overlay.json"
    stale = Overlay(path)
    expected = stale.credential_revisions("acct", fields=_BROWSER_FIELDS)
    fresh = Overlay(path)
    mutation = {"clear": ("refresh_token",)} if clear else {"refresh_token": "NEW-RT"}
    assert fresh.record_credentials(_spec(), **mutation)
    before = path.read_bytes()
    assert not stale.record_credentials(
        _spec(), expected_revisions=expected,
        browser_state="STALE-STATE", access_token="STALE-AT", refresh_token="",
    )
    assert path.read_bytes() == before


def test_credential_revisions_include_raw_metadata_and_read_fresh_disk(tmp_path):
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    assert overlay.record_credentials(_spec(), access_token="PRIVATE-AT", refresh_token="PRIVATE-RT")
    overlay.load()
    before = overlay.credential_revisions("acct", fields=_BROWSER_FIELDS)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["entries"]["acct"]["fields"]["access_token"]["future_metadata"] = {"version": 2}
    path.write_text(json.dumps(document), encoding="utf-8")
    after = overlay.credential_revisions("acct", fields=_BROWSER_FIELDS)
    assert before["access_token"] != after["access_token"]
    assert before["refresh_token"] == after["refresh_token"]
    assert before["browser_state"] == after["browser_state"]
    assert "PRIVATE-AT" not in repr(after)
    assert "PRIVATE-RT" not in repr(after)
    stored = path.read_bytes()
    assert not overlay.record_credentials(_spec(), access_token="STALE", expected_revisions=before)
    assert path.read_bytes() == stored


def test_unrelated_updates_preserve_raw_revisions_and_allow_expected_write(tmp_path):
    path = tmp_path / "overlay.json"
    document = {
        "version": 3,
        "entries": {"acct": {"fields": {
            "access_token": {"value": "LEGACY-AT", "ttl": 0, "future_metadata": {"keep": True}},
            "refresh_token": "LEGACY-RT",
            "unknown_credential": {"keep": "unknown"},
        }, "future_account_metadata": {"keep": True}}},
        "future_top_level": {"keep": True},
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    stale = Overlay(path).load()
    expected = stale.credential_revisions("acct", fields=_BROWSER_FIELDS)
    fresh = Overlay(path)
    assert fresh.record_flow("acct", [Discovery(stage="login", value="refresh", confidence=0.9)])
    assert fresh.record_health("acct", ok=False, verdict="failed")
    assert fresh.put_learning("acct", "quiz", {"question": "answer"})
    assert fresh.record_credentials(_spec(), cookie="UNRELATED-COOKIE")
    assert fresh.record_credentials(
        AccountSpec(id="other", name="o", base_url="https://other.example"), access_token="OTHER-AT",
    )
    oauth = fresh.resolve_oauth_state("github", "default", "CONFIG-OAUTH")
    assert fresh.record_oauth_state(oauth, "OAUTH-STATE")
    before = json.loads(path.read_text(encoding="utf-8"))
    for name, value in document["entries"]["acct"]["fields"].items():
        assert before["entries"]["acct"]["fields"][name] == value
    assert fresh.credential_revisions("acct", fields=_BROWSER_FIELDS) == expected
    assert stale.record_credentials(
        _spec(), expected_revisions=expected,
        access_token="NEW-AT", refresh_token="NEW-RT", browser_state="NEW-STATE",
    )
    after = json.loads(path.read_text(encoding="utf-8"))
    for name in ("flow", "health", "learning", "future_account_metadata"):
        assert after["entries"]["acct"][name] == before["entries"]["acct"][name]
    assert after["entries"]["other"] == before["entries"]["other"]
    assert after["oauth_states"] == before["oauth_states"]
    assert after["future_top_level"] == before["future_top_level"]
    fields = after["entries"]["acct"]["fields"]
    assert fields["access_token"]["future_metadata"] == {"keep": True}
    assert fields["unknown_credential"] == {"keep": "unknown"}
    assert fields["cookie"] == before["entries"]["acct"]["fields"]["cookie"]
    resolved = Overlay(path).load().apply(_spec())
    assert resolved.credentials.access_token == "NEW-AT"
    assert resolved.credentials.refresh_token == "NEW-RT"
    assert resolved.credentials.browser_state == "NEW-STATE"


@pytest.mark.parametrize(("initial", "rewrites"), [
    ("A", ("A",)),
    ("A", ("B", "A")),
    ("A", ("", "A")),
    ("", ("",)),
    ("", ("B", "")),
])
def test_same_second_rewrites_and_aba_change_revisions(tmp_path, monkeypatch, initial, rewrites):
    monkeypatch.setattr("config.overlay.utc_iso", lambda: "2026-01-01T00:00:00Z")
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    spec = _spec(access_token="CONFIG-AT")
    seen = set()
    original = None
    for value in (initial, *rewrites):
        mutation = {"access_token": value} if value else {"clear": ("access_token",)}
        assert overlay.record_credentials(spec, **mutation)
        revisions = overlay.credential_revisions("acct", fields=_BROWSER_FIELDS)
        assert revisions["access_token"] not in seen
        seen.add(revisions["access_token"])
        if original is None:
            original = revisions
        entry = Overlay(path).load().entry("acct").fields["access_token"]
        assert entry.updated_at == "2026-01-01T00:00:00Z"
        assert entry.revision_nonce
        assert FieldEntry.from_payload(entry.to_payload()) == entry
    assert overlay.record_health("acct", ok=True)
    assert overlay.credential_revisions("acct", fields=_BROWSER_FIELDS) == revisions
    before = path.read_bytes()
    assert not overlay.record_credentials(spec, access_token="STALE", expected_revisions=original)
    assert path.read_bytes() == before


@pytest.mark.parametrize("document", [
    None,
    [],
    {"entries": None},
    {"entries": []},
    {"entries": {"acct": None}},
    {"entries": {"acct": []}},
    {"entries": {"acct": {"fields": None}}},
    {"entries": {"acct": {"fields": []}}},
    {"entries": {"acct": {"fields": {"access_token": None}}}},
    {"entries": {"acct": {"fields": {"access_token": []}}}},
    {"entries": {"acct": {"fields": {"access_token": {}}}}},
    {"entries": {"acct": {"fields": {"access_token": {"value": ""}}}}},
    {"entries": {"acct": {"fields": {"access_token": {"value": "", "tombstone": True}}}}},
])
def test_corrupt_credential_entries_are_not_missing_and_cas_never_repairs_them(tmp_path, document):
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    missing = overlay.credential_revisions("acct", fields=_BROWSER_FIELDS)
    path.write_text(json.dumps(document), encoding="utf-8")
    corrupted = overlay.credential_revisions("acct", fields=_BROWSER_FIELDS)
    assert corrupted["access_token"] != missing["access_token"]
    before = path.read_bytes()
    receipt = {"keep": "unchanged"}
    for expected in (missing, corrupted):
        assert not overlay.record_credentials(
            _spec(), access_token="NEW-AT", browser_state="NEW-STATE",
            expected_revisions=expected, written_revisions=receipt,
        )
        assert path.read_bytes() == before
        assert receipt == {"keep": "unchanged"}


def test_invalid_json_rejects_credential_cas_without_losing_document(tmp_path):
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    missing = overlay.credential_revisions("acct")
    path.write_text("{broken", encoding="utf-8")
    corrupted = overlay.credential_revisions("acct")
    assert corrupted != missing
    assert not overlay.record_credentials(_spec(), clear=("refresh_token",), expected_revisions=corrupted)
    assert path.read_text(encoding="utf-8") == "{broken"


def test_successful_cas_receipt_contains_only_actual_writes(tmp_path):
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    spec = _spec(refresh_token="CONFIG-RT")
    expected = overlay.credential_revisions("acct", fields=_BROWSER_FIELDS)
    receipt = {"keep": "unchanged"}
    assert overlay.record_credentials(
        spec, expected_revisions=expected, written_revisions=receipt,
        access_token="NEW-AT", browser_state="", clear=("refresh_token",),
    )
    actual = Overlay(path).credential_revisions("acct", fields=_BROWSER_FIELDS)
    assert receipt == {"keep": "unchanged", **{name: actual[name] for name in ("access_token", "refresh_token")}}
    assert actual["browser_state"] == expected["browser_state"]
    for name in ("access_token", "refresh_token"):
        assert actual[name] != expected[name]
    assert "NEW-AT" not in repr(receipt)
    before = path.read_bytes()
    saved_receipt = dict(receipt)
    assert not overlay.record_credentials(
        spec, access_token="STALE-AT", clear=("refresh_token",),
        expected_revisions=expected, written_revisions=receipt,
    )
    assert path.read_bytes() == before
    assert receipt == saved_receipt


def test_failed_atomic_write_does_not_publish_credential_receipt(tmp_path, monkeypatch):
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    assert overlay.record_credentials(_spec(), access_token="CURRENT-AT")
    expected = overlay.credential_revisions("acct")
    before = path.read_bytes()
    receipt = {"keep": "unchanged"}

    def fail_write(*args, **kwargs):
        raise OSError("simulated write failure")

    monkeypatch.setattr("config.overlay.paths.atomic_write_json", fail_write)
    assert not overlay.record_credentials(
        _spec(), access_token="REJECTED-AT", expected_revisions=expected, written_revisions=receipt,
    )
    assert path.read_bytes() == before
    assert receipt == {"keep": "unchanged"}
    assert overlay.entry("acct").fields["access_token"].value == "CURRENT-AT"


def test_credential_receipt_is_exact_commit_not_newer_writer_after_unlock(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from config import paths as paths_mod

    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    expected = overlay.credential_revisions("acct", fields=_BROWSER_FIELDS)
    real_lock = paths_mod.file_lock
    own_revision = {}

    @contextmanager
    def lock_then_newer_writer(target, **kwargs):
        with real_lock(target, **kwargs):
            yield
        own_revision.update(Overlay(path).credential_revisions("acct", fields=("access_token",)))
        monkeypatch.setattr(paths_mod, "file_lock", real_lock)
        assert Overlay(path).record_credentials(_spec(), access_token="CONCURRENT-AT")

    monkeypatch.setattr(paths_mod, "file_lock", lock_then_newer_writer)
    receipt = {}
    assert overlay.record_credentials(
        _spec(), access_token="OWN-AT", expected_revisions=expected, written_revisions=receipt,
    )
    assert receipt == own_revision
    assert receipt["access_token"] != Overlay(path).credential_revisions("acct")["access_token"]
    assert Overlay(path).load().apply(_spec()).credentials.access_token == "CONCURRENT-AT"


def test_credential_cas_rechecks_after_waiting_for_lock(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from config import paths as paths_mod

    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    expected = overlay.credential_revisions("acct", fields=_BROWSER_FIELDS)
    real_lock = paths_mod.file_lock
    committed = {}

    @contextmanager
    def lock_after_newer_writer(target, **kwargs):
        monkeypatch.setattr(paths_mod, "file_lock", real_lock)
        assert Overlay(path).record_credentials(_spec(), clear=("refresh_token",))
        committed["bytes"] = path.read_bytes()
        with real_lock(target, **kwargs):
            yield

    monkeypatch.setattr(paths_mod, "file_lock", lock_after_newer_writer)
    receipt = {"keep": "unchanged"}
    assert not overlay.record_credentials(
        _spec(), browser_state="STALE-STATE", access_token="STALE-AT",
        expected_revisions=expected, written_revisions=receipt,
    )
    assert path.read_bytes() == committed["bytes"]
    assert receipt == {"keep": "unchanged"}


def test_unguarded_write_keeps_last_writer_behavior_and_returns_receipt(tmp_path):
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    assert overlay.record_credentials(_spec(), access_token="FIRST-AT")
    assert Overlay(path).record_credentials(_spec(), access_token="SECOND-AT")
    receipt = {}
    assert overlay.record_credentials(_spec(), access_token="THIRD-AT", written_revisions=receipt)
    assert receipt == Overlay(path).credential_revisions("acct", fields=("access_token",))
    assert Overlay(path).load().apply(_spec()).credentials.access_token == "THIRD-AT"


# ── 一致凭据快照 ────────────────────────────────────────────────────────────
def test_credential_snapshot_uses_one_raw_read_and_ignores_stale_memory(tmp_path, monkeypatch):
    import config.overlay as overlay_mod

    path = tmp_path / "overlay.json"
    spec = _spec(refresh_token="CONFIG-RT")
    first = Overlay(path)
    assert first.record_credentials(spec, access_token="FIRST-AT", refresh_token="FIRST-RT")
    stale = Overlay(path).load()
    stale._accounts_mtime = ""  # noqa: SLF001
    assert Overlay(path).record_credentials(spec, access_token="DISK-AT")
    expected_revisions = stale.credential_revisions("acct")
    real_read = overlay_mod._read_overlay_document
    calls = []

    def read_then_concurrent_write(target):
        document = real_read(target)
        calls.append(target)
        concurrent = json.loads(path.read_text(encoding="utf-8"))
        fields = concurrent["entries"]["acct"]["fields"]
        fields["access_token"].update(value="CONCURRENT-AT", revision_nonce="concurrent")
        fields["refresh_token"] = {
            "value": "", "updated_at": utc_iso(), "ttl": 0, "origin": "refresh",
            "config_hash": overlay_mod._hash("CONFIG-RT"), "revision_nonce": "tomb", "tombstone": True,
        }
        path.write_text(json.dumps(concurrent), encoding="utf-8")
        return document

    monkeypatch.setattr(overlay_mod, "_read_overlay_document", read_then_concurrent_write)
    resolved, revisions, entry = stale.credential_snapshot(spec)
    monkeypatch.setattr(overlay_mod, "_read_overlay_document", real_read)
    assert calls == [path]
    assert resolved.credentials.access_token == entry.fields["access_token"].value == "DISK-AT"
    assert resolved.credentials.refresh_token == entry.fields["refresh_token"].value == "FIRST-RT"
    assert revisions == expected_revisions
    assert tuple(revisions) == CREDENTIAL_FIELDS
    assert stale.apply(spec).credentials.access_token == "FIRST-AT"
    latest_resolved, latest_revisions, latest_entry = stale.credential_snapshot(spec)
    assert latest_resolved.credentials.access_token == "CONCURRENT-AT"
    assert latest_resolved.credentials.refresh_token == ""
    assert latest_entry.fields["refresh_token"].tombstone
    assert latest_revisions["access_token"] != revisions["access_token"]
    assert latest_revisions["refresh_token"] != revisions["refresh_token"]
    with pytest.raises(TypeError):
        revisions["access_token"] = "modified"


def test_credential_snapshot_is_readonly_and_never_migrates_or_creates_files(tmp_path, monkeypatch):
    from config import paths as paths_mod

    legacy = tmp_path / "token_cache.json"
    legacy.write_text(json.dumps({"tokens": {"k": {"access_token": "LEGACY-SECRET"}}}), encoding="utf-8")
    monkeypatch.setattr(paths_mod, "LEGACY_TOKEN_CACHE_PATH", legacy)
    path = tmp_path / "missing-dir" / "overlay.json"
    overlay = Overlay(path)
    overlay._accounts_mtime = ""  # noqa: SLF001

    def forbidden(*args, **kwargs):
        raise AssertionError("snapshot must not load, migrate, lock, or write")

    monkeypatch.setattr(Overlay, "_migrate_legacy", forbidden)
    for name in ("read_json", "atomic_write_json", "atomic_write_text", "file_lock"):
        monkeypatch.setattr(paths_mod, name, forbidden)
    spec = _spec(access_token="CONFIG-AT")
    # conftest 预建 .cache-checkin；只断言快照前后文件树完全一致。
    before = sorted(str(item.relative_to(tmp_path)) for item in tmp_path.rglob("*"))
    resolved, revisions, entry = overlay.credential_snapshot(spec)
    assert resolved.credentials.access_token == "CONFIG-AT"
    assert set(resolved.origins.values()) == {"config"}
    assert entry.fields == {}
    assert revisions == overlay.credential_revisions("acct")
    assert sorted(str(item.relative_to(tmp_path)) for item in tmp_path.rglob("*")) == before
    assert not path.parent.exists()
    assert legacy.read_text(encoding="utf-8") == json.dumps({"tokens": {"k": {"access_token": "LEGACY-SECRET"}}})
    assert not overlay._loaded  # noqa: SLF001
    assert overlay._entries == {}  # noqa: SLF001


def _snapshot_rules_document():
    from config.overlay import _hash

    def item(value, *, ttl=0, config_hash="", updated_at=None, **rest):
        return {
            "value": value, "updated_at": updated_at or utc_iso(), "ttl": ttl,
            "origin": "refresh", "config_hash": config_hash, **rest,
        }

    return {"version": 3, "entries": {"acct": {
        "fields": {
            "access_token": item("CACHED-AT", config_hash=_hash("CONFIG-AT")),
            "refresh_token": item("", config_hash=_hash("CONFIG-RT"), tombstone=True),
            "cookie": item("EXPIRED-COOKIE", ttl=60, updated_at=_iso(days=-1),
                           config_hash=_hash("CONFIG-COOKIE")),
            "browser_state": item("HASH-MISMATCH-STATE", config_hash=_hash("OLD-STATE")),
            "session_cookie": item("LEGACY-SESSION", updated_at=_iso(days=-2)),
        },
        "flow": {"login": {"value": "refresh"}},
        "health": {"failure_streak": 1},
        "accounts_mtime": "",
        "updated_at": _iso(days=-2),
    }}}


@pytest.mark.parametrize("policy", [CachePolicy.COMPATIBLE, CachePolicy.READONLY, CachePolicy.IGNORE])
@pytest.mark.parametrize("explicit", [(), ("access_token", "refresh_token"), ("browser_state",)])
def test_credential_snapshot_preserves_apply_policy_explicit_ttl_and_hash_rules(tmp_path, policy, explicit):
    path = tmp_path / "overlay.json"
    path.write_text(json.dumps(_snapshot_rules_document()), encoding="utf-8")
    before = path.read_bytes()
    spec = _spec(
        access_token="CONFIG-AT", refresh_token="CONFIG-RT", cookie="CONFIG-COOKIE",
        browser_state="CONFIG-STATE", session_cookie="CONFIG-SESSION",
    )
    overlay = Overlay(path, policy=policy)
    overlay._accounts_mtime = _iso(days=-1)  # noqa: SLF001 - 让 4b 选择配置
    resolved, revisions, entry = overlay.credential_snapshot(spec, explicit=explicit)
    normal = Overlay(path, policy=policy)
    normal._accounts_mtime = overlay._accounts_mtime  # noqa: SLF001
    assert resolved == normal.load().apply(spec, explicit=explicit)
    assert revisions == Overlay(path, policy=policy).credential_revisions("acct")
    assert entry.fields["refresh_token"].tombstone
    assert path.read_bytes() == before

    values = resolved.credentials
    if policy == CachePolicy.IGNORE:
        assert values == spec.credentials
        assert resolved.learned_flow == {}
        assert resolved.health == {}
    else:
        assert values.access_token == ("CONFIG-AT" if "access_token" in explicit else "CACHED-AT")
        assert values.refresh_token == ("CONFIG-RT" if "refresh_token" in explicit else "")
        assert values.cookie == "CONFIG-COOKIE"
        assert values.browser_state == "CONFIG-STATE"
        assert values.session_cookie == "CONFIG-SESSION"
        assert resolved.health == {"failure_streak": 1}
    for name in explicit:
        assert resolved.origins[name] == "explicit"


@pytest.mark.parametrize("document", [
    None,
    [],
    {"entries": None},
    {"entries": []},
    {"entries": {"acct": None}},
    {"entries": {"acct": []}},
    {"entries": {"acct": {"fields": None}}},
    {"entries": {"acct": {"fields": []}}},
    {"entries": {"acct": {"fields": {"access_token": None}}}},
    {"entries": {"acct": {"fields": {"browser_state": {}}}}},
    {"entries": {"acct": {"fields": {"refresh_token": {"value": ""}}}}},
    {"entries": {"acct": {"fields": {"refresh_token": {"value": "", "tombstone": True}}}}},
])
def test_credential_snapshot_fails_closed_for_corrupt_document_or_credentials(tmp_path, document):
    path = tmp_path / "overlay.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    before = path.read_bytes()
    for policy in (CachePolicy.COMPATIBLE, CachePolicy.READONLY, CachePolicy.IGNORE):
        with pytest.raises(ValueError):
            Overlay(path, policy=policy).credential_snapshot(_spec())
    path.write_text("{broken", encoding="utf-8")
    with pytest.raises(ValueError):
        Overlay(path).credential_snapshot(_spec())
    path.write_bytes(before)


def test_credential_snapshot_scopes_corruption_to_target_credentials(tmp_path):
    path = tmp_path / "overlay.json"
    path.write_text(json.dumps({"version": 3, "entries": {
        "acct": {"fields": {"access_token": "LEGACY-AT", "unknown_credential": []},
                 "flow": [], "learning": None, "health": "bad"},
        "other": [],
    }}), encoding="utf-8")
    resolved, revisions, entry = Overlay(path).credential_snapshot(_spec())
    assert resolved.credentials.access_token == entry.fields["access_token"].value == "LEGACY-AT"
    assert resolved.learned_flow == {}
    assert resolved.health == {}
    assert revisions == Overlay(path).credential_revisions("acct")


def test_credential_snapshot_revisions_drive_atomic_browser_group_cas(tmp_path):
    path = tmp_path / "overlay.json"
    spec = _spec(refresh_token="CONFIG-RT")
    initial = {name: f"INITIAL-{name}" for name in _BROWSER_FIELDS}
    assert Overlay(path).record_credentials(spec, **initial)
    launch_resolved, launch_revisions, _ = Overlay(path).credential_snapshot(spec)
    assert launch_resolved.credentials.browser_state == "INITIAL-browser_state"
    assert Overlay(path).record_credentials(spec, clear=("refresh_token",))
    current_resolved, current_revisions, current_entry = Overlay(path).credential_snapshot(spec)
    assert current_resolved.credentials.browser_state == launch_resolved.credentials.browser_state
    assert current_resolved.credentials.refresh_token == ""
    assert current_entry.fields["refresh_token"].tombstone
    assert current_revisions["browser_state"] == launch_revisions["browser_state"]
    assert current_revisions["refresh_token"] != launch_revisions["refresh_token"]
    before = path.read_bytes()
    expected = {name: launch_revisions[name] for name in _BROWSER_FIELDS}
    assert not Overlay(path).record_credentials(spec, expected_revisions=expected, **initial)
    assert path.read_bytes() == before


# ── 流程结论与健康度 ────────────────────────────────────────────────────────
def test_record_and_reuse_flow_discovery(tmp_path):
    overlay = Overlay(tmp_path / "overlay.json")
    overlay.record_flow("acct", [Discovery(stage="login", value="refresh", confidence=0.9)])

    reopened = Overlay(tmp_path / "overlay.json").load()
    discoveries = reopened.entry("acct").flow_discoveries()
    assert discoveries["login"].value == "refresh"
    assert discoveries["login"].is_fresh()


def test_health_failure_streak_accumulates_and_resets(tmp_path):
    overlay = Overlay(tmp_path / "overlay.json")
    overlay.record_health("acct", ok=False, verdict="failed", reason="need_login")
    overlay.record_health("acct", ok=False, verdict="failed", reason="need_login")
    assert overlay.entry("acct").failure_streak == 2
    overlay.record_health("acct", ok=True, verdict="success")
    assert overlay.entry("acct").failure_streak == 0


# ── 学习数据 ────────────────────────────────────────────────────────────────
def test_learning_roundtrip_and_size_cap(tmp_path):
    overlay = Overlay(tmp_path / "overlay.json")
    assert overlay.put_learning("acct", "quiz_bank", {"q1": "a"})
    assert overlay.get_learning("acct", "quiz_bank") == {"q1": "a"}
    assert overlay.get_learning("acct", "missing", default=[]) == []
    # 超限拒绝而不是静默截断
    assert not overlay.put_learning("acct", "huge", {"k": "x" * 300_000})
    assert overlay.get_learning("acct", "huge") is None


# ── 旧 token_cache.json 迁移 ────────────────────────────────────────────────
def test_legacy_token_cache_is_migrated(tmp_path, monkeypatch):
    from config import paths as paths_mod

    legacy = tmp_path / "token_cache.json"
    legacy.write_text(
        json.dumps(
            {
                "version": 2,
                "tokens": {
                    "https://example.com|测试站": {
                        "access_token": "OLD",
                        "browser_state": "STATE",
                        "updated_at": utc_iso(),
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(paths_mod, "LEGACY_TOKEN_CACHE_PATH", legacy)

    overlay = Overlay(tmp_path / "overlay.json").load()
    legacy_entry = overlay.entry("legacy:https://example.com|测试站")
    assert legacy_entry.fields["access_token"].value == "OLD"
    # 迁移条目没有 config_hash，走时间判据
    assert legacy_entry.fields["access_token"].config_hash == ""

    moved = overlay.migrate_keys({"https://example.com|测试站": "acct"})
    assert moved == 1
    assert overlay.entry("acct").fields["browser_state"].value == "STATE"
    assert overlay.apply(_spec()).credentials.access_token == "OLD"


def test_migrate_keys_never_overwrites_fresh_entry(tmp_path, monkeypatch):
    from config import paths as paths_mod

    legacy = tmp_path / "token_cache.json"
    legacy.write_text(
        json.dumps({"tokens": {"k": {"access_token": "OLD", "updated_at": utc_iso()}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(paths_mod, "LEGACY_TOKEN_CACHE_PATH", legacy)
    overlay = Overlay(tmp_path / "overlay.json").load()
    overlay.record_credentials(_spec(), access_token="NEW")
    assert overlay.migrate_keys({"k": "acct"}) == 0
    assert overlay.entry("acct").fields["access_token"].value == "NEW"


# ── 诊断输出 ────────────────────────────────────────────────────────────────
def test_explain_reports_rule_and_never_leaks_value(tmp_path):
    overlay = _overlay(tmp_path, {"acct": _entry()})
    lines = overlay.explain(_spec(access_token="SECRET_CONFIG_VALUE"))
    joined = "\n".join(lines)
    assert "access_token" in joined
    assert "SECRET_CONFIG_VALUE" not in joined
    assert "CACHED" not in joined


def _rule(overlay: Overlay, spec: AccountSpec) -> str:
    return "\n".join(overlay.explain(spec))


# ── 共享 OAuth 缓存 ─────────────────────────────────────────────────────────
def test_oauth_state_roundtrip_isolated_and_preserves_document_extensions(tmp_path):
    path = tmp_path / "overlay.json"
    path.write_text(json.dumps({"version": 3, "entries": {}, "health": {"keep": True}}), encoding="utf-8")
    overlay = Overlay(path).load()
    first = overlay.resolve_oauth_state("github", "work", "CONFIG", now_iso="2026-01-01T00:00:00Z")
    assert not first.from_overlay
    assert overlay.record_oauth_state(first, "STATE", now_iso="2026-01-01T00:00:00Z")
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["health"] == {"keep": True}
    assert stored["oauth_states"]["github"]["accounts"]["work"]["value"] == "STATE"
    resolved = Overlay(path).resolve_oauth_state("github", "work", "CONFIG", now_iso="2026-01-02T00:00:00Z")
    assert resolved.state == "STATE"
    assert resolved.from_overlay
    assert Overlay(path).resolve_oauth_state("github", "other", "CONFIG").state == "CONFIG"


def test_oauth_empty_or_changed_config_never_revives_cache(tmp_path):
    overlay = Overlay(tmp_path / "overlay.json")
    original = overlay.resolve_oauth_state("linuxdo", "default", "CONFIG", now_iso="2026-01-01T00:00:00Z")
    assert overlay.record_oauth_state(original, "STATE", now_iso="2026-01-01T00:00:00Z")
    assert overlay.resolve_oauth_state("linuxdo", "default", "").state == ""
    changed = overlay.resolve_oauth_state("linuxdo", "default", "NEW", now_iso="2026-01-02T00:00:00Z")
    assert changed.state == "NEW"
    assert not changed.from_overlay


def test_oauth_expiry_future_invalid_ttl_and_policy(tmp_path):
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    resolution = overlay.resolve_oauth_state("github", "a", "C", now_iso="2026-01-01T00:00:00Z")
    assert overlay.record_oauth_state(resolution, "S", ttl=10, now_iso="2026-01-01T00:00:00Z")
    valid_readonly = Overlay(path, policy=CachePolicy.READONLY).resolve_oauth_state(
        "github", "a", "C", now_iso="2026-01-01T00:00:01Z"
    )
    assert valid_readonly.state == "S"
    assert valid_readonly.from_overlay
    assert Overlay(path).resolve_oauth_state("github", "a", "C", now_iso="2026-01-01T00:00:11Z").state == "C"
    assert Overlay(path).resolve_oauth_state("github", "a", "C", now_iso="2025-12-31T23:59:59Z").state == "C"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["oauth_states"]["github"]["accounts"]["a"]["updated_at"] = "2026-01-02T00:00:00Z"
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert Overlay(path).resolve_oauth_state("github", "a", "C", now_iso="2026-01-01T00:00:01Z").state == "C"
    raw["oauth_states"]["github"]["accounts"]["a"]["ttl"] = 0
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert Overlay(path).resolve_oauth_state("github", "a", "C").state == "C"
    assert Overlay(path, policy=CachePolicy.IGNORE).resolve_oauth_state("github", "a", "C").state == "C"
    assert not Overlay(path, policy=CachePolicy.IGNORE).record_oauth_state(resolution, "S")
    assert Overlay(path, policy=CachePolicy.READONLY).resolve_oauth_state("github", "a", "C").state == "C"
    assert not Overlay(path, policy=CachePolicy.READONLY).record_oauth_state(resolution, "S")


def test_oauth_same_identity_cas_rejects_and_different_identity_survives(tmp_path):
    path = tmp_path / "overlay.json"
    a = Overlay(path)
    b = Overlay(path)
    ra = a.resolve_oauth_state("github", "a", "C")
    rb = b.resolve_oauth_state("github", "b", "C")
    assert a.record_oauth_state(ra, "A", now_iso="2026-01-01T00:00:00Z")
    assert b.record_oauth_state(rb, "B", now_iso="2026-01-01T00:00:00Z")
    stale = Overlay(path).resolve_oauth_state("github", "a", "C")
    assert a.record_oauth_state(stale, "A2", now_iso="2026-01-01T00:00:01Z")
    assert not b.record_oauth_state(stale, "A3", now_iso="2026-01-01T00:00:02Z")


def test_oauth_callback_change_and_corrupt_cache_reject_writes(tmp_path):
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    resolution = overlay.resolve_oauth_state("github", "default", "CONFIG")
    assert not overlay.record_oauth_state(
        resolution,
        "STATE",
        current_config=lambda: ("CHANGED", "sha256:changed"),
    )
    path.write_text("{broken", encoding="utf-8")
    assert not overlay.record_oauth_state(resolution, "STATE")


def test_oauth_revision_changes_same_second_and_metadata_basis_is_checked(tmp_path):
    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    resolution = overlay.resolve_oauth_state("github", "default", "CONFIG")
    assert overlay.record_oauth_state(resolution, "STATE", now_iso="2026-01-01T00:00:00Z")
    first = json.loads(path.read_text(encoding="utf-8"))
    first_revision = Overlay(path).resolve_oauth_state("github", "default", "CONFIG").revision
    assert overlay.record_oauth_state(
        Overlay(path).resolve_oauth_state("github", "default", "CONFIG"),
        "STATE2",
        now_iso="2026-01-01T00:00:00Z",
    )
    second_revision = Overlay(path).resolve_oauth_state("github", "default", "CONFIG").revision
    assert first_revision != second_revision
    assert first["oauth_states"]["github"]["accounts"]["default"]["revision_nonce"]
    assert not overlay.record_oauth_state(
        Overlay(path).resolve_oauth_state("github", "default", "CONFIG"),
        "STATE3",
        current_config=lambda: ("CONFIG", "sha256:metadata-changed"),
    )
    assert not overlay.record_oauth_state(
        Overlay(path).resolve_oauth_state("github", "default", "CONFIG"),
        "STATE4",
        current_config=lambda: ("", "sha256:empty"),
    )


def test_oauth_corrupt_containers_are_not_treated_as_missing(tmp_path):
    path = tmp_path / "overlay.json"
    path.write_text(json.dumps({"version": 3, "entries": {}, "oauth_states": []}), encoding="utf-8")
    overlay = Overlay(path)
    resolution = overlay.resolve_oauth_state("github", "default", "CONFIG")
    assert not overlay.record_oauth_state(resolution, "STATE")
    assert json.loads(path.read_text(encoding="utf-8"))["oauth_states"] == []
    path.write_text(json.dumps({"version": 3, "entries": {}, "oauth_states": {"github": {"accounts": []}}}), encoding="utf-8")
    resolution = Overlay(path).resolve_oauth_state("github", "default", "CONFIG")
    assert not Overlay(path).record_oauth_state(resolution, "STATE")


def test_oauth_legacy_migration_policy_and_normal_writes_preserve_shared_state(tmp_path, monkeypatch):
    from config import paths as paths_mod

    legacy = tmp_path / "token_cache.json"
    legacy.write_text(json.dumps({"tokens": {"k": {"access_token": "OLD", "updated_at": "2026-01-01T00:00:00Z"}}}), encoding="utf-8")
    monkeypatch.setattr(paths_mod, "LEGACY_TOKEN_CACHE_PATH", legacy)
    readonly_path = tmp_path / "readonly.json"
    assert Overlay(readonly_path, policy=CachePolicy.READONLY).load()
    assert not readonly_path.exists()
    ignore_path = tmp_path / "ignore.json"
    assert Overlay(ignore_path, policy=CachePolicy.IGNORE).load()
    assert not ignore_path.exists()

    path = tmp_path / "overlay.json"
    overlay = Overlay(path)
    resolution = overlay.resolve_oauth_state("github", "default", "CONFIG")
    assert overlay.record_oauth_state(resolution, "STATE")
    assert overlay.record_credentials(_spec(), access_token="TOKEN")
    assert overlay.record_health("acct", ok=True, verdict="success")
    assert overlay.put_learning("acct", "key", "value")
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["oauth_states"]["github"]["accounts"]["default"]["value"] == "STATE"
    assert overlay.entry("acct").fields["access_token"].value == "TOKEN"

    legacy_path = tmp_path / "legacy-overlay.json"
    legacy_path.write_text(json.dumps({"version": 3, "entries": {"legacy:k": {"fields": {"access_token": {"value": "OLD", "updated_at": "2026-01-01T00:00:00Z", "ttl": 0, "origin": "legacy", "config_hash": ""}}}} , "oauth_states": {"github": {"accounts": {"default": {"value": "LATEST", "updated_at": "2026-01-01T00:00:00Z", "ttl": 86400, "origin": "oauth", "config_hash": "sha256:dummy"}}}}}), encoding="utf-8")
    legacy_overlay = Overlay(legacy_path).load()
    assert legacy_overlay.migrate_keys({"k": "acct"}) == 1
    migrated = json.loads(legacy_path.read_text(encoding="utf-8"))
    assert migrated["entries"]["acct"]["fields"]["access_token"]["value"] == "OLD"
    assert migrated["oauth_states"]["github"]["accounts"]["default"]["value"] == "LATEST"


def test_normal_writer_re_reads_latest_oauth_namespace(tmp_path):
    path = tmp_path / "overlay.json"
    stale = Overlay(path).load()
    fresh = Overlay(path)
    resolution = fresh.resolve_oauth_state("linuxdo", "default", "CONFIG")
    assert fresh.record_oauth_state(resolution, "LATEST")
    assert stale.record_health("acct", ok=True, verdict="success")
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["oauth_states"]["linuxdo"]["accounts"]["default"]["value"] == "LATEST"
