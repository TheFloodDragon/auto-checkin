"""运行期覆盖层的时间规则真值表。

这是重构诉求 4 的核心验收：缓存与配置谁说了算，必须由**时间**而不是只由摘要决定，
且任何判定都不会删除缓存值。
"""

from __future__ import annotations

import json
from datetime import timedelta

from config.overlay import TTL_DEFAULTS, CachePolicy, Overlay
from core.account import AccountSpec, CredentialSet
from core.flow import Discovery
from core.timebase import utc_iso, utc_now


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


def test_record_credentials_ignores_blank_fields(tmp_path):
    overlay = Overlay(tmp_path / "overlay.json")
    assert not overlay.record_credentials(_spec(), access_token="  ")


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
