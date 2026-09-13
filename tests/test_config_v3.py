"""配置层：v2 → v3 迁移、未知键保全、Secret 导出。

这三件事共享一条不变量：**用户写进配置的东西，不能因为程序读过一遍就消失。**
旧实现在这里丢过 cookie_file、referer_path，也丢过整份运行期缓存（迁移换了缓存键）。
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import timedelta

import pytest

from config import migrate, schema, secrets, store
from config.overlay import CachePolicy, Overlay, _hash
from core.timebase import utc_now

LEGACY = {
    "accounts": [
        {
            "name": "极速蹬",
            "base_url": "https://jsd.invalid/",
            "site_profile": "sub2api",
            "auth_method": "oauth",
            "checkin_action": "browser_script",
            "script": "scripts/checkin/jisudeng.py",
            "script_args": {"start_path": "/play/checkin", "email": "a@b.c", "password": "pw"},
            "script_timeout": 300,
            "oauth_provider": "linuxdo",
            "oauth_fallback_provider": "github",
            "access_token": "tok",
            "refresh_token": "rt",
            "tolerate_failure": True,
            "verification_mode": "turnstile",
            "login_selector": "#legacy",
        },
        {
            "name": "New API 站",
            "base_url": "https://api.invalid",
            "site_profile": "newapi",
            "auth_method": "cookie",
            "checkin_action": "api",
            "cookie": "s=1",
            "user_id": "42",
            "api_variant": "auto",
        },
    ],
    "oauth_states": {"linuxdo": {"accounts": {"default": {"state": "STATE"}}}},
}


def test_migration_maps_every_dimension() -> None:
    result = migrate.migrate_document(LEGACY)
    jsd, api = result.payload["accounts"]

    assert jsd["template"] == "scripts/tasks/jisudeng.py", "脚本目录已改名"
    assert jsd["tasks"][0]["method"] == "script"
    assert jsd["tasks"][0]["timeout"] == 300
    assert jsd["login"]["method"] == "oauth"
    assert jsd["flow"] == {"verification": "turnstile"}
    assert jsd["policy"] == {"tolerate_failure": True}
    assert {item["method"] for item in jsd["login"]["fallback"]} == {"oauth", "password"}

    assert api["template"] == "newapi"
    assert api["tasks"][0]["method"] == "http_api"
    # 旧 auto 的语义是「challenge 优先」，不是新模型的默认值 legacy。
    assert api["tasks"][0]["args"]["variant"] == "challenge"
    assert api["credentials"]["user_id"] == "42"


def test_migration_moves_script_credentials_out_of_task_args() -> None:
    """账密从 script_args 搬到登录方式的参数上：凭据不该混在任务参数里。"""
    result = migrate.migrate_document(LEGACY)
    jsd = result.payload["accounts"][0]
    password = next(item for item in jsd["login"]["fallback"] if item["method"] == "password")
    assert password["args"] == {"email": "a@b.c", "password": "pw"}


def test_migration_explains_every_change() -> None:
    """每条改动都要留言：静默迁移会让用户对着一份自己没写过的配置发懵。"""
    notes = "\n".join(migrate.migrate_document(LEGACY).notes)
    assert "site_profile" in notes
    assert "auth_method" in notes
    assert "tolerate_failure" in notes
    assert "login_selector" in notes, "被丢弃的废弃字段同样要说明"


def test_migration_maps_legacy_cache_keys() -> None:
    """旧缓存键 base_url|name → 新账号 id，否则一次迁移等于清空全部运行期凭据。"""
    keys = migrate.migrate_document(LEGACY).cache_keys
    assert keys["https://jsd.invalid|极速蹬"] == "jsd-invalid"


def test_migration_is_idempotent() -> None:
    once = migrate.migrate_document(LEGACY).payload
    assert migrate.needs_migration(LEGACY) is True
    assert migrate.needs_migration(once) is False


def test_unknown_keys_survive_a_full_round_trip() -> None:
    """解析器不认识的键必须原样写回：GUI 保存一次不该抹掉用户手写的东西。"""
    raw = {
        "id": "s",
        "name": "s",
        "base_url": "https://s.invalid",
        "template": "newapi",
        "tasks": [{"id": "daily"}],
        "credentials": {"my_field": "keep"},
        "my_note": "也要留着",
    }
    dumped = schema.dump_account(schema.parse_account(raw))
    assert dumped["my_note"] == "也要留着"
    assert dumped["credentials"]["my_field"] == "keep"


def test_load_migrates_and_rehomes_the_overlay(tmp_path) -> None:
    """加载旧配置时自动迁移，并把运行期缓存重挂到新 id 上。"""
    config = tmp_path / "ACCOUNTS.json"
    config.write_text(json.dumps(LEGACY, ensure_ascii=False), encoding="utf-8")

    overlay = Overlay(path=tmp_path / "overlay.json").load()
    overlay._entries["https://jsd.invalid|极速蹬"] = overlay.entry("https://jsd.invalid|极速蹬")
    document = store.load(config, overlay=overlay)

    assert document.version == schema.CONFIG_VERSION
    assert [spec.id for spec in document.accounts] == ["jsd-invalid", "new-api"]
    assert any("已迁移" in note for note in document.notes)
    assert list(tmp_path.glob("ACCOUNTS.json.bak-v2-*")), "迁移前必须留一份备份"


def test_secret_export_keeps_credentials_but_drops_disabled_accounts() -> None:
    """Secret 只带 CI 真正要用的东西：启用账号 + 它们引用到的共享登录态。"""
    document = schema.parse_document(migrate.migrate_document(LEGACY).payload)
    payload = secrets.build_secret_payload(document)

    exported = {item["id"] for item in payload["accounts"]}
    assert exported == {"jsd-invalid", "new-api"}

    jsd = next(item for item in payload["accounts"] if item["id"] == "jsd-invalid")
    # 凭据与登录方式无关：只要有就导出。旧实现按 auth_method 过滤，导致 OAuth 账号的
    # token 没进 Secret，CI 里纯 API 那一级直接被跳过，只能拉浏览器（而 CI 过不去）。
    assert jsd["credentials"]["access_token"] == "tok"
    assert jsd["credentials"]["refresh_token"] == "rt"
    assert payload["oauth_states"]["linuxdo"]["accounts"]["default"]["state"] == "STATE"


def test_secret_size_check_is_actionable() -> None:
    assert secrets.check_size("x" * 10) == ""
    warning = secrets.check_size("x" * (secrets.SECRET_SIZE_LIMIT + 1))
    assert "KiB" in warning and "登录态" in warning


def test_cookie_file_is_not_expanded_into_plaintext(tmp_path) -> None:
    """用户把凭据放在单独文件里，就是不想让它们进配置。"""
    creds = tmp_path / "creds.txt"
    creds.write_text("sess=1\n42\ntok\n", encoding="utf-8")

    spec = schema.parse_account(
        {
            "id": "s",
            "name": "s",
            "base_url": "https://s.invalid",
            "tasks": [{"id": "daily"}],
            "credentials": {"cookie_file": str(creds)},
        }
    )
    assert spec.credentials.cookie == "sess=1", "运行期确实读到了值"

    dumped = schema.dump_account(spec)
    assert dumped["credentials"] == {"cookie_file": str(creds)}
    assert "cookie" not in dumped["credentials"]


@pytest.mark.parametrize("login", [
    {"method": "browser_state"},
    {"method": "oauth", "provider": "linuxdo"},
    {"method": "access_token"},
    {"method": "cookie", "fallback": [{"method": "browser_state"}]},
    {},
])
def test_secret_export_preserves_configured_browser_state(login):
    raw = {"version": 3, "accounts": [{
        "id": "site", "base_url": "https://site.invalid", "login": login,
        "tasks": [{"id": "daily", "method": "browser_flow"}],
        "credentials": {"browser_state": "CONFIGURED_STATE", "access_token": "TOKEN"},
        "display": {"label": "local only"},
    }]}
    before = deepcopy(raw)
    document = schema.parse_document(raw)
    payload = secrets.build_secret_payload(document)
    assert payload["accounts"][0]["credentials"] == raw["accounts"][0]["credentials"]
    assert "display" not in payload["accounts"][0]
    assert json.loads(secrets.dumps(document)) == payload
    assert raw == before


@pytest.mark.parametrize("flag", [True, "true", " YES ", "on", 1, False, "false", "0", None, ""])
def test_secret_export_recognizes_github_fallback_as_an_explicit_reference(flag):
    document = schema.parse_document({"accounts": [{
        "id": "forum", "base_url": "https://linux.do", "template": "scripts/tasks/linuxdo_browse.py",
        "login": {"method": "browser_state", "args": {"github_fallback": flag, "github_account": " work "}},
        "credentials": {"browser_state": "FORUM_STATE"},
    }], "oauth_states": {"github": {"accounts": {
        "work": {"state": "WORK_STATE"}, "unused": {"state": "UNUSED_STATE"},
    }}}})
    payload = secrets.build_secret_payload(document)
    if flag in (True, "true", " YES ", "on", 1):
        assert payload["oauth_states"] == {"github": {"accounts": {"work": {"state": "WORK_STATE"}}}}
    else:
        assert "oauth_states" not in payload


@pytest.mark.parametrize("account", [None, "", "  ", "default"])
def test_secret_export_github_fallback_defaults_to_default_shared_account(account):
    document = schema.parse_document({"accounts": [{
        "id": "forum", "base_url": "https://linux.do",
        "login": {"method": "oauth", "provider": "linuxdo", "account": "forum-user",
                  "args": {"github_fallback": True, "github_account": account}},
    }], "oauth_states": {
        "linuxdo": {"accounts": {"forum-user": {"state": "FORUM_STATE"}}},
        "github": {"accounts": {"default": {"state": "GITHUB_STATE"}, "unused": {"state": "UNUSED"}}},
    }})
    states = secrets.build_secret_payload(document)["oauth_states"]
    assert states == {
        "linuxdo": {"accounts": {"forum-user": {"state": "FORUM_STATE"}}},
        "github": {"accounts": {"default": {"state": "GITHUB_STATE"}}},
    }


@pytest.mark.parametrize(("primary_args", "fallback_args", "expected"), [
    ({"github_fallback": False, "github_account": "work"}, {"github_fallback": True}, {"work"}),
    ({"github_fallback": True, "github_account": "work"}, {"github_account": "backup"}, {"work", "backup"}),
    ({"github_fallback": True, "github_account": "work"},
     {"github_fallback": False, "github_account": "private"}, {"work"}),
])
def test_secret_export_github_fallback_inherits_and_overrides_login_arguments(primary_args, fallback_args, expected):
    document = schema.parse_document({"accounts": [{
        "id": "forum", "base_url": "https://linux.do",
        "login": {"method": "oauth", "provider": "linuxdo", "args": primary_args,
                  "fallback": [{"method": "browser_state", "args": fallback_args}]},
    }], "oauth_states": {"github": {"accounts": {
        name: {"state": name.upper()} for name in ("work", "backup", "private", "unused")
    }}}})
    accounts = secrets.build_secret_payload(document)["oauth_states"]["github"]["accounts"]
    assert set(accounts) == expected


def test_secret_export_excludes_disabled_accounts_and_unreferenced_shared_states():
    document = schema.parse_document({"accounts": [
        {"id": "enabled", "base_url": "https://site.invalid",
         "login": {"method": "oauth", "provider": "linuxdo", "account": "forum",
                   "fallback": [{"method": "oauth", "provider": "github", "account": "work"}]}},
        {"id": "renew", "base_url": "https://renew.invalid",
         "login": {"method": "cookie", "provider": "github", "account": "renew"},
         "tasks": [{"id": "daily", "method": "relogin"}]},
        {"id": "disabled", "base_url": "https://disabled.invalid", "enabled": False,
         "credentials": {"browser_state": "DISABLED_STATE"},
         "login": {"method": "oauth", "provider": "github", "account": "disabled",
                   "args": {"github_fallback": True, "github_account": "private"}}},
        {"id": "inactive", "base_url": "https://inactive.invalid",
         "login": {"method": "cookie", "provider": "github", "account": "inactive"},
         "tasks": [{"id": "daily", "method": "relogin", "enabled": False}]},
    ], "oauth_states": {
        "linuxdo": {"accounts": {"forum": {"state": "FORUM_STATE"}, "unused": {"state": "UNUSED"}}},
        "github": {"accounts": {name: {"state": name.upper()} for name in (
            "work", "renew", "disabled", "private", "inactive", "unused",
        )}},
    }})
    payload = secrets.build_secret_payload(document)
    assert {account["id"] for account in payload["accounts"]} == {"enabled", "renew", "inactive"}
    assert set(payload["oauth_states"]["linuxdo"]["accounts"]) == {"forum"}
    assert set(payload["oauth_states"]["github"]["accounts"]) == {"work", "renew"}
    assert "DISABLED_STATE" not in secrets.dumps(document)


def _cached(value, *, configured="", age_hours=1):
    return {
        "value": value,
        "updated_at": (utc_now() - timedelta(hours=age_hours)).isoformat(timespec="seconds"),
        "ttl": 86400, "origin": "browser", "config_hash": _hash(configured),
    }


def _export_overlay(tmp_path, entries, *, policy=CachePolicy.COMPATIBLE):
    path = tmp_path / "overlay.json"
    path.write_text(json.dumps({"version": 3, "entries": entries}), encoding="utf-8")
    overlay = Overlay(path=path, accounts_path=tmp_path / "ACCOUNTS.json", policy=policy).load()
    overlay._accounts_mtime = utc_now().isoformat(timespec="seconds")
    return overlay


def test_secret_export_overlay_is_opt_in_scoped_and_read_only(tmp_path):
    document = schema.parse_document({"accounts": [
        {"id": "first", "name": "same name", "base_url": "https://first.invalid",
         "login": {"method": "browser_state"}, "credentials": {"cookie": "CONFIG_COOKIE"}},
        {"id": "second", "name": "same name", "base_url": "https://second.invalid",
         "login": {"method": "oauth", "provider": "github", "account": "work"}},
        {"id": "disabled", "base_url": "https://disabled.invalid", "enabled": False},
    ], "oauth_states": {"github": {"accounts": {
        "work": {"state": "SHARED_STATE"}, "unused": {"state": "UNUSED_SHARED_STATE"},
    }}}})
    # 浏览器快照整体保留；外站 localStorage 绝不能被提取成本站独立 token。
    first_state = json.dumps({"cookies": [], "origins": [{
        "origin": "https://other.invalid", "localStorage": [{"name": "auth_token", "value": "OTHER_TOKEN"}],
    }]})
    overlay = _export_overlay(tmp_path, {
        "first": {"fields": {"browser_state": _cached(first_state)},
                  "flow": {"login": "LEARNED_FLOW"}, "learning": {"private": "LEARNING_DATA"},
                  "health": {"last_reason": "HEALTH_DATA"}},
        "second": {"fields": {"browser_state": _cached("SECOND_STATE"), "access_token": _cached("SECOND_TOKEN")}},
        "disabled": {"fields": {"browser_state": _cached("DISABLED_CACHE")}},
        "orphan": {"fields": {"browser_state": _cached("ORPHAN_CACHE")}},
    })
    before = document.to_payload()
    cache_bytes, cache_mtime = overlay.path.read_bytes(), overlay.path.stat().st_mtime_ns
    plain = secrets.build_secret_payload(document)
    assert plain["accounts"][0]["credentials"] == {"cookie": "CONFIG_COOKIE"}
    assert "credentials" not in plain["accounts"][1]
    text = secrets.dumps(document, overlay=overlay)
    payload = json.loads(text)
    first, second = payload["accounts"]
    assert first["credentials"] == {"cookie": "CONFIG_COOKIE", "browser_state": first_state}
    assert second["credentials"] == {"browser_state": "SECOND_STATE", "access_token": "SECOND_TOKEN"}
    assert payload["oauth_states"] == plain["oauth_states"]
    assert all(value not in text for value in (
        "DISABLED_CACHE", "ORPHAN_CACHE", "LEARNED_FLOW", "LEARNING_DATA", "HEALTH_DATA", "UNUSED_SHARED_STATE",
    ))
    assert len(text.splitlines()) == 1
    assert document.to_payload() == before
    assert overlay.path.read_bytes() == cache_bytes and overlay.path.stat().st_mtime_ns == cache_mtime


@pytest.mark.parametrize(("configured", "basis", "age_hours", "policy", "expected"), [
    ("CONFIG", "CONFIG", 1, CachePolicy.COMPATIBLE, "CACHED"),
    ("NEW_CONFIG", "OLD_CONFIG", 1, CachePolicy.COMPATIBLE, "NEW_CONFIG"),
    ("", "OLD_CONFIG", 1, CachePolicy.COMPATIBLE, ""),
    ("CONFIG", "CONFIG", 48, CachePolicy.COMPATIBLE, "CONFIG"),
    ("CONFIG", "CONFIG", -1, CachePolicy.COMPATIBLE, "CONFIG"),
    ("CONFIG", "CONFIG", 1, CachePolicy.IGNORE, "CONFIG"),
    ("CONFIG", "CONFIG", 1, CachePolicy.READONLY, "CACHED"),
])
def test_secret_export_overlay_respects_existing_priority_and_ttl(tmp_path, configured, basis, age_hours, policy, expected):
    document = schema.parse_document({"accounts": [{
        "id": "site", "base_url": "https://site.invalid", "credentials": {"browser_state": configured},
    }]})
    overlay = _export_overlay(tmp_path, {"site": {"fields": {
        "browser_state": _cached("CACHED", configured=basis, age_hours=age_hours),
    }}}, policy=policy)
    before = overlay.path.read_bytes()
    payload = secrets.build_secret_payload(document, overlay=overlay)
    assert payload["accounts"][0].get("credentials", {}).get("browser_state", "") == expected
    assert overlay.path.read_bytes() == before


@pytest.mark.parametrize(("configured", "expected"), [("CONFIG", "CONFIG"), ("", "CACHED")])
def test_secret_export_legacy_overlay_keeps_original_timestamps(tmp_path, configured, expected):
    document = schema.parse_document({"accounts": [{
        "id": "site", "base_url": "https://site.invalid", "credentials": {"browser_state": configured},
    }]})
    field = {**_cached("CACHED"), "config_hash": ""}
    overlay = _export_overlay(tmp_path, {"site": {"fields": {"browser_state": field}}})
    before = overlay.path.read_bytes()
    payload = secrets.build_secret_payload(document, overlay=overlay)
    assert payload["accounts"][0]["credentials"]["browser_state"] == expected
    assert overlay.entry("site").fields["browser_state"].updated_at == field["updated_at"]
    assert overlay.path.read_bytes() == before


@pytest.mark.parametrize("configured", ["", "NEW_CONFIG"])
def test_secret_export_overlay_respects_explicit_fields_including_empty(tmp_path, configured):
    document = schema.parse_document({"accounts": [{
        "id": "site", "base_url": "https://site.invalid", "credentials": {"browser_state": configured},
    }]})
    overlay = _export_overlay(tmp_path, {"site": {"fields": {
        "browser_state": _cached("CACHED", configured=configured),
    }}})
    text = secrets.dumps(document, overlay=overlay, explicit=("browser_state",))
    assert json.loads(text)["accounts"][0].get("credentials", {}).get("browser_state", "") == configured


def test_secret_export_overlay_does_not_expand_cookie_file(tmp_path):
    creds = tmp_path / "creds.txt"
    creds.write_text("FILE_COOKIE\n42\nFILE_TOKEN\n", encoding="utf-8")
    document = schema.parse_document({"accounts": [{
        "id": "site", "base_url": "https://site.invalid", "credentials": {"cookie_file": str(creds)},
    }]})
    overlay = _export_overlay(tmp_path, {"site": {"fields": {
        "browser_state": _cached("CACHED_STATE"),
        "cookie": _cached("CACHED_COOKIE", configured="FILE_COOKIE"),
        "access_token": _cached("CACHED_TOKEN", configured="FILE_TOKEN"),
    }}})
    payload = secrets.build_secret_payload(document, overlay=overlay)
    assert payload["accounts"][0]["credentials"] == {"cookie_file": str(creds), "browser_state": "CACHED_STATE"}


def test_secret_size_limit_counts_utf8_bytes_and_mentions_browser_state():
    assert secrets.check_size("x" * secrets.SECRET_SIZE_LIMIT) == ""
    warning = secrets.check_size("中" * (secrets.SECRET_SIZE_LIMIT // 3 + 1))
    assert "64 KiB" in warning and "browser_state" in warning and "多个 Secret" in warning


def test_cli_secret_export_requires_explicit_overlay_opt_in(tmp_path, monkeypatch, capsys):
    from apps import cli
    from config import paths

    monkeypatch.delenv("CHECKIN_CACHE_POLICY", raising=False)
    config = tmp_path / "ACCOUNTS.json"
    config.write_text(json.dumps({"version": 3, "accounts": [{
        "id": "site", "base_url": "https://site.invalid", "login": {"method": "browser_state"},
        "credentials": {"browser_state": "CONFIG_STATE"},
    }]}), encoding="utf-8")
    spec = store.load(config).accounts[0]
    overlay = Overlay(path=paths.OVERLAY_PATH, accounts_path=config).load()
    assert overlay.record_credentials(spec, browser_state="CACHED_STATE")
    before_config, before_cache = config.read_bytes(), overlay.path.read_bytes()

    def no_execution(*args, **kwargs):
        pytest.fail("Secret export must not log in or run tasks")

    monkeypatch.setattr(cli, "run_account_sync", no_execution)
    for extra, expected in (([], "CONFIG_STATE"), (["--include-overlay"], "CACHED_STATE")):
        assert cli.main(["--config", str(config), "--export-secret", *extra]) == cli.EXIT_OK
        captured = capsys.readouterr()
        assert captured.err == ""
        assert len(captured.out.splitlines()) == 1
        assert json.loads(captured.out)["accounts"][0]["credentials"]["browser_state"] == expected
    assert config.read_bytes() == before_config and overlay.path.read_bytes() == before_cache


def test_cli_secret_export_account_json_keeps_explicit_clear(tmp_path, monkeypatch, capsys):
    import io

    from apps import cli
    from config import paths

    monkeypatch.delenv("CHECKIN_CACHE_POLICY", raising=False)
    account = {"id": "site", "base_url": "https://site.invalid", "credentials": {"browser_state": ""}}
    overlay = Overlay(path=paths.OVERLAY_PATH).load()
    assert overlay.record_credentials(schema.parse_account(account), browser_state="CACHED_STATE")
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(json.dumps(account)))
    assert cli.main(["--account-json", "-", "--export-secret", "--include-overlay"]) == cli.EXIT_OK
    captured = capsys.readouterr()
    assert "browser_state" not in json.loads(captured.out)["accounts"][0].get("credentials", {})
    assert "CACHED_STATE" not in captured.out + captured.err


def test_cli_include_overlay_is_only_valid_for_secret_export(capsys):
    from apps import cli

    with pytest.raises(SystemExit) as caught:
        cli.parse_args(["--include-overlay"])
    assert caught.value.code == 2
    assert "--export-secret" in capsys.readouterr().err


def test_cli_oversized_secret_reports_actionable_warning_without_losing_state(tmp_path, capsys):
    from apps import cli

    state = "STATE" * secrets.SECRET_SIZE_LIMIT
    config = tmp_path / "ACCOUNTS.json"
    config.write_text(json.dumps({"version": 3, "accounts": [{
        "id": "site", "base_url": "https://site.invalid", "credentials": {"browser_state": state},
    }]}), encoding="utf-8")
    assert cli.main(["--config", str(config), "--export-secret"]) == cli.EXIT_OK
    captured = capsys.readouterr()
    assert "64 KiB" in captured.err and "browser_state" in captured.err and "多个 Secret" in captured.err
    assert state not in captured.err
    assert json.loads(captured.out)["accounts"][0]["credentials"]["browser_state"] == state
