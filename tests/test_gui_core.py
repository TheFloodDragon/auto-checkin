"""原始 v3 JSON 校验、导入与原子保存回归测试；不使用 Qt 或真实账号。"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import FrozenInstanceError

import pytest

from config import paths, schema, store
from core.errors import ConfigError
from core.manifest import STAGES
from gui import config_store, core


@pytest.fixture
def payload():
    return {
        "version": 3,
        "extension": {"nested": [False, None, {"text": "保留"}]},
        "accounts": [{
            "id": "stable", "name": "原名", "base_url": "https://example.invalid/", "enabled": True,
            "template": "auto", "custom_account": {"items": [1, 2]},
            "login": {
                "method": "oauth", "provider": "github", "args": {"password": "LOGIN_SECRET", "nested": [1]},
                "extension": {"order": [1, 2]},
                "fallback": [{"method": "custom-login", "args": {"x": [3]}, "extension": True,
                              "fallback": [{"method": "password", "args": {"password": "FALLBACK_SECRET"}}]}],
            },
            "tasks": [
                {"id": "first", "method": "visit", "args": {"nested": [{"x": 1}]}, "unknown": [1]},
                {"id": "second", "depends_on": ["first"], "method": "custom-task", "timeout": 51,
                 "template": "scripts/tasks/example.py", "args": {"password": "TASK_SECRET", "items": [1, 2]},
                 "policy": {"retry": 0, "extension": {"on": True}}, "flow": {"execute": ["unknown", "off"]},
                 "extension": {"keep": "second task"}},
            ],
            "flow": {stage: ["extension-method", "auto"] for stage in STAGES},
            "credentials": {"access_token": "TOKEN_SECRET", "cookie": "", "extension": {"fields": [1]}},
            "network": {"proxy": "socks5://localhost:1080", "verify_ssl": False, "extension": {"headers": [1]}},
            "policy": {"retry": 4, "allow_browser": False, "headless": None, "extension": [1, None]},
            "display": {"text_label": "保留", "extension": {"options": [1]}},
        }],
        "oauth_states": {"github": {
            "extension": {"key": [1, 2]},
            "accounts": {"default": {"state": "OAUTH_SECRET", "username": "user", "updated_at": "today",
                                      "metadata": {"issued": [1, 2]}}},
        }},
    }


def test_validate_keeps_every_layer_and_schema_does_not_alias_payload(payload):
    before = copy.deepcopy(payload)
    document = core.validate_payload(payload)
    assert isinstance(document, schema.Document)
    document.accounts[0].login.args["nested"].append(2)
    document.accounts[0].tasks[0].args["nested"][0]["x"] = 999
    assert payload == before
    assert document.accounts[0].task_policy(document.accounts[0].tasks[1]).allow_browser is True
    assert document.accounts[0].policy.allow_browser is False


def test_fingerprint_is_canonical_sha256_not_secret_json(payload):
    digest = core.fingerprint(payload)
    assert digest == hashlib.sha256(json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    assert core.fingerprint(dict(reversed(list(payload.items())))) == digest
    assert len(digest) == 64 and "SECRET" not in digest
    payload["accounts"][0]["tasks"][1]["extension"]["keep"] = "changed"
    assert core.fingerprint(payload) != digest


@pytest.mark.parametrize(("section", "value", "field"), [
    ("enabled", "false", "enabled"), ("enabled", 1, "enabled"),
    ("login", [], "login"), ("login", {"args": []}, "args"),
    ("login", {"fallback": {}}, "fallback"), ("login", {"fallback": [None]}, "fallback"),
    ("login", {"fallback": [{"args": []}]}, "args"),
    ("credentials", [], "credentials"), ("credentials", {"access_token": []}, "access_token"),
    ("credentials", {"cookie_file": {}}, "cookie_file"),
    ("network", [], "network"), ("network", {"verify_ssl": "false"}, "verify_ssl"),
    ("network", {"proxy": []}, "proxy"),
    ("policy", [], "policy"), ("policy", {"retry": True}, "retry"),
    ("policy", {"retry": 11}, "retry"), ("policy", {"retry": 1.5}, "retry"),
    ("policy", {"allow_browser": "false"}, "allow_browser"),
    ("policy", {"headless": 1}, "headless"), ("policy", {"humanize": []}, "humanize"),
    ("display", [], "display"), ("flow", [], "flow"),
    ("flow", {"execute": [False]}, "execute"), ("flow", {"execute": {}}, "execute"),
    ("flow", {"eighth-stage": "auto"}, "flow"),
    ("tasks", [], "tasks"), ("tasks", {}, "tasks"), ("tasks", [None], "tasks"),
    ("tasks", [{"id": "x", "args": []}], "args"),
    ("tasks", [{"id": "x", "depends_on": "x"}], "depends_on"),
    ("tasks", [{"id": "x", "depends_on": [None]}], "depends_on"),
    ("tasks", [{"id": "x", "timeout": True}], "timeout"),
    ("tasks", [{"id": "x", "timeout": "120"}], "timeout"),
    ("tasks", [{"id": "x", "timeout": 0}], "timeout"),
    ("tasks", [{"id": "x", "timeout": 7201}], "timeout"),
    ("tasks", [{"id": "x", "policy": []}], "policy"),
    ("tasks", [{"id": "x", "policy": {"retry": -1}}], "retry"),
    ("tasks", [{"id": "x", "enabled": "false"}], "enabled"),
])
def test_illegal_known_fields_report_safe_paths(payload, section, value, field):
    payload["accounts"][0][section] = value
    with pytest.raises(ConfigError) as caught:
        core.validate_payload(payload)
    assert field in str(caught.value)
    assert "SECRET" not in str(caught.value)


@pytest.mark.parametrize("url", ["ftp://example.invalid", "file:///etc/passwd", "javascript:alert(1)",
                                 "example.invalid", "https://", "https://x.invalid:99999", "https://[broken",
                                 "https://user:URL_SECRET@example.invalid", "https://bad host.invalid"])
def test_url_must_be_http_without_embedded_credentials(payload, url):
    payload["accounts"][0]["base_url"] = url
    with pytest.raises(ConfigError, match="base_url") as caught:
        core.validate_payload(payload)
    assert "SECRET" not in str(caught.value)


@pytest.mark.parametrize("states", [[], None, {"github": []}, {"github": {"accounts": []}},
                                   {"github": {"accounts": {"a": []}}},
                                   {"github": {"accounts": {"a": {"state": {}}}}}])
def test_illegal_oauth_containers_are_not_silently_discarded(payload, states):
    payload["oauth_states"] = states
    with pytest.raises(ConfigError, match="oauth_states"):
        core.validate_payload(payload)


@pytest.mark.parametrize("value", [float("inf"), float("nan"), {1: "value"}, (1, 2), {1, 2}])
def test_unknown_extensions_must_still_be_json(payload, value):
    payload["extension"] = value
    with pytest.raises(ConfigError):
        core.validate_payload(payload)
    with pytest.raises(ConfigError):
        core.fingerprint(payload)


def test_circular_json_rejected(payload):
    payload["cycle"] = payload
    with pytest.raises(ConfigError, match="循环"):
        core.validate_payload(payload)


def test_raw_roundtrip_and_snapshot_freezing(tmp_path, payload):
    path = tmp_path / "accounts.json"
    before = copy.deepcopy(payload)
    request = config_store.build_save_request(payload, path=path, expected_revision=None)
    assert not hasattr(request, "__dict__")
    assert "SECRET" not in repr(request)
    assert "SECRET" not in repr(config_store.LoadedConfiguration(payload, path, None))
    with pytest.raises(FrozenInstanceError):
        request.snapshot = "changed"
    payload["accounts"][0]["tasks"][1]["args"]["items"].append(99)
    request.payload["accounts"][0]["login"]["args"]["nested"].append(99)
    saved = request.persist()
    assert saved.payload == before
    assert saved.revision == hashlib.sha256(path.read_bytes()).hexdigest()
    assert json.loads(path.read_text(encoding="utf-8")) == before
    assert config_store.load_configuration(path).payload == before
    saved.payload["accounts"].clear()
    assert request.payload == before


def test_public_store_save_payload_retains_unknown_layers(tmp_path, payload):
    path = tmp_path / "accounts.json"
    assert store.save_payload(payload, path) == path
    assert json.loads(path.read_text(encoding="utf-8")) == payload
    with pytest.raises(ConfigError):
        store.save_payload({"accounts": [False]}, path)
    assert json.loads(path.read_text(encoding="utf-8")) == payload


def test_cookie_file_never_expands_into_persisted_payload(tmp_path, payload):
    cookies = tmp_path / "cookies.txt"
    cookies.write_text("COOKIE_FILE_SECRET\n42\nFILE_TOKEN_SECRET\n", encoding="utf-8")
    payload["accounts"][0]["credentials"] = {"cookie_file": str(cookies), "extension": {"keep": True}}
    path = tmp_path / "accounts.json"
    saved = config_store.build_save_request(payload, path=path, expected_revision=None).persist()
    assert saved.payload == payload
    assert "FILE_SECRET" not in path.read_text(encoding="utf-8")
    assert "FILE_TOKEN_SECRET" not in path.read_text(encoding="utf-8")
    assert core.validate_payload(saved.payload).accounts[0].credentials.cookie == "COOKIE_FILE_SECRET"


@pytest.mark.parametrize("location", ["credentials", "account"])
def test_relative_cookie_file_follows_config_path_without_rewriting_reference(tmp_path, payload, location):
    (tmp_path / "cookie.txt").write_text("RELATIVE_COOKIE_SECRET\n42\nRELATIVE_TOKEN_SECRET\n", encoding="utf-8")
    path = tmp_path / "accounts.json"
    account = payload["accounts"][0]
    account["credentials"] = {}
    section = account["credentials"] if location == "credentials" else account
    section["cookie_file"] = "cookie.txt"
    original = copy.deepcopy(payload)
    validated = core.validate_payload(payload, path=path)
    assert validated.accounts[0].credentials.cookie == "RELATIVE_COOKIE_SECRET"
    assert core.selected_task_ids(account, ("second",), path=path) == ("first", "second")
    saved = config_store.build_save_request(payload, path=path, expected_revision=None).persist()
    assert saved.payload == original
    assert config_store.load_configuration(path).payload == original
    assert "RELATIVE_COOKIE_SECRET" not in path.read_text(encoding="utf-8")
    extra = {"id": "another", "base_url": "https://another.invalid", "credentials": {"cookie_file": "cookie.txt"}}
    imported = core.import_accounts(payload, json.dumps(extra), path=path)
    assert imported["accounts"][1]["credentials"]["cookie_file"] == "cookie.txt"
    assert payload == original


def test_atomic_replace_failure_preserves_file_and_cleans_temporary_file(tmp_path, payload, monkeypatch):
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    before = path.read_bytes()
    loaded = config_store.load_configuration(path)
    payload["accounts"][0]["name"] = "edited"
    request = config_store.build_save_request(payload, path=path, expected_revision=loaded.revision)

    def fail_replace(*args):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(paths.os, "replace", fail_replace)
    with pytest.raises(ConfigError, match="原子保存失败"):
        request.persist()
    assert path.read_bytes() == before
    assert list(tmp_path.glob(".accounts.json.*.tmp")) == []


@pytest.mark.parametrize("change", ["content", "whitespace", "delete"])
def test_external_revision_conflicts_never_overwrite(tmp_path, payload, change):
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = config_store.load_configuration(path)
    request = config_store.build_save_request(payload, path=path, expected_revision=loaded.revision)
    if change == "delete":
        path.unlink()
        expected = None
    else:
        expected = b"{}" if change == "content" else path.read_bytes() + b"\n"
        path.write_bytes(expected)
    with pytest.raises(ConfigError, match="外部修改"):
        request.persist()
    assert (path.read_bytes() if path.exists() else None) == expected


def test_missing_onboarding_then_external_creation_conflicts(tmp_path):
    path = tmp_path / "accounts.json"
    loaded = config_store.load_configuration(path)
    assert loaded.payload["accounts"] == [] and loaded.revision is None
    assert not path.exists()
    request = config_store.build_save_request(loaded.payload, path=path, expected_revision=None)
    path.write_bytes(b"external file")
    with pytest.raises(ConfigError, match="外部修改"):
        request.persist()
    assert path.read_bytes() == b"external file"


def test_revision_is_original_disk_bytes_not_normalized_json(tmp_path):
    path = tmp_path / "accounts.json"
    content = b'\xef\xbb\xbf{ "version": 3, "accounts": [] }\r\n'
    path.write_bytes(content)
    loaded = config_store.load_configuration(path)
    assert loaded.revision == hashlib.sha256(content).hexdigest()
    assert path.read_bytes() == content


@pytest.mark.parametrize("content", [b"", b"broken TOKEN_SECRET", b"\xff", b"{}", b"[]x",
                                     b'{"accounts": [] ,"accounts": [null]}',
                                     b'{"accounts": [null]}', b'{"accounts": {}, "version": 2}',
                                     b'{"version": 3, "accounts": [], "number": NaN}'])
def test_loading_bad_config_never_becomes_empty_or_overwrites(tmp_path, content):
    path = tmp_path / "accounts.json"
    path.write_bytes(content)
    before = config_store.LoadedConfiguration({"version": 3, "accounts": []}, path, "old")
    with pytest.raises(ConfigError) as caught:
        config_store.load_configuration(path)
    assert "SECRET" not in str(caught.value)
    assert path.read_bytes() == content
    assert before.revision == "old"
    assert list(tmp_path.glob("*.bak-*")) == []


def test_migration_validates_then_backs_up_and_preserves_extensions(tmp_path):
    path = tmp_path / "accounts.json"
    raw = {"version": 2, "note": {"keep": [1]}, "accounts": [{
        "name": "old", "base_url": "https://old.invalid", "site_profile": "sub2api",
        "auth_method": "browser", "checkin_action": "browser_script", "script": "scripts/checkin/custom.py",
        "custom": {"keep": [1, 2]}, "refresh_token": "OLD_SECRET",
    }]}
    original = json.dumps(raw).encode()
    path.write_bytes(original)
    loaded = config_store.load_configuration(path)
    assert loaded.notes and loaded.payload["version"] == 3
    assert loaded.payload["accounts"][0]["login"]["method"] == "browser_state"
    assert loaded.payload["accounts"][0]["tasks"][0]["method"] == "script"
    assert loaded.payload["accounts"][0]["custom"] == {"keep": [1, 2]}
    assert loaded.payload["note"] == {"keep": [1]}
    assert len(list(tmp_path.glob("*.bak-*"))) == 1
    assert next(tmp_path.glob("*.bak-*")).read_bytes() == original
    assert json.loads(path.read_bytes()) == loaded.payload
    assert loaded.revision == hashlib.sha256(path.read_bytes()).hexdigest()


def test_migration_failure_and_backup_failure_do_not_overwrite(tmp_path, monkeypatch):
    path = tmp_path / "accounts.json"
    raw = {"version": 2, "accounts": [{"name": "bad", "site_profile": "newapi"}]}
    path.write_text(json.dumps(raw), encoding="utf-8")
    original = path.read_bytes()
    with pytest.raises(ConfigError):
        config_store.load_configuration(path)
    assert path.read_bytes() == original and not list(tmp_path.glob("*.bak-*"))
    raw["accounts"][0]["base_url"] = "https://valid.invalid"
    path.write_text(json.dumps(raw), encoding="utf-8")
    original = path.read_bytes()
    monkeypatch.setattr(store, "backup", lambda _path: None)
    with pytest.raises(ConfigError, match="备份失败"):
        config_store.load_configuration(path)
    assert path.read_bytes() == original


def test_save_does_not_touch_runtime_overlay(tmp_path, payload, monkeypatch):
    from config.overlay import Overlay

    def forbidden(*args, **kwargs):
        raise AssertionError("配置保存不能清空或修改覆盖层")

    monkeypatch.setattr(Overlay, "load", forbidden)
    monkeypatch.setattr(Overlay, "_update", forbidden)
    monkeypatch.setattr(Overlay, "migrate_keys", forbidden)
    config_store.build_save_request(payload, path=tmp_path / "accounts.json", expected_revision=None).persist()


def test_schema_errors_do_not_echo_cookie_file_or_account_secrets(payload):
    payload["accounts"][0]["name"] = "NAME_SECRET"
    payload["accounts"][0]["credentials"]["cookie_file"] = "UNREADABLE_SECRET/never-exists.txt"
    with pytest.raises(ConfigError) as caught:
        core.validate_payload(payload)
    assert "SECRET" not in str(caught.value)
    assert caught.value.__cause__ is None
