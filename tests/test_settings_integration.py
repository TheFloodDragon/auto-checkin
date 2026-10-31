"""settings 与账号、GUI、CI 的离线集成回归。"""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from config import paths, settings, store
from core.errors import ConfigError
from gui import config_store


def _group(group_id: str = "office") -> dict:
    return {
        "id": group_id,
        "name": "办公节点",
        "enabled": True,
        "selected": "node",
        "proxies": [
            {
                "id": "node",
                "name": "本地出口",
                "enabled": True,
                "url": "http://user:NODE_SECRET@proxy.invalid:8080",
                "extension": {"keep": [1, 2]},
            }
        ],
        "subscription": {
            "id": "source",
            "url": "https://subscription.invalid/SUBSCRIPTION_SECRET",
            "format": "clash",
            "updated_at": "2026-01-01T00:00:00Z",
            "extension": {"keep": True},
        },
    }


def _accounts(*, proxy_group: str = "") -> dict:
    account = {
        "id": "site",
        "base_url": "https://site.invalid",
        "tasks": [{"id": "daily"}],
        "credentials": {"cookie": "session=ACCOUNT_SECRET"},
    }
    if proxy_group:
        account["network"] = {"proxy_mode": "group", "proxy_group": proxy_group}
    return {"version": 3, "accounts": [account], "oauth_states": {}, "extension": {"keep": True}}


def _write_accounts(payload: dict, path: Path | None = None) -> Path:
    target = path or paths.ACCOUNTS_PATH
    target.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return target


def _saved_settings() -> dict:
    return yaml.safe_load(settings.settings_path().read_text(encoding="utf-8"))


def test_startup_reuses_legacy_nodes_without_rewriting_accounts():
    payload = _accounts(proxy_group="office")
    payload.update(proxy_groups=[_group()], default_proxy_group="office")
    target = _write_accounts(payload)
    original = target.read_bytes()

    document = store.load()

    assert target.read_bytes() == original
    assert document.proxy_groups[0].id == "office"
    assert _saved_settings()["proxy_groups"] == payload["proxy_groups"]
    assert _saved_settings()["default_proxy_group"] == "office"
    assert "HTTP_REQUEST" in _saved_settings()
    template = paths.SETTINGS_DEFAULT_PATH.read_text(encoding="utf-8")
    assert "SECRET" not in template
    assert "ACCOUNTS" not in template


def test_runtime_load_merges_settings_before_validating_group_references():
    settings.save({"proxy_groups": [_group()], "default_proxy_group": "office"})
    target = _write_accounts(_accounts(proxy_group="office"))
    original = target.read_bytes()

    document = store.load()

    assert document.proxy_groups[0].to_payload() == _group()
    assert document.default_proxy_group == "office"
    assert target.read_bytes() == original


def test_existing_local_nodes_are_not_replaced_by_default_or_preset(monkeypatch):
    monkeypatch.setenv("SETTINGS", json.dumps({"proxy_groups": [_group("preset")], "default_proxy_group": "preset"}))
    payload = _accounts(proxy_group="office")
    payload.update(proxy_groups=[_group()], default_proxy_group="office")
    _write_accounts(payload)

    assert store.load().proxy_groups[0].id == "office"
    assert _saved_settings()["proxy_groups"] == [_group()]
    # 后续启动仍以旧账号文件的显式节点为准，直到工作台显式转存。
    settings.save({"proxy_groups": [_group("other")], "default_proxy_group": "other"})
    assert store.load().proxy_groups[0].id == "office"
    assert _saved_settings()["proxy_groups"] == [_group("other")]


def test_explicit_empty_legacy_nodes_do_not_inherit_settings():
    settings.save({"proxy_groups": [_group()], "default_proxy_group": "office"})
    payload = _accounts()
    payload.update(proxy_groups=[], default_proxy_group="")
    _write_accounts(payload)

    document = store.load()

    assert document.proxy_groups == ()
    assert document.default_proxy_group == ""


def test_custom_account_file_keeps_self_contained_node_scope(tmp_path):
    settings.save({"proxy_groups": [_group()], "default_proxy_group": "office"})
    target = _write_accounts(_accounts(), tmp_path / "other.json")

    document = store.load(target)

    assert document.proxy_groups == ()
    assert document.default_proxy_group == ""
    payload = _accounts(proxy_group="office")
    _write_accounts(payload, target)
    with pytest.raises(ConfigError):
        store.load(target)


def test_gui_load_and_save_transfer_nodes_to_settings_without_losing_metadata():
    payload = _accounts(proxy_group="office")
    payload.update(proxy_groups=[_group()], default_proxy_group="office")
    target = _write_accounts(payload)
    loaded = config_store.load_configuration()
    values = settings.load()
    values["HTTP_REQUEST"] = 77
    settings.save(values)
    loaded = config_store.load_configuration()
    draft = deepcopy(loaded.payload)
    draft["accounts"][0]["name"] = "已编辑"
    draft["proxy_groups"][0]["proxies"][0]["extension"]["keep"].append(3)
    request = config_store.build_save_request(
        draft, expected_revision=loaded.revision, expected_settings_revision=loaded.settings_revision
    )
    draft["proxy_groups"].clear()

    saved = request.persist()

    assert saved.payload == request.payload
    raw = json.loads(target.read_text(encoding="utf-8"))
    assert "proxy_groups" not in raw and "default_proxy_group" not in raw
    assert raw["accounts"][0]["credentials"] == payload["accounts"][0]["credentials"]
    values = _saved_settings()
    assert values["HTTP_REQUEST"] == 77
    assert values["proxy_groups"] == request.payload["proxy_groups"]
    assert values["default_proxy_group"] == "office"
    assert "ACCOUNT_SECRET" not in settings.settings_path().read_text(encoding="utf-8")
    assert config_store.load_configuration().payload == saved.payload
    assert store.load().proxy_groups[0].id == "office"
    assert yaml.safe_load(paths.SETTINGS_DEFAULT_PATH.read_text(encoding="utf-8"))["HTTP_REQUEST"] == 30


@pytest.mark.parametrize("change", ["nodes", "whitespace", "delete"])
def test_gui_detects_external_settings_revision_changes(change):
    settings.save({"proxy_groups": [_group()], "default_proxy_group": "office"})
    target = _write_accounts(_accounts(proxy_group="office"))
    original = target.read_bytes()
    loaded = config_store.load_configuration()
    request = config_store.build_save_request(
        loaded.payload, expected_revision=loaded.revision, expected_settings_revision=loaded.settings_revision
    )
    settings_target = settings.settings_path()
    if change == "delete":
        settings_target.unlink()
        expected = None
    elif change == "whitespace":
        expected = settings_target.read_bytes() + b"\n"
        settings_target.write_bytes(expected)
    else:
        settings.save({"proxy_groups": [_group("external")], "default_proxy_group": "external"})
        expected = settings_target.read_bytes()

    with pytest.raises(ConfigError, match="外部修改"):
        request.persist()

    assert target.read_bytes() == original
    assert (settings_target.read_bytes() if settings_target.exists() else None) == expected


def test_failed_account_write_rolls_back_settings_bytes(monkeypatch):
    settings.save({"proxy_groups": [_group()], "default_proxy_group": "office"})
    target = _write_accounts(_accounts(proxy_group="office"))
    loaded = config_store.load_configuration()
    settings_target = settings.settings_path()
    # 使用 LF 与额外空白验证回滚恢复原始字节，而不是重新序列化旧数据。
    previous = settings_target.read_bytes().replace(b"\r\n", b"\n") + b"\n"
    settings_target.write_bytes(previous)
    loaded = config_store.load_configuration()
    original_accounts = target.read_bytes()
    draft = deepcopy(loaded.payload)
    draft["proxy_groups"][0]["name"] = "保存失败的草稿"
    request = config_store.build_save_request(
        draft, expected_revision=loaded.revision, expected_settings_revision=loaded.settings_revision
    )
    atomic_write = paths.atomic_write_text

    def fail_accounts(path, text):
        if Path(path).resolve() == target.resolve():
            raise OSError("simulated account disk failure")
        atomic_write(path, text)

    monkeypatch.setattr(paths, "atomic_write_text", fail_accounts)
    with pytest.raises(ConfigError, match="原子保存失败"):
        request.persist()

    assert target.read_bytes() == original_accounts
    assert settings_target.read_bytes() == previous
    assert request.payload == draft


def test_generic_store_save_keeps_legacy_format_and_also_saves_nodes():
    payload = _accounts(proxy_group="office")
    payload.update(proxy_groups=[_group()], default_proxy_group="office")

    store.save_payload(payload)

    assert json.loads(paths.ACCOUNTS_PATH.read_text(encoding="utf-8")) == payload
    assert _saved_settings()["proxy_groups"] == payload["proxy_groups"]
    assert _saved_settings()["default_proxy_group"] == "office"


def test_gui_can_explicitly_clear_nodes_and_default_group():
    settings.save({"proxy_groups": [_group()], "default_proxy_group": "office"})
    _write_accounts(_accounts())
    loaded = config_store.load_configuration()
    draft = deepcopy(loaded.payload)
    draft.update(proxy_groups=[], default_proxy_group="")

    saved = config_store.build_save_request(
        draft, expected_revision=loaded.revision, expected_settings_revision=loaded.settings_revision
    ).persist()

    assert saved.payload == draft
    assert _saved_settings()["proxy_groups"] == []
    assert _saved_settings()["default_proxy_group"] == ""
    assert store.load().proxy_groups == ()


def test_startup_creates_defaults_even_when_accounts_are_missing():
    with pytest.raises(ConfigError, match="未找到配置文件"):
        store.load()

    assert paths.SETTINGS_PATH.exists()
    assert paths.SETTINGS_DEFAULT_PATH.exists()
    assert not paths.ACCOUNTS_PATH.exists()


def test_gui_onboarding_uses_existing_settings_nodes():
    settings.save({"proxy_groups": [_group()], "default_proxy_group": "office"})

    loaded = config_store.load_configuration()

    assert loaded.needs_save
    assert loaded.payload["accounts"] == []
    assert loaded.payload["proxy_groups"] == [_group()]
    assert loaded.revision is None
    assert loaded.settings_revision is not None
    assert not paths.ACCOUNTS_PATH.exists()


def test_ci_domain_split_can_read_nodes_from_settings():
    from ci.proxy_config import _split_outbound_from_accounts

    group = _group()
    group["proxies"] = [
        {
            "id": "node",
            "name": "分流出口",
            "enabled": True,
            "clash": {"type": "vless", "server": "edge.invalid", "port": 443, "uuid": "NODE_SECRET"},
        }
    ]
    settings.save({"proxy_groups": [group], "default_proxy_group": "office"})
    target = _write_accounts(_accounts())

    outbound = _split_outbound_from_accounts(target, "office")

    assert outbound["server"] == "edge.invalid"
    assert outbound["name"] == "分流出口"


def test_workflow_reuses_settings_secret_and_detects_bridge_from_effective_config():
    workflow = yaml.safe_load((paths.REPO_ROOT / ".github/workflows/auto_checkin.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["checkin"]
    assert job["env"]["SETTINGS"] == "${{ secrets.SETTINGS }}"
    detection = next(step for step in job["steps"] if step.get("id") == "detect_mihomo")
    assert "uv run python" in detection["run"]
    assert "store.load_settings(" in detection["run"]
    assert "store.load(" not in detection["run"], "桥接检测不能提前迁移账号并遗漏旧缓存重挂"


def test_settings_and_accounts_cannot_share_the_same_path(monkeypatch):
    monkeypatch.setenv("SETTINGS", str(paths.ACCOUNTS_PATH))
    with pytest.raises(ConfigError, match="同一路径"):
        config_store.load_configuration()


def test_standalone_cli_account_json_uses_settings_nodes(monkeypatch):
    from apps import cli

    settings.save({"proxy_groups": [_group()], "default_proxy_group": "office"})
    account = _accounts(proxy_group="office")["accounts"][0]
    monkeypatch.setattr(cli, "_read_account_json", lambda _reference: account)
    monkeypatch.setattr(
        cli,
        "_explain",
        lambda spec, overlay, *, document: {
            "group": document.proxy_groups[0].id,
            "default": document.default_proxy_group,
        },
    )

    payload, code = cli._dispatch(cli.parse_args(["--account-json", "-", "--explain"]))

    assert code == cli.EXIT_OK
    assert payload == {"group": "office", "default": "office"}
    assert not paths.ACCOUNTS_PATH.exists()


def test_gui_rejects_settings_change_between_load_and_save_request_creation():
    settings.save({"proxy_groups": [_group()], "default_proxy_group": "office"})
    target = _write_accounts(_accounts(proxy_group="office"))
    loaded = config_store.load_configuration()
    original = target.read_bytes()
    settings.save({"proxy_groups": [_group("external")], "default_proxy_group": "external"})
    changed = settings.settings_path().read_bytes()
    request = config_store.build_save_request(
        loaded.payload,
        expected_revision=loaded.revision,
        expected_settings_revision=loaded.settings_revision,
    )

    with pytest.raises(ConfigError, match="外部修改"):
        request.persist()

    assert target.read_bytes() == original
    assert settings.settings_path().read_bytes() == changed


def test_gui_load_does_not_bind_old_nodes_to_new_settings_revision(monkeypatch):
    settings.save({"proxy_groups": [_group()], "default_proxy_group": "office"})
    target = _write_accounts(_accounts(proxy_group="office"))
    original = target.read_bytes()
    read_bytes = config_store._read_bytes
    changed = False

    def external_edit_after_snapshot(path):
        nonlocal changed
        content = read_bytes(path)
        if Path(path) == settings.settings_path() and not changed:
            changed = True
            group = _group()
            group["name"] = "外部刚修改的节点"
            settings.save({"proxy_groups": [group], "default_proxy_group": "office"})
        return content

    monkeypatch.setattr(config_store, "_read_bytes", external_edit_after_snapshot)
    with pytest.raises(ConfigError, match="外部修改"):
        config_store.load_configuration()

    assert target.read_bytes() == original
    assert _saved_settings()["proxy_groups"][0]["name"] == "外部刚修改的节点"


def test_typed_store_roundtrip_preserves_explicit_empty_nodes():
    settings.save({"proxy_groups": [_group()], "default_proxy_group": "office"})
    payload = _accounts()
    payload.update(proxy_groups=[], default_proxy_group="")
    target = _write_accounts(payload)
    document = store.load()

    store.save(document)

    saved = json.loads(target.read_text(encoding="utf-8"))
    assert saved["proxy_groups"] == []
    assert saved["default_proxy_group"] == ""
    assert store.load().proxy_groups == ()
    assert store.load().default_proxy_group == ""


def test_ci_bridge_detection_leaves_legacy_account_and_cache_migration_for_execution(capsys):
    from types import SimpleNamespace

    raw = {
        "version": 2,
        "accounts": [
            {
                "name": "old",
                "base_url": "https://old.invalid",
                "site_profile": "sub2api",
                "auth_method": "browser",
                "checkin_action": "browser_script",
                "script": "scripts/checkin/custom.py",
                "refresh_token": "OLD_ACCOUNT_SECRET",
            }
        ],
    }
    target = _write_accounts(raw)
    original = target.read_bytes()
    workflow = yaml.safe_load((paths.REPO_ROOT / ".github/workflows/auto_checkin.yml").read_text(encoding="utf-8"))
    detection = next(step for step in workflow["jobs"]["checkin"]["steps"] if step.get("id") == "detect_mihomo")
    script = detection["run"].split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]

    exec(compile(script, "CI bridge detection", "exec"), {"__name__": "bridge_detection_test"})

    assert capsys.readouterr().out.strip() == "false"
    assert target.read_bytes() == original
    moved = []
    overlay = SimpleNamespace(migrate_keys=lambda keys: moved.append(dict(keys)) or len(keys))
    document = store.load(overlay=overlay)
    assert document.version == 3
    assert moved, "执行入口仍必须能迁移旧覆盖层凭据缓存键"


def test_stdlib_ci_report_works_with_broken_settings_file_and_preset(tmp_path):
    broken = tmp_path / "broken-settings.yml"
    broken.write_text("proxy_groups: [PRIVATE_NODE_SECRET", encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(paths.REPO_ROOT), "SETTINGS": str(broken)}

    completed = subprocess.run(
        [sys.executable, "-B", "-S", "-m", "ci.report", "--result-fresh", "false", "--exit-code", "3"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )

    assert completed.returncode == 1
    report = (tmp_path / "checkin_report.md").read_text(encoding="utf-8")
    assert "签到脚本退出码" in report
    assert "SECRET" not in report + completed.stderr
