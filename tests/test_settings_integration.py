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


def _legacy_settings(groups: list | None = None, default: str = "office", **values) -> Path:
    """模拟旧版本把节点转存进 settings.yml（当前 settings.save 已拒绝节点字段）。"""
    settings.load()
    target = settings.settings_path()
    payload = {**_saved_settings(), **values, "proxy_groups": [_group()] if groups is None else groups,
               "default_proxy_group": default}
    target.write_text(yaml.safe_dump(payload, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return target


def _settings_backups() -> list[Path]:
    return sorted(settings.settings_path().parent.glob(settings.settings_path().name + ".bak-proxies-*"))


def _account_backups() -> list[Path]:
    return sorted(paths.ACCOUNTS_PATH.parent.glob(paths.ACCOUNTS_PATH.name + ".bak-proxies-*"))


def test_nodes_saved_in_accounts_never_reach_settings():
    payload = _accounts(proxy_group="office")
    payload.update(proxy_groups=[_group()], default_proxy_group="office")
    target = _write_accounts(payload)
    original = target.read_bytes()

    document = store.load()

    assert target.read_bytes() == original
    assert document.proxy_groups[0].to_payload() == _group()
    assert document.default_proxy_group == "office"
    saved = _saved_settings()
    assert "HTTP_REQUEST" in saved
    assert "proxy_groups" not in saved and "default_proxy_group" not in saved
    text = settings.settings_path().read_text(encoding="utf-8") + paths.SETTINGS_DEFAULT_PATH.read_text(encoding="utf-8")
    assert "SECRET" not in text and "ACCOUNTS" not in text


def test_legacy_settings_nodes_move_back_into_accounts_with_backups():
    _legacy_settings(HTTP_REQUEST=77)
    target = _write_accounts(_accounts(proxy_group="office"))
    original = target.read_bytes()

    document = store.load()

    assert document.proxy_groups[0].to_payload() == _group()
    assert document.default_proxy_group == "office"
    raw = json.loads(target.read_text(encoding="utf-8"))
    assert raw["proxy_groups"] == [_group()] and raw["default_proxy_group"] == "office"
    assert raw["accounts"] == _accounts(proxy_group="office")["accounts"]
    assert raw["extension"] == {"keep": True}
    assert [backup.read_bytes() for backup in _account_backups()] == [original]
    saved = _saved_settings()
    assert "proxy_groups" not in saved and "default_proxy_group" not in saved
    assert saved["HTTP_REQUEST"] == 77
    assert yaml.safe_load(_settings_backups()[0].read_text(encoding="utf-8"))["proxy_groups"] == [_group()]
    assert any("迁回" in note for note in document.notes)
    # 迁回后只认账号配置：settings 不再参与，再次加载不改写任何文件。
    migrated = target.read_bytes()
    assert store.load().proxy_groups[0].id == "office"
    assert target.read_bytes() == migrated
    assert len(_account_backups()) == 1


def test_existing_account_nodes_win_and_stale_settings_nodes_are_retired():
    _legacy_settings([_group("stale")], "stale")
    payload = _accounts(proxy_group="office")
    payload.update(proxy_groups=[_group()], default_proxy_group="office")
    target = _write_accounts(payload)
    original = target.read_bytes()

    document = store.load()

    assert [group.id for group in document.proxy_groups] == ["office"]
    assert target.read_bytes() == original
    assert "proxy_groups" not in _saved_settings()
    assert yaml.safe_load(_settings_backups()[0].read_text(encoding="utf-8"))["proxy_groups"] == [_group("stale")]


def test_explicit_empty_account_nodes_do_not_inherit_legacy_settings():
    _legacy_settings()
    payload = _accounts()
    payload.update(proxy_groups=[], default_proxy_group="")
    _write_accounts(payload)

    document = store.load()

    assert document.proxy_groups == ()
    assert document.default_proxy_group == ""
    assert "proxy_groups" not in _saved_settings()


def test_preset_nodes_fill_accounts_without_nodes_and_never_touch_local_settings(monkeypatch):
    monkeypatch.setenv("SETTINGS", json.dumps({"proxy_groups": [_group("preset")], "default_proxy_group": "preset"}))
    target = _write_accounts(_accounts(proxy_group="preset"))

    document = store.load()

    assert document.proxy_groups[0].id == "preset"
    assert json.loads(target.read_text(encoding="utf-8"))["proxy_groups"] == [_group("preset")]
    assert "proxy_groups" not in _saved_settings()
    assert not _settings_backups()


@pytest.mark.parametrize("failure", ["backup", "write"])
def test_failed_move_keeps_accounts_and_legacy_settings_nodes(monkeypatch, failure):
    _legacy_settings()
    target = _write_accounts(_accounts(proxy_group="office"))
    original = target.read_bytes()
    if failure == "backup":
        monkeypatch.setattr(store, "backup", lambda *_args, **_kwargs: None)
    else:
        def fail_write(path, _payload):
            raise OSError("simulated account disk failure")
        monkeypatch.setattr(store, "_write", fail_write)

    document = store.load()

    assert document.proxy_groups[0].id == "office", "本次仍按内存合并运行"
    assert target.read_bytes() == original
    assert _saved_settings()["proxy_groups"] == [_group()], "迁回失败时不能删除唯一一份节点"
    assert not _settings_backups()
    assert any("未能写回" in note for note in document.notes)


def test_readonly_load_without_migration_merges_legacy_nodes_in_memory_only():
    _legacy_settings()
    target = _write_accounts(_accounts(proxy_group="office"))
    original = target.read_bytes()

    document = store.load(auto_migrate=False)

    assert document.proxy_groups[0].id == "office"
    assert target.read_bytes() == original
    assert _saved_settings()["proxy_groups"] == [_group()]


def test_invalid_legacy_settings_nodes_fail_without_rewriting_accounts():
    _legacy_settings([{"id": "broken", "name": "组", "proxies": [{"id": "n", "name": "n", "url": "ftp://bad"}]}], "")
    target = _write_accounts(_accounts())
    original = target.read_bytes()

    with pytest.raises(ConfigError, match="旧版"):
        store.load()

    assert target.read_bytes() == original


def test_custom_account_file_keeps_self_contained_node_scope(tmp_path):
    _legacy_settings()
    target = _write_accounts(_accounts(), tmp_path / "other.json")
    original = target.read_bytes()

    document = store.load(target)

    assert document.proxy_groups == ()
    assert document.default_proxy_group == ""
    assert target.read_bytes() == original
    assert _saved_settings()["proxy_groups"] == [_group()], "其他配置文件不能消费默认配置的旧节点"
    payload = _accounts(proxy_group="office")
    _write_accounts(payload, target)
    with pytest.raises(ConfigError):
        store.load(target)


def test_gui_saves_nodes_in_accounts_without_losing_metadata():
    payload = _accounts(proxy_group="office")
    payload.update(proxy_groups=[_group()], default_proxy_group="office")
    target = _write_accounts(payload)
    values = settings.load()
    values["HTTP_REQUEST"] = 77
    settings.save(values)
    loaded = config_store.load_configuration()
    draft = deepcopy(loaded.payload)
    draft["accounts"][0]["name"] = "已编辑"
    draft["proxy_groups"][0]["proxies"][0]["extension"]["keep"].append(3)
    request = config_store.build_save_request(draft, expected_revision=loaded.revision)
    draft["proxy_groups"].clear()

    saved = request.persist()

    assert saved.payload == request.payload
    raw = json.loads(target.read_text(encoding="utf-8"))
    assert raw["proxy_groups"] == request.payload["proxy_groups"]
    assert raw["proxy_groups"][0]["proxies"][0]["extension"]["keep"] == [1, 2, 3]
    assert raw["default_proxy_group"] == "office"
    assert raw["accounts"][0]["credentials"] == payload["accounts"][0]["credentials"]
    values = _saved_settings()
    assert values["HTTP_REQUEST"] == 77
    assert "proxy_groups" not in values and "default_proxy_group" not in values
    assert "SECRET" not in settings.settings_path().read_text(encoding="utf-8")
    assert config_store.load_configuration().payload == saved.payload
    assert store.load().proxy_groups[0].id == "office"
    assert yaml.safe_load(paths.SETTINGS_DEFAULT_PATH.read_text(encoding="utf-8"))["HTTP_REQUEST"] == 30


def test_gui_load_moves_legacy_settings_nodes_back_into_accounts():
    _legacy_settings()
    target = _write_accounts(_accounts(proxy_group="office"))
    original = target.read_bytes()

    loaded = config_store.load_configuration()

    raw = json.loads(target.read_text(encoding="utf-8"))
    assert raw["proxy_groups"] == [_group()] and raw["default_proxy_group"] == "office"
    assert loaded.payload["proxy_groups"] == [_group()]
    assert loaded.revision == config_store._revision(target.read_bytes())
    assert not loaded.needs_save
    assert [backup.read_bytes() for backup in _account_backups()] == [original]
    assert "proxy_groups" not in _saved_settings()
    assert _settings_backups()
    assert any("迁回" in note for note in loaded.notes)
    # 迁回后的草稿可以按新 revision 直接保存。
    draft = deepcopy(loaded.payload)
    draft["proxy_groups"][0]["name"] = "改名"
    config_store.build_save_request(draft, expected_revision=loaded.revision).persist()
    assert json.loads(target.read_text(encoding="utf-8"))["proxy_groups"][0]["name"] == "改名"


def test_gui_node_move_does_not_persist_unsaved_draft_normalization():
    _legacy_settings()
    payload = _accounts(proxy_group="office")
    del payload["accounts"][0]["tasks"]
    target = _write_accounts(payload)

    loaded = config_store.load_configuration()

    raw = json.loads(target.read_text(encoding="utf-8"))
    assert raw["proxy_groups"] == [_group()]
    assert "tasks" not in raw["accounts"][0], "草稿补足的默认任务要等用户显式保存"
    assert loaded.payload["accounts"][0]["tasks"] == [{"id": "daily"}]
    assert loaded.needs_save
    assert "proxy_groups" not in _saved_settings()


def test_gui_detects_external_account_changes_before_saving_nodes():
    payload = _accounts(proxy_group="office")
    payload.update(proxy_groups=[_group()], default_proxy_group="office")
    target = _write_accounts(payload)
    loaded = config_store.load_configuration()
    request = config_store.build_save_request(loaded.payload, expected_revision=loaded.revision)
    external = deepcopy(payload)
    external["proxy_groups"][0]["name"] = "外部修改"
    _write_accounts(external)
    changed = target.read_bytes()

    with pytest.raises(ConfigError, match="外部修改"):
        request.persist()

    assert target.read_bytes() == changed


def test_settings_changes_do_not_conflict_with_gui_account_saves():
    payload = _accounts(proxy_group="office")
    payload.update(proxy_groups=[_group()], default_proxy_group="office")
    target = _write_accounts(payload)
    loaded = config_store.load_configuration()
    values = settings.load()
    values["HTTP_REQUEST"] = 55
    settings.save(values)
    draft = deepcopy(loaded.payload)
    draft["accounts"][0]["name"] = "已编辑"

    config_store.build_save_request(draft, expected_revision=loaded.revision).persist()

    assert json.loads(target.read_text(encoding="utf-8"))["accounts"][0]["name"] == "已编辑"
    assert _saved_settings()["HTTP_REQUEST"] == 55


def test_generic_store_save_keeps_nodes_in_accounts_only():
    payload = _accounts(proxy_group="office")
    payload.update(proxy_groups=[_group()], default_proxy_group="office")

    store.save_payload(payload)

    assert json.loads(paths.ACCOUNTS_PATH.read_text(encoding="utf-8")) == payload
    assert not settings.settings_path().exists() or "proxy_groups" not in _saved_settings()


def test_store_save_payload_does_not_borrow_legacy_settings_nodes():
    _legacy_settings()

    with pytest.raises(ConfigError):
        store.save_payload(_accounts(proxy_group="office"))

    assert not paths.ACCOUNTS_PATH.exists()


def test_gui_can_explicitly_clear_nodes_and_default_group():
    payload = _accounts()
    payload.update(proxy_groups=[_group()], default_proxy_group="office")
    target = _write_accounts(payload)
    loaded = config_store.load_configuration()
    draft = deepcopy(loaded.payload)
    draft.update(proxy_groups=[], default_proxy_group="")

    saved = config_store.build_save_request(draft, expected_revision=loaded.revision).persist()

    assert saved.payload == draft
    raw = json.loads(target.read_text(encoding="utf-8"))
    assert raw["proxy_groups"] == [] and raw["default_proxy_group"] == ""
    assert store.load().proxy_groups == ()


def test_startup_creates_defaults_even_when_accounts_are_missing():
    with pytest.raises(ConfigError, match="未找到配置文件"):
        store.load()

    assert paths.SETTINGS_PATH.exists()
    assert paths.SETTINGS_DEFAULT_PATH.exists()
    assert not paths.ACCOUNTS_PATH.exists()


def test_gui_onboarding_carries_legacy_settings_nodes_into_first_save():
    _legacy_settings()

    loaded = config_store.load_configuration()

    assert loaded.needs_save
    assert loaded.payload["accounts"] == []
    assert loaded.payload["proxy_groups"] == [_group()]
    assert loaded.revision is None
    assert not paths.ACCOUNTS_PATH.exists()
    assert _saved_settings()["proxy_groups"] == [_group()], "首次保存前不能删除唯一一份节点"

    config_store.build_save_request(loaded.payload, expected_revision=None).persist()

    assert json.loads(paths.ACCOUNTS_PATH.read_text(encoding="utf-8"))["proxy_groups"] == [_group()]
    assert "proxy_groups" not in _saved_settings()


def test_ci_domain_split_reads_nodes_from_accounts():
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
    payload = _accounts()
    payload.update(proxy_groups=[group], default_proxy_group="office")
    target = _write_accounts(payload)

    outbound = _split_outbound_from_accounts(target, "office")

    assert outbound["server"] == "edge.invalid"
    assert outbound["name"] == "分流出口"


def test_ci_domain_split_still_reads_legacy_settings_nodes():
    from ci.proxy_config import _split_outbound_from_accounts

    group = _group()
    group["proxies"] = [{"id": "node", "name": "旧出口", "enabled": True,
                         "clash": {"type": "vless", "server": "legacy.invalid", "port": 443, "uuid": "NODE_SECRET"}}]
    _legacy_settings([group])
    target = _write_accounts(_accounts())
    original = target.read_bytes()

    assert _split_outbound_from_accounts(target, "office")["server"] == "legacy.invalid"
    assert target.read_bytes() == original


def test_workflow_keeps_settings_secret_and_detects_bridge_from_accounts():
    workflow = yaml.safe_load((paths.REPO_ROOT / ".github/workflows/auto_checkin.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["checkin"]
    assert job["env"]["SETTINGS"] == "${{ secrets.SETTINGS }}"
    detection = next(step for step in job["steps"] if step.get("id") == "detect_mihomo")
    assert "uv run python" in detection["run"]
    assert "store.with_legacy_proxies(" in detection["run"]
    assert "store.load(" not in detection["run"], "桥接检测不能提前迁移账号并遗漏旧缓存重挂"


def test_settings_and_accounts_cannot_share_the_same_path(monkeypatch):
    monkeypatch.setenv("SETTINGS", str(paths.ACCOUNTS_PATH))
    with pytest.raises(ConfigError, match="同一路径"):
        config_store.load_configuration()


def test_standalone_cli_account_json_does_not_inherit_settings_nodes(monkeypatch):
    from apps import cli

    _legacy_settings()
    account = _accounts(proxy_group="office")["accounts"][0]
    monkeypatch.setattr(cli, "_read_account_json", lambda _reference: account)

    with pytest.raises(ConfigError):
        cli._dispatch(cli.parse_args(["--account-json", "-", "--explain"]))

    assert not paths.ACCOUNTS_PATH.exists()


def test_typed_store_roundtrip_preserves_explicit_empty_nodes():
    _legacy_settings()
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
