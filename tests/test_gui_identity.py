"""v3 稳定账号/任务 ID、依赖闭包、凭据编辑意图与无损导入。"""

from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.account import CREDENTIAL_FIELDS
from core.errors import ConfigError
from gui import config_store, core


def account(**changes):
    return {"id": "stable", "name": "原名", "base_url": "https://example.invalid",
            "tasks": [{"id": "first"}, {"id": "second", "depends_on": ["first"]}], **changes}


def document(*accounts):
    return {"version": 3, "accounts": list(accounts), "oauth_states": {}}


def test_unique_id_is_deterministic_and_collision_safe():
    assert core.unique_id("My Account", []) == "my-account"
    assert core.unique_id("My Account", ["my-account", "my-account-2"]) == "my-account-3"
    assert core.unique_id("中文", []) == core.unique_id("中文", [])
    assert core.unique_id("", []) == "account"


def test_missing_ids_become_fixed_draft_identity_and_survive_rename(tmp_path):
    path = tmp_path / "accounts.json"
    raw = document(
        {"name": "中文名", "base_url": "https://example.invalid", "tasks": [{}, {"id": "task1"}]},
        {"id": "example-invalid", "name": "显式 ID", "base_url": "https://other.invalid"},
    )
    path.write_text(json.dumps(raw), encoding="utf-8")
    before = path.read_bytes()
    loaded = config_store.load_configuration(path)
    assert loaded.payload["accounts"][0]["id"] == "example-invalid-2"
    assert [task["id"] for task in loaded.payload["accounts"][0]["tasks"]] == ["task1-2", "task1"]
    assert loaded.payload["accounts"][1]["tasks"] == [{"id": "daily"}]
    assert any("尚未写入文件" in note for note in loaded.notes)
    assert path.read_bytes() == before
    assert config_store.load_configuration(path).payload == loaded.payload
    edited = copy.deepcopy(loaded.payload)
    edited["accounts"][0]["name"] = "改名"
    edited["accounts"][0]["base_url"] = "https://renamed.invalid"
    edited["accounts"].reverse()
    config_store.build_save_request(edited, path=path, expected_revision=loaded.revision).persist()
    restored = config_store.load_configuration(path)
    assert [row["id"] for row in restored.payload["accounts"]] == ["example-invalid", "example-invalid-2"]


def test_duplicate_account_ids_do_not_get_silently_regenerated():
    with pytest.raises(ConfigError, match="账号 ID 重复"):
        core.validate_payload(document(account(), account(name="别名")))


def test_duplicate_task_ids_rejected():
    with pytest.raises(ConfigError, match="任务 ID 重复"):
        core.validate_payload(document(account(tasks=[{"id": "same"}, {"id": "same"}])))


def test_task_selection_includes_recursive_dependencies_in_topological_order():
    row = account(tasks=[
        {"id": "finish", "depends_on": ["middle", "start"]},
        {"id": "unused"}, {"id": "middle", "depends_on": ["start"]}, {"id": "start"},
        {"id": "disabled", "enabled": False},
    ])
    before = copy.deepcopy(row)
    assert core.selected_task_ids(row, ("finish", "finish")) == ("start", "middle", "finish")
    assert core.selected_task_ids(row) == ("start", "middle", "finish", "unused")
    assert row == before


@pytest.mark.parametrize("tasks", [
    [{"id": "a", "depends_on": ["missing"]}],
    [{"id": "a", "depends_on": ["a"]}],
    [{"id": "a", "depends_on": ["b"]}, {"id": "b", "depends_on": ["a"]}],
])
def test_invalid_dependencies_fail_validation_even_if_not_selected(tasks):
    with pytest.raises(ConfigError, match="depends_on"):
        core.validate_payload(document(account(tasks=tasks)))


def test_disabled_dependency_and_unknown_selection_are_explicit_errors():
    row = account(tasks=[{"id": "a", "enabled": False}, {"id": "b", "depends_on": ["a"]}])
    core.validate_payload(document(row))
    with pytest.raises(ConfigError, match="禁用"):
        core.selected_task_ids(row, ("b",))
    with pytest.raises(ConfigError, match="不存在"):
        core.selected_task_ids(row, ("missing",))
    with pytest.raises(ConfigError):
        core.selected_task_ids(row, "b")


def test_disabled_account_or_all_disabled_tasks_cannot_run():
    with pytest.raises(ConfigError, match="账号已禁用"):
        core.selected_task_ids(account(enabled=False))
    with pytest.raises(ConfigError, match="没有启用"):
        core.selected_task_ids(account(tasks=[{"id": "a", "enabled": False}]))
    with pytest.raises(ConfigError, match="不能为空"):
        core.selected_task_ids(account(tasks=[]))


def test_omitted_tasks_can_use_schema_default_but_empty_cannot():
    row = account()
    row.pop("tasks")
    assert core.selected_task_ids(row) == ("daily",)
    assert "tasks" not in row


def test_policy_empty_object_is_whole_override_and_null_inherits():
    row = account(policy={"retry": 8, "allow_browser": False}, tasks=[
        {"id": "inherit"}, {"id": "null", "policy": None}, {"id": "replace", "policy": {}},
    ])
    spec = core.validate_payload(document(row)).accounts[0]
    assert spec.task_policy(spec.tasks[0]).retry == 8
    assert spec.task_policy(spec.tasks[1]).retry == 8
    assert spec.task_policy(spec.tasks[2]).retry == 1
    assert spec.task_policy(spec.tasks[2]).allow_browser is True


def test_only_changed_credentials_are_explicit_including_presence_and_empty():
    original = account(credentials={"access_token": "token", "refresh_token": "", "browser_state": "state"})
    edited = copy.deepcopy(original)
    assert core.credential_changes(edited, original) == ()
    edited["name"] = "rename"
    edited["credentials"]["extension"] = "not a credential"
    assert core.credential_changes(edited, original) == ()
    edited["credentials"]["access_token"] = ""
    edited["credentials"]["cookie"] = ""
    del edited["credentials"]["browser_state"]
    assert core.credential_changes(edited, original) == ("access_token", "cookie", "browser_state")
    assert core.credential_changes(account(), None) == ()
    assert core.credential_changes(account(credentials={"cookie": ""}), None) == ("cookie",)
    assert core.credential_changes(account(), account(credentials={"cookie": ""})) == ("cookie",)


def test_all_five_credential_fields_are_compared_without_trimming():
    original = account(credentials={name: "secret" for name in CREDENTIAL_FIELDS})
    edited = account(credentials={name: " secret" for name in CREDENTIAL_FIELDS})
    assert core.credential_changes(edited, original) == CREDENTIAL_FIELDS


@pytest.mark.parametrize("shape", ["document", "array", "single"])
def test_import_appends_and_preserves_all_tasks_and_extensions(shape):
    original = document(account())
    incoming = account(
        login={"method": "custom", "args": {"password": "LOGIN_SECRET"}, "extra": {"a": [1]}},
        tasks=[{"id": "first", "extra": 1}, {"id": "second", "depends_on": ["first"],
               "args": {"secret": "TASK_SECRET"}, "extra": {"keep": [1, 2]}}],
        credentials={"session_cookie": "COOKIE_SECRET"}, custom={"keep": [1]},
    )
    raw = document(incoming) if shape == "document" else [incoming] if shape == "array" else incoming
    before = copy.deepcopy(original)
    imported = core.import_accounts(original, json.dumps(raw))
    assert original == before
    assert [row["id"] for row in imported["accounts"]] == ["stable", "stable-2"]
    assert imported["accounts"][1]["tasks"] == incoming["tasks"]
    assert imported["accounts"][1]["login"] == incoming["login"]
    assert imported["accounts"][1]["custom"] == incoming["custom"]
    imported["accounts"][0]["tasks"].clear()
    assert original == before
    imported_again = core.import_accounts(original, json.dumps(raw))
    assert imported_again["accounts"][1]["id"] == "stable-2"


def test_multiple_imported_duplicate_ids_get_new_stable_ids():
    imported = core.import_accounts(document(account()), json.dumps([account(), account()]))
    assert [row["id"] for row in imported["accounts"]] == ["stable", "stable-2", "stable-3"]


def test_collector_legacy_payload_uses_migration_and_keeps_extensions():
    raw = {"name": "collector", "base_url": "https://collector.invalid", "site_profile": "sub2api",
           "auth_method": "browser", "checkin_action": "browser_script", "script": "scripts/checkin/custom.py",
           "refresh_token": "REFRESH_SECRET", "script_args": {"count": 2}, "extra": {"keep": [1, 2]}}
    imported = core.import_accounts(document(), json.dumps(raw))
    row = imported["accounts"][0]
    assert row["login"]["method"] == "browser_state"
    assert row["template"] == "scripts/tasks/custom.py"
    assert row["tasks"][0]["method"] == "script"
    assert row["tasks"][0]["args"] == {"count": 2}
    assert row["credentials"]["refresh_token"] == "REFRESH_SECRET"
    assert row["extra"] == {"keep": [1, 2]}


def test_legacy_same_name_accounts_receive_unique_ids(tmp_path):
    path = tmp_path / "accounts.json"
    row = {"name": "same", "base_url": "https://example.invalid", "type": "newapi"}
    path.write_text(json.dumps([row, row]), encoding="utf-8")
    loaded = config_store.load_configuration(path)
    assert [item["id"] for item in loaded.payload["accounts"]] == ["same", "same-2"]


def test_oauth_metadata_merges_without_overwriting_and_conflicts_are_transactional():
    original = document(account())
    original["oauth_states"] = {"github": {"extension": [1], "accounts": {"default": {"state": "OLD_SECRET"}}}}
    incoming = document(account(id="new"))
    incoming["oauth_states"] = {
        "github": {"extension": [1], "accounts": {"another": {"state": "NEW_SECRET", "meta": {"keep": [1]}}}}
    }
    incoming["extension"] = {"keep": [1]}
    result = core.import_accounts(original, json.dumps(incoming))
    assert set(result["oauth_states"]["github"]["accounts"]) == {"default", "another"}
    assert result["oauth_states"]["github"]["accounts"]["another"]["meta"] == {"keep": [1]}
    assert result["extension"] == {"keep": [1]}
    before = copy.deepcopy(original)
    incoming["oauth_states"]["github"]["accounts"]["default"] = {"state": "CONFLICT_SECRET"}
    with pytest.raises(ConfigError, match="冲突") as caught:
        core.import_accounts(original, json.dumps(incoming))
    assert "SECRET" not in str(caught.value)
    assert original == before


@pytest.mark.parametrize("text", ["", "{broken SECRET", "null", "123", "{}", "[false]",
                                 '{"version": 3, "accounts": [], "oauth_states": []}',
                                 '{"accounts": [], "accounts": [null]}'])
def test_invalid_import_does_not_change_current_document(text):
    original = document(account())
    before = copy.deepcopy(original)
    with pytest.raises(ConfigError) as caught:
        core.import_accounts(original, text)
    assert "SECRET" not in str(caught.value)
    assert original == before


def test_simultaneous_save_requests_share_lock_and_only_one_revision_wins(tmp_path):
    path = tmp_path / "accounts.json"
    loaded = config_store.build_save_request(document(account()), path=path, expected_revision=None).persist()
    first = config_store.build_save_request(document(account(name="one")), path=path, expected_revision=loaded.revision)
    second = config_store.build_save_request(document(account(name="two")), path=path, expected_revision=loaded.revision)

    def persist(request):
        try:
            return request.persist()
        except ConfigError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(persist, (first, second)))
    successes = [result for result in results if result is not None]
    assert len(successes) == 1
    assert json.loads(path.read_bytes()) == successes[0].payload
