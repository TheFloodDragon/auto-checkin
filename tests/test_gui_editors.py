"""离屏测试 v3 编辑器的稀疏写回、密码安全、多任务和 Manifest 参数。"""

from __future__ import annotations

import copy
import json
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6", reason="GUI 专项测试需要可选 PySide6")

from PySide6.QtTest import QSignalSpy  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog, QLineEdit, QSizePolicy  # noqa: E402

from core.account import CREDENTIAL_FIELDS  # noqa: E402
from core.errors import ConfigError  # noqa: E402
from gui import dialogs, widgets  # noqa: E402
from gui.dialogs import ArgsEditor, JsonDialog, SecretEdit, TaskDialog  # noqa: E402
from gui.widgets import AccountEditor  # noqa: E402


@pytest.fixture(scope="module")
def qt_app():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def editor(qt_app):
    result = AccountEditor()
    yield result
    result.close()
    result.deleteLater()
    qt_app.processEvents()


@pytest.fixture
def raw():
    return {
        "id": "stable", "name": "账号", "base_url": "", "template": "scripts/tasks/custom.py",
        "credentials": {"access_token": "TOKEN_SECRET", "refresh_token": None, "user_id": 42,
                        "cookie_file": "relative.txt", "extension": {"keep": [1]}},
        "login": {"method": "custom-login", "provider": None, "args": {"unknown": [1, {"x": None}]},
                  "fallback": [{"method": "password", "args": {"password": "FALLBACK_SECRET"},
                                "extension": [1], "fallback": [{"method": "custom"}]}], "extension": {"x": 2}},
        "tasks": [
            {"id": "first", "method": "visit", "args": {"extra": [1]}, "extension": {"x": 1}},
            {"id": "second", "depends_on": ["first"], "template": "custom/path.py", "title": None,
             "method": "script", "args": {"secret": "TASK_SECRET", "extra": [2]},
             "policy": {}, "flow": {"execute": ["custom", "off"]}, "extension": [2]},
        ],
        "policy": {"allow_browser": False, "extension": [1]},
        "flow": {"execute": "custom"}, "network": {"proxy": "socks5://localhost:1080", "extension": [2]},
        "extension": {"preserve": [None, 1]},
    }


@pytest.fixture
def catalog():
    return [{
        "reference": "scripts/tasks/custom.py", "title": "自定义模板", "description": "模板说明",
        "login_methods": ["custom-login", "password"], "task_methods": ["script", "visit"],
        "args": [
            {"name": "count", "type": "int", "default": 5, "minimum": 0, "maximum": 10, "env": "COUNT_ENV"},
            {"name": "secret", "type": "str", "secret": True, "default": "HIDDEN_DEFAULT"},
        ],
        "task_args": {"script": [
            {"name": "ratio", "type": "float", "default": 0.5},
            {"name": "switch", "type": "bool", "default": True},
            {"name": "options", "type": "json", "default": {}},
            {"name": "choice", "type": "str", "choices": ["a", "b"], "default": "a"},
        ]},
        "login_args": {"custom-login": [
            {"name": "password", "type": "str", "secret": True, "env": "PASSWORD_ENV", "default": "HIDDEN_DEFAULT"},
            {"name": "count", "type": "int", "default": 2},
        ]},
        "task_options": [{"method": "script", "args": [{"name": "from_option", "type": "str"}]}],
    }]


def test_set_account_is_silent_and_full_payload_is_independent(editor, raw):
    before = copy.deepcopy(raw)
    spy = QSignalSpy(editor.changed)
    editor.set_account(raw)
    assert spy.count() == 0
    assert editor.value() == before
    assert editor.has_pending_changes() is False
    raw["tasks"][1]["args"]["extra"].append(99)
    value = editor.value()
    value["login"]["fallback"].clear()
    assert editor.value() == before
    assert editor.fields["id"].isReadOnly()
    editor.fields["id"].setText("attempted-change")
    assert editor.value()["id"] == "stable"


def test_ordinary_edit_does_not_fill_defaults_normalize_null_or_change_credentials(editor, raw):
    original = copy.deepcopy(raw)
    editor.set_account(raw)
    editor.fields["name"].setText("改名")
    original["name"] = "改名"
    assert editor.value() == original
    assert "enabled" not in editor.value()
    assert editor.value()["credentials"]["user_id"] == 42
    assert editor.value()["credentials"]["refresh_token"] is None
    assert editor.value()["login"]["provider"] is None
    assert editor.has_pending_changes()
    editor.fields["base_url"].setText("https://new.invalid")
    editor.fields["base_url"].clear()
    assert editor.value()["base_url"] == ""


def test_missing_groups_and_default_task_are_not_materialized_until_edited(editor):
    raw = {"id": "a", "name": None, "base_url": ""}
    editor.set_account(raw)
    assert editor.selected_task_id() == "daily"
    assert editor.value() == raw
    editor.fields["name"].setText("new")
    assert editor.value() == {**raw, "name": "new"}
    editor.login_fields["method"].setEditText("password")
    assert editor.value()["login"] == {"method": "password"}
    assert "credentials" not in editor.value() and "tasks" not in editor.value()
    editor.toggle_task()
    assert editor.value()["tasks"] == [{"id": "daily", "enabled": False}]


def test_url_alias_and_root_credential_references_stay_in_original_location(editor):
    raw = {"id": "a", "url": "https://alias.invalid", "user_id": 42, "cookie_file": "cookie.txt"}
    editor.set_account(raw)
    editor.fields["name"].setText("name")
    assert editor.value()["user_id"] == 42
    editor.fields["base_url"].setText("https://changed.invalid")
    editor.credential_fields["cookie_file"].setText("changed.txt")
    value = editor.value()
    assert value["url"] == "https://changed.invalid" and "base_url" not in value
    assert value["cookie_file"] == "changed.txt" and "credentials" not in value


def test_switching_login_never_deletes_credentials_fallback_or_extensions(editor, raw):
    editor.set_account(raw)
    editor.login_fields["method"].setEditText("oauth")
    editor.login_fields["provider"].setEditText("github")
    value = editor.value()
    assert value["credentials"] == raw["credentials"]
    assert value["login"]["fallback"] == raw["login"]["fallback"]
    assert value["login"]["extension"] == raw["login"]["extension"]
    assert value["login"]["method"] == "oauth"


def test_credential_password_fields_and_explicit_clear(editor, raw):
    editor.set_account(raw)
    assert set(editor.credential_fields) == {*CREDENTIAL_FIELDS, "user_id", "cookie_file"}
    for field in editor.credential_fields.values():
        assert field.edit.echoMode() == QLineEdit.EchoMode.Password
        assert "SECRET" not in field.toolTip()
    field = editor.credential_fields["access_token"]
    field.toggle.setChecked(True)
    assert field.edit.echoMode() == QLineEdit.EchoMode.Normal
    field.setText("")
    assert editor.value()["credentials"]["access_token"] == ""
    editor.set_account(raw)
    assert field.edit.echoMode() == QLineEdit.EchoMode.Password
    assert "SECRET" not in repr(editor)


def test_open_combos_expand_for_custom_paths_and_login_fields(editor, raw):
    editor.set_account(raw)
    for field in (editor.fields["template"], *editor.login_fields.values()):
        assert field.sizePolicy().horizontalPolicy() == QSizePolicy.Policy.Expanding
        assert field.minimumContentsLength() >= 18
    assert editor.fields["template"].currentText() == raw["template"]


def test_catalog_arrival_is_silent_and_never_replaces_custom_template(editor, raw, catalog):
    editor.set_account(raw)
    before = editor.value()
    spy = QSignalSpy(editor.changed)
    editor.set_catalog(catalog)
    assert editor.value() == before and spy.count() == 0
    assert editor.fields["template"].currentText() == "scripts/tasks/custom.py"
    editor.set_catalog([])
    assert editor.value() == before and spy.count() == 0
    assert editor.fields["template"].currentText() == "scripts/tasks/custom.py"


def test_account_manifest_args_keep_unknown_and_never_fill_defaults(editor, raw, catalog):
    editor.set_account(raw)
    editor.set_catalog(catalog)
    assert editor.login_args.fields["count"].text() == ""
    assert isinstance(editor.login_args.fields["password"], SecretEdit)
    assert editor.value() == raw
    editor.login_args.fields["count"].setText("7")
    value = editor.value()
    assert value["login"]["args"] == {"unknown": [1, {"x": None}], "count": 7}
    assert "password" not in value["login"]["args"]
    editor.set_catalog(catalog)
    assert editor.value() == value
    editor.login_args.fields["count"].setText("not-number")
    with pytest.raises(ConfigError):
        editor.value()
    assert editor.has_pending_changes()
    editor.set_catalog([])
    assert editor.login_args.fields["count"].text() == "not-number"


def test_task_copy_reorder_enable_delete_and_identity(editor, raw):
    editor.set_account(raw)
    editor.task_list.setCurrentRow(1)
    assert editor.copy_task()
    value = editor.value()
    assert [task["id"] for task in value["tasks"]] == ["first", "second", "second-2"]
    assert value["tasks"][2]["args"] == raw["tasks"][1]["args"]
    assert value["tasks"][2]["extension"] == [2]
    assert editor.selected_task_id() == "second-2"
    assert editor.move_task(-1)
    assert [task["id"] for task in editor.value()["tasks"]] == ["first", "second-2", "second"]
    assert editor.selected_task_id() == "second-2"
    assert editor.toggle_task()
    assert editor.value()["tasks"][1]["enabled"] is False
    assert editor.delete_task()
    assert [task["id"] for task in editor.value()["tasks"]] == ["first", "second"]
    assert raw["tasks"][1]["id"] == "second"


def test_task_delete_refuses_dependencies_and_final_task(editor, raw):
    editor.set_account(raw)
    assert editor.selected_task_id() == "first"
    assert editor.delete_task() is False
    assert "依赖" in editor.error_label.text()
    editor.task_list.setCurrentRow(1)
    assert editor.delete_task() is True
    assert editor.delete_task() is False
    assert "最后" in editor.error_label.text()
    assert editor.value()["tasks"] == [raw["tasks"][0]]


def test_run_signal_carries_selected_stable_task_id_and_capture_has_no_payload(editor, raw):
    editor.set_account(raw)
    spy = QSignalSpy(editor.run_requested)
    capture = QSignalSpy(editor.capture_requested)
    editor.task_list.setCurrentRow(1)
    editor.task_run_button.click()
    assert spy.count() == 1 and spy.at(0) == ["second"]
    editor.capture_requested.emit()
    assert capture.count() == 1


def test_task_list_exposes_template_source_and_dependency_graph(editor, raw):
    editor.set_account(raw)
    assert "继承账号" in editor.task_list.item(0).text()
    assert "scripts/tasks/custom.py" in editor.task_list.item(0).toolTip()
    assert "任务覆盖" in editor.task_list.item(1).text()
    assert "前置：first" in editor.task_list.item(1).toolTip()
    editor.enabled.setChecked(False)
    assert not editor.task_run_button.isEnabled()
    editor.enabled.setChecked(True)
    assert editor.task_run_button.isEnabled()


@pytest.mark.parametrize("change", [{"tasks": [None]}, {"tasks": {}}, {"login": {"fallback": {}}},
                                    {"credentials": []}, {"tasks": [{"id": "a", "depends_on": "b"}]}])
def test_bad_container_set_account_is_transactional(editor, raw, change):
    editor.set_account(raw)
    before = editor.value()
    with pytest.raises(ConfigError):
        editor.set_account({**raw, **change})
    assert editor.value() == before


def test_add_task_while_numeric_input_is_invalid_shows_safe_error(editor, raw, catalog):
    editor.set_account(raw)
    editor.set_catalog(catalog)
    editor.login_args.fields["count"].setText("COUNT_SECRET")
    assert editor.add_task() is False
    assert "SECRET" not in editor.error_label.text()
    assert editor.has_pending_changes()


def test_add_task_deduplicates_id_and_copies_input(editor, raw):
    editor.set_account(raw)
    incoming = {"id": "second", "args": {"nested": [1]}, "unknown": [2]}
    editor.add_task(incoming)
    incoming["args"]["nested"].append(99)
    assert editor.value()["tasks"][-1] == {"id": "second-2", "args": {"nested": [1]}, "unknown": [2]}


def test_json_dialog_accept_reject_type_and_secret_safe_errors(qt_app):
    dialog = JsonDialog("JSON", {"secret": "BODY_SECRET", "unknown": [1]})
    value = dialog.value()
    value["unknown"].append(2)
    assert dialog.value()["unknown"] == [1]
    dialog.editor.setPlainText('{"secret":"BODY_SECRET", broken}')
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert "BODY_SECRET" not in dialog.error_label.text()
    dialog.editor.setPlainText("[]")
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Rejected
    dialog.editor.setPlainText('{"secret":"BODY_SECRET", "unknown":[2]}')
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert dialog.value()["unknown"] == [2]
    assert "BODY_SECRET" not in repr(dialog)
    dialog.close()


@pytest.mark.parametrize("text", ['{"a": 1, "a": 2}', '{"a": NaN}', '[1]', '"SECRET"', 'null'])
def test_json_dialog_rejects_ambiguous_or_wrong_root(qt_app, text):
    dialog = JsonDialog("JSON", {})
    dialog.editor.setPlainText(text)
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert "SECRET" not in dialog.error_label.text()
    dialog.close()


def test_task_dialog_unchanged_keeps_every_layer_and_null(qt_app, raw):
    task = copy.deepcopy(raw["tasks"][1])
    dialog = TaskDialog(task, account=raw)
    assert dialog.value() == task
    dialog.fields["title"].setText("edited")
    expected = {**task, "title": "edited"}
    assert dialog.value() == expected
    dialog.fields["id"].setText("not-used")
    assert dialog.value()["id"] == "second"
    assert dialog.fields["template"].currentText() == "custom/path.py"
    assert task == raw["tasks"][1]
    dialog.close()


def test_task_dialog_complete_fields_and_policy_whole_override(qt_app, raw):
    dialog = TaskDialog(raw["tasks"][1], account=raw)
    dialog.fields["template"].setEditText("different/path.py")
    dialog.fields["method"].setEditText("unknown-method")
    dialog.fields["title"].setText("标题")
    dialog.fields["text_label"].setText("奖励")
    dialog.fields["timeout"].setText("123")
    dialog.depends_on.setText('["first"]')
    dialog.policy_mode.setCurrentIndex(1)
    value = dialog.value()
    assert value["policy"] is None
    assert value["template"] == "different/path.py" and value["method"] == "unknown-method"
    assert value["timeout"] == 123 and value["text_label"] == "奖励"
    assert value["flow"] == raw["tasks"][1]["flow"]
    dialog.policy_mode.setCurrentIndex(2)
    assert dialog.value()["policy"] == {}
    dialog.policy_mode.setCurrentIndex(0)
    assert "policy" not in dialog.value()
    dialog.close()


def test_task_dialog_invalid_timeout_and_dependencies_do_not_accept(qt_app, raw):
    dialog = TaskDialog(raw["tasks"][1], account=raw)
    dialog.fields["timeout"].setText("TIMEOUT_SECRET")
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert "SECRET" not in dialog.error_label.text()
    dialog.fields["timeout"].setText("5")
    dialog.depends_on.setText('["second"]')
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert "循环" in dialog.error_label.text()
    dialog.depends_on.setText('["missing"]')
    dialog.accept()
    assert "不存在" in dialog.error_label.text()
    dialog.depends_on.setText('["first"]')
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Accepted
    dialog.close()


def test_task_manifest_args_merge_template_method_and_option_declarations(qt_app, raw, catalog):
    raw["tasks"][1]["template"] = "scripts/tasks/custom.py"
    dialog = TaskDialog(raw["tasks"][1], account=raw, catalog=catalog)
    fields = dialog.args_editor.fields
    assert set(fields) == {"count", "secret", "ratio", "switch", "options", "choice", "from_option"}
    assert fields["count"].text() == ""
    assert fields["ratio"].text() == ""
    assert fields["switch"].currentIndex() == 0
    assert fields["choice"].currentText() == ""
    assert isinstance(fields["secret"], SecretEdit)
    assert dialog.value() == raw["tasks"][1]
    fields["count"].setText("8")
    fields["ratio"].setText("0.75")
    fields["switch"].setCurrentIndex(2)
    fields["choice"].setEditText("b")
    value = dialog.value()
    assert value["args"] == {**raw["tasks"][1]["args"], "count": 8, "ratio": 0.75, "switch": False, "choice": "b"}
    assert "options" not in value["args"]
    fields["count"].setText("11")
    with pytest.raises(ConfigError, match="范围"):
        dialog.value()
    dialog.close()


def test_args_remove_override_preserves_unknown_and_catalog_changes(qt_app, catalog):
    args = ArgsEditor()
    specs = dialogs.argument_specs(catalog[0], "task", "script")
    original = {"count": 7, "unknown": [1], "secret": "SECRET"}
    args.set_value(original, specs)
    args.remove_argument("count")
    assert args.value() == {"unknown": [1], "secret": "SECRET"}
    args.set_specs(specs)
    assert args.value() == {"unknown": [1], "secret": "SECRET"}
    assert args.has_pending_changes()
    assert "HIDDEN_DEFAULT" not in " ".join(item.text() for item in args.findChildren(dialogs.QLabel))
    args.close()


def test_manifest_json_arg_is_modal_and_preserves_other_args(qt_app, catalog, monkeypatch):
    args = ArgsEditor()
    args.set_value({"unknown": [1]}, dialogs.argument_specs(catalog[0], "task", "script"))

    class Replacement(JsonDialog):
        def exec(self):
            self.editor.setPlainText('{"nested":[1, false, null]}')
            self.accept()
            return self.result()

    monkeypatch.setattr(dialogs, "JsonDialog", Replacement)
    args._edit_json_arg("options")
    assert args.value() == {"unknown": [1], "options": {"nested": [1, False, None]}}
    assert args.has_pending_changes()
    args.close()


def test_account_json_modal_transaction_preserves_id_and_other_fields(editor, raw, monkeypatch):
    editor.set_account(raw)
    changed = copy.deepcopy(raw)
    changed["extension"]["preserve"].append("added")

    class Replacement(JsonDialog):
        def exec(self):
            self.editor.setPlainText(json.dumps(changed))
            self.accept()
            return self.result()

    monkeypatch.setattr(widgets, "JsonDialog", Replacement)
    editor._edit_account_json()
    assert editor.value() == changed
    assert editor.has_pending_changes()
    changed["id"] = "forbidden"
    before = editor.value()
    editor._edit_account_json()
    assert editor.value() == before
    assert "ID" in editor.error_label.text()


def test_cancelled_modal_and_accepting_unchanged_defaults_do_not_create_keys(editor, monkeypatch):
    original = {"id": "a", "base_url": ""}
    editor.set_account(original)

    class Unchanged(JsonDialog):
        def exec(self):
            self.accept()
            return self.result()

    monkeypatch.setattr(widgets, "JsonDialog", Unchanged)
    editor._edit_section("network")
    editor._edit_fallback()
    assert editor.value() == original

    class Cancelled(JsonDialog):
        def exec(self):
            self.editor.setPlainText('{"proxy":"not-applied"}')
            return QDialog.DialogCode.Rejected

    monkeypatch.setattr(widgets, "JsonDialog", Cancelled)
    editor._edit_section("network")
    assert editor.value() == original
