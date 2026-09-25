"""可视化编辑器与运行监视器的离线交互回归；不访问网络、不启动任务进程。"""
from __future__ import annotations

import os
from copy import deepcopy
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtCore import QPointF, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from core.errors import ConfigError
from gui.chain_editor import ChainEditorDialog
from gui.chain_model import ChainDocument
from gui.run_panel import RunPanel, chain_summary
from gui.task_graph import TaskDependencyDialog

STEPS = [
    {"id": "http", "kind": "http", "title": "HTTP 签到", "login": ["access_token", "refresh"]},
    {"id": "browser", "kind": "browser", "title": "浏览器登录并签到", "login": ["browser_state", "password"]},
]
CUSTOM = {"use": "custom", "steps": STEPS, "future": {"keep": True}}


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def dialog(qapp, monkeypatch):
    from gui import theme

    monkeypatch.setattr(theme, "load_theme", lambda: "light")
    monkeypatch.setattr(QMessageBox, "question", lambda *_a, **_k: QMessageBox.StandardButton.Discard)
    result = ChainEditorDialog(deepcopy(CUSTOM), STEPS, theme_name="light")
    result.show()
    qapp.processEvents()
    result.canvas.fit_graph()
    yield result
    result.done(QDialog.DialogCode.Rejected)
    result.deleteLater()
    qapp.processEvents()


def test_no_edit_roundtrip_does_not_expand_implicit_edges():
    doc = ChainDocument(CUSTOM, STEPS)
    assert doc.payload() == CUSTOM
    assert doc.links() == [("http", "browser")]
    assert doc.order() == ["http", "browser"]
    assert not doc.issues()


def test_layout_changes_never_rewire_execution():
    doc = ChainDocument(CUSTOM)
    doc.set_positions({"browser": [-900, -300], "http": [900, 300]})
    assert doc.order() == ["http", "browser"]
    assert doc.payload()["steps"] == CUSTOM["steps"]
    assert doc.payload()["future"] == {"keep": True}
    doc.auto_layout()
    assert doc.order() == ["http", "browser"]


def test_cycle_rejected_without_modifying_original_draft():
    doc = ChainDocument(CUSTOM)
    original = doc.payload()
    with pytest.raises(ConfigError, match="循环"):
        doc.connect("browser", "http")
    assert doc.payload() == original
    with pytest.raises(ConfigError, match="自己"):
        doc.connect("http", "http")


def test_disconnect_is_explicit_and_does_not_fall_through_array():
    doc = ChainDocument(CUSTOM)
    doc.connect("http", "")
    assert doc.order() == ["http"]
    assert doc.payload()["steps"][0]["on_failure"] == ""
    assert any(i.node == "browser" and i.severity == "warning" for i in doc.issues())
    doc.connect("http", "browser")
    assert doc.order() == ["http", "browser"]


def test_insert_and_duplicate_preserve_configuration_and_unique_ids():
    original = deepcopy(CUSTOM)
    original["steps"][0]["unknown"] = {"a": [1, 2]}
    doc = ChainDocument(original, STEPS)
    inserted = doc.add("http", after="http", position=[11, 22])
    assert doc.order() == ["http", inserted, "browser"]
    duplicate = doc.duplicate("http")
    assert duplicate not in doc.order(), "复制节点不能偷偷接入执行路径"
    assert doc.step(duplicate)["unknown"] == {"a": [1, 2]}
    assert len({row["id"] for row in doc.steps()}) == 4
    assert doc.payload()["future"] == original["future"]


def test_deleting_entry_requires_explicit_new_entry():
    doc = ChainDocument(CUSTOM)
    doc.delete(["http"])
    assert any(i.severity == "error" for i in doc.issues())
    doc.set_entry("browser")
    assert doc.order() == ["browser"]
    assert not doc.issues()


def test_move_sequence_is_explicit_not_just_layout():
    doc = ChainDocument(CUSTOM)
    doc.move_in_order("browser", -1)
    assert doc.order() == ["browser", "http"]
    assert doc.entry() == "browser"
    doc.auto_layout()
    assert doc.positions()["browser"][0] < doc.positions()["http"][0]


@pytest.mark.parametrize("raw", [None, {}, {"use": "template"}])
def test_template_inheritance_is_preserved_until_customized(raw):
    doc = ChainDocument(raw, STEPS)
    assert doc.payload() == raw
    if raw is not None:
        with pytest.raises(ConfigError, match="自定义"):
            doc.connect("http", "")
    doc.select_source("custom")
    if raw is not None:
        assert len(doc.steps()) == 2
    else:
        assert doc.steps() == []
    assert doc.payload()["use"] == "custom"


@pytest.mark.parametrize("raw", [[], 5, {"use": []}, {"steps": [{"id": [1], "kind": "http"}]}])
def test_invalid_raw_config_can_be_shown_for_repair(raw):
    doc = ChainDocument(raw)
    doc.order()
    doc.positions()
    assert any(issue.severity == "error" for issue in doc.issues())


def test_dialog_preserves_raw_on_open_and_cancel(dialog):
    assert not dialog.has_changes()
    assert dialog.value() == CUSTOM
    assert len(dialog.canvas.nodes) == 2
    assert len(dialog.canvas.edges) == 1
    assert dialog.accept_button.isEnabled()


def test_dialog_add_undo_redo_and_dependency_edit(dialog):
    dialog.add_step("http")
    assert len(dialog.value()["steps"]) == 3
    assert dialog.has_changes()
    dialog.undo_stack.undo()
    assert dialog.value() == CUSTOM
    dialog.undo_stack.redo()
    assert len(dialog.value()["steps"]) == 3
    before = dialog.value()
    dialog.connect_steps("browser", "http")
    assert "循环" in dialog.notice.text()
    assert dialog.value() == before


def test_delete_connection_and_reconnect_with_property_panel(dialog):
    dialog._delete([], [("http", "browser")])
    assert dialog.doc.order() == ["http"]
    assert dialog.issues_list.count() == 1
    dialog.target.setCurrentIndex(dialog.target.findData("browser"))
    assert dialog.apply_properties()
    assert dialog.doc.order() == ["http", "browser"]


def test_title_property_preserves_unknown_fields_and_does_not_drop_pending_on_select(dialog):
    dialog.title_edit.setText("新的 HTTP 名称")
    dialog.title_edit.textEdited.emit("新的 HTTP 名称")
    assert dialog.has_changes()
    assert not dialog.undo_action.isEnabled(), "未应用属性时不允许全局撤销丢掉表单输入"
    dialog._select("browser")
    assert dialog.doc.step("http")["title"] == "新的 HTTP 名称"
    assert dialog.value()["future"] == {"keep": True}
    dialog.undo_stack.undo()
    assert dialog.doc.step("http")["title"] == STEPS[0]["title"]


def test_empty_explicit_login_is_rejected(dialog):
    for i in range(dialog.logins.count()):
        dialog.logins.item(i).setCheckState(Qt.CheckState.Unchecked)
    dialog.inherit_login.setChecked(False)
    assert not dialog.apply_properties()
    assert "至少" in dialog.notice.text()
    assert dialog.value() == CUSTOM
    dialog.inherit_login.setChecked(True)
    assert dialog.apply_properties()
    assert "login" not in dialog.doc.step("http")


def test_ui_state_blocks_save_after_deleting_entry(dialog):
    dialog._delete(["http"], [])
    assert not dialog.accept_button.isEnabled()
    dialog._set_entry()
    assert dialog.accept_button.isEnabled()
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Accepted


def test_path_preview_does_not_mutate_or_execute(dialog):
    before = dialog.value()
    dialog.simulate(1)
    assert dialog.value() == before
    assert dialog.canvas.nodes["http"].data["state"] == "failed"
    assert dialog.canvas.nodes["browser"].data["state"] == "success"
    assert not dialog.has_changes()
    assert "模拟" in dialog.notice.text()
    dialog.simulate(None)
    assert dialog.canvas.nodes["http"].data["state"] == ""


def test_actual_mouse_drag_changes_layout_only(dialog, qapp):
    view = dialog.canvas
    node = view.nodes["http"]
    start = view.mapFromScene(node.mapToScene(QPointF(70, 45)))
    finish = start + view.mapFromScene(QPointF(45, 55)) - view.mapFromScene(QPointF(0, 0))
    QTest.mousePress(view.viewport(), Qt.MouseButton.LeftButton, pos=start)
    QTest.mouseMove(view.viewport(), finish, delay=10)
    QTest.mouseRelease(view.viewport(), Qt.MouseButton.LeftButton, pos=finish)
    qapp.processEvents()
    assert "http" in dialog.value().get("layout", {})
    assert dialog.doc.order() == ["http", "browser"]
    assert dialog.value()["steps"] == CUSTOM["steps"]
    dialog.undo_stack.undo()
    assert dialog.value() == CUSTOM


def test_actual_port_drag_reconnects_after_explicit_disconnect(dialog, qapp):
    dialog.connect_steps("http", "")
    view = dialog.canvas
    source = view.nodes["http"]
    target = view.nodes["browser"]
    start = view.mapFromScene(source.mapToScene(source.output_pos()))
    finish = view.mapFromScene(target.mapToScene(target.input_pos()))
    QTest.mousePress(view.viewport(), Qt.MouseButton.LeftButton, pos=start)
    QTest.mouseMove(view.viewport(), finish, delay=10)
    QTest.mouseRelease(view.viewport(), Qt.MouseButton.LeftButton, pos=finish)
    qapp.processEvents()
    assert dialog.doc.order() == ["http", "browser"]
    assert len(view.edges) == 1


def test_readonly_runtime_never_changes_configuration(qapp):
    rows = [{"id": "http", "kind": "http", "status": "failed", "reason": "need_login"},
            {"id": "browser", "kind": "browser", "status": "success", "duration_seconds": 4.5}]
    dlg = ChainEditorDialog(None, read_only=True, runtime_steps=rows, theme_name="dark")
    assert not dlg.source.isEnabled()
    assert not dlg.has_changes()
    assert dlg.canvas.nodes["http"].data["state"] == "failed"
    dlg.add_step("http")
    assert len(dlg.canvas.nodes) == 2
    assert dlg.value() is None
    dlg.accept()
    dlg.deleteLater()
    qapp.processEvents()


def test_dependency_graph_cycle_rejected_and_multi_parent_allowed(qapp):
    raw = {"tasks": [{"id": "a", "future": 1}, {"id": "b"}, {"id": "c"}]}
    dialog = TaskDependencyDialog(raw, theme_name="light")
    assert dialog.connect_tasks("a", "c")
    assert dialog.connect_tasks("b", "c")
    assert dialog.value()[2]["depends_on"] == ["a", "b"]
    before = dialog.value()
    assert not dialog.connect_tasks("c", "a")
    assert dialog.value() == before
    assert dialog.value()[0]["future"] == 1
    assert raw["tasks"][2] == {"id": "c"}
    dialog.auto_layout()
    assert dialog.layout_value()["c"][0] > dialog.layout_value()["a"][0]
    dialog._delete([], [("a", "c")])
    assert dialog.value()[2]["depends_on"] == ["b"]
    dialog.undo_stack.undo()
    assert dialog.value()[2]["depends_on"] == ["a", "b"]
    dialog.done(QDialog.DialogCode.Rejected)
    dialog.deleteLater()
    qapp.processEvents()


def test_account_editor_chain_entry_updates_only_draft(qapp, monkeypatch):
    import gui.chain_editor as module
    from gui.widgets import AccountEditor

    original = {"id": "a", "base_url": "https://a.invalid", "tasks": [{"id": "daily", "future": 4}]}
    class FakeDialog:
        def __init__(self, *args, **kwargs):
            pass
        def exec(self):
            return QDialog.DialogCode.Accepted
        def value(self):
            return {"use": "template"}
        def has_changes(self):
            return True
    monkeypatch.setattr(module, "ChainEditorDialog", FakeDialog)
    editor = AccountEditor()
    editor.set_account(original)
    assert editor.edit_chain()
    assert editor.value()["tasks"][0] == {"id": "daily", "future": 4, "chain": {"use": "template"}}
    assert "chain" not in original["tasks"][0]
    editor.deleteLater()
    qapp.processEvents()


def event(task="daily", step="http", status="running", message="执行 HTTP", reason=""):
    return {"task": task, "stage": "chain", "message": message,
            "fields": {"step": step, "kind": "http", "status": status, "reason": reason}}


def test_run_panel_isolates_jobs_logs_and_step_status(qapp):
    panel = RunPanel()
    panel.register_job("one", "账号甲", ("daily",))
    panel.register_job("two", "账号乙", ("other",))
    panel.receive_event("one", event())
    panel.append_log("one", "甲 HTTP 开始")
    panel.receive_event("two", event("other"))
    panel.append_log("two", "乙 HTTP 开始")
    panel.select_job("one")
    assert "甲" in panel.log_view.toPlainText() and "乙" not in panel.log_view.toPlainText()
    assert panel.table.rowCount() == 1
    panel.receive_event("one", event(status="failed", message="凭据失效", reason="need_login"))
    panel.refresh_steps()
    assert panel.table.item(0, 3).text() == "失败"
    assert panel.table.item(0, 5).text() == "need_login"
    # 不同任务的事件不能借同请求写入任务结果。
    panel.receive_event("one", event("outsider", "foreign"))
    assert ("one", "outsider", "foreign") not in panel.steps
    panel.search.setText("不存在的事件")
    assert panel.log_view.toPlainText() == ""
    panel.clear_logs()
    assert not panel.logs
    panel.deleteLater()
    qapp.processEvents()


def test_run_panel_completion_uses_result_snapshot(qapp):
    panel = RunPanel()
    panel.register_job("one", "账号甲", ("daily",))
    payload = {"task_id": "daily", "data": {"chain": {"hit": "browser", "steps": [
        {"id": "http", "kind": "http", "status": "failed"},
        {"id": "browser", "kind": "browser", "title": "浏览器签到", "status": "success", "duration_seconds": 4},
    ]}}}
    panel.complete("one", [payload])
    payload["data"]["chain"]["steps"][1]["title"] = "后来编辑的草稿"
    assert panel.table.item(1, 1).text() == "浏览器签到"
    assert chain_summary({"data": {"chain": {"hit": "http", "steps": [{"id": "http", "title": "HTTP"}]}}}) == "完成方式：HTTP"
    panel.deleteLater()
    qapp.processEvents()
