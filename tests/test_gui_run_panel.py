"""运行监视器：按请求/任务隔离步骤与日志，只读运行快照，不伪造成功。"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6", reason="GUI 专项测试需要可选 PySide6")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QDialog  # noqa: E402

from gui.run_panel import RunPanel, chain_summary, show_chain_record  # noqa: E402


@pytest.fixture(scope="module")
def qt_app():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def panel(qt_app):
    widget = RunPanel()
    yield widget
    widget.close()
    widget.deleteLater()
    qt_app.processEvents()


def event(task="daily", step="http", status="running", *, message="", kind="http", reason=None):
    fields = {"step": step, "kind": kind, "status": status, "task": task}
    if reason is not None:
        fields["reason"] = reason
    return {"stage": "chain", "message": message, "task": task, "fields": fields}


def rows(panel: RunPanel) -> list[list[str]]:
    return [
        [panel.table.item(row, col).text() for col in range(panel.table.columnCount())]
        for row in range(panel.table.rowCount())
    ]


def test_events_only_land_in_their_own_request_and_declared_tasks(panel):
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.receive_event("job-a", event(message="步骤开始"))
    panel.receive_event("unknown-job", event(task="daily", step="browser"))
    panel.receive_event("job-a", event(task="quiz", step="http"))
    panel.refresh_steps()

    assert [row[0] for row in rows(panel)] == ["daily"], "未注册请求与未声明任务的事件都不能进入表格"
    assert [row[1] for row in rows(panel)] == ["http"]
    assert panel.table.rowCount() == 1


@pytest.mark.parametrize("payload", [
    {"fields": {"step": "http"}},                    # 缺任务
    {"task": "daily", "fields": {}},                 # 缺步骤
    {"task": "daily", "fields": {"step": 7}},        # 步骤类型不对
    "not-a-dict",
])
def test_malformed_events_are_dropped_without_creating_rows(panel, payload):
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.receive_event("job-a", payload)
    panel.refresh_steps()

    assert panel.table.rowCount() == 0


def test_running_step_then_failure_and_fallback_are_both_visible(panel):
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.receive_event("job-a", event(message="开始"))
    panel.receive_event("job-a", event(status="failed", message="登录失效", reason="need_login"))
    panel.receive_event("job-a", event(step="browser", kind="browser", message="浏览器接管"))
    panel.refresh_steps()

    table = rows(panel)
    assert [row[1] for row in table] == ["http", "browser"]
    assert table[0][2] == "HTTP" and table[1][2] == "浏览器"
    assert table[0][3] == "失败" and table[0][5] == "need_login"
    assert table[1][3] == "运行中"
    assert "当前步骤" in panel.summary.text() and "browser" in panel.summary.text()


def test_completion_replaces_live_rows_with_the_result_snapshot(panel):
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.receive_event("job-a", event(message="开始"))
    panel.complete("job-a", [{
        "task_id": "daily",
        "data": {"chain": {"hit": "browser", "summary": "http=失败 → browser=成功", "steps": [
            {"id": "http", "kind": "http", "title": "HTTP 签到", "status": "failed",
             "reason": "need_login", "duration_seconds": 1.25, "message": "登录失效"},
            {"id": "browser", "kind": "browser", "title": "浏览器签到", "status": "success",
             "duration_seconds": 12.5, "message": "签到成功"},
        ]}},
    }])

    table = rows(panel)
    assert [row[1] for row in table] == ["HTTP 签到", "浏览器签到"]
    assert [row[3] for row in table] == ["失败", "成功"]
    assert [row[4] for row in table] == ["1.2s", "12.5s"]
    assert "当前步骤" not in panel.summary.text(), "结束后不应继续显示运行中的步骤"
    assert "运行快照" in panel.summary.text()


def test_worker_failure_marks_running_steps_without_inventing_success(panel):
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.receive_event("job-a", event(message="开始"))
    panel.fail("job-a", "子进程异常退出")

    table = rows(panel)
    assert table[0][3] == "失败"
    assert table[0][5] == "worker_error"
    assert table[0][6] == "子进程异常退出"
    assert all(row[3] != "成功" for row in table)


def test_logs_and_steps_are_filtered_by_request_task_and_search(panel):
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.register_job("job-b", "账号乙", ("quiz",))
    panel.receive_event("job-a", event(message="甲开始"))
    panel.receive_event("job-b", event(task="quiz", step="http", message="乙开始"))
    panel.append_log("job-a", "甲的日志行")
    panel.append_log("job-b", "乙的日志行")
    panel.refresh_steps()
    assert panel.table.rowCount() == 2

    panel.select_job("job-b")
    assert [row[0] for row in rows(panel)] == ["quiz"]
    assert "乙的日志行" in panel.log_view.toPlainText()
    assert "甲的日志行" not in panel.log_view.toPlainText()

    panel.job_filter.setCurrentIndex(0)
    panel.search.setText("甲的")
    assert panel.log_view.toPlainText().strip() == "甲的日志行"

    panel.search.clear()
    index = panel.task_filter.findData("quiz")
    panel.task_filter.setCurrentIndex(index)
    assert [row[0] for row in rows(panel)] == ["quiz"]


def test_clear_logs_keeps_step_records(panel):
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.receive_event("job-a", event(message="开始"))
    panel.append_log("job-a", "一行日志")
    panel.clear_logs()

    assert panel.log_view.toPlainText() == ""
    panel.refresh_steps()
    assert panel.table.rowCount() == 1


@pytest.mark.parametrize("record,expected", [
    (None, ""),
    ({"data": {}}, ""),
    ({"data": {"chain": {"hit": "browser", "steps": [{"id": "browser", "title": "浏览器签到"}]}}}, "完成方式：浏览器签到"),
    ({"data": {"chain": {"hit": "", "summary": "http=失败(need_login)"}}}, "http=失败(need_login)"),
    ({"data": {"chain": {"hit": ""}}}, "访问链未完成"),
])
def test_chain_summary_reports_the_step_that_actually_completed(record, expected):
    assert chain_summary(record) == expected


def test_runtime_graph_only_links_the_fallback_that_really_happened(qt_app, monkeypatch):
    shown: dict = {}

    class Recorder(QDialog):
        def __init__(self, value, template=None, parent=None, **kwargs):
            super().__init__(parent)
            shown["value"] = value
            shown["kwargs"] = kwargs

        def exec(self):  # noqa: A003 - 匹配 QDialog 接口
            return QDialog.DialogCode.Accepted

    from gui import chain_editor

    monkeypatch.setattr(chain_editor, "ChainEditorDialog", Recorder)
    show_chain_record({"data": {"chain": {"steps": [
        {"id": "http", "kind": "http", "title": "HTTP", "status": "failed"},
        {"id": "browser", "kind": "browser", "title": "浏览器", "status": "success"},
        {"id": "spare", "kind": "http", "title": "备用", "status": "not_run"},
    ]}}})

    nodes = {item["id"]: item for item in shown["value"]["steps"]}
    assert nodes["http"]["on_failure"] == "browser", "失败后确实回退过，连线保留"
    assert nodes["browser"]["on_failure"] == "", "成功步骤不连向未执行的备用步骤"
    assert nodes["spare"]["on_failure"] == ""
    assert shown["kwargs"]["read_only"] is True
    assert [row["id"] for row in shown["kwargs"]["runtime_steps"]] == ["http", "browser", "spare"]


def test_runtime_graph_is_not_opened_without_step_records(qt_app, monkeypatch):
    from gui import chain_editor

    def refuse(*_args, **_kwargs):
        raise AssertionError("没有步骤记录时不应打开执行图")

    monkeypatch.setattr(chain_editor, "ChainEditorDialog", refuse)
    show_chain_record({"data": {"chain": {"steps": []}}})
    show_chain_record(None)


def test_graph_button_follows_available_rows(panel):
    assert panel.graph_button.isEnabled() is False
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.receive_event("job-a", event(message="开始"))
    panel.refresh_steps()
    assert panel.graph_button.isEnabled() is True
