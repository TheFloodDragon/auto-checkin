"""运行监视器：按请求/任务隔离步骤与日志，只读运行快照，不伪造成功。"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6", reason="GUI 专项测试需要可选 PySide6")

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


def test_challenge_rejection_visible_once_before_worker_finishes(panel):
    panel.register_job("job-a", "账号甲", ("daily",))
    payload = {"stage": "solve", "task": "daily", "message": "Cloudflare 明确拒绝", "fields": {
        "event": "challenge_status", "status": "rejected", "step": "browser", "generation": "g1"}}
    assert panel.receive_event("job-a", payload) is True
    assert "Cloudflare 明确拒绝" in panel.challenge_notice.text()
    assert panel.receive_event("job-a", payload) is False
    assert "job-a" not in panel._finished_jobs
    panel.refresh_steps()
    assert rows(panel)[0][5] == "challenge_rejected"


def test_rejection_without_step_shows_notice_not_an_invented_step(panel):
    panel.register_job("job-a", "账号甲", ("daily",), account_id="a")
    payload = {"account": "a", "stage": "solve", "task": "daily", "fields": {
        "event": "challenge_status", "status": "rejected", "generation": "g1"}}
    assert panel.receive_event("job-a", payload) is True
    panel.refresh_steps()
    assert "账号甲 / daily" in panel.challenge_notice.text()
    assert panel.table.rowCount() == 0
    assert panel.receive_event("job-a", {**payload, "account": "other"}) is False


def test_gui_preview_reads_current_task_scoped_learning(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from config import schema
    from core.flow import FlowPlan
    from runtime import engine, capabilities
    from templates import registry
    from gui import worker, core

    spec = schema.parse_document({"version": 3, "accounts": [{"id": "a", "base_url": "https://a.invalid",
        "template": "newapi", "tasks": [{"id": "first"}, {"id": "second"}]}]}).accounts[0]
    overlay = Mock()
    overlay.apply.return_value = SimpleNamespace(credentials=spec.credentials, learned_flow={"execute": "legacy_wrong"}, health={})
    overlay.explain.return_value = {}
    expected = [engine.learning_scopes(spec, task, registry.get("newapi").manifest,
                configured=engine._flow_config(spec, task)) for task in spec.tasks]
    learned = {expected[0][1]: "first-scoped", expected[1][1]: "second-scoped"}
    overlay.learned_for.side_effect = lambda account, login_scope, task_scope: {"execute": learned[task_scope]}
    monkeypatch.setattr(worker, "_account_request", lambda _request: (spec, ("first", "second")))
    monkeypatch.setattr(worker, "_overlay", lambda _request: overlay)
    monkeypatch.setattr(capabilities, "detect", lambda _account: frozenset())
    monkeypatch.setattr(core, "proxy_status", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(engine, "relogin_owns_login", lambda *_args: False)
    monkeypatch.setattr(FlowPlan, "resolve", lambda **kwargs: SimpleNamespace(
        to_payload=lambda: dict(kwargs["learned"]), describe=lambda: "scoped preview"))
    result = worker._explain({"account": {}}, worker.Redactor({}))
    assert [task["flow"]["execute"] for task in result["tasks"]] == ["first-scoped", "second-scoped"]
    assert [(call.args[0], call.kwargs) for call in overlay.learned_for.call_args_list] == [
        ("a", {"login_scope": login_key, "task_scope": task_key}) for login_key, task_key in expected]


def test_worker_forwards_rejection_once_before_completion(qt_app):
    from gui.workers import JobRunner, _Job
    from gui.worker import Redactor
    from runtime.events import RunEvent, EventLevel

    runner = JobRunner()
    job = _Job("job-a", "", "run", b"", Redactor({}))
    received, progress, complete = [], [], []
    runner.event_received.connect(lambda *args: received.append(args))
    runner.progress.connect(lambda *args: progress.append(args))
    runner.completed.connect(lambda *args: complete.append(args))
    line = RunEvent("solve", "Cloudflare 明确拒绝", level=EventLevel.WARNING, account="a", task="daily",
                    fields={"event": "challenge_status", "status": "rejected", "step": "login", "generation": "g1"}).to_line()
    runner._log_line(job, line)
    runner._log_line(job, line)
    assert len(received) == len(progress) == 1
    assert complete == []
    runner.deleteLater()


def test_challenge_pending_updates_progress_without_rejection_notice(panel):
    panel.register_job("job-a", "账号甲", ("daily",))
    assert panel.receive_event("job-a", {"stage": "solve", "task": "daily", "message": "等待验证完成", "fields": {
        "event": "challenge_status", "status": "click_unconfirmed", "step": "browser", "generation": "g1"}}) is False
    panel.refresh_steps()
    assert rows(panel)[0][3] == "运行中"
    assert panel.challenge_notice.text() == ""


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


def test_independent_task_logs_do_not_require_chain_steps(panel):
    panel.register_job("job-a", "账号甲", ("daily", "chop_tree"))
    for task, line in (("daily", "签到失败"), ("chop_tree", "砍树成功")):
        panel.receive_event("job-a", {"stage": "execute", "task": task, "fields": {}, "message": line})
        panel.append_log("job-a", line)
    panel.receive_event("job-a", {"stage": "run", "task": "", "message": "账号结束"})
    panel.append_log("job-a", "账号结束")
    panel.task_filter.setCurrentIndex(panel.task_filter.findData("chop_tree"))
    assert panel.log_view.toPlainText() == "砍树成功"
    assert panel.table.rowCount() == 0, "普通任务日志不能伪造访问链步骤"


def test_retry_clears_previous_failure_and_restarts_duration(panel, monkeypatch):
    from gui import run_panel

    clock = [10.0]
    monkeypatch.setattr(run_panel.time, "monotonic", lambda: clock[0])
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.receive_event("job-a", event())
    clock[0] = 15.0
    panel.receive_event("job-a", event(status="failed", reason="network_error"))
    clock[0] = 30.0
    panel.receive_event("job-a", event(message="重试开始"))
    panel.refresh_steps()
    assert rows(panel)[0][3:6] == ["运行中", "0.0s", "—"]
    clock[0] = 32.0
    panel.receive_event("job-a", event(status="success", message="重试成功"))
    panel.refresh_steps()
    assert rows(panel)[0][3:6] == ["成功", "2.0s", "—"]


def test_snapshot_removes_obsolete_live_steps(panel):
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.receive_event("job-a", event(step="obsolete"))
    panel.complete("job-a", [{"task_id": "daily", "data": {"chain": {"steps": [
        {"id": "actual", "kind": "http", "status": "failed", "reason": "need_login"},
    ]}}}])
    assert [row[1] for row in rows(panel)] == ["actual"]
    assert "当前步骤" not in panel.summary.text()


def test_missing_final_trace_does_not_leave_steps_running_or_invent_success(panel):
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.receive_event("job-a", event())
    panel.complete("job-a", [{"task_id": "daily", "verdict": "success", "data": {}}])
    assert rows(panel)[0][3] not in ("运行中", "成功")
    assert rows(panel)[0][5] == "incomplete_trace"
    assert "当前步骤" not in panel.summary.text()


def test_finished_jobs_ignore_late_events(panel):
    panel.register_job("job-a", "账号甲", ("daily",))
    panel.receive_event("job-a", event())
    panel.fail("job-a", "后台异常")
    panel.receive_event("job-a", event(message="迟到事件"))
    panel.refresh_steps()
    assert rows(panel)[0][3] == "失败"
    assert rows(panel)[0][6] == "后台异常"
