"""v3 工作台整窗回归：临时配置、Qt offscreen 和不访问网络的执行替身。"""

from __future__ import annotations

import ast
import json
import os
import time
from copy import deepcopy
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication

from core.timebase import business_date, utc_iso
from gui import config_store, core


class OfflineRunner(QObject):
    started = Signal(str)
    progress = Signal(str, str)
    completed = Signal(str, object)
    failed = Signal(str, str)
    idle = Signal()
    changed = Signal()

    def __init__(self, parent=None, max_workers=4):
        super().__init__(parent)
        self.requests = {}
        self.states = {}
        self.groups = {}
        self.controls = []
        self.closed = False

    @property
    def active_count(self):
        return sum(state == "running" for state in self.states.values())

    @property
    def pending_count(self):
        return sum(state == "queued" for state in self.states.values())

    @property
    def busy(self):
        return bool(self.states)

    def submit(self, job_id, request, *, group=""):
        assert not self.closed
        self.requests[job_id] = deepcopy(request)
        self.groups[job_id] = group
        self.states[job_id] = "queued"
        self.changed.emit()

    def start(self, job_id):
        self.states[job_id] = "running"
        self.started.emit(job_id)
        self.changed.emit()

    def complete(self, job_id, result):
        self.states.pop(job_id, None)
        self.completed.emit(job_id, deepcopy(result))
        self.changed.emit()
        if not self.busy:
            self.idle.emit()

    def fail(self, job_id, error="离线模拟进程错误"):
        self.states.pop(job_id, None)
        self.failed.emit(job_id, error)
        self.changed.emit()
        if not self.busy:
            self.idle.emit()

    def cancel_pending(self):
        keys = [key for key, state in self.states.items() if state == "queued"]
        for key in keys:
            self.states.pop(key)
        self.changed.emit()
        return keys

    def complete_capture(self, job_id):
        self.controls.append((job_id, "finish"))

    def cancel_capture(self, job_id):
        self.controls.append((job_id, "cancel"))
        self.fail(job_id, "CaptureCancelled")

    def shutdown(self, wait_ms=0):
        if self.busy:
            return False
        self.closed = True
        return True


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def wait(qapp, predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        qapp.processEvents()
    qapp.processEvents()
    assert predicate(), "等待界面后台回调超时"


def example():
    return {
        "version": 3,
        "metadata": {"owner": "testing", "future": [1, {"retain": True}]},
        "accounts": [
            {
                "id": "alpha", "name": "相同显示名", "base_url": "https://a.invalid", "template": "newapi",
                "login": {"method": "cookie", "future": {"retain": 9}},
                "credentials": {"cookie": "session=LOCAL-TEST-SECRET", "user_id": 17, "future": "keep"},
                "tasks": [
                    {"id": "first", "method": "http_api", "future": {"keep": [1, 2]}},
                    {"id": "second", "template": "scripts/tasks/100xlabs.py", "method": "script",
                     "depends_on": ["first"], "policy": None, "args": {"future": {"nested": True}}},
                    {"id": "third", "depends_on": ["second"], "flow": {"confirm": "off"}},
                ],
                "network": {"verify_ssl": False, "future": {"value": 3}},
                "policy": {"allow_browser": False, "future": "keep"},
                "display": {"label": "任务"}, "future": {"x": 1},
            },
            {"id": "beta", "name": "相同显示名", "base_url": "https://b.invalid",
             "template": "auto", "tasks": [{"id": "heartbeat", "args": {"value": False}}]},
            {"id": "disabled", "name": "停用账号", "base_url": "https://c.invalid", "enabled": False,
             "tasks": [{"id": "daily", "policy": {}}]},
        ],
        "oauth_states": {"github": {"future": {"keep": True}, "accounts": {
            "work": {"state": "OPAQUE-SHARED-STATE", "username": "tester", "future": "keep"},
        }}},
    }


@pytest.fixture
def window(qapp, tmp_path, monkeypatch):
    from gui import app as module
    config = tmp_path / "ACCOUNTS.json"
    config.write_text(json.dumps(example(), ensure_ascii=False), encoding="utf-8")
    monkeypatch.setattr(module, "JobRunner", OfflineRunner)
    monkeypatch.setattr(module.theme, "load_pref", lambda key, default=None: default)
    monkeypatch.setattr(module.theme, "save_pref", lambda *args: None)
    obj = module.App(config_path=config, results_dir=tmp_path / "results", discover_templates=False)
    monkeypatch.setattr(obj, "_confirm", lambda *args: True)
    original_error = obj._error
    monkeypatch.setattr(obj, "_error", lambda title, error, **kwargs: original_error(title, error, dialog=False))
    wait(qapp, lambda: not obj._loading and not obj.storage.busy)
    assert not obj._load_failed
    yield obj
    for job_id in list(obj.runner.states):
        obj.runner.fail(job_id, "测试结束")
    wait(qapp, lambda: not obj.storage.busy)
    obj.close()
    wait(qapp, lambda: obj._allow_close)
    obj.deleteLater()
    qapp.processEvents()


def edit(window, transform):
    value = window.editor.value()
    transform(value)
    window.editor.set_account(value)
    window.editor.changed.emit()
    return window.editor.value()


def record(account_id, task_id, verdict="success", **extra):
    return {"account_id": account_id, "task_id": task_id, "name": "提交时名称", "verdict": verdict,
            "label": "自定义结果", "reason": "custom_reason", "text": "命中 3 次", "text_label": "抽奖",
            "extras": [["次数", "3"]], "business_date": business_date(), "generated_at": utc_iso(), **extra}


def run_payload(account_id, task_ids, verdict="success"):
    return {"schema_version": 2, "account_id": account_id, "generated_at": utc_iso(),
            "results": [record(account_id, task_id, verdict) for task_id in task_ids]}


def test_gui_core_references_exist():
    missing = []
    for path in Path("gui").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "core":
                if not hasattr(core, node.attr):
                    missing.append(f"{path}:{node.lineno}:{node.attr}")
    assert not missing


def test_window_loads_all_accounts_without_mutation(window):
    before = deepcopy(window.payload)
    assert window.nav.labels() == ["账号", "运行", "代理", "登录态", "模板"]
    assert window.workspace.count() == 5
    for account in before["accounts"]:
        assert window.select_account(account["id"])
        assert window.editor.value() == account
        assert window._flush_editor()
    assert window.payload == before == example()
    assert not window._dirty
    assert window.account_list.count() == 3
    assert window.metric_values[1].text() == "4"


def test_save_preserves_all_tasks_unknown_fields_and_shared_metadata(window, qapp):
    edit(window, lambda value: value.update(name="新名称"))
    expected = deepcopy(window.payload)
    assert window._dirty
    window._save()
    wait(qapp, lambda: not window._saving and not window.storage.busy)
    assert json.loads(window.config_path.read_text(encoding="utf-8")) == expected
    assert expected["accounts"][0]["tasks"][1]["args"]["future"] == {"nested": True}
    assert expected["accounts"][0]["credentials"]["user_id"] == 17
    assert not window._dirty


def test_edit_during_background_save_stays_dirty(window, qapp, monkeypatch):
    operations = []
    monkeypatch.setattr(window.storage, "submit", lambda operation, callback=None: operations.append((operation, callback)))
    edit(window, lambda value: value.update(name="将写入磁盘"))
    window._save()
    assert window._saving
    edit(window, lambda value: value.update(name="保存期间继续编辑"))
    operation, callback = operations.pop()
    callback(operation(), None)
    assert window._dirty
    assert window._saved_payload["accounts"][0]["name"] == "将写入磁盘"
    assert window.accounts[0]["name"] == "保存期间继续编辑"
    assert not window._saving


def test_external_modification_is_not_overwritten(window, qapp):
    edit(window, lambda value: value.update(name="本地草稿"))
    external = example()
    external["metadata"]["owner"] = "external-writer"
    window.config_path.write_text(json.dumps(external), encoding="utf-8")
    window._save()
    wait(qapp, lambda: not window._saving and not window.storage.busy)
    assert json.loads(window.config_path.read_text(encoding="utf-8")) == external
    assert window.accounts[0]["name"] == "本地草稿"
    assert window._dirty
    assert "外部修改" in window.banner.text()


def test_reload_failure_keeps_draft_and_blocks_save(window, qapp):
    edit(window, lambda value: value.update(name="不能丢失"))
    before = deepcopy(window.payload)
    window.config_path.write_text("{ invalid-json", encoding="utf-8")
    window._reload()
    wait(qapp, lambda: not window._loading and not window.storage.busy)
    assert window.payload == before
    assert window._load_failed and not window.save_button.isEnabled()
    window._save()
    assert window.config_path.read_text(encoding="utf-8") == "{ invalid-json"


def test_missing_config_has_safe_onboarding(window, qapp, tmp_path):
    missing = tmp_path / "new-config.json"
    window._reload(path=missing)
    wait(qapp, lambda: not window._loading and not window.storage.busy)
    assert not window.accounts and not window._load_failed
    assert not missing.exists()
    window._add_account()
    assert len(window.accounts) == 1
    assert window.accounts[0]["tasks"][0]["id"] == "daily"
    assert window._dirty


def test_invalid_editor_cannot_switch_or_save(window, monkeypatch):
    saved = deepcopy(window.payload)
    def invalid():
        raise ConfigError("任务 timeout 必须是整数")
    from core.errors import ConfigError
    monkeypatch.setattr(window.editor, "value", invalid)
    window.editor.changed.emit()
    assert window._dirty
    assert not window.select_account("beta")
    window._save()
    assert window.payload == saved and window.selected_id == "alpha"
    assert "timeout" in window.editor_error.text()


def test_search_and_move_use_stable_identity(window):
    window.select_account("beta")
    window.search.setText("b.invalid")
    assert window.account_list.count() == 1
    assert window.selected_id == "beta"
    window._move_account(-1)
    assert window.accounts[0]["id"] == "beta"
    assert window.editor.value()["id"] == "beta"
    window.search.clear()
    assert window.account_list.count() == 3


def test_duplicate_generates_account_id_preserves_task_graph(window):
    original = deepcopy(window.accounts[0])
    window._duplicate_account()
    copied = window._account()
    assert copied["id"] != original["id"]
    assert copied["tasks"] == original["tasks"]
    assert copied["credentials"] == original["credentials"]
    copied["tasks"][1]["args"]["future"]["nested"] = False
    assert window.accounts[0]["tasks"][1]["args"]["future"]["nested"] is True


def test_run_selected_task_uses_dependency_closure_and_frozen_draft(window):
    edit(window, lambda value: value["credentials"].update(cookie=""))
    window.editor.run_requested.emit("third")
    request = next(iter(window.runner.requests.values()))
    assert request["only_tasks"] == ["first", "second", "third"]
    assert request["explicit"] == ["cookie"]
    assert request["account"]["credentials"]["cookie"] == ""
    assert request["oauth_states"] == example()["oauth_states"]
    assert request["config_path"] == str(window.config_path)
    assert next(iter(window.runner.groups.values())) == "https://a.invalid"
    edit(window, lambda value: value["tasks"][1].update(title="之后的编辑"))
    assert "title" not in request["account"]["tasks"][1]
    assert window._dirty


def test_run_all_skips_disabled_and_busy_accounts_without_duplicates(window):
    window._run_all()
    assert len(window.runner.requests) == 2
    assert {request["account"]["id"] for request in window.runner.requests.values()} == {"alpha", "beta"}
    window._run_all()
    assert len(window.runner.requests) == 2


def test_task_results_keep_snapshot_identity_and_custom_fields(window):
    window._run_current()
    job_id = next(iter(window.runner.requests))
    window.runner.start(job_id)
    edit(window, lambda value: value.update(name="运行时改名"))
    window._delete_account()
    window.runner.complete(job_id, run_payload("alpha", ["first", "second", "third"], "no_effect"))
    assert window._account("alpha") is None
    assert len(window.store.records("alpha")) == 3
    assert not window.store.records("beta")
    assert window.results_table.rowCount() == 3
    assert "抽奖" in window.results_table.item(0, 4).text()
    assert "extras" in window.result_detail.toPlainText()
    assert window.metric_values[3].text() == "0"


def test_wrong_owner_or_missing_task_results_rejected(window):
    window._run_current()
    job_id = next(iter(window.runner.requests))
    window.runner.complete(job_id, run_payload("beta", ["first"]))
    assert not window.store.records()
    assert window._jobs[job_id].state == "error"
    window._run_current()
    job_id = list(window.runner.requests)[-1]
    window.runner.complete(job_id, run_payload("alpha", ["first"]))
    assert not window.store.records()
    assert window._jobs[job_id].state == "error"


@pytest.mark.parametrize("malformation", ["wrong-row-owner", "duplicate-task"])
def test_result_rows_cannot_change_owner_or_duplicate_tasks(window, malformation):
    window._run_current()
    job_id = next(iter(window.runner.requests))
    payload = run_payload("alpha", ["first", "second", "third"])
    if malformation == "wrong-row-owner":
        payload["results"][0]["account_id"] = "beta"
    else:
        payload["results"].append(deepcopy(payload["results"][0]))
    window.runner.complete(job_id, payload)
    assert not window.store.records()
    assert window._jobs[job_id].state == "error"


def test_stop_pending_keeps_active_job_and_no_fake_business_result(window):
    window._run_all()
    job_ids = list(window.runner.requests)
    window.runner.start(job_ids[0])
    window._stop_pending()
    assert window._jobs[job_ids[0]].state == "running"
    assert window._jobs[job_ids[1]].state == "cancelled"
    assert not window.store.records()
    assert window.runner.busy


def test_preview_is_not_execution_and_marks_stale_draft(window):
    window._preview()
    job_id = next(iter(window.runner.requests))
    assert window.runner.requests[job_id]["action"] == "explain"
    window.runner.complete(job_id, {"account_id": "alpha", "tasks": [{"task_id": "first", "describe": "只读预览"}]})
    assert "只读预览" in window.preview_view.toPlainText()
    assert not window.store.records()
    edit(window, lambda value: value.update(template="auto"))
    assert "已经改变" in window.preview_view.toPlainText()


def test_export_keeps_second_task_unknown_metadata_without_mutating_draft(window, monkeypatch):
    before = deepcopy(window.payload)
    window._export_secret()
    text = QApplication.clipboard().text()
    exported = json.loads(text)
    assert len(text.splitlines()) == 1
    assert text == json.dumps(exported, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    assert exported["accounts"] == before["accounts"][:2]
    assert exported["accounts"][0]["tasks"] == before["accounts"][0]["tasks"]
    assert exported["metadata"] == before["metadata"]
    assert exported["oauth_states"] == before["oauth_states"]
    assert window.payload == before and not window._dirty
    monkeypatch.setattr(window, "_confirm", lambda *args: False)
    QApplication.clipboard().setText("unchanged")
    window._export_secret()
    assert QApplication.clipboard().text() == "unchanged"


def test_export_keeps_browser_state_and_escapes_embedded_newlines(window):
    state = '{"cookies":[],\n"origins":[]}'
    edit(window, lambda value: value["credentials"].update(browser_state=state))
    before, saved = deepcopy(window.payload), window.config_path.read_bytes()
    window._export_secret()
    text = QApplication.clipboard().text()
    assert len(text.splitlines()) == 1
    assert json.loads(text)["accounts"][0]["credentials"]["browser_state"] == state
    assert window.payload == before and window._dirty
    assert window.config_path.read_bytes() == saved


def test_export_rejects_oversized_secret_without_changing_clipboard_or_draft(window):
    from config.secrets import SECRET_SIZE_LIMIT

    state = "STATE" * SECRET_SIZE_LIMIT
    edit(window, lambda value: value["credentials"].update(browser_state=state))
    before, saved = deepcopy(window.payload), window.config_path.read_bytes()
    QApplication.clipboard().setText("unchanged")
    window._export_secret()
    assert QApplication.clipboard().text() == "unchanged"
    message = window.status_message.text()
    assert "64 KiB" in message and "browser_state" in message and "多个 Secret" in message
    assert state not in message + window.log_view.toPlainText()
    assert window.payload == before and window.config_path.read_bytes() == saved


def test_import_appends_unique_account_ids_and_keeps_all_tasks(window):
    incoming = deepcopy(window.accounts[0])
    window._import_text(json.dumps(incoming))
    assert len(window.accounts) == 4
    assert window.accounts[-1]["id"] == "alpha-2"
    assert window.accounts[-1]["tasks"] == incoming["tasks"]
    assert window.selected_id == "alpha-2" and window._dirty


def test_site_capture_is_explicit_and_targets_original_account(window):
    before = window.config_path.read_bytes()
    window._capture_site()
    job_id = window._capture_job
    window.runner.start(job_id)
    window._finish_capture()
    assert window.runner.controls[-1] == (job_id, "finish")
    window.select_account("beta")
    window.runner.complete(job_id, {"ok": True, "credentials": {"browser_state": "CAPTURED-STATE", "access_token": "CAPTURED-TOKEN"}})
    assert "browser_state" not in window._account("alpha")["credentials"]
    assert not window.store.records()
    window._apply_capture()
    assert window._account("alpha")["credentials"]["browser_state"] == "CAPTURED-STATE"
    assert not window._account("beta").get("credentials")
    assert window._dirty
    assert window.config_path.read_bytes() == before
    assert "CAPTURED-STATE" not in window.log_view.toPlainText()


def test_deleted_capture_target_never_writes_to_new_selection(window):
    window._capture_site()
    job_id = window._capture_job
    window.runner.start(job_id)
    window._delete_account()
    window.runner.complete(job_id, {"ok": True, "credentials": {"browser_state": "PRIVATE-CAPTURE"}})
    window._apply_capture()
    assert window._account("alpha") is None
    assert all(not account.get("credentials") for account in window.accounts)
    assert not window._capture_job


def test_oauth_capture_requires_provider_and_preserves_metadata(window):
    window._capture_oauth()
    assert not window.runner.requests
    index = window.oauth_provider.findData("github")
    window.oauth_provider.setCurrentIndex(index)
    window.oauth_account.setText("work")
    window._capture_oauth()
    job_id = window._capture_job
    window.runner.start(job_id)
    window.runner.complete(job_id, {"ok": True, "state": "NEW-OAUTH-STATE", "username": "new-name"})
    window._apply_capture()
    entry = window.payload["oauth_states"]["github"]["accounts"]["work"]
    assert entry["state"] == "NEW-OAUTH-STATE" and entry["future"] == "keep"
    assert window.payload["oauth_states"]["github"]["future"] == {"keep": True}
    assert not window.store.records()


def test_cancel_capture_does_not_write_credentials(window):
    before = deepcopy(window.payload)
    window._capture_site()
    job_id = window._capture_job
    window.runner.start(job_id)
    window._cancel_capture()
    assert (job_id, "cancel") in window.runner.controls
    assert window.payload == before
    assert not window._capture_job
    assert window._jobs[job_id].state == "cancelled"


def test_logs_redact_known_secrets(window):
    window._run_current()
    job_id = next(iter(window.runner.requests))
    window.runner.progress.emit(job_id, "无标签 LOCAL-TEST-SECRET 和 OPAQUE-SHARED-STATE")
    log = window.log_view.toPlainText()
    assert "LOCAL-TEST-SECRET" not in log and "OPAQUE-SHARED-STATE" not in log


def test_close_waits_for_active_requests_and_storage(window, qapp):
    window.show()
    window._run_all()
    active, pending = list(window.runner.requests)
    window.runner.start(active)
    window.close()
    assert window._closing and not window._allow_close
    assert window.isVisible()
    assert window._jobs[pending].state == "cancelled"
    window.runner.complete(active, run_payload("alpha", ["first", "second", "third"]))
    wait(qapp, lambda: window._allow_close)
    assert not window.isVisible()
    result_path = window.store.results_dir / "gui_results.json"
    assert len(json.loads(result_path.read_text(encoding="utf-8"))["results"]) == 3


def test_cancel_close_keeps_workbench_usable(window):
    window._run_current()
    job_id = next(iter(window.runner.requests))
    window.runner.start(job_id)
    window.close()
    assert window._closing
    window._abort_close()
    assert not window._closing and window.workspace.isEnabled()
    assert window.runner.busy and not window.runner.closed


def account_card(window, account_id):
    from PySide6.QtCore import Qt
    from gui.widgets import ACCOUNT_CARD_ROLE

    for index in range(window.account_list.count()):
        item = window.account_list.item(index)
        if item.data(Qt.ItemDataRole.UserRole) == account_id:
            return item.data(ACCOUNT_CARD_ROLE)
    raise AssertionError("账号卡片不存在")


def test_account_overview_is_default_and_has_clear_empty_state(window):
    assert window.account_stack.currentIndex() == 0
    assert window.overview_button.isChecked()
    assert window.latest_text.text() == "还没有返回结果"
    assert not window.copy_return_button.isEnabled()
    assert not window.latest_details_button.isEnabled()
    assert set(window.task_return_labels) == {"first", "second", "third"}
    assert all("第一次返回" in label.text() for label in window.task_return_labels.values())
    assert not account_card(window, "alpha")["has_result"]


def test_account_latest_and_each_task_update_on_completion_without_leaving_page(window):
    window._run_current()
    job_id = next(iter(window.runner.requests))
    result = run_payload("alpha", ["first", "second", "third"])
    for row, text, label in zip(result["results"], ["$128.54", "抽中 3 次", "会话已续期"], ["账户余额", "抽奖", "状态"]):
        row.update(text=text, text_label=label)
    window.runner.complete(job_id, result)
    assert window.workspace.currentIndex() == 0
    assert window.latest_text.text() == "会话已续期"
    assert "third" in window.latest_caption.text()
    assert "会话已续期" in account_card(window, "alpha")["summary"]
    assert "$128.54" in window.task_return_labels["first"].text()
    assert "抽中 3 次" in window.task_return_labels["second"].text()
    assert not window._dirty


def test_latest_failed_message_replaces_old_success_text(window):
    from datetime import timedelta
    from core import timebase

    old = run_payload("alpha", ["first"])
    old_stamp = (timebase.utc_now() - timedelta(seconds=5)).isoformat()
    old["generated_at"] = old_stamp
    old["results"][0].update(generated_at=old_stamp, text="$100.00")
    window.store.apply(old)
    failed = run_payload("alpha", ["first"], "failed")
    failed["results"][0].update(text="", message="登录状态失效，请重新登录", label="登录失效")
    window.store.apply(failed)
    window._refresh_results()
    assert window.latest_text.text() == "登录状态失效，请重新登录"
    assert "$100.00" not in account_card(window, "alpha")["summary"]
    assert window.latest_badge.property("tone") == "danger"
    assert account_card(window, "alpha")["tone"] == "danger"


def test_latest_is_by_identity_not_duplicate_display_name(window):
    first, second = run_payload("alpha", ["first"]), run_payload("beta", ["heartbeat"])
    first["results"][0]["text"] = "账号甲的余额"
    second["results"][0]["text"] = "账号乙的保活"
    window.store.apply(first)
    window.store.apply(second)
    window._refresh_results()
    assert "账号甲的余额" in account_card(window, "alpha")["summary"]
    assert "账号乙的保活" in account_card(window, "beta")["summary"]
    window.select_account("beta")
    assert window.latest_text.text() == "账号乙的保活"
    window.select_account("alpha")
    edit(window, lambda value: value.update(name="改名后的甲"))
    window._refresh_accounts()
    assert window.latest_text.text() == "账号甲的余额"


def test_latest_history_visible_after_restart_without_today_status(window, qapp):
    from datetime import timedelta
    from core import timebase

    stamp = (timebase.utc_now() - timedelta(days=1)).isoformat()
    value = record("alpha", "second", "failed", text="昨晚的返回文本", generated_at=stamp,
                   business_date=timebase.business_date_of(stamp))
    window.store.apply({"schema_version": 2, "account_id": "alpha", "results": [value]})
    window.store.save()
    window._reload()
    wait(qapp, lambda: not window._loading and not window.storage.busy)
    assert window.latest_text.text() == "昨晚的返回文本"
    assert "历史" in window.latest_meta.text()
    assert "历史" in account_card(window, "alpha")["stamp"]
    assert not window.store.records("alpha")
    assert window.results_table.rowCount() == 0
    assert window.metric_values[3].text() == "0"


def test_refresh_results_loads_history_and_keeps_execution_order(window, qapp):
    from datetime import timedelta
    from core import timebase
    from gui.status_store import ResultStore

    external = ResultStore(window.store.results_dir)
    stamp = (timebase.utc_now() - timedelta(days=1)).isoformat()
    rows = [record("alpha", task, text=task, generated_at=stamp, business_date=timebase.business_date_of(stamp))
            for task in ["third", "first", "second"]]
    external.apply({"schema_version": 2, "account_id": "alpha", "results": rows})
    external.save()
    window._reload_results()
    wait(qapp, lambda: not window.storage.busy)
    assert window.latest_text.text() == "second"
    assert window.store.records() == []


def test_latest_is_kept_visible_while_running_and_after_process_error(window):
    value = run_payload("alpha", ["first"])
    value["results"][0]["text"] = "上次返回仍可参考"
    window.store.apply(value)
    window._refresh_results()
    window._run_current()
    job_id = next(iter(window.runner.requests))
    window.runner.start(job_id)
    assert window.latest_text.text() == "上次返回仍可参考"
    assert "上次返回" in window.account_activity.text()
    window.runner.fail(job_id, "进程意外退出")
    assert window.latest_text.text() == "上次返回仍可参考"
    assert "未生成新结果" in window.account_activity.text()


def test_latest_copy_is_full_plain_text_and_redacted(window):
    from PySide6.QtCore import Qt

    value = run_payload("alpha", ["first"])
    text = "<b>普通文本</b> " + "返回数据" * 450 + " LOCAL-TEST-SECRET"
    value["results"][0]["text"] = text
    window.store.apply(value)
    window._refresh_results()
    assert window.latest_text.textFormat() == Qt.TextFormat.PlainText
    assert len(window.latest_text.text()) <= 1201
    assert "LOCAL-TEST-SECRET" not in window.latest_text.text()
    window._copy_latest_text()
    copied = QApplication.clipboard().text()
    assert copied.startswith("<b>普通文本</b>")
    assert len(copied) > len(window.latest_text.text())
    assert "LOCAL-TEST-SECRET" not in copied
    assert "LOCAL-TEST-SECRET" not in account_card(window, "alpha")["summary"]


def test_configuration_view_still_shows_latest_without_changing_draft(window):
    before = deepcopy(window.payload)
    window.store.apply(run_payload("alpha", ["first"]))
    window._refresh_results()
    window._set_account_mode(1)
    assert window.account_stack.currentWidget() is window.editor
    assert "命中 3 次" in window.account_latest_line.text()
    assert not window.account_latest_line.isHidden()
    window._set_account_mode(0)
    assert window.account_stack.currentIndex() == 0
    assert window.payload == before and not window._dirty


def test_removed_task_does_not_supply_current_account_latest(window):
    result = run_payload("alpha", ["first", "second", "third"])
    for row in result["results"]:
        row["text"] = row["task_id"]
    window.store.apply(result)
    window._refresh_results()
    assert window.latest_text.text() == "third"
    edit(window, lambda value: value["tasks"].pop())
    window._refresh_accounts()
    assert window.latest_text.text() == "second"
    assert "third" not in window.task_return_labels
    assert window.store.latest("alpha", "third") is not None


def test_switch_to_account_without_results_clears_previous_latest(window):
    window.store.apply(run_payload("alpha", ["first"]))
    window._refresh_results()
    window.select_account("beta")
    assert window.latest_text.text() == "还没有返回结果"
    assert not window.copy_return_button.isEnabled()
    assert "命中 3 次" not in account_card(window, "beta")["summary"]


def test_new_account_opens_configuration_instead_of_empty_overview(window):
    window._add_account()
    assert window.account_stack.currentWidget() is window.editor
    assert window.editor.tabs.currentIndex() == 0


def test_actual_config_api_matches_window_baseline(window):
    loaded = config_store.load_configuration(window.config_path)
    assert loaded.revision == window._revision
    assert core.fingerprint(loaded.payload) == window._saved_snapshot


def test_default_startup_discovers_real_manifests_without_executing_accounts(qapp, tmp_path, monkeypatch):
    from gui import app as module

    config = tmp_path / "startup.json"
    config.write_text(json.dumps(example(), ensure_ascii=False), encoding="utf-8")
    before = config.read_bytes()
    monkeypatch.setattr(module.theme, "load_pref", lambda key, default=None: default)
    monkeypatch.setattr(module.theme, "save_pref", lambda *args: None)
    obj = module.App(config_path=config, results_dir=tmp_path / "startup-results")
    monkeypatch.setattr(obj, "_confirm", lambda *args: True)
    try:
        wait(qapp, lambda: not obj._loading and not obj.runner.busy and not obj.storage.busy, timeout=30)
        assert not obj._load_failed
        assert any(item.get("reference") == "newapi" and "error" not in item for item in obj.catalog)
        assert any(item.get("reference") == "sub2api" and "error" not in item for item in obj.catalog)
        assert all(job.action == "templates" for job in obj._jobs.values())
        assert not obj.store.records()
        assert not obj._dirty
        assert config.read_bytes() == before
    finally:
        obj.close()
        wait(qapp, lambda: obj._allow_close, timeout=30)
        obj.deleteLater()
        qapp.processEvents()


def test_safe_reuses_redactor_until_payload_changes(window, monkeypatch):
    from gui import app as module
    built = []
    real = module.Redactor

    class Counting(real):
        def __init__(self, request=None):
            built.append(1)
            super().__init__(request)

    monkeypatch.setattr(module, "Redactor", Counting)
    window._invalidate_safe()
    for index in range(10):
        assert window._safe(f"line {index}") == f"line {index}"
    assert len(built) == 1
    assert "LOCAL-TEST-SECRET" not in window._safe("cookie session=LOCAL-TEST-SECRET 已脱敏")
    edit(window, lambda value: value.__setitem__("name", "改名后"))
    assert window._flush_editor()
    window._safe("again")
    assert len(built) == 2


def test_refresh_accounts_is_fast_with_many_accounts(window, qapp):
    for index in range(60):
        window.accounts.append({"id": f"bulk-{index}", "name": f"批量 {index}", "base_url": f"https://bulk{index}.invalid",
                                "tasks": [{"id": "daily"}, {"id": "extra"}]})
        window.store.apply(run_payload(f"bulk-{index}", ["daily", "extra"], "failed" if index % 3 else "success"))
    window._invalidate_safe()
    started = time.perf_counter()
    window._refresh_accounts()
    elapsed = time.perf_counter() - started
    assert window.account_list.count() == 63
    assert elapsed < 0.4, f"_refresh_accounts 耗时 {elapsed:.3f}s"
    assert window.metric_values[3].text() == str(sum(2 for index in range(60) if index % 3))


def test_job_progress_updates_only_its_row(window, qapp):
    window.select_account("alpha")
    window._run_current()
    window.select_account("beta")
    window._run_current()
    first, second = list(window._jobs)
    window.runner.start(first)
    qapp.processEvents()
    assert window.jobs_table.rowCount() == 2
    row_first = window._job_rows[first]
    row_second = window._job_rows[second]
    before_second = window.jobs_table.item(row_second, 3).text()
    started = time.perf_counter()
    for index in range(200):
        window.runner.progress.emit(first, f"阶段事件 {index} session=LOCAL-TEST-SECRET")
    elapsed = time.perf_counter() - started
    assert elapsed < 0.5, f"200 行进度耗时 {elapsed:.3f}s"
    latest = window.jobs_table.item(row_first, 3).text()
    assert latest.startswith("阶段事件 199") and "LOCAL-TEST-SECRET" not in latest
    assert window.jobs_table.item(row_first, 2).text() == "运行中"
    assert window.jobs_table.item(row_second, 3).text() == before_second
    assert window.jobs_table.item(row_second, 2).text() == "排队中"
    assert "LOCAL-TEST-SECRET" not in window.log_view.toPlainText()
    window.runner.complete(first, run_payload("alpha", ["first", "second", "third"]))
    window.runner.start(second)
    window.runner.complete(second, run_payload("beta", ["heartbeat"]))
    qapp.processEvents()
    assert window.jobs_table.item(window._job_rows[first], 2).text() == "已结束"
