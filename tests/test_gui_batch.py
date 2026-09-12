"""独立 GUI 后台回归：Qt 本地 stub / .invalid / tmp_path，绝不运行真实账号。"""
from __future__ import annotations

import asyncio
import io
import json
import os
import threading
import time
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtCore import QObject, QProcess, QTimer, Signal
from PySide6.QtWidgets import QApplication

from core import timebase
from gui import worker
from gui.status_store import ResultStore
from gui.workers import JobRunner, StorageRunner


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def wait(qapp, predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        qapp.processEvents()
    qapp.processEvents()
    assert predicate(), "等待 Qt 事件超时"


class ProcessStub(QObject):
    started = Signal()
    readyReadStandardOutput = Signal()
    readyReadStandardError = Signal()
    errorOccurred = Signal(object)
    finished = Signal(int, object)

    def __init__(self, parent):
        super().__init__(parent)
        self.status = QProcess.ProcessState.NotRunning
        self.input = bytearray()
        self.output = bytearray()
        self.logs = bytearray()
        self.arguments = []
        self.program = ""
        self.write_closed = False

    def setProcessChannelMode(self, value):
        self.mode = value

    def setWorkingDirectory(self, value):
        self.cwd = value

    def setProgram(self, value):
        self.program = value

    def setArguments(self, value):
        self.arguments = value

    def state(self):
        return self.status

    def start(self):
        self.status = QProcess.ProcessState.Starting
        QTimer.singleShot(0, self.launch)

    def launch(self):
        self.status = QProcess.ProcessState.Running
        self.started.emit()

    def write(self, value):
        self.input.extend(value)
        return len(value)

    def closeWriteChannel(self):
        self.write_closed = True

    def readAllStandardOutput(self):
        value = bytes(self.output)
        self.output.clear()
        return value

    def readAllStandardError(self):
        value = bytes(self.logs)
        self.logs.clear()
        return value

    def errorString(self):
        return "本地进程启动失败"

    def stdout(self, value):
        self.output.extend(value)
        self.readyReadStandardOutput.emit()

    def stderr(self, value):
        self.logs.extend(value)
        self.readyReadStandardError.emit()

    def end(self, value=b'{}', code=0):
        self.stdout(value)
        self.status = QProcess.ProcessState.NotRunning
        self.finished.emit(code, QProcess.ExitStatus.NormalExit)


@pytest.fixture
def runner(qapp, monkeypatch):
    obj = JobRunner(max_workers=2)
    processes = []

    def create():
        process = ProcessStub(obj)
        processes.append(process)
        return process

    monkeypatch.setattr(obj, "_new_process", create)
    yield obj, processes
    obj.cancel_pending()
    for process in processes:
        if process.state() != QProcess.ProcessState.NotRunning:
            process.end()
    wait(qapp, lambda: not obj.busy)
    assert obj.shutdown()


def account():
    return {"id": "stable-id", "name": "可改显示名", "base_url": "https://example.invalid", "template": "auto",
            "login": {"method": "auto"}, "credentials": {},
            "tasks": [{"id": "quiz"}, {"id": "lottery", "depends_on": ["quiz"]}]}


def request(tmp_path=None, action="run"):
    value = {"action": action, "account": account(), "oauth_states": {}, "explicit": [], "only_tasks": []}
    if tmp_path is not None:
        overlay = tmp_path / "overlay.json"
        overlay.write_text('{"entries": {}}', encoding="utf-8")
        value.update(config_path=str(tmp_path / "ACCOUNTS.json"), overlay_path=str(overlay))
    return value


def test_same_origin_serial_and_cross_origin_parallel(runner, qapp):
    obj, processes = runner
    starts, ends = [], []
    obj.started.connect(starts.append)
    obj.completed.connect(lambda key, value: ends.append(key))
    obj.submit("a1", request(), group="https://same.invalid")
    obj.submit("a2", request(), group="https://same.invalid")
    obj.submit("b1", request(), group="https://other.invalid")
    wait(qapp, lambda: len(starts) == 2)
    assert starts == ["a1", "b1"]
    assert (obj.active_count, obj.pending_count) == (2, 1)
    assert not obj.shutdown(0)
    processes[0].end()
    wait(qapp, lambda: len(starts) == 3)
    assert starts == ["a1", "b1", "a2"]
    assert ends == ["a1"]


def test_request_frozen_and_credentials_only_in_stdin(runner, qapp):
    obj, processes = runner
    value = request()
    value["account"]["credentials"] = {"cookie": "session=UNIQUE-CREDENTIAL"}
    value["oauth_states"] = {"linuxdo": {"default": "OPAQUE-OAUTH"}}
    obj.submit("freeze", value)
    value["account"]["credentials"]["cookie"] = "MUTATED"
    value["oauth_states"].clear()
    wait(qapp, lambda: bool(processes[0].input))
    process = processes[0]
    sent = json.loads(process.input)
    assert sent["account"]["credentials"]["cookie"] == "session=UNIQUE-CREDENTIAL"
    assert sent["oauth_states"]["linuxdo"]["default"] == "OPAQUE-OAUTH"
    assert process.arguments == ["-u", "-X", "utf8", "-m", "gui.worker"]
    assert "CREDENTIAL" not in process.program + " ".join(process.arguments)
    assert process.write_closed
    with pytest.raises(ValueError):
        obj.submit("freeze", request())
    with pytest.raises(ValueError):
        obj.submit("bad", {"action": "verify"})


def test_pending_cancel_does_not_fake_results_and_active_finishes(runner, qapp):
    obj, processes = runner
    completed, failures, idles = [], [], []
    obj.completed.connect(lambda key, result: completed.append(key))
    obj.failed.connect(lambda key, error: failures.append(key))
    obj.idle.connect(lambda: idles.append(True))
    obj.submit("active", request(), group="site")
    obj.submit("pending", request(), group="site")
    assert obj.cancel_pending() == ["pending"]
    assert not completed and not failures and obj.busy
    wait(qapp, lambda: bool(processes[0].input))
    processes[0].end()
    assert completed == ["active"] and not failures
    assert idles == [True]


def test_utf8_chunks_event_decode_and_redaction(runner, qapp):
    obj, processes = runner
    lines, results = [], []
    value = request()
    value["account"]["credentials"]["access_token"] = "RAWSECRET1234"
    obj.progress.connect(lambda key, line: lines.append(line))
    obj.completed.connect(lambda key, result: results.append(result))
    obj.submit("utf8", value)
    wait(qapp, lambda: bool(processes[0].input))
    event = {"version": 2, "stage": "execute", "message": "签到中文 RAWSECRET1234",
             "fields": {"password": "OTHER-SECRET"}, "task": "quiz"}
    encoded = ("@checkin-event " + json.dumps(event, ensure_ascii=False) + "\n").encode()
    for byte in encoded:
        processes[0].stderr(bytes([byte]))
    encoded = json.dumps({"results": [], "message": "结果中文 RAWSECRET1234"}, ensure_ascii=False).encode()
    for byte in encoded:
        processes[0].stdout(bytes([byte]))
    processes[0].end(b"")
    assert len(results) == 1 and "结果中文" in results[0]["message"]
    assert "[execute:quiz]" in lines[0] and "签到中文" in lines[0]
    assert "RAWSECRET1234" not in repr(lines) + repr(results)
    assert "OTHER-SECRET" not in repr(lines)
    assert "�" not in repr(lines) + repr(results)


@pytest.mark.parametrize("mode", ["invalid-json", "double-json", "invalid-utf8", "error-result", "crash", "start-error"])
def test_failure_is_notified_once(runner, qapp, mode):
    obj, processes = runner
    failures, results = [], []
    obj.failed.connect(lambda key, error: failures.append((key, error)))
    obj.completed.connect(lambda key, result: results.append(result))
    obj.submit("failure", request())
    process = processes[0]
    wait(qapp, lambda: bool(process.input))
    data = {"invalid-json": b"not json", "double-json": b"{}{}", "invalid-utf8": b"\xff",
            "error-result": b'{"error":"failure"}'}.get(mode, b"{}")
    if mode in {"crash", "start-error"}:
        if mode == "start-error":
            process.status = QProcess.ProcessState.NotRunning
        process.errorOccurred.emit(QProcess.ProcessError.FailedToStart if mode == "start-error" else QProcess.ProcessError.Crashed)
    process.end(data)
    assert len(failures) == 1 and not results and not obj.busy


def test_capture_commands_and_raw_credentials_are_not_progress(runner, qapp):
    obj, processes = runner
    results, lines = [], []
    obj.completed.connect(lambda key, result: results.append(result))
    obj.progress.connect(lambda key, line: lines.append(line))
    obj.submit("capture", {"action": "capture", "target": "site", "account": account()})
    obj.complete_capture("capture")  # Starting 状态也能排队发送控制命令。
    wait(qapp, lambda: b'"finish"' in processes[0].input)
    assert not processes[0].write_closed
    obj.cancel_capture("capture")
    assert b'"cancel"' in processes[0].input
    processes[0].end(b'{"ok":true,"credentials":{"cookie":"PRIVATE-CAPTURE"}}')
    assert results[0]["credentials"]["cookie"] == "PRIVATE-CAPTURE"
    assert "PRIVATE-CAPTURE" not in repr(lines)
    with pytest.raises(ValueError):
        ResultStore().apply(results[0])


def test_cross_thread_submission_and_main_thread_signals(runner, qapp):
    obj, processes = runner
    main = threading.get_ident()
    calls = []
    obj.started.connect(lambda key: calls.append(threading.get_ident()))
    thread = threading.Thread(target=lambda: obj.submit("thread", request()))
    thread.start()
    thread.join()
    wait(qapp, lambda: bool(calls))
    assert calls == [main]
    assert processes[0].thread() == qapp.thread()


def test_output_limits_do_not_kill_process(runner, qapp, monkeypatch):
    import gui.workers as module

    monkeypatch.setattr(module, "MAX_RESULT_BYTES", 12)
    monkeypatch.setattr(module, "MAX_STDERR_BYTES", 12)
    obj, processes = runner
    failures, lines = [], []
    obj.failed.connect(lambda key, error: failures.append(error))
    obj.progress.connect(lambda key, line: lines.append(line))
    obj.submit("limit", request())
    wait(qapp, lambda: bool(processes[0].input))
    process = processes[0]
    process.stderr(b"x" * 20)
    process.stderr(b"y" * 20)
    process.stdout(b"x" * 20)
    assert obj.busy and not failures and len(lines) == 1
    process.end()
    assert len(failures) == 1 and "大小限制" in failures[0]


def test_storage_serial_callbacks_main_thread_and_errors(qapp):
    obj = StorageRunner()
    release = threading.Event()
    work, callbacks = [], []
    main = threading.get_ident()

    def first():
        release.wait(3)
        work.append((1, threading.get_ident()))
        return "saved"

    def second():
        work.append((2, threading.get_ident()))
        raise OSError("磁盘不可写")

    def callback(result, error):
        callbacks.append((result, error, threading.get_ident()))

    obj.submit(first, callback)
    obj.submit(second, callback)
    assert obj.busy and not obj.shutdown(0)
    release.set()
    wait(qapp, lambda: len(callbacks) == 2)
    assert [entry[0] for entry in work] == [1, 2]
    assert all(entry[1] != main for entry in work)
    assert all(entry[2] == main for entry in callbacks)
    assert callbacks[0][:2] == ("saved", None)
    assert isinstance(callbacks[1][1], OSError)
    assert obj.shutdown() and not obj.busy


def payload(stamp, *, task="quiz", text="自由结果", name="显示名"):
    return {"schema_version": 2, "account_id": "stable-id", "name": name, "generated_at": stamp,
            "results": [{"account_id": "stable-id", "task_id": task, "name": name, "verdict": "no_effect",
                         "ok": True, "reason": "custom_reason", "text": text, "text_label": "自定义",
                         "evidence": [{"path": "proof.png"}], "business_date": timebase.business_date_of(stamp)}]}


@pytest.fixture
def clock(monkeypatch):
    current = [datetime(2026, 7, 30, 4, 0, tzinfo=timezone.utc)]
    monkeypatch.setattr(timebase, "utc_now", lambda: current[0])
    return current


def test_result_store_multitask_stable_ids_and_frozen_snapshot(tmp_path, clock):
    store = ResultStore(tmp_path)
    item = payload(timebase.utc_iso())
    item["results"].extend(payload(timebase.utc_iso(), task="lottery", text="抽奖无变化")["results"])
    store.apply(item)
    assert set(store.entries) == {("stable-id", "quiz"), ("stable-id", "lottery")}
    assert store.get("stable-id", "quiz")["ok"] is True
    assert store.get("stable-id", "quiz")["reason"] == "custom_reason"
    assert store.get("stable-id", "quiz")["evidence"] == [{"path": "proof.png"}]
    snapshot = store.snapshot_payload()
    item["results"][0]["text"] = "caller mutation"
    record = store.get("stable-id", "quiz")
    record["text"] = "reader mutation"
    clock[0] += timedelta(seconds=2)
    store.apply(payload(timebase.utc_iso(), name="重命名", text="新结果"))
    assert len(store.entries) == 2 and store.get("stable-id", "quiz")["name"] == "重命名"
    assert snapshot["results"][1]["text"] == "自由结果"


def test_store_today_merge_and_timezone_comparison(tmp_path, clock):
    (tmp_path / "checkin_result.json").write_text(json.dumps(payload("2026-07-30T11:00:00+08:00", text="batch")), encoding="utf-8")
    current = payload("2026-07-30T03:30:00Z", text="gui")
    current["results"] += payload("2026-07-30T03:20:00Z", task="lottery")["results"]
    (tmp_path / "gui_results.json").write_text(json.dumps(current), encoding="utf-8")
    store = ResultStore(tmp_path)
    store.load()
    assert store.get("stable-id", "quiz")["text"] == "gui"
    assert len(store.records()) == 2
    store.apply(payload("2026-07-30T11:15:00+08:00", text="stale"))
    assert store.get("stable-id", "quiz")["text"] == "gui"
    store.apply(payload("2026-07-29T04:00:00Z", text="yesterday"))
    assert store.get("stable-id", "quiz")["text"] == "gui"
    store.save()
    assert (tmp_path / "gui_results.json").is_file()


def test_stale_snapshot_cannot_overwrite_newer_disk_or_cross_day(tmp_path, clock):
    first, second = ResultStore(tmp_path), ResultStore(tmp_path)
    first.apply(payload(timebase.utc_iso(), text="old"))
    stale = first.snapshot_payload()
    clock[0] += timedelta(seconds=2)
    second.apply(payload(timebase.utc_iso(), text="new"))
    second.apply(payload(timebase.utc_iso(), task="lottery"))
    second.save()
    ResultStore.write_payload(tmp_path, stale)
    first.load()
    assert first.get("stable-id", "quiz")["text"] == "new"
    assert len(first.records()) == 2
    disk = (tmp_path / "gui_results.json").read_bytes()
    clock[0] += timedelta(days=1)
    ResultStore.write_payload(tmp_path, stale)
    assert (tmp_path / "gui_results.json").read_bytes() == disk
    assert first.records() == []


def test_result_redaction_removes_secrets_but_preserves_free_reason(tmp_path, clock):
    store = ResultStore(tmp_path)
    value = payload(timebase.utc_iso())
    value["results"][0].update(data={"password": "RAW-PASSWORD"}, message="received RAW-PASSWORD", reason="business_specific")
    store.apply(value)
    store.save()
    assert "RAW-PASSWORD" not in repr(store.records())
    assert "RAW-PASSWORD" not in (tmp_path / "gui_results.json").read_text(encoding="utf-8")
    assert store.get("stable-id", "quiz")["reason"] == "business_specific"


def test_read_write_errors_preserve_memory_and_hide_yesterday(tmp_path, clock, monkeypatch):
    from config import paths

    store = ResultStore(tmp_path)
    store.apply(payload(timebase.utc_iso()))
    previous = deepcopy(store.entries)
    (tmp_path / "gui_results.json").write_text("broken", encoding="utf-8")
    with pytest.raises(ValueError):
        store.load()
    assert store.entries == previous
    with pytest.raises(ValueError):
        store.save()
    assert (tmp_path / "gui_results.json").read_text() == "broken"
    (tmp_path / "gui_results.json").unlink()

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(paths, "atomic_write_text", fail)
    with pytest.raises(OSError):
        store.save()
    assert store.entries == previous
    (tmp_path / "gui_results.json").write_text("broken", encoding="utf-8")
    clock[0] += timedelta(days=1)
    assert store.get("stable-id", "quiz") is None and store.records() == []
    assert store.entries == previous and store.today != timebase.business_date()
    with pytest.raises(ValueError):
        store.snapshot_payload()


def test_worker_timestamp_preserves_newest_text_within_same_second(tmp_path, clock, monkeypatch):
    from apps import cli

    calls = []

    def run(*args, **kwargs):
        calls.append(True)
        value = payload(timebase.utc_iso(), text=f"第{len(calls)}轮返回")
        return SimpleNamespace(to_payload=lambda: value)

    monkeypatch.setattr(cli, "run_account_sync", run)
    first = worker.execute(request(tmp_path))
    clock[0] += timedelta(microseconds=1)
    second = worker.execute(request(tmp_path))
    assert timebase.parse_timestamp(second["generated_at"]) > timebase.parse_timestamp(first["generated_at"])
    store = ResultStore(tmp_path)
    store.apply(first)
    store.apply(second)
    assert store.latest("stable-id", "quiz")["text"] == "第2轮返回"


def test_worker_run_uses_shared_cli_once_and_actual_task_ids(tmp_path, monkeypatch):
    from apps import cli
    from core.outcome import no_effect
    from runtime.engine import AccountRun, TaskRecord

    calls = []

    def run(spec, **kwargs):
        calls.append((spec, kwargs))
        return AccountRun(spec.id, spec.name, spec.base_url, tuple(
            TaskRecord(spec.id, task_id, spec.name, spec.base_url, no_effect("自由文本", reason="custom_reason"))
            for task_id in kwargs["only_tasks"]
        ))

    monkeypatch.setattr(cli, "run_account_sync", run)
    value = request(tmp_path)
    value["only_tasks"] = ["lottery"]
    value["explicit"] = ["access_token"]
    value["oauth_states"] = {"linuxdo": {"default": {"state": "shared-state"}}}
    result = worker.execute(value)
    assert len(calls) == 1
    assert calls[0][1]["structured"] is True
    assert calls[0][1]["explicit"] == ("access_token",)
    assert calls[0][1]["only_tasks"] == ("quiz", "lottery")
    assert [item["task_id"] for item in result["results"]] == ["quiz", "lottery"]
    assert result["results"][0]["reason"] == "custom_reason"


def test_worker_top_level_exception_does_not_create_daily(tmp_path, monkeypatch):
    from apps import cli
    from browser import runtime_loop

    original = cli._single

    def fail(coro):
        coro.close()
        raise RuntimeError("top-level error")

    monkeypatch.setattr(runtime_loop, "run_sync", fail)
    with pytest.raises(RuntimeError, match="top-level error"):
        worker.execute(request(tmp_path))
    assert cli._single is original


def test_worker_disabled_dependency_rejected_before_engine(tmp_path, monkeypatch):
    from apps import cli

    monkeypatch.setattr(cli, "run_account_sync", lambda *a, **k: pytest.fail("不可进入引擎"))
    value = request(tmp_path)
    value["account"]["tasks"][0]["enabled"] = False
    value["only_tasks"] = ["lottery"]
    with pytest.raises(Exception, match="禁用"):
        worker.execute(value)


def test_explain_auto_is_offline_and_explicit_matches_overlay(tmp_path, monkeypatch):
    from runtime import engine

    monkeypatch.setattr(engine, "run_account", lambda *a, **k: pytest.fail("解释不可执行"))
    value = request(tmp_path, "explain")
    value["account"]["credentials"]["access_token"] = "private-token"
    value["explicit"] = ["access_token"]
    result = worker.execute(value)
    assert len(result["tasks"]) == 2
    assert all(item["runtime_detection"] and item["flow"] is None for item in result["tasks"])
    assert "private-token" not in repr(result)
    assert any("调用方显式" in text or "显式" in text for text in result["overlay"])


def test_templates_enumerates_scripts_and_isolates_item_errors(tmp_path, monkeypatch):
    from core.manifest import ArgSchema, ArgSpec, LoginOption, TaskOption, TemplateManifest
    from templates import registry

    directory = tmp_path / "scripts" / "tasks"
    directory.mkdir(parents=True)
    (directory / "script.py").write_text("", encoding="utf-8")
    (directory / "_private.py").write_text("", encoding="utf-8")
    monkeypatch.setattr(registry, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(registry, "ids", lambda: ["broken", "good"])
    manifest = TemplateManifest("good", title="自定义模板", description="声明说明",
        login=(LoginOption("custom_login"),), task=(TaskOption("custom_task"),),
        args=ArgSchema([ArgSpec("opaque", secret=True, default="DO-NOT-SHOW"), ArgSpec("count", kind="int", default=2)]))

    def get(reference):
        if reference == "broken":
            raise ValueError("坏模板")
        return SimpleNamespace(manifest=manifest, source="script" if reference.endswith(".py") else "builtin")

    monkeypatch.setattr(registry, "get", get)
    result = worker.execute({"action": "templates"})
    items = {item["reference"]: item for item in result["templates"]}
    assert set(items) == {"broken", "good", "scripts/tasks/script.py"}
    assert "error" in items["broken"]
    assert items["good"]["args"][0]["secret"] is True
    assert items["good"]["args"][0]["default"] is None
    assert items["good"]["args"][1]["type"] == "int"
    assert "DO-NOT-SHOW" not in repr(result)


@pytest.mark.parametrize("provider", ["", "not-a-provider"])
def test_oauth_capture_requires_explicit_known_provider(provider):
    with pytest.raises(ValueError):
        asyncio.run(worker._capture({"target": "oauth", "provider": provider}, worker.CaptureControl()))


def test_site_capture_is_generic_scoped_and_closes_on_finish_cancel_timeout(monkeypatch):
    from browser import service

    closed, visited = [], []
    state = {"cookies": [{"name": "session", "value": "ours", "domain": "example.invalid", "path": "/"},
                         {"name": "secret", "value": "foreign", "domain": "other.invalid", "path": "/"}],
             "origins": [{"origin": "https://other.invalid", "localStorage": [{"name": "auth_token", "value": "foreign"}]},
                         {"origin": "https://example.invalid", "localStorage": [{"name": "auth_token", "value": "ours"}]}]}

    class Lease:
        context = None

        async def __aenter__(self):
            self.context = self
            return self

        async def __aexit__(self, *args):
            return False

        async def new_page(self):
            return None

        async def goto(self):
            visited.append("base_url")

        async def storage_state(self):
            return state

    class Service:
        def __init__(self, **kwargs):
            pass

        def lease(self, **kwargs):
            return Lease()

        async def aclose(self):
            closed.append(True)

    monkeypatch.setattr(service, "BrowserService", Service)
    value = {"target": "site", "account": account()}
    finish = worker.CaptureControl()
    finish.set("finish")
    result = asyncio.run(worker._capture(value, finish))
    assert result["credentials"]["access_token"] == "ours"
    assert result["credentials"]["cookie"] == "session=ours"
    assert "未验证" in result["message"]
    cancel = worker.CaptureControl()
    cancel.set("cancel")
    with pytest.raises(worker.CaptureCancelled):
        asyncio.run(worker._capture(value, cancel))
    with pytest.raises(TimeoutError):
        asyncio.run(worker._capture(value, worker.CaptureControl(timeout=0)))
    assert len(closed) == 3 and visited == ["base_url"] * 3


def test_worker_main_stdout_single_json_and_stderr_diagnostics(monkeypatch):
    value = request()
    stdout, stderr = io.StringIO(), io.StringIO()
    monkeypatch.setattr(worker.sys, "stdin", io.StringIO(json.dumps(value) + "\n"))
    monkeypatch.setattr(worker.sys, "stdout", stdout)
    monkeypatch.setattr(worker.sys, "stderr", stderr)

    def execute(*args, **kwargs):
        print("诊断只走 stderr")
        return {"results": [], "message": "结果"}

    monkeypatch.setattr(worker, "execute", execute)
    assert worker.main() == 0
    assert json.loads(stdout.getvalue())["message"] == "结果"
    assert stderr.getvalue().strip() == "诊断只走 stderr"


def test_real_qprocess_offline_explain(tmp_path, qapp):
    obj = JobRunner(max_workers=1)
    completed, failed = [], []
    obj.completed.connect(lambda key, result: completed.append(result))
    obj.failed.connect(lambda key, error: failed.append(error))
    obj.submit("real-offline", request(tmp_path, "explain"))
    wait(qapp, lambda: not obj.busy, timeout=20)
    assert not failed and len(completed) == 1
    assert completed[0]["account_id"] == "stable-id"
    assert all(item["runtime_detection"] for item in completed[0]["tasks"])
    assert obj.shutdown()


def test_real_failed_to_start_notifies_once(tmp_path, qapp, monkeypatch):
    import gui.workers as module

    monkeypatch.setattr(module.sys, "executable", str(tmp_path / "missing-python.invalid"))
    obj = JobRunner()
    failures, completed = [], []
    obj.failed.connect(lambda key, error: failures.append(error))
    obj.completed.connect(lambda key, result: completed.append(result))
    obj.submit("missing", request())
    wait(qapp, lambda: not obj.busy)
    assert len(failures) == 1 and not completed
    assert obj.shutdown()


def test_process_factory_exception_releases_queue(runner, monkeypatch):
    obj, _ = runner
    failures = []
    obj.failed.connect(lambda key, error: failures.append(error))

    def fail():
        raise RuntimeError("QProcess construction failed")

    monkeypatch.setattr(obj, "_new_process", fail)
    obj.submit("bad-factory", request())
    assert len(failures) == 1 and not obj.busy


def test_template_option_args_do_not_cross_scopes(tmp_path, monkeypatch):
    from core.manifest import ArgSchema, ArgSpec, LoginOption, TaskOption, TemplateManifest
    from templates import registry

    monkeypatch.setattr(registry, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(registry, "ids", lambda: ["scoped"])
    manifest = TemplateManifest(
        "scoped", args=ArgSchema([ArgSpec("shared", default="global")]),
        login=(LoginOption("login", args=ArgSchema([ArgSpec("code", secret=True, default="HIDDEN")])),),
        task=(TaskOption("quiz", args=ArgSchema([ArgSpec("code", kind="int", minimum=1, maximum=5)]),
                         owns=frozenset({"execute"}), requires=frozenset({"browser"})),),
    )
    monkeypatch.setattr(registry, "get", lambda ref: SimpleNamespace(manifest=manifest, source="script"))
    item = worker.execute({"action": "templates"})["templates"][0]
    assert [arg["name"] for arg in item["args"]] == ["shared"]
    assert item["login_args"]["login"][0]["secret"] is True
    assert item["task_args"]["quiz"][0]["secret"] is False
    assert item["task_args"]["quiz"][0]["type"] == "int"
    assert item["task_options"][0]["args"][0]["maximum"] == 5
    assert item["task_options"][0]["owns"] == ["execute"]
    assert item["task_options"][0]["requires"] == ["browser"]
    assert "HIDDEN" not in repr(item)


def test_cookie_file_relative_to_config_and_no_plaintext_log(tmp_path, monkeypatch):
    from apps import cli
    from core.outcome import no_effect
    from runtime.engine import AccountRun, TaskRecord

    value = request(tmp_path)
    value["account"]["credentials"] = {"cookie_file": "credentials.txt"}
    (tmp_path / "credentials.txt").write_text("session=FILE-ONLY-SECRET\n", encoding="utf-8")
    output, diagnostics = io.StringIO(), io.StringIO()
    monkeypatch.setattr(worker.sys, "stdin", io.StringIO(json.dumps(value) + "\n"))
    monkeypatch.setattr(worker.sys, "stdout", output)
    monkeypatch.setattr(worker.sys, "stderr", diagnostics)

    def run(spec, **kwargs):
        assert spec.credentials.cookie == "session=FILE-ONLY-SECRET"
        print("unlabelled FILE-ONLY-SECRET")
        return AccountRun(spec.id, spec.name, spec.base_url, (
            TaskRecord(spec.id, "quiz", spec.name, spec.base_url, no_effect("FILE-ONLY-SECRET")),
        ))

    monkeypatch.setattr(cli, "run_account_sync", run)
    assert worker.main() == 0
    assert "FILE-ONLY-SECRET" not in output.getvalue() + diagnostics.getvalue()
    assert "unlabelled" in diagnostics.getvalue()
    assert value["account"]["credentials"]["cookie_file"] == "credentials.txt"
    assert json.loads(output.getvalue())["results"][0]["task_id"] == "quiz"


def test_worker_serialization_error_is_still_single_json(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(worker.sys, "stdin", io.StringIO('{"action":"templates"}\n'))
    monkeypatch.setattr(worker.sys, "stdout", output)
    monkeypatch.setattr(worker, "execute", lambda *a, **k: {"not_json": object()})
    assert worker.main() == 1
    assert "error" in json.loads(output.getvalue())


def test_capture_control_finish_cancel_and_eof_commands():
    finish = worker.CaptureControl(io.StringIO('{"command":"finish"}\n'))
    finish._read()
    asyncio.run(finish.wait())
    cancel = worker.CaptureControl(io.StringIO('{"command":"cancel"}\n'))
    cancel._read()
    with pytest.raises(worker.CaptureCancelled):
        asyncio.run(cancel.wait())
    eof = worker.CaptureControl(io.StringIO(""))
    eof._read()
    with pytest.raises(worker.CaptureCancelled):
        asyncio.run(eof.wait())


def test_oversized_log_line_is_dropped_without_partial_credential(runner, qapp, monkeypatch):
    import gui.workers as module

    monkeypatch.setattr(module, "MAX_LOG_LINE", 10)
    obj, processes = runner
    lines = []
    obj.progress.connect(lambda key, line: lines.append(line))
    obj.submit("long-line", request())
    wait(qapp, lambda: bool(processes[0].input))
    processes[0].stderr(b"password=PART")
    processes[0].stderr(b"IAL-SECRET\nnormal\n")
    processes[0].end()
    assert lines == ["normal"]


def test_explain_named_template_reuses_engine_flow_precedence(tmp_path, monkeypatch):
    from core.flow import FlowPlan
    from core.manifest import TaskOption, TemplateManifest
    from runtime import capabilities, engine
    from templates import registry

    value = request(tmp_path, "explain")
    value["account"]["template"] = "local"
    value["account"]["flow"] = {"execute": "off"}
    value["account"]["tasks"][0]["flow"] = {"execute": "auto"}
    value["only_tasks"] = ["quiz"]
    manifest = TemplateManifest("local", task=(TaskOption("api"),))
    monkeypatch.setattr(registry, "get", lambda ref: SimpleNamespace(manifest=manifest))
    monkeypatch.setattr(capabilities, "detect", lambda spec: frozenset())
    result = worker.execute(value)
    spec, _ = worker._account_request(value)
    expected = FlowPlan.resolve(configured=engine._flow_config(spec, spec.tasks[0]), template=manifest,
                                learned={}, capabilities=frozenset(), failure_streak=0)
    assert result["tasks"][0]["flow"] == expected.to_payload()
    assert result["tasks"][0]["describe"] == expected.describe()


def test_idle_callback_can_submit_without_stranding_queue(runner, qapp):
    obj, processes = runner
    submitted = []

    def on_idle():
        if not submitted:
            submitted.append(True)
            obj.submit("from-idle", request())

    obj.idle.connect(on_idle)
    obj.submit("first", request())
    wait(qapp, lambda: bool(processes[0].input))
    processes[0].end()
    wait(qapp, lambda: len(processes) == 2 and bool(processes[1].input))
    assert obj.active_count == 1 and obj.pending_count == 0
    processes[1].end()
    assert not obj.busy


@pytest.mark.parametrize("filename", ["checkin_result.json", "gui_results.json"])
def test_latest_reads_yesterday_from_legacy_v2_results_only(tmp_path, clock, filename):
    value = payload("2026-07-29T04:00:00Z", text="昨日返回")
    value["business_date"] = "2026-07-29"
    (tmp_path / filename).write_text(json.dumps(value), encoding="utf-8")
    store = ResultStore(tmp_path)
    store.load()
    assert store.records() == [] and store.entries == {}
    assert store.get("stable-id", "quiz") is None
    assert store.today == timebase.business_date()
    assert store.latest("stable-id")["text"] == "昨日返回"
    assert store.latest("stable-id", "quiz")["business_date"] == "2026-07-29"
    assert len(store.latest_records()) == 1
    assert store.latest("missing") is None and store.latest("stable-id", "missing") is None


@pytest.mark.parametrize("filename", ["checkin_result.json", "gui_results.json"])
def test_new_day_write_carries_disk_history_and_restart_keeps_display_fields(tmp_path, clock, filename):
    old = payload(timebase.utc_iso(), text="昨天服务端原文")
    old["results"][0].update(label="完成标签", text_label="返回标签", message="服务端消息", reason="site_reason")
    (tmp_path / filename).write_text(json.dumps(old), encoding="utf-8")
    clock[0] += timedelta(days=1)
    store = ResultStore(tmp_path)  # 不先 load，写锁内也必须合并磁盘历史。
    store.apply(payload(timebase.utc_iso(), task="lottery", text="今天抽奖"))
    store.save()
    disk = json.loads((tmp_path / "gui_results.json").read_text(encoding="utf-8"))
    assert disk["schema_version"] == 2
    assert [row["task_id"] for row in disk["results"]] == ["lottery"]
    assert len(disk["latest_results"]) == 2
    restarted = ResultStore(tmp_path)
    restarted.load()
    latest = restarted.latest("stable-id", "quiz")
    assert {key: latest[key] for key in ("text", "label", "text_label", "message", "reason")} == {
        "text": "昨天服务端原文", "label": "完成标签", "text_label": "返回标签",
        "message": "服务端消息", "reason": "site_reason",
    }
    assert restarted.get("stable-id", "quiz") is None
    assert restarted.latest("stable-id")["task_id"] == "lottery"
    assert [row["task_id"] for row in restarted.records()] == ["lottery"]


def test_cross_day_load_retains_unsaved_latest_and_filters_today(tmp_path, clock):
    store = ResultStore(tmp_path)
    store.apply(payload(timebase.utc_iso(), text="磁盘旧返回"))
    store.save()
    clock[0] += timedelta(seconds=1)
    store.apply(payload(timebase.utc_iso(), text="尚未写盘的新返回"))
    pending = store.snapshot_payload()
    disk = (tmp_path / "gui_results.json").read_bytes()
    clock[0] += timedelta(days=1)
    store.load()
    assert store.entries == {} and store.records() == []
    assert store.latest("stable-id")["text"] == "尚未写盘的新返回"
    ResultStore.write_payload(tmp_path, pending)
    assert (tmp_path / "gui_results.json").read_bytes() == disk
    store.apply(payload(timebase.utc_iso(), task="lottery", text="今日尚未写盘"))
    store.load()
    assert [row["task_id"] for row in store.records()] == ["lottery"]
    assert store.latest("stable-id", "quiz")["text"] == "尚未写盘的新返回"
    store.save()
    restarted = ResultStore(tmp_path)
    restarted.load()
    assert len(restarted.latest_records()) == 2
    assert restarted.latest("stable-id")["text"] == "今日尚未写盘"
    assert restarted.latest("stable-id", "quiz")["text"] == "尚未写盘的新返回"


def test_latest_keys_isolate_accounts_even_when_names_and_tasks_match(tmp_path, clock):
    store = ResultStore(tmp_path)
    store.apply(payload(timebase.utc_iso(), text="甲账号返回"))
    other = payload(timebase.utc_iso(), text="乙账号返回")
    other["account_id"] = other["results"][0]["account_id"] = "other-id"
    store.apply(other)
    store.save()
    restarted = ResultStore(tmp_path)
    restarted.load()
    assert restarted.latest("stable-id", "quiz")["text"] == "甲账号返回"
    assert restarted.latest("other-id", "quiz")["text"] == "乙账号返回"
    assert len(restarted.latest_records()) == 2
    assert [row["text"] for row in restarted.latest_records("other-id")] == ["乙账号返回"]


@pytest.mark.parametrize("tasks", [("a-first", "z-last"), ("z-first", "a-last"), ("quiz", "lottery")])
def test_latest_same_run_prefers_last_executed_array_item_across_restart(tmp_path, clock, tasks):
    value = payload(timebase.utc_iso(), task=tasks[0], text="先执行")
    value["results"] += payload(timebase.utc_iso(), task=tasks[1], text="后执行")["results"]
    store = ResultStore(tmp_path)
    store.apply(value)
    assert [row["task_id"] for row in store.latest_records("stable-id")] == list(reversed(tasks))
    assert store.latest("stable-id")["text"] == "后执行"
    store.save()
    restarted = ResultStore(tmp_path)
    restarted.load()
    restarted.save()  # results 的稳定键排序不能改写显式执行顺序。
    clock[0] += timedelta(days=1)
    restarted.load()
    assert restarted.latest("stable-id")["task_id"] == tasks[1]
    assert len(restarted.latest_records("stable-id")) == 2 and restarted.records() == []
    assert all("_result_order" not in row for row in restarted.latest_records())


def test_latest_does_not_choose_dependency_skip_over_executed_result(tmp_path, clock):
    value = payload(timebase.utc_iso(), task="z-run", text="真正执行返回")
    skipped = payload(timebase.utc_iso(), task="a-skipped", text="依赖跳过")["results"][0]
    skipped.update(reason="not_applicable", data={"blocked_by": "z-run"})
    value["results"].append(skipped)
    store = ResultStore(tmp_path)
    store.apply(value)
    store.save()
    restarted = ResultStore(tmp_path)
    restarted.load()
    assert restarted.latest("stable-id")["task_id"] == "z-run"
    assert restarted.latest("stable-id", "a-skipped")["reason"] == "not_applicable"
    assert len(restarted.latest_records()) == 2


def test_latest_failure_replaces_entire_success_instead_of_reusing_old_text(tmp_path, clock):
    store = ResultStore(tmp_path)
    success = payload(timebase.utc_iso(), text="旧成功文本")
    store.apply(success)
    store.save()
    clock[0] += timedelta(days=1)
    failure = payload(timebase.utc_iso())
    row = failure["results"][0]
    row.pop("text")
    row.pop("text_label")
    row.update(verdict="failed", ok=False, label="本次失败", message="仅有失败消息", reason="server_failed")
    store.apply(failure)
    store.apply(success)  # 过时执行回调不能回滚最近失败。
    store.save()
    restarted = ResultStore(tmp_path)
    restarted.load()
    result = restarted.latest("stable-id", "quiz")
    assert result["message"] == "仅有失败消息" and result["ok"] is False
    assert result["label"] == "本次失败" and result["reason"] == "server_failed"
    assert "text" not in result and "text_label" not in result
    assert "旧成功文本" not in repr(restarted.latest_records())
    assert len(restarted.latest_records()) == 1


def test_latest_orders_instants_microseconds_and_rejects_stale_callbacks_and_snapshots(tmp_path, clock):
    stale = ResultStore(tmp_path)
    stale.apply(payload("2026-07-30T12:00:00.100000+08:00", text="过时文本"))
    snapshot = stale.snapshot_payload()
    store = ResultStore(tmp_path)
    store.apply(payload("2026-07-30T04:00:00.900000Z", text="最新文本"))
    store.apply(payload("2026-07-30T12:00:00.500000+08:00", text="过时回调"))
    store.apply(payload("2026-07-30T12:00:00.900000+08:00", text="同刻回放"))
    store.apply(payload("2026-07-30T11:59:59+08:00", task="lottery", text="较早任务"))
    store.apply(payload("2026-07-29T20:01:00+08:00", task="yesterday", text="昨日任务"))
    assert [row["task_id"] for row in store.latest_records()] == ["quiz", "lottery", "yesterday"]
    assert store.latest("stable-id")["text"] == "最新文本"
    assert store.get("stable-id", "quiz")["text"] == "最新文本"
    assert store.get("stable-id", "yesterday") is None
    store.save()
    ResultStore.write_payload(tmp_path, snapshot)
    stale.load()
    assert stale.latest("stable-id")["text"] == "最新文本"
    assert len(stale.latest_records()) == 3


def test_latest_input_queries_and_snapshot_are_independent_deep_copies(tmp_path, clock):
    store = ResultStore(tmp_path)
    value = payload(timebase.utc_iso())
    store.apply(value)
    value["results"][0]["evidence"][0]["path"] = "caller-mutation"
    queries = [store.latest_records()[0], store.latest_records("stable-id")[0],
               store.latest("stable-id"), store.latest("stable-id", "quiz")]
    for query in queries:
        query["evidence"][0]["path"] = "reader-mutation"
        query["text"] = "reader-mutation"
    snapshot = store.snapshot_payload()
    snapshot["latest_results"][0]["evidence"].clear()
    snapshot["latest_results"][0]["text"] = "snapshot-mutation"
    assert store.latest("stable-id")["text"] == "自由结果"
    assert store.latest("stable-id")["evidence"] == [{"path": "proof.png"}]
    assert store.get("stable-id", "quiz")["evidence"] == [{"path": "proof.png"}]


@pytest.mark.parametrize("source", ["apply", "legacy", "latest"])
def test_latest_redacts_disk_and_memory_including_sibling_and_parent_credentials(tmp_path, clock, source):
    value = payload(timebase.utc_iso(), text="响应 RAW-PASSWORD PARENT-COOKIE")
    value["credentials"] = {"cookie": "session=PARENT-COOKIE"}
    value["results"][0].update(data={"password": "RAW-PASSWORD"}, reason="free_reason", message="RAW-PASSWORD")
    value["results"] += payload(timebase.utc_iso(), task="lottery", text="旁路响应 RAW-PASSWORD")["results"]
    store = ResultStore(tmp_path)
    if source == "apply":
        store.apply(value)
    else:
        if source == "latest":
            value["latest_results"] = value["results"]
            value["results"] = []
            for row in value["latest_results"]:
                row["generated_at"] = value["generated_at"]
        (tmp_path / "gui_results.json").write_text(json.dumps(value), encoding="utf-8")
        store.load()
    store.save()
    clock[0] += timedelta(days=1)
    store.load()
    serialized = repr(store.latest_records()) + (tmp_path / "gui_results.json").read_text(encoding="utf-8")
    assert "RAW-PASSWORD" not in serialized and "PARENT-COOKIE" not in serialized
    assert store.latest("stable-id", "quiz")["reason"] == "free_reason"
    assert "响应" in store.latest("stable-id", "quiz")["text"]
    assert store.records() == []


@pytest.mark.parametrize("corrupt_latest", [None, {}, [None], [{"account_id": "stable-id"}]])
def test_corrupt_latest_is_transactional_and_preserves_existing_history(tmp_path, clock, corrupt_latest):
    store = ResultStore(tmp_path)
    store.apply(payload(timebase.utc_iso(), text="内存中的返回"))
    before = deepcopy(store.entries), store.latest_records(), store.today
    corrupt = payload(timebase.utc_iso(), text="损坏磁盘不可合入")
    corrupt["latest_results"] = corrupt_latest
    text = json.dumps(corrupt)
    (tmp_path / "gui_results.json").write_text(text, encoding="utf-8")
    with pytest.raises(ValueError):
        store.load()
    with pytest.raises(ValueError):
        store.save()
    assert (store.entries, store.latest_records(), store.today) == before
    assert (tmp_path / "gui_results.json").read_text(encoding="utf-8") == text
    clock[0] += timedelta(days=1)
    assert store.latest("stable-id")["text"] == "内存中的返回"
    assert store.records() == [] and store.get("stable-id", "quiz") is None
    assert (store.entries, store.latest_records(), store.today) == before


@pytest.mark.parametrize("capture", [
    {"account_id": "stable-id", "credentials": {"cookie": "PRIVATE-CAPTURE"}},
    {"account_id": "stable-id", "schema_version": 2, "action": "capture", "results": []},
])
def test_latest_rejects_capture_without_changing_results(tmp_path, clock, capture):
    store = ResultStore(tmp_path)
    store.apply(payload(timebase.utc_iso()))
    before = store.latest_records()
    with pytest.raises(ValueError):
        store.apply(capture)
    assert store.latest_records() == before


@pytest.mark.parametrize("next_day", [False, True])
def test_latest_write_failure_keeps_both_memory_maps_and_disk(tmp_path, clock, monkeypatch, next_day):
    from config import paths

    store = ResultStore(tmp_path)
    store.apply(payload(timebase.utc_iso(), text="已保存"))
    store.save()
    clock[0] += timedelta(seconds=1)
    store.apply(payload(timebase.utc_iso(), text="尚未保存"))
    before = deepcopy(store.entries), deepcopy(store._latest_entries), store.today
    disk = (tmp_path / "gui_results.json").read_bytes()
    if next_day:
        clock[0] += timedelta(days=1)

    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr(paths, "atomic_write_text", fail)
    with pytest.raises(OSError, match="disk full"):
        store.save()
    assert (store.entries, store._latest_entries, store.today) == before
    assert (tmp_path / "gui_results.json").read_bytes() == disk


def test_latest_read_failure_does_not_partially_merge_disk(tmp_path, clock, monkeypatch):
    import gui.status_store as module

    store = ResultStore(tmp_path)
    store.apply(payload(timebase.utc_iso(), text="当前内存"))
    store.save()
    before = deepcopy(store.entries), deepcopy(store._latest_entries), store.today
    disk = (tmp_path / "gui_results.json").read_bytes()
    clock[0] += timedelta(seconds=1)
    (tmp_path / "checkin_result.json").write_text(json.dumps(payload(timebase.utc_iso(), text="不完整读取")), encoding="utf-8")
    original_read = module._read

    def fail(path):
        if path.name == "gui_results.json":
            raise PermissionError("unreadable")
        return original_read(path)

    monkeypatch.setattr(module, "_read", fail)
    with pytest.raises(PermissionError):
        store.load()
    with pytest.raises(PermissionError):
        store.save()
    assert (store.entries, store._latest_entries, store.today) == before
    assert (tmp_path / "gui_results.json").read_bytes() == disk
    clock[0] += timedelta(days=1)
    assert store.latest("stable-id")["text"] == "当前内存"
    assert store.records() == []
    assert (store.entries, store._latest_entries, store.today) == before


@pytest.mark.parametrize("field", ["results", "latest_results"])
def test_latest_undated_disk_rows_are_not_promoted_by_snapshot_date(tmp_path, clock, field):
    value = payload("")
    if field == "latest_results":
        value["latest_results"] = value["results"]
        value["results"] = []
        value["generated_at"] = timebase.utc_iso()
        value["business_date"] = timebase.business_date()
    (tmp_path / "gui_results.json").write_text(json.dumps(value), encoding="utf-8")
    store = ResultStore(tmp_path)
    store.load()
    assert store.latest_records() == [] and store.records() == []


def test_latest_duplicate_task_rows_keep_only_final_return(tmp_path, clock):
    value = payload(timebase.utc_iso(), text="重复任务首次")
    value["results"] += payload(timebase.utc_iso(), text="重复任务末次")["results"]
    store = ResultStore(tmp_path)
    store.apply(value)
    assert store.latest("stable-id")["text"] == "重复任务末次"
    store.save()
    disk = json.loads((tmp_path / "gui_results.json").read_text(encoding="utf-8"))
    assert len(disk["results"]) == len(disk["latest_results"]) == 1
    store.load()
    assert store.latest("stable-id")["text"] == "重复任务末次"
