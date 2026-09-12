"""Qt 调度层：每账号一个 QProcess，同组串行；文件操作独立串行线程池。"""
from __future__ import annotations

import codecs
import json
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import (
    QCoreApplication, QEventLoop, QObject, QProcess, QRunnable, QThreadPool, QTimer,
    Qt, Signal, Slot,
)

from runtime.events import RunEvent

from .worker import ACTIONS, MAX_LOG_LINE, MAX_REQUEST_BYTES, MAX_RESULT_BYTES, Redactor, safe_data

StorageOperation = Callable[[], Any]
StorageCallback = Callable[[Any, BaseException | None], None]
MAX_STDERR_BYTES = 2 * 1024 * 1024


@dataclass
class _Job:
    job_id: str
    group: str
    action: str
    envelope: bytes = field(repr=False)
    redactor: Redactor = field(repr=False)
    process: QProcess | None = None
    stdout: list[str] = field(default_factory=list, repr=False)
    stdout_size: int = 0
    stderr_size: int = 0
    stderr_line: str = ""
    dropping_line: bool = False
    log_limited: bool = False
    output_decoder: Any = field(default_factory=lambda: codecs.getincrementaldecoder("utf-8")("strict"))
    log_decoder: Any = field(default_factory=lambda: codecs.getincrementaldecoder("utf-8")("replace"))
    error: str = ""
    command: str = ""
    notified: bool = False


class JobRunner(QObject):
    """接收时冻结请求。停止排队不取消引擎，也不销毁运行中的子进程。"""

    started = Signal(str)
    progress = Signal(str, str)
    completed = Signal(str, object)
    failed = Signal(str, str)
    idle = Signal()
    changed = Signal()
    _wake = Signal()

    def __init__(self, parent: QObject | None = None, max_workers: int = 4):
        super().__init__(parent)
        self._max_workers = max(1, int(max_workers))
        self._pending: deque[_Job] = deque()
        self._active: dict[str, _Job] = {}
        self._seen: set[str] = set()
        self._lock = threading.RLock()
        self._closed = False
        self._was_busy = False
        self._pumping = False
        self._pump_requested = False
        self._wake.connect(self._pump)

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._active)

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    @property
    def busy(self) -> bool:
        with self._lock:
            return bool(self._active or self._pending)

    def submit(self, job_id: str, request: dict, *, group: str = "") -> None:
        if not isinstance(job_id, str) or not job_id.strip():
            raise ValueError("job_id 不能为空")
        if not isinstance(request, dict) or request.get("action") not in ACTIONS:
            raise ValueError("未知后台操作")
        envelope = (json.dumps(request, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(envelope) > MAX_REQUEST_BYTES:
            raise ValueError("后台请求超过大小限制")
        frozen = json.loads(envelope)
        job = _Job(job_id, str(group), frozen["action"], envelope, Redactor(frozen))
        with self._lock:
            if self._closed:
                raise RuntimeError("后台调度器已关闭")
            if job_id in self._seen:
                raise ValueError("job_id 已提交，不可重复")
            self._seen.add(job_id)
            self._pending.append(job)
            self._was_busy = True
        self._wake.emit()

    def cancel_pending(self) -> list[str]:
        with self._lock:
            cancelled = [job.job_id for job in self._pending]
            self._pending.clear()
        if cancelled:
            self._wake.emit()
        return cancelled

    def complete_capture(self, job_id: str) -> None:
        self._capture_command(job_id, "finish")

    def cancel_capture(self, job_id: str) -> None:
        self._capture_command(job_id, "cancel")

    def _capture_command(self, job_id: str, command: str) -> None:
        with self._lock:
            job = self._active.get(job_id)
            if job is None or job.action != "capture":
                raise ValueError("未找到运行中的捕获任务")
            job.command = command
        self._wake.emit()

    @Slot()
    def _pump(self) -> None:
        if self._pumping:
            self._pump_requested = True
            return
        self._pumping = True
        try:
            with self._lock:
                for job in list(self._active.values()):
                    if job.command and job.process is not None and job.process.state() == QProcess.ProcessState.Running:
                        job.process.write((json.dumps({"command": job.command}) + "\n").encode("utf-8"))
                        job.command = ""
                while len(self._active) < self._max_workers:
                    groups = {job.group for job in self._active.values() if job.group}
                    job = next((item for item in self._pending if not item.group or item.group not in groups), None)
                    if job is None:
                        break
                    self._pending.remove(job)
                    self._active[job.job_id] = job
                    try:
                        self._start(job)
                    except Exception as exc:
                        job.error = job.redactor.text(exc)
                        self._retire(job)
            self.changed.emit()
            if not self.busy and self._was_busy:
                self._was_busy = False
                self.idle.emit()
        finally:
            self._pumping = False
            if self._pump_requested:
                self._pump_requested = False
                QTimer.singleShot(0, self._pump)

    def _new_process(self) -> QProcess:
        return QProcess(self)

    def _start(self, job: _Job) -> None:
        process = self._new_process()
        job.process = process
        process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        process.setWorkingDirectory(str(Path(__file__).resolve().parents[1]))
        # argv/环境变量都不传账号、共享 OAuth 或凭据；只通过受控 stdin 管道。
        process.setProgram(sys.executable)
        process.setArguments(["-u", "-X", "utf8", "-m", "gui.worker"])
        process.started.connect(lambda: self._started(job))
        process.readyReadStandardOutput.connect(lambda: self._read_stdout(job))
        process.readyReadStandardError.connect(lambda: self._read_stderr(job))
        process.errorOccurred.connect(lambda error: self._process_error(job, error))
        process.finished.connect(lambda code, status: self._finished(job, code, status))
        try:
            process.start()
        except Exception as exc:
            job.error = job.redactor.text(exc)
            self._retire(job)

    def _started(self, job: _Job) -> None:
        if job.notified or job.process is None:
            return
        job.process.write(job.envelope)
        job.envelope = b""
        if job.action != "capture":
            job.process.closeWriteChannel()
        self.started.emit(job.job_id)
        self._wake.emit()

    def _read_stdout(self, job: _Job, *, final: bool = False) -> None:
        raw = bytes(job.process.readAllStandardOutput()) if job.process is not None else b""
        job.stdout_size += len(raw)
        if job.stdout_size > MAX_RESULT_BYTES:
            job.stdout.clear()
            job.error = "后台结果超过大小限制"
            return
        try:
            job.stdout.append(job.output_decoder.decode(raw, final=final))
        except UnicodeDecodeError:
            job.error = "后台 stdout 不是有效 UTF-8"

    def _read_stderr(self, job: _Job, *, final: bool = False) -> None:
        raw = bytes(job.process.readAllStandardError()) if job.process is not None else b""
        job.stderr_size += len(raw)
        if job.stderr_size > MAX_STDERR_BYTES:
            job.stderr_line = ""
            if not job.log_limited:
                job.log_limited = True
                self.progress.emit(job.job_id, "诊断输出达到上限，后续日志已省略；任务继续执行")
            return
        text = job.log_decoder.decode(raw, final=final)
        for fragment in text.splitlines(keepends=True):
            newline = fragment.endswith(("\n", "\r"))
            if not job.dropping_line:
                job.stderr_line += fragment
                if len(job.stderr_line) > MAX_LOG_LINE:
                    # 不展示截断的半段凭据，超长行整行丢弃。
                    job.stderr_line = ""
                    job.dropping_line = True
            if newline:
                if not job.dropping_line:
                    self._log_line(job, job.stderr_line)
                job.stderr_line = ""
                job.dropping_line = False
        if final and job.stderr_line and not job.dropping_line:
            self._log_line(job, job.stderr_line)
            job.stderr_line = ""

    def _log_line(self, job: _Job, line: str) -> None:
        event = RunEvent.from_line(line)
        if event is not None:
            event_redactor = Redactor(event.fields)
            event.fields = safe_data(event.fields)
            line = event_redactor.text(event.to_text())
        safe = job.redactor.text(line.strip())
        if safe:
            self.progress.emit(job.job_id, safe)

    def _process_error(self, job: _Job, error: QProcess.ProcessError) -> None:
        if job.notified:
            return
        job.error = job.error or f"后台进程错误：{job.process.errorString()}"
        if error == QProcess.ProcessError.FailedToStart:
            self._retire(job)

    def _finished(self, job: _Job, code: int, status: QProcess.ExitStatus) -> None:
        if job.notified:
            return
        self._read_stdout(job, final=True)
        self._read_stderr(job, final=True)
        result = None
        if not job.error:
            try:
                result = json.loads("".join(job.stdout))
                if not isinstance(result, dict):
                    raise ValueError("后台结果必须是 JSON 对象")
                if "error" in result:
                    job.error = str(result["error"])
                elif code != 0 or status != QProcess.ExitStatus.NormalExit:
                    job.error = f"后台进程异常退出（{code}）"
            except (ValueError, TypeError):
                job.error = "后台结果协议错误（需要单个 JSON 对象）"
        # 捕获凭据是仅发往显式草稿接收方的私密结果，不记录日志、不进入 ResultStore。
        if result is not None and job.action not in {"capture", "templates"}:
            result = job.redactor.data(safe_data(result))
        self._retire(job, result)

    def _retire(self, job: _Job, result: Any = None) -> None:
        if job.notified:
            return
        if job.process is not None and job.process.state() != QProcess.ProcessState.NotRunning:
            return  # error 信号可能先于退出；仍保留进程及站点租约。
        job.notified = True
        with self._lock:
            self._active.pop(job.job_id, None)
        if job.error:
            self.failed.emit(job.job_id, job.redactor.text(job.error))
        else:
            self.completed.emit(job.job_id, result)
        if job.process is not None:
            job.process.deleteLater()
        job.stdout.clear()
        job.envelope = b""
        self._wake.emit()

    def shutdown(self, wait_ms: int = 0) -> bool:
        """只等待自然完成。忙时返回 False，调用方必须保留窗口及 runner。"""
        deadline = time.monotonic() + max(0, wait_ms) / 1000
        while self.busy and time.monotonic() < deadline:
            QCoreApplication.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 20)
        with self._lock:
            if self._active or self._pending:
                return False
            self._closed = True
        return True


class _StorageTask(QRunnable):
    def __init__(self, operation: StorageOperation, callback: StorageCallback | None, signal: Any):
        super().__init__()
        self.operation, self.callback, self.signal = operation, callback, signal

    def run(self) -> None:
        try:
            result, error = self.operation(), None
        except BaseException as exc:
            result, error = None, exc
        self.signal.emit(self.callback, result, error)


class StorageRunner(QObject):
    """串行写盘；回调和完成计数通过 queued signal 回到对象所属主线程。"""

    _done = Signal(object, object, object)
    changed = Signal()
    failed = Signal(str)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._pool = QThreadPool(self)
        self._pool.setMaxThreadCount(1)
        self._count = 0
        self._closed = False
        self._lock = threading.Lock()
        self._done.connect(self._dispatch, Qt.ConnectionType.QueuedConnection)

    @property
    def busy(self) -> bool:
        with self._lock:
            return self._count > 0

    def submit(self, operation: StorageOperation, callback: StorageCallback | None = None) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("存储队列已关闭")
            self._count += 1
        self._pool.start(_StorageTask(operation, callback, self._done))
        self.changed.emit()

    @Slot(object, object, object)
    def _dispatch(self, callback: object, result: object, error: object) -> None:
        with self._lock:
            self._count -= 1
        try:
            if callable(callback):
                callback(result, error)
            elif isinstance(error, BaseException):
                self.failed.emit(Redactor().text(error))
        except Exception as exc:
            self.failed.emit(Redactor().text(f"存储回调失败：{exc}"))
        finally:
            self.changed.emit()

    def shutdown(self, wait_ms: int = 5000) -> bool:
        # 等待时让已结束操作的回调继续投递，避免关闭前漏报写盘错误。
        deadline = time.monotonic() + max(0, wait_ms) / 1000
        while self.busy and time.monotonic() < deadline:
            QCoreApplication.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 20)
        with self._lock:
            if self._count or not self._pool.waitForDone(0):
                return False
            self._closed = True
        return True


__all__ = ["JobRunner", "StorageRunner"]
