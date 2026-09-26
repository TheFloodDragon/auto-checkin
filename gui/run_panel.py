"""只读运行监视器：按请求隔离步骤与日志，不读取或修改当前配置草稿。"""
from __future__ import annotations

import time
from collections import deque
from copy import deepcopy

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHeaderView, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .graph_canvas import STATE_LABELS
from .ui import FlowLayout, table_placeholder


def chain_data(record: dict | None) -> dict:
    data = (record or {}).get("data")
    chain = data.get("chain") if isinstance(data, dict) else None
    return chain if isinstance(chain, dict) else {}


def chain_summary(record: dict | None) -> str:
    chain = chain_data(record)
    if not chain:
        return ""
    hit = chain.get("hit")
    rows = chain.get("steps") or []
    node = next((row for row in rows if isinstance(row, dict) and row.get("id") == hit), {})
    if hit:
        return "完成方式：" + str(node.get("title") or hit)
    return str(chain.get("summary") or "访问链未完成")


class RunPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.jobs = {}
        self.steps = {}
        self.logs = deque(maxlen=3000)
        self._active_steps = {}
        self._seen_tasks = set()
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 8, 0, 0)
        root.setSpacing(12)
        filters = FlowLayout(spacing=10)
        self.job_filter = QComboBox()
        self.job_filter.setAccessibleName("筛选运行请求")
        self.job_filter.setMinimumContentsLength(14)
        self.job_filter.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.job_filter.addItem("全部运行请求", "")
        self.task_filter = QComboBox()
        self.task_filter.addItem("全部任务", "")
        self.task_filter.setAccessibleName("筛选任务")
        self.task_filter.setMinimumContentsLength(10)
        self.task_filter.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.search = QLineEdit()
        self.search.setAccessibleName("搜索事件或失败原因")
        self.search.setPlaceholderText("搜索事件或失败原因…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(220)
        self.graph_button = QPushButton("查看执行图")
        self.graph_button.setToolTip("按运行快照展示实际执行路径")
        # 没有步骤记录时点开是一个空白对话框；等有记录再放行。
        self.graph_button.setEnabled(False)
        self.graph_button.clicked.connect(self.show_graph)
        self.clear_button = QPushButton("清空日志")
        self.clear_button.setProperty("kind", "quiet")
        self.clear_button.setToolTip("仅清空当前窗口中的日志，步骤记录会保留。")
        self.clear_button.clicked.connect(self.clear_logs)
        for widget in (self.job_filter, self.task_filter, self.search, self.graph_button, self.clear_button):
            filters.addWidget(widget)
        root.addLayout(filters)
        self.summary = QLabel("选择运行请求查看步骤；日志最多保留 3,000 行。")
        self.summary.setObjectName("activity")
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        root.addWidget(self.summary)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(8)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["任务", "步骤", "方式", "状态", "用时", "原因", "最新说明"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(42)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        for column, width in enumerate((120, 180, 82, 90, 78, 140)):
            self.table.setColumnWidth(column, width)
        self.table.currentCellChanged.connect(self._selection)
        table_placeholder(self.table, "暂无步骤记录", "开始运行后，这里会实时显示每个步骤的状态与耗时。", "activity")
        splitter.addWidget(self.table)
        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("logView")
        self.log_view.setAccessibleName("运行日志")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(3000)
        self.log_view.setPlaceholderText("暂无日志。选择运行请求后，实时日志会显示在这里。")
        splitter.addWidget(self.log_view)
        splitter.setSizes([280, 240])
        root.addWidget(splitter, 1)
        self.job_filter.currentIndexChanged.connect(self._filters_changed)
        self.task_filter.currentIndexChanged.connect(self._filters_changed)
        self.search.textChanged.connect(self._filters_changed)
        self._refresh = QTimer(self)
        self._refresh.setSingleShot(True)
        self._refresh.timeout.connect(self.refresh_steps)
        self._clock = QTimer(self)
        self._clock.setInterval(500)
        self._clock.timeout.connect(self._tick)
        self._clock.start()

    def register_job(self, job_id: str, title: str, task_ids=()):
        if job_id in self.jobs:
            return
        self.jobs[job_id] = {"title": title, "tasks": tuple(task_ids)}
        self.job_filter.addItem(f"{title} · {job_id[:6]}", job_id)
        for task in task_ids:
            self._add_task(task)

    def _add_task(self, task):
        if task and task not in self._seen_tasks:
            self._seen_tasks.add(task)
            self.task_filter.addItem(task, task)

    def select_job(self, job_id: str):
        index = self.job_filter.findData(job_id)
        if index >= 0:
            self.job_filter.setCurrentIndex(index)

    def append_log(self, job_id: str, line: str):
        task = self._active_steps.get(job_id, ("", ""))[0]
        row = (job_id, task, line)
        self.logs.append(row)
        if self._matches(*row):
            self.log_view.appendPlainText(line)

    def _matches(self, job, task, line=""):
        expected_job = self.job_filter.currentData()
        expected_task = self.task_filter.currentData()
        text = self.search.text().strip().casefold()
        return (not expected_job or job == expected_job) and (not expected_task or task == expected_task) and (
            not text or text in line.casefold()
        )

    def receive_event(self, job_id: str, event: dict):
        """输入必须已经在进程边界脱敏；不把事件中的配置或凭据写回草稿。"""
        if job_id not in self.jobs or not isinstance(event, dict):
            return
        fields = event.get("fields")
        fields = fields if isinstance(fields, dict) else {}
        task = event.get("task") or fields.get("task", "")
        step = fields.get("step", "")
        if not isinstance(task, str) or not isinstance(step, str) or not task or not step:
            return
        if self.jobs[job_id]["tasks"] and task not in self.jobs[job_id]["tasks"]:
            return
        self._add_task(task)
        self._active_steps[job_id] = (task, step)
        key = (job_id, task, step)
        item = self.steps.setdefault(key, {"id": step, "task": task, "kind": str(fields.get("kind") or ""), "status": "running"})
        status = fields.get("status")
        if status in STATE_LABELS:
            item["status"] = status
            if status == "running" and "started" not in item:
                item["started"] = time.monotonic()
            elif status != "running" and "started" in item:
                item["duration_seconds"] = max(0, time.monotonic() - item["started"])
        if isinstance(fields.get("reason"), str):
            item["reason"] = fields["reason"]
        item["message"] = str(event.get("message") or "")
        item["stage"] = str(event.get("stage") or "")
        self._refresh.start(60)

    def complete(self, job_id: str, records: list[dict]):
        for record in records:
            task = str(record.get("task_id") or "")
            chain = chain_data(record)
            for row in chain.get("steps", []):
                if isinstance(row, dict) and isinstance(row.get("id"), str):
                    self.steps[(job_id, task, row["id"])] = {**deepcopy(row), "task": task}
        self._active_steps.pop(job_id, None)
        self.refresh_steps()

    def fail(self, job_id: str, message: str):
        for key, row in self.steps.items():
            if key[0] == job_id and row.get("status") == "running":
                row.update(status="failed", message=message, reason="worker_error")
                if "started" in row:
                    row["duration_seconds"] = max(0, time.monotonic() - row["started"])
        self._active_steps.pop(job_id, None)
        self.refresh_steps()

    def _filters_changed(self, *_):
        self.log_view.setPlainText("\n".join(line for job, task, line in self.logs if self._matches(job, task, line)))
        self.refresh_steps()

    def clear_logs(self):
        self.logs.clear()
        self.log_view.clear()

    def _tick(self):
        if self.isVisible() and any(row.get("status") == "running" for row in self.steps.values()):
            self.refresh_steps()

    def refresh_steps(self):
        selected = self.table.item(self.table.currentRow(), 0)
        key = selected.data(Qt.ItemDataRole.UserRole) if selected else None
        rows = [(k, v) for k, v in self.steps.items() if self._matches(k[0], k[1], str(v.get("message", "")) + str(v.get("reason", "")))]
        self.table.blockSignals(True)
        self.table.setRowCount(len(rows))
        selection = -1
        for index, (item_key, row) in enumerate(rows):
            elapsed = row.get("duration_seconds")
            if row.get("status") == "running" and "started" in row:
                elapsed = max(0, time.monotonic() - row["started"])
            duration = f"{elapsed:.1f}s" if type(elapsed) in (float, int) else "—"
            values = [item_key[1], row.get("title") or row["id"], "HTTP" if row.get("kind") == "http" else "浏览器",
                      STATE_LABELS.get(row.get("status"), row.get("status", "—")), duration,
                      row.get("reason") or "—", row.get("message") or "—"]
            for col, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(f"{self.jobs.get(item_key[0], {}).get('title', item_key[0])}\n{value}" if col == 0 else str(value))
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, item_key)
                self.table.setItem(index, col, item)
            if item_key == key:
                selection = index
        self.table.blockSignals(False)
        if rows:
            self.table.selectRow(selection if selection >= 0 else 0)
        running = [(key, row) for key, row in rows if row.get("status") == "running"]
        self.summary.setText("当前步骤：" + "；".join(f"{key[1]} / {row.get('title') or key[2]}" for key, row in running)
                             if running else f"{len(rows)} 条步骤记录 · 来自运行快照，后续草稿修改不会覆盖这里。")
        self.graph_button.setEnabled(bool(rows))

    def _selection(self, *_):
        self.graph_button.setEnabled(self.table.currentRow() >= 0)

    def show_graph(self):
        item = self.table.item(self.table.currentRow(), 0)
        if item is None:
            return
        job, task, _step = item.data(Qt.ItemDataRole.UserRole)
        rows = [deepcopy(row) for key, row in self.steps.items() if key[:2] == (job, task)]
        show_chain_record({"data": {"chain": {"steps": rows}}}, self)


def show_chain_record(record, parent=None):
    from .chain_editor import ChainEditorDialog

    chain = chain_data(record)
    rows = [row for row in chain.get("steps", []) if isinstance(row, dict) and row.get("id")]
    if not rows:
        return
    # 只画实际发生的回退，不把未执行/不可达节点误连成运行路径。
    nodes = [{"id": row["id"], "kind": row.get("kind", "http"), "title": row.get("title", row["id"]),
              "on_failure": ""} for row in rows]
    for i, row in enumerate(rows[:-1]):
        if row.get("status") in ("failed", "unavailable") and rows[i + 1].get("status") not in ("not_run", None):
            nodes[i]["on_failure"] = nodes[i + 1]["id"]
    dialog = ChainEditorDialog({"use": "custom", "steps": nodes}, parent=parent, read_only=True, runtime_steps=rows)
    dialog.exec()
