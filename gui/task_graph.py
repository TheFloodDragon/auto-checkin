"""业务任务依赖编辑器：与访问链分层，连线只表示成功依赖，不表示失败回退。"""
from __future__ import annotations

from copy import deepcopy

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QHBoxLayout, QListWidget, QListWidgetItem,
    QScrollArea, QSplitter, QToolButton, QVBoxLayout, QWidget,
)
from PySide6.QtGui import QUndoStack

from core.errors import ConfigError
from . import core, theme
from .chain_editor import _Snapshot, _button, _label
from .graph_canvas import GraphCanvas


class TaskDependencyDialog(QDialog):
    def __init__(self, account: dict, parent=None, *, theme_name=None):
        super().__init__(parent)
        self.setWindowTitle("任务依赖 · 成功后执行")
        self.resize(1060, 720)
        self.setMinimumSize(820, 540)
        name = theme_name or getattr(parent.window() if parent else None, "_theme", None) or theme.load_theme()
        self.setPalette(theme.palette(name))
        self.setStyleSheet(theme.build_qss(name))
        self._initial = {"tasks": deepcopy(account.get("tasks") or [{"id": "daily"}]),
                         "layout": deepcopy((account.get("display") or {}).get("task_layout", {}))}
        self.state = deepcopy(self._initial)
        self.selected = ""
        self.loading = False
        self.pending = False
        self.undo_stack = QUndoStack(self)
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 16)
        root.addWidget(_label("任务依赖", "accountTitle"))
        root.addWidget(_label("这里连接的是不同业务任务。所有前置任务完成后才执行后继；访问方式失败回退请在任务的访问链中配置。"))
        tools = QHBoxLayout()
        for action, key in ((self.undo_stack.createUndoAction(self, "撤销"), QKeySequence.StandardKey.Undo),
                            (self.undo_stack.createRedoAction(self, "重做"), QKeySequence.StandardKey.Redo)):
            action.setShortcut(key)
            self.addAction(action)
            button = QToolButton()
            button.setDefaultAction(action)
            tools.addWidget(button)
        tools.addWidget(_button("自动布局", self.auto_layout))
        tools.addStretch(1)
        tools.addWidget(_button("适应画布", lambda: self.canvas.fit_graph()))
        root.addLayout(tools)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.canvas = GraphCanvas(relation="success", theme_name=name)
        self.canvas.connection_requested.connect(self.connect_tasks)
        self.canvas.positions_changed.connect(self.set_positions)
        self.canvas.delete_requested.connect(self._delete)
        self.canvas.selection_changed.connect(self._selected)
        splitter.addWidget(self.canvas)
        right = QWidget()
        right.setMinimumWidth(260)
        right.setMaximumWidth(320)
        column = QVBoxLayout(right)
        column.addWidget(_label("执行计划", "sectionTitle"))
        self.order_list = QListWidget()
        self.order_list.setMaximumHeight(165)
        self.order_list.setAccessibleName("由任务依赖计算出的执行顺序")
        self.order_list.itemClicked.connect(lambda item: self.canvas.select_node(item.data(Qt.ItemDataRole.UserRole), center=True))
        column.addWidget(self.order_list)
        column.addWidget(_label("无依赖任务按列表顺序调度；拖动只改变布局。"))
        self.task_label = _label("选择任务编辑前置依赖", "sectionTitle")
        column.addWidget(self.task_label)
        self.dependencies = QListWidget()
        self.dependencies.setAccessibleName("前置任务，多个勾选表示全部依赖")
        self.dependencies.itemChanged.connect(self._touch)
        column.addWidget(self.dependencies, 1)
        self.apply_dependencies = _button("应用依赖", self._flush, "primary")
        column.addWidget(self.apply_dependencies)
        column.addWidget(_label("拖动任务右端口到后继节点建立依赖；选中连线按 Delete 断开。此处不会删除业务任务。"))
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setSizes([700, 280])
        root.addWidget(splitter, 1)
        self.error = _label("", "error")
        self.error.hide()
        root.addWidget(self.error)
        self.status = _label("")
        root.addWidget(self.status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.accept_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.accept_button.setText("应用到账号")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)
        self._refresh()
        QTimer.singleShot(0, self.canvas.fit_graph)

    def value(self) -> list[dict]:
        return deepcopy(self.state["tasks"])

    def layout_value(self) -> dict:
        return deepcopy(self.state["layout"])

    def has_changes(self) -> bool:
        return self.state != self._initial or self.pending

    def _ids(self, state=None):
        return {str(item.get("id") or f"task{i+1}"): item for i, item in enumerate((state or self.state)["tasks"])}

    def _order(self, state=None):
        tasks = self._ids(state)
        return core._dependency_order({key: list(item.get("depends_on") or []) for key, item in tasks.items()},
                                      list(tasks), "$.tasks")

    def _restore(self, state):
        self.state = state
        self.pending = False
        self._refresh()

    def _commit(self, text, candidate):
        try:
            self._order(candidate)
        except (ConfigError, TypeError, ValueError) as exc:
            self.error.setText(str(exc))
            self.error.show()
            return False
        self.error.hide()
        if self.state != candidate:
            self.undo_stack.push(_Snapshot(text, self.state, candidate, self._restore))
        return True

    def _refresh(self):
        self.loading = True
        tasks = self._ids()
        try:
            order = list(self._order())
            self.accept_button.setEnabled(True)
            self.error.hide()
        except ConfigError as exc:
            order = list(tasks)
            self.error.setText(str(exc))
            self.error.show()
            self.accept_button.setEnabled(False)
        if self.selected not in tasks:
            self.selected = order[0] if order else ""
        nodes = []
        edges = []
        warnings = []
        self.order_list.clear()
        for i, key in enumerate(order):
            item = tasks[key]
            title = item.get("title") or key
            nodes.append({"id": key, "kind": "task", "title": title, "index": i + 1,
                          "subtitle": key, "state": "" if item.get("enabled", True) else "unavailable",
                          "footer": "全部前置完成后执行" if item.get("depends_on") else "无前置依赖"})
            row = QListWidgetItem(f"{i+1}  {title}")
            row.setData(Qt.ItemDataRole.UserRole, key)
            self.order_list.addItem(row)
            for parent in item.get("depends_on") or []:
                edges.append({"source": parent, "target": key})
                if parent in tasks and tasks[parent].get("enabled", True) is False:
                    warnings.append(f"{key} 的前置 {parent} 已禁用")
        positions = self.state["layout"] if isinstance(self.state["layout"], dict) else {}
        positions = {key: value for key, value in positions.items() if isinstance(value, list) and len(value) == 2 and
                     all(type(v) in (float, int) and abs(v) <= 100000 for v in value)}
        self.canvas.load_graph(nodes, edges, positions, self.selected)
        self.dependencies.clear()
        current = tasks.get(self.selected, {})
        self.task_label.setText("前置依赖 · " + str(current.get("title") or self.selected))
        for key, item in tasks.items():
            if key == self.selected:
                continue
            row = QListWidgetItem(str(item.get("title") or key) + (" · 已禁用" if item.get("enabled", True) is False else ""))
            row.setData(Qt.ItemDataRole.UserRole, key)
            row.setFlags(row.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            row.setCheckState(Qt.CheckState.Checked if key in (current.get("depends_on") or []) else Qt.CheckState.Unchecked)
            self.dependencies.addItem(row)
        self.apply_dependencies.setEnabled(False)
        self.status.setText("；".join(warnings) if warnings else "蓝色实线 = 成功依赖；多个前置必须全部满足。应用后仍需在工作台保存。")
        self.loading = False

    def _touch(self, *_):
        if not self.loading:
            self.pending = True
            self.apply_dependencies.setEnabled(True)

    def _flush(self):
        if not self.pending:
            return True
        deps = [self.dependencies.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.dependencies.count())
                if self.dependencies.item(i).checkState() == Qt.CheckState.Checked]
        candidate = deepcopy(self.state)
        self._ids(candidate)[self.selected]["depends_on"] = deps
        if not self._commit("修改前置依赖", candidate):
            return False
        self.pending = False
        return True

    def _selected(self, nodes, edges):
        if self.loading or not nodes or nodes[0] == self.selected:
            return
        new = nodes[0]
        if self._flush():
            self.selected = new
            self._refresh()
        else:
            self.loading = True
            self.canvas.select_node(self.selected)
            self.loading = False

    def connect_tasks(self, source: str, target: str):
        if not self._flush():
            return False
        candidate = deepcopy(self.state)
        tasks = self._ids(candidate)
        if source not in tasks or target not in tasks:
            return False
        deps = list(tasks[target].get("depends_on") or [])
        if source not in deps:
            deps.append(source)
        tasks[target]["depends_on"] = deps
        return self._commit("建立任务成功依赖", candidate)

    def _delete(self, nodes, edges):
        if nodes:
            self.status.setText("这里只调整任务依赖。如需删除任务，请在账号的任务列表操作。")
        if not edges or not self._flush():
            return
        candidate = deepcopy(self.state)
        tasks = self._ids(candidate)
        for source, target in edges:
            tasks[target]["depends_on"] = [key for key in tasks[target].get("depends_on", []) if key != source]
        self._commit("断开任务依赖", candidate)

    def set_positions(self, positions):
        if self._flush():
            candidate = deepcopy(self.state)
            candidate["layout"] = {**(candidate.get("layout") or {}), **positions}
            self._commit("移动任务节点", candidate)

    def auto_layout(self):
        if not self._flush():
            return
        try:
            order = self._order()
        except ConfigError:
            return
        tasks = self._ids()
        levels, counts, positions = {}, {}, {}
        for key in order:
            depth = max((levels[parent] + 1 for parent in tasks[key].get("depends_on", [])), default=0)
            levels[key] = depth
            positions[key] = [depth * 330, counts.get(depth, 0) * 180]
            counts[depth] = counts.get(depth, 0) + 1
        self.set_positions(positions)
        self.canvas.fit_graph()

    def accept(self):
        if self._flush():
            try:
                self._order()
            except ConfigError as exc:
                self.error.setText(str(exc))
                self.error.show()
                return
            super().accept()
