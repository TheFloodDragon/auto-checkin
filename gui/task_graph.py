"""业务任务依赖编辑器：与访问链分层，连线只表示成功依赖，不表示失败回退。"""
from __future__ import annotations

import math
from copy import deepcopy

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFrame, QListWidget, QListWidgetItem,
    QSplitter, QToolButton, QVBoxLayout, QWidget,
)
from PySide6.QtGui import QUndoStack

from core.errors import ConfigError
from . import core, theme
from .chain_editor import _Snapshot, _button, _label
from .graph_canvas import GraphCanvas
from .ui import FlowLayout, fit_dialog


class TaskDependencyDialog(QDialog):
    def __init__(self, account: dict, parent=None, *, theme_name=None):
        super().__init__(parent)
        self.setWindowTitle("任务依赖 · 成功后执行")
        name = theme_name or getattr(parent.window() if parent else None, "_theme", None) or theme.load_theme()
        self.setPalette(theme.palette(name))
        self.setStyleSheet(theme.build_qss(name))
        # 坐标存顶层 task_layout 而不是 display：display 是 Mapping[str, str]，
        # 解析时每个值都会过 str()，嵌套坐标会被写成 "{'daily': [10, 20]}" 这样的
        # Python repr 字符串，再也读不回来。顶层未知键由 extras 原样往返。
        self._initial = {"tasks": deepcopy(account.get("tasks") or [{"id": "daily"}]),
                         "layout": deepcopy(account.get("task_layout") or {})}
        self.state = deepcopy(self._initial)
        self.selected = ""
        self.loading = False
        self.pending = False
        self.undo_stack = QUndoStack(self)
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 16)
        root.setSpacing(12)
        root.addWidget(_label("任务依赖", "pageTitle"))
        root.addWidget(_label("连接不同的业务任务：所有前置任务成功后才执行后继任务。失败回退请在任务访问链中配置。"))
        tool_frame = QFrame()
        tool_frame.setObjectName("toolbar")
        tools = FlowLayout(tool_frame, spacing=8, margins=(10, 8, 10, 8))
        for action, key in ((self.undo_stack.createUndoAction(self, "撤销"), QKeySequence.StandardKey.Undo),
                            (self.undo_stack.createRedoAction(self, "重做"), QKeySequence.StandardKey.Redo)):
            action.setShortcut(key)
            self.addAction(action)
            control = QToolButton()
            control.setDefaultAction(action)
            control.setAccessibleName(action.text())
            tools.addWidget(control)
        tools.addWidget(_button("自动布局", self.auto_layout))
        tools.addWidget(_button("适应画布", lambda: self.canvas.fit_graph(), "quiet"))
        legend = _label("蓝色实线：成功依赖 · 拖动只改变布局")
        legend.setWordWrap(False)
        tools.addWidget(legend)
        root.addWidget(tool_frame)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(8)
        self.canvas = GraphCanvas(relation="success", theme_name=name)
        self.canvas.connection_requested.connect(self.connect_tasks)
        self.canvas.positions_changed.connect(self.set_positions)
        self.canvas.delete_requested.connect(self._delete)
        self.canvas.selection_changed.connect(self._selected)
        splitter.addWidget(self.canvas)
        right = QWidget()
        right.setMinimumWidth(230)
        right.setMaximumWidth(340)
        column = QVBoxLayout(right)
        column.setContentsMargins(10, 0, 0, 0)
        column.setSpacing(9)
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
        self.accept_button.setProperty("kind", "primary")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)
        self._refresh()
        fit_dialog(self, 1080, 740, (720, 500))
        QTimer.singleShot(0, self.canvas.fit_graph)

    def value(self) -> list[dict]:
        return deepcopy(self.state["tasks"])

    def layout_value(self) -> dict:
        return deepcopy(self.state["layout"])

    def has_changes(self) -> bool:
        return self.state != self._initial or self.pending

    def _ids(self, state=None):
        """任务 id → 条目。缺 id 的位次名与 schema 的 ``task{i+1}`` 保持一致。

        重复 id 会让两个不同任务折叠成一个键，编辑依赖时其中一个被静默丢弃；
        这种草稿由 ``_conflict`` 拦在编辑之前，这里不再额外处理。
        """
        return {str(item.get("id") or f"task{i + 1}"): item for i, item in enumerate((state or self.state)["tasks"])}

    def _conflict(self, state=None) -> str:
        """返回阻止依赖编辑的原因；空字符串表示可以编辑。

        标识不唯一时，画布上的一个节点无法对应到确定的任务，任何依赖写回都可能
        落到另一个同名任务上。此时只展示、不允许编辑，请用户先在任务列表改 id。
        """
        seen: set[str] = set()
        for index, item in enumerate((state or self.state)["tasks"]):
            if not isinstance(item, dict):
                return "任务列表存在非对象条目，请先在任务列表修正。"
            key = str(item.get("id") or f"task{index + 1}")
            if key in seen:
                return f"任务 id {key} 重复，无法确定依赖归属；请先在任务列表改成唯一 id。"
            seen.add(key)
        return ""

    def _order(self, state=None):
        tasks = self._ids(state)
        return core._dependency_order({key: list(item.get("depends_on") or []) for key, item in tasks.items()},
                                      list(tasks), "$.tasks")

    def _restore(self, state):
        self.state = state
        self.pending = False
        self._refresh()

    def _commit(self, text, candidate):
        # 标识歧义时一律不写回：写回的依赖可能落到另一个同名任务上。
        conflict = self._conflict(candidate) or self._conflict()
        if conflict:
            self.error.setText(conflict)
            self.error.show()
            return False
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
        conflict = self._conflict()
        try:
            order = list(self._order())
            self.accept_button.setEnabled(not conflict)
            self.error.hide()
        except ConfigError as exc:
            order = list(tasks)
            self.error.setText(str(exc))
            self.error.show()
            self.accept_button.setEnabled(False)
        if conflict:
            # 标识不唯一时一个节点对应不到确定的任务：只展示，不允许任何写回。
            self.error.setText(conflict)
            self.error.show()
            self.accept_button.setEnabled(False)
        self.canvas.read_only = bool(conflict)
        self.dependencies.setEnabled(not conflict)
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
        # NaN 会让 abs() 比较恒为假地通过，必须显式挡掉；它也不是合法 JSON。
        positions = {key: value for key, value in positions.items() if isinstance(value, list) and len(value) == 2 and
                     all(type(v) in (float, int) and math.isfinite(v) and abs(v) <= 100000 for v in value)}
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
        self.status.setText(conflict or ("；".join(warnings) if warnings else
                            "蓝色实线 = 成功依赖；多个前置必须全部满足。应用后仍需在工作台保存。"))
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
