"""可视化访问链编辑器及业务任务依赖图。所有操作只改副本，点击应用才交回父编辑器。"""
from __future__ import annotations

from copy import deepcopy

from PySide6.QtCore import QMimeData, QTimer, Qt
from PySide6.QtGui import QDrag, QKeySequence, QUndoCommand, QUndoStack
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QFrame,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, QMessageBox,
    QPushButton, QScrollArea, QSpinBox, QSplitter, QToolButton, QVBoxLayout, QWidget,
)

from core.errors import ConfigError
from . import theme
from .chain_model import ChainDocument, ChainIssue
from .graph_canvas import GraphCanvas, KIND_MIME, STATE_LABELS
from .ui import FlowLayout, fit_dialog

LOGIN_TITLES = {
    "access_token": "已有 AT", "refresh": "使用 RT 续期", "cookie": "Cookie",
    "password": "账号密码", "browser_state": "恢复站点登录态", "oauth": "共享 OAuth 登录",
}


def _label(text="", style="hint"):
    label = QLabel(text)
    label.setObjectName(style)
    label.setWordWrap(True)
    return label


def _button(text, callback, kind=""):
    result = QPushButton(text)
    result.setCursor(Qt.CursorShape.PointingHandCursor)
    result.setAccessibleName(text)
    result.setProperty("kind", kind)
    result.clicked.connect(callback)
    return result


class _Snapshot(QUndoCommand):
    def __init__(self, caption, before, after, apply):
        super().__init__(caption)
        self.before, self.after = deepcopy(before), deepcopy(after)
        self.apply = apply

    def undo(self):
        self.apply(deepcopy(self.before))

    def redo(self):
        self.apply(deepcopy(self.after))


class _Palette(QListWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMaximumHeight(94)
        self.setDragEnabled(True)
        self.setAccessibleName("步骤库，可拖动到画布或双击添加")
        for key, caption in (("http", "H   HTTP 步骤"), ("browser", "B   浏览器步骤")):
            item = QListWidgetItem(caption)
            item.setData(Qt.ItemDataRole.UserRole, key)
            self.addItem(item)

    def startDrag(self, supportedActions):
        item = self.currentItem()
        if item is None:
            return
        mime = QMimeData()
        mime.setData(KIND_MIME, str(item.data(Qt.ItemDataRole.UserRole)).encode("ascii"))
        drag = QDrag(self)
        drag.setMimeData(mime)
        drag.exec(Qt.DropAction.CopyAction)


class ChainEditorDialog(QDialog):
    def __init__(
        self, chain: dict | None, template_chain: list[dict] | None = None, parent=None, *,
        theme_name=None, runtime_steps: list[dict] | None = None, read_only=False, account=None, task=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("访问链 · 执行记录" if read_only else "访问链编辑器")
        self.theme_name = theme_name or getattr(parent.window() if parent else None, "_theme", None) or theme.load_theme()
        self.setPalette(theme.palette(self.theme_name))
        self.setStyleSheet(theme.build_qss(self.theme_name))
        self.read_only = read_only
        self.account = deepcopy(account or {})
        self.task = deepcopy(task or {})
        self.runtime_steps = deepcopy(runtime_steps or [])
        self._initial = deepcopy(chain)
        self._selected = ""
        self._loading = False
        self._pending = False
        self._form_base = {}
        self._selection_guard = False
        self._simulation = None
        effective = deepcopy(chain)
        if read_only and self.runtime_steps and (effective is None or not template_chain and not effective.get("steps")):
            effective = {"use": "custom", "steps": [{
                "id": row["id"], "kind": row.get("kind", "http"), "title": row.get("title", row["id"]),
            } for row in self.runtime_steps if isinstance(row, dict) and row.get("id")]}
        self.doc = ChainDocument(effective, template_chain)
        self.undo_stack = QUndoStack(self)
        self._build()
        self._refresh()
        fit_dialog(self, 1240, 800, (760, 520))
        QTimer.singleShot(0, self.canvas.fit_graph)

    def _build(self):
        from .dialogs import ArgsEditor

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 16)
        root.setSpacing(12)
        top = QHBoxLayout()
        heading = QVBoxLayout()
        heading.setSpacing(5)
        heading.addWidget(_label("访问链", "pageTitle"))
        heading.addWidget(_label("为同一任务准备多种完成方式：前一步失败才尝试下一步，任一步成功即结束。"))
        top.addLayout(heading, 1)
        self.source = QComboBox()
        self.source.setAccessibleName("访问链来源")
        self.source.addItems(["原流程（不使用访问链）", "模板默认", "自定义"])
        self.source.currentIndexChanged.connect(self._source_changed)
        self.source.setEnabled(not self.read_only)
        top.addWidget(self.source)
        self.custom_button = _button("复制为自定义", lambda: self._change_source("custom"))
        top.addWidget(self.custom_button)
        root.addLayout(top)
        tool_frame = QFrame()
        tool_frame.setObjectName("toolbar")
        tools = FlowLayout(tool_frame, spacing=8, margins=(10, 8, 10, 8))
        undo = self.undo_stack.createUndoAction(self, "撤销")
        undo.setShortcut(QKeySequence.StandardKey.Undo)
        redo = self.undo_stack.createRedoAction(self, "重做")
        redo.setShortcut(QKeySequence.StandardKey.Redo)
        self.undo_action, self.redo_action = undo, redo
        for action in (undo, redo):
            self.addAction(action)
            control = QToolButton()
            control.setDefaultAction(action)
            control.setAccessibleName(action.text())
            tools.addWidget(control)
        self.auto_button = _button("自动布局", self.auto_layout)
        self.json_button = _button("高级 JSON", self._edit_json, "quiet")
        tools.addWidget(self.auto_button)
        tools.addWidget(self.json_button)
        self.preview_button = _button("预演路径", self._preview, "quiet")
        tools.addWidget(self.preview_button)
        tools.addWidget(_button("缩小", lambda: self.canvas.zoom(1 / 1.2), "quiet"))
        tools.addWidget(_button("放大", lambda: self.canvas.zoom(1.2), "quiet"))
        tools.addWidget(_button("适应画布", lambda: self.canvas.fit_graph(), "quiet"))
        legend = _label("橙色虚线：失败回退 · 坐标仅影响布局")
        legend.setWordWrap(False)
        tools.addWidget(legend)
        root.addWidget(tool_frame)
        self.notice = _label("", "activity")
        root.addWidget(self.notice)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(8)
        left = QWidget()
        left.setMinimumWidth(170)
        left.setMaximumWidth(250)
        column = QVBoxLayout(left)
        column.setContentsMargins(0, 0, 10, 0)
        column.setSpacing(8)
        column.addWidget(_label("添加步骤", "sectionTitle"))
        self.palette = _Palette()
        self.palette.itemDoubleClicked.connect(lambda item: self.add_step(item.data(Qt.ItemDataRole.UserRole)))
        column.addWidget(self.palette)
        column.addWidget(_label("拖入画布，或双击加入所选步骤之后。"))
        column.addWidget(_label("执行顺序 / 列表操作", "sectionTitle"))
        self.step_list = QListWidget()
        self.step_list.setAccessibleName("访问步骤，按连线顺序排列")
        self.step_list.currentItemChanged.connect(self._list_selected)
        column.addWidget(self.step_list, 1)
        ordering = QHBoxLayout()
        self.up_button = _button("上移顺序", lambda: self._move_order(-1))
        self.down_button = _button("下移顺序", lambda: self._move_order(1))
        ordering.addWidget(self.up_button)
        ordering.addWidget(self.down_button)
        column.addLayout(ordering)
        splitter.addWidget(left)
        self.canvas = GraphCanvas(relation="failure", theme_name=self.theme_name, read_only=self.read_only)
        self.canvas.selection_changed.connect(self._canvas_selected)
        self.canvas.positions_changed.connect(self._positions_changed)
        self.canvas.connection_requested.connect(self.connect_steps)
        self.canvas.delete_requested.connect(self._delete)
        self.canvas.kind_dropped.connect(self._drop)
        self.canvas.node_activated.connect(lambda key: self.title_edit.setFocus())
        self.canvas.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.canvas.customContextMenuRequested.connect(self._context_menu)
        splitter.addWidget(self.canvas)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMinimumWidth(230)
        scroll.setMaximumWidth(360)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.inspector = QWidget()
        props = QVBoxLayout(self.inspector)
        props.setContentsMargins(12, 0, 4, 4)
        props.setSpacing(10)
        props.addWidget(_label("步骤属性", "sectionTitle"))
        self.empty = _label("在画布或列表中选择一个步骤。")
        props.addWidget(self.empty)
        self.form_widget = QWidget()
        form = QFormLayout(self.form_widget)
        form.setContentsMargins(0, 0, 0, 0)
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setVerticalSpacing(10)
        self.id_label = _label("", "hint")
        form.addRow("稳定标识 / 类型", self.id_label)
        self.title_edit = QLineEdit()
        self.title_edit.setAccessibleName("步骤显示名称")
        self.title_edit.textEdited.connect(self._touch)
        form.addRow("显示名称", self.title_edit)
        self.entry_button = _button("设为入口", self._set_entry)
        form.addRow(self.entry_button)
        self.inherit_login = QCheckBox("使用模板默认凭据来源")
        self.inherit_login.toggled.connect(self._touch)
        form.addRow(self.inherit_login)
        self.logins = QListWidget()
        self.logins.setMaximumHeight(132)
        self.logins.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.logins.itemChanged.connect(self._touch)
        self.logins.model().rowsMoved.connect(self._touch)
        self.logins.setAccessibleName("勾选凭据来源并拖动调整尝试顺序")
        form.addRow("凭据 / 登录（可拖动排序）", self.logins)
        self.timeout = QSpinBox()
        self.timeout.setRange(0, 7200)
        self.timeout.setSpecialValueText("共享任务剩余时间")
        self.timeout.setSuffix(" 秒")
        self.timeout.valueChanged.connect(self._touch)
        form.addRow("此步骤预算", self.timeout)
        self.target = QComboBox()
        self.target.setAccessibleName("失败后回退目标")
        self.target.currentIndexChanged.connect(self._touch)
        form.addRow("失败后", self.target)
        self.stop_on = QLineEdit()
        self.stop_on.setPlaceholderText("可选，如 blocked；多个原因用逗号分隔")
        self.stop_on.textEdited.connect(self._touch)
        form.addRow("以下失败直接结束", self.stop_on)
        props.addWidget(self.form_widget)
        self.args_editor = ArgsEditor()
        self.args_editor.changed.connect(self._touch)
        props.addWidget(self.args_editor)
        self.apply_props = _button("应用属性", self.apply_properties, "primary")
        props.addWidget(self.apply_props)
        actions = QHBoxLayout()
        self.copy_button = _button("复制步骤", self._duplicate, "quiet")
        self.delete_button = _button("删除步骤", lambda: self._delete([self._selected], []), "danger")
        actions.addWidget(self.copy_button)
        actions.addWidget(self.delete_button)
        props.addLayout(actions)
        self.runtime_label = _label("", "activity")
        self.runtime_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        props.addWidget(self.runtime_label)
        props.addStretch(1)
        scroll.setWidget(self.inspector)
        splitter.addWidget(scroll)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([190, 680, 300])
        root.addWidget(splitter, 1)
        self.issues_list = QListWidget()
        self.issues_list.setMaximumHeight(82)
        self.issues_list.setAccessibleName("配置校验问题列表")
        self.issues_list.itemActivated.connect(lambda item: self.canvas.select_node(item.data(Qt.ItemDataRole.UserRole), center=True))
        self.issues_list.itemClicked.connect(lambda item: self.canvas.select_node(item.data(Qt.ItemDataRole.UserRole), center=True))
        root.addWidget(self.issues_list)
        footer = QFrame()
        footer.setObjectName("dialogFooter")
        bottom = QHBoxLayout(footer)
        bottom.setContentsMargins(0, 12, 0, 0)
        self.status = _label("")
        bottom.addWidget(self.status, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.accept_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.accept_button.setText("关闭" if self.read_only else "应用到任务")
        self.accept_button.setProperty("kind", "primary")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setVisible(not self.read_only)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        bottom.addWidget(buttons)
        root.addWidget(footer)

    def value(self) -> dict | None:
        return deepcopy(self._initial) if self.read_only else self.doc.payload()

    def has_changes(self) -> bool:
        return not self.read_only and (self._pending or self.doc.payload() != self._initial)

    def _restore(self, value):
        self.doc = ChainDocument(value, self.doc.template_steps)
        self._pending = False
        self._simulation = None
        self._refresh()

    def _commit(self, caption, operation, *, flush=True) -> bool:
        if self.read_only or (flush and not self.apply_properties()):
            return False
        before = self.doc.payload()
        candidate = ChainDocument(before, self.doc.template_steps)
        try:
            result = operation(candidate)
        except (ConfigError, ValueError, TypeError, KeyError) as exc:
            self.notice.setText(str(exc))
            return False
        after = candidate.payload()
        if before != after:
            if isinstance(result, str) and candidate.step(result):
                self._selected = result
            self.undo_stack.push(_Snapshot(caption, before, after, self._restore))
        return True

    def _refresh(self):
        self._loading = True
        source = self.doc.source
        self.source.setCurrentIndex({"legacy": 0, "template": 1, "custom": 2}.get(source, 2))
        editable = source == "custom" and not self.read_only
        self.palette.setEnabled(editable)
        self.custom_button.setVisible(not self.read_only and source != "custom")
        self.auto_button.setEnabled(not self.read_only and bool(self.doc.steps()))
        self.json_button.setEnabled(not self.read_only)
        self.preview_button.setEnabled(bool(self.doc.steps()) and not self.read_only)
        self.canvas.read_only = self.read_only or source != "custom"
        states = {row.get("id"): row for row in (self._simulation or self.runtime_steps)}
        order = self.doc.order()
        raw = self.doc.steps()
        if not self.doc.step(self._selected):
            self._selected = order[0] if order else (str(raw[0].get("id", "")) if raw else "")
        sorted_nodes = sorted(raw, key=lambda x: order.index(x.get("id")) if x.get("id") in order else len(order))
        nodes = []
        self.step_list.blockSignals(True)
        self.step_list.clear()
        for row in sorted_nodes:
            key = str(row.get("id") or "")
            index = order.index(key) + 1 if key in order else "—"
            title = str(row.get("title") or key)
            login = row.get("login", [])
            if isinstance(login, str):
                login = [login]
            subtitle = " · ".join(LOGIN_TITLES.get(item, item) for item in login) or "凭据来源继承模板"
            state = states.get(key, {}).get("status", "")
            nodes.append({"id": key, "kind": row.get("kind", "http"), "title": title, "index": index,
                          "entry": key == self.doc.entry(), "subtitle": subtitle, "unreachable": key not in order,
                          "state": state, "tooltip": f"{key} · {title}"})
            item = QListWidgetItem(f"{index}  {title}\n{STATE_LABELS.get(state) or key}")
            item.setData(Qt.ItemDataRole.UserRole, key)
            self.step_list.addItem(item)
            if key == self._selected:
                self.step_list.setCurrentItem(item)
        self.step_list.blockSignals(False)
        edges = [{"source": a, "target": b, "active": states.get(a, {}).get("status") == "failed" and
                  states.get(b, {}).get("status") not in (None, "not_run")} for a, b in self.doc.links()]
        self.canvas.load_graph(nodes, edges, self.doc.positions(), self._selected)
        self._show_form()
        if self.read_only:
            text = "只读运行快照；节点状态来自实际记录，不会修改配置。"
        elif self._simulation:
            text = "模拟执行路径（没有访问任何站点）。修改配置后退出预演。"
        elif source == "template":
            text = "当前继承模板默认链。要调整步骤，请先复制为自定义；不会修改其他账号。"
        elif source == "legacy":
            text = "当前仍使用原流程，未做任何自动转换。选择模板默认或自定义后才启用访问链。"
        else:
            text = "拖动右侧端口建立失败回退，或在属性里选择目标。拖动节点只改布局；Ctrl + 滚轮缩放，中键平移。"
        self.notice.setText(text)
        self._loading = False
        self._validate()

    def _show_form(self):
        self._loading = True
        step = self.doc.step(self._selected)
        self.empty.setVisible(step is None)
        self.form_widget.setVisible(step is not None)
        self.args_editor.setVisible(step is not None and not self.read_only)
        self.apply_props.setVisible(not self.read_only)
        editable = bool(step) and self.doc.source == "custom" and not self.read_only
        for button in (self.copy_button, self.delete_button, self.up_button, self.down_button):
            button.setEnabled(editable)
        self.form_widget.setEnabled(editable)
        self.args_editor.setEnabled(editable)
        self.apply_props.setEnabled(editable and self._pending)
        if step is not None:
            self._form_base = deepcopy(step)
            self.id_label.setText(f"{step['id']} / {step.get('kind', '')}")
            self.title_edit.setText(str(step.get("title") or ""))
            logins = step.get("login") or []
            if isinstance(logins, str):
                logins = [logins]
            defaults = ["access_token", "refresh", "cookie", "password"] if step.get("kind") == "http" else ["browser_state", "oauth", "password"]
            choices = list(dict.fromkeys([*logins, *defaults]))
            self.logins.clear()
            for method in choices:
                item = QListWidgetItem(LOGIN_TITLES.get(method, method))
                item.setData(Qt.ItemDataRole.UserRole, method)
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Checked if method in logins else Qt.CheckState.Unchecked)
                self.logins.addItem(item)
            self.inherit_login.setChecked(not logins)
            self.logins.setEnabled(editable and not self.inherit_login.isChecked())
            self.timeout.setValue(step.get("timeout") if type(step.get("timeout")) is int else 0)
            self.target.clear()
            self.target.addItem("结束（不再回退）", "")
            for other in self.doc.steps():
                if other.get("id") != step["id"]:
                    self.target.addItem(f"{other.get('title') or other['id']} · {other['id']}", other["id"])
            target = dict(self.doc.links()).get(step["id"], "")
            self.target.setCurrentIndex(max(0, self.target.findData(target)))
            reasons = step.get("stop_on", [])
            self.stop_on.setText(reasons if isinstance(reasons, str) else ", ".join(reasons))
            self.args_editor.set_value(step.get("args"))
            self.entry_button.setText("当前入口" if step["id"] == self.doc.entry() else "设为入口")
            self.entry_button.setEnabled(editable and step["id"] != self.doc.entry())
        runtime = next((item for item in self.runtime_steps if item.get("id") == self._selected), None)
        self.runtime_label.setVisible(bool(runtime))
        if runtime:
            texts = [f"执行状态：{STATE_LABELS.get(runtime.get('status'), runtime.get('status', ''))}"]
            if runtime.get("duration_seconds") is not None:
                texts.append(f"用时：{runtime['duration_seconds']} 秒")
            for key in ("reason", "message"):
                if runtime.get(key):
                    texts.append(str(runtime[key]))
            texts.extend(str(value) for value in runtime.get("login", []) if isinstance(value, str))
            self.runtime_label.setText("\n".join(texts))
        self._pending = False
        self._loading = False

    def _touch(self, *_args):
        if self._loading or self.read_only:
            return
        self._pending = True
        self.apply_props.setEnabled(True)
        self.undo_action.setEnabled(False)
        self.redo_action.setEnabled(False)
        self.logins.setEnabled(not self.inherit_login.isChecked())
        self.status.setText("属性已修改 · 点击应用属性，或完成编辑时统一应用；尚未写入磁盘。")

    def apply_properties(self) -> bool:
        if not self._pending or self.read_only:
            return True
        patch, remove = {}, []
        baseline = self._form_base
        if self.title_edit.text() != str(baseline.get("title") or ""):
            patch["title"] = self.title_edit.text()
        selected = [self.logins.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.logins.count())
                    if self.logins.item(i).checkState() == Qt.CheckState.Checked]
        before_logins = baseline.get("login", [])
        before_logins = [before_logins] if isinstance(before_logins, str) else before_logins
        if self.inherit_login.isChecked():
            if before_logins:
                remove.append("login")
        elif not selected:
            self.notice.setText("至少勾选一种凭据来源，或启用「使用模板默认凭据来源」。")
            return False
        elif selected != before_logins:
            patch["login"] = selected
        if self.timeout.value() != (baseline.get("timeout") or 0):
            if self.timeout.value() == 0:
                remove.append("timeout")
            else:
                patch["timeout"] = self.timeout.value()
        reasons = [text.strip() for text in self.stop_on.text().replace("，", ",").split(",") if text.strip()]
        old_reasons = baseline.get("stop_on", [])
        old_reasons = [old_reasons] if isinstance(old_reasons, str) else old_reasons
        if reasons != old_reasons:
            if reasons:
                patch["stop_on"] = reasons
            else:
                remove.append("stop_on")
        try:
            if self.args_editor.has_pending_changes():
                patch["args"] = self.args_editor.value()
        except (ConfigError, ValueError, TypeError):
            self.notice.setText("步骤参数格式不正确，请检查参数编辑器。")
            return False
        target = self.target.currentData() or ""
        key = self._selected
        before = self.doc.payload()
        candidate = ChainDocument(before, self.doc.template_steps)
        try:
            candidate.update(key, patch, tuple(remove))
            if target != dict(self.doc.links()).get(key, ""):
                candidate.connect(key, target)
            issues = [item for item in candidate.issues() if item.severity == "error"]
            if issues:
                raise ConfigError(issues[0].message)
        except (ConfigError, TypeError, ValueError) as exc:
            self.notice.setText(str(exc))
            return False
        self._pending = False
        if before != candidate.payload():
            self.undo_stack.push(_Snapshot("修改步骤属性", before, candidate.payload(), self._restore))
        self.apply_props.setEnabled(False)
        self._validate()
        return True

    def _select(self, key):
        if key == self._selected or self._selection_guard:
            return
        if not self.apply_properties():
            self._selection_guard = True
            self.canvas.select_node(self._selected)
            for i in range(self.step_list.count()):
                if self.step_list.item(i).data(Qt.ItemDataRole.UserRole) == self._selected:
                    self.step_list.setCurrentRow(i)
            self._selection_guard = False
            return
        self._selected = key
        self._selection_guard = True
        self.canvas.select_node(key)
        for i in range(self.step_list.count()):
            if self.step_list.item(i).data(Qt.ItemDataRole.UserRole) == key:
                self.step_list.setCurrentRow(i)
        self._selection_guard = False
        self._show_form()

    def _list_selected(self, item, _previous):
        if not self._loading and item is not None:
            self._select(item.data(Qt.ItemDataRole.UserRole))

    def _canvas_selected(self, nodes, edges):
        if not self._loading and nodes:
            self._select(nodes[0])

    def _source_changed(self, index):
        if not self._loading:
            self._change_source(["legacy", "template", "custom"][index])

    def _change_source(self, source):
        if not self._commit("切换访问链来源", lambda doc: doc.select_source(source)):
            self.source.blockSignals(True)
            self.source.setCurrentIndex({"legacy": 0, "template": 1, "custom": 2}.get(self.doc.source, 0))
            self.source.blockSignals(False)

    def add_step(self, kind: str):
        after = self._selected if self._selected in self.doc.order() else ""
        point = self.doc.positions().get(after)
        position = [point[0] + 320, point[1]] if point else [len(self.doc.steps()) * 320, 0]
        self._commit("添加步骤", lambda doc: doc.add(kind, after=after, position=position))

    def _drop(self, kind, position, after):
        self._commit("拖入步骤", lambda doc: doc.add(kind, after=after, position=position))

    def connect_steps(self, source, target):
        self._commit("调整失败回退", lambda doc: doc.connect(source, target))

    def _positions_changed(self, positions):
        self._commit("移动节点", lambda doc: doc.set_positions(positions))

    def auto_layout(self):
        if self._commit("自动布局", lambda doc: doc.auto_layout()):
            self.canvas.fit_graph()

    def _move_order(self, direction):
        self._commit("调整执行顺序", lambda doc: doc.move_in_order(self._selected, direction))

    def _set_entry(self):
        self._commit("设置入口", lambda doc: doc.set_entry(self._selected))

    def _duplicate(self):
        self._commit("复制步骤", lambda doc: doc.duplicate(self._selected))

    def _delete(self, nodes, edges):
        if self.read_only:
            return
        if nodes:
            def remove(doc):
                doc.delete(nodes)
            self._commit("删除步骤并断开连接", remove)
        elif edges:
            def disconnect(doc):
                for source, _ in edges:
                    doc.connect(source, "")
            self._commit("断开回退连接", disconnect)

    def _context_menu(self, point):
        if self.read_only or self.doc.source != "custom":
            return
        menu = QMenu(self)
        nodes, edges = self.canvas.selected()
        if nodes:
            menu.addAction("设为入口", self._set_entry)
            menu.addAction("复制步骤", self._duplicate)
            menu.addAction("断开失败回退", lambda: self.connect_steps(nodes[0], ""))
            menu.addAction("删除步骤（断开关联连线）", lambda: self._delete(nodes, []))
        elif edges:
            menu.addAction("断开失败回退", lambda: self._delete([], edges))
        menu.addAction("自动布局（不改变顺序）", self.auto_layout)
        menu.exec(self.canvas.mapToGlobal(point))

    def _edit_json(self):
        from .dialogs import JsonDialog

        if not self.apply_properties():
            return
        dialog = JsonDialog("访问链 JSON（高级）", self.doc.payload() or {"use": "custom", "steps": []}, self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.has_changes():
            new = dialog.value()
            self.undo_stack.push(_Snapshot("修改访问链 JSON", self.doc.payload(), new, self._restore))

    def _validate(self):
        issues = self.doc.issues()
        reachable = set(self.doc.order())
        policy = self.task.get("policy") if isinstance(self.task.get("policy"), dict) else self.account.get("policy", {})
        for item in self.doc.steps():
            if item.get("kind") == "browser" and item.get("id") in reachable:
                if isinstance(policy, dict) and policy.get("allow_browser") is False:
                    issues.append(ChainIssue("warning", "当前策略禁用浏览器，该回退步骤运行时将不可用。", item["id"]))
                reference = self.task.get("template") or self.account.get("template")
                if reference == "newapi":
                    issues.append(ChainIssue("error", "NewAPI 浏览器签到尚未实现，请保留 HTTP 或原流程。", item["id"]))
        self.issues_list.clear()
        for issue in issues:
            item = QListWidgetItem(("错误 · " if issue.severity == "error" else "提示 · ") + issue.message)
            item.setData(Qt.ItemDataRole.UserRole, issue.node)
            self.issues_list.addItem(item)
        self.issues_list.setVisible(bool(issues))
        errors = sum(item.severity == "error" for item in issues)
        self.accept_button.setEnabled(self.read_only or errors == 0)
        self.undo_action.setEnabled(not self._pending and not self.read_only and self.undo_stack.canUndo())
        self.redo_action.setEnabled(not self._pending and not self.read_only and self.undo_stack.canRedo())
        self.status.setText("只读记录" if self.read_only else (
            f"{errors} 项错误 · 修正后可应用" if errors else
            f"校验通过 · {len(reachable)} 个可达步骤 · " + ("有未应用的更改" if self.has_changes() else "未更改")
        ))
        return errors == 0

    def _preview(self):
        if not self.apply_properties() or not self._validate():
            return
        order = self.doc.order()
        menu = QMenu(self)
        for failed_count in range(len(order) + 1):
            caption = "首步成功" if not failed_count else f"前 {failed_count} 步失败" + ("（全部失败）" if failed_count == len(order) else "，下一步成功")
            menu.addAction(caption, lambda count=failed_count: self.simulate(count))
        menu.addSeparator()
        menu.addAction("退出预演", lambda: self.simulate(None))
        menu.exec(self.preview_button.mapToGlobal(self.preview_button.rect().bottomLeft()))

    def simulate(self, failed_count: int | None):
        self._simulation = None if failed_count is None else [{
            "id": key, "status": "failed" if i < failed_count else "success" if i == failed_count else "not_run",
        } for i, key in enumerate(self.doc.order())]
        self._refresh()

    def accept(self):
        if self.read_only or self.apply_properties() and self._validate():
            super().accept()

    def reject(self):
        if self.has_changes() and QMessageBox.question(
            self, "放弃编辑？", "这些更改尚未应用到任务。是否放弃？",
            QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        ) != QMessageBox.StandardButton.Discard:
            return
        super().reject()
