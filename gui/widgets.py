"""v3 账号与多任务编辑器；表单是原始草稿上的稀疏编辑，不重新投影 schema。"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QMenu, QPushButton, QScrollArea, QStyle,
    QStyledItemDelegate, QTabWidget, QToolButton, QVBoxLayout, QWidget,
)

from core.account import CREDENTIAL_FIELDS
from core.errors import ConfigError

from . import core, theme
from .proxy_widgets import ProxySelector
from .dialogs import ArgsEditor, JsonDialog, OpenCombo, SecretEdit, TaskDialog, argument_specs, button, catalog_entry, label


ACCOUNT_CARD_ROLE = int(Qt.ItemDataRole.UserRole) + 1
CARD_HEIGHT = 72


class NavRail(QFrame):
    """左侧窄导航：品牌块、页面按钮与底部工具按钮；只发页面索引信号。"""

    activated = Signal(int)

    def __init__(self, pages: list[tuple[str, str]], parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("navRail")
        self.setFixedWidth(72)
        self._buttons: list[QToolButton] = []
        column = QVBoxLayout(self)
        column.setContentsMargins(8, 14, 8, 12)
        column.setSpacing(4)
        brand = QLabel("D")
        brand.setObjectName("brandMark")
        brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        brand.setFixedSize(36, 36)
        column.addWidget(brand, 0, Qt.AlignmentFlag.AlignHCenter)
        column.addSpacing(10)
        for index, (icon, text) in enumerate(pages):
            item = QToolButton()
            item.setProperty("kind", "nav")
            item.setText(f"{icon}\n{text}")
            item.setCheckable(True)
            item.setAutoExclusive(True)
            item.setCursor(Qt.CursorShape.PointingHandCursor)
            item.setFixedSize(56, 54)
            item.setToolTip(text)
            item.clicked.connect(lambda _checked=False, page=index: self.activated.emit(page))
            column.addWidget(item, 0, Qt.AlignmentFlag.AlignHCenter)
            self._buttons.append(item)
        column.addStretch(1)
        self.tools = QVBoxLayout()
        self.tools.setSpacing(4)
        column.addLayout(self.tools)
        if self._buttons:
            self._buttons[0].setChecked(True)

    def add_tool(self, widget: QWidget) -> None:
        widget.setFixedSize(56, 34)
        self.tools.addWidget(widget, 0, Qt.AlignmentFlag.AlignHCenter)

    def labels(self) -> list[str]:
        return [item.text().split("\n", 1)[-1] for item in self._buttons]

    def set_current(self, index: int) -> None:
        if 0 <= index < len(self._buttons):
            self._buttons[index].setChecked(True)


class AccountCardDelegate(QStyledItemDelegate):
    """账号卡只绘制脱敏后的展示数据；三行紧凑布局，长文本按宽度省略。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._colors = theme.tokens(theme.DEFAULT_THEME)

    def set_theme(self, name: str) -> None:
        self._colors = theme.tokens(name)

    def sizeHint(self, option, index) -> QSize:  # noqa: N802
        return QSize(240, CARD_HEIGHT)

    def paint(self, painter: QPainter, option, index) -> None:
        data = index.data(ACCOUNT_CARD_ROLE) or {}
        if not data:
            super().paint(painter, option, index)
            return
        t = self._colors
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        hovered = bool(option.state & QStyle.StateFlag.State_MouseOver)
        rect = QRectF(option.rect).adjusted(4, 2, -4, -2)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        if selected or hovered:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(t["selection"] if selected else t["hover"]))
            painter.drawRoundedRect(rect, 8, 8)
        if selected:
            painter.setBrush(QColor(t["accent"]))
            painter.drawRoundedRect(QRectF(rect.left(), rect.top() + 14, 3, rect.height() - 28), 1.5, 1.5)
        font = QFont(option.font)

        def text(value: str, x: float, y: float, width: float, size: int, color: str, bold: bool = False) -> None:
            font.setPixelSize(size)
            font.setWeight(QFont.Weight.DemiBold if bold else QFont.Weight.Normal)
            painter.setFont(font)
            painter.setPen(QColor(color))
            line = painter.fontMetrics().elidedText(" ".join(str(value).split()), Qt.TextElideMode.ElideRight, max(0, int(width)))
            painter.drawText(QRectF(x, y, width, 20), Qt.AlignmentFlag.AlignVCenter, line)

        tone = str(data.get("tone") or "muted")
        color = t.get(tone, t["muted"])
        left = rect.left() + 12
        width = rect.width() - 24
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(color))
        painter.drawEllipse(QRectF(rect.right() - 18, rect.top() + 12, 7, 7))
        text(data.get("name", ""), left, rect.top() + 6, width - 16, 13, t["text"], True)
        text(data.get("summary", "尚无返回文本"), left, rect.top() + 26, width,
             12, t["danger"] if tone == "danger" else t["text"] if data.get("has_result") else t["muted"])
        text(data.get("host", ""), left, rect.top() + 46, width - 70, 10, t["muted"])
        painter.setFont(font)
        font.setPixelSize(10)
        painter.setPen(QColor(color))
        painter.drawText(QRectF(rect.right() - 76, rect.top() + 46, 66, 20),
                         Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, str(data.get("status", "")))
        painter.restore()


class AccountEditor(QWidget):
    changed = Signal()
    run_requested = Signal(str)
    capture_requested = Signal()
    manage_proxies = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._account: dict | None = None
        self._initial: dict | None = None
        self._catalog: list[dict] = []
        self._loading = False
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        self.empty_hint = label("选择一个账号开始编辑，或新增 / 导入账号。")
        root.addWidget(self.empty_hint)
        self.tabs = QTabWidget()
        self.tabs.setObjectName("configTabs")
        self.tabs.tabBar().setDrawBase(False)
        root.addWidget(self.tabs, 1)
        self.tabs.addTab(self._build_account(), "基本信息")
        self.tabs.addTab(self._build_login(), "登录与凭据")
        self.tabs.addTab(self._build_tasks(), "多任务")
        self.tabs.addTab(self._build_advanced(), "高级设置")
        self.error_label = label("", "error")
        self.error_label.hide()
        root.addWidget(self.error_label)
        self.set_account(None)

    @staticmethod
    def _scroll(content: QWidget) -> QScrollArea:
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.Shape.NoFrame)
        area.setWidget(content)
        return area

    @staticmethod
    def _page() -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        column = QVBoxLayout(page)
        column.setContentsMargins(4, 12, 12, 12)
        column.setSpacing(10)
        return page, column

    @staticmethod
    def _form() -> QFormLayout:
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(8)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return form

    def _build_account(self) -> QWidget:
        page, column = self._page()
        column.addWidget(label("账号信息", "sectionTitle"))
        column.addWidget(label("稳定 ID 是历史结果的锚点，改名不改变 ID；模板可以是内置名称或脚本路径。"))
        form = self._form()
        self.fields: dict[str, QWidget] = {}
        for key, title in (("id", "稳定账号 ID"), ("name", "账号名称"), ("base_url", "站点地址"), ("template", "账号模板")):
            field = OpenCombo() if key == "template" else QLineEdit()
            field.setObjectName("account_" + key)
            if key == "id":
                field.setReadOnly(True)
            elif isinstance(field, OpenCombo):
                field.lineEdit().setPlaceholderText("auto / 模板名称 / scripts/tasks/自定义.py")
                field.currentTextChanged.connect(lambda text, name=key: self._set_field(name, text))
            else:
                field.textChanged.connect(lambda text, name=key: self._set_field(name, text))
            if key == "base_url":
                field.setPlaceholderText("https://example.com")
            self.fields[key] = field
            form.addRow(title, field)
        self.enabled = QCheckBox("启用账号")
        self.enabled.setObjectName("account_enabled")
        self.enabled.toggled.connect(lambda value: self._set_field("enabled", value))
        form.addRow("状态", self.enabled)
        column.addLayout(form)
        self.template_hint = label("可先填写模板路径；模板发现失败也不会改写已填内容。")
        column.addWidget(self.template_hint)
        column.addWidget(label("网络与代理", "sectionTitle"))
        self.proxy_selector = ProxySelector()
        self.proxy_selector.changed.connect(self._set_network)
        self.proxy_selector.manage_requested.connect(self.manage_proxies.emit)
        column.addWidget(self.proxy_selector)
        column.addStretch(1)
        return self._scroll(page)

    def _build_login(self) -> QWidget:
        page, column = self._page()
        column.addWidget(label("登录方式", "sectionTitle"))
        column.addWidget(label("登录方式是开放集合；切换方式不会清空凭据，备选链保留顺序和扩展字段。"))
        form = self._form()
        self.login_fields: dict[str, OpenCombo] = {}
        for key, title in (("method", "主登录方式"), ("provider", "OAuth 提供商"), ("account", "共享 OAuth 账号")):
            field = OpenCombo()
            field.setObjectName("login_" + key)
            if key == "provider":
                field.choices(["linuxdo", "github"])
            field.lineEdit().setPlaceholderText("留空使用默认值；可自由输入")
            field.currentTextChanged.connect(lambda text, name=key: self._set_login(name, text))
            self.login_fields[key] = field
            form.addRow(title, field)
        column.addLayout(form)
        self.login_args = ArgsEditor()
        self.login_args.changed.connect(self._changed)
        column.addWidget(self.login_args)
        row = QHBoxLayout()
        row.addWidget(button("编辑备选登录链 JSON", self._edit_fallback))
        row.addWidget(button("捕获登录态", lambda: self.capture_requested.emit()))
        row.addStretch(1)
        column.addLayout(row)
        column.addSpacing(6)
        column.addWidget(label("账号凭据", "sectionTitle"))
        column.addWidget(label("凭据仅保存在当前草稿；点击显示才会明文展示。cookie_file 保留文件引用。"))
        credentials = self._form()
        self.credential_fields: dict[str, SecretEdit] = {}
        for key in (*CREDENTIAL_FIELDS, "user_id", "cookie_file"):
            field = SecretEdit()
            field.setObjectName("credential_" + key)
            field.setPlaceholderText("未设置")
            field.textChanged.connect(lambda text, name=key: self._set_credential(name, text))
            self.credential_fields[key] = field
            credentials.addRow(key, field)
        column.addLayout(credentials)
        column.addStretch(1)
        return self._scroll(page)

    def _build_tasks(self) -> QWidget:
        page, column = self._page()
        heading = QHBoxLayout()
        heading.addWidget(label("任务配置", "sectionTitle"), 1)
        self.add_task_button = button("新增任务", self.add_task)
        heading.addWidget(self.add_task_button)
        column.addLayout(heading)
        column.addWidget(label("双击编辑；执行顺序由前置依赖决定。"))
        self.task_list = QListWidget()
        self.task_list.setObjectName("taskList")
        self.task_list.currentRowChanged.connect(lambda _index: self._task_actions())
        self.task_list.itemDoubleClicked.connect(lambda _item: self.edit_task())
        column.addWidget(self.task_list, 1)
        actions = QHBoxLayout()
        self.edit_task_button = button("编辑任务", self.edit_task)
        self.copy_task_button = button("复制", self.copy_task, "quiet")
        self.more_tasks_button = QPushButton("更多")
        self.more_tasks_button.setProperty("kind", "quiet")
        menu = QMenu(self.more_tasks_button)
        self.task_up_button = menu.addAction("上移", lambda: self.move_task(-1))
        self.task_down_button = menu.addAction("下移", lambda: self.move_task(1))
        menu.addSeparator()
        self.task_toggle_button = menu.addAction("启用 / 禁用", self.toggle_task)
        self.delete_task_button = menu.addAction("删除任务", self.delete_task)
        self.more_tasks_button.setMenu(menu)
        for control in (self.edit_task_button, self.copy_task_button, self.more_tasks_button):
            actions.addWidget(control)
        actions.addStretch(1)
        self.task_run_button = button("运行所选任务", self._run_selected, "primary")
        actions.addWidget(self.task_run_button)
        column.addLayout(actions)
        self.task_hint = label("运行时会自动包含所选任务的前置依赖。")
        column.addWidget(self.task_hint)
        return page

    def _build_advanced(self) -> QWidget:
        page, column = self._page()
        column.addWidget(label("高级设置", "sectionTitle"))
        column.addWidget(label("各分区以 JSON 编辑，未知字段原样保留。"))
        for title, key, hint in (
            ("账号 flow", "flow", "login / prepare / detect / execute / verification / confirm / render；任务 flow 逐键覆盖。"),
            ("网络设置", "network", "proxy_mode / proxy / proxy_group、verify_ssl / referer_path 及扩展字段；基本信息页可选择代理。"),
            ("账号策略", "policy", "retry / allow_browser / headless / humanize / tolerate_failure；任务 policy 整体替代。"),
            ("展示设置", "display", "结果列名称及展示扩展。"),
        ):
            row = QHBoxLayout()
            row.setSpacing(12)
            control = button("编辑 " + title, lambda section=key: self._edit_section(section))
            control.setFixedWidth(150)
            row.addWidget(control)
            row.addWidget(label(hint), 1)
            column.addLayout(row)
        column.addSpacing(6)
        column.addWidget(label("完整账号 JSON", "sectionTitle"))
        row = QHBoxLayout()
        row.setSpacing(12)
        control = button("编辑完整 JSON", self._edit_account_json)
        control.setFixedWidth(150)
        row.addWidget(control)
        row.addWidget(label("含凭据；确认后整体替换草稿，稳定账号 ID 不可改变。"), 1)
        column.addLayout(row)
        column.addStretch(1)
        return self._scroll(page)

    @staticmethod
    def _check_containers(account: dict) -> None:
        def object_section(owner: dict, key: str) -> dict:
            value = owner.get(key)
            if value is not None and not isinstance(value, dict):
                raise ConfigError(f"账号 {key} 必须是 JSON 对象")
            return value or {}

        def login_shape(login: dict) -> None:
            object_section(login, "args")
            fallback = login.get("fallback")
            fallback = [] if fallback is None else fallback
            if not isinstance(fallback, list) or any(not isinstance(item, dict) for item in fallback):
                raise ConfigError("账号 login.fallback 必须是对象数组")
            for item in fallback:
                login_shape(item)

        core.fingerprint(account)
        for key in ("credentials", "network", "policy", "flow", "display"):
            object_section(account, key)
        login_shape(object_section(account, "login"))
        if "tasks" in account:
            tasks = account["tasks"]
            if not isinstance(tasks, list) or any(not isinstance(task, dict) for task in tasks):
                raise ConfigError("账号 tasks 必须是任务对象数组")
            for task in tasks:
                for key in ("args", "flow", "policy"):
                    object_section(task, key)
                dependencies = task.get("depends_on")
                if dependencies is not None and (
                    not isinstance(dependencies, list) or any(not isinstance(dep, str) for dep in dependencies)
                ):
                    raise ConfigError("任务 depends_on 必须是字符串数组")

    def set_account(self, account: dict | None) -> None:
        if account is not None:
            if not isinstance(account, dict):
                raise ConfigError("账号编辑器需要 JSON 对象")
            self._check_containers(account)
        self._loading = True
        self._account = deepcopy(account)
        self._initial = deepcopy(account)
        self.error_label.hide()
        self.tabs.setVisible(account is not None)
        self.empty_hint.setVisible(account is None)
        try:
            raw = account or {}
            for key, field in self.fields.items():
                value = raw.get(key)
                if key == "base_url" and "base_url" not in raw:
                    value = raw.get("url")
                text = "" if value is None else str(value)
                if isinstance(field, OpenCombo):
                    field.setEditText(text)
                else:
                    field.setText(text)
            self.enabled.setChecked(raw.get("enabled", True) is not False)
            login = raw.get("login") if isinstance(raw.get("login"), dict) else {}
            for key, field in self.login_fields.items():
                field.setEditText("" if login.get(key) is None else str(login[key]))
            self.login_args.set_value(login.get("args"))
            credentials = raw.get("credentials") if isinstance(raw.get("credentials"), dict) else {}
            for key, field in self.credential_fields.items():
                value = credentials.get(key, raw.get(key) if key in {"user_id", "cookie_file"} else None)
                field.conceal()
                field.setText("" if value is None else str(value))
            self.proxy_selector.set_network(raw.get("network"))
            self._refresh_catalog()
            self._refresh_tasks()
        finally:
            self._loading = False

    def value(self) -> dict:
        if self._account is None:
            return {}
        result = deepcopy(self._account)
        if self.login_args.has_pending_changes():
            if not isinstance(result.get("login"), dict):
                result["login"] = {}
            result["login"]["args"] = self.login_args.value()
        # 不进行 URL/可执行性校验，允许输入中的临时空值。完整校验交给保存/运行入口。
        self._check_containers(result)
        return result

    def has_pending_changes(self) -> bool:
        try:
            return core.fingerprint({"account": self.value() if self._account is not None else None}) != core.fingerprint(
                {"account": self._initial}
            )
        except ConfigError:
            return True

    def set_catalog(self, catalog: list[dict]) -> None:
        self._catalog = deepcopy(catalog)
        self._refresh_catalog()


    def set_proxy_context(self, payload: dict) -> None:
        self.proxy_selector.set_context(payload)


    def _set_network(self) -> None:
        if self._loading or self._account is None:
            return
        self._account["network"] = self.proxy_selector.value()
        self._changed()

    def _refresh_catalog(self) -> None:
        reference = self.fields["template"].currentText()
        self.fields["template"].choices([str(item["reference"]) for item in self._catalog if item.get("reference")])
        entry = catalog_entry(self._catalog, reference)
        self.login_fields["method"].choices([str(method) for method in entry.get("login_methods", [])])
        self.login_args.set_specs(argument_specs(entry, "login", self.login_fields["method"].currentText()))
        if entry.get("error"):
            self.template_hint.setText("该模板发现失败；保留当前模板路径，可以手工编辑参数。")
        elif entry:
            self.template_hint.setText(str(entry.get("description") or "模板已发现，可在登录及任务弹窗中编辑声明参数。"))
        else:
            self.template_hint.setText("未发现该模板的参数声明；路径仍原样保留，可用 JSON 手工填写参数。")

    def _set_field(self, name: str, value: Any) -> None:
        if self._loading or self._account is None:
            return
        # 原先使用 url 别名的账号继续编辑同一键，避免制造互相矛盾的两份 URL。
        key = "url" if name == "base_url" and "base_url" not in self._account and "url" in self._account else name
        self._account[key] = value
        if name == "template":
            self._refresh_catalog()
            self._refresh_tasks()
        if name == "enabled":
            self._task_actions()
        self._changed()

    def _set_login(self, name: str, value: str) -> None:
        if self._loading or self._account is None:
            return
        if not isinstance(self._account.get("login"), dict):
            self._account["login"] = {}
        self._account["login"][name] = value
        if name == "method":
            self._refresh_catalog()
        self._changed()

    def _set_credential(self, name: str, value: str) -> None:
        if self._loading or self._account is None:
            return
        credentials = self._account.get("credentials")
        # 兼容输入源保留在原来位置；不把根级 user_id/cookie_file 搬家或复制。
        if name in {"user_id", "cookie_file"} and name in self._account and (
            not isinstance(credentials, dict) or name not in credentials
        ):
            self._account[name] = value
        else:
            if not isinstance(credentials, dict):
                self._account["credentials"] = {}
            self._account["credentials"][name] = value
        self._changed()

    def _changed(self) -> None:
        if not self._loading and self._account is not None:
            self.error_label.hide()
            self.changed.emit()

    def _error(self, message: str) -> None:
        self.error_label.setText(message)
        self.error_label.show()

    def _tasks(self) -> list[dict]:
        if self._account is None:
            return []
        if "tasks" not in self._account:
            return [{"id": "daily"}]
        tasks = self._account.get("tasks")
        return deepcopy(tasks) if isinstance(tasks, list) else []

    def selected_task_id(self) -> str:
        item = self.task_list.currentItem()
        return str(item.data(Qt.ItemDataRole.UserRole)) if item is not None else ""

    def _refresh_tasks(self, selected: str = "") -> None:
        selected = selected or self.selected_task_id()
        self.task_list.blockSignals(True)
        self.task_list.clear()
        target = 0
        for index, task in enumerate(self._tasks()):
            if not isinstance(task, dict):
                continue
            task_id = str(task.get("id") or f"task{index + 1}")
            state = "启用" if task.get("enabled", True) is not False else "禁用"
            title = str(task.get("title") or task_id)
            method = str(task.get("method") or "auto")
            reference = task.get("template") or (self._account or {}).get("template") or "auto"
            source = "任务覆盖" if task.get("template") else "继承账号"
            dependencies = task.get("depends_on") or []
            deps = "、".join(str(dep) for dep in dependencies) if isinstance(dependencies, list) else "配置类型待修复"
            detail = f"模板：{reference}（{source}）  |  前置：{deps or '无'}"
            item = QListWidgetItem(f"{title}  ·  {task_id}  ·  {method}  ·  {state}\n{detail}")
            item.setToolTip(detail)
            item.setData(Qt.ItemDataRole.UserRole, task_id)
            self.task_list.addItem(item)
            if task_id == selected:
                target = self.task_list.count() - 1
        if self.task_list.count():
            self.task_list.setCurrentRow(target)
        self.task_list.blockSignals(False)
        self._task_actions()

    def _task_actions(self) -> None:
        index = self.task_list.currentRow()
        tasks = self._tasks()
        valid = 0 <= index < len(tasks)
        for control in (self.edit_task_button, self.copy_task_button, self.task_toggle_button, self.task_run_button):
            control.setEnabled(valid)
        self.task_up_button.setEnabled(valid and index > 0)
        self.task_down_button.setEnabled(valid and index < len(tasks) - 1)
        reason = self._delete_reason(tasks, index)
        self.delete_task_button.setEnabled(valid and not reason)
        self.delete_task_button.setToolTip(reason)
        if valid:
            enabled = tasks[index].get("enabled", True) is not False
            self.task_toggle_button.setText("禁用所选任务" if enabled else "启用所选任务")
            self.task_run_button.setEnabled(enabled and (self._account or {}).get("enabled", True) is not False)

    @staticmethod
    def _delete_reason(tasks: list[dict], index: int) -> str:
        if not 0 <= index < len(tasks):
            return "请先选择任务"
        if len(tasks) <= 1:
            return "不能删除最后一个任务；请禁用任务或账号"
        selected = tasks[index].get("id")
        if any(selected in (task.get("depends_on") or []) for pos, task in enumerate(tasks) if pos != index):
            return "其他任务仍依赖此任务，请先调整前置依赖"
        return ""

    def _replace_tasks(self, tasks: list[dict], selected: str = "") -> None:
        if self._account is None:
            return
        self._account["tasks"] = deepcopy(tasks)
        self._refresh_tasks(selected)
        self._changed()

    def add_task(self, task: dict | None = None) -> bool:
        if self._account is None:
            return False
        tasks = self._tasks()
        used = {str(item.get("id")) for item in tasks}
        if task is None:
            try:
                account = self.value()
            except ConfigError:
                self._error("请先修复登录参数中的类型错误")
                return False
            candidate = {"id": core.unique_id("task", used)}
            dialog = TaskDialog(candidate, self, account=account, catalog=self._catalog)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return False
            candidate = dialog.value()
        else:
            candidate = deepcopy(task)
            candidate["id"] = core.unique_id(str(candidate.get("id") or "task"), used)
        tasks.append(candidate)
        self._replace_tasks(tasks, candidate["id"])
        return True

    def edit_task(self) -> bool:
        tasks = self._tasks()
        index = self.task_list.currentRow()
        if not 0 <= index < len(tasks):
            return False
        try:
            account = self.value()
        except ConfigError:
            self._error("请先修复登录参数中的类型错误")
            return False
        dialog = TaskDialog(tasks[index], self, account=account, catalog=self._catalog)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return False
        updated = dialog.value()
        if core.fingerprint(updated) != core.fingerprint(tasks[index]):
            tasks[index] = updated
            self._replace_tasks(tasks, str(updated.get("id") or ""))
        return True

    def copy_task(self) -> bool:
        tasks = self._tasks()
        index = self.task_list.currentRow()
        if not 0 <= index < len(tasks):
            return False
        clone = deepcopy(tasks[index])
        clone["id"] = core.unique_id(str(clone.get("id") or "task"), (str(item.get("id")) for item in tasks))
        tasks.insert(index + 1, clone)
        self._replace_tasks(tasks, clone["id"])
        return True

    def delete_task(self) -> bool:
        tasks = self._tasks()
        index = self.task_list.currentRow()
        reason = self._delete_reason(tasks, index)
        if reason:
            self._error(reason)
            return False
        tasks.pop(index)
        self._replace_tasks(tasks)
        return True

    def move_task(self, direction: int) -> bool:
        tasks = self._tasks()
        index = self.task_list.currentRow()
        target = index + direction
        if not 0 <= index < len(tasks) or not 0 <= target < len(tasks):
            return False
        tasks[index], tasks[target] = tasks[target], tasks[index]
        self._replace_tasks(tasks, str(tasks[target].get("id") or ""))
        return True

    def toggle_task(self) -> bool:
        tasks = self._tasks()
        index = self.task_list.currentRow()
        if not 0 <= index < len(tasks):
            return False
        tasks[index]["enabled"] = tasks[index].get("enabled", True) is False
        self._replace_tasks(tasks, str(tasks[index].get("id") or ""))
        return True

    def _run_selected(self) -> None:
        task_id = self.selected_task_id()
        if task_id:
            self.run_requested.emit(task_id)

    def _edit_fallback(self) -> None:
        if self._account is None:
            return
        login = self._account.get("login") if isinstance(self._account.get("login"), dict) else {}
        current = deepcopy(login.get("fallback", []))
        dialog = JsonDialog("备选登录链（依次尝试，可含凭据）", current, self, expected_type=list)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.has_changes():
            value = dialog.value()
            if any(not isinstance(item, dict) for item in value):
                self._error("备选登录链的每一项必须是 JSON 对象")
                return
            if not isinstance(self._account.get("login"), dict):
                self._account["login"] = {}
            self._account["login"]["fallback"] = value
            self._changed()

    def _edit_section(self, key: str) -> None:
        if self._account is None:
            return
        current = deepcopy(self._account.get(key, {}))
        dialog = JsonDialog("账号 " + key + " JSON", current, self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.has_changes():
            self._account[key] = dialog.value()
            self._changed()

    def _edit_account_json(self) -> None:
        if self._account is None:
            return
        try:
            current = self.value()
        except ConfigError:
            self._error("请先修复登录参数中的类型错误")
            return
        dialog = JsonDialog("完整账号 JSON（包含凭据）", current, self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.has_changes():
            updated = dialog.value()
            if updated.get("id") != current.get("id"):
                self._error("稳定账号 ID 不可修改；需要新身份时请复制账号")
                return
            try:
                self._check_containers(updated)
            except ConfigError as exc:
                self._error(str(exc))
                return
            initial = self._initial
            self.set_account(updated)
            self._initial = initial
            self._changed()
