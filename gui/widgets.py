"""v3 账号与多任务编辑器；表单是原始草稿上的稀疏编辑，不重新投影 schema。"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QMenu, QPushButton, QScrollArea, QStyle,
    QStyledItemDelegate, QTabWidget, QToolButton, QVBoxLayout, QWidget,
)

from core.account import CREDENTIAL_FIELDS
from core.errors import ConfigError

from . import core, theme
from .ui import FlowLayout, SectionCard, configure_form, icon
from .proxy_widgets import ProxySelector
from .dialogs import ArgsEditor, JsonDialog, OpenCombo, SecretEdit, TaskDialog, argument_specs, button, catalog_entry, label


ACCOUNT_CARD_ROLE = int(Qt.ItemDataRole.UserRole) + 1
CARD_HEIGHT = 94


class NoticeBanner(QFrame):
    """可关闭的非阻断提示，保持原 banner 的 text()/setText() 接口。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("banner")
        row = QHBoxLayout(self)
        row.setContentsMargins(12, 8, 8, 8)
        self.message = QLabel()
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setWordWrap(True)
        row.addWidget(self.message, 1)
        dismiss = QToolButton()
        dismiss.setText("×")
        dismiss.setAccessibleName("关闭提示")
        dismiss.setToolTip("关闭提示，不会丢弃草稿或更改任务状态")
        dismiss.setProperty("kind", "quiet")
        dismiss.clicked.connect(self.hide)
        row.addWidget(dismiss)

    def setText(self, value: str) -> None:
        self.message.setText(value)

    def text(self) -> str:
        return self.message.text()

    def setWordWrap(self, value: bool) -> None:
        self.message.setWordWrap(value)


class NavRail(QFrame):
    """可收起的工作区导航，视觉状态与业务页面索引保持独立。"""

    activated = Signal(int)

    def __init__(self, pages: list[tuple[str, str]], parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("navRail")
        self._pages = pages
        self._buttons: list[QToolButton] = []
        self._tools: list[QToolButton] = []
        self._compact = False
        self._column = QVBoxLayout(self)
        self._column.setContentsMargins(14, 24, 14, 16)
        self._column.setSpacing(6)
        brand_row = QHBoxLayout()
        brand_row.setSpacing(10)
        brand = QLabel("D")
        brand.setObjectName("brandMark")
        brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        brand.setFixedSize(40, 40)
        brand_row.addWidget(brand)
        self.brand_copy = QWidget()
        brand_text = QVBoxLayout(self.brand_copy)
        brand_text.setContentsMargins(0, 0, 0, 0)
        brand_text.setSpacing(2)
        name = QLabel("DailyTask")
        name.setObjectName("brandName")
        brand_text.addWidget(name)
        caption = QLabel("让每日任务井然有序")
        caption.setObjectName("brandCaption")
        brand_text.addWidget(caption)
        brand_row.addWidget(self.brand_copy, 1)
        self._column.addLayout(brand_row)
        self._column.addSpacing(24)
        self.caption = QLabel("工作空间")
        self.caption.setObjectName("navCaption")
        self._column.addWidget(self.caption)
        self._column.addSpacing(4)
        for index, (_symbol, text) in enumerate(pages):
            item = QToolButton()
            item.setProperty("kind", "nav")
            item.setText(text)
            item.setIconSize(QSize(20, 20))
            item.setCheckable(True)
            item.setAutoExclusive(True)
            item.setCursor(Qt.CursorShape.PointingHandCursor)
            item.setAccessibleName(text + "工作区")
            item.setToolTip(f"{text}  ·  Alt+{index + 1}")
            item.setShortcut(f"Alt+{index + 1}")
            item.clicked.connect(lambda _checked=False, page=index: self.activated.emit(page))
            self._column.addWidget(item)
            self._buttons.append(item)
        self._column.addStretch(1)
        divider = QFrame()
        divider.setObjectName("navDivider")
        divider.setFixedHeight(1)
        self._column.addWidget(divider)
        self._column.addSpacing(8)
        self.tools = QVBoxLayout()
        self.tools.setSpacing(4)
        self._column.addLayout(self.tools)
        self.local_hint = QLabel("本地配置 · 安全掌控")
        self.local_hint.setObjectName("navCaption")
        self.local_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._column.addSpacing(8)
        self._column.addWidget(self.local_hint)
        self.set_compact(False)
        self.set_theme(theme.DEFAULT_THEME)
        if self._buttons:
            self._buttons[0].setChecked(True)

    def add_tool(self, widget: QToolButton) -> None:
        self._tools.append(widget)
        widget.setIconSize(QSize(18, 18))
        self.tools.addWidget(widget)
        self._size_buttons()

    def labels(self) -> list[str]:
        return [text for _symbol, text in self._pages]

    def set_current(self, index: int) -> None:
        if 0 <= index < len(self._buttons):
            self._buttons[index].setChecked(True)

    def set_theme(self, name: str) -> None:
        colors = theme.tokens(name)
        for nav_button, (symbol, _text) in zip(self._buttons, self._pages):
            nav_button.setIcon(icon(symbol, colors["rail_text"], colors["rail_active"]))

    def set_compact(self, compact: bool) -> None:
        self._compact = compact
        self.setFixedWidth(76 if compact else 196)
        self._column.setContentsMargins(10 if compact else 14, 22, 10 if compact else 14, 14)
        self.brand_copy.setVisible(not compact)
        self.caption.setVisible(not compact)
        self.local_hint.setVisible(not compact)
        self._size_buttons()

    def _size_buttons(self) -> None:
        for nav_button in self._buttons + self._tools:
            nav_button.setProperty("compact", self._compact)
            nav_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon if self._compact
                                          else Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            nav_button.setFixedSize(56 if self._compact else 168, 54 if self._compact else 44)
            nav_button.style().unpolish(nav_button)
            nav_button.style().polish(nav_button)


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
        focused = bool(option.state & QStyle.StateFlag.State_HasFocus)
        rect = QRectF(option.rect).adjusted(2, 4, -2, -4)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor(t["accent"] if focused else t["hero_border"]), 1) if selected
                       else Qt.PenStyle.NoPen)
        painter.setBrush(QColor(t["selection"] if selected else t["hover"]) if selected or hovered
                         else Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(rect, 10, 10)
        font = QFont(option.font)

        def text(value: str, x: float, y: float, width: float, size: int, color: str, bold=False):
            font.setPixelSize(size)
            font.setWeight(QFont.Weight.DemiBold if bold else QFont.Weight.Normal)
            painter.setFont(font)
            painter.setPen(QColor(color))
            value = painter.fontMetrics().elidedText(" ".join(str(value).split()), Qt.TextElideMode.ElideRight,
                                                     max(0, int(width)))
            painter.drawText(QRectF(x, y, max(0, width), 20), Qt.AlignmentFlag.AlignVCenter, value)

        left, top, width = rect.left() + 12, rect.top() + 12, rect.width() - 24
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(t["hero_border"] if selected else t["raised"]))
        painter.drawRoundedRect(QRectF(left, top, 34, 34), 10, 10)
        font.setPixelSize(15)
        font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(font)
        painter.setPen(QColor(t["accent"] if selected else t["muted"]))
        painter.drawText(QRectF(left, top, 34, 34), Qt.AlignmentFlag.AlignCenter,
                         str(data.get("name") or "D")[:1].upper())
        text(data.get("name", ""), left + 45, top - 3, width - 61, 13, t["text"], True)
        text(data.get("host", ""), left + 45, top + 17, width - 45, 10, t["muted"])
        tone = str(data.get("tone") or "muted")
        color = t.get(tone, t["muted"])
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(color))
        painter.drawEllipse(QRectF(rect.right() - 20, top + 3, 6, 6))
        text(data.get("summary", "等待第一次运行"), left, top + 45, width - 52, 11,
             t["danger"] if tone == "danger" else t["muted"])
        text(data.get("status", ""), rect.right() - 58, top + 45, 48, 10, color)
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
        column.setContentsMargins(0, 12, 6, 8)
        column.setSpacing(16)
        return page, column

    @staticmethod
    def _form() -> QFormLayout:
        return configure_form(QFormLayout())

    def _build_account(self) -> QWidget:
        page, column = self._page()
        identity = SectionCard("账号信息", "为账号设置一个易于辨认的名称。稳定 ID 用于关联历史记录，不随名称变化。")
        form = self._form()
        self.fields: dict[str, QWidget] = {}
        for key, title in (("id", "稳定账号 ID"), ("name", "账号名称"), ("base_url", "站点地址"), ("template", "账号模板")):
            field = OpenCombo() if key == "template" else QLineEdit()
            field.setObjectName("account_" + key)
            field.setAccessibleName(title)
            if key == "id":
                field.setReadOnly(True)
                field.setToolTip("稳定 ID 关联配置、缓存和历史记录，不在此修改。")
            elif isinstance(field, OpenCombo):
                field.lineEdit().setPlaceholderText("auto / 模板名称 / scripts/tasks/自定义.py")
                field.currentTextChanged.connect(lambda text, name=key: self._set_field(name, text))
            else:
                field.textChanged.connect(lambda text, name=key: self._set_field(name, text))
            if key == "base_url":
                field.setPlaceholderText("https://example.com")
            elif key == "name":
                field.setPlaceholderText("例如：我的每日签到")
            self.fields[key] = field
            form.addRow(title, field)
        self.enabled = QCheckBox("启用此账号，允许执行每日任务")
        self.enabled.setObjectName("account_enabled")
        self.enabled.toggled.connect(lambda value: self._set_field("enabled", value))
        form.addRow("运行状态", self.enabled)
        identity.body.addLayout(form)
        self.template_hint = label("可先填写模板路径；模板发现失败也不会改写已填内容。")
        identity.body.addWidget(self.template_hint)
        column.addWidget(identity)
        network = SectionCard("网络与代理", "为当前账号选择访问出口，与任务运行和登录态捕获保持一致。")
        self.proxy_selector = ProxySelector()
        self.proxy_selector.changed.connect(self._set_network)
        self.proxy_selector.manage_requested.connect(self.manage_proxies.emit)
        network.body.addWidget(self.proxy_selector)
        column.addWidget(network)
        column.addStretch(1)
        return self._scroll(page)

    def _build_login(self) -> QWidget:
        page, column = self._page()
        login = SectionCard("登录方式", "留空即可自动选择。切换方式不会清空已保存的凭据。")
        form = self._form()
        self.login_fields: dict[str, OpenCombo] = {}
        for key, title in (("method", "主登录方式"), ("provider", "OAuth 提供商"), ("account", "共享 OAuth 账号")):
            field = OpenCombo()
            field.setObjectName("login_" + key)
            field.setAccessibleName(title)
            if key == "provider":
                field.choices(["linuxdo", "github"])
            field.lineEdit().setPlaceholderText("使用默认值，或自行输入")
            field.currentTextChanged.connect(lambda text, name=key: self._set_login(name, text))
            self.login_fields[key] = field
            form.addRow(title, field)
        login.body.addLayout(form)
        self.login_args = ArgsEditor()
        self.login_args.changed.connect(self._changed)
        login.body.addWidget(self.login_args)
        row = FlowLayout()
        row.addWidget(button("捕获登录态", lambda: self.capture_requested.emit(), "primary"))
        row.addWidget(button("编辑备选登录链 JSON", self._edit_fallback, "quiet"))
        login.body.addLayout(row)
        column.addWidget(login)
        credentials_card = SectionCard("账号凭据", "默认隐藏敏感内容，点击“显示”才会展示明文。更改仅在保存后写入配置。")
        credentials = self._form()
        self.credential_fields: dict[str, SecretEdit] = {}
        titles = {"access_token": "访问令牌", "refresh_token": "刷新令牌", "cookie": "Cookie",
                  "browser_state": "浏览器登录态", "user_id": "用户 ID", "cookie_file": "Cookie 文件"}
        for key in (*CREDENTIAL_FIELDS, "user_id", "cookie_file"):
            field = SecretEdit()
            field.setObjectName("credential_" + key)
            field.setAccessibleName(titles.get(key, key))
            field.setPlaceholderText("未设置")
            field.textChanged.connect(lambda text, name=key: self._set_credential(name, text))
            self.credential_fields[key] = field
            credentials.addRow(titles.get(key, key), field)
        credentials_card.body.addLayout(credentials)
        column.addWidget(credentials_card)
        column.addStretch(1)
        return self._scroll(page)

    def _build_tasks(self) -> QWidget:
        page, column = self._page()
        heading = QHBoxLayout()
        heading.addWidget(label("任务配置", "sectionTitle"), 1)
        self.dependencies_button = button("任务依赖图", self.edit_dependencies)
        heading.addWidget(self.dependencies_button)
        self.add_task_button = button("新增任务", self.add_task, "primary")
        heading.addWidget(self.add_task_button)
        column.addLayout(heading)
        column.addWidget(label("任务依赖图决定成功后的执行顺序；访问链决定失败后的回退路径。双击任务可编辑属性。"))
        self.task_list = QListWidget()
        self.task_list.setObjectName("taskList")
        self.task_list.setMinimumHeight(120)
        self.task_list.currentRowChanged.connect(lambda _index: self._task_actions())
        self.task_list.itemDoubleClicked.connect(lambda _item: self.edit_task())
        column.addWidget(self.task_list, 1)
        actions = FlowLayout()
        self.edit_task_button = button("任务属性", self.edit_task)
        self.chain_button = button("编辑访问链", self.edit_chain)
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
        self.task_run_button = button("运行所选任务", self._run_selected, "primary")
        for control in (self.task_run_button, self.edit_task_button, self.chain_button, self.copy_task_button, self.more_tasks_button):
            actions.addWidget(control)
        column.addLayout(actions)
        self.task_hint = label("运行时会自动包含所选任务的前置依赖。")
        column.addWidget(self.task_hint)
        return page

    def _build_advanced(self) -> QWidget:
        page, column = self._page()
        column.addWidget(label("按需调整高级选项。仅修改对应分区，未识别的扩展字段会原样保留。"))
        for title, key, hint in (
            ("执行流程", "flow", "控制登录、准备、探测、执行、验证、确认和渲染阶段。任务 flow 按键覆盖账号设置。"),
            ("网络设置", "network", "配置代理、SSL 校验、来源页面及扩展字段。常用代理选项也可在基本信息中设置。"),
            ("账号策略", "policy", "配置重试、浏览器、无头模式和失败容忍。任务 policy 整体替代账号策略。"),
            ("展示设置", "display", "自定义结果列名称及展示扩展。"),
        ):
            card = SectionCard()
            heading = QHBoxLayout()
            heading.addWidget(label(title, "sectionTitle"), 1)
            heading.addWidget(button("编辑 JSON", lambda section=key: self._edit_section(section), "quiet"))
            card.body.addLayout(heading)
            card.body.addWidget(label(hint))
            column.addWidget(card)
        complete = SectionCard("完整账号 JSON", "包含敏感凭据。确认后替换当前草稿，稳定账号 ID 不可改变。")
        control = button("编辑完整 JSON", self._edit_account_json)
        complete.body.addWidget(control, 0, Qt.AlignmentFlag.AlignLeft)
        column.addWidget(complete)
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
        # 任务列表里「模板默认访问链」的步骤名来自模板目录，目录到达后重绘一次。
        self._refresh_tasks()


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
            reference = task.get("template") or (self._account or {}).get("template") or "auto"
            has_chain = task.get("chain") is not None
            method = "访问链" if has_chain else str(task.get("method") or "auto")
            source = "任务覆盖" if task.get("template") else "继承账号"
            dependencies = task.get("depends_on") or []
            deps = "、".join(str(dep) for dep in dependencies) if isinstance(dependencies, list) else "配置类型待修复"
            detail = f"模板：{reference}（{source}）  |  前置：{deps or '无'}"
            if has_chain:
                template_chain = catalog_entry(self._catalog, str(reference)).get("chain") or []
                detail += f"  |  访问链：{core.chain_summary(task.get('chain'), template_chain)}"
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
        for control in (self.chain_button, self.edit_task_button, self.copy_task_button, self.task_toggle_button, self.task_run_button):
            control.setEnabled(valid)
        self.dependencies_button.setEnabled(bool(tasks))
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

    def edit_chain(self) -> bool:
        from .chain_editor import ChainEditorDialog

        tasks = self._tasks()
        index = self.task_list.currentRow()
        if not 0 <= index < len(tasks):
            return False
        try:
            account = self.value()
        except ConfigError:
            self._error("请先修复账号参数中的错误")
            return False
        task = tasks[index]
        reference = task.get("template") or account.get("template") or "auto"
        template_steps = catalog_entry(self._catalog, str(reference)).get("chain") or []
        dialog = ChainEditorDialog(task.get("chain"), template_steps, self, account=account, task=task)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return False
        if dialog.has_changes():
            value = dialog.value()
            if value is None:
                task.pop("chain", None)
            else:
                task["chain"] = value
            self._replace_tasks(tasks, str(task.get("id") or ""))
        return True

    def edit_dependencies(self) -> bool:
        from .task_graph import TaskDependencyDialog

        try:
            account = self.value()
        except ConfigError:
            self._error("请先修复账号参数中的错误")
            return False
        dialog = TaskDependencyDialog(account, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return False
        if dialog.has_changes():
            layout = dialog.layout_value()
            # 坐标存顶层 task_layout：display 的值在 schema 里被强制转成字符串
            # （只用于 text_label 这类标签），嵌套字典放进去会变成 "{'daily': [10, 20]}"。
            # 顶层未知键由 AccountSpec.extras 原样往返，嵌套结构不受损。
            if layout != (account.get("task_layout") or {}):
                if layout:
                    self._account["task_layout"] = layout
                else:
                    self._account.pop("task_layout", None)
            self._replace_tasks(dialog.value(), self.selected_task_id())
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
