"""代理选择与组管理。所有编辑先进入草稿；界面状态不冒充连通性检测。"""

from __future__ import annotations

from copy import deepcopy
from urllib.parse import quote
from uuid import uuid4

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
    QHBoxLayout, QHeaderView, QLineEdit, QMessageBox, QSpinBox, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from config.proxies import MODES, network_from_payload, network_mode, parse_groups, parse_proxy_url
from core.errors import ConfigError
from gui import core
from gui.dialogs import SecretEdit, button, label
from gui.worker import Redactor


def _table(headers):
    result = QTableWidget(0, len(headers))
    result.setHorizontalHeaderLabels(headers)
    result.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    result.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    result.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    result.verticalHeader().hide()
    result.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    result.horizontalHeader().setStretchLastSection(True)
    return result


def _row(table, values):
    row = table.rowCount()
    table.insertRow(row)
    for column, value in enumerate(values):
        item = QTableWidgetItem(str(value))
        table.setItem(row, column, item)


def _confirm(parent, title, text):
    dialog = QMessageBox(parent)
    dialog.setWindowTitle(title)
    dialog.setTextFormat(Qt.TextFormat.PlainText)
    dialog.setText(text)
    dialog.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    dialog.setDefaultButton(QMessageBox.StandardButton.No)
    return dialog.exec() == QMessageBox.StandardButton.Yes


def _finish_dialog(dialog, layout):
    dialog.error_label = label("", "error")
    dialog.error_label.hide()
    layout.addWidget(dialog.error_label)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    buttons.button(QDialogButtonBox.StandardButton.Ok).setText("确认")
    buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)


class ProxySelector(QWidget):
    changed = Signal()
    manage_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._network = {}
        self._context = {}
        self._loading = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        row.addWidget(label("代理方式"))
        self.mode = QComboBox()
        for title, mode in (("继承全局", "inherit"), ("直连", "direct"), ("自定义代理", "custom"), ("代理组", "group")):
            self.mode.addItem(title, mode)
        row.addWidget(self.mode, 1)
        row.addWidget(button("管理代理组", self.manage_requested.emit, "link"))
        layout.addLayout(row)
        self.custom_box = QWidget()
        custom = QVBoxLayout(self.custom_box)
        custom.setContentsMargins(0, 0, 0, 0)
        custom.addWidget(label("代理 URL（可含认证；默认隐藏）"))
        self.proxy = SecretEdit()
        self.proxy.setPlaceholderText("http://127.0.0.1:7897")
        custom.addWidget(self.proxy)
        layout.addWidget(self.custom_box)
        self.group_box = QWidget()
        groups = QHBoxLayout(self.group_box)
        groups.setContentsMargins(0, 0, 0, 0)
        groups.addWidget(label("使用代理组"))
        self.group = QComboBox()
        self.group.setMinimumContentsLength(18)
        self.group.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        groups.addWidget(self.group, 1)
        layout.addWidget(self.group_box)
        self.status = label("")
        layout.addWidget(self.status)
        self.mode.currentIndexChanged.connect(self._mode_changed)
        self.proxy.textChanged.connect(self._proxy_changed)
        self.group.currentIndexChanged.connect(self._group_changed)
        self.set_network({})

    def value(self):
        return deepcopy(self._network)

    def set_context(self, payload):
        self._context = core.proxy_context(payload)
        self._refresh_groups()
        self._refresh_status()

    def _refresh_groups(self):
        selected = self._network.get("proxy_group", "")
        blocked = self.group.blockSignals(True)
        self.group.clear()
        self.group.addItem("请选择代理组", "")
        redactor = Redactor(self._context)
        for group in self._context.get("proxy_groups", []):
            suffix = "（已停用）" if not group.get("enabled", True) else "（空组）" if not group.get("proxies") else "（未选节点）" if not group.get("selected") else ""
            self.group.addItem(redactor.text(f"{group.get('name') or group.get('id')} {suffix}"), group.get("id"))
        index = self.group.findData(selected)
        if index < 0 and selected:
            self.group.addItem("引用的代理组不存在（请重新选择）", selected)
            index = self.group.count() - 1
        self.group.setCurrentIndex(max(0, index))
        self.group.blockSignals(blocked)

    def set_network(self, network):
        self._loading = True
        try:
            self._network = deepcopy(network) if isinstance(network, dict) else {}
            mode = self._network.get("proxy_mode")
            if mode not in MODES:
                mode = "custom" if self._network.get("proxy") else "group" if self._network.get("proxy_group") else "inherit"
            self.mode.setCurrentIndex(self.mode.findData(mode))
            self.proxy.conceal()
            self.proxy.setText(str(self._network.get("proxy") or ""))
            self._refresh_groups()
            self._refresh_status()
        finally:
            self._loading = False

    def _refresh_status(self):
        mode = self.mode.currentData()
        self.custom_box.setVisible(mode == "custom")
        self.group_box.setVisible(mode == "group")
        status = core.proxy_status(self._network, self._context)
        text = status["description"]
        if status.get("valid"):
            if mode == "inherit" and status.get("source") == "direct":
                text = "继承全局 → 直连（未配置默认组或 CHECKIN_PROXY）"
            text += " · 配置状态，未检测连通性"
        self.status.setText(text)
        self.status.setObjectName("hint" if status.get("valid") else "error")
        self.status.style().unpolish(self.status)
        self.status.style().polish(self.status)

    def _mode_changed(self):
        if self._loading:
            return
        mode = self.mode.currentData()
        self._network.pop("proxy", None)
        self._network.pop("proxy_group", None)
        self._network["proxy_mode"] = mode
        if mode == "custom":
            self._network["proxy"] = self.proxy.text().strip()
        elif mode == "group":
            self._network["proxy_group"] = self.group.currentData() or ""
        self._edited()

    def _proxy_changed(self, text):
        if not self._loading and self.mode.currentData() == "custom":
            self._network["proxy"] = text.strip()
            self._edited()

    def _group_changed(self):
        if not self._loading and self.mode.currentData() == "group":
            self._network["proxy_group"] = self.group.currentData() or ""
            self._edited()

    def _edited(self):
        self._refresh_status()
        self.changed.emit()


class ProxyNodeDialog(QDialog):
    def __init__(self, raw=None, parent=None):
        super().__init__(parent)
        self._raw = deepcopy(raw) if raw is not None else {}
        self._new = raw is None
        self.setWindowTitle("新增代理" if self._new else "编辑代理")
        self.resize(620, 480)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.id_field = QLineEdit(self._raw.get("id", "node-" + uuid4().hex[:12]))
        self.id_field.setReadOnly(True)
        self.name_field = QLineEdit(self._raw.get("name", ""))
        self.scheme = QComboBox()
        for scheme in ("http", "https", "socks5"):
            self.scheme.addItem(scheme.upper(), scheme)
        self.host = QLineEdit()
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(7897)
        self.username = SecretEdit()
        self.password = SecretEdit()
        self.enabled = QCheckBox("启用此代理")
        self.enabled.setChecked(self._raw.get("enabled", True))
        for name, widget in (("稳定 ID", self.id_field), ("名称", self.name_field), ("协议", self.scheme),
                             ("主机 / IPv6", self.host), ("端口", self.port),
                             ("用户名（可选）", self.username), ("密码（可选）", self.password)):
            form.addRow(name, widget)
        form.addRow(self.enabled)
        layout.addLayout(form)
        layout.addWidget(label("HTTP/HTTPS 可用于 HTTP 和浏览器；SOCKS5 仅浏览器，含 HTTP 步骤可能失败。未扩展驱动的 SOCKS 认证能力。"))
        paste = QHBoxLayout()
        self.url_input = SecretEdit()
        self.url_input.setPlaceholderText("粘贴代理 URL 后点击解析")
        paste.addWidget(self.url_input, 1)
        paste.addWidget(button("解析 URL", self.import_url))
        layout.addLayout(paste)
        if self._raw.get("url"):
            self._load_connection(parse_proxy_url(self._raw["url"]))
        self._connection_start = self._connection()
        self._imported = False
        _finish_dialog(self, layout)

    def _connection(self):
        return (self.scheme.currentData(), self.host.text().strip(), self.port.value(), self.username.text(), self.password.text())

    def _load_connection(self, parsed):
        self.scheme.setCurrentIndex(self.scheme.findData(parsed.scheme))
        self.host.setText(parsed.host)
        self.port.setValue(parsed.port or {"http": 80, "https": 443, "socks5": 1080}[parsed.scheme])
        self.username.setText(parsed.username)
        self.password.setText(parsed.password)

    def import_url(self):
        try:
            self._load_connection(parse_proxy_url(self.url_input.text(), allow_bare=True))
            self._imported = True
            self.url_input.setText("")
            self.error_label.hide()
        except ConfigError as exc:
            self.error_label.setText(exc.message)
            self.error_label.show()

    def value(self):
        result = deepcopy(self._raw)
        result.update(id=self._raw.get("id", self.id_field.text()), name=self.name_field.text().strip())
        if not result["name"]:
            raise ConfigError("请填写代理名称")
        if self._new or self._imported or self._connection() != self._connection_start:
            scheme, host, port, username, password = self._connection()
            host = host.strip("[]")
            if ":" in host:
                host = "[" + host + "]"
            if password and not username:
                raise ConfigError("填写密码时请同时填写用户名")
            auth = (quote(username, safe="") + ":" + quote(password, safe="") + "@") if username else ""
            result["url"] = parse_proxy_url(f"{scheme}://{auth}{host}:{port}").url
        if self._new or "enabled" in result or not self.enabled.isChecked():
            result["enabled"] = self.enabled.isChecked()
        parse_groups([{"id": "validation", "name": "校验", "proxies": [result]}])
        return result

    def accept(self):
        try:
            self.value()
        except ConfigError as exc:
            self.error_label.setText(exc.message)
            self.error_label.show()
            return
        super().accept()


class ProxyGroupDialog(QDialog):
    def __init__(self, raw=None, parent=None):
        super().__init__(parent)
        self._raw = deepcopy(raw) if raw is not None else {}
        self._new = raw is None
        self._nodes = deepcopy(self._raw.get("proxies", []))
        self._selected = self._raw.get("selected", "")
        self.setWindowTitle("新建代理组" if self._new else "编辑代理组")
        self.resize(900, 580)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.id_field = QLineEdit(self._raw.get("id", "group-" + uuid4().hex[:12]))
        self.id_field.setReadOnly(True)
        self.name_field = QLineEdit(self._raw.get("name", ""))
        self.enabled = QCheckBox("启用此组")
        self.enabled.setChecked(self._raw.get("enabled", True))
        form.addRow("稳定 ID", self.id_field)
        form.addRow("组名", self.name_field)
        form.addRow(self.enabled)
        layout.addLayout(form)
        layout.addWidget(label("手动选择当前节点；同次账号运行不切换出口。空组、停用或未选节点时，引用账号将报告配置错误，不会直连。"))
        self.members = _table(["名称", "协议", "服务器", "认证", "启用", "当前"])
        self.members.cellDoubleClicked.connect(lambda *_: self.edit_node())
        layout.addWidget(self.members, 1)
        actions = QHBoxLayout()
        for title, callback in (("新增代理", self.add_node), ("编辑", self.edit_node), ("删除", self.delete_node),
                                ("启用 / 停用", self.toggle_node), ("设为当前", self.select_node),
                                ("上移", lambda: self.move_node(-1)), ("下移", lambda: self.move_node(1))):
            actions.addWidget(button(title, callback))
        layout.addLayout(actions)
        self.status = label("")
        layout.addWidget(self.status)
        _finish_dialog(self, layout)
        self._refresh()
        self.enabled.toggled.connect(self._refresh_status)

    def value(self):
        result = deepcopy(self._raw)
        result.update(id=self._raw.get("id", self.id_field.text()), name=self.name_field.text().strip())
        if self._new or "enabled" in result or not self.enabled.isChecked():
            result["enabled"] = self.enabled.isChecked()
        if self._new or "proxies" in result or self._nodes:
            result["proxies"] = deepcopy(self._nodes)
        if self._new or "selected" in result or self._selected:
            result["selected"] = self._selected
        parse_groups([result])
        return result

    def _refresh_status(self):
        if not self.enabled.isChecked():
            text = "此组已停用，引用账号无法执行。"
        elif not self._nodes:
            text = "空组：请新增代理，并明确设为当前节点。"
        elif not self._selected:
            text = "未选择当前节点；不会自动使用第一项。"
        else:
            node = next((item for item in self._nodes if item["id"] == self._selected), None)
            text = "配置有效（未检测连通性）" if node and node.get("enabled", True) else "当前节点停用或不存在，请重新选择。"
        self.status.setText(text)

    def _refresh(self, selected=None):
        row = self.members.currentRow() if selected is None else selected
        self.members.setRowCount(0)
        redactor = Redactor(self._nodes)
        for node in self._nodes:
            parsed = parse_proxy_url(node["url"])
            _row(self.members, [redactor.text(node["name"]), parsed.scheme.upper(), parsed.display,
                                "已配置" if parsed.username or parsed.password else "无",
                                "启用" if node.get("enabled", True) else "停用",
                                "当前" if node["id"] == self._selected else ""])
        if self._nodes:
            self.members.selectRow(max(0, min(row, len(self._nodes) - 1)))
        self._refresh_status()

    def add_node(self):
        dialog = ProxyNodeDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._nodes.append(dialog.value())
            self._refresh(len(self._nodes) - 1)

    def edit_node(self):
        index = self.members.currentRow()
        if index < 0:
            return
        dialog = ProxyNodeDialog(self._nodes[index], self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._nodes[index] = dialog.value()
            self._refresh(index)

    def delete_node(self):
        index = self.members.currentRow()
        if index < 0:
            return
        current = self._nodes[index]["id"] == self._selected
        message = "删除当前节点后，本组将变成未选择状态，引用账号无法执行。不会自动切换。" if current else "删除此代理？此操作仅修改草稿。"
        if not _confirm(self, "删除代理", message):
            return
        if current:
            self._selected = ""
        self._nodes.pop(index)
        self._refresh(index)

    def toggle_node(self):
        index = self.members.currentRow()
        if index < 0:
            return
        node = self._nodes[index]
        if node.get("enabled", True) and node["id"] == self._selected:
            if not _confirm(self, "停用当前节点", "引用本组的账号将无法执行，直到重新启用或明确选择其他节点。"):
                return
        node["enabled"] = not node.get("enabled", True)
        self._refresh(index)

    def select_node(self):
        index = self.members.currentRow()
        if index < 0:
            return
        if not self._nodes[index].get("enabled", True):
            self.error_label.setText("请先启用节点，再设为当前。")
            self.error_label.show()
            return
        self._selected = self._nodes[index]["id"]
        self.error_label.hide()
        self._refresh(index)

    def move_node(self, direction):
        index = self.members.currentRow()
        target = index + direction
        if index < 0 or not 0 <= target < len(self._nodes):
            return
        self._nodes[index], self._nodes[target] = self._nodes[target], self._nodes[index]
        self._refresh(target)

    def accept(self):
        try:
            self.value()
        except ConfigError as exc:
            self.error_label.setText(exc.message)
            self.error_label.show()
            return
        if self._raw.get("enabled", True) and not self.enabled.isChecked():
            if not _confirm(self, "停用代理组", "引用本组的账号将无法执行，直到重新启用或改绑。"):
                return
        super().accept()


class ProxyGroupsPage(QWidget):
    changed = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._payload = {"accounts": []}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.addWidget(label("代理组", "pageTitle"))
        layout.addWidget(label("共享节点，按组手动选择出口。所有改动先进入草稿，点击工作台保存后落盘；不会自动测速或故障切换。"))
        row = QHBoxLayout()
        row.addWidget(label("全局默认"))
        self.default_group = QComboBox()
        self.default_group.setMinimumContentsLength(22)
        row.addWidget(self.default_group, 1)
        layout.addLayout(row)
        self.default_status = label("")
        layout.addWidget(self.default_status)
        self.table = _table(["代理组", "当前节点", "启用 / 总数", "引用", "配置状态"])
        self.table.cellDoubleClicked.connect(lambda *_: self.edit_group())
        layout.addWidget(self.table, 1)
        actions = QHBoxLayout()
        for title, callback in (("新建代理组", self.add_group), ("编辑组及代理", self.edit_group),
                                ("删除组", self.delete_group), ("启用 / 停用", self.toggle_group)):
            actions.addWidget(button(title, callback))
        actions.addStretch(1)
        layout.addLayout(actions)
        self.message = label("")
        layout.addWidget(self.message)
        self.default_group.currentIndexChanged.connect(self._default_changed)
        self.set_payload(self._payload)

    def value(self):
        return {"proxy_groups": deepcopy(self._payload.get("proxy_groups", [])),
                "default_proxy_group": self._payload.get("default_proxy_group", "")}

    def set_payload(self, payload):
        self._payload = deepcopy(payload)
        previous = self.table.currentRow()
        self.table.setRowCount(0)
        groups = self._payload.get("proxy_groups", [])
        redactor = Redactor(payload)
        blocked = self.default_group.blockSignals(True)
        self.default_group.clear()
        self.default_group.addItem("不设默认组（CHECKIN_PROXY / 直连）", "")
        for group in groups:
            self.default_group.addItem(redactor.text(group.get("name") or group["id"]), group["id"])
            nodes = group.get("proxies", [])
            node = next((item for item in nodes if item["id"] == group.get("selected")), None)
            status = core.proxy_status({"proxy_group": group["id"]}, {"proxy_groups": [group]})
            _row(self.table, [redactor.text(group["name"]), redactor.text(node["name"]) if node else "未选择",
                              f"{sum(item.get('enabled', True) for item in nodes)} / {len(nodes)}",
                              str(len(self.references(group["id"]))),
                              "配置有效（未检测）" if status["valid"] else status["description"]])
        default = self._payload.get("default_proxy_group", "")
        index = self.default_group.findData(default)
        if index < 0:
            self.default_group.addItem("默认组不存在（请重新选择）", default)
            index = self.default_group.count() - 1
        self.default_group.setCurrentIndex(index)
        self.default_group.blockSignals(blocked)
        if groups:
            self.table.selectRow(max(0, min(previous, len(groups) - 1)))
        self.default_status.setText(core.proxy_status({}, self._payload)["description"])

    def references(self, group_id):
        refs = []
        default = self._payload.get("default_proxy_group", "")
        if default == group_id:
            refs.append("全局默认")
        redactor = Redactor(self._payload)
        for account in self._payload.get("accounts", []):
            network = account.get("network") or {}
            try:
                mode = network_mode(network_from_payload(network))
            except ConfigError:
                mode = "group" if network.get("proxy_group") else "inherit"
            if network.get("proxy_group") == group_id or mode == "inherit" and default == group_id:
                refs.append(redactor.text(account.get("name") or account.get("id") or "未命名账号"))
        return refs

    def _commit(self, groups, default):
        self.message.clear()
        self.set_payload({**self._payload, "proxy_groups": deepcopy(groups), "default_proxy_group": default})
        self.changed.emit(self.value())

    def _default_changed(self):
        self._commit(self._payload.get("proxy_groups", []), self.default_group.currentData() or "")

    def add_group(self):
        dialog = ProxyGroupDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            groups = deepcopy(self._payload.get("proxy_groups", []))
            groups.append(dialog.value())
            self._commit(groups, self._payload.get("default_proxy_group", ""))

    def edit_group(self):
        index = self.table.currentRow()
        if index < 0:
            return
        groups = deepcopy(self._payload.get("proxy_groups", []))
        dialog = ProxyGroupDialog(groups[index], self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            groups[index] = dialog.value()
            self._commit(groups, self._payload.get("default_proxy_group", ""))

    def delete_group(self):
        index = self.table.currentRow()
        if index < 0:
            return
        groups = deepcopy(self._payload.get("proxy_groups", []))
        refs = self.references(groups[index]["id"])
        if refs:
            self.message.setText("无法删除：仍被 " + "、".join(refs) + " 引用。请先改绑账号或清除全局默认组。")
            return
        if not _confirm(self, "删除代理组", "确认从草稿删除该组及所有组内代理？"):
            return
        groups.pop(index)
        self._commit(groups, self._payload.get("default_proxy_group", ""))

    def toggle_group(self):
        index = self.table.currentRow()
        if index < 0:
            return
        groups = deepcopy(self._payload.get("proxy_groups", []))
        group = groups[index]
        if group.get("enabled", True) and self.references(group["id"]):
            if not _confirm(self, "停用代理组", "引用本组的账号将无法执行；不会自动回退到环境代理或直连。"):
                return
        group["enabled"] = not group.get("enabled", True)
        self._commit(groups, self._payload.get("default_proxy_group", ""))
