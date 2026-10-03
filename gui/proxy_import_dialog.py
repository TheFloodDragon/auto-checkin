"""代理订阅来源选择与安全预览对话框。"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any, Mapping
from urllib.parse import parse_qsl, unquote, urlsplit

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QPlainTextEdit, QScrollArea, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget, QGroupBox,
)

from config.subscriptions import (
    SubscriptionImport, parse_node_link, parse_subscription_text, select_policy_nodes,
    subscription_update_summary,
)
from net.subscriptions import read_source, write_text_file
from core.errors import ConfigError
from gui.dialogs import button, label
from gui.ui import configure_form, fit_dialog, table_placeholder
from gui.worker import Redactor


def _import_redactor(result: SubscriptionImport, existing_group: Mapping[str, Any] | None = None) -> Redactor:
    """所有展示字段共享凭据集合，避免凭据混入名称、说明或策略组标题。"""
    redactor = Redactor(dict(existing_group or {}))
    urls = [result.source_label]
    for candidate in result.candidates:
        redactor.secrets.update(candidate.secrets)
        if candidate.url:
            urls.append(candidate.url)
    subscription = (existing_group or {}).get("subscription")
    if isinstance(subscription, Mapping):
        urls.append(str(subscription.get("url") or ""))
    for value in urls:
        try:
            parts = urlsplit(value)
            redactor.secrets.update(unquote(item) for item in (parts.username, parts.password) if item)
            redactor.secrets.update(item for _, item in parse_qsl(parts.query) if item)
        except ValueError:
            pass
    return redactor


class ProxySourceInput(QWidget):
    """可嵌入的来源输入；value 只验证输入，不访问网络或读取文件。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        source_group = QGroupBox("代理来源")
        form = configure_form(QFormLayout(source_group))
        self.kind = QComboBox()
        self.kind.setAccessibleName("代理来源类型")
        for title, value in (
            ("Clash / 订阅链接", "subscription_url"),
            ("单个节点链接", "node_url"),
            ("Clash / 节点文件", "file"),
            ("粘贴 Clash YAML / 节点正文", "text"),
        ):
            self.kind.addItem(title, value)
        form.addRow("来源类型", self.kind)
        self.source = QLineEdit()
        self.source.setAccessibleName("订阅或节点来源")
        self.browse_button = button("选择文件", self._browse, "quiet")
        self.edit_button = button("编辑文件", self._edit_file, "quiet")
        self.source_box = QWidget()
        source_row = QHBoxLayout(self.source_box)
        source_row.setContentsMargins(0, 0, 0, 0)
        source_row.addWidget(self.source, 1)
        source_row.addWidget(self.browse_button)
        source_row.addWidget(self.edit_button)
        self.source_label = label("链接 / 路径")
        form.addRow(self.source_label, self.source_box)
        self.format = QComboBox()
        self.format.setAccessibleName("订阅格式")
        for title, value in (("自动识别", "auto"), ("Clash YAML", "clash_yaml"), ("Base64 节点列表", "base64"), ("节点链接列表", "uri")):
            self.format.addItem(title, value)
        form.addRow("格式", self.format)
        self.bind_subscription = QCheckBox("保存订阅链接，后续可一键更新")
        self.bind_subscription.setChecked(True)
        form.addRow(self.bind_subscription)
        layout.addWidget(source_group)
        self.content_hint = label("可直接复制完整 Clash YAML 文件，或粘贴多行节点链接 / Base64 正文；无需只截取 proxies 部分，支持自动识别。")
        layout.addWidget(self.content_hint)
        self.content = QPlainTextEdit()
        self.content.setAccessibleName("粘贴订阅或节点正文")
        self.content.setPlaceholderText("在此粘贴完整 Clash YAML 文件或节点正文")
        self.content.setMinimumHeight(240)
        self.content.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.content.setMaximumBlockCount(0)
        layout.addWidget(self.content, 1)
        layout.addWidget(label("支持 HTTP、HTTPS、SOCKS5，以及通过本地 mihomo 桥接的 VLESS、AnyTLS、VMess、Trojan、SS、Hysteria2、TUIC。"))
        self.error_label = label("", "error")
        self.error_label.hide()
        layout.addWidget(self.error_label)
        self.kind.currentIndexChanged.connect(self._kind_changed)
        self.source.textChanged.connect(self._source_changed)
        self._kind_changed()

    def _source_changed(self) -> None:
        self.edit_button.setVisible(self.kind.currentData() == "file" and bool(self.source.text().strip()))
        self.error_label.hide()

    def _kind_changed(self) -> None:
        kind = self.kind.currentData()
        is_file, is_text = kind == "file", kind == "text"
        self.source_box.setVisible(not is_text)
        self.source.setVisible(not is_text)
        self.source_label.setVisible(not is_text)
        self.content.setVisible(is_text)
        self.content_hint.setVisible(is_text)
        self.browse_button.setVisible(is_file)
        self.edit_button.setVisible(is_file and bool(self.source.text().strip()))
        self.bind_subscription.setVisible(kind == "subscription_url")
        self.bind_subscription.setEnabled(kind == "subscription_url")
        self.source.setPlaceholderText(
            "选择 Clash YAML / Base64 / 节点文件" if is_file
            else "粘贴 http(s)、socks5、vless、vmess、trojan 等单个节点链接" if kind == "node_url"
            else "粘贴 HTTPS 订阅链接"
        )
        self.format.setCurrentIndex(self.format.findData("uri" if kind == "node_url" else "auto"))
        self.format.setEnabled(kind != "node_url")
        self.error_label.hide()

    def _edit_file(self) -> None:
        source = self.source.text().strip()
        try:
            fetched = read_source(source, kind="file")
            dialog = SubscriptionContentDialog(
                fetched.text, source_label=fetched.label, source_path=source,
                format=str(self.format.currentData() or "auto"), parent=self,
            )
            if dialog.exec() == QDialog.DialogCode.Accepted and dialog.result is not None:
                # “使用解析结果”应使用编辑后的正文，即使用户未选择覆盖原文件。
                self.content.setPlainText(dialog.editor.toPlainText())
                self.kind.setCurrentIndex(self.kind.findData("text"))
                self.format.setCurrentIndex(self.format.findData(dialog.format.currentData()))
        except ConfigError:
            self.error_label.setText("无法读取或编辑本地文件，请检查路径、权限和文件内容。")
            self.error_label.show()

    def _browse(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self, "选择 Clash / 节点文件", "", "订阅与节点文件 (*.yaml *.yml *.txt *.conf);;所有文件 (*)",
        )
        if filename:
            self.source.setText(filename)

    def value(self) -> dict[str, Any]:
        kind = self.kind.currentData()
        source_kind = {"subscription_url": "url", "node_url": "node", "file": "file", "text": "text"}.get(kind)
        if source_kind is None:
            raise ConfigError("请选择有效的代理来源类型")
        source = self.content.toPlainText() if kind == "text" else self.source.text().strip()
        if not source.strip():
            raise ConfigError("请粘贴订阅正文" if kind == "text" else "请填写订阅链接、节点链接或选择文件")
        if kind == "text":
            try:
                size = len(source.encode("utf-8"))
            except UnicodeError:
                raise ConfigError("订阅正文必须是有效的 UTF-8 文本") from None
            if size > 8 * 1024 * 1024:
                raise ConfigError("订阅正文过大，不能超过 8 MiB；输入内容未被截断")
        elif kind == "node_url":
            try:
                valid = parse_node_link(source).importable
            except (ConfigError, ValueError, UnicodeError):
                valid = False
            if not valid:
                raise ConfigError("节点链接格式无效或协议不受支持，请检查协议、主机和认证信息")
        elif kind == "subscription_url":
            try:
                parts = urlsplit(source)
                if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                    raise ValueError
                if parts.username or parts.password or parts.fragment:
                    raise ValueError
                if parts.port is not None and not 1 <= parts.port <= 65535:
                    raise ValueError
                if any(char.isspace() or ord(char) < 32 for char in source):
                    raise ValueError
            except ValueError:
                raise ConfigError("订阅链接格式无效，请检查协议、主机和认证信息") from None
        elif any(ord(char) < 32 for char in source):
            raise ConfigError("文件路径格式无效，请重新选择本地文件")
        return {
            "kind": source_kind,
            "source": source,
            "format": str(self.format.currentData() or "auto"),
            "bind_subscription": bool(source_kind == "url" and self.bind_subscription.isChecked()),
        }


class ProxySourceDialog(QDialog):
    """兼容独立导入流程；来源输入也可直接嵌入新建代理组。"""

    def __init__(self, groups: list[dict[str, Any]] | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("导入 Clash 订阅 / 节点")
        self.setModal(True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)
        layout.addWidget(label("导入 Clash 订阅 / 节点", "pageTitle"))
        self.input = ProxySourceInput(self)
        for name in ("kind", "source", "content", "format", "bind_subscription", "browse_button", "edit_button"):
            setattr(self, name, getattr(self.input, name))
        self.source_scroll = QScrollArea()
        self.source_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.source_scroll.setWidgetResizable(True)
        self.source_scroll.setWidget(self.input)
        layout.addWidget(self.source_scroll, 1)
        form = configure_form(QFormLayout())
        self.target = QComboBox()
        self.target.setAccessibleName("导入目标代理组")
        self.target.addItem("新建代理组", "")
        for group in groups or []:
            if isinstance(group, dict) and group.get("id"):
                self.target.addItem(str(group.get("name") or group["id"]), str(group["id"]))
        form.addRow("目标组", self.target)
        self.group_name = QLineEdit()
        self.group_name.setAccessibleName("新代理组名称")
        self.group_name.setPlaceholderText("留空则使用订阅标题或来源主机名")
        form.addRow("新组名称", self.group_name)
        layout.addLayout(form)
        layout.addWidget(label("确认预览后才写入草稿；同一来源更新只替换该来源生成的节点，保留手工节点及其它来源节点。"))
        self.error_label = label("", "error")
        self.error_label.hide()
        layout.addWidget(self.error_label)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("读取并预览")
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("kind", "primary")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.target.currentIndexChanged.connect(self._target_changed)
        self.kind.currentIndexChanged.connect(self.error_label.hide)
        self._target_changed()
        fit_dialog(self, 800, 680, (560, 460))

    def _target_changed(self) -> None:
        existing = bool(self.target.currentData())
        self.group_name.setEnabled(not existing)
        if existing:
            self.group_name.clear()
        self.bind_subscription.setText("更新此组的订阅绑定" if existing else "保存订阅链接，后续可一键更新")

    def value(self) -> dict[str, Any]:
        values = self.input.value()
        target_group = str(self.target.currentData() or "")
        values.update(target_group=target_group, group_name=self.group_name.text().strip() if not target_group else "")
        return values

    def accept(self) -> None:
        try:
            self.value()
        except ConfigError as exc:
            self.error_label.setText(exc.message)
            self.error_label.show()
            return
        self.error_label.hide()
        super().accept()


class SubscriptionContentDialog(QDialog):
    """编辑一次抓取的正文；解析与保存都不会回写远程 URL。"""

    def __init__(
        self,
        text: str,
        *,
        source_id: str = "",
        source_label: str = "订阅正文",
        source_path: str = "",
        format: str = "auto",
        parent=None,
        existing_group: Mapping[str, Any] | None = None,
        base_result: SubscriptionImport | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("编辑订阅正文")
        self.setModal(True)
        self._base_result = base_result
        self._existing_group = deepcopy(dict(existing_group)) if existing_group is not None else None
        self._original_text = str(text or "")
        self._source_id = base_result.source_id if base_result is not None else str(source_id or "")
        self._source_label = base_result.source_label if base_result is not None else str(source_label or "订阅正文")
        self._source_path = str(source_path or "")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)
        layout.addWidget(label("编辑订阅正文", "pageTitle"))
        layout.addWidget(label("正文只用于本次解析；远程订阅不会被写回。保存本地文件时使用 UTF-8 和同目录原子替换。"))
        form = configure_form(QFormLayout())
        self.format = QComboBox()
        for title, value in (("自动识别", "auto"), ("Clash YAML", "clash_yaml"), ("Base64 节点列表", "base64"), ("节点链接列表", "uri")):
            self.format.addItem(title, value)
        index = self.format.findData(format)
        self.format.setCurrentIndex(index if index >= 0 else 0)
        form.addRow("格式", self.format)
        layout.addLayout(form)
        self.editor = QPlainTextEdit()
        self.editor.setAccessibleName("订阅正文编辑器")
        self.editor.setMinimumHeight(260)
        self.editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.editor.setMaximumBlockCount(0)
        self.editor.setPlainText(str(text or ""))
        self.editor.textChanged.connect(self._update_stats)
        layout.addWidget(self.editor, 1)
        self.stats = label("")
        layout.addWidget(self.stats)
        actions = QHBoxLayout()
        actions.addWidget(button("重新解析", self.parse, "primary"))
        actions.addWidget(button("另存为", self.save_as, "quiet"))
        if self._source_path:
            actions.addWidget(button("保存原文件", self.save, "quiet"))
        layout.addLayout(actions)
        self.error_label = label("", "error")
        self.error_label.hide()
        layout.addWidget(self.error_label)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("使用解析结果")
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("kind", "primary")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        self.buttons.accepted.connect(self._accept_parsed)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.result: SubscriptionImport | None = None
        self._update_stats()
        fit_dialog(self, 1000, 720, (620, 460))

    def _update_stats(self) -> None:
        text = self.editor.toPlainText()
        self.stats.setText(f"{len(text.encode('utf-8', errors='replace')):,} 字节 · {len(text.splitlines())} 行")
        self.result = None
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
        self.error_label.hide()

    def _show_error(self, message: str) -> None:
        self.error_label.setText(message)
        self.error_label.show()

    def parse(self) -> SubscriptionImport | None:
        text = self.editor.toPlainText()
        format = str(self.format.currentData() or "auto")
        base = self._base_result
        self.result = None
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        # 外部 provider 正文不在编辑器内，离线重解析不能安全覆盖已展开的节点。
        external = base is not None and any(
            str(item.get("type") or "").lower() in {"http", "file"}
            and bool(item.get("resolved")) for item in base.providers
        )
        if external:
            if text == self._original_text and format in {"auto", base.format}:
                self.result = base
            else:
                self._show_error("原来源包含已读取的外部 provider 节点。离线编辑不能重新展开或安全删除它们；请取消编辑，修改后重新导入来源以再次读取 provider。")
                return None
        try:
            if self.result is None:
                self.result = parse_subscription_text(
                    text, source_id=self._source_id, source_label=self._source_label,
                    group_id=base.group_id if base is not None else "",
                    group_name=base.group_name if base is not None else "",
                    title=base.title if base is not None else "",
                    userinfo=base.userinfo if base is not None else None,
                    existing_group=self._existing_group, format=format,
                )
                if base is not None and hasattr(base, "source_kind"):
                    self.result = replace(self.result, source_kind=base.source_kind)
        except ConfigError:
            self._show_error("正文解析失败，请检查格式、UTF-8 编码、大小限制及节点配置；错误详情不会回显正文或凭据。")
            return None
        if not getattr(self.result, "providers_complete", True):
            self._show_error("正文包含尚未读取的外部 provider。离线编辑不访问网络，请重新导入来源读取完整节点；当前结果不能用于覆盖配置。")
        elif not self.result.nodes:
            self._show_error("没有可导入节点，请检查正文、格式或与现有节点的重复情况。")
        else:
            self.error_label.hide()
            self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(True)
        return self.result

    def _accept_parsed(self) -> None:
        result = self.parse()
        if result is not None and result.nodes and getattr(result, "providers_complete", True):
            super().accept()

    def save(self) -> None:
        try:
            write_text_file(self._source_path, self.editor.toPlainText())
            self.error_label.hide()
        except ConfigError:
            self._show_error("无法保存本地文件，请检查目标路径、权限及 UTF-8 编码。")

    def save_as(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(self, "保存订阅正文", self._source_path, "订阅与节点文件 (*.yaml *.yml *.txt *.conf);;所有文件 (*)")
        if not filename:
            return
        try:
            write_text_file(filename, self.editor.toPlainText())
            self._source_path = filename
            self.error_label.hide()
        except ConfigError:
            self._show_error("无法保存本地文件，请检查目标路径、权限及 UTF-8 编码。")


class ProxyImportPreviewDialog(QDialog):
    """只显示安全摘要；候选对象不会放进 Qt item data 或 tooltip。"""

    def __init__(
        self, result: SubscriptionImport, summary: Mapping[str, Any] | None = None, parent=None,
        *, existing_group: Mapping[str, Any] | None = None,
    ):
        super().__init__(parent)
        self.result = result
        self._initial_result = result
        self._legacy_summary = dict(summary or {})
        self._existing_group = deepcopy(dict(existing_group)) if existing_group is not None else None
        self.update_summary = dict(summary or {})
        self._active_result = result
        self.setWindowTitle("确认导入代理节点")
        self.setModal(True)
        self._redact = _import_redactor(result, self._existing_group)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)
        self.summary = QLabel()
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setWordWrap(True)
        self.summary.setObjectName("sectionTitle")
        layout.addWidget(self.summary)
        self.update_hint = label("", "hint")
        self.update_hint.setVisible(bool(self.update_summary))
        layout.addWidget(self.update_hint)
        layout.addWidget(label("HTTP / HTTPS 可用于 HTTP 与浏览器；SOCKS5 仅用于浏览器；VLESS / AnyTLS 等通过本地 mihomo 桥接。确认后只写入草稿，不会自动保存或自动选中节点。"))

        controls = QHBoxLayout()
        self.policy_group = QComboBox()
        self.policy_group.setAccessibleName("Clash 策略组")
        self._populate_policy_groups()
        self.policy_group.currentIndexChanged.connect(self._refresh_view)
        controls.addWidget(self.policy_group)
        self.edit_content_button = button("编辑正文", self.edit_content, "quiet")
        self.edit_content_button.setVisible(bool(result.content))
        controls.addWidget(self.edit_content_button)
        controls.addStretch(1)
        layout.addLayout(controls)
        self.scope_hint = label("")
        layout.addWidget(self.scope_hint)

        self.table = QTableWidget(0, 5)
        self.table.setAccessibleName("待导入代理节点预览")
        self.table.setHorizontalHeaderLabels(["名称", "协议", "服务器", "状态", "说明"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setShowGrid(False)
        layout.addWidget(self.table, 1)

        self.notices = QPlainTextEdit()
        self.notices.setReadOnly(True)
        self.notices.setAccessibleName("代理导入注意事项")
        self.notices.setMaximumHeight(110)
        layout.addWidget(self.notices)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("导入到草稿")
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("kind", "primary")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self._refresh_view()
        fit_dialog(self, 900, 600, (600, 420))

    def _populate_policy_groups(self, current: str = "") -> None:
        blocked = self.policy_group.blockSignals(True)
        self.policy_group.clear()
        self.policy_group.addItem("导入全部可用节点", "")
        for item in self.result.policy_groups:
            if str(item.get("type") or "").lower() == "select":
                name = str(item.get("name") or "")
                self.policy_group.addItem(f"select 递归范围：{self._redact.text(name)[:100]}", name)
        index = self.policy_group.findData(current)
        self.policy_group.setCurrentIndex(index if index >= 0 else 0)
        self.policy_group.setVisible(self.policy_group.count() > 1)
        self.policy_group.blockSignals(blocked)

    def _effective_result(self) -> SubscriptionImport:
        selected = str(self.policy_group.currentData() or "")
        if not selected:
            return self.result
        try:
            nodes = select_policy_nodes(self.result, selected)
        except ConfigError:
            return replace(self.result, candidates=(), nodes=(), notices=tuple(self.result.notices) + ("所选策略组无法展开，请检查组引用或重新导入来源。",))
        node_ids = {str(node.get("id") or "") for node in nodes}
        candidates = tuple(item for item in self.result.candidates if item.node_id and item.node_id in node_ids)
        return replace(self.result, candidates=candidates, nodes=nodes)

    def _refresh_view(self) -> None:
        result = self._effective_result()
        self._redact = _import_redactor(self.result, self._existing_group)
        has_context = self._existing_group is not None or not self._legacy_summary
        if has_context:
            self.update_summary = subscription_update_summary(self._existing_group, result)
            result = replace(result, selection_lost=bool(self.update_summary.get("selection_lost")))
        elif result is self._initial_result:
            self.update_summary = dict(self._legacy_summary)
        else:
            # 旧 API 只给聚合计数时无法推回旧节点；宁可说明缺少上下文，也不展示过期的删除数。
            self.update_summary = {}
        self._active_result = result
        filtered = max(0, self.result.importable_count - result.importable_count)
        self.summary.setText(
            f"来源：{self._redact.text(result.source_label)} · 总数 {len(self.result.candidates)} 个 · "
            f"将导入 {result.importable_count} 个 · 跳过 {self.result.skipped_count} 个 · "
            f"重复 {self.result.duplicate_count} 个 · 被筛选 {filtered} 个"
        )
        selected = str(self.policy_group.currentData() or "")
        self.scope_hint.setText(
            "当前范围：所选 select 组递归可达的节点，包含嵌套策略组与已读取的 provider；不执行自动测速、轮换或规则分流。"
            if selected else "当前范围：全部已解析且可导入的节点（包括已读取的 provider），不按策略组预先筛选。"
        )
        self.update_hint.setVisible(bool(self.update_summary) or bool(self._legacy_summary))
        if self.update_summary:
            self.update_hint.setText(
                "刷新摘要："
                f"新增 {int(self.update_summary.get('added', 0))} · "
                f"替换 {int(self.update_summary.get('replaced', 0))} · "
                f"移除 {int(self.update_summary.get('removed', 0))} · "
                f"保留 {int(self.update_summary.get('unchanged', 0))}"
                + (" · 当前节点将清除" if self.update_summary.get("selection_lost") else "")
            )
        elif self._legacy_summary:
            self.update_hint.setText("内容或范围已变化，导入数量已重新统计；未提供目标组节点上下文，无法重新计算替换和移除数量。")
        active_ids = {str(node.get("id") or "") for node in result.nodes}
        self.table.setRowCount(len(self.result.candidates))
        for row, candidate in enumerate(self.result.candidates):
            excluded = candidate.importable and candidate.node_id not in active_ids
            status = "被筛选" if excluded else {
                "accepted": "可导入", "browser_only": "仅浏览器", "bridged": "需 mihomo 桥接",
                "duplicate": "重复", "unsupported": "跳过", "invalid": "无效", "conflict": "冲突",
            }.get(candidate.status, "检查")
            reason = "不在所选策略组的递归范围内" if excluded else candidate.reason or "将写入目标代理组"
            values = [candidate.name, candidate.protocol.upper(), candidate.display, status, reason]
            for column, value in enumerate(values):
                safe = self._redact.text(value)
                item = QTableWidgetItem(safe)
                item.setToolTip(safe)
                self.table.setItem(row, column, item)
        if not self.result.candidates:
            table_placeholder(self.table, "没有识别到节点", "请返回检查来源类型、文件内容或订阅格式。", "network")
        elif hasattr(self.table, "_placeholder"):
            self.table._placeholder.sync()
        notices = list(result.notices)
        complete = getattr(result, "providers_complete", True)
        if not complete:
            notices.append("外部 provider 尚未完整读取，当前不能导入，以免覆盖时丢失节点。请重新导入原来源并读取完整 provider。")
        self.notices.setPlainText("\n".join(self._redact.text(item) for item in notices))
        self.notices.setVisible(bool(notices))
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(bool(result.nodes) and complete)

    def edit_content(self) -> None:
        if not self.result.content:
            return
        dialog = SubscriptionContentDialog(
            self.result.content,
            source_id=self.result.source_id,
            source_label=self.result.source_label,
            # 结果格式可能是解码后的 YAML，原正文仍可能是 Base64 包装。
            format="auto",
            existing_group=self._existing_group,
            base_result=self.result,
            parent=self,
        )
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.result is not None:
            current = str(self.policy_group.currentData() or "")
            self.result = dialog.result
            self._redact = _import_redactor(self.result, self._existing_group)
            self._populate_policy_groups(current)
            self.edit_content_button.setVisible(bool(self.result.content))
            self._refresh_view()

    def accept(self) -> None:
        if not self._active_result.nodes or not getattr(self._active_result, "providers_complete", True):
            return
        self.result = self._active_result
        super().accept()
