"""代理订阅来源选择与安全预览对话框。"""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlsplit

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QPlainTextEdit, QTableWidget,
    QTableWidgetItem, QVBoxLayout,
)

from config.subscriptions import SubscriptionImport, parse_subscription_text
from net.subscriptions import read_source, write_text_file
from core.errors import ConfigError
from core.masking import mask_secrets
from gui.dialogs import button, label
from gui.ui import configure_form, fit_dialog, table_placeholder
from gui.worker import Redactor


class ProxySourceDialog(QDialog):
    """只收集来源和目标组，不读取网络或文件。"""

    def __init__(self, groups: list[dict[str, Any]] | None = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("导入 Clash 订阅 / 节点")
        self.setModal(True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)
        layout.addWidget(label("导入 Clash 订阅 / 节点", "pageTitle"))
        layout.addWidget(label("支持 HTTP、HTTPS、SOCKS5，以及经本地 mihomo 桥接的 VLESS、AnyTLS、VMess、Trojan、SS、Hysteria2、TUIC；规则与策略组不展开。"))

        form = configure_form(QFormLayout())
        self.kind = QComboBox()
        self.kind.setAccessibleName("代理来源类型")
        self.kind.addItem("Clash / 订阅链接", "subscription_url")
        self.kind.addItem("单个节点链接", "node_url")
        self.kind.addItem("Clash / 节点文件", "file")
        self.source = QLineEdit()
        self.source.setAccessibleName("订阅或节点来源")
        self.source.setPlaceholderText("https://订阅地址，或粘贴 http(s)/socks5 节点链接")
        self.browse_button = button("选择文件", self._browse, "quiet")
        self.edit_button = button("编辑文件", self._edit_file, "quiet")
        source_row = QHBoxLayout()
        source_row.setContentsMargins(0, 0, 0, 0)
        source_row.addWidget(self.source, 1)
        source_row.addWidget(self.browse_button)
        source_row.addWidget(self.edit_button)
        source_box = source_row
        form.addRow("来源", source_box)

        self.format = QComboBox()
        self.format.setAccessibleName("订阅格式")
        for title, value in (("自动识别", "auto"), ("Clash YAML", "clash_yaml"), ("Base64 节点列表", "base64"), ("节点链接列表", "uri")):
            self.format.addItem(title, value)
        form.addRow("格式", self.format)

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
        self.bind_subscription = QCheckBox("保存订阅链接，后续可一键更新")
        self.bind_subscription.setChecked(True)
        form.addRow("订阅绑定", self.bind_subscription)
        layout.addLayout(form)
        layout.addWidget(label("同一来源再次导入时，只替换该来源生成的节点；手工节点、其它来源节点和当前选择不会被静默删除或切换。", "hint"))

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
        self.kind.currentIndexChanged.connect(self._kind_changed)
        self.source.textChanged.connect(lambda: self.edit_button.setVisible(self.kind.currentData() == "file" and bool(self.source.text().strip())))
        self.target.currentIndexChanged.connect(self._target_changed)
        self._kind_changed()
        self._target_changed()
        fit_dialog(self, 760, 500, (520, 400))

    def _kind_changed(self) -> None:
        kind = self.kind.currentData()
        is_file = kind == "file"
        self.browse_button.setVisible(is_file)
        self.edit_button.setVisible(is_file and bool(self.source.text().strip()))
        self.source.setPlaceholderText(
            "选择 Clash YAML / Base64 / 节点文件" if is_file
            else "粘贴单个 http(s)/socks5 节点链接" if kind == "node_url"
            else "粘贴 HTTPS 订阅链接"
        )
        if kind == "node_url":
            index = self.format.findData("uri")
            if index >= 0:
                self.format.setCurrentIndex(index)
        elif kind == "subscription_url":
            index = self.format.findData("auto")
            if index >= 0:
                self.format.setCurrentIndex(index)

    def _target_changed(self) -> None:
        existing = bool(self.target.currentData())
        self.group_name.setEnabled(not existing)
        if existing:
            self.group_name.clear()
        self.bind_subscription.setVisible(self.kind.currentData() == "subscription_url")
        self.bind_subscription.setText("保存订阅链接，后续可一键更新" if not existing else "更新此组的订阅绑定")

    def _edit_file(self) -> None:
        source = self.source.text().strip()
        try:
            fetched = read_source(source, kind="file")
            dialog = SubscriptionContentDialog(
                fetched.text,
                source_id="",
                source_label=fetched.label,
                source_path=source,
                format=str(self.format.currentData() or "auto"),
                parent=self,
            )
            dialog.exec()
        except ConfigError as exc:
            self.error_label.setText(exc.message)
            self.error_label.show()

    def _browse(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self, "选择 Clash / 节点文件", "", "订阅与节点文件 (*.yaml *.yml *.txt *.conf);;所有文件 (*)",
        )
        if filename:
            self.source.setText(filename)

    def value(self) -> dict[str, str]:
        kind = self.kind.currentData()
        source = self.source.text().strip()
        if not source:
            raise ConfigError("请填写订阅链接、节点链接或选择文件")
        if kind == "file":
            source_kind = "file"
        elif kind == "node_url":
            source_kind = "node"
            try:
                parts = urlsplit(source)
                if parts.scheme.lower() not in {"http", "https", "socks5"} or not parts.hostname:
                    raise ValueError
                if any(char.isspace() or ord(char) < 32 for char in source):
                    raise ValueError
            except ValueError:
                raise ConfigError("节点链接格式无效，请检查协议、主机和认证信息") from None
        else:
            source_kind = "url"
            try:
                parts = urlsplit(source)
                if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                    raise ValueError
                if parts.username or parts.password or parts.fragment:
                    raise ValueError
                if any(char.isspace() or ord(char) < 32 for char in source):
                    raise ValueError
            except ValueError:
                raise ConfigError("订阅链接格式无效，请检查协议、主机和认证信息") from None
        target_group = str(self.target.currentData() or "")
        group_name = self.group_name.text().strip() if not target_group else ""
        return {
            "kind": source_kind,
            "format": str(self.format.currentData() or "auto"),
            "source": source,
            "target_group": target_group,
            "group_name": group_name,
            "bind_subscription": bool(self.bind_subscription.isChecked() and source_kind == "url"),
        }

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
    ):
        super().__init__(parent)
        self.setWindowTitle("编辑订阅正文")
        self.setModal(True)
        self._source_id = str(source_id or "")
        self._source_label = str(source_label or "订阅正文")
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
        self.stats.setText(f"{len(text.encode('utf-8')):,} 字节 · {len(text.splitlines())} 行")

    def _show_error(self, error: Any) -> None:
        self.error_label.setText(str(error))
        self.error_label.show()

    def parse(self) -> SubscriptionImport | None:
        try:
            self.result = parse_subscription_text(
                self.editor.toPlainText(),
                source_id=self._source_id,
                source_label=self._source_label,
                format=str(self.format.currentData() or "auto"),
            )
        except ConfigError as exc:
            self.result = None
            self._show_error(exc.message)
            return None
        self.error_label.hide()
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(bool(self.result.nodes))
        return self.result

    def _accept_parsed(self) -> None:
        if self.parse() is not None:
            super().accept()

    def save(self) -> None:
        try:
            write_text_file(self._source_path, self.editor.toPlainText())
            self.error_label.hide()
        except ConfigError as exc:
            self._show_error(exc.message)

    def save_as(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(self, "保存订阅正文", self._source_path, "订阅与节点文件 (*.yaml *.yml *.txt *.conf);;所有文件 (*)")
        if not filename:
            return
        try:
            write_text_file(filename, self.editor.toPlainText())
            self._source_path = filename
            self.error_label.hide()
        except ConfigError as exc:
            self._show_error(exc.message)


class ProxyImportPreviewDialog(QDialog):
    """只显示安全摘要；候选对象不会放进 Qt item data 或 tooltip。"""

    def __init__(self, result: SubscriptionImport, summary: Mapping[str, Any] | None = None, parent=None):
        super().__init__(parent)
        self.update_summary = dict(summary or {})
        self.setWindowTitle("确认导入代理节点")
        self.setModal(True)
        redact = Redactor()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)
        self.summary = QLabel(
            f"来源：{mask_secrets(result.source_label)} · 可导入 {result.importable_count} 个，"
            f"跳过 {result.skipped_count} 个，重复 {result.duplicate_count} 个"
        )
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setWordWrap(True)
        self.summary.setObjectName("sectionTitle")
        layout.addWidget(self.summary)
        if self.update_summary:
            layout.addWidget(label(
                "刷新摘要："
                f"新增 {self.update_summary.get('added', 0)} · "
                f"替换 {self.update_summary.get('replaced', 0)} · "
                f"移除 {self.update_summary.get('removed', 0)} · "
                f"保留 {self.update_summary.get('unchanged', 0)}"
                + (" · 当前节点将清除" if self.update_summary.get("selection_lost") else ""),
                "hint",
            ))
        layout.addWidget(label("HTTP / HTTPS 可用于 HTTP 与浏览器；SOCKS5 仅用于浏览器；VLESS / AnyTLS 等通过本地 mihomo 桥接。确认后只写入草稿，不会自动保存或自动选中节点。"))

        self.table = QTableWidget(len(result.candidates), 5)
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
        for row, candidate in enumerate(result.candidates):
            status = {
                "accepted": "可导入",
                "browser_only": "仅浏览器",
                "bridged": "需 mihomo 桥接",
                "duplicate": "重复",
                "unsupported": "跳过",
                "invalid": "无效",
                "conflict": "冲突",
            }.get(candidate.status, "检查")
            candidate_redactor = Redactor({"proxy": candidate.url}) if candidate.url else redact
            values = [
                mask_secrets(candidate_redactor.text(candidate.name))[:160], candidate.protocol.upper(), candidate.display[:180],
                status, redact.text(candidate.reason or "将写入目标代理组")[:240],
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row, column, item)
        if not result.candidates:
            table_placeholder(self.table, "没有识别到节点", "请返回检查来源类型、文件内容或订阅格式。", "network")
        layout.addWidget(self.table, 1)

        self.notices = QPlainTextEdit()
        self.notices.setReadOnly(True)
        self.notices.setAccessibleName("代理导入注意事项")
        self.notices.setMaximumHeight(110)
        self.notices.setPlainText("\n".join(result.notices))
        self.notices.setVisible(bool(result.notices))
        layout.addWidget(self.notices)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("导入到草稿")
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("kind", "primary")
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(bool(result.nodes))
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        fit_dialog(self, 900, 600, (600, 420))
