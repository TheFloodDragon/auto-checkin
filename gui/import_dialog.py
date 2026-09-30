"""网站账号导入的脱敏预览；只确认操作，不持有或保存配置草稿。"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QDialog, QDialogButtonBox, QHeaderView, QLabel,
    QPlainTextEdit, QTableWidget, QTableWidgetItem, QVBoxLayout,
)

from .worker import Redactor


class ImportPreviewDialog(QDialog):
    """接收准备好的新增账号，仅显示白名单摘要，不展示原始 JSON 或凭据。"""

    def __init__(self, accounts: list[dict[str, Any]], parent=None):
        super().__init__(parent)
        self.setWindowTitle("确认导入账号")
        self.setObjectName("importPreviewDialog")
        self.resize(850, 480)
        self.setMinimumSize(560, 340)
        self.setModal(True)
        redact = Redactor(accounts)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)
        self.summary = QLabel(f"将导入 {len(accounts)} 个账号到草稿，尚不会保存或执行任务。")
        self.summary.setTextFormat(Qt.TextFormat.PlainText)
        self.summary.setWordWrap(True)
        self.summary.setObjectName("sectionTitle")
        layout.addWidget(self.summary)
        hint = QLabel("下表显示导入后的最终 ID；同名 ID 已自动去重，不覆盖已有账号。敏感内容不在此预览中展示。")
        hint.setTextFormat(Qt.TextFormat.PlainText)
        hint.setWordWrap(True)
        hint.setObjectName("hint")
        layout.addWidget(hint)
        self.table = QTableWidget(len(accounts), 6)
        self.table.setAccessibleName("待导入账号预览")
        self.table.setHorizontalHeaderLabels(["名称", "最终 ID", "站点", "模板", "认证方式", "任务 / 状态"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setShowGrid(False)
        notices = []
        for row, account in enumerate(accounts):
            login = account.get("login") if isinstance(account.get("login"), dict) else {}
            tasks = account.get("tasks") if isinstance(account.get("tasks"), list) else []
            parsed = urlsplit(str(account.get("base_url") or account.get("url") or ""))
            task_text = ", ".join(str(task.get("id") or "daily") for task in tasks if isinstance(task, dict))
            status = "启用" if account.get("enabled", True) else "停用 / 待核实"
            values = [account.get("name") or account.get("id", ""), account.get("id", ""),
                      parsed.hostname or "", account.get("template") or "自动识别",
                      login.get("method") or "自动选择", f"{task_text} · {status}"]
            for column, value in enumerate(values):
                # 不把完整账号对象挂在 item data / tooltip 上，避免隐藏的凭据泄漏。
                text = redact.text(value)
                item = QTableWidgetItem(text[:500])
                item.setToolTip(text[:500])
                self.table.setItem(row, column, item)
            info = account.get("collected_info")
            if isinstance(info, dict):
                if info.get("export_kind") == "preview":
                    notices.append("当前内容是无凭据预览；请在网站 Console 执行 await autoCheckinCollector.copy() 后重新导入完整账号。")
                warnings = info.get("warnings")
                if isinstance(warnings, list):
                    for warning in warnings[:5]:
                        if isinstance(warning, str):
                            notices.append(f"{redact.text(account.get('id', ''))}: {redact.text(warning)[:240]}")
                if info.get("requires_review"):
                    notices.append(f"{redact.text(account.get('id', ''))}: 采集信息需要核实，导入后请检查配置。")
            credentials = account.get("credentials")
            if not isinstance(credentials, dict) or not any(credentials.get(key) for key in (
                "access_token", "refresh_token", "cookie", "session_cookie", "browser_state", "cookie_file",
            )):
                notices.append(f"{redact.text(account.get('id', ''))}: 未携带可用凭据，请确认是否复制了采集器的完整导出内容。")
        layout.addWidget(self.table, 1)
        self.notices = QPlainTextEdit()
        self.notices.setReadOnly(True)
        self.notices.setAccessibleName("导入注意事项")
        self.notices.setMaximumHeight(120)
        self.notices.setPlainText("\n".join(dict.fromkeys(notices)))
        self.notices.setVisible(bool(notices))
        layout.addWidget(self.notices)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("导入到草稿")
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("kind", "primary")
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(bool(accounts))
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
