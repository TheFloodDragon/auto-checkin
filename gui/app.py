"""v3 工作台：原始配置草稿、账号级执行请求和逐任务结果各自独立。"""

from __future__ import annotations

import argparse
import json
import os
import sys
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QColor, QFont, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QButtonGroup, QComboBox, QDialog, QFileDialog, QFrame,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea,
    QSizePolicy, QSplitter, QStackedWidget, QTabWidget, QTableWidget, QTableWidgetItem,
    QToolButton, QVBoxLayout, QWidget,
)

from config import paths, secrets
from core import timebase
from core.account import CREDENTIAL_FIELDS
from core.errors import ConfigError
from core.timebase import business_date, utc_iso
from gui import config_store, core, theme
from gui.dialogs import JsonDialog
from gui.proxy_widgets import ProxyGroupsPage, ProxySelector
from gui.status_store import ResultStore
from gui.widgets import ACCOUNT_CARD_ROLE, AccountCardDelegate, AccountEditor, NavRail
from gui.worker import Redactor, safe_data
from gui.workers import JobRunner, StorageRunner

_VERDICTS = {"success": "成功", "already_done": "已完成", "failed": "失败", "no_effect": "无影响"}
_ACTIONS = {"run": "执行", "explain": "流程预览", "capture": "登录态捕获", "templates": "模板发现"}
_STATES = {"queued": "排队中", "running": "运行中", "completed": "已结束", "error": "进程异常", "cancelled": "已取消排队"}
_STATE_TONES = {"queued": "muted", "running": "accent", "completed": "success", "error": "danger", "cancelled": "muted"}


def _identity(account: dict) -> str:
    return str(account.get("id") or "").strip()


def _label(text: str, name: str = "") -> QLabel:
    result = QLabel(text)
    result.setTextFormat(Qt.TextFormat.PlainText)
    if name:
        result.setObjectName(name)
    return result


def _button(text: str, callback, kind: str = "") -> QPushButton:
    result = QPushButton(text)
    result.setCursor(Qt.CursorShape.PointingHandCursor)
    if kind:
        result.setProperty("kind", kind)
    result.clicked.connect(callback)
    return result


def _table(headers: list[str]) -> QTableWidget:
    result = QTableWidget(0, len(headers))
    result.setHorizontalHeaderLabels(headers)
    result.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    result.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    result.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    result.setAlternatingRowColors(True)
    result.setWordWrap(False)
    result.verticalHeader().hide()
    result.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    result.horizontalHeader().setStretchLastSection(True)
    result.verticalHeader().setDefaultSectionSize(36)
    result.setShowGrid(False)
    return result


def _put(table: QTableWidget, row: int, values: list[str], key: Any = None) -> None:
    for column, value in enumerate(values):
        item = QTableWidgetItem(str(value))
        item.setToolTip(str(value))
        if column == 0:
            item.setData(Qt.ItemDataRole.UserRole, key)
        table.setItem(row, column, item)


@dataclass
class JobView:
    """只存稳定身份及展示元数据；请求和凭据由子进程管道独立管理。"""

    action: str
    account_id: str = ""
    title: str = ""
    task_ids: tuple[str, ...] = ()
    state: str = "queued"
    message: str = ""
    fingerprint: str = ""
    target: str = ""
    provider: str = ""
    shared_account: str = ""
    capture_basis: str = ""
    capture_cancelled: bool = False


class App(QMainWindow):
    def __init__(
        self, *, config_path: Path | None = None, results_dir: Path | None = None,
        discover_templates: bool = True,
    ):
        super().__init__()
        self.config_path = Path(config_path or paths.ACCOUNTS_PATH).resolve()
        self._results_override = Path(results_dir).resolve() if results_dir is not None else None
        self.payload: dict = {"version": 3, "accounts": [], "oauth_states": {}}
        self._saved_payload = deepcopy(self.payload)
        self._saved_snapshot = core.fingerprint(self.payload)
        self._revision: str | None = None
        self.selected_id = ""
        self._dirty = False
        self._edit_error = ""
        self._loading = False
        self._saving = False
        self._load_failed = False
        self._closing = False
        self._allow_close = False
        self._storage_error = ""
        self._jobs: dict[str, JobView] = {}
        self._job_rows: dict[str, int] = {}
        self._previews: dict[str, tuple[str, dict]] = {}
        self._capture_job = ""
        self._captured: dict | None = None
        self._latest_record: dict | None = None
        self._overview_signature = ""
        self._redactor: Redactor | None = None
        self._preview_shown: tuple | None = None
        self._shown_day = business_date()
        self.task_return_labels: dict[str, QLabel] = {}
        self.catalog: list[dict] = []
        self._theme = theme.load_theme()
        self.store = ResultStore(self._results_path(self.config_path))
        self.runner = JobRunner(self, max_workers=4)
        self.storage = StorageRunner(self)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.timeout.connect(self._deferred_refresh)
        self._metrics_timer = QTimer(self)
        self._metrics_timer.setSingleShot(True)
        self._metrics_timer.timeout.connect(self._refresh_actions)
        self._message_timer = QTimer(self)
        self._message_timer.setSingleShot(True)
        self._message_timer.timeout.connect(lambda: self.status_message.clear())
        self._results_timer = QTimer(self)
        self._results_timer.setSingleShot(True)
        self._results_timer.timeout.connect(self._persist_results)
        self._close_timer = QTimer(self)
        self._close_timer.setInterval(100)
        self._close_timer.timeout.connect(self._try_close)
        self._day_timer = QTimer(self)
        self._day_timer.setInterval(30_000)
        self._day_timer.timeout.connect(self._check_day)
        self._build()
        self._connect()
        self._apply_theme()
        self.resize(1280, 820)
        self.setMinimumSize(960, 620)
        geometry = theme.load_pref("geometry")
        if geometry is not None:
            try:
                self.restoreGeometry(geometry)
            except (TypeError, ValueError):
                pass
        self._reload(initial=True)
        if discover_templates:
            QTimer.singleShot(0, self._discover_templates)
        self._day_timer.start()

    @property
    def accounts(self) -> list[dict]:
        return self.payload["accounts"]

    def _results_path(self, config_path: Path) -> Path:
        return self._results_override or config_path.parent / paths.RESULTS_DIR_NAME

    def _account(self, account_id: str | None = None) -> dict | None:
        target = self.selected_id if account_id is None else account_id
        return next((account for account in self.accounts if _identity(account) == target), None)

    def _safe(self, value: Any) -> str:
        if self._redactor is None:
            self._redactor = Redactor((self.payload, self._saved_payload))
        return self._redactor.text(value)

    def _invalidate_safe(self) -> None:
        """草稿或已保存副本变化后，下一次脱敏重新收集密钥。"""
        self._redactor = None

    def _deferred_refresh(self) -> None:
        self._refresh_accounts()

    def _check_day(self) -> None:
        if business_date() != self._shown_day:
            self._shown_day = business_date()
            self._refresh_results()

    def _build(self) -> None:
        self.setWindowTitle("DailyTask 工作台")
        root_widget = QWidget()
        root_widget.setObjectName("appRoot")
        self.setCentralWidget(root_widget)
        root = QHBoxLayout(root_widget)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self.nav = NavRail([("⌂", "账号"), ("▶", "运行"), ("⇄", "代理"), ("⚿", "登录态"), ("▦", "模板")])
        self.nav.activated.connect(self.set_page)
        self.theme_button = QToolButton()
        self.theme_button.setProperty("kind", "nav")
        self.theme_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_button.clicked.connect(self._toggle_theme)
        self.nav.add_tool(self.theme_button)
        self.file_button = QToolButton()
        self.file_button.setProperty("kind", "nav")
        self.file_button.setText("⋯")
        self.file_button.setToolTip("文件与更多操作")
        self.file_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.file_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.nav.add_tool(self.file_button)
        root.addWidget(self.nav)
        main = QVBoxLayout()
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)
        notices = QVBoxLayout()
        notices.setContentsMargins(20, 12, 20, 0)
        notices.setSpacing(8)
        self.banner = _label("", "banner")
        self.banner.setWordWrap(True)
        self.banner.hide()
        notices.addWidget(self.banner)
        self.capture_bar = QFrame()
        self.capture_bar.setObjectName("captureBar")
        capture_row = QHBoxLayout(self.capture_bar)
        capture_row.setContentsMargins(14, 10, 10, 10)
        self.capture_hint = _label("", "captureHint")
        self.capture_hint.setWordWrap(True)
        capture_row.addWidget(self.capture_hint, 1)
        self.capture_finish = _button("完成捕获", self._finish_capture, "primary")
        self.capture_cancel = _button("取消捕获", self._cancel_capture)
        capture_row.addWidget(self.capture_finish)
        capture_row.addWidget(self.capture_cancel)
        self.capture_bar.hide()
        notices.addWidget(self.capture_bar)
        main.addLayout(notices)
        self.workspace = QStackedWidget()
        self.workspace.setObjectName("workspace")
        self.workspace.addWidget(self._account_page())
        self.workspace.addWidget(self._runtime_page())
        self.workspace.addWidget(self._proxy_page())
        self.workspace.addWidget(self._oauth_page())
        self.workspace.addWidget(self._catalog_page())
        main.addWidget(self.workspace, 1)
        main.addWidget(self._status_strip())
        root.addLayout(main, 1)
        self.menuBar().hide()
        self._build_menus()
        self._notify("正在加载配置…")

    def _status_strip(self) -> QWidget:
        strip = QFrame()
        strip.setObjectName("statusStrip")
        row = QHBoxLayout(strip)
        row.setContentsMargins(20, 6, 20, 6)
        row.setSpacing(10)
        self.path_label = _label(self.config_path.name, "stripText")
        self.path_label.setToolTip(str(self.config_path))
        self.path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(self.path_label)
        self.save_state = _label("已保存", "saveState")
        row.addWidget(self.save_state)
        self.status_message = _label("", "stripText")
        self.status_message.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        row.addWidget(self.status_message, 1)
        self.metric_values: list[QLabel] = []
        for title, tone in (("账号", ""), ("任务", ""), ("运行 / 排队", "accent"), ("失败", "danger")):
            row.addWidget(_label(title, "stripText"))
            value = _label("0", "metricValue")
            value.setProperty("tone", tone)
            row.addWidget(value)
            row.addSpacing(6)
            self.metric_values.append(value)
        self.cancel_close = _button("取消等待退出", self._abort_close)
        self.cancel_close.hide()
        row.addWidget(self.cancel_close)
        self.export_button = _button("导出 Secret", self._export_secret, "quiet")
        row.addWidget(self.export_button)
        self.reload_button = _button("重新加载", self._reload, "quiet")
        row.addWidget(self.reload_button)
        self.save_button = _button("保存更改", self._save, "primary")
        row.addWidget(self.save_button)
        return strip

    def set_page(self, index: int) -> None:
        self.workspace.setCurrentIndex(index)
        self.nav.set_current(index)

    def _account_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setObjectName("accountSplitter")
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(1)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setMinimumWidth(240)
        sidebar.setMaximumWidth(380)
        column = QVBoxLayout(sidebar)
        column.setContentsMargins(12, 12, 8, 10)
        column.setSpacing(8)
        filters = QHBoxLayout()
        filters.setSpacing(6)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索账号")
        self.search.setToolTip("按名称、ID、地址或模板搜索")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._filter_accounts)
        filters.addWidget(self.search, 1)
        self.account_filter = QComboBox()
        self.account_filter.addItems(["全部", "启用", "停用"])
        self.account_filter.setFixedWidth(70)
        self.account_filter.currentIndexChanged.connect(self._filter_accounts)
        filters.addWidget(self.account_filter)
        column.addLayout(filters)
        self.account_list = QListWidget()
        self.account_list.setObjectName("accountList")
        self.account_list.setMouseTracking(True)
        self.account_list.setUniformItemSizes(True)
        self.account_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.account_delegate = AccountCardDelegate(self.account_list)
        self.account_list.setItemDelegate(self.account_delegate)
        self.account_list.currentItemChanged.connect(self._selection_changed)
        column.addWidget(self.account_list, 1)
        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)
        self.list_hint = _label("", "hint")
        toolbar.addWidget(self.list_hint, 1)
        self.add_button = _button("+ 新增", self._add_account, "quiet")
        toolbar.addWidget(self.add_button)
        self.import_button = QPushButton("导入")
        self.import_button.setProperty("kind", "quiet")
        menu = QMenu(self.import_button)
        menu.addAction("从剪贴板导入", self._import_clipboard)
        menu.addAction("从 JSON 文件导入", self._import_file)
        self.import_button.setMenu(menu)
        toolbar.addWidget(self.import_button)
        column.addLayout(toolbar)
        splitter.addWidget(sidebar)
        right = QFrame()
        right.setObjectName("accountPanel")
        body = QVBoxLayout(right)
        body.setContentsMargins(24, 16, 24, 12)
        body.setSpacing(12)
        account_header = QHBoxLayout()
        account_header.setSpacing(10)
        heading = QVBoxLayout()
        heading.setSpacing(3)
        self.account_title = _label("欢迎使用 DailyTask", "accountTitle")
        self.account_caption = _label("添加一个账号，开始管理任务和返回结果。", "hint")
        self.account_caption.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.account_title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        heading.addWidget(self.account_title)
        heading.addWidget(self.account_caption)
        self.account_latest_line = _label("", "accountLatestLine")
        self.account_latest_line.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.account_latest_line.hide()
        heading.addWidget(self.account_latest_line)
        account_header.addLayout(heading, 1)
        self.preview_button = _button("预览流程", self._preview, "quiet")
        account_header.addWidget(self.preview_button)
        self.more_account_button = QPushButton("更多")
        self.more_account_button.setProperty("kind", "quiet")
        menu = QMenu(self.more_account_button)
        self.duplicate_button = menu.addAction("复制账号", self._duplicate_account)
        self.up_button = menu.addAction("上移账号", lambda: self._move_account(-1))
        self.down_button = menu.addAction("下移账号", lambda: self._move_account(1))
        menu.addSeparator()
        self.delete_button = menu.addAction("删除账号", self._delete_account)
        self.more_account_button.setMenu(menu)
        account_header.addWidget(self.more_account_button)
        self.run_button = _button("运行此账号", self._run_current, "primary")
        account_header.addWidget(self.run_button)
        body.addLayout(account_header)
        navigation = QHBoxLayout()
        mode_switch = QFrame()
        mode_switch.setObjectName("modeSwitch")
        modes = QHBoxLayout(mode_switch)
        modes.setContentsMargins(3, 3, 3, 3)
        modes.setSpacing(2)
        self.mode_group = QButtonGroup(self)
        self.overview_button = _button("概览", lambda: self._set_account_mode(0), "segment")
        self.configure_button = _button("配置", lambda: self._set_account_mode(1), "segment")
        for button in (self.overview_button, self.configure_button):
            button.setCheckable(True)
            self.mode_group.addButton(button)
            modes.addWidget(button)
        self.overview_button.setChecked(True)
        navigation.addWidget(mode_switch)
        navigation.addStretch(1)
        body.addLayout(navigation)
        self.editor_error = _label("", "error")
        self.editor_error.setWordWrap(True)
        self.editor_error.hide()
        body.addWidget(self.editor_error)
        self.account_stack = QStackedWidget()
        self.account_stack.addWidget(self._account_overview_page())
        self.editor = AccountEditor()
        self.editor.set_account(None)
        self.account_stack.addWidget(self.editor)
        body.addWidget(self.account_stack, 1)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([280, 920])
        layout.addWidget(splitter)
        return page

    def _account_overview_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setObjectName("overviewScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.viewport().setAutoFillBackground(False)
        content = QWidget()
        content.setObjectName("overviewContent")
        content.setAutoFillBackground(False)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 6, 4)
        layout.setSpacing(14)
        hero = QFrame()
        hero.setObjectName("latestCard")
        hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(18, 14, 18, 12)
        hero_layout.setSpacing(6)
        top = QHBoxLayout()
        top.addWidget(_label("最新返回", "eyebrow"), 1)
        self.latest_badge = _label("未运行", "verdictBadge")
        top.addWidget(self.latest_badge)
        hero_layout.addLayout(top)
        self.latest_caption = _label("运行后自动更新", "hint")
        self.latest_caption.setWordWrap(True)
        self.latest_caption.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.latest_badge.setMaximumWidth(180)
        hero_layout.addWidget(self.latest_caption)
        self.latest_text = _label("还没有返回结果", "latestText")
        self.latest_text.setWordWrap(True)
        self.latest_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.latest_text.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        hero_layout.addWidget(self.latest_text)
        self.latest_extras = _label("", "hint")
        self.latest_extras.setWordWrap(True)
        self.latest_extras.hide()
        hero_layout.addWidget(self.latest_extras)
        footer = QHBoxLayout()
        self.latest_meta = _label("", "hint")
        self.latest_meta.setWordWrap(True)
        footer.addWidget(self.latest_meta, 1)
        self.copy_return_button = _button("复制文本", self._copy_latest_text, "link")
        self.latest_details_button = _button("完整结果", self._open_latest_record, "link")
        footer.addWidget(self.copy_return_button)
        footer.addWidget(self.latest_details_button)
        hero_layout.addLayout(footer)
        layout.addWidget(hero)
        self.account_activity = _label("", "activity")
        self.account_activity.setWordWrap(True)
        self.account_activity.hide()
        layout.addWidget(self.account_activity)
        heading = QHBoxLayout()
        self.task_results_title = _label("任务返回", "sectionTitle")
        self.task_results_title.setToolTip("每项任务保留最后一次返回；历史结果会标明时间，不计入今日状态。")
        heading.addWidget(self.task_results_title, 1)
        self.manage_tasks_button = _button("管理任务", self._manage_tasks, "link")
        heading.addWidget(self.manage_tasks_button)
        layout.addLayout(heading)
        self.task_results_box = QWidget()
        self.task_results_layout = QVBoxLayout(self.task_results_box)
        self.task_results_layout.setContentsMargins(0, 0, 0, 0)
        self.task_results_layout.setSpacing(8)
        layout.addWidget(self.task_results_box)
        layout.addStretch(1)
        scroll.setWidget(content)
        return scroll

    def _set_account_mode(self, mode: int) -> None:
        if not self._flush_editor():
            self.overview_button.setChecked(self.account_stack.currentIndex() == 0)
            self.configure_button.setChecked(self.account_stack.currentIndex() == 1)
            return
        self.account_stack.setCurrentIndex(mode)
        self.overview_button.setChecked(mode == 0)
        self.configure_button.setChecked(mode == 1)
        self.account_latest_line.setVisible(mode == 1 and self._latest_record is not None)
        self._refresh_account_overview()

    def _manage_tasks(self) -> None:
        self._set_account_mode(1)
        self.editor.tabs.setCurrentIndex(2)

    @staticmethod
    def _page_frame(title: str, hint: str) -> tuple[QWidget, QVBoxLayout, QHBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 12)
        layout.setSpacing(12)
        header = QHBoxLayout()
        header.setSpacing(8)
        heading = _label(title, "pageTitle")
        heading.setToolTip(hint)
        header.addWidget(heading)
        header.addStretch(1)
        layout.addLayout(header)
        return page, layout, header

    def _runtime_page(self) -> QWidget:
        page, layout, header = self._page_frame("运行中心", "同站点串行，跨站点最多 4 个账号并发。")
        self.runtime_hint = _label("同站点串行 · 跨站点最多 4 个并发", "hint")
        header.insertWidget(1, self.runtime_hint)
        self.stop_button = _button("停止排队", self._stop_pending)
        self.stop_button.setToolTip("只取消尚未启动的请求；运行中的任务自然收尾，不强制关闭浏览器。")
        header.addWidget(self.stop_button)
        self.run_all_button = _button("运行全部启用账号", self._run_all, "primary")
        header.addWidget(self.run_all_button)
        self.runtime_tabs = QTabWidget()
        self.runtime_tabs.setDocumentMode(True)
        self.jobs_table = _table(["账号 / 操作", "任务", "状态", "最新事件"])
        self.jobs_table.setColumnWidth(0, 220)
        self.jobs_table.setColumnWidth(1, 160)
        self.jobs_table.setColumnWidth(2, 100)
        self.runtime_tabs.addTab(self.jobs_table, "本次会话")
        results_page = QWidget()
        result_layout = QVBoxLayout(results_page)
        result_layout.setContentsMargins(0, 8, 0, 0)
        result_layout.setSpacing(8)
        results_toolbar = QHBoxLayout()
        self.results_hint = _label("", "hint")
        results_toolbar.addWidget(self.results_hint, 1)
        self.result_filter = QComboBox()
        self.result_filter.addItems(["所有结论", "失败", "成功", "已完成", "无影响"])
        self.result_filter.currentIndexChanged.connect(self._refresh_results)
        results_toolbar.addWidget(self.result_filter)
        results_toolbar.addWidget(_button("刷新记录", self._reload_results, "quiet"))
        result_layout.addLayout(results_toolbar)
        split = QSplitter(Qt.Orientation.Vertical)
        split.setHandleWidth(6)
        self.results_table = _table(["账号", "任务 ID", "结论", "原因", "模板返回文本", "用时", "更新时间"])
        self.results_table.setColumnWidth(0, 155)
        self.results_table.setColumnWidth(1, 120)
        self.results_table.setColumnWidth(2, 130)
        self.results_table.setColumnWidth(4, 220)
        self.results_table.currentCellChanged.connect(self._show_result)
        split.addWidget(self.results_table)
        self.result_detail = QPlainTextEdit()
        self.result_detail.setReadOnly(True)
        self.result_detail.setObjectName("jsonView")
        self.result_detail.setPlaceholderText("选择一项结果，查看模板文本、扩展字段、实际流程与证据（已脱敏）。")
        split.addWidget(self.result_detail)
        split.setSizes([370, 180])
        result_layout.addWidget(split, 1)
        self.runtime_tabs.addTab(results_page, "今日任务结果")
        self.preview_view = QPlainTextEdit()
        self.preview_view.setObjectName("jsonView")
        self.preview_view.setReadOnly(True)
        self.preview_view.setPlaceholderText("在账号页点击预览流程：只解析 Flow、能力和 Overlay 来源，不执行任务。")
        self.runtime_tabs.addTab(self.preview_view, "Flow 与覆盖层")
        logs_page = QWidget()
        logs_layout = QVBoxLayout(logs_page)
        logs_layout.setContentsMargins(0, 8, 0, 0)
        logs_layout.setSpacing(8)
        logs_toolbar = QHBoxLayout()
        logs_toolbar.addWidget(_label("按账号请求隔离的阶段事件；最多保留 3,000 行。", "hint"), 1)
        logs_toolbar.addWidget(_button("清空显示", lambda: self.log_view.clear(), "quiet"))
        logs_layout.addLayout(logs_toolbar)
        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("logView")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(3000)
        logs_layout.addWidget(self.log_view)
        self.runtime_tabs.addTab(logs_page, "事件日志")
        layout.addWidget(self.runtime_tabs, 1)
        return page

    def _proxy_page(self) -> QWidget:
        self.proxy_page = ProxyGroupsPage()
        self.proxy_page.changed.connect(self._proxy_changed)
        return self.proxy_page

    def _proxy_changed(self, value: dict) -> None:
        """代理组编辑只改草稿；校验失败时草稿与页面都回到改动前。"""
        if self._loading or self._closing:
            return
        candidate = deepcopy(self.payload)
        for key in ("proxy_groups", "default_proxy_group"):
            candidate.pop(key, None)
            if value.get(key):
                candidate[key] = deepcopy(value[key])
        try:
            core.validate_payload(candidate, path=self.config_path)
        except Exception as exc:
            self._error("代理组配置无效，草稿未改变", exc)
            self.proxy_page.set_payload(self._proxy_payload())
            return
        self.payload = candidate
        self._invalidate_safe()
        self._sync_proxies()
        self._update_dirty()
        self._refresh_accounts()
        self._show_preview()

    def _proxy_payload(self) -> dict:
        """代理组页面需要账号引用，才能拦截仍被使用的组。"""
        return {**core.proxy_context(self.payload), "accounts": deepcopy(self.accounts)}

    def _sync_proxies(self) -> None:
        if not hasattr(self, "proxy_page"):
            return
        context = core.proxy_context(self.payload)
        self.editor.set_proxy_context(context)
        self.proxy_page.set_payload(self._proxy_payload())
        self.oauth_proxy.set_context(context)

    def _manage_proxies(self) -> None:
        self.set_page(2)

    def _oauth_page(self) -> QWidget:
        page, layout, header = self._page_frame(
            "共享登录态", "按提供商与共享账号保存；各站点通过 login.provider / login.account 引用。捕获仅加入草稿，保存后才落盘。",
        )
        self.oauth_provider = QComboBox()
        self.oauth_provider.addItem("选择提供商", "")
        from browser.oauth_providers import KNOWN_OAUTH_PROVIDERS
        for provider in sorted(KNOWN_OAUTH_PROVIDERS):
            self.oauth_provider.addItem(provider, provider)
        self.oauth_account = QLineEdit("default")
        self.oauth_account.setPlaceholderText("共享账号名称")
        self.oauth_account.setFixedWidth(160)
        header.addWidget(self.oauth_provider)
        header.addWidget(self.oauth_account)
        self.oauth_capture_button = _button("捕获共享登录态", self._capture_oauth, "primary")
        header.addWidget(self.oauth_capture_button)
        # 捕获出口与账号执行共用同一套代理选择：登录态往往绑定出口 IP，
        # 用另一个出口捕获的登录态在执行时可能立刻失效。
        self.oauth_proxy = ProxySelector()
        self.oauth_proxy.manage_requested.connect(self._manage_proxies)
        layout.addWidget(_label("捕获出口（不写入配置，仅本次捕获使用）", "sectionTitle"))
        layout.addWidget(self.oauth_proxy)
        self.oauth_table = _table(["提供商", "共享账号", "用户名", "登录态", "更新时间"])
        self.oauth_table.currentCellChanged.connect(self._select_oauth)
        layout.addWidget(self.oauth_table, 1)
        buttons = QHBoxLayout()
        buttons.addWidget(_label("列表只显示登录态是否存在，不展示凭据内容。", "hint"), 1)
        buttons.addWidget(_button("编辑共享 JSON", self._edit_oauth, "quiet"))
        self.oauth_delete_button = _button("删除选中登录态", self._delete_oauth, "danger")
        buttons.addWidget(self.oauth_delete_button)
        layout.addLayout(buttons)
        return page

    def _catalog_page(self) -> QWidget:
        page, layout, header = self._page_frame("模板库", "清单来自模板注册表与脚本 MANIFEST；参数表单不回填环境变量或默认值。")
        self.catalog_button = _button("重新发现模板", self._discover_templates)
        header.addWidget(self.catalog_button)
        split = QSplitter(Qt.Orientation.Vertical)
        split.setHandleWidth(6)
        self.catalog_table = _table(["模板引用", "名称", "登录方式", "任务方式"])
        self.catalog_table.setColumnWidth(0, 250)
        self.catalog_table.setColumnWidth(1, 180)
        self.catalog_table.setColumnWidth(2, 250)
        self.catalog_table.currentCellChanged.connect(self._show_template)
        split.addWidget(self.catalog_table)
        self.catalog_detail = QPlainTextEdit()
        self.catalog_detail.setObjectName("jsonView")
        self.catalog_detail.setReadOnly(True)
        self.catalog_detail.setPlaceholderText("选择模板查看说明、参数类型、必填项、资源需求与自管阶段。")
        split.addWidget(self.catalog_detail)
        split.setSizes([350, 210])
        layout.addWidget(split, 1)
        return page

    def _build_menus(self) -> None:
        menu = QMenu(self.file_button)
        self.file_button.setMenu(menu)
        self.menuBar().hide()
        for title, callback, shortcut in (
            ("打开配置…", self._open_configuration, "Ctrl+O"),
            ("保存配置", self._save, "Ctrl+S"),
            ("重新加载", self._reload, "Ctrl+R"),
            ("新增账号", self._add_account, "Ctrl+N"),
            ("文档设置 JSON…", self._edit_metadata, ""),
            ("导出 Secret…", self._export_secret, ""),
        ):
            action = QAction(title, self)
            if shortcut:
                action.setShortcut(QKeySequence(shortcut))
            action.triggered.connect(callback)
            menu.addAction(action)
            self.addAction(action)
        menu.addSeparator()
        menu.addAction("退出", self.close)
        # 不注册全局 Delete：文本框中的 Delete 永远只删除文本。

    def _connect(self) -> None:
        self.editor.changed.connect(self._editor_changed)
        self.editor.run_requested.connect(self._run_task)
        self.editor.capture_requested.connect(self._capture_site)
        self.editor.manage_proxies.connect(self._manage_proxies)
        self.runner.started.connect(self._job_started)
        self.runner.progress.connect(self._job_progress)
        self.runner.completed.connect(self._job_completed)
        self.runner.failed.connect(self._job_failed)
        self.runner.changed.connect(self._refresh_actions)
        self.runner.idle.connect(self._try_close)
        self.storage.failed.connect(lambda error: self._error("后台存储失败", error, dialog=False))
        self.storage.changed.connect(self._refresh_actions)

    def _apply_theme(self) -> None:
        palette = theme.palette(self._theme)
        self.setPalette(palette)
        application = QApplication.instance()
        if application is not None:
            application.setPalette(palette)
        self.setStyleSheet(theme.build_qss(self._theme))
        self.theme_button.setText("☀" if self._theme == "dark" else "☾")
        self.theme_button.setToolTip("切换到浅色外观" if self._theme == "dark" else "切换到深色外观")
        self.account_delegate.set_theme(self._theme)
        self._overview_signature = ""
        self._refresh_results()

    def _toggle_theme(self) -> None:
        self._theme = "light" if self._theme == "dark" else "dark"
        theme.save_theme(self._theme)
        self._apply_theme()

    def _confirm(self, title: str, text: str) -> bool:
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(self._safe(text))
        box.setIcon(QMessageBox.Icon.Question)
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        return box.exec() == QMessageBox.StandardButton.Yes

    def _notify(self, message: str, *, banner: bool = False) -> None:
        message = self._safe(message)
        self.status_message.setText(message)
        self.status_message.setToolTip(message)
        self._message_timer.start(12_000)
        if banner:
            self.banner.setText(message)
            self.banner.show()
        self.log_view.appendPlainText(f"[{utc_iso()}] {message}")

    def _error(self, title: str, error: Any, *, dialog: bool = True) -> None:
        text = self._safe(error)
        self._notify(f"{title}：{text}", banner=True)
        if dialog and not self._closing:
            box = QMessageBox(self)
            box.setWindowTitle(title)
            box.setTextFormat(Qt.TextFormat.PlainText)
            box.setText(text)
            box.setIcon(QMessageBox.Icon.Warning)
            box.exec()

    def _flush_editor(self, *, dialog: bool = True) -> bool:
        account = self._account()
        if account is None:
            return True
        try:
            value = self.editor.value()
            identity = _identity(value)
            if not identity or any(_identity(other) == identity for other in self.accounts if other is not account):
                raise ConfigError("账号 ID 必须非空且唯一")
            self.accounts[self.accounts.index(account)] = value
            self.selected_id = identity
            self._edit_error = ""
            self._invalidate_safe()
        except (ConfigError, ValueError, TypeError) as exc:
            self._edit_error = self._safe(exc)
            if dialog:
                self._error("请先修复当前账号", exc)
        self.editor_error.setText(self._edit_error)
        self.editor_error.setVisible(bool(self._edit_error))
        self._update_dirty()
        return not self._edit_error

    def _editor_changed(self) -> None:
        if self._loading or self._closing:
            return
        self._flush_editor(dialog=False)
        self._refresh_timer.start(120)
        self._refresh_actions()
        self._show_preview()

    def _update_dirty(self) -> None:
        self._dirty = bool(self._edit_error) or core.fingerprint(self.payload) != self._saved_snapshot
        self.save_state.setText("保存中…" if self._saving else "未保存" if self._dirty else "已保存")
        self.save_state.setProperty("dirty", self._dirty)
        self.save_state.style().unpolish(self.save_state)
        self.save_state.style().polish(self.save_state)
        suffix = " *" if self._dirty else ""
        self.setWindowTitle(f"DailyTask 工作台 — {self.config_path.name}{suffix}")

    def _selection_changed(self, current: QListWidgetItem | None, previous: QListWidgetItem | None) -> None:
        if current is None:
            return
        target = str(current.data(Qt.ItemDataRole.UserRole))
        if target == self.selected_id:
            return
        if not self._flush_editor():
            self.account_list.blockSignals(True)
            self.account_list.setCurrentItem(previous)
            self.account_list.blockSignals(False)
            return
        self.select_account(target)

    def select_account(self, account_id: str) -> bool:
        if account_id != self.selected_id and not self._flush_editor():
            return False
        account = self._account(account_id)
        self.selected_id = _identity(account) if account is not None else ""
        self.editor.set_account(account)
        self._edit_error = ""
        self.editor_error.hide()
        self.account_stack.setCurrentIndex(0)
        self.overview_button.setChecked(True)
        self.configure_button.setChecked(False)
        self._refresh_accounts()
        self._show_preview()
        return account is not None

    def _filter_accounts(self, *_args: Any) -> None:
        self._refresh_accounts()

    @staticmethod
    def _result_tone(record: dict | None) -> str:
        verdict = (record or {}).get("verdict")
        return "danger" if verdict == "failed" else "success" if verdict in {"success", "already_done"} else "muted"

    def _return_content(self, record: dict | None) -> tuple[str, str]:
        if record is None:
            return "返回文本", "尚未返回"
        value = record.get("text")
        if value is not None and str(value).strip():
            return self._safe(record.get("text_label") or "返回文本"), self._safe(value)
        value = record.get("message") or record.get("label") or _VERDICTS.get(record.get("verdict")) or "任务未返回文本"
        return "返回说明", self._safe(value)

    @staticmethod
    def _return_time(record: dict | None) -> str:
        stamp = timebase.parse_timestamp((record or {}).get("generated_at"))
        if stamp is None:
            return "等待首次返回"
        local = stamp.astimezone()
        if record.get("business_date") == business_date():
            return "今日 " + local.strftime("%H:%M")
        pattern = "%m-%d %H:%M" if local.year == timebase.utc_now().astimezone().year else "%Y-%m-%d %H:%M"
        return local.strftime(pattern) + " · 历史"

    @staticmethod
    def _account_host(account: dict) -> str:
        try:
            parsed = urlsplit(str(account.get("base_url") or account.get("url") or ""))
            return (parsed.hostname or "地址待完善") + (f":{parsed.port}" if parsed.port else "")
        except ValueError:
            return "地址待完善"

    def _account_recent(self, account: dict, latest: dict[str, list[dict]] | None = None) -> list[dict]:
        task_ids = {str(task.get("id") or "").strip() for task in account.get("tasks", [])}
        rows = latest.get(_identity(account), []) if latest is not None else self.store.latest_records(_identity(account))
        return [record for record in rows if record["task_id"] in task_ids]

    def _latest_by_account(self) -> dict[str, list[dict]]:
        grouped: dict[str, list[dict]] = {}
        for record in self.store.latest_records():
            grouped.setdefault(record["account_id"], []).append(record)
        return grouped

    def _refresh_account_overview(self) -> None:
        account = self._account()
        recent = self._account_recent(account) if account is not None else []
        latest = recent[0] if recent else None
        self._latest_record = latest
        self.copy_return_button.setEnabled(latest is not None)
        self.latest_details_button.setEnabled(latest is not None)
        self.manage_tasks_button.setEnabled(account is not None)
        self.account_latest_line.setVisible(latest is not None and self.account_stack.currentIndex() == 1)
        self._refresh_account_activity()
        signature = core.fingerprint({"account": account, "recent": recent, "day": business_date(), "theme": self._theme})
        if signature == self._overview_signature:
            return
        self._overview_signature = signature
        tasks = (account or {}).get("tasks", [])
        by_id = {record["task_id"]: record for record in recent}
        caption, text = self._return_content(latest)
        if latest is not None:
            task = next((item for item in tasks if item.get("id") == latest["task_id"]), {})
            title = self._safe(task.get("title") or latest["task_id"])
            self.latest_caption.setText(f"{title} · {caption}")
            self.latest_text.setText(text[:1200] + ("…" if len(text) > 1200 else ""))
            self.latest_text.setToolTip(text[:4000])
            self.latest_meta.setText("最后返回 · " + self._return_time(latest))
            self.latest_badge.setText(self._safe(latest.get("label") or _VERDICTS.get(latest.get("verdict"), "已返回")))
            self.account_latest_line.setText("最近返回 · " + text[:180] + ("…" if len(text) > 180 else ""))
            self.account_latest_line.setToolTip(text[:4000])
            extras = latest.get("extras") or []
            descriptions = [f"{item[0]} {item[1]}" for item in extras if isinstance(item, (list, tuple)) and len(item) == 2]
            self.latest_extras.setText(self._safe("   ·   ".join(descriptions))[:600])
            self.latest_extras.setVisible(bool(descriptions))
        else:
            self.latest_caption.setText("运行此账号后，返回文本会自动显示在这里。" if account else "先添加或选择一个账号。")
            self.latest_text.setText("还没有返回结果")
            self.latest_text.setToolTip("")
            self.latest_meta.setText("支持每项任务的自定义文本与返回说明")
            self.latest_badge.setText("未运行")
            self.latest_extras.hide()
            self.account_latest_line.clear()
        self.latest_text.setProperty("empty", latest is None)
        self.latest_badge.setProperty("tone", self._result_tone(latest))
        for widget in (self.latest_badge, self.latest_text):
            widget.style().unpolish(widget)
            widget.style().polish(widget)
        self.task_results_title.setText(f"任务返回  /  {len(tasks):02d}")
        while self.task_results_layout.count():
            item = self.task_results_layout.takeAt(0)
            if item.widget() is not None:
                item.widget().hide()
                item.widget().deleteLater()
        self.task_return_labels = {}
        for index, task in enumerate(tasks):
            task_id = str(task.get("id") or "").strip()
            record = by_id.get(task_id)
            card = QFrame()
            card.setObjectName("taskResult")
            column = QVBoxLayout(card)
            column.setContentsMargins(14, 10, 14, 10)
            column.setSpacing(6)
            header = QHBoxLayout()
            number = _label(f"{index + 1:02d}", "taskIndex")
            number.setAlignment(Qt.AlignmentFlag.AlignCenter)
            number.setFixedSize(22, 22)
            header.addWidget(number)
            title_label = _label(self._safe(task.get("title") or task_id), "taskName")
            title_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            title_label.setToolTip(title_label.text())
            header.addWidget(title_label, 1)
            badge = _label(self._safe((record or {}).get("label") or _VERDICTS.get((record or {}).get("verdict"))
                                     or ("未运行" if task.get("enabled", True) else "已停用")), "verdictBadge")
            badge.setMaximumWidth(160)
            badge.setToolTip(badge.text())
            badge.setProperty("tone", self._result_tone(record))
            header.addWidget(badge)
            column.addLayout(header)
            label, value = self._return_content(record)
            shown = f"{label}  {value}" if record and label != "返回说明" else value if record else "等待这项任务的第一次返回"
            result_label = _label(shown[:1200] + ("…" if len(shown) > 1200 else ""), "taskReturn")
            result_label.setWordWrap(True)
            result_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
            result_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            result_label.setToolTip(shown[:4000])
            self.task_return_labels[task_id] = result_label
            column.addWidget(result_label)
            footer = QHBoxLayout()
            footer.addWidget(_label(self._return_time(record), "hint"), 1)
            if record:
                footer.addWidget(_button("详情", lambda _checked=False, item=record: self._open_record(item), "link"))
            else:
                footer.addWidget(_label("ID · " + self._safe(task_id), "hint"))
            column.addLayout(footer)
            self.task_results_layout.addWidget(card)

    def _refresh_account_activity(self) -> None:
        job = next((item for item in reversed(self._jobs.values())
                    if item.account_id == self.selected_id and item.action == "run"), None)
        if job is not None and job.state in {"running", "queued"}:
            self.account_activity.setText("任务" + ("正在运行" if job.state == "running" else "等待运行")
                                          + "，完成后自动更新；现有文本是上次返回。")
            self.account_activity.show()
        elif job is not None and job.state == "error":
            self.account_activity.setText(self._safe("本次请求未生成新结果：" + job.message))
            self.account_activity.show()
        else:
            self.account_activity.hide()

    def _copy_latest_text(self) -> None:
        if self._latest_record is not None:
            QApplication.clipboard().setText(self._return_content(self._latest_record)[1])
            self._notify("已复制最近一次返回文本。")

    def _open_latest_record(self) -> None:
        if self._latest_record is not None:
            self._open_record(self._latest_record)

    def _open_record(self, record: dict) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("任务返回 · " + self._safe(record.get("task_id", "")))
        dialog.resize(720, 550)
        layout = QVBoxLayout(dialog)
        layout.addWidget(_label(self._return_time(record) + " · 完整结果（已脱敏，只读）", "hint"))
        view = QPlainTextEdit()
        view.setObjectName("jsonView")
        view.setReadOnly(True)
        view.setPlainText(self._safe(json.dumps(safe_data(record), ensure_ascii=False, indent=2)))
        layout.addWidget(view, 1)
        layout.addWidget(_button("关闭", dialog.accept))
        dialog.exec()

    def _refresh_accounts(self) -> None:
        self._refresh_timer.stop()
        scroll = self.account_list.verticalScrollBar().value()
        self.account_list.setUpdatesEnabled(False)
        self.account_list.blockSignals(True)
        self.account_list.clear()
        query = self.search.text().strip().casefold()
        mode = self.account_filter.currentIndex()
        latest_rows = self._latest_by_account()
        busy_ids = {job.account_id for job in self._jobs.values() if job.state in {"queued", "running"}}
        for account in self.accounts:
            enabled = account.get("enabled", True)
            search_text = " ".join(str(account.get(key, "")) for key in ("id", "name", "base_url", "url", "template"))
            if query and query not in search_text.casefold() or mode == 1 and not enabled or mode == 2 and enabled:
                continue
            identity = _identity(account)
            name = str(account.get("name") or identity)
            tasks = account.get("tasks", [])
            recent = self._account_recent(account, latest_rows)
            latest = recent[0] if recent else None
            caption, value = self._return_content(latest)
            summary = f"{caption}  {value}" if latest and caption != "返回说明" else value if latest else "运行后显示返回文本"
            busy = identity in busy_ids
            state = "运行中" if busy else "已停用" if not enabled else _VERDICTS.get((latest or {}).get("verdict"), "待运行")
            stamp = self._return_time(latest) if latest else f"{len(tasks)} 项任务 · 未运行"
            safe_name = self._safe(name)
            host = self._safe(self._account_host(account))
            item = QListWidgetItem(f"{safe_name}\n{identity}\n{summary}\n{stamp} · {state}")
            item.setData(Qt.ItemDataRole.UserRole, identity)
            item.setData(ACCOUNT_CARD_ROLE, {
                "name": safe_name, "host": host,
                "summary": summary, "stamp": stamp, "status": state, "has_result": latest is not None,
                "tone": "accent" if busy else "muted" if not enabled else self._result_tone(latest),
            })
            item.setToolTip(f"{safe_name} · {host}\n{summary}\n{stamp}")
            self.account_list.addItem(item)
            if identity == self.selected_id:
                self.account_list.setCurrentItem(item)
        self.account_list.verticalScrollBar().setValue(scroll)
        self.account_list.blockSignals(False)
        self.account_list.setUpdatesEnabled(True)
        count = self.account_list.count()
        self.list_hint.setText(f"显示 {count} / {len(self.accounts)} 个账号" if count else "没有匹配账号；可清空筛选或新增账号。")
        account = self._account()
        if account is not None:
            self.account_title.setText(self._safe(account.get("name") or self.selected_id))
            self.account_caption.setText(self._safe(f"{self._account_host(account)}  ·  {account.get('template') or 'auto'}  ·  {len(account.get('tasks', []))} 项任务"))
            self.account_caption.setToolTip(self._safe(f"稳定 ID: {self.selected_id}"))
        else:
            self.account_title.setText("欢迎使用 DailyTask")
            self.account_caption.setText("添加一个账号，开始管理任务和返回结果。")
            self.account_caption.setToolTip("")
        self._refresh_account_overview()
        # 账号的代理绑定会改变「组是否仍被引用」，删除保护必须看当前草稿。
        self._sync_proxies()
        self._refresh_actions()

    def _account_busy(self, account_id: str) -> bool:
        return any(job.account_id == account_id and job.state in {"queued", "running"} for job in self._jobs.values())

    def _refresh_actions(self) -> None:
        if not hasattr(self, "run_all_button"):
            return
        editable = not self._loading and not self._closing
        account = self._account()
        runnable = editable and not self._load_failed and not self._edit_error
        selected = account is not None
        enabled = bool(account.get("enabled", True)) if account else False
        busy = self._account_busy(self.selected_id) if selected else False
        self.workspace.setEnabled(editable)
        self.add_button.setEnabled(editable)
        self.import_button.setEnabled(editable)
        self.save_button.setEnabled(editable and not self._saving and not self._load_failed)
        self.reload_button.setEnabled(editable and not self._saving and not self.runner.busy)
        self.export_button.setEnabled(editable and not self._edit_error)
        for button in (self.duplicate_button, self.delete_button, self.up_button, self.down_button):
            button.setEnabled(editable and selected)
        self.run_button.setEnabled(runnable and selected and enabled and not busy)
        self.run_button.setText("运行中…" if busy else "运行此账号")
        self.configure_button.setEnabled(editable and selected)
        self.more_account_button.setEnabled(editable and selected)
        self._refresh_account_activity()
        self.preview_button.setEnabled(runnable and selected and enabled and not busy)
        self.run_all_button.setEnabled(runnable and bool(self.accounts))
        self.stop_button.setEnabled(editable and self.runner.pending_count > 0)
        self.oauth_capture_button.setEnabled(editable and not self._capture_job and not self.runner.busy)
        self.oauth_delete_button.setEnabled(editable and self.oauth_table.currentRow() >= 0)
        self.catalog_button.setEnabled(editable and not any(job.action == "templates" and job.state in {"queued", "running"} for job in self._jobs.values()))
        self.metric_values[0].setText(f"{sum(a.get('enabled', True) for a in self.accounts)} / {len(self.accounts)}")
        self.metric_values[1].setText(str(sum(t.get("enabled", True) for a in self.accounts if a.get("enabled", True) for t in a.get("tasks", []))))
        self.metric_values[2].setText(f"{self.runner.active_count} / {self.runner.pending_count}")
        self.metric_values[3].setText(str(self.store.failed_count()))

    def _reload(self, _checked: bool = False, *, initial: bool = False, path: Path | None = None) -> None:
        if self._loading or self._saving or self._closing:
            return
        if not initial:
            if self.runner.busy:
                self._notify("请等待当前后台请求结束后再重新加载或切换配置。")
                return
            self._flush_editor(dialog=False)
            if self._dirty and not self._confirm("放弃未保存更改？", "重新加载只会在读取成功后替换草稿。是否放弃当前未保存的更改？"):
                return
        target = Path(path or self.config_path).resolve()
        results_path = self._results_path(target)
        self._loading = True
        self._refresh_actions()

        def load():
            loaded = config_store.load_configuration(target)
            store = ResultStore(results_path)
            error = ""
            try:
                store.load()
            except Exception:
                error = "结果缓存读取失败；配置仍可编辑，损坏的缓存不会被覆盖。"
            return loaded, store, error

        def loaded(value, error):
            self._loading = False
            if error is not None:
                self._load_failed = True
                self._error("配置读取失败，已保留当前草稿", error, dialog=False)
            else:
                configuration, store, cache_error = value
                self.config_path = configuration.path
                self.payload = deepcopy(configuration.payload)
                self._saved_payload = deepcopy(self.payload)
                self._saved_snapshot = core.fingerprint(self.payload)
                self._revision = configuration.revision
                self.store = store
                self._load_failed = False
                self._edit_error = ""
                self._invalidate_safe()
                self._previews.clear()
                self.selected_id = ""
                self.editor.set_account(None)
                self.path_label.setText(self.config_path.name)
                self.path_label.setToolTip(str(self.config_path))
                if self.accounts:
                    self.select_account(_identity(self.accounts[0]))
                self._update_dirty()
                self._refresh_accounts()
                self._refresh_oauth()
                self._refresh_results()
                self.banner.hide()
                message = f"已加载 {len(self.accounts)} 个账号；所有修改需显式保存。"
                if configuration.notes:
                    message += " " + "；".join(configuration.notes)
                self._notify(cache_error or message, banner=bool(cache_error or configuration.notes))
            self._refresh_actions()

        self.storage.submit(load, loaded)

    def _open_configuration(self) -> None:
        if self._closing or self._loading or self._saving or self.runner.busy:
            self._notify("请等待后台请求完成后再切换配置。")
            return
        filename, _ = QFileDialog.getOpenFileName(self, "打开配置", str(self.config_path.parent), "JSON 配置 (*.json)")
        if filename:
            self._reload(path=Path(filename))

    def _save(self) -> None:
        if self._closing or self._loading or self._saving:
            return
        if self._load_failed:
            self._error("暂不能保存", "最近一次加载失败；请修复文件并重新加载，防止覆盖原配置。")
            return
        if not self._flush_editor():
            return
        try:
            request = config_store.build_save_request(self.payload, path=self.config_path, expected_revision=self._revision)
        except Exception as exc:
            self._error("保存校验失败", exc)
            return
        self._saving = True
        self._update_dirty()
        self._refresh_actions()

        def saved(configuration, error):
            self._saving = False
            if error is not None:
                self._error("保存失败，草稿仍保留", error, dialog=False)
            else:
                self._saved_payload = deepcopy(configuration.payload)
                self._saved_snapshot = core.fingerprint(configuration.payload)
                self._revision = configuration.revision
                self._invalidate_safe()
                self.banner.hide()
                self._update_dirty()
                suffix = "；保存期间的新编辑仍未保存" if self._dirty else ""
                self._notify(f"配置已原子保存{suffix}。")
            self._update_dirty()
            self._refresh_actions()

        self.storage.submit(request.persist, saved)

    def _add_account(self) -> None:
        if self._closing or self._loading or not self._flush_editor():
            return
        identity = core.unique_id("account", [_identity(account) for account in self.accounts])
        self.accounts.append({"id": identity, "name": "新账号", "base_url": "", "template": "auto", "tasks": [{"id": "daily", "title": "每日任务"}]})
        self._invalidate_safe()
        self.search.clear()
        self.account_filter.setCurrentIndex(0)
        self.select_account(identity)
        self.set_page(0)
        self._set_account_mode(1)
        self.editor.tabs.setCurrentIndex(0)
        self._update_dirty()

    def _duplicate_account(self) -> None:
        if not self._flush_editor() or self._account() is None:
            return
        copied = deepcopy(self._account())
        copied["id"] = core.unique_id(self.selected_id + "-copy", [_identity(account) for account in self.accounts])
        copied["name"] = str(copied.get("name") or self.selected_id) + " · 副本"
        index = next(i for i, account in enumerate(self.accounts) if _identity(account) == self.selected_id)
        self.accounts.insert(index + 1, copied)
        self._invalidate_safe()
        self.search.clear()
        self.account_filter.setCurrentIndex(0)
        self.select_account(copied["id"])
        self._update_dirty()

    def _delete_account(self) -> None:
        account = self._account()
        if account is None:
            return
        if not self._confirm("删除账号？", "删除选中账号及其全部任务和凭据？保存后生效。已启动请求仍按原始身份完成，历史结果不会转给其他账号。"):
            return
        index = self.accounts.index(account)
        del self.accounts[index]
        self._invalidate_safe()
        self.selected_id = ""
        self.editor.set_account(None)
        self._edit_error = ""
        if self.accounts:
            self.select_account(_identity(self.accounts[min(index, len(self.accounts) - 1)]))
        else:
            self._refresh_accounts()
        self._update_dirty()

    def _move_account(self, delta: int) -> None:
        if not self._flush_editor() or self._account() is None:
            return
        index = next(i for i, account in enumerate(self.accounts) if _identity(account) == self.selected_id)
        target = index + delta
        if 0 <= target < len(self.accounts):
            self.accounts[index], self.accounts[target] = self.accounts[target], self.accounts[index]
            self._refresh_accounts()
            self._update_dirty()

    def _import_text(self, text: str) -> None:
        if self._loading or self._closing or not self._flush_editor():
            return
        try:
            count = len(self.accounts)
            imported = core.import_accounts(self.payload, text, path=self.config_path)
            self.payload = imported
            self._invalidate_safe()
            if len(self.accounts) > count:
                self.select_account(_identity(self.accounts[count]))
            self._refresh_accounts()
            self._refresh_oauth()
            self._update_dirty()
            self._notify(f"已导入 {len(self.accounts) - count} 个账号；尚未保存。")
        except Exception as exc:
            self._error("导入失败，原草稿未变更", exc)

    def _import_clipboard(self) -> None:
        self._import_text(QApplication.clipboard().text())

    def _import_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "导入账号", str(self.config_path.parent), "JSON 配置 (*.json)")
        if not filename:
            return
        try:
            text = Path(filename).read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError):
            self._error("导入失败", "无法读取 UTF-8 JSON 文件，请检查文件权限与编码。")
            return
        self._import_text(text)

    def _export_secret(self) -> None:
        if self._loading or self._closing or not self._flush_editor():
            return
        exported = deepcopy(self.payload)
        exported["accounts"] = [account for account in exported["accounts"] if account.get("enabled", True)]
        try:
            core.validate_payload(exported, path=self.config_path)
            if not exported["accounts"]:
                raise ConfigError("没有启用的账号可导出")
            # 多行 Secret 的每一行都会被 GitHub 自动掩码；缩进/括号等短行会误遮日志。
            text = json.dumps(exported, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            warning = secrets.check_size(text)
            if warning:
                raise ConfigError(warning)
        except Exception as exc:
            self._error("导出校验失败", exc)
            return
        if not self._confirm("复制包含凭据的 Secret？", "将启用账号的完整 v3 单行 JSON 复制到系统剪贴板，包含所有任务、扩展字段和共享 OAuth 登录态。请仅粘贴到可信的 Secret 存储。cookie_file 引用保持原文，远端必须能读取同一凭据文件。"):
            return
        QApplication.clipboard().setText(text)
        self._notify(f"已复制 {len(exported['accounts'])} 个启用账号的 Secret；本地草稿与禁用账号未改变。")

    def _edit_metadata(self) -> None:
        if self._loading or self._closing or not self._flush_editor():
            return
        value = {key: deepcopy(item) for key, item in self.payload.items() if key not in {"accounts", "oauth_states"}}
        dialog = JsonDialog("文档设置（不含账号和共享登录态）", value, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        updated = dialog.value()
        if "accounts" in updated or "oauth_states" in updated:
            self._error("文档设置无效", "请在对应工作区编辑 accounts 与 oauth_states。")
            return
        candidate = {**updated, "accounts": self.accounts}
        if "oauth_states" in self.payload:
            candidate["oauth_states"] = self.payload["oauth_states"]
        try:
            core.validate_payload(candidate, path=self.config_path)
        except Exception as exc:
            self._error("文档设置无效", exc)
            return
        self.payload = deepcopy(candidate)
        self._invalidate_safe()
        self._sync_proxies()
        self._update_dirty()

    def _submit(self, request: dict, job: JobView, *, group: str = "") -> str:
        if self._closing:
            raise RuntimeError("工作台正在等待退出")
        job_id = uuid4().hex
        self._jobs[job_id] = job
        try:
            self.runner.submit(job_id, request, group=group)
        except Exception:
            self._jobs.pop(job_id, None)
            raise
        self._refresh_jobs()
        self._refresh_accounts()
        return job_id

    def _queue_account(self, account: dict, action: str, task_ids: tuple[str, ...] = ()) -> str:
            identity = _identity(account)
            if self._account_busy(identity):
                raise ConfigError("该账号已有执行或预览请求，请等待完成")
            spec = core.validate_payload(core.account_payload(account, self.payload), path=self.config_path).accounts[0]
            selected = core.selected_task_ids(account, task_ids, path=self.config_path, context=self.payload)
            baseline = next((item for item in self._saved_payload["accounts"] if _identity(item) == identity), None)
            request = {
                "action": action, "account": deepcopy(account), "only_tasks": list(selected),
                "oauth_states": deepcopy(self.payload.get("oauth_states", {})),
                "explicit": list(core.credential_changes(account, baseline)),
                "config_path": str(self.config_path), "overlay_path": str(self.store.results_dir / "overlay.json"),
                # 代理组随请求冻结：子进程读取的是提交那一刻的组与节点，
                # 期间在界面改组不会悄悄改变已排队请求的出口。
                **core.proxy_context(self.payload),
                "environ_proxy": os.environ.get("CHECKIN_PROXY", ""),
            }
            return self._submit(request, JobView(action, identity, self._safe(account.get("name") or identity), selected,
                                                fingerprint=core.proxy_fingerprint(account, self.payload)), group=spec.site_key)

    def _run_task(self, task_id: str) -> None:
        self._run_current(task_id=task_id)

    def _run_current(self, _checked: bool = False, *, task_id: str = "") -> None:
        if self._load_failed or self._loading or not self._flush_editor():
            return
        account = self._account()
        if account is None:
            return
        try:
            self._queue_account(account, "run", (task_id,) if task_id else ())
            self._notify("任务已提交，返回结果会在账号概览中自动更新。")
        except Exception as exc:
            self._error("无法启动账号", exc)

    def _run_all(self) -> None:
        if self._load_failed or self._loading or not self._flush_editor():
            return
        count = 0
        skipped: list[str] = []
        for account in self.accounts:
            if not account.get("enabled", True):
                continue
            try:
                self._queue_account(account, "run")
                count += 1
            except Exception as exc:
                skipped.append(self._safe(f"{account.get('name') or _identity(account)}：{exc}"))
        self.set_page(1)
        self.runtime_tabs.setCurrentIndex(0)
        self._notify(f"已提交 {count} 个账号；跳过 {len(skipped)} 个。" + (" " + "；".join(skipped) if skipped else ""), banner=bool(skipped))

    def _preview(self) -> None:
        if not self._flush_editor() or self._account() is None:
            return
        try:
            self._queue_account(self._account(), "explain")
            self.set_page(1)
            self.runtime_tabs.setCurrentIndex(2)
            self.preview_view.setPlainText("正在隔离进程中解析 Flow、能力和覆盖层来源；不会执行站点任务…")
        except Exception as exc:
            self._error("无法预览流程", exc)

    def _show_preview(self) -> None:
        entry = self._previews.get(self.selected_id)
        if entry is None:
            self._preview_shown = None
            self.preview_view.clear()
            return
        fingerprint, payload = entry
        current = self._account()
        stale = bool(self._edit_error or current is None or core.fingerprint(current) != fingerprint)
        shown = (self.selected_id, fingerprint, stale)
        if shown == self._preview_shown:
            return  # 同一预览且新鲜度未变化，不重复序列化大 JSON。
        self._preview_shown = shown
        prefix = "此预览对应此前的草稿，配置已经改变，请重新预览。\n\n" if stale else "只读流程预览；实际执行以运行事件和结果为准。\n\n"
        self.preview_view.setPlainText(prefix + json.dumps(payload, ensure_ascii=False, indent=2))

    def _job_started(self, job_id: str) -> None:
        job = self._jobs.get(job_id)
        if job is None:
            return
        job.state = "running"
        self._refresh_jobs()
        if job.action == "capture":
            self.capture_finish.setEnabled(True)

    def _job_progress(self, job_id: str, line: str) -> None:
        job = self._jobs.get(job_id)
        if job is None:
            return
        safe = self._safe(line)
        job.message = safe[:500]
        self.log_view.appendPlainText(f"[{job.title or _ACTIONS[job.action]}] {safe}")
        self._update_job_row(job_id)

    def _job_completed(self, job_id: str, result: Any) -> None:
        job = self._jobs.get(job_id)
        if job is None:
            return
        job.state = "completed"
        try:
            if not isinstance(result, dict):
                raise ValueError("后台结果必须是 JSON 对象")
            if job.action == "run":
                if result.get("account_id") != job.account_id:
                    raise ValueError("后台结果账号 ID 与请求不一致，未归入其他账号")
                rows = result.get("results")
                if (
                    not isinstance(rows, list)
                    or len(rows) != len(job.task_ids)
                    or any(not isinstance(row, dict) or row.get("account_id") != job.account_id for row in rows)
                    or {row.get("task_id") for row in rows} != set(job.task_ids)
                ):
                    raise ValueError("后台返回的任务集合或归属与请求不一致，未伪造任务结果")
                self.store.apply(result)
                self._results_timer.start(150)
                failures = sum(row.get("verdict") == "failed" for row in rows)
                job.message = f"{len(rows)} 项任务已结束，{failures} 项失败"
                self._refresh_results()
            elif job.action == "explain":
                self._previews[job.account_id] = (job.fingerprint, safe_data(result))
                job.message = "只读流程预览已生成"
                self._show_preview()
            elif job.action == "templates":
                self.catalog = result.get("templates", [])
                self.editor.set_catalog(self.catalog)
                self._refresh_catalog()
                job.message = f"已发现 {len(self.catalog)} 个模板"
            elif job.action == "capture":
                if self._closing or job.capture_cancelled:
                    self._clear_capture()
                elif result.get("ok") is False:
                    self._clear_capture()
                    raise ValueError("未捕获到有效登录态，请在浏览器完成登录后重试")
                else:
                    self._captured = result
                    self.capture_hint.setText("捕获已完成（未验证）。点击“纳入草稿”后仍需保存；凭据不会写入结果缓存。")
                    self.capture_finish.setText("纳入草稿")
                    self.capture_finish.setEnabled(True)
                    self.capture_cancel.setText("丢弃捕获")
                    job.message = "捕获已就绪，等待显式纳入草稿"
        except Exception as exc:
            job.state = "error"
            job.message = self._safe(exc)
            self._error("后台结果处理失败", exc, dialog=False)
        self._refresh_jobs()
        self._refresh_accounts()

    def _job_failed(self, job_id: str, error: str) -> None:
        job = self._jobs.get(job_id)
        if job is None:
            return
        job.state = "cancelled" if job.capture_cancelled else "error"
        job.message = "已取消捕获，未写入草稿" if job.capture_cancelled else self._safe(error)
        if job.action == "capture":
            self._clear_capture()
        self._notify(f"{job.title or _ACTIONS[job.action]}：{job.message}", banner=not job.capture_cancelled)
        self._refresh_jobs()
        self._refresh_accounts()

    def _job_values(self, job: JobView) -> list[str]:
        title = f"{job.title} / {_ACTIONS[job.action]}" if job.title else _ACTIONS[job.action]
        return [title, ", ".join(job.task_ids), _STATES[job.state], job.message]

    def _tint_job_row(self, row: int, job: JobView) -> None:
        item = self.jobs_table.item(row, 2)
        if item is not None:
            item.setForeground(QColor(theme.tokens(self._theme)[_STATE_TONES[job.state]]))

    def _update_job_row(self, job_id: str) -> None:
        """只改动单行的状态与最新事件；日志行不再触发整表重建。"""
        job = self._jobs.get(job_id)
        row = self._job_rows.get(job_id)
        if job is None or row is None or row >= self.jobs_table.rowCount():
            self._refresh_jobs()
            return
        for column, value in ((2, _STATES[job.state]), (3, job.message)):
            item = self.jobs_table.item(row, column)
            if item is None:
                self._refresh_jobs()
                return
            if item.text() != value:
                item.setText(value)
                item.setToolTip(value)
        self._tint_job_row(row, job)
        self._metrics_timer.start(150)

    def _refresh_jobs(self) -> None:
        self.jobs_table.setUpdatesEnabled(False)
        self.jobs_table.setRowCount(len(self._jobs))
        self._job_rows = {}
        for row, (job_id, job) in enumerate(reversed(self._jobs.items())):
            _put(self.jobs_table, row, self._job_values(job), job_id)
            self._tint_job_row(row, job)
            self._job_rows[job_id] = row
        self.jobs_table.setUpdatesEnabled(True)
        self._refresh_actions()

    def _stop_pending(self, _checked: bool = False, *, notify: bool = True) -> None:
        cancelled = self.runner.cancel_pending()
        for job_id in cancelled:
            job = self._jobs.get(job_id)
            if job is not None:
                job.state = "cancelled"
                job.message = "请求尚未启动，不生成业务结果"
        self._refresh_jobs()
        self._refresh_accounts()
        if notify:
            self._notify(f"已取消 {len(cancelled)} 个排队请求；运行中的任务会正常收尾。")

    def _refresh_results(self, *_args: Any) -> None:
        if not hasattr(self, "results_table"):
            return
        selected_key = None
        item = self.results_table.item(self.results_table.currentRow(), 0)
        if item is not None:
            selected_key = item.data(Qt.ItemDataRole.UserRole)
        verdict = ("", "failed", "success", "already_done", "no_effect")[self.result_filter.currentIndex()]
        records = [record for record in self.store.records() if not verdict or record.get("verdict") == verdict]
        self.results_table.blockSignals(True)
        self.results_table.setRowCount(len(records))
        selection = -1
        for row, record in enumerate(records):
            key = (record["account_id"], record["task_id"])
            value = record.get("text") or ""
            text = f"{record['text_label']}：{value}" if value and record.get("text_label") else value
            duration = record.get("duration_seconds")
            duration_text = f"{duration:.2f}s" if isinstance(duration, (int, float)) else "—"
            label = record.get("label") or _VERDICTS.get(record.get("verdict"), "未知结论")
            if record.get("icon"):
                label = f"{record['icon']} {label}"
            values = [record.get("name") or record["account_id"], record["task_id"], label,
                      record.get("reason") or "—", text or "—", duration_text, record.get("generated_at", "")]
            _put(self.results_table, row, [self._safe(value) for value in values], key)
            tone = "danger" if record.get("verdict") == "failed" else "muted" if record.get("verdict") == "no_effect" else "success"
            self.results_table.item(row, 2).setForeground(QColor(theme.tokens(self._theme)[tone]))
            if key == selected_key:
                selection = row
        self.results_table.blockSignals(False)
        self.results_hint.setText(f"业务日 {business_date()} · {len(records)} 项结果；只有 failed 计入失败。")
        if selection >= 0:
            self.results_table.selectRow(selection)
        elif records:
            self.results_table.selectRow(0)
        else:
            self.result_detail.clear()
        self._show_result()
        self._refresh_accounts()

    def _show_result(self, *_args: Any) -> None:
        item = self.results_table.item(self.results_table.currentRow(), 0)
        if item is None:
            self.result_detail.clear()
            return
        key = item.data(Qt.ItemDataRole.UserRole)
        record = self.store.get(*key)
        self.result_detail.setPlainText(self._safe(json.dumps(safe_data(record), ensure_ascii=False, indent=2)))

    def _persist_results(self) -> None:
        self._results_timer.stop()
        try:
            payload = self.store.snapshot_payload()
        except Exception as exc:
            self._storage_error = self._safe(exc)
            self._error("结果缓存暂未保存", exc, dialog=False)
            return
        directory = self.store.results_dir

        def saved(_result, error):
            if error is not None:
                self._storage_error = self._safe(error)
                if self._closing:
                    self._abort_close()
                self._error("结果缓存保存失败，内存结果仍保留", error, dialog=False)
            else:
                self._storage_error = ""

        self.storage.submit(lambda: ResultStore.write_payload(directory, payload), saved)

    def _reload_results(self) -> None:
        if self._results_timer.isActive():
            self._persist_results()
        directory = self.store.results_dir

        def read():
            store = ResultStore(directory)
            store.load()
            return store.snapshot_payload()

        def loaded(snapshot, error):
            if error is not None:
                self._error("结果读取失败，已保留内存结果", "请检查缓存文件格式与访问权限。", dialog=False)
                return
            # 一并合入历史最近返回和单轮顺序；不覆盖刷新期间到达的较新结果。
            by_account: dict[str, dict] = {}
            for field in ("results", "latest_results"):
                for record in snapshot.get(field, []):
                    group = by_account.setdefault(record["account_id"], {"results": [], "latest_results": []})
                    group[field].append(record)
            for account_id, group in by_account.items():
                self.store.apply({"schema_version": 2, "account_id": account_id, **group})
            self._refresh_results()

        self.storage.submit(read, loaded)

    def _discover_templates(self) -> None:
        if self._closing or any(job.action == "templates" and job.state in {"queued", "running"} for job in self._jobs.values()):
            return
        try:
            self._submit({"action": "templates"}, JobView("templates"))
        except Exception as exc:
            self._error("模板发现失败，可继续手工配置", exc, dialog=False)

    def _refresh_catalog(self) -> None:
        self.catalog_table.setRowCount(len(self.catalog))
        for row, entry in enumerate(self.catalog):
            _put(self.catalog_table, row, [entry.get("reference", ""), entry.get("title") or entry.get("error", ""),
                                          ", ".join(entry.get("login_methods", [])), ", ".join(entry.get("task_methods", []))], row)
        if self.catalog:
            self.catalog_table.selectRow(0)

    def _show_template(self, *_args: Any) -> None:
        row = self.catalog_table.currentRow()
        if 0 <= row < len(self.catalog):
            self.catalog_detail.setPlainText(json.dumps(self.catalog[row], ensure_ascii=False, indent=2))
        else:
            self.catalog_detail.clear()

    def _refresh_oauth(self) -> None:
        self.oauth_table.blockSignals(True)
        self.oauth_table.setRowCount(0)
        for provider, bucket in self.payload.get("oauth_states", {}).items():
            for name, entry in bucket.get("accounts", {}).items():
                row = self.oauth_table.rowCount()
                self.oauth_table.insertRow(row)
                _put(self.oauth_table, row, [provider, name, entry.get("username", ""), "已保存" if entry.get("state") else "空",
                                            entry.get("updated_at", "")], (provider, name))
        self.oauth_table.blockSignals(False)
        self._refresh_actions()

    def _select_oauth(self, *_args: Any) -> None:
        item = self.oauth_table.item(self.oauth_table.currentRow(), 0)
        if item is not None:
            provider, account = item.data(Qt.ItemDataRole.UserRole)
            index = self.oauth_provider.findData(provider)
            if index < 0:
                self.oauth_provider.addItem(provider, provider)
                index = self.oauth_provider.findData(provider)
            self.oauth_provider.setCurrentIndex(index)
            self.oauth_account.setText(account)
        self._refresh_actions()

    def _edit_oauth(self) -> None:
        dialog = JsonDialog("共享 OAuth JSON（包含敏感登录态）", self.payload.get("oauth_states", {}), self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        value = dialog.value()
        try:
            core.validate_payload({"version": 3, "accounts": [], "oauth_states": value})
        except Exception as exc:
            self._error("共享登录态配置无效", exc)
            return
        self.payload["oauth_states"] = value
        self._invalidate_safe()
        self._refresh_oauth()
        self._update_dirty()

    def _delete_oauth(self) -> None:
        item = self.oauth_table.item(self.oauth_table.currentRow(), 0)
        if item is None or not self._confirm("删除共享登录态？", "删除当前共享账号的登录态？引用它的站点配置会保留，保存后生效。"):
            return
        provider, account = item.data(Qt.ItemDataRole.UserRole)
        self.payload["oauth_states"][provider]["accounts"].pop(account, None)
        self._invalidate_safe()
        self._refresh_oauth()
        self._update_dirty()

    def _capture_site(self) -> None:
            if not self._flush_editor() or self._account() is None:
                return
            account = self._account()
            try:
                spec = core.validate_payload(core.account_payload(account, self.payload), path=self.config_path).accounts[0]
                raw = deepcopy(account)
                raw["base_url"] = spec.base_url
                job = JobView("capture", self.selected_id, self._safe(account.get("name") or self.selected_id), target="site",
                              capture_basis=core.fingerprint(account.get("credentials", {})))
                # 站点捕获沿用该账号自己的代理选择：换出口捕获到的登录态常在执行时立即失效。
                self._start_capture({"action": "capture", "target": "site", "account": raw,
                                     **core.proxy_context(self.payload),
                                     "environ_proxy": os.environ.get("CHECKIN_PROXY", "")},
                                    job, group=spec.site_key)
            except Exception as exc:
                self._error("无法捕获站点登录态", exc)

    def _capture_oauth(self) -> None:
            provider = str(self.oauth_provider.currentData() or "")
            account = self.oauth_account.text().strip()
            if not provider or not account:
                self._error("缺少捕获目标", "请明确选择提供商并填写共享账号名称，不会自动选择默认提供商。")
                return
            entry = self.payload.get("oauth_states", {}).get(provider, {}).get("accounts", {}).get(account, {})
            job = JobView("capture", title=f"{provider} / {account}", target="oauth", provider=provider,
                          shared_account=account, capture_basis=core.fingerprint(entry))
            try:
                request = {"action": "capture", "target": "oauth", "provider": provider,
                           "network": self.oauth_proxy.value(), **core.proxy_context(self.payload)}
                self._start_capture(request, job, group=f"oauth:{provider}")
            except Exception as exc:
                self._error("无法捕获共享登录态", exc)

    def _start_capture(self, request: dict, job: JobView, *, group: str) -> None:
        if self._capture_job or self.runner.busy:
            raise ConfigError("请等待当前请求结束后再开始人工捕获")
        self._captured = None
        self._capture_job = self._submit(request, job, group=group)
        self.capture_hint.setText("正在打开浏览器。完成登录后点击“完成捕获”；取消不会保存凭据。捕获不等于验证或签到。")
        self.capture_finish.setText("完成捕获")
        self.capture_cancel.setText("取消捕获")
        self.capture_finish.setEnabled(False)
        self.capture_bar.show()
        self._refresh_actions()

    def _finish_capture(self) -> None:
        if self._captured is not None:
            self._apply_capture()
            return
        if self._capture_job:
            try:
                self.runner.complete_capture(self._capture_job)
                self.capture_finish.setEnabled(False)
                self.capture_hint.setText("正在读取并关闭浏览器，请稍候…")
            except ValueError:
                self._notify("捕获请求尚未启动或正在结束，请稍候。")

    def _cancel_capture(self) -> None:
        if self._captured is not None:
            self._clear_capture()
            return
        if self._capture_job:
            job = self._jobs.get(self._capture_job)
            if job:
                job.capture_cancelled = True
            try:
                self.runner.cancel_capture(self._capture_job)
                self.capture_hint.setText("正在取消捕获并关闭浏览器，不保存任何凭据…")
            except ValueError:
                self._clear_capture()

    def _clear_capture(self) -> None:
        self._captured = None
        self._capture_job = ""
        self.capture_bar.hide()
        self._refresh_actions()

    def _apply_capture(self) -> None:
        if self._captured is None or not self._flush_editor():
            return
        job = self._jobs[self._capture_job]
        result = self._captured
        if job.target == "site":
            account = self._account(job.account_id)
            if account is None:
                self._notify("原账号已被删除，捕获结果未写入任何其他账号。", banner=True)
                self._clear_capture()
                return
            current = account.get("credentials", {})
            incoming = {name: value for name, value in result.get("credentials", {}).items() if name in CREDENTIAL_FIELDS and isinstance(value, str)}
            if not incoming.get("browser_state"):
                self._error("捕获无效", "没有可纳入草稿的浏览器登录态。")
                self._clear_capture()
                return
        else:
            current = self.payload.get("oauth_states", {}).get(job.provider, {}).get("accounts", {}).get(job.shared_account, {})
            if not isinstance(result.get("state"), str) or not result["state"]:
                self._error("捕获无效", "没有可纳入草稿的共享登录态。")
                self._clear_capture()
                return
        conflict = core.fingerprint(current) != job.capture_basis
        warning = "捕获期间目标凭据已被编辑，继续会覆盖同名凭据。\n\n" if conflict else ""
        if not self._confirm("纳入捕获结果？", warning + "将捕获结果写入原目标的内存草稿？不会自动保存，也不代表登录已经验证。"):
            return
        if job.target == "site":
            account.setdefault("credentials", {}).update(incoming)
            if self.selected_id == job.account_id:
                self.editor.set_account(account)
        else:
            bucket = self.payload.setdefault("oauth_states", {}).setdefault(job.provider, {}).setdefault("accounts", {})
            entry = bucket.setdefault(job.shared_account, {})
            entry.update(state=result["state"], username=str(result.get("username") or ""), updated_at=utc_iso())
            self._refresh_oauth()
        self._invalidate_safe()
        self._clear_capture()
        self._update_dirty()
        self._notify("捕获结果已纳入原目标草稿，请保存配置。")

    def _abort_close(self) -> None:
        self._closing = False
        self._close_timer.stop()
        self.cancel_close.hide()
        self._refresh_actions()

    def _try_close(self) -> None:
        if not self._closing or self.runner.busy or self.storage.busy:
            return
        if self._results_timer.isActive():
            self._persist_results()
            return
        if not self.runner.shutdown(0) or not self.storage.shutdown(0):
            return
        self._close_timer.stop()
        self._day_timer.stop()
        self._refresh_timer.stop()
        theme.save_pref("geometry", self.saveGeometry())
        self._allow_close = True
        self.close()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt API
        if self._allow_close:
            event.accept()
            return
        event.ignore()
        if self._closing:
            return
        self._flush_editor(dialog=False)
        if (self._dirty or self._captured is not None) and not self._confirm("放弃未保存内容并退出？", "草稿或尚未纳入的捕获结果未保存。是否放弃这些内容并退出？"):
            return
        if self._storage_error and not self._confirm("结果缓存未保存", "部分结果缓存写入失败。是否仍退出？"):
            return
        if self.runner.busy and not self._confirm("等待安全退出？", "将停止排队并等待当前任务自然结束，再完成存储并退出。不强制终止浏览器；等待期间可以取消退出。"):
            return
        self._closing = True
        self._stop_pending(notify=False)
        if self._capture_job:
            self._cancel_capture()
        if self._results_timer.isActive():
            self._persist_results()
        self.cancel_close.show()
        self._refresh_actions()
        self._notify("正在等待后台任务和存储安全收尾…")
        self._close_timer.start()
        QTimer.singleShot(0, self._try_close)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DailyTask v3 图形工作台")
    parser.add_argument("--config", type=Path, default=None, help="打开指定的 v3 配置文件")
    args = parser.parse_args(argv)
    application = QApplication.instance() or QApplication(sys.argv[:1])
    application.setApplicationName("DailyTask 工作台")
    application.setStyle("Fusion")
    application.setFont(QFont(theme.FONT_FAMILY, 10))
    window = App(config_path=args.config)
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
