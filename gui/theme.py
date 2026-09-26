"""工作台设计令牌：雾白 / 石墨内容区、靛蓝主操作和一致的语义状态。"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QSettings
from PySide6.QtGui import QColor, QPalette

FONT_FAMILY = "Microsoft YaHei UI"
MONO_FAMILY = "Consolas"
DEFAULT_THEME = "light"

_THEMES = {
    "light": {
        "background": "#f5f6fa", "surface": "#ffffff", "input": "#fbfcff",
        "raised": "#eef1f7", "border": "#e1e6ef", "text": "#1e293f",
        "muted": "#66758c", "accent": "#4b63e8", "accent_bg": "#4b63e8",
        "accent_hover": "#3d51ca", "on_accent": "#ffffff",
        "hover": "#f0f3fa", "success": "#168363", "warning": "#a66a12",
        "danger": "#c94258", "selection": "#edf1ff", "hero": "#f0f3ff",
        "hero_border": "#dbe2ff", "success_bg": "#e7f5ee", "danger_bg": "#fcecef",
        "warning_bg": "#fff4df",
        "rail": "#192237", "rail_text": "#a6b2cc", "rail_active": "#ffffff",
        "rail_hover": "#232f48", "rail_selected": "#303e60", "rail_muted": "#7f90b3",
    },
    "dark": {
        "background": "#111722", "surface": "#1b2433", "input": "#151e2c",
        "raised": "#263247", "border": "#303d53", "text": "#e8edf7",
        "muted": "#a0adc4", "accent": "#9aafff", "accent_bg": "#546de5",
        "accent_hover": "#657dee", "on_accent": "#ffffff",
        "hover": "#253249", "success": "#72d5ad", "warning": "#ebbd72",
        "danger": "#ff96a7", "selection": "#2b3b61", "hero": "#212e49",
        "hero_border": "#374b72", "success_bg": "#203f37", "danger_bg": "#432b3a",
        "warning_bg": "#3d3427",
        "rail": "#0c121e", "rail_text": "#a1aec7", "rail_active": "#f3f6ff",
        "rail_hover": "#192439", "rail_selected": "#263654", "rail_muted": "#7f90b3",
    },
}


def tokens(name: str) -> dict[str, str]:
    return dict(_THEMES.get(name, _THEMES[DEFAULT_THEME]))


def load_pref(key: str, default: Any = None) -> Any:
    return QSettings("DailyTask", "Workbench-v3").value(key, default)


def save_pref(key: str, value: Any) -> None:
    QSettings("DailyTask", "Workbench-v3").setValue(key, value)


def load_theme() -> str:
    value = str(load_pref("theme", DEFAULT_THEME))
    return value if value in _THEMES else DEFAULT_THEME


def save_theme(name: str) -> None:
    save_pref("theme", name if name in _THEMES else DEFAULT_THEME)


def palette(name: str) -> QPalette:
    t = tokens(name)
    result = QPalette()
    for role, value in (
        (QPalette.ColorRole.Window, t["background"]),
        (QPalette.ColorRole.WindowText, t["text"]),
        (QPalette.ColorRole.Base, t["input"]),
        (QPalette.ColorRole.AlternateBase, t["surface"]),
        (QPalette.ColorRole.Text, t["text"]),
        (QPalette.ColorRole.Button, t["surface"]),
        (QPalette.ColorRole.ButtonText, t["text"]),
        (QPalette.ColorRole.Highlight, t["accent_bg"]),
        (QPalette.ColorRole.HighlightedText, t["on_accent"]),
        (QPalette.ColorRole.ToolTipBase, t["surface"]),
        (QPalette.ColorRole.ToolTipText, t["text"]),
        (QPalette.ColorRole.PlaceholderText, t["muted"]),
        (QPalette.ColorRole.Link, t["accent"]),
        (QPalette.ColorRole.Mid, t["border"]),
    ):
        result.setColor(role, QColor(value))
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText, QPalette.ColorRole.WindowText):
        result.setColor(QPalette.ColorGroup.Disabled, role, QColor(t["muted"]))
    return result


def build_qss(name: str) -> str:
    t = tokens(name)
    return f"""
QWidget {{ color: {t['text']}; font-family: "{FONT_FAMILY}"; font-size: 13px; }}
QMainWindow, QDialog, QMessageBox, QWidget#appRoot {{ background: {t['background']}; }}
QLabel {{ background: transparent; border: none; }}

/* 导航：图标和文字使用同一套矢量资源，紧凑模式保留文字。 */
QFrame#navRail {{ background: {t['rail']}; border: none; }}
QLabel#brandMark {{ background: {t['accent_bg']}; color: white; border-radius: 12px; font-size: 21px; font-weight: 700; }}
QLabel#brandName {{ color: {t['rail_active']}; font-size: 18px; font-weight: 700; }}
QLabel#brandCaption, QLabel#navCaption {{ color: {t['rail_muted']}; font-size: 11px; }}
QToolButton[kind="nav"] {{
    color: {t['rail_text']}; background: transparent; border: 1px solid transparent;
    border-radius: 9px; padding: 8px; font-size: 13px; text-align: left;
}}
QToolButton[kind="nav"][compact="true"] {{ font-size: 10px; padding: 4px; }}
QToolButton[kind="nav"]:hover {{ background: {t['rail_hover']}; color: {t['rail_active']}; }}
QToolButton[kind="nav"]:checked {{ background: {t['rail_selected']}; color: {t['rail_active']}; font-weight: 600; }}
QToolButton[kind="nav"]:focus {{ border-color: {t['rail_text']}; }}
QToolButton[kind="nav"]::menu-indicator {{ image: none; width: 0; }}
QFrame#navDivider {{ background: {t['rail_hover']}; max-height: 1px; border: none; }}

/* 工作台顶栏与状态栏。 */
QFrame#workspaceHeader {{ background: {t['surface']}; border-bottom: 1px solid {t['border']}; }}
QLabel#workspaceTitle {{ font-size: 14px; font-weight: 600; }}
QLabel#workspaceCrumb {{ color: {t['muted']}; font-size: 12px; }}
QLabel#localBadge {{ color: {t['success']}; background: {t['success_bg']}; padding: 5px 10px; border-radius: 6px; font-size: 11px; }}
QFrame#statusStrip {{ background: {t['surface']}; border-top: 1px solid {t['border']}; }}
QLabel#stripText {{ color: {t['muted']}; font-size: 11px; }}
QLabel#saveState {{ color: {t['success']}; background: {t['success_bg']}; font-size: 11px; border-radius: 6px; padding: 4px 8px; }}
QLabel#saveState[dirty="true"] {{ color: {t['warning']}; background: {t['warning_bg']}; }}
QLabel#metricValue {{ font-size: 12px; font-weight: 600; }}
QLabel#metricValue[tone="accent"] {{ color: {t['accent']}; }}
QLabel#metricValue[tone="danger"] {{ color: {t['danger']}; }}
QLabel#statValue {{ font-size: 25px; font-weight: 700; }}
QLabel#statValue[tone="accent"] {{ color: {t['accent']}; }}
QLabel#statValue[tone="danger"] {{ color: {t['danger']}; }}

/* 标题、正文、说明和状态不争夺注意力。 */
QLabel#pageTitle, QLabel#accountTitle {{ font-size: 26px; font-weight: 700; }}
QLabel#sectionTitle {{ font-size: 14px; font-weight: 600; }}
QLabel#sidebarTitle {{ font-size: 17px; font-weight: 650; }}
QLabel#hint, QLabel#muted {{ color: {t['muted']}; font-size: 12px; }}
QLabel#eyebrow {{ color: {t['accent']}; font-size: 11px; font-weight: 600; }}
QLabel#latestText {{ font-size: 24px; font-weight: 650; }}
QLabel#latestText[empty="true"] {{ font-size: 21px; font-weight: 600; }}
QLabel#taskReturn {{ font-size: 13px; }}
QLabel#taskName {{ font-size: 14px; font-weight: 600; }}
QLabel#taskIndex {{ color: {t['accent']}; background: {t['selection']}; border-radius: 7px; font-size: 11px; font-weight: 600; }}
QLabel#accountLatestLine {{ color: {t['accent']}; font-size: 12px; }}
QLabel#activity {{ color: {t['accent']}; background: {t['selection']}; border: 1px solid {t['hero_border']}; border-radius: 9px; padding: 11px 14px; font-size: 12px; }}
QLabel#error {{ color: {t['danger']}; background: {t['danger_bg']}; border-radius: 8px; padding: 10px 14px; }}
QLabel#banner {{ color: {t['warning']}; background: {t['warning_bg']}; border-radius: 8px; padding: 10px 14px; }}
QFrame#banner {{ background: {t['warning_bg']}; border: 1px solid {t['border']}; border-radius: 8px; }}
QFrame#banner QLabel {{ color: {t['warning']}; }}
QLabel#captureHint {{ font-size: 12px; }}

/* 容器与空状态。 */
QFrame#sidebar {{ background: {t['surface']}; border: none; border-right: 1px solid {t['border']}; }}
QFrame#accountPanel {{ background: {t['background']}; border: none; }}
QFrame#surfaceCard, QFrame#statCard {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 12px; }}
QFrame#captureBar {{ background: {t['hero']}; border: 1px solid {t['hero_border']}; border-radius: 10px; }}
QFrame#latestCard {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 {t['hero']}, stop:1 {t['surface']});
    border: 1px solid {t['hero_border']}; border-radius: 14px;
}}
QFrame#taskResult {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 11px; }}
QFrame#modeSwitch {{ background: {t['raised']}; border: 1px solid {t['border']}; border-radius: 9px; }}
QFrame#toolbar {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 9px; }}
QFrame#dialogFooter {{ background: transparent; border-top: 1px solid {t['border']}; }}
QFrame#emptyState {{ background: transparent; border: none; }}
QLabel#emptyMark {{ background: {t['selection']}; border-radius: 14px; }}
QLabel#emptyTitle {{ font-size: 16px; font-weight: 600; }}
QLabel#verdictBadge {{ color: {t['muted']}; background: {t['raised']}; border-radius: 6px; padding: 4px 9px; font-size: 11px; }}
QLabel#verdictBadge[tone="success"] {{ color: {t['success']}; background: {t['success_bg']}; }}
QLabel#verdictBadge[tone="danger"] {{ color: {t['danger']}; background: {t['danger_bg']}; }}
QLabel#verdictBadge[tone="accent"] {{ color: {t['accent']}; background: {t['selection']}; }}

/* 操作反馈：保留可辨识的键盘焦点与禁用状态。 */
QPushButton {{
    background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 8px;
    padding: 7px 13px; min-height: 19px; font-size: 12px;
}}
QPushButton:hover {{ background: {t['hover']}; border-color: {t['accent']}; }}
QPushButton:pressed {{ background: {t['selection']}; border-color: {t['accent']}; }}
QPushButton:focus {{ border-color: {t['accent']}; }}
QPushButton::menu-indicator {{ subcontrol-position: right center; subcontrol-origin: padding; left: -3px; }}
QPushButton[kind="primary"] {{ background: {t['accent_bg']}; color: {t['on_accent']}; border-color: {t['accent_bg']}; font-weight: 600; }}
QPushButton[kind="primary"]:hover {{ background: {t['accent_hover']}; border-color: {t['accent_hover']}; }}
QPushButton[kind="primary"]:pressed {{ background: {t['accent_hover']}; border-color: {t['text']}; }}
QPushButton[kind="primary"]:focus {{ border-color: {t['text']}; }}
QPushButton[kind="quiet"] {{ color: {t['muted']}; background: transparent; border-color: transparent; }}
QPushButton[kind="quiet"]:hover {{ color: {t['text']}; background: {t['hover']}; border-color: {t['border']}; }}
QPushButton[kind="quiet"]:focus {{ border-color: {t['accent']}; }}
QPushButton[kind="link"] {{ color: {t['accent']}; background: transparent; border: 1px solid transparent; padding: 3px 6px; }}
QPushButton[kind="link"]:hover {{ background: {t['selection']}; }}
QPushButton[kind="link"]:focus {{ border-color: {t['accent']}; }}
QPushButton[kind="segment"] {{ background: transparent; border: 1px solid transparent; color: {t['muted']}; padding: 5px 19px; border-radius: 6px; }}
QPushButton[kind="segment"]:checked {{ background: {t['surface']}; color: {t['accent']}; border-color: {t['border']}; font-weight: 600; }}
QPushButton[kind="segment"]:focus {{ border-color: {t['accent']}; }}
QPushButton[kind="danger"] {{ color: {t['danger']}; }}
QPushButton[kind="danger"]:hover {{ background: {t['danger_bg']}; border-color: {t['danger']}; }}
QPushButton:disabled {{ color: {t['muted']}; border-color: {t['border']}; background: {t['raised']}; }}
QPushButton[kind="primary"]:disabled {{ color: {t['muted']}; background: {t['raised']}; border-color: {t['border']}; }}
QToolButton {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 7px; padding: 6px 9px; }}
QToolButton:hover {{ border-color: {t['accent']}; background: {t['hover']}; }}
QToolButton:focus {{ border-color: {t['accent']}; }}
QToolButton:disabled {{ color: {t['muted']}; background: {t['raised']}; }}
QToolButton[kind="quiet"] {{ background: transparent; border-color: transparent; }}

/* 输入与表单。 */
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background: {t['input']}; border: 1px solid {t['border']}; border-radius: 7px;
    padding: 7px 10px; font-size: 13px; selection-background-color: {t['accent_bg']}; selection-color: {t['on_accent']};
}}
QLineEdit:hover, QComboBox:hover {{ border-color: {t['muted']}; }}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{ border-color: {t['accent']}; }}
QLineEdit:read-only, QLineEdit:disabled, QPlainTextEdit:disabled, QComboBox:disabled {{ color: {t['muted']}; background: {t['raised']}; }}
QComboBox {{ min-height: 19px; padding-right: 24px; }}
QComboBox::drop-down {{ width: 24px; border: none; }}
QComboBox QLineEdit {{ border: none; background: transparent; padding: 0; }}
QComboBox QAbstractItemView {{ background: {t['surface']}; border: 1px solid {t['border']}; padding: 4px; selection-background-color: {t['selection']}; selection-color: {t['text']}; }}
QCheckBox {{ spacing: 9px; padding: 4px 0; }}
QCheckBox::indicator {{ width: 17px; height: 17px; }}
QCheckBox:disabled {{ color: {t['muted']}; }}
QCheckBox:focus {{ outline: 1px solid {t['accent']}; }}
QGroupBox {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 10px; margin-top: 15px; padding: 18px 12px 12px 12px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 14px; padding: 0 5px; color: {t['text']}; font-weight: 600; }}

/* 标签页。 */
QTabWidget::pane {{ border: none; padding-top: 8px; }}
QTabBar {{ qproperty-drawBase: 0; }}
QTabBar::tab {{ background: transparent; color: {t['muted']}; padding: 10px 14px; margin-right: 6px; border: none; border-bottom: 2px solid transparent; font-size: 12px; }}
QTabBar::tab:selected {{ color: {t['accent']}; border-bottom: 2px solid {t['accent']}; font-weight: 600; }}
QTabBar::tab:hover {{ color: {t['text']}; background: {t['hover']}; }}
QTabWidget#configTabs::pane {{ border-top: 1px solid {t['border']}; }}

/* 数据密度适中的列表和表格。 */
QListWidget, QTreeWidget, QTableWidget {{
    background: {t['surface']}; alternate-background-color: {t['input']}; border: 1px solid {t['border']};
    border-radius: 9px; gridline-color: {t['border']}; selection-background-color: {t['selection']};
    selection-color: {t['text']}; outline: none;
}}
QListWidget:focus, QTreeWidget:focus, QTableWidget:focus {{ border-color: {t['accent']}; }}
QListWidget#accountList {{ border: none; background: transparent; }}
QListWidget#accountList::item {{ padding: 0; margin: 0; background: transparent; border: none; }}
QListWidget#taskList::item {{ padding: 13px 14px; border: none; border-bottom: 1px solid {t['border']}; margin: 0; }}
QListWidget#taskList::item:selected {{ background: {t['selection']}; color: {t['text']}; }}
QListWidget#taskList::item:hover {{ background: {t['hover']}; }}
QHeaderView {{ background: transparent; }}
QHeaderView::section {{ background: {t['input']}; color: {t['muted']}; border: none; border-bottom: 1px solid {t['border']}; padding: 11px 10px; font-size: 11px; font-weight: 600; }}
QTableWidget::item, QTreeWidget::item {{ padding: 6px 8px; border: none; }}
QTableWidget::item:selected {{ background: {t['selection']}; color: {t['text']}; }}
QTableWidget::item:hover {{ background: {t['hover']}; }}
QScrollArea, QScrollArea#overviewScroll, QWidget#overviewContent {{ border: none; background: transparent; }}
QSplitter::handle {{ background: transparent; }}
QSplitter#accountSplitter::handle {{ background: {t['border']}; }}
QSplitter::handle:hover {{ background: {t['accent']}; }}
QPlainTextEdit#logView, QPlainTextEdit#jsonView, QPlainTextEdit#jsonEditor {{ font-family: "{MONO_FAMILY}"; font-size: 12px; padding: 12px; }}
QProgressBar {{ background: {t['raised']}; border: none; border-radius: 3px; min-height: 5px; max-height: 5px; }}
QProgressBar::chunk {{ background: {t['accent_bg']}; border-radius: 3px; }}

/* 系统浮层和滚动条。 */
QMenuBar, QMenu {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 8px; padding: 5px; }}
QMenu::item {{ padding: 8px 26px; border-radius: 5px; }}
QMenuBar::item:selected, QMenu::item:selected {{ background: {t['selection']}; }}
QMenu::item:disabled {{ color: {t['muted']}; }}
QMenu::separator {{ height: 1px; background: {t['border']}; margin: 5px 8px; }}
QToolTip {{ color: {t['text']}; background: {t['surface']}; border: 1px solid {t['border']}; padding: 7px; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {t['border']}; border-radius: 3px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {t['muted']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {t['border']}; border-radius: 3px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background: {t['muted']}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}
"""
