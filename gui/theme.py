"""工作台主题：深色导航栏、浅/深双主题内容区、统一 8px 圆角与紧凑间距。"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QSettings
from PySide6.QtGui import QColor, QPalette

FONT_FAMILY = "Microsoft YaHei UI"
MONO_FAMILY = "Consolas"
DEFAULT_THEME = "light"

_THEMES = {
    "light": {
        "background": "#f3f4f6", "surface": "#ffffff", "input": "#f9fafb",
        "raised": "#eef0f3", "border": "#e4e7ec", "text": "#1f2933",
        "muted": "#6b7787", "accent": "#2f6fed", "accent_bg": "#2f6fed",
        "hover": "#f1f4f9", "success": "#1f8a5b", "warning": "#b7791f",
        "danger": "#d64550", "selection": "#e8f0fe", "hero": "#f5f8ff",
        "hero_border": "#d9e4fb", "success_bg": "#e6f5ee", "danger_bg": "#fdecee",
        "warning_bg": "#fdf4e3",
        "rail": "#1b2332", "rail_text": "#9aa7bb", "rail_active": "#ffffff",
        "rail_hover": "#263044", "rail_selected": "#2f3d55",
    },
    "dark": {
        "background": "#12161d", "surface": "#1a202a", "input": "#161c25",
        "raised": "#232b37", "border": "#2b3442", "text": "#e6ebf2",
        "muted": "#8a97aa", "accent": "#6f9bff", "accent_bg": "#2f6fed",
        "hover": "#222a37", "success": "#5cc692", "warning": "#e0b15e",
        "danger": "#f07f89", "selection": "#23314d", "hero": "#1b2434",
        "hero_border": "#2c3b5a", "success_bg": "#1e3a2e", "danger_bg": "#3f2630",
        "warning_bg": "#3a3222",
        "rail": "#0c0f15", "rail_text": "#7f8ca0", "rail_active": "#ffffff",
        "rail_hover": "#181d27", "rail_selected": "#232b3a",
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
        (QPalette.ColorRole.Highlight, t["selection"]),
        (QPalette.ColorRole.HighlightedText, t["text"]),
        (QPalette.ColorRole.ToolTipBase, t["surface"]),
        (QPalette.ColorRole.ToolTipText, t["text"]),
        (QPalette.ColorRole.PlaceholderText, t["muted"]),
    ):
        result.setColor(role, QColor(value))
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText, QPalette.ColorRole.WindowText):
        result.setColor(QPalette.ColorGroup.Disabled, role, QColor(t["muted"]))
    return result


def build_qss(name: str) -> str:
    t = tokens(name)
    return f"""
QMainWindow, QDialog, QMessageBox, QWidget#appRoot {{ background: {t['background']}; color: {t['text']}; }}
QWidget {{ color: {t['text']}; }}
QLabel {{ background: transparent; }}

/* ---- 导航栏 ---- */
QFrame#navRail {{ background: {t['rail']}; border: none; }}
QFrame#navRail QLabel#brandMark {{
    background: {t['accent_bg']}; color: white; border-radius: 10px; font-size: 18px; font-weight: 700;
}}
QToolButton[kind="nav"] {{
    background: transparent; color: {t['rail_text']}; border: none; border-radius: 8px;
    font-size: 11px; padding: 2px;
}}
QToolButton[kind="nav"]:hover {{ background: {t['rail_hover']}; color: {t['rail_active']}; }}
QToolButton[kind="nav"]:checked {{ background: {t['rail_selected']}; color: {t['rail_active']}; font-weight: 600; }}
QToolButton[kind="nav"]::menu-indicator {{ image: none; width: 0; }}

/* ---- 底部状态条 ---- */
QFrame#statusStrip {{ background: {t['surface']}; border-top: 1px solid {t['border']}; }}
QLabel#stripText {{ color: {t['muted']}; font-size: 11px; }}
QLabel#saveState {{
    color: {t['success']}; background: {t['success_bg']}; font-size: 11px;
    border-radius: 6px; padding: 2px 8px;
}}
QLabel#saveState[dirty="true"] {{ color: {t['warning']}; background: {t['warning_bg']}; }}
QLabel#metricValue {{ font-size: 12px; font-weight: 600; }}
QLabel#metricValue[tone="accent"] {{ color: {t['accent']}; }}
QLabel#metricValue[tone="danger"] {{ color: {t['danger']}; }}

/* ---- 文本层级 ---- */
QLabel#pageTitle {{ font-size: 18px; font-weight: 650; }}
QLabel#accountTitle {{ font-size: 20px; font-weight: 650; }}
QLabel#sectionTitle {{ font-size: 13px; font-weight: 600; }}
QLabel#hint, QLabel#muted {{ color: {t['muted']}; font-size: 11px; }}
QLabel#eyebrow {{ color: {t['accent']}; font-size: 11px; font-weight: 600; letter-spacing: 1px; }}
QLabel#latestText {{ font-size: 20px; font-weight: 650; color: {t['text']}; }}
QLabel#latestText[empty="true"] {{ font-size: 16px; font-weight: 500; color: {t['muted']}; }}
QLabel#taskReturn {{ font-size: 13px; color: {t['text']}; }}
QLabel#taskName {{ font-size: 13px; font-weight: 600; }}
QLabel#taskIndex {{ color: {t['muted']}; background: {t['raised']}; border-radius: 6px; font-size: 10px; }}
QLabel#accountLatestLine {{ color: {t['accent']}; font-size: 11px; }}
QLabel#activity {{
    color: {t['accent']}; background: {t['selection']}; border-radius: 8px; padding: 8px 12px; font-size: 12px;
}}
QLabel#error {{ color: {t['danger']}; background: {t['danger_bg']}; border-radius: 8px; padding: 8px 12px; }}
QLabel#banner {{ color: {t['warning']}; background: {t['warning_bg']}; border-radius: 8px; padding: 8px 12px; }}
QLabel#captureHint {{ color: {t['text']}; font-size: 12px; }}

/* ---- 容器 ---- */
QFrame#sidebar {{ background: {t['surface']}; border: none; border-right: 1px solid {t['border']}; }}
QFrame#accountPanel {{ background: {t['background']}; border: none; }}
QFrame#captureBar {{ background: {t['hero']}; border: 1px solid {t['hero_border']}; border-radius: 10px; }}
QFrame#latestCard {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 10px; }}
QFrame#taskResult {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 8px; }}
QFrame#modeSwitch {{ background: {t['raised']}; border: none; border-radius: 8px; }}
QLabel#verdictBadge {{
    color: {t['muted']}; background: {t['raised']}; border-radius: 6px; padding: 3px 8px; font-size: 11px;
}}
QLabel#verdictBadge[tone="success"] {{ color: {t['success']}; background: {t['success_bg']}; }}
QLabel#verdictBadge[tone="danger"] {{ color: {t['danger']}; background: {t['danger_bg']}; }}
QLabel#verdictBadge[tone="accent"] {{ color: {t['accent']}; background: {t['selection']}; }}

/* ---- 按钮 ---- */
QPushButton {{
    background: {t['surface']}; border: 1px solid {t['border']};
    border-radius: 6px; padding: 5px 12px; min-height: 18px; font-size: 12px;
}}
QPushButton:hover {{ background: {t['hover']}; border-color: {t['accent']}; }}
QPushButton:pressed {{ background: {t['selection']}; }}
QPushButton:focus {{ border-color: {t['accent']}; }}
QPushButton::menu-indicator {{ subcontrol-position: right center; subcontrol-origin: padding; left: -4px; }}
QPushButton[kind="primary"] {{ background: {t['accent_bg']}; color: white; border-color: {t['accent_bg']}; font-weight: 600; }}
QPushButton[kind="primary"]:hover {{ background: {t['accent']}; border-color: {t['accent']}; }}
QPushButton[kind="quiet"] {{ color: {t['muted']}; background: transparent; border-color: transparent; }}
QPushButton[kind="quiet"]:hover {{ color: {t['text']}; background: {t['hover']}; border-color: transparent; }}
QPushButton[kind="link"] {{ color: {t['accent']}; background: transparent; border: none; padding: 2px 4px; }}
QPushButton[kind="link"]:hover {{ text-decoration: underline; }}
QPushButton[kind="segment"] {{ background: transparent; border: none; color: {t['muted']}; padding: 4px 14px; border-radius: 6px; }}
QPushButton[kind="segment"]:checked {{ background: {t['surface']}; color: {t['text']}; font-weight: 600; }}
QPushButton[kind="danger"] {{ color: {t['danger']}; }}
QPushButton[kind="danger"]:hover {{ border-color: {t['danger']}; }}
QPushButton:disabled {{ color: {t['muted']}; border-color: transparent; background: {t['raised']}; }}
QPushButton[kind="primary"]:disabled {{ color: {t['muted']}; background: {t['raised']}; }}

/* ---- 输入 ---- */
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background: {t['input']}; border: 1px solid {t['border']}; border-radius: 6px;
    padding: 5px 8px; font-size: 12px; selection-background-color: {t['selection']}; selection-color: {t['text']};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus,
QSpinBox:focus, QDoubleSpinBox:focus {{ border-color: {t['accent']}; }}
QLineEdit:read-only, QLineEdit:disabled, QPlainTextEdit:disabled, QComboBox:disabled {{ color: {t['muted']}; }}
QComboBox {{ min-height: 20px; padding-right: 22px; }}
QComboBox::drop-down {{ width: 20px; border: none; }}
QComboBox QLineEdit {{ border: none; background: transparent; padding: 0; }}
QComboBox QAbstractItemView {{
    background: {t['surface']}; border: 1px solid {t['border']};
    selection-background-color: {t['selection']}; selection-color: {t['text']};
}}

/* ---- 标签页（下划线式） ---- */
QTabWidget::pane {{ border: none; padding-top: 4px; }}
QTabBar {{ qproperty-drawBase: 0; }}
QTabBar::tab {{
    background: transparent; color: {t['muted']}; padding: 7px 12px; margin-right: 10px;
    border: none; border-bottom: 2px solid transparent; font-size: 12px;
}}
QTabBar::tab:selected {{ color: {t['text']}; border-bottom: 2px solid {t['accent']}; font-weight: 600; }}
QTabBar::tab:hover {{ color: {t['text']}; }}
QTabWidget#configTabs::pane {{ border-top: 1px solid {t['border']}; }}

/* ---- 列表 / 表格 ---- */
QListWidget, QTreeWidget, QTableWidget {{
    background: {t['surface']}; alternate-background-color: {t['input']};
    border: 1px solid {t['border']}; border-radius: 8px;
    gridline-color: {t['border']}; selection-background-color: {t['selection']};
    selection-color: {t['text']}; outline: none;
}}
QListWidget#accountList {{ border: none; background: transparent; }}
QListWidget#accountList::item {{ padding: 0; margin: 0; background: transparent; border: none; }}
QListWidget#taskList::item {{ padding: 10px 12px; border: none; border-bottom: 1px solid {t['border']}; margin: 0; }}
QListWidget#taskList::item:selected {{ background: {t['selection']}; color: {t['text']}; }}
QListWidget#taskList::item:hover {{ background: {t['hover']}; }}
QHeaderView::section {{
    background: {t['surface']}; color: {t['muted']}; border: none;
    border-bottom: 1px solid {t['border']}; padding: 7px 8px; font-size: 11px; font-weight: 600;
}}
QTableWidget::item, QTreeWidget::item {{ padding: 4px 6px; border: none; }}
QTableWidget::item:selected {{ background: {t['selection']}; color: {t['text']}; }}
QCheckBox {{ spacing: 8px; padding: 3px 0; }}
QCheckBox:disabled {{ color: {t['muted']}; }}
QGroupBox {{ border: 1px solid {t['border']}; border-radius: 8px; margin-top: 12px; padding-top: 8px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {t['accent']}; }}
QScrollArea, QScrollArea#overviewScroll, QWidget#overviewContent {{ border: none; background: transparent; }}
QSplitter::handle {{ background: transparent; }}
QSplitter#accountSplitter::handle {{ background: {t['border']}; }}
QSplitter::handle:hover {{ background: {t['accent']}; }}
QPlainTextEdit#logView, QPlainTextEdit#jsonView, QPlainTextEdit#jsonEditor {{ font-family: "{MONO_FAMILY}"; font-size: 12px; }}
QMenuBar, QMenu {{ background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 6px; padding: 4px; }}
QMenu::item {{ padding: 6px 24px; border-radius: 4px; }}
QMenuBar::item:selected, QMenu::item:selected {{ background: {t['selection']}; }}
QMenu::separator {{ height: 1px; background: {t['border']}; margin: 4px 8px; }}
QToolTip {{ color: {t['text']}; background: {t['surface']}; border: 1px solid {t['border']}; padding: 6px; }}
QScrollBar:vertical {{ background: transparent; width: 8px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {t['border']}; border-radius: 3px; min-height: 28px; }}
QScrollBar::handle:vertical:hover {{ background: {t['muted']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
QScrollBar:horizontal {{ background: transparent; height: 8px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {t['border']}; border-radius: 3px; min-width: 28px; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: transparent; }}
"""
