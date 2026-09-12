"""工作台主题：低对比度容器、清晰的结果层级与一致的深浅配色。"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QSettings
from PySide6.QtGui import QColor, QPalette

FONT_FAMILY = "Microsoft YaHei UI"
MONO_FAMILY = "Consolas"
DEFAULT_THEME = "light"

_THEMES = {
    "light": {
        "background": "#f4f6f8", "surface": "#ffffff", "input": "#f8fafb",
        "raised": "#edf2f4", "border": "#e0e7eb", "text": "#21343f",
        "muted": "#627783", "accent": "#15856e", "accent_bg": "#17876f",
        "hover": "#f0f6f4", "success": "#278566", "warning": "#aa7935",
        "danger": "#c55060", "selection": "#edf8f4", "hero": "#f0f8f5",
        "hero_border": "#d3e9df", "success_bg": "#e8f5ee", "danger_bg": "#fbecef",
        "warning_bg": "#fbf4e8",
    },
    "dark": {
        "background": "#11181e", "surface": "#1b252d", "input": "#172128",
        "raised": "#25323b", "border": "#2d3d47", "text": "#e5edf1",
        "muted": "#8fa5b0", "accent": "#79d7bb", "accent_bg": "#287e69",
        "hover": "#24353a", "success": "#80cfa8", "warning": "#e2b778",
        "danger": "#e9929f", "selection": "#213b36", "hero": "#1b332e",
        "hero_border": "#34574b", "success_bg": "#234235", "danger_bg": "#422d36",
        "warning_bg": "#3c3528",
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
QMainWindow, QDialog, QMessageBox, QWidget#appRoot {{
    background: {t['background']}; color: {t['text']};
}}
QWidget {{ color: {t['text']}; }}
QLabel {{ background: transparent; }}
QLabel#brandMark {{
    background: {t['accent_bg']}; color: white; border-radius: 12px;
    font-size: 24px; font-weight: 700;
}}
QLabel#appTitle {{ font-size: 24px; font-weight: 700; }}
QLabel#accountTitle {{ font-size: 22px; font-weight: 650; }}
QLabel#sectionTitle {{ font-size: 15px; font-weight: 600; }}
QLabel#hint, QLabel#muted {{ color: {t['muted']}; font-size: 11px; }}
QLabel#eyebrow {{ color: {t['accent']}; font-size: 12px; font-weight: 600; }}
QLabel#latestText {{ font-size: 28px; font-weight: 650; color: {t['text']}; }}
QLabel#latestText[empty="true"] {{ font-size: 23px; color: {t['muted']}; }}
QLabel#taskReturn {{ font-size: 15px; color: {t['text']}; }}
QLabel#taskName {{ font-size: 13px; font-weight: 600; }}
QLabel#taskIndex {{ color: {t['muted']}; background: {t['raised']}; border-radius: 7px; font-size: 11px; }}
QLabel#accountLatestLine {{ color: {t['accent']}; font-size: 12px; }}
QLabel#error {{ color: {t['danger']}; padding: 6px; }}
QLabel#banner {{
    color: {t['warning']}; background: {t['warning_bg']};
    border: none; border-radius: 9px; padding: 10px;
}}
QLabel#saveState {{ color: {t['muted']}; font-size: 11px; padding: 5px; }}
QLabel#saveState[dirty="true"] {{ color: {t['warning']}; }}
QFrame#sidebar {{ background: transparent; border: none; }}
QFrame#accountPanel, QFrame#card {{
    background: {t['surface']}; border: 1px solid {t['border']}; border-radius: 16px;
}}
QFrame#latestCard {{
    background: {t['hero']}; border: 1px solid {t['hero_border']}; border-radius: 14px;
}}
QFrame#taskResult {{
    background: {t['input']}; border: 1px solid {t['border']}; border-radius: 11px;
}}
QFrame#modeSwitch {{ background: {t['input']}; border: none; border-radius: 9px; }}
QFrame#metricsBar {{ background: transparent; border: none; }}
QLabel#metricValue {{ font-size: 15px; font-weight: 600; }}
QLabel#metricValue[tone="accent"] {{ color: {t['accent']}; }}
QLabel#metricValue[tone="danger"] {{ color: {t['danger']}; }}
QLabel#verdictBadge {{
    color: {t['muted']}; background: {t['raised']};
    border: none; border-radius: 9px; padding: 4px 9px; font-size: 11px;
}}
QLabel#verdictBadge[tone="success"] {{ color: {t['success']}; background: {t['success_bg']}; }}
QLabel#verdictBadge[tone="danger"] {{ color: {t['danger']}; background: {t['danger_bg']}; }}
QLabel#verdictBadge[tone="accent"] {{ color: {t['accent']}; background: {t['selection']}; }}
QPushButton, QToolButton {{
    background: {t['surface']}; border: 1px solid {t['border']};
    border-radius: 8px; padding: 8px 13px; min-height: 18px; font-size: 12px;
}}
QPushButton:hover, QToolButton:hover {{ background: {t['hover']}; border-color: {t['accent']}; }}
QPushButton:pressed, QToolButton:pressed {{ background: {t['selection']}; }}
QPushButton:focus, QToolButton:focus {{ border-color: {t['accent']}; }}
QPushButton[kind="primary"] {{ background: {t['accent_bg']}; color: white; border-color: {t['accent_bg']}; font-weight: 600; }}
QPushButton[kind="primary"]:hover {{ border-color: {t['accent']}; }}
QPushButton[kind="quiet"] {{ color: {t['muted']}; background: transparent; border-color: transparent; }}
QPushButton[kind="quiet"]:hover {{ color: {t['text']}; background: {t['hover']}; }}
QPushButton[kind="link"] {{ color: {t['accent']}; background: transparent; border: none; padding: 3px 5px; }}
QPushButton[kind="segment"] {{ background: transparent; border: none; color: {t['muted']}; padding: 7px 15px; }}
QPushButton[kind="segment"]:checked {{ background: {t['surface']}; color: {t['text']}; font-weight: 600; }}
QPushButton[kind="danger"] {{ color: {t['danger']}; }}
QPushButton:disabled, QToolButton:disabled {{ color: {t['muted']}; border-color: transparent; background: {t['input']}; }}
QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
    background: {t['input']}; border: 1px solid {t['border']}; border-radius: 7px;
    padding: 8px; font-size: 12px; selection-background-color: {t['selection']}; selection-color: {t['text']};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus,
QSpinBox:focus, QDoubleSpinBox:focus {{ border-color: {t['accent']}; }}
QLineEdit:read-only, QLineEdit:disabled, QPlainTextEdit:disabled, QComboBox:disabled {{ color: {t['muted']}; }}
QComboBox {{ min-height: 20px; padding-right: 24px; }}
QComboBox::drop-down {{ width: 22px; border: none; }}
QComboBox QLineEdit {{ border: none; background: transparent; padding: 0; }}
QComboBox QAbstractItemView {{
    background: {t['surface']}; border: 1px solid {t['border']};
    selection-background-color: {t['selection']}; selection-color: {t['text']};
}}
QTabWidget::pane {{ border: none; padding-top: 8px; }}
QTabBar::tab {{
    background: transparent; color: {t['muted']}; padding: 8px 14px;
    border: none; border-radius: 8px; margin-right: 5px; font-size: 12px;
}}
QTabBar::tab:selected {{ color: {t['accent']}; background: {t['selection']}; font-weight: 600; }}
QTabBar::tab:hover {{ background: {t['hover']}; }}
QTabWidget#configTabs::pane {{ border-top: 1px solid {t['border']}; padding-top: 6px; }}
QListWidget, QTreeWidget, QTableWidget {{
    background: {t['surface']}; alternate-background-color: {t['input']};
    border: 1px solid {t['border']}; border-radius: 9px;
    gridline-color: {t['border']}; selection-background-color: {t['selection']};
    selection-color: {t['text']}; outline: none;
}}
QListWidget#accountList {{ border: none; background: transparent; }}
QListWidget#accountList::item {{ padding: 0; margin: 0; background: transparent; border: none; }}
QListWidget#taskList {{ border: none; }}
QListWidget::item {{ padding: 14px 12px; border: 1px solid {t['border']}; border-radius: 9px; margin: 3px 0; }}
QListWidget::item:selected {{ background: {t['selection']}; color: {t['text']}; border-color: {t['hero_border']}; }}
QListWidget::item:hover {{ background: {t['hover']}; }}
QHeaderView::section {{
    background: {t['input']}; color: {t['muted']}; border: none;
    border-bottom: 1px solid {t['border']}; padding: 10px; font-weight: 500;
}}
QTableWidget::item, QTreeWidget::item {{ padding: 6px; }}
QCheckBox {{ spacing: 8px; padding: 4px 0; }}
QCheckBox:disabled {{ color: {t['muted']}; }}
QGroupBox {{ border: 1px solid {t['border']}; border-radius: 9px; margin-top: 13px; padding-top: 10px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 5px; color: {t['accent']}; }}
QScrollArea, QScrollArea#overviewScroll, QWidget#overviewContent {{ border: none; background: transparent; }}
QSplitter::handle {{ background: transparent; width: 16px; height: 12px; }}
QSplitter::handle:hover {{ background: {t['border']}; }}
QPlainTextEdit#logView, QPlainTextEdit#jsonView, QPlainTextEdit#jsonEditor {{ font-family: "{MONO_FAMILY}"; }}
QMenuBar, QMenu {{ background: {t['surface']}; }}
QStatusBar {{ background: {t['background']}; color: {t['muted']}; font-size: 10px; }}
QStatusBar::item {{ border: none; }}
QMenuBar::item:selected, QMenu::item:selected {{ background: {t['selection']}; }}
QMenu::item {{ padding: 9px 26px; }}
QToolTip {{ color: {t['text']}; background: {t['surface']}; border: 1px solid {t['border']}; padding: 7px; }}
QScrollBar:vertical {{ background: transparent; width: 8px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {t['border']}; border-radius: 3px; min-height: 28px; }}
QScrollBar::handle:vertical:hover {{ background: {t['muted']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
"""
