"""纯展示组件：矢量图标、可换行工具栏、卡片和空状态，不接触业务数据。"""

from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, QPointF, QRect, QRectF, QSize, Qt
from PySide6.QtGui import QColor, QIcon, QIconEngine, QPainter, QPainterPath, QPalette, QPen, QPixmap
from PySide6.QtWidgets import (
    QApplication, QDialog, QFormLayout, QFrame, QLabel, QLayout, QSizePolicy,
    QStackedWidget, QVBoxLayout,
)


class _LineIcon(QIconEngine):
    """在目标尺寸绘制，避免字体符号在不同缩放和机器上缺失。"""

    def __init__(self, name: str, color: str | None, active_color: str | None):
        super().__init__()
        self.name, self.color, self.active_color = name, color, active_color

    def clone(self):
        return _LineIcon(self.name, self.color, self.active_color)

    def pixmap(self, size, mode, state):
        image = QPixmap(size)
        image.fill(Qt.GlobalColor.transparent)
        painter = QPainter(image)
        self.paint(painter, QRect(0, 0, size.width(), size.height()), mode, state)
        painter.end()
        return image

    def paint(self, painter, rect, mode, state):
        palette = QApplication.palette()
        color = self.active_color if state == QIcon.State.On and self.active_color else self.color
        ink = QColor(color) if color else palette.color(QPalette.ColorRole.WindowText)
        if mode == QIcon.Mode.Disabled:
            ink.setAlpha(95)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        edge = min(rect.width(), rect.height())
        painter.translate(rect.x() + (rect.width() - edge) / 2, rect.y() + (rect.height() - edge) / 2)
        painter.scale(edge / 24, edge / 24)
        painter.setPen(QPen(ink, 1.7, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.setBrush(Qt.BrushStyle.NoBrush)

        def line(*points):
            path = QPainterPath(QPointF(*points[0]))
            for point in points[1:]:
                path.lineTo(QPointF(*point))
            painter.drawPath(path)

        def box(x, y, w, h, radius=2):
            painter.drawRoundedRect(QRectF(x, y, w, h), radius, radius)

        match self.name:
            case "accounts":
                painter.drawEllipse(QRectF(8, 3, 8, 8))
                path = QPainterPath(QPointF(4, 21))
                path.cubicTo(4, 11, 20, 11, 20, 21)
                painter.drawPath(path)
            case "run":
                line((8, 4), (20, 12), (8, 20), (8, 4))
            case "network" | "graph":
                box(9, 3, 6, 5, 1)
                box(2, 16, 6, 5, 1)
                box(16, 16, 6, 5, 1)
                line((12, 8), (12, 12), (5, 12), (5, 16))
                line((12, 12), (19, 12), (19, 16))
            case "key":
                painter.drawEllipse(QRectF(3, 3, 10, 10))
                line((12, 12), (21, 21), (21, 16))
                line((17, 17), (20, 14))
            case "templates":
                for x, y in ((3, 3), (14, 3), (3, 14), (14, 14)):
                    box(x, y, 7, 7, 1.5)
            case "sun":
                painter.drawEllipse(QRectF(8, 8, 8, 8))
                for a, b in (((12, 2), (12, 4)), ((12, 20), (12, 22)), ((2, 12), (4, 12)),
                             ((20, 12), (22, 12)), ((5, 5), (6.5, 6.5)), ((17.5, 17.5), (19, 19)),
                             ((5, 19), (6.5, 17.5)), ((17.5, 6.5), (19, 5))):
                    line(a, b)
            case "moon":
                path = QPainterPath(QPointF(20, 14))
                path.cubicTo(13, 16, 7, 10, 10, 3)
                path.cubicTo(-2, 6, 4, 26, 16, 20)
                path.cubicTo(18, 19, 20, 16, 20, 14)
                painter.drawPath(path)
            case "more":
                painter.setBrush(ink)
                for x in (5, 12, 19):
                    painter.drawEllipse(QRectF(x - 1, 11, 2, 2))
            case "plus":
                line((12, 5), (12, 19))
                line((5, 12), (19, 12))
            case "search":
                painter.drawEllipse(QRectF(3, 3, 13, 13))
                line((15, 15), (21, 21))
            case "check":
                line((5, 12), (10, 17), (20, 6))
            case "close":
                line((6, 6), (18, 18))
                line((6, 18), (18, 6))
            case "refresh":
                painter.drawArc(QRectF(4, 4, 16, 16), 40 * 16, 290 * 16)
                line((20, 4), (20, 10), (14, 10))
            case "save":
                line((5, 3), (17, 3), (21, 7), (21, 21), (3, 21), (3, 3), (5, 3))
                box(7, 3, 9, 6, 0.5)
                box(7, 14, 10, 7, 0.5)
            case "download":
                line((12, 3), (12, 15))
                line((7, 10), (12, 15), (17, 10))
                line((4, 16), (4, 21), (20, 21), (20, 16))
            case "copy":
                box(8, 8, 13, 13)
                line((16, 5), (16, 3), (3, 3), (3, 16), (5, 16))
            case "info":
                painter.drawEllipse(QRectF(3, 3, 18, 18))
                line((12, 11), (12, 17))
                painter.drawPoint(QPointF(12, 7))
            case "settings":
                for y, x in ((5, 8), (12, 16), (19, 8)):
                    line((3, y), (x - 2, y))
                    line((x + 2, y), (21, y))
                    painter.drawEllipse(QRectF(x - 2, y - 2, 4, 4))
            case "file":
                line((14, 3), (5, 3), (5, 21), (19, 21), (19, 8), (14, 3), (14, 8), (19, 8))
                line((9, 13), (15, 13))
                line((9, 17), (15, 17))
            case "shield":
                path = QPainterPath(QPointF(12, 2))
                path.lineTo(21, 6)
                path.cubicTo(21, 15, 17, 20, 12, 22)
                path.cubicTo(7, 20, 3, 15, 3, 6)
                path.closeSubpath()
                painter.drawPath(path)
                line((8, 12), (11, 15), (16, 9))
            case "activity":
                line((2, 12), (6, 12), (9, 5), (14, 20), (17, 12), (22, 12))
            case "list":
                for y in (5, 12, 19):
                    painter.drawPoint(QPointF(3, y))
                    line((8, y), (21, y))
            case "code":
                line((7, 6), (2, 12), (7, 18))
                line((17, 6), (22, 12), (17, 18))
                line((14, 3), (10, 21))
            case "chevron-right":
                line((9, 5), (16, 12), (9, 19))
            case "arrow-left":
                line((11, 5), (4, 12), (11, 19))
                line((4, 12), (21, 12))
            case _:
                box(4, 4, 16, 16, 4)
                line((8, 12), (11, 15), (16, 9))
        painter.restore()


def icon(name: str, color: str | None = None, active_color: str | None = None) -> QIcon:
    return QIcon(_LineIcon(name, color, active_color))


class FlowLayout(QLayout):
    """操作保持自然宽度，空间不足时换行；不改变按钮顺序和键盘行为。"""

    def __init__(self, parent=None, *, spacing=8, margins=(0, 0, 0, 0)):
        super().__init__(parent)
        self._items = []
        self.setContentsMargins(*margins)
        self.setSpacing(spacing)

    def addItem(self, item):  # noqa: N802
        self._items.append(item)

    def count(self):
        return len(self._items)

    def itemAt(self, index):  # noqa: N802
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index):  # noqa: N802
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):  # noqa: N802
        return Qt.Orientation(0)

    def hasHeightForWidth(self):  # noqa: N802
        return True

    def heightForWidth(self, width):  # noqa: N802
        return self._arrange(QRect(0, 0, width, 0), False)

    def setGeometry(self, rect):  # noqa: N802
        super().setGeometry(rect)
        self._arrange(rect, True)

    def sizeHint(self):  # noqa: N802
        return self.minimumSize()

    def minimumSize(self):  # noqa: N802
        size = QSize()
        for item in self._items:
            if not item.isEmpty():
                size = size.expandedTo(item.minimumSize())
        left, top, right, bottom = self.getContentsMargins()
        return size + QSize(left + right, top + bottom)

    def _arrange(self, rect, apply):
        left, top, right, bottom = self.getContentsMargins()
        area = rect.adjusted(left, top, -right, -bottom)
        x, y, height = area.x(), area.y(), 0
        for item in self._items:
            if item.isEmpty():
                continue
            size = item.sizeHint()
            if height and x + size.width() > area.right() + 1:
                x, y, height = area.x(), y + height + self.spacing(), 0
            if apply:
                item.setGeometry(QRect(x, y, min(size.width(), max(0, area.width())), size.height()))
            x += size.width() + self.spacing()
            height = max(height, size.height())
        return y + height - rect.y() + bottom


class SectionCard(QFrame):
    def __init__(self, title: str = "", description: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("surfaceCard")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(20, 18, 20, 18)
        self.body.setSpacing(12)
        for text, name in ((title, "sectionTitle"), (description, "hint")):
            if text:
                label = QLabel(text)
                label.setTextFormat(Qt.TextFormat.PlainText)
                label.setWordWrap(True)
                label.setObjectName(name)
                self.body.addWidget(label)


class EmptyState(QFrame):
    def __init__(self, title: str, description: str, symbol: str = "list", parent=None):
        super().__init__(parent)
        self.setObjectName("emptyState")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.symbol = symbol
        column = QVBoxLayout(self)
        column.setContentsMargins(24, 28, 24, 28)
        column.setSpacing(10)
        self.mark = QLabel()
        self.mark.setObjectName("emptyMark")
        self.mark.setFixedSize(48, 48)
        self.mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        column.addWidget(self.mark, 0, Qt.AlignmentFlag.AlignHCenter)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("emptyTitle")
        self.description_label = QLabel(description)
        self.description_label.setObjectName("hint")
        for label in (self.title_label, self.description_label):
            label.setTextFormat(Qt.TextFormat.PlainText)
            label.setWordWrap(True)
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            column.addWidget(label)
        self._refresh_icon()

    def _refresh_icon(self):
        self.mark.setPixmap(icon(self.symbol, self.palette().color(QPalette.ColorRole.Highlight).name()).pixmap(26, 26))

    def changeEvent(self, event):  # noqa: N802
        super().changeEvent(event)
        if event.type() == QEvent.Type.PaletteChange and hasattr(self, "mark"):
            self._refresh_icon()


class _TablePlaceholder(QObject):
    def __init__(self, table, title, description, symbol):
        super().__init__(table)
        self.table = table
        self.panel = EmptyState(title, description, symbol, table.viewport())
        self.panel.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        table.viewport().installEventFilter(self)
        for signal in (table.model().rowsInserted, table.model().rowsRemoved, table.model().modelReset):
            signal.connect(self.sync)
        self.sync()

    def sync(self, *_args):
        viewport = self.table.viewport()
        height = min(self.panel.sizeHint().height(), viewport.height())
        self.panel.setGeometry(0, max(0, (viewport.height() - height) // 2), viewport.width(), height)
        self.panel.setVisible(self.table.rowCount() == 0)

    def eventFilter(self, watched, event):  # noqa: N802
        if event.type() in (QEvent.Type.Resize, QEvent.Type.Show):
            self.sync()
        return super().eventFilter(watched, event)


def table_placeholder(table, title: str, description: str, symbol: str = "list") -> EmptyState:
    overlay = _TablePlaceholder(table, title, description, symbol)
    table._placeholder = overlay
    return overlay.panel


def configure_form(form: QFormLayout) -> QFormLayout:
    form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
    form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
    form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    form.setFormAlignment(Qt.AlignmentFlag.AlignTop)
    form.setHorizontalSpacing(18)
    form.setVerticalSpacing(14)
    return form


def fit_dialog(dialog: QDialog, width: int, height: int, minimum: tuple[int, int] = (480, 360)) -> None:
    """按逻辑像素和当前屏幕可用区域约束弹窗，底部操作不会落到任务栏外。"""
    screen = dialog.screen() or QApplication.primaryScreen()
    available = screen.availableGeometry().size() - QSize(48, 64) if screen else QSize(width, height)
    available = available.expandedTo(QSize(320, 240))
    dialog.setMinimumSize(min(minimum[0], available.width()), min(minimum[1], available.height()))
    dialog.resize(min(width, available.width()), min(height, available.height()))


class ElidedLabel(QLabel):
    """保留完整文本和提示，但在紧凑布局中用省略号而不是直接裁切。"""

    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setMinimumWidth(0)
        self.setToolTip(text)

    def setText(self, text):  # noqa: N802
        super().setText(text)
        self.setToolTip(text)

    def paintEvent(self, event):  # noqa: N802
        painter = QPainter(self)
        painter.setFont(self.font())
        painter.setPen(self.palette().color(QPalette.ColorRole.WindowText))
        text = self.fontMetrics().elidedText(self.text(), Qt.TextElideMode.ElideRight, self.contentsRect().width())
        painter.drawText(self.contentsRect(), self.alignment(), text)


class FlexibleStack(QStackedWidget):
    """隐藏页面不挤大整个窗口；页面内部负责自身滚动和换行。"""

    def minimumSizeHint(self):  # noqa: N802
        return QSize(0, 0)

    def sizeHint(self):  # noqa: N802
        return self.currentWidget().sizeHint() if self.currentWidget() else QSize(640, 480)
