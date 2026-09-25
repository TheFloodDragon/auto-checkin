"""工作流画布：拖动只移动坐标，端口连线由外部草稿模型校验和提交。

同时用于访问链（失败回退虚线）与任务依赖（成功实线）。不保存配置、不执行任务。
"""
from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import (
    QColor, QFont, QPainter, QPainterPath, QPainterPathStroker, QPen, QPolygonF,
)
from PySide6.QtWidgets import QGraphicsItem, QGraphicsObject, QGraphicsPathItem, QGraphicsScene, QGraphicsView

from . import theme

KIND_MIME = "application/x-dailytask-step"
NODE_WIDTH = 228
NODE_HEIGHT = 132
STATE_LABELS = {
    "running": "运行中", "success": "成功", "already_done": "已完成", "failed": "失败",
    "no_effect": "无影响", "unavailable": "不可用", "not_run": "未执行", "queued": "等待中",
    "cancelled": "已取消", "blocked": "已阻断",
}


def font(size: int, *, bold: bool = False) -> QFont:
    value = QFont(theme.FONT_FAMILY)
    value.setPixelSize(size)
    value.setBold(bold)
    return value


class GraphNode(QGraphicsObject):
    def __init__(self, view: "GraphCanvas", data: dict):
        super().__init__()
        self.view = view
        self.data = data
        self.key = data["id"]
        self.hovered = False
        flags = QGraphicsItem.GraphicsItemFlag.ItemIsSelectable | QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges
        if not view.read_only:
            flags |= QGraphicsItem.GraphicsItemFlag.ItemIsMovable
        self.setFlags(flags)
        self.setAcceptHoverEvents(True)
        self.setZValue(2)
        self.setToolTip(str(data.get("tooltip") or data.get("title") or self.key))

    def boundingRect(self) -> QRectF:
        return QRectF(-10, -6, NODE_WIDTH + 20, NODE_HEIGHT + 18)

    def shape(self) -> QPainterPath:
        path = QPainterPath()
        path.addRoundedRect(QRectF(0, 0, NODE_WIDTH, NODE_HEIGHT), 12, 12)
        path.addEllipse(self.input_pos(), 10, 10)
        path.addEllipse(self.output_pos(), 10, 10)
        return path

    def input_pos(self) -> QPointF:
        return QPointF(0, NODE_HEIGHT / 2)

    def output_pos(self) -> QPointF:
        return QPointF(NODE_WIDTH, NODE_HEIGHT / 2)

    def itemChange(self, change, value):
        result = super().itemChange(change, value)
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            self.view.update_edges(self.key)
        return result

    def hoverEnterEvent(self, event):
        self.hovered = True
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self.hovered = False
        self.update()
        super().hoverLeaveEvent(event)

    def paint(self, painter, option, widget=None):
        t = self.view.tokens
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        area = QRectF(0, 0, NODE_WIDTH, NODE_HEIGHT)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(0, 0, 0, 15))
        painter.drawRoundedRect(area.translated(0, 4), 12, 12)
        state = self.data.get("state", "")
        tone = "danger" if state in {"failed", "blocked"} else "success" if state in {
            "success", "already_done",
        } else "accent" if state == "running" else "border"
        border = t["accent"] if self.isSelected() or self.hovered else t[tone]
        painter.setPen(QPen(QColor(border), 2 if self.isSelected() or state == "running" else 1))
        painter.setBrush(QColor(t["surface"]))
        painter.drawRoundedRect(area, 12, 12)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(t["selection"] if self.data.get("kind") == "http" else t["raised"]))
        painter.drawRoundedRect(QRectF(14, 13, 31, 26), 6, 6)
        painter.setPen(QColor(t["accent"]))
        painter.setFont(font(12, bold=True))
        symbol = {"http": "H", "browser": "B", "task": "T"}.get(self.data.get("kind"), "T")
        painter.drawText(QRectF(14, 13, 31, 26), Qt.AlignmentFlag.AlignCenter, symbol)
        painter.setFont(font(11))
        painter.setPen(QColor(t["muted"]))
        tag = self.data.get("kind_title") or {"http": "HTTP", "browser": "浏览器", "task": "业务任务"}.get(
            self.data.get("kind"), "步骤",
        )
        painter.drawText(QRectF(54, 16, 100, 22), Qt.AlignmentFlag.AlignVCenter, str(tag))
        index = str(self.data.get("index", "—"))
        if self.data.get("entry"):
            index = f"入口 · {index}"
        painter.setFont(font(11, bold=True))
        painter.setPen(QColor(t["accent"] if self.data.get("entry") else t["muted"]))
        painter.drawText(QRectF(147, 15, 65, 24), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, index)
        painter.setFont(font(14, bold=True))
        painter.setPen(QColor(t["text"]))
        title = painter.fontMetrics().elidedText(str(self.data.get("title") or self.key), Qt.TextElideMode.ElideRight, 195)
        painter.drawText(QRectF(16, 47, 197, 24), Qt.AlignmentFlag.AlignVCenter, title)
        painter.setFont(font(11))
        painter.setPen(QColor(t["muted"]))
        sub = painter.fontMetrics().elidedText(str(self.data.get("subtitle") or self.key), Qt.TextElideMode.ElideRight, 197)
        painter.drawText(QRectF(16, 74, 197, 21), Qt.AlignmentFlag.AlignVCenter, sub)
        painter.setPen(QPen(QColor(t["border"]), 1))
        painter.drawLine(QPointF(15, 101), QPointF(NODE_WIDTH - 15, 101))
        painter.setFont(font(10))
        painter.setPen(QColor(t[tone] if tone != "border" else t["muted"]))
        footer = STATE_LABELS.get(state) or ("不在执行路径" if self.data.get("unreachable") else self.data.get("footer", "成功即结束"))
        painter.drawText(QRectF(16, 106, 145, 18), Qt.AlignmentFlag.AlignVCenter, str(footer))
        painter.setPen(QColor(t["warning"] if self.view.relation == "failure" else t["accent"]))
        painter.drawText(QRectF(164, 106, 48, 18), Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                         "失败时" if self.view.relation == "failure" else "成功后")
        for point, color in ((self.input_pos(), t["muted"]), (self.output_pos(), self.view.edge_color)):
            painter.setPen(QPen(QColor(color), 2))
            painter.setBrush(QColor(t["surface"]))
            painter.drawEllipse(point, 6, 6)


class GraphEdge(QGraphicsPathItem):
    def __init__(self, view: "GraphCanvas", source: str, target: str, active: bool = False):
        super().__init__()
        self.view = view
        self.source, self.target = source, target
        self.active = active
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setZValue(0)
        self.setToolTip("失败后回退；拖动箭头端点可重新连接" if view.relation == "failure" else "前置任务成功或已完成后执行")
        self.update_path()

    def update_path(self):
        source = self.view.nodes.get(self.source)
        target = self.view.nodes.get(self.target)
        if source is None or target is None:
            return
        start = source.mapToScene(source.output_pos())
        end = target.mapToScene(target.input_pos())
        distance = max(65, min(200, abs(end.x() - start.x()) * 0.5))
        path = QPainterPath(start)
        path.cubicTo(start + QPointF(distance, 0), end - QPointF(distance, 0), end)
        self.setPath(path)

    def shape(self):
        stroke = QPainterPathStroker()
        stroke.setWidth(18)
        return stroke.createStroke(self.path())

    def boundingRect(self):
        return super().boundingRect().adjusted(-32, -20, 32, 20)

    def paint(self, painter, option, widget=None):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = QColor(self.view.tokens["accent"] if self.isSelected() else self.view.edge_color)
        pen = QPen(color, 2.5 if self.isSelected() or self.active else 1.5)
        if self.view.relation == "failure" and not self.active:
            pen.setStyle(Qt.PenStyle.DashLine)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(self.path())
        end = self.path().pointAtPercent(1)
        before = self.path().pointAtPercent(0.98)
        angle = math.atan2(end.y() - before.y(), end.x() - before.x())
        corners = [end, end - QPointF(10 * math.cos(angle - 0.45), 10 * math.sin(angle - 0.45)),
                   end - QPointF(10 * math.cos(angle + 0.45), 10 * math.sin(angle + 0.45))]
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        painter.drawPolygon(QPolygonF(corners))
        midpoint = self.path().pointAtPercent(0.5)
        area = QRectF(midpoint.x() - 32, midpoint.y() - 11, 64, 22)
        painter.setBrush(QColor(self.view.tokens["background"]))
        painter.drawRoundedRect(area, 5, 5)
        painter.setFont(font(10))
        painter.setPen(color)
        painter.drawText(area, Qt.AlignmentFlag.AlignCenter, "失败回退" if self.view.relation == "failure" else "成功依赖")
        if self.isSelected():
            painter.setBrush(QColor(self.view.tokens["surface"]))
            painter.setPen(QPen(color, 2))
            painter.drawEllipse(end, 8, 8)


class GraphCanvas(QGraphicsView):
    selection_changed = Signal(object, object)
    positions_changed = Signal(object)
    connection_requested = Signal(str, str)
    delete_requested = Signal(object, object)
    node_activated = Signal(str)
    kind_dropped = Signal(str, object, str)

    def __init__(self, parent=None, *, relation="failure", theme_name=None, read_only=False):
        super().__init__(parent)
        self.relation = relation
        self.read_only = read_only
        self.tokens = theme.tokens(theme_name or theme.load_theme())
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self._loading = False
        self._drag_positions = None
        self._connecting = ""
        self._preview = None
        self._pan = False
        scene = QGraphicsScene(self)
        self.setScene(scene)
        scene.selectionChanged.connect(self._selected)
        self.setObjectName("chainCanvas")
        self.setAccessibleName("失败回退流程画布" if relation == "failure" else "任务成功依赖画布")
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.BoundingRectViewportUpdate)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setDragMode(QGraphicsView.DragMode.RubberBandDrag)
        self.setAcceptDrops(not read_only)
        self.setMinimumSize(250, 220)
        self.setStyleSheet(f"QGraphicsView {{background:{self.tokens['background']}; border:0; border-radius:10px;}}")

    @property
    def edge_color(self) -> str:
        return self.tokens["warning" if self.relation == "failure" else "accent"]

    def load_graph(self, nodes: list[dict], edges: list[dict], positions: dict | None = None, selected: str = ""):
        self._loading = True
        self.cancel_connection()
        self.edges.clear()
        self.nodes.clear()
        self.scene().clear()
        positions = positions or {}
        for index, data in enumerate(nodes):
            if not data.get("id") or data["id"] in self.nodes:
                continue
            item = GraphNode(self, data)
            self.nodes[item.key] = item
            self.scene().addItem(item)
            xy = positions.get(item.key, [index * 320, 0])
            item.setPos(float(xy[0]), float(xy[1]))
            item.setSelected(item.key == selected)
        for data in edges:
            if data["source"] in self.nodes and data["target"] in self.nodes:
                item = GraphEdge(self, data["source"], data["target"], data.get("active", False))
                self.edges.append(item)
                self.scene().addItem(item)
        self.scene().setSceneRect(self.scene().itemsBoundingRect().adjusted(-140, -140, 140, 140))
        self._loading = False

    def select_node(self, key: str, *, center=False):
        self.scene().clearSelection()
        item = self.nodes.get(key)
        if item is not None:
            item.setSelected(True)
            if center:
                self.centerOn(item)

    def selected(self) -> tuple[list[str], list[tuple[str, str]]]:
        items = self.scene().selectedItems()
        return ([item.key for item in items if isinstance(item, GraphNode)],
                [(item.source, item.target) for item in items if isinstance(item, GraphEdge)])

    def _selected(self):
        if not self._loading:
            self.selection_changed.emit(*self.selected())

    def update_edges(self, key: str):
        for edge in self.edges:
            if key in (edge.source, edge.target):
                edge.update_path()

    def fit_graph(self):
        if self.nodes:
            rect = self.scene().itemsBoundingRect().adjusted(-40, -40, 40, 40)
            self.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)
            if self.transform().m11() > 1.15:
                self.resetTransform()
                self.centerOn(rect.center())

    def zoom(self, scale: float):
        target = self.transform().m11() * scale
        if 0.2 <= target <= 2.5:
            self.scale(scale, scale)

    def drawBackground(self, painter, rect):
        painter.fillRect(rect, QColor(self.tokens["background"]))
        if self.transform().m11() < 0.35:
            return
        painter.setPen(QPen(QColor(self.tokens["border"]), 1.5))
        left = math.floor(rect.left() / 24) * 24
        top = math.floor(rect.top() / 24) * 24
        for x in range(left, int(rect.right()) + 24, 24):
            for y in range(top, int(rect.bottom()) + 24, 24):
                painter.drawPoint(QPointF(x, y))

    def cancel_connection(self):
        if self._preview is not None:
            self.scene().removeItem(self._preview)
            self._preview = None
        self._connecting = ""

    def _begin_connection(self, key: str):
        self.cancel_connection()
        self._connecting = key
        self._preview = QGraphicsPathItem()
        self._preview.setPen(QPen(QColor(self.edge_color), 2, Qt.PenStyle.DashLine))
        self._preview.setZValue(-1)
        self.scene().addItem(self._preview)

    def mousePressEvent(self, event):
        point = self.mapToScene(event.position().toPoint())
        if event.button() == Qt.MouseButton.MiddleButton:
            self._pan = True
            self._pan_point = event.position()
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
            event.accept()
            return
        if not self.read_only and event.button() == Qt.MouseButton.LeftButton:
            for key, node in self.nodes.items():
                if (node.mapToScene(node.output_pos()) - point).manhattanLength() < 22:
                    self._begin_connection(key)
                    event.accept()
                    return
            for edge in self.edges:
                if (edge.path().pointAtPercent(1) - point).manhattanLength() < 15:
                    self._begin_connection(edge.source)
                    event.accept()
                    return
            self._drag_positions = {key: [node.pos().x(), node.pos().y()] for key, node in self.nodes.items()}
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._pan:
            delta = event.position() - self._pan_point
            self._pan_point = event.position()
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() - int(delta.x()))
            self.verticalScrollBar().setValue(self.verticalScrollBar().value() - int(delta.y()))
            return
        if self._connecting:
            source = self.nodes.get(self._connecting)
            if source is not None:
                start = source.mapToScene(source.output_pos())
                end = self.mapToScene(event.position().toPoint())
                path = QPainterPath(start)
                path.cubicTo(start + QPointF(70, 0), end - QPointF(70, 0), end)
                self._preview.setPath(path)
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if self._pan:
            self._pan = False
            self.unsetCursor()
            return
        if self._connecting:
            point = self.mapToScene(event.position().toPoint())
            target = next((key for key, node in self.nodes.items() if node.shape().contains(node.mapFromScene(point))), "")
            source = self._connecting
            self.cancel_connection()
            if target:
                self.connection_requested.emit(source, target)
            return
        super().mouseReleaseEvent(event)
        if self._drag_positions is not None:
            values = {key: [node.pos().x(), node.pos().y()] for key, node in self.nodes.items()}
            previous = self._drag_positions
            self._drag_positions = None
            if previous != values:
                self.positions_changed.emit(values)

    def mouseDoubleClickEvent(self, event):
        item = self.itemAt(event.position().toPoint())
        if isinstance(item, GraphNode):
            self.node_activated.emit(item.key)
        super().mouseDoubleClickEvent(event)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.cancel_connection()
            self.scene().clearSelection()
            return
        if not self.read_only and event.key() in (Qt.Key.Key_Delete, Qt.Key.Key_Backspace):
            self.delete_requested.emit(*self.selected())
            return
        super().keyPressEvent(event)

    def wheelEvent(self, event):
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self.zoom(1.15 if event.angleDelta().y() > 0 else 1 / 1.15)
            event.accept()
        else:
            super().wheelEvent(event)

    def dragEnterEvent(self, event):
        if not self.read_only and event.mimeData().hasFormat(KIND_MIME):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        self.dragEnterEvent(event)

    def dropEvent(self, event):
        if self.read_only or not event.mimeData().hasFormat(KIND_MIME):
            event.ignore()
            return
        kind = bytes(event.mimeData().data(KIND_MIME)).decode("ascii", errors="ignore")
        point = self.mapToScene(event.position().toPoint())
        item = self.itemAt(event.position().toPoint())
        after = item.source if isinstance(item, GraphEdge) else ""
        self.kind_dropped.emit(kind, [point.x(), point.y()], after)
        event.acceptProposedAction()
