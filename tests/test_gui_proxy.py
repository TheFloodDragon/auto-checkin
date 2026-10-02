"""代理 GUI 的无窗口契约测试。"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication

from gui.proxy_import_dialog import ProxySourceDialog
from gui.proxy_widgets import ProxyNodeDialog


@pytest.fixture(scope="module")
def app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    return QApplication.instance() or QApplication([])


def test_source_dialog_returns_subscription_binding(app):
    dialog = ProxySourceDialog([])
    dialog.source.setText("https://feed.example.invalid/sub?token=private")
    values = dialog.value()
    assert values["kind"] == "url"
    assert values["bind_subscription"] is True
    assert values["target_group"] == ""


def test_node_dialog_accepts_bridged_link_without_showing_secret(app):
    dialog = ProxyNodeDialog()
    dialog.name_field.setText("桥接节点")
    dialog.url_input.setText(
        "vless://11111111-1111-1111-1111-111111111111@edge.example.invalid:443?security=tls#VLESS"
    )
    dialog.import_url()
    value = dialog.value()
    assert value["clash"]["type"] == "vless"
    assert "11111111" not in dialog.bridge_summary.text()
    assert "mihomo" in dialog.bridge_summary.text()
