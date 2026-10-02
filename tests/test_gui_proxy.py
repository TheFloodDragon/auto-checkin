"""代理 GUI 的无窗口契约测试。"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication

from gui.proxy_import_dialog import ProxySourceDialog, SubscriptionContentDialog
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



    def test_subscription_content_dialog_reparses_and_saves_local_text(app, tmp_path):
        target = tmp_path / "edited.txt"
        dialog = SubscriptionContentDialog(
            "http://node.example.invalid:8080#旧\n",
            source_id="source-edit",
            source_label="本地文件",
            source_path=str(target),
            format="uri",
        )
        dialog.editor.setPlainText("http://node.example.invalid:8080#新\n")
        result = dialog.parse()
        assert result is not None and result.nodes[0]["name"] == "新"
        dialog.save()
        assert target.read_text(encoding="utf-8") == "http://node.example.invalid:8080#新\n"
        dialog.deleteLater()
