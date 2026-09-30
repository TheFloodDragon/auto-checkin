"""导入预览只展示安全摘要，不保存或执行账号。"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QLabel

from gui.import_dialog import ImportPreviewDialog


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def test_import_preview_never_exposes_credentials_or_url_userinfo(qapp):
    secret = "IMPORT-PREVIEW-SECRET"
    dialog = ImportPreviewDialog([{
        "id": "site", "name": "站点 " + secret,
        "base_url": "https://user:password@site.invalid/path?token=" + secret,
        "template": "newapi", "login": {"method": "access_token"},
        "credentials": {"access_token": secret}, "tasks": [{"id": "daily"}],
        "collected_info": {"warnings": ["请核对 " + secret], "requires_review": True},
    }])
    try:
        texts = [label.text() for label in dialog.findChildren(QLabel)]
        texts.append(dialog.notices.toPlainText())
        for row in range(dialog.table.rowCount()):
            for column in range(dialog.table.columnCount()):
                item = dialog.table.item(row, column)
                texts.extend([item.text(), item.toolTip()])
                assert item.data(Qt.ItemDataRole.UserRole) is None
        output = "\n".join(texts)
        assert secret not in output and "password" not in output
        assert dialog.table.item(0, 2).text() == "site.invalid"
        assert all(label.textFormat() == Qt.TextFormat.PlainText for label in dialog.findChildren(QLabel))
        dialog.reject()
        assert dialog.result() == QDialog.DialogCode.Rejected
    finally:
        dialog.close()
        dialog.deleteLater()
        qapp.processEvents()


def test_preview_missing_credentials_is_explicit_and_does_not_auto_accept(qapp):
    dialog = ImportPreviewDialog([{
        "id": "preview", "base_url": "https://preview.invalid", "template": "newapi",
        "enabled": False, "tasks": [{"id": "daily", "enabled": False}],
        "collected_info": {"export_kind": "preview", "requires_review": True},
    }])
    try:
        assert "未携带可用凭据" in dialog.notices.toPlainText()
        assert "autoCheckinCollector.copy()" in dialog.notices.toPlainText()
        assert "停用" in dialog.table.item(0, 5).text()
        assert dialog.result() == QDialog.DialogCode.Rejected
        assert dialog.buttons.button(QDialogButtonBox.StandardButton.Ok).text() == "导入到草稿"
        dialog.resize(560, 340)
        dialog.show()
        qapp.processEvents()
        assert dialog.buttons.geometry().bottom() <= dialog.height()
    finally:
        dialog.close()
        dialog.deleteLater()
        qapp.processEvents()


def test_empty_import_preview_has_no_enabled_confirm_button(qapp):
    dialog = ImportPreviewDialog([])
    try:
        assert not dialog.buttons.button(QDialogButtonBox.StandardButton.Ok).isEnabled()
    finally:
        dialog.close()
        dialog.deleteLater()
        qapp.processEvents()
