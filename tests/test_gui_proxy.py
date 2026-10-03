"""代理 GUI 的无窗口契约测试。"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import replace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QWidget

from config.subscriptions import (
    BRIDGED_SCHEMES, SourceSpec, SubscriptionImporter, merge_proxy_import,
    parse_subscription_text, subscription_update_summary,
)
from core.errors import ConfigError
from gui.proxy_import_dialog import (
    ProxyImportPreviewDialog, ProxySourceDialog, ProxySourceInput, SubscriptionContentDialog,
)
from gui.proxy_widgets import ProxyNodeDialog


@pytest.fixture(scope="module")
def app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    return QApplication.instance() or QApplication([])


CLASH_TEXT = """proxies:
  - {name: 香港, type: http, server: hk.example.invalid, port: 80}
  - {name: 美国, type: http, server: us.example.invalid, port: 80}
proxy-groups:
  - {name: 手动出口, type: select, proxies: [香港, DIRECT]}
"""


def _parse(text=CLASH_TEXT, **kwargs):
    return parse_subscription_text(
        text, source_id="source-preview", source_label="clash.yaml", **kwargs,
    )


def _ok(dialog):
    return dialog.buttons.button(QDialogButtonBox.StandardButton.Ok)


def test_source_dialog_returns_subscription_binding(app):
    dialog = ProxySourceDialog([])
    assert isinstance(dialog.input, ProxySourceInput)
    assert isinstance(dialog.input, QWidget)
    for name in ("kind", "source", "format", "bind_subscription", "content"):
        assert getattr(dialog, name) is getattr(dialog.input, name)
    assert dialog.kind.currentData() == "subscription_url"
    dialog.source.setText("https://feed.example.invalid/sub?token=private")
    values = dialog.value()
    assert values["kind"] == "url"
    assert values["bind_subscription"] is True
    assert values["target_group"] == ""
    dialog.bind_subscription.setChecked(False)
    assert dialog.value()["bind_subscription"] is False
    dialog.deleteLater()


def test_source_input_switches_all_modes_and_visibility(app):
    widget = ProxySourceInput()
    assert not widget.kind.isHidden()
    assert not widget.bind_subscription.isHidden()
    assert widget.content.isHidden()
    assert widget.browse_button.isHidden()
    assert widget.format.currentData() == "auto"
    widget.kind.setCurrentIndex(widget.kind.findData("file"))
    assert not widget.browse_button.isHidden()
    assert widget.edit_button.isHidden()
    assert widget.bind_subscription.isHidden()
    assert not widget.bind_subscription.isEnabled()
    widget.source.setText("C:/example/full.yaml")
    assert not widget.edit_button.isHidden()
    assert widget.value()["kind"] == "file"
    assert widget.value()["bind_subscription"] is False
    widget.kind.setCurrentIndex(widget.kind.findData("node_url"))
    assert widget.browse_button.isHidden()
    assert widget.edit_button.isHidden()
    assert widget.format.currentData() == "uri"
    assert not widget.format.isEnabled()
    widget.kind.setCurrentIndex(widget.kind.findData("text"))
    assert widget.source.isHidden() and widget.source_box.isHidden()
    assert not widget.content.isHidden()
    assert not widget.content_hint.isHidden()
    assert widget.format.currentData() == "auto" and widget.format.isEnabled()
    assert widget.bind_subscription.isHidden()
    widget.kind.setCurrentIndex(widget.kind.findData("subscription_url"))
    assert not widget.source.isHidden()
    assert widget.content.isHidden()
    assert not widget.bind_subscription.isHidden() and widget.bind_subscription.isEnabled()
    assert widget.format.currentData() == "auto"
    widget.deleteLater()


def test_source_dialog_target_changes_do_not_restore_hidden_binding(app):
    dialog = ProxySourceDialog([{"id": "office", "name": "办公室"}])
    dialog.group_name.setText("新组")
    dialog.target.setCurrentIndex(1)
    dialog.source.setText("https://feed.example.invalid/sub")
    assert dialog.value()["target_group"] == "office"
    assert dialog.value()["group_name"] == ""
    assert not dialog.group_name.isEnabled()
    dialog.kind.setCurrentIndex(dialog.kind.findData("text"))
    dialog.content.setPlainText(CLASH_TEXT)
    dialog.target.setCurrentIndex(0)
    assert dialog.bind_subscription.isHidden()
    assert dialog.group_name.isEnabled()
    assert dialog.value()["kind"] == "text"
    assert dialog.value()["bind_subscription"] is False
    dialog.deleteLater()


def test_source_input_pastes_complete_text_without_truncation(app):
    widget = ProxySourceInput()
    widget.kind.setCurrentIndex(widget.kind.findData("text"))
    text = "# " + "完整文件说明" * 12000 + "\n" + CLASH_TEXT + "\n"
    widget.content.setPlainText(text)
    assert widget.content.maximumBlockCount() == 0
    assert widget.content.minimumHeight() >= 200
    assert "完整" in widget.content_hint.text()
    assert widget.value() == {"kind": "text", "source": text, "format": "auto", "bind_subscription": False}
    values = widget.value()
    result = SubscriptionImporter().import_source(SourceSpec(kind=values["kind"], format=values["format"], source=values["source"]))
    assert [node["name"] for node in result.nodes] == ["香港", "美国"]
    assert result.source_kind == "text"
    widget.kind.setCurrentIndex(widget.kind.findData("subscription_url"))
    widget.kind.setCurrentIndex(widget.kind.findData("text"))
    assert widget.value()["source"] == text
    widget.deleteLater()


@pytest.mark.parametrize("kind, source", [
    ("subscription_url", ""),
    ("subscription_url", "https://alice:super-private@example.invalid/sub"),
    ("subscription_url", "https://feed.example.invalid:bad/sub?token=super-private"),
    ("subscription_url", "https://feed.example.invalid:0/sub"),
    ("subscription_url", "https://feed.example.invalid/#super-private"),
    ("subscription_url", "https://feed.example.invalid/sub?token=super-private\nother"),
    ("node_url", "vless://super-private@invalid:bad"),
    ("node_url", "wireguard://super-private@edge.example.invalid:443"),
    ("node_url", "http://alice:super-private@"),
    ("file", ""),
    ("file", "super-private\nfile.yaml"),
    ("text", " \n\t"),
])
def test_source_input_rejects_invalid_input_without_credentials(app, kind, source):
    dialog = ProxySourceDialog()
    dialog.kind.setCurrentIndex(dialog.kind.findData(kind))
    if kind == "text":
        dialog.content.setPlainText(source)
    else:
        dialog.source.setText(source)
    with pytest.raises(ConfigError) as error:
        dialog.value()
    assert "super-private" not in str(error.value)
    assert "alice" not in str(error.value)
    dialog.accept()
    assert QDialog.result(dialog) != QDialog.DialogCode.Accepted
    assert not dialog.error_label.isHidden()
    assert "super-private" not in dialog.error_label.text()
    dialog.deleteLater()


_BRIDGED_LINKS = {
    "vless": "vless://11111111-1111-1111-1111-111111111111@edge.example.invalid:443?security=tls#VLESS",
    "anytls": "anytls://private-password@edge.example.invalid:443#AnyTLS",
    "vmess": "vmess://" + base64.b64encode(json.dumps({
        "v": "2", "ps": "VMess", "add": "edge.example.invalid", "port": "443",
        "id": "11111111-1111-1111-1111-111111111111", "aid": "0", "net": "tcp", "tls": "tls",
    }).encode()).decode(),
    "trojan": "trojan://private-password@edge.example.invalid:443#Trojan",
    "ss": "ss://" + base64.b64encode(b"aes-128-gcm:private-password").decode() + "@edge.example.invalid:443#SS",
    "hysteria2": "hysteria2://private-password@edge.example.invalid:443#HY2",
    "hy2": "hy2://private-password@edge.example.invalid:443#HY2",
    "tuic": "tuic://11111111-1111-1111-1111-111111111111:private-password@edge.example.invalid:443#TUIC",
}


@pytest.mark.parametrize("scheme", sorted(BRIDGED_SCHEMES))
def test_source_input_supports_all_bridged_schemes(app, scheme):
    widget = ProxySourceInput()
    widget.kind.setCurrentIndex(widget.kind.findData("node_url"))
    widget.source.setText(_BRIDGED_LINKS[scheme])
    assert widget.value() == {
        "kind": "node", "source": _BRIDGED_LINKS[scheme], "format": "uri", "bind_subscription": False,
    }
    widget.deleteLater()


def test_source_file_picker_and_editor_use_edited_text(app, monkeypatch, tmp_path):
    path = tmp_path / "nodes.txt"
    path.write_text("http://old.example.invalid:8080#旧\n", encoding="utf-8")
    monkeypatch.setattr("gui.proxy_import_dialog.QFileDialog.getOpenFileName", lambda *a: (str(path), ""))
    widget = ProxySourceInput()
    widget.kind.setCurrentIndex(widget.kind.findData("file"))
    widget.browse_button.click()
    assert widget.source.text() == str(path)
    edited = "http://new.example.invalid:8080#新\n"

    def edit(dialog):
        dialog.editor.setPlainText(edited)
        dialog._accept_parsed()
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(SubscriptionContentDialog, "exec", edit)
    widget.edit_button.click()
    assert widget.kind.currentData() == "text"
    assert widget.value()["source"] == edited
    assert path.read_text(encoding="utf-8").startswith("http://old.")
    widget.deleteLater()


def test_node_dialog_accepts_bridged_link_without_showing_secret(app):
    dialog = ProxyNodeDialog()
    dialog.name_field.setText("桥接节点")
    dialog.url_input.setText(_BRIDGED_LINKS["vless"])
    dialog.import_url()
    value = dialog.value()
    assert value["clash"]["type"] == "vless"
    assert "11111111" not in dialog.bridge_summary.text()
    assert "mihomo" in dialog.bridge_summary.text()
    dialog.deleteLater()


def test_subscription_content_dialog_reparses_and_saves_local_text(app, tmp_path):
    target = tmp_path / "edited.txt"
    dialog = SubscriptionContentDialog(
        "http://node.example.invalid:8080#旧\n", source_id="source-edit",
        source_label="本地文件", source_path=str(target), format="uri",
    )
    dialog.editor.setPlainText("http://node.example.invalid:8080#新\n")
    result = dialog.parse()
    assert result is not None and result.nodes[0]["name"] == "新"
    dialog.save()
    assert target.read_text(encoding="utf-8") == "http://node.example.invalid:8080#新\n"
    dialog.deleteLater()


def test_subscription_content_invalid_parse_disables_accept_without_leaking(app):
    dialog = SubscriptionContentDialog("proxies: [password: private-password", format="clash_yaml")
    assert dialog.parse() is None
    assert not _ok(dialog).isEnabled()
    assert "private-password" not in dialog.error_label.text()
    dialog._accept_parsed()
    assert QDialog.result(dialog) != QDialog.DialogCode.Accepted
    dialog.editor.setPlainText("proxies: []")
    assert dialog.parse().nodes == ()
    assert not _ok(dialog).isEnabled()
    dialog._accept_parsed()
    assert QDialog.result(dialog) != QDialog.DialogCode.Accepted
    dialog.deleteLater()


def test_preview_defaults_to_all_nodes_with_complete_counts(app):
    result = _parse(CLASH_TEXT.replace("proxy-groups:", """  - {name: 香港, type: http, server: hk.example.invalid, port: 80}
  - {name: 不支持, type: wireguard, server: wg.example.invalid, port: 443}
proxy-groups:"""))
    dialog = ProxyImportPreviewDialog(result)
    assert dialog.policy_group.currentData() == ""
    assert [item["name"] for item in dialog._active_result.nodes] == ["香港", "美国"]
    assert len(result.candidates) == 4
    assert result.skipped_count == 1 and result.duplicate_count == 1
    for count in ("总数 4", "将导入 2", "跳过 1", "重复 1", "被筛选 0"):
        assert count in dialog.summary.text()
    assert dialog.table.rowCount() == 4
    dialog.policy_group.setCurrentIndex(1)
    for count in ("总数 4", "将导入 1", "跳过 1", "重复 1", "被筛选 1"):
        assert count in dialog.summary.text()
    assert dialog.table.rowCount() == 4
    assert dialog.table.item(1, 3).text() == "被筛选"
    dialog.policy_group.setCurrentIndex(0)
    assert dialog._active_result.nodes == result.nodes
    dialog.accept()
    assert dialog.result.nodes == result.nodes
    dialog.deleteLater()


def test_preview_can_limit_import_to_clash_select_group(app):
    result = _parse(format="clash_yaml")
    dialog = ProxyImportPreviewDialog(result)
    assert dialog.policy_group.count() == 2
    dialog.policy_group.setCurrentIndex(1)
    assert [item["name"] for item in dialog._active_result.nodes] == ["香港"]
    assert "递归" in dialog.scope_hint.text()
    dialog.deleteLater()


def test_preview_recursive_group_counts_and_selection_summary(app):
    text = CLASH_TEXT.replace("proxies: [香港, DIRECT]", "proxies: [自动出口, DIRECT]")
    text += "  - {name: 自动出口, type: url-test, proxies: [香港], url: https://example.invalid, interval: 300}\n"
    result = _parse(text)
    group = {"id": result.group_id, "proxies": list(result.nodes), "selected": result.nodes[1]["id"]}
    dialog = ProxyImportPreviewDialog(result, {"added": 999}, existing_group=group)
    assert dialog.update_summary["unchanged"] == 2
    dialog.policy_group.setCurrentIndex(1)
    assert [node["name"] for node in dialog._active_result.nodes] == ["香港"]
    assert "嵌套" in dialog.scope_hint.text() and "递归" in dialog.policy_group.currentText()
    assert dialog.update_summary["removed"] == 1
    assert dialog.update_summary["unchanged"] == 1
    assert dialog.update_summary["selection_lost"] is True
    assert dialog._active_result.selection_lost is True
    assert "999" not in dialog.update_hint.text()
    dialog.policy_group.setCurrentIndex(0)
    assert dialog.update_summary["removed"] == 0
    assert dialog.update_summary["selection_lost"] is False
    dialog.deleteLater()


def test_preview_without_existing_context_does_not_keep_stale_summary(app):
    dialog = ProxyImportPreviewDialog(_parse(), {"added": 9, "removed": 7})
    assert "移除 7" in dialog.update_hint.text()
    dialog.policy_group.setCurrentIndex(1)
    assert "移除 7" not in dialog.update_hint.text()
    assert "上下文" in dialog.update_hint.text()
    assert "将导入 1" in dialog.summary.text()
    dialog.deleteLater()


def test_preview_and_editor_preserve_metadata_dedup_and_recompute_summary(app, monkeypatch):
    original = "http://old.example.invalid:8080#旧\n"
    base = parse_subscription_text(
        original, source_id="source-edit", source_label="feed.example.invalid", group_id="custom-id",
        group_name="自定义组名", title="订阅标题", userinfo={"upload": 1, "download": 2, "total": 3},
    )
    manual = {"id": "manual", "name": "手工", "url": "http://manual.example.invalid:8080", "enabled": True}
    existing = {
        "id": "custom-id", "name": "自定义组名", "selected": base.nodes[0]["id"],
        "proxies": [manual, *base.nodes],
        "subscription": {"url": "https://feed.example.invalid/sub?token=private-token", "source_id": "source-edit"},
    }
    edited = "http://manual.example.invalid:8080#手工\nhttp://new.example.invalid:8080#新\n"

    def edit(dialog):
        assert dialog._existing_group == existing
        assert dialog._base_result is base
        dialog.editor.setPlainText(edited)
        dialog._accept_parsed()
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(SubscriptionContentDialog, "exec", edit)
    preview = ProxyImportPreviewDialog(base, subscription_update_summary(existing, base), existing_group=existing)
    preview.edit_content()
    result = preview.result
    assert (result.group_id, result.group_name, result.title) == ("custom-id", "自定义组名", "订阅标题")
    assert result.source_id == "source-edit" and dict(result.userinfo) == dict(base.userinfo)
    assert result.content_hash != base.content_hash
    assert result.duplicate_count == 1 and [node["name"] for node in result.nodes] == ["新"]
    assert preview.update_summary["added"] == 1 and preview.update_summary["removed"] == 1
    assert preview.update_summary["unchanged"] == 0 and preview.update_summary["selection_lost"]
    assert "总数 2" in preview.summary.text() and "重复 1" in preview.summary.text()
    merged = merge_proxy_import({"version": 3, "accounts": [], "proxy_groups": [existing]}, preview._active_result, target_group_id="custom-id")
    assert merged["proxy_groups"][0]["subscription"]["url"] == existing["subscription"]["url"]
    assert "content" not in merged["proxy_groups"][0]["subscription"]
    assert "content" not in merged["proxy_groups"][0]
    assert original not in json.dumps(merged, ensure_ascii=False)
    assert edited not in json.dumps(merged, ensure_ascii=False)
    assert existing["proxies"][1]["name"] == "旧"
    preview.deleteLater()


def test_preview_edit_rebuilds_policy_choices_and_summary(app, monkeypatch):
    base = _parse()
    existing = {"id": base.group_id, "proxies": list(base.nodes), "selected": ""}
    dialog = ProxyImportPreviewDialog(base, existing_group=existing)
    dialog.policy_group.setCurrentIndex(1)

    def edit(editor):
        editor.editor.setPlainText("http://new.example.invalid:8080#新节点\n")
        editor.format.setCurrentIndex(editor.format.findData("auto"))
        editor._accept_parsed()
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(SubscriptionContentDialog, "exec", edit)
    dialog.edit_content()
    assert dialog.policy_group.count() == 1 and dialog.policy_group.currentData() == ""
    assert [node["name"] for node in dialog._active_result.nodes] == ["新节点"]
    assert dialog.update_summary["removed"] == 2
    assert "总数 1" in dialog.summary.text() and "被筛选 0" in dialog.summary.text()
    dialog.deleteLater()


def test_preview_sanitizes_all_cells_tooltips_notices_and_group_names(app):
    token = "feed-private-token"
    secret = "11111111-1111-1111-1111-111111111111"
    base = _parse(_BRIDGED_LINKS["vless"])
    candidate = replace(base.candidates[0], name=secret, reason=f"检查 {secret}", display=f"节点 {secret}")
    result = replace(
        base, source_label=f"https://feed.example.invalid/sub?token={token}", candidates=(candidate,),
        notices=(f"订阅 {token} 节点 {secret}",),
        policy_groups=({"name": secret, "type": "select", "proxies": [secret]},),
    )
    dialog = ProxyImportPreviewDialog(result)
    visible = [dialog.summary.text(), dialog.notices.toPlainText(), dialog.policy_group.itemText(1)]
    for row in range(dialog.table.rowCount()):
        for column in range(dialog.table.columnCount()):
            visible.extend([dialog.table.item(row, column).text(), dialog.table.item(row, column).toolTip()])
    assert secret not in "\n".join(visible)
    assert token not in "\n".join(visible)
    dialog.deleteLater()


def test_preview_blocks_incomplete_provider_import(app):
    base = replace(_parse(), providers_complete=False)
    dialog = ProxyImportPreviewDialog(base)
    assert not _ok(dialog).isEnabled()
    assert "provider" in dialog.notices.toPlainText()
    dialog.accept()
    assert QDialog.result(dialog) != QDialog.DialogCode.Accepted
    dialog.deleteLater()


@pytest.mark.parametrize("edited", [CLASH_TEXT + "# changed\n", "http://single.example.invalid:80#只有本地\n"])
def test_editor_does_not_drop_resolved_external_provider_nodes(app, edited):
    base = replace(_parse(), providers=({"name": "远端", "type": "http", "resolved": True},), providers_complete=True)
    dialog = SubscriptionContentDialog(base.content, base_result=base)
    assert dialog.parse() is base
    dialog.editor.setPlainText(edited)
    dialog.format.setCurrentIndex(dialog.format.findData("auto"))
    assert dialog.parse() is None
    assert "外部 provider" in dialog.error_label.text()
    assert not _ok(dialog).isEnabled()
    dialog._accept_parsed()
    assert QDialog.result(dialog) != QDialog.DialogCode.Accepted
    assert len(base.nodes) == 2
    dialog.deleteLater()


def test_editor_retains_source_kind_and_refuses_unresolved_provider(app):
    base = replace(_parse(), source_kind="text")
    dialog = SubscriptionContentDialog(base.content, base_result=base)
    assert dialog.parse().source_kind == "text"
    dialog.editor.setPlainText(CLASH_TEXT + "proxy-providers:\n  remote:\n    type: http\n    url: https://feed.example.invalid/sub?token=private\n")
    parsed = dialog.parse()
    assert parsed is not None and parsed.providers_complete is False
    assert not _ok(dialog).isEnabled()
    assert "provider" in dialog.error_label.text()
    assert "token=private" not in dialog.error_label.text()
    dialog.deleteLater()


@pytest.mark.parametrize("format", ["auto", "base64"])
def test_file_editor_preserves_base64_clash_input_format(app, monkeypatch, tmp_path, format):
    encoded = base64.b64encode(CLASH_TEXT.encode()).decode()
    path = tmp_path / "encoded.txt"
    path.write_text(encoded, encoding="utf-8")
    widget = ProxySourceInput()
    widget.kind.setCurrentIndex(widget.kind.findData("file"))
    widget.source.setText(str(path))
    widget.format.setCurrentIndex(widget.format.findData(format))

    def edit(dialog):
        dialog._accept_parsed()
        assert dialog.result.format == "clash_yaml"
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(SubscriptionContentDialog, "exec", edit)
    widget.edit_button.click()
    values = widget.value()
    assert values["kind"] == "text" and values["source"] == encoded
    assert values["format"] == format
    result = SubscriptionImporter().import_source(SourceSpec(values["kind"], values["format"], values["source"]))
    assert result.importable_count == 2
    widget.deleteLater()


def test_preview_editor_redetects_base64_wrapped_clash_content(app, monkeypatch):
    encoded = base64.b64encode(CLASH_TEXT.encode()).decode()
    result = _parse(encoded)
    assert result.format == "clash_yaml" and result.content == encoded

    def edit(dialog):
        assert dialog.format.currentData() == "auto"
        dialog._accept_parsed()
        assert dialog.result is not None and dialog.result.importable_count == 2
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(SubscriptionContentDialog, "exec", edit)
    preview = ProxyImportPreviewDialog(result)
    preview.edit_content()
    assert preview.result.importable_count == 2
    preview.deleteLater()


def test_source_dialog_paste_area_scrolls_without_hiding_actions(app):
    dialog = ProxySourceDialog()
    dialog.kind.setCurrentIndex(dialog.kind.findData("text"))
    dialog.resize(600, 500)
    dialog.show()
    app.processEvents()
    assert dialog.content.geometry().bottom() < dialog.input.height()
    assert dialog.source_scroll.verticalScrollBar().maximum() > 0
    assert dialog.buttons.geometry().bottom() < dialog.height()
    dialog.close()
    dialog.deleteLater()
