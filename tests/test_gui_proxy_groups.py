"""离屏测试代理组控件：手动选择、引用保护与凭据不外泄。"""

from __future__ import annotations

import copy
import json
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6", reason="GUI 专项测试需要可选 PySide6")

from PySide6.QtWidgets import QApplication, QDialog  # noqa: E402

from core.errors import ConfigError  # noqa: E402
from gui import proxy_widgets  # noqa: E402
from gui.proxy_widgets import ProxyGroupDialog, ProxyGroupsPage, ProxyNodeDialog, ProxySelector  # noqa: E402

URL = "http://secret-user:secret-pass@127.0.0.1:7897"


@pytest.fixture(scope="module")
def qt_app():
    return QApplication.instance() or QApplication([])


def node(node_id="first", *, name="节点一", url=URL, enabled=True):
    return {"id": node_id, "name": name, "url": url, "enabled": enabled}


def group(group_id="office", *, selected="first", enabled=True, nodes=None):
    return {"id": group_id, "name": "办公代理", "enabled": enabled,
            "selected": selected, "proxies": [node()] if nodes is None else nodes}


def context(*groups, default=""):
    return {"proxy_groups": [copy.deepcopy(item) for item in groups], "default_proxy_group": default}


@pytest.fixture
def selector(qt_app):
    widget = ProxySelector()
    yield widget
    widget.close()
    widget.deleteLater()
    qt_app.processEvents()


@pytest.fixture
def page(qt_app, monkeypatch):
    widget = ProxyGroupsPage()
    monkeypatch.setattr(proxy_widgets, "_confirm", lambda *args: True)
    yield widget
    widget.close()
    widget.deleteLater()
    qt_app.processEvents()


def accepted(value):
    """替身对话框：避免测试进入模态事件循环。"""

    class Stub:
        def __init__(self, *args, **kwargs):
            pass

        def exec(self):
            return QDialog.DialogCode.Accepted

        def value(self):
            return copy.deepcopy(value)

    return Stub


def test_mode_switch_clears_conflicting_keys_and_keeps_extras(selector):
    selector.set_context(context(group()))
    selector.set_network({"verify_ssl": False, "extension": [1]})
    assert selector.value() == {"verify_ssl": False, "extension": [1]}

    selector.mode.setCurrentIndex(selector.mode.findData("custom"))
    selector.proxy.setText("localhost:7897")
    assert selector.value() == {"verify_ssl": False, "extension": [1],
                               "proxy_mode": "custom", "proxy": "localhost:7897"}

    selector.mode.setCurrentIndex(selector.mode.findData("group"))
    value = selector.value()
    assert "proxy" not in value, "切到代理组必须清掉自定义代理，否则两者冲突无法保存"
    assert value["proxy_mode"] == "group"

    selector.group.setCurrentIndex(selector.group.findData("office"))
    assert selector.value()["proxy_group"] == "office"

    selector.mode.setCurrentIndex(selector.mode.findData("direct"))
    value = selector.value()
    assert value["proxy_mode"] == "direct" and "proxy_group" not in value
    assert value["verify_ssl"] is False and value["extension"] == [1]


def test_legacy_proxy_is_recognized_as_custom_without_rewriting(selector):
    selector.set_network({"proxy": URL})
    assert selector.mode.currentData() == "custom"
    assert selector.value() == {"proxy": URL}, "只读不改写：未编辑就不写入 proxy_mode"
    assert selector.proxy.edit.echoMode().name == "Password"


def test_status_describes_configuration_not_connectivity(selector, monkeypatch):
    monkeypatch.delenv("CHECKIN_PROXY", raising=False)
    selector.set_context(context(group()))
    selector.set_network({"proxy_group": "office"})
    text = selector.status.text()
    assert "未检测连通性" in text
    assert "secret-user" not in text and "secret-pass" not in text
    assert "127.0.0.1:7897" in text

    selector.set_network({})
    assert "直连" in selector.status.text()


@pytest.mark.parametrize("mutation,marker", [
    ({"enabled": False}, "停用"),
    ({"proxies": [], "selected": ""}, "空"),
    ({"selected": ""}, "未选择"),
])
def test_unusable_group_is_reported_as_error_not_silent_direct(selector, mutation, marker):
    raw = group()
    raw.update(mutation)
    selector.set_context(context(raw))
    selector.set_network({"proxy_group": "office"})
    assert "不可用" in selector.status.text()
    assert marker in selector.status.text()
    assert selector.status.objectName() == "error"


def test_missing_group_reference_stays_visible(selector):
    selector.set_context(context(group()))
    selector.set_network({"proxy_group": "removed"})
    assert selector.group.currentData() == "removed", "缺失引用不能被悄悄换成别的组"
    assert "不存在" in selector.group.currentText()
    assert selector.status.objectName() == "error"


def test_node_dialog_round_trips_url_and_conceals_authentication(qt_app):
    dialog = ProxyNodeDialog()
    dialog.name_field.setText("节点一")
    dialog.url_input.setText("socks5://u%40ser:p%40ss@[::1]:1080")
    dialog.import_url()
    assert dialog.host.text() == "::1" and dialog.port.value() == 1080
    assert dialog.scheme.currentData() == "socks5"
    for field in (dialog.username, dialog.password, dialog.url_input):
        assert field.edit.echoMode().name == "Password"
    value = dialog.value()
    assert value["url"] == "socks5://u%40ser:p%40ss@[::1]:1080"
    assert value["name"] == "节点一" and value["enabled"] is True
    dialog.deleteLater()


def test_node_dialog_validates_and_preserves_unknown_fields(qt_app):
    dialog = ProxyNodeDialog({"id": "kept", "name": "原名", "url": URL, "extension": {"keep": [1]}})
    assert dialog.id_field.isReadOnly() and dialog.id_field.text() == "kept"
    assert dialog.username.text() == "secret-user"

    dialog.name_field.setText("")
    with pytest.raises(ConfigError, match="名称"):
        dialog.value()

    dialog.name_field.setText("改名")
    value = dialog.value()
    assert value["id"] == "kept" and value["extension"] == {"keep": [1]}
    assert value["url"] == URL, "未编辑连接信息就不该重建 URL"
    assert "enabled" not in value, "原本没有 enabled 就不物化默认值"

    dialog.username.setText("")
    with pytest.raises(ConfigError, match="用户名"):
        dialog.value()

    dialog.host.setText("")
    dialog.password.setText("")
    with pytest.raises(ConfigError):
        dialog.value()
    dialog.deleteLater()


def test_node_dialog_rejects_bad_url_without_echoing_it(qt_app):
    dialog = ProxyNodeDialog()
    dialog.url_input.setText("ftp://leaked-host?password=leaked")
    dialog.import_url()
    # 对话框未 show() 时子控件的 isVisible() 恒为假，按既有 GUI 测试惯例断言文本。
    assert "代理 URL 无效" in dialog.error_label.text()
    assert "leaked" not in dialog.error_label.text()
    assert dialog.host.text() == "", "解析失败不得写入任何连接字段"
    dialog.deleteLater()


def test_group_dialog_never_auto_selects_a_node(qt_app, monkeypatch):
    dialog = ProxyGroupDialog()
    dialog.name_field.setText("新组")
    monkeypatch.setattr(proxy_widgets, "ProxyNodeDialog", accepted(node()))
    dialog.add_node()
    monkeypatch.setattr(proxy_widgets, "ProxyNodeDialog", accepted(node("second", name="节点二")))
    dialog.add_node()
    assert dialog.value()["selected"] == "", "新增节点不能自动成为当前节点"
    assert "未选择当前节点" in dialog.status.text()

    dialog.members.selectRow(1)
    dialog.select_node()
    assert dialog.value()["selected"] == "second"
    assert "配置有效" in dialog.status.text()

    dialog.move_node(-1)
    assert [item["id"] for item in dialog.value()["proxies"]] == ["second", "first"]
    assert dialog.value()["selected"] == "second", "排序不改变手动选择"
    dialog.deleteLater()


def test_group_dialog_keeps_selection_explicit_when_current_node_goes_away(qt_app, monkeypatch):
    monkeypatch.setattr(proxy_widgets, "_confirm", lambda *args: True)
    dialog = ProxyGroupDialog(group(nodes=[node(), node("second", name="节点二")]))
    dialog.members.selectRow(0)
    dialog.toggle_node()
    assert dialog.value()["selected"] == "first"
    assert "当前节点停用" in dialog.status.text(), "停用当前节点要显式报告，不能顶替成别的节点"

    dialog.select_node()
    assert "请先启用节点" in dialog.error_label.text()
    assert dialog.value()["selected"] == "first", "停用节点不能被设为当前"

    dialog.delete_node()
    assert dialog.value()["selected"] == "", "删除当前节点后置为未选择，而不是顺延"
    assert [item["id"] for item in dialog.value()["proxies"]] == ["second"]
    dialog.deleteLater()


def test_group_dialog_table_and_validation_hide_credentials(qt_app):
    dialog = ProxyGroupDialog(group())
    row = [dialog.members.item(0, column).text() for column in range(dialog.members.columnCount())]
    assert "secret-user" not in "".join(row) and "secret-pass" not in "".join(row)
    assert "http://127.0.0.1:7897" in row and "已配置" in row

    dialog.name_field.setText("")
    with pytest.raises(ConfigError):
        dialog.value()
    dialog.deleteLater()


def test_page_reports_status_references_and_blocks_used_group(page, monkeypatch):
    monkeypatch.delenv("CHECKIN_PROXY", raising=False)
    payload = {**context(group(), group("spare", selected="")),
               "accounts": [{"id": "site", "name": "站点", "network": {"proxy_group": "office"}}]}
    page.set_payload(payload)
    assert page.references("office") == ["站点"]
    assert page.references("spare") == []

    table = [[page.table.item(row, column).text() for column in range(page.table.columnCount())]
             for row in range(page.table.rowCount())]
    assert table[0][1] == "节点一" and table[0][3] == "1"
    assert "配置有效" in table[0][4] and "未选择" in table[1][4]
    assert "secret-pass" not in json.dumps(table, ensure_ascii=False)

    page.table.selectRow(0)
    page.delete_group()
    assert [item["id"] for item in page.value()["proxy_groups"]] == ["office", "spare"]
    assert "仍被" in page.message.text() and "站点" in page.message.text()

    page.table.selectRow(1)
    page.delete_group()
    assert [item["id"] for item in page.value()["proxy_groups"]] == ["office"]


def test_page_default_group_counts_as_a_reference(page):
    page.set_payload({**context(group(), default="office"), "accounts": []})
    assert page.references("office") == ["全局默认"]
    page.table.selectRow(0)
    page.delete_group()
    assert page.value()["proxy_groups"], "被默认组引用时不能删除"

    page.default_group.setCurrentIndex(page.default_group.findData(""))
    assert page.value()["default_proxy_group"] == ""
    page.delete_group()
    assert page.value()["proxy_groups"] == []


def test_page_inheriting_account_follows_default_group(page):
    page.set_payload({**context(group(), default="office"),
                      "accounts": [{"id": "site", "name": "继承账号"}]})
    assert page.references("office") == ["全局默认", "继承账号"]
    assert page.table.item(0, 3).text() == "2"


def test_page_edits_emit_draft_values_only(page, monkeypatch):
    page.set_payload({**context(group()), "accounts": []})
    seen: list[dict] = []
    page.changed.connect(seen.append)

    monkeypatch.setattr(proxy_widgets, "ProxyGroupDialog", accepted(group("added", selected="")))
    page.add_group()
    assert [item["id"] for item in seen[-1]["proxy_groups"]] == ["office", "added"]

    page.table.selectRow(0)
    page.toggle_group()
    assert seen[-1]["proxy_groups"][0]["enabled"] is False
    page.toggle_group()
    assert page.value()["proxy_groups"][0]["enabled"] is True
    assert len(seen) == 3
