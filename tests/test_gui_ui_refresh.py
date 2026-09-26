"""界面重构回归：紧凑导航、模板搜索、空状态与主题切换，不访问网络与真实配置。"""

from __future__ import annotations

import os
import runpy

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

_smoke = runpy.run_path(os.path.join(os.path.dirname(__file__), "test_gui_app_smoke.py"))
qapp = pytest.fixture(scope="module")(_smoke["qapp"].__wrapped__)
window = pytest.fixture(_smoke["window"].__wrapped__)
wait = _smoke["wait"]


def test_navigation_collapses_on_narrow_window_and_keeps_labels(window, qapp):
    window.show()
    window.resize(1400, 860)
    qapp.processEvents()
    assert not window.nav._compact
    window.resize(900, 600)
    qapp.processEvents()
    assert window.nav._compact
    assert window.nav.labels() == ["账号", "运行", "代理", "登录态", "模板"]
    assert not window.metrics_strip.isVisible()


def test_set_page_updates_header_title(window):
    window.set_page(1)
    assert window.workspace_title.text() == "运行中心"
    window.set_page(4)
    assert window.workspace_title.text() == "模板库"
    window.set_page(99)
    assert window.workspace.currentIndex() == 4


def test_catalog_search_filters_rows_and_detail_follows_source_entry(window):
    window.catalog = [
        {"reference": "newapi", "title": "New API", "login_methods": ["cookie"], "task_methods": ["http_api"]},
        {"reference": "sub2api", "title": "Sub2API", "login_methods": ["refresh"], "task_methods": ["visit"]},
    ]
    window._refresh_catalog()
    assert window.catalog_table.rowCount() == 2
    window.catalog_search.setText("sub2")
    assert window.catalog_table.rowCount() == 1
    assert window.catalog_table.item(0, 0).text() == "sub2api"
    assert '"sub2api"' in window.catalog_detail.toPlainText()
    window.catalog_search.clear()
    assert window.catalog_table.rowCount() == 2


def test_account_filter_without_matches_shows_empty_state(window):
    window.search.setText("no-such-account-xyz")
    assert window.account_list.count() == 0
    assert window.account_list_stack.currentIndex() == 1
    assert window.clear_filter_button.isVisibleTo(window.account_empty)
    window._clear_account_filters()
    assert window.account_list.count() == 3
    assert window.account_list_stack.currentIndex() == 0


def test_theme_toggle_keeps_draft_and_updates_toggle_label(window, monkeypatch):
    before = window.editor.value()
    monkeypatch.setattr(window, "_theme", "light")
    window._apply_theme()
    assert window.theme_button.text() == "深色"
    window._toggle_theme()
    assert window._theme == "dark"
    assert window.theme_button.text() == "浅色"
    assert window.editor.value() == before
    assert not window._dirty
