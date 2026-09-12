"""GUI 启动冒烟：无头把主窗口真正构造出来。

为什么必须有这一条：``gui/core.py`` 有 80 项纯逻辑测试，但 ``gui/app.py``（2000+ 行
的表单装配）一行覆盖都没有。于是「core 里删掉一个常量、app 里还在引用」这种改动能
一路过测试，直到用户双击图标才崩——实测发生过一次（``core.DEFAULT_API_VARIANT``）。

这里用 Qt 的 offscreen 平台，不需要显示器，也不需要人操作：构造 ``App()`` 会走完
建控件 → 读配置 → 选中第一行 → 回填表单的完整路径，正是那次崩溃的现场。
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest


# ── 静态检查：不需要 Qt，任何环境都能跑 ────────────────────────────────────
def test_every_core_attribute_referenced_by_the_ui_exists() -> None:
    """界面里写的每一个 ``core.X`` 都必须真的存在。

    这是上面那次崩溃的最小复现：改词表时删了常量，引用方却在另一个文件里。
    """
    from gui import core

    missing: dict[str, list[str]] = {}
    for path in sorted(pathlib.Path("gui").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "core"
                and not hasattr(core, node.attr)
            ):
                missing.setdefault(node.attr, []).append(f"{path}:{node.lineno}")
    assert not missing, f"界面引用了 gui.core 里不存在的名字：{missing}"


def test_combo_fallbacks_are_valid_choices() -> None:
    """下拉框的兜底值必须真的在选项里。

    选项来自注册表（开放集合），兜底值是常量；两者漂移时选中项落不到任何选项上，
    表现为「打开就崩」或者「静默把用户的配置改成别的」。
    """
    from gui import core

    assert core.DEFAULT_AUTH_METHOD in core.AUTH_METHODS
    assert core.DEFAULT_ACTION in core.CHECKIN_ACTIONS
    assert core.DEFAULT_API_VARIANT in core.API_VARIANTS
    assert core.DEFAULT_VERIFICATION_MODE in core.VERIFICATION_MODES
    assert core.DEFAULT_OAUTH_PROVIDER in core.OAUTH_PROVIDERS
    assert core.DEFAULT_TEMPLATE in core.TYPES


def test_every_template_has_a_button_label() -> None:
    """模板是开放集合：用户往 templates/user/ 放一个 TOML，按钮条就多一项。

    旧代码用 ``TYPE_LABELS[t]`` 直接下标，遇到没登记的模板会 KeyError，界面直接起不来。
    """
    from gui import core

    for template_id in core.TYPES:
        label = core.template_label(template_id)
        assert label, f"模板 {template_id} 没有可显示的标签"


# ── 动态检查：需要 PySide6，无头构造主窗口 ─────────────────────────────────
@pytest.fixture
def offscreen_app(tmp_path, monkeypatch):
    """一个 offscreen 的 QApplication + 一份临时配置。"""
    pytest.importorskip("PySide6", reason="未安装 GUI 依赖（uv sync --extra gui）")
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")

    config = tmp_path / "ACCOUNTS.json"
    config.write_text(
        json.dumps(
            {
                "version": 3,
                "accounts": [
                    {
                        "id": "builtin-site",
                        "name": "内置模板站",
                        "base_url": "https://a.invalid",
                        "template": "newapi",
                        "login": {"method": "cookie"},
                        "tasks": [{"id": "daily", "method": "http_api"}],
                        "credentials": {"cookie": "s=1"},
                    },
                    {
                        # 路径模板：按钮条里没有它对应的按钮，最容易踩到兜底逻辑
                        "id": "script-site",
                        "name": "脚本模板站",
                        "base_url": "https://b.invalid",
                        "template": "scripts/tasks/100xlabs.py",
                        "login": {"method": "oauth", "provider": "linuxdo"},
                        "tasks": [{"id": "daily", "method": "script"}],
                    },
                ],
                "oauth_states": {},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    from config import paths

    monkeypatch.setattr(paths, "ACCOUNTS_PATH", config)

    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


def test_main_window_builds_and_loads_every_row(offscreen_app) -> None:
    """构造主窗口并逐行回填表单——上次崩溃就发生在回填这一步。"""
    from gui.app import App

    window = App()
    try:
        assert len(window.rows) == 2
        assert window.detail_tabs.count() == 3
        assert [window.detail_tabs.tabText(i) for i in range(3)] == ["账号管理", "凭证中心", "运行日志"]
        for index in range(len(window.rows)):
            window._select_real(index)  # noqa: SLF001 - 就是要走界面自己的加载路径
            window.detail_tabs.setCurrentIndex(0)
            window.detail_tabs.setCurrentIndex(1)
            assert window.token_edit.text() == window.rows[index].access_token
            assert window.refresh_edit.text() == window.rows[index].refresh_token
        window.detail_tabs.setCurrentIndex(2)
        assert window.workspace_title.text() == "运行日志"
    finally:
        window.close()


def test_credential_edit_and_secret_visibility_are_wired(offscreen_app) -> None:
    """凭证中心能回填、隐藏 Token，并把编辑纳入 v3 脏状态。"""
    from PySide6.QtWidgets import QLineEdit

    from gui import core
    from gui.app import App

    window = App()
    try:
        window._select_real(0)  # noqa: SLF001
        window.token_edit.setText("aaa.bbb.ccc")
        window.refresh_edit.setText("refresh-value")
        window.state_edit.setPlainText("browser-state")
        window._flush()  # noqa: SLF001

        assert window.token_edit.echoMode() == QLineEdit.Password
        window.token_toggle.setChecked(True)
        assert window.token_edit.echoMode() == QLineEdit.Normal
        assert window.token_toggle.text() == "隐藏"
        window.token_toggle.setChecked(False)
        assert window.token_edit.echoMode() == QLineEdit.Password
        assert core.config_snapshot(window.rows, window.oauth_states) != window._saved_snapshot  # noqa: SLF001
    finally:
        window.close()


def test_path_template_survives_a_form_roundtrip(offscreen_app) -> None:
    """选中一个路径模板的账号再回写，模板不能被兜底成 newapi。

    按钮条里没有路径模板的按钮，``_current_type()`` 若兜底成内置模板，用户的模板
    就在「打开界面看了一眼」之后被悄悄改掉了。
    """
    from gui.app import App

    window = App()
    try:
        index = next(i for i, row in enumerate(window.rows) if row.name == "脚本模板站")
        window._select_real(index)  # noqa: SLF001
        window._flush()  # noqa: SLF001 - 模拟表单编辑后的回写

        row = window.rows[index]
        assert row.script == "scripts/tasks/100xlabs.py"
        saved = window_account(window, index)
        assert saved["template"] == "scripts/tasks/100xlabs.py"
    finally:
        window.close()


def window_account(window, index: int) -> dict:
    from gui import core

    return core.persist_accounts([window.rows[index]])[0]
