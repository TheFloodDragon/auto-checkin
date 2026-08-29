"""模板层：清单继承、声明式执行、响应映射。

「不写一行 Python 就能加一个站点」这句话成立与否，全看这三件事：
- ``extends`` 能继承登录方式、端点、请求头与响应映射；
- ``[response]`` 能让通用驱动读懂响应；
- 声明不全时必须**明确报错**，而不是猜——猜错会造成「显示成功但没到账」。
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from core.errors import ConfigError
from core.manifest import ResponseMap
from core.outcome import Verdict
from task import http_api
from templates import registry as templates


# ── 响应映射 ────────────────────────────────────────────────────────────────
def test_response_map_picks_by_dotted_path_and_by_key_search() -> None:
    """点分路径精确取；不含点的候选在整个响应里按键名搜。

    各 fork 的嵌套层级并不一致（有的包在 data 里、有的直接顶层），写死层级会让一次
    改版就失效。
    """
    mapping = ResponseMap(checked_in=("stats.checked_in_today", "checked_in_today"))
    assert mapping.pick({"stats": {"checked_in_today": True}}, "checked_in") is True
    assert mapping.pick({"deep": {"nest": {"checked_in_today": True}}}, "checked_in") is True
    assert mapping.pick({"other": 1}, "checked_in") is None


def test_response_map_unit_conversion_and_zero_handling() -> None:
    quota = ResponseMap(unit="quota_500000")
    assert quota.format(1_000_000) == "$2.00"
    assert quota.format(500) == "$0.0010"
    assert quota.has_amount(0) is False, "0 是「站点没回数值」，不是「获得 0」"
    assert quota.to_number(float("nan")) is None, "NaN 会让「是否增长」的判定静默失效"
    assert quota.to_number(True) is None, "bool 不是数值"

    raw = ResponseMap(unit="raw")
    assert raw.format(3) == "3"


# ── 清单继承 ────────────────────────────────────────────────────────────────
def test_child_template_inherits_endpoints_headers_and_login() -> None:
    parent = templates.get("newapi").manifest
    child = templates.get("scripts/tasks/sotamodel.py").manifest

    assert child.endpoints["user"] == parent.endpoints["user"], "端点被继承"
    assert child.headers == parent.headers, "站点族请求头被继承"
    assert child.login_order() == parent.login_order(), "登录方式被继承"
    assert child.task_option("http_api").owns == frozenset({"detect", "confirm"}), "自己的声明覆盖父的"


def test_declarative_toml_template_is_executable(tmp_path, monkeypatch) -> None:
    """一个 TOML 模板 + 通用驱动，就能跑通一个站点。"""
    user_dir = tmp_path / "user"
    user_dir.mkdir()
    (user_dir / "demo_site.toml").write_text(
        """
id = "demo_site"
title = "示例站"

[[login]]
method = "access_token"

[[task]]
method = "http_api"

[endpoints]
state = "/api/state"
submit = "/api/checkin"
user = "/api/me"

[response]
checked_in = ["checked_in_today"]
awarded = ["reward"]
balance = ["balance"]
unit = "usd"
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(templates, "USER_DIR", user_dir)
    templates.REGISTRY.clear()

    template = templates.get("demo_site")
    assert template.manifest.title == "示例站"
    assert template.manifest.response.unit == "usd"
    assert template.hook("run") is None, "声明式模板没有 run()，由通用驱动执行"

    class _Http:
        def get(self, path: str, **_: Any) -> Any:
            return {"data": {"checked_in_today": False, "balance": 10}}

        def request(self, method: str, path: str, **_: Any) -> Any:
            return {"data": {"reward": 1.5, "balance": 11.5}}

    class _Ctx:
        http = _Http()
        args: dict[str, Any] = {}

        def log(self, message: str, **_: Any) -> None:
            pass

    outcome = asyncio.run(http_api.declarative_run(_Ctx(), template))
    assert outcome.verdict is Verdict.SUCCESS
    view = outcome.rendered()
    assert view.text == "$11.50"
    assert ("获得", "$1.50") in view.extras


def test_declarative_template_without_response_map_refuses_to_guess() -> None:
    """只有端点没有响应映射时必须报错。

    猜「HTTP 200 就是成功」正是「显示成功但额度没到账」的成因。
    """
    from core.manifest import TemplateManifest

    manifest = TemplateManifest(id="x", endpoints={"submit": "/go"})
    template = type("T", (), {"manifest": manifest, "hook": lambda self, name: None})()

    with pytest.raises(ConfigError, match="response"):
        asyncio.run(http_api.declarative_run(object(), template))


def test_unknown_template_lists_what_is_available() -> None:
    with pytest.raises(Exception) as excinfo:
        templates.get("no-such-template")
    assert "newapi" in str(excinfo.value), "报错要顺带告诉用户有哪些可选"


def test_builtin_templates_declare_what_they_need() -> None:
    """CI 靠 requires 决定装不装浏览器，声明缺失会让 CI 与实际执行对不上。"""
    from runtime import capabilities

    assert "browser" in capabilities.required_by(templates.get("newapi").manifest)
    assert "browser" in capabilities.required_by(
        templates.get("scripts/tasks/abrdns_welfare.py").manifest
    )
