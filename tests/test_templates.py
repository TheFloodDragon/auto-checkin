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
    assert child.task_option("http_api").owns == frozenset({"detect", "confirm", "execute"}), "自己的声明覆盖父的"


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


@pytest.mark.parametrize("login_ok", [True, False])
def test_sub2api_password_fallback_records_tokens_with_runtime_context(monkeypatch, login_ok) -> None:
    """浏览器账密兜底成功后传入真实 ctx 续存 token；失败时不能续存或签到。"""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    import sdk
    from scripts.tasks import _sub2api_flow as flow

    page = SimpleNamespace(
        evaluate=AsyncMock(return_value=False),
        wait_for_load_state=AsyncMock(),
        wait_for_timeout=AsyncMock(),
    )
    lease = SimpleNamespace(page=page, context=object(), mark_authenticated=Mock())
    ctx = SimpleNamespace(args={"email": "test@example.test", "password": "test-password"})
    expected = object()
    helpers = SimpleNamespace(
        ctx=ctx,
        resolve_url=lambda path: f"https://example.test{path}",
        goto=AsyncMock(),
        solve=AsyncMock(return_value=SimpleNamespace(value="test-turnstile-token")),
        success=Mock(return_value=expected),
        need_login=Mock(return_value=expected),
    )
    monkeypatch.setattr(sdk, "PageHelpers", lambda *_: helpers)
    for name in ("add_init_script", "keep_waf_cookies", "dismiss_notice", "navigate_and_settle"):
        monkeypatch.setattr(flow, name, AsyncMock())
    for name in ("fill_login_form", "authenticated", "stash_session", "mark_login_done"):
        monkeypatch.setattr(flow, name, AsyncMock(return_value=True))
    monkeypatch.setattr(flow, "on_login_page", AsyncMock(side_effect=[True, False]))
    monkeypatch.setattr(
        flow, "submit_login", AsyncMock(return_value={"ok": login_ok, "status": 200 if login_ok else 401})
    )
    record_tokens = AsyncMock()
    monkeypatch.setattr(flow, "_record_new_tokens", record_tokens)
    checkin = AsyncMock(return_value={"ok": True, "status": 200, "balance": 15, "reward": 5})
    monkeypatch.setattr(flow, "api_checkin", checkin)
    spec = flow.SiteSpec(
        site_label="测试站点",
        checkin_path="/api/v1/check-in",
        login_reset_sentinel="test_login_reset",
        screenshot_prefix="test",
    )

    assert asyncio.run(flow.run_flow(ctx, lease, spec)) is expected
    if login_ok:
        record_tokens.assert_awaited_once_with(page, helpers, ctx, "https://example.test")
        checkin.assert_awaited_once_with(page, spec, "https://example.test")
        lease.mark_authenticated.assert_called_once()
    else:
        record_tokens.assert_not_awaited()
        checkin.assert_not_awaited()
        lease.mark_authenticated.assert_not_called()


@pytest.mark.parametrize("site_state", ["", "cached-site-state"])
def test_fengwind_oauth_restores_state_and_returns_fresh_credentials(monkeypatch, site_state) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from core.errors import TaskError
    from core.manifest import LoginOption
    from scripts.tasks import fengwind_welfare as fengwind

    page = object()
    lease = SimpleNamespace(new_page=AsyncMock(return_value=page))
    manager = AsyncMock()
    manager.__aenter__.return_value = lease
    browser = SimpleNamespace(lease=Mock(return_value=manager))
    ctx = SimpleNamespace(
        credentials=SimpleNamespace(access_token="expired-token", browser_state=site_state),
        args={"provider": "linuxdo", "account": "secondary"},
        account=SimpleNamespace(login=SimpleNamespace(provider="linuxdo", account="secondary")),
        oauth_state=Mock(return_value="shared-linuxdo-state"),
        browser=browser,
        log=Mock(),
    )
    monkeypatch.setattr(fengwind, "_request", Mock(side_effect=TaskError("expired", status=401)))
    browser_login = AsyncMock(return_value=("fresh-welfare-token", {}))
    monkeypatch.setattr(fengwind, "_browser_login", browser_login, raising=False)

    state = asyncio.run(fengwind.login(ctx, LoginOption("oauth")))

    assert state.verified
    assert state.headers["Authorization"] == "Bearer fresh-welfare-token"
    assert state.credentials["access_token"] == "fresh-welfare-token"
    browser.lease.assert_called_once_with(reason="fengwind_sso", state_text=site_state or "shared-linuxdo-state")
    browser_login.assert_awaited_once_with(ctx, lease, page)
    if not site_state:
        ctx.oauth_state.assert_called_once_with("linuxdo", "secondary")
    assert fengwind.login(ctx, LoginOption("access_token")) is None


@pytest.mark.parametrize("login_context", [False, True])
def test_fengwind_sso_reads_budget_from_supported_context(monkeypatch, login_context) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from scripts.tasks import fengwind_welfare as fengwind

    ctx = (
        SimpleNamespace(deadline=SimpleNamespace(remaining=lambda: 85.0))
        if login_context else SimpleNamespace(remaining_seconds=lambda: 85.0)
    )
    helpers = SimpleNamespace(ctx=ctx, log=Mock())
    page = object()
    login_url = "https://main.example.test/sso/continue"
    monkeypatch.setattr(fengwind, "_fetch_login_url", AsyncMock(return_value=login_url))
    monkeypatch.setattr(fengwind, "_safe_goto", AsyncMock())
    monkeypatch.setattr(fengwind.bypass, "solve_cloudflare", AsyncMock())
    drive = AsyncMock(return_value={"token": "fresh-token", "reason": "", "stage": "welfare_callback"})
    monkeypatch.setattr(fengwind, "_drive_sso_chain", drive)

    result = asyncio.run(fengwind._login_with_linuxdo(page, helpers, "https://welfare.example.test"))

    assert result["token"] == "fresh-token"
    assert drive.await_args.args[-1] == 40.0


def test_fengwind_sso_timeout_stops_stalled_page_and_captures_stage(monkeypatch) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from scripts.tasks import fengwind_welfare as fengwind

    async def stalled(*_args, **_kwargs):
        await asyncio.Event().wait()

    page = SimpleNamespace(url="https://connect.linux.do/oauth2/authorize")
    helpers = SimpleNamespace(
        ctx=SimpleNamespace(remaining_seconds=lambda: 45.05),
        log=Mock(),
        screenshot=AsyncMock(return_value="fengwind-sso-timeout.png"),
    )
    monkeypatch.setattr(
        fengwind, "_fetch_login_url", AsyncMock(return_value="https://main.example.test/sso/continue")
    )
    monkeypatch.setattr(fengwind, "_safe_goto", AsyncMock())
    monkeypatch.setattr(fengwind.bypass, "solve_cloudflare", stalled)

    result = asyncio.run(
        asyncio.wait_for(fengwind._login_with_linuxdo(page, helpers, "https://welfare.example.test"), timeout=1)
    )

    assert result["token"] == ""
    assert result["reason"] == "timeout"
    assert result["stage"] == "connect"
    assert result["screenshot"] == "fengwind-sso-timeout.png"
    helpers.screenshot.assert_awaited_once()


def test_fengwind_sso_accepts_token_after_frontend_clears_callback(monkeypatch) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from scripts.tasks import fengwind_welfare as fengwind

    origin = "https://welfare.example.test"
    page = SimpleNamespace(url=origin, wait_for_timeout=AsyncMock())
    helpers = SimpleNamespace(log=Mock())
    monkeypatch.setattr(fengwind, "STAGE_SETTLE_SECONDS", 0)
    monkeypatch.setattr(fengwind, "_page_token", AsyncMock(return_value="frontend-token"))
    monkeypatch.setattr(fengwind, "_verify_page_token", AsyncMock(return_value=True))
    goto = AsyncMock(side_effect=AssertionError("前端已完成登录，不应再次发起 SSO"))
    monkeypatch.setattr(fengwind, "_safe_goto", goto)

    result = asyncio.run(
        fengwind._drive_sso_chain(page, helpers, origin, "https://main.example.test/sso/continue", "test-state", 1)
    )

    assert result["token"] == "frontend-token"
    assert result["reason"] == ""
    goto.assert_not_awaited()


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        ({"auth_token": "expired", "welfare_token": "fresh"}, "fresh"),
        ({"welfare_token": "fresh"}, "fresh"),
        ({"auth_token": "cached"}, "cached"),
        ({}, ""),
    ],
)
def test_fengwind_prefers_native_token_and_synchronizes_cache(stored, expected) -> None:
    import json
    import shutil
    import subprocess

    from scripts.tasks import fengwind_welfare as fengwind

    node = shutil.which("node")
    if not node:
        from pathlib import Path

        from playwright._impl._driver import compute_driver_executable

        node = compute_driver_executable()[0]
        if not Path(node).is_file():
            pytest.skip("需 Node.js 或 Playwright 自带运行时执行页面逻辑")
    storage = dict(stored)

    class Page:
        async def evaluate(self, script):
            probe = (
                "const store = JSON.parse(process.argv[1]);"
                "const localStorage = {getItem:k=>store[k]||null,setItem:(k,v)=>{store[k]=v;}};"
                f"const token = ({script})();"
                "process.stdout.write(JSON.stringify({token,store}));"
            )
            result = subprocess.run(
                [node, "-e", probe, json.dumps(storage)], capture_output=True, text=True, timeout=10
            )
            assert result.returncode == 0, result.stderr
            data = json.loads(result.stdout)
            storage.update(data["store"])
            return data["token"]

    assert asyncio.run(fengwind._page_token(Page())) == expected
    if expected:
        assert storage["auth_token"] == storage["welfare_token"] == expected
