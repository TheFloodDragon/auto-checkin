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
    # 当前子模板也自管 execute；否则会误走父模板的通用声明式执行器。
    assert child.task_option("http_api").owns == frozenset({"detect", "execute", "confirm"}), "自己的声明覆盖父的"


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


def test_fengwind_transport_failure_predicate() -> None:
    """连接层失败（无 HTTP 状态码的瞬时错误）与应用层临时故障必须区分开。

    SSL EOF / 连接重置 = 纯 HTTP 指纹被防护拦下，浏览器能救；5xx/429 带状态码，
    是服务端应用层故障，浏览器同样无解，不该据此白开一次浏览器。
    """
    from core.errors import LoginRequired, TaskError, TransientError
    from scripts.tasks import fengwind_welfare as fengwind

    assert fengwind._is_transport_failure(
        TransientError("网络请求失败：[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred")
    ) is True
    assert fengwind._is_transport_failure(TransientError("网关错误", status=503)) is False
    assert fengwind._is_transport_failure(LoginRequired("expired", status=401)) is False
    assert fengwind._is_transport_failure(TaskError("boom")) is False


def test_fengwind_oauth_falls_back_to_browser_on_transport_failure(monkeypatch) -> None:
    """纯 HTTP 校验 Token 撞 SSL EOF 时降级到浏览器双层 SSO，而不是终局报「站点不可达」。

    实测全量运行时 api-welfalre.fengwind.com 的 /api/me 纯 HTTP 请求撞
    ``SSL: UNEXPECTED_EOF_WHILE_READING``（站点对标准库 Python 的 TLS 指纹重置连接）。
    旧实现只对 401/403 降级，把这类连接层失败直接 raise 成 network_error「站点不可达」，
    而 Camoufox 真实指纹能连上——本应交给浏览器双层 SSO。
    """
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from core.errors import TransientError
    from core.manifest import LoginOption
    from scripts.tasks import fengwind_welfare as fengwind

    page = object()
    lease = SimpleNamespace(new_page=AsyncMock(return_value=page))
    manager = AsyncMock()
    manager.__aenter__.return_value = lease
    browser = SimpleNamespace(lease=Mock(return_value=manager))
    ctx = SimpleNamespace(
        credentials=SimpleNamespace(access_token="stale-token", browser_state="shared-state"),
        args={"provider": "linuxdo", "account": "default"},
        account=SimpleNamespace(login=SimpleNamespace(provider="linuxdo", account="default")),
        oauth_state=Mock(return_value="shared-state"),
        browser=browser,
        log=Mock(),
    )
    ssl_eof = TransientError(
        "网络请求失败：[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol"
    )
    monkeypatch.setattr(fengwind, "_request", Mock(side_effect=ssl_eof))
    browser_login = AsyncMock(return_value=("fresh-welfare-token", {}))
    monkeypatch.setattr(fengwind, "_browser_login", browser_login, raising=False)

    state = asyncio.run(fengwind.login(ctx, LoginOption("oauth")))

    assert state.verified
    assert state.headers["Authorization"] == "Bearer fresh-welfare-token"
    browser_login.assert_awaited_once_with(ctx, lease, page)


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


@pytest.fixture
def linuxdo_run(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from scripts.tasks import linuxdo_browse as browse

    page = SimpleNamespace(
        url="https://linux.do/latest",
        evaluate=AsyncMock(return_value=True),
        wait_for_selector=AsyncMock(),
        go_back=AsyncMock(),
        reload=AsyncMock(),
    )
    lease = SimpleNamespace(
        page=page,
        new_page=AsyncMock(return_value=page),
        goto=AsyncMock(),
        dismiss_popups=AsyncMock(),
        mark_authenticated=Mock(),
        screenshot=AsyncMock(return_value="test-linuxdo.png"),
    )
    manager = AsyncMock()
    manager.__aenter__.return_value = lease
    ctx = SimpleNamespace(
        args={"post_count": 2, "min_read_seconds": 3, "max_read_seconds": 5},
        account=SimpleNamespace(base_url="https://linux.do"),
        browser=SimpleNamespace(lease=Mock(return_value=manager)),
        store=SimpleNamespace(get=Mock(return_value=None), put=Mock(return_value=True)),
        log=Mock(),
        remaining_seconds=lambda: 600.0,
    )
    links = AsyncMock(return_value=["https://linux.do/t/1", "https://linux.do/t/2"])
    opened = AsyncMock(return_value=True)
    monkeypatch.setattr(browse, "_wait_loaded", AsyncMock(return_value=True))
    # 本组只验证论坛态复用/计数；CF探测及失败路径在专用安全回归中覆盖。
    monkeypatch.setattr(browse, "_is_challenge", AsyncMock(return_value=False))
    monkeypatch.setattr(browse, "_logged_in", AsyncMock(return_value=True), raising=False)
    # 刷帖循环按 _session_probe 判定，需要区分「确认未登录」和「限流问不出来」。
    monkeypatch.setattr(
        browse,
        "_session_probe",
        AsyncMock(return_value={"authenticated": True, "status": 200, "throttled": False}),
        raising=False,
    )
    monkeypatch.setattr(browse, "_collect_topic_links", links)
    monkeypatch.setattr(browse, "_open_topic", opened, raising=False)
    monkeypatch.setattr(browse, "_simulate_read", AsyncMock(return_value=5.0))
    monkeypatch.setattr(browse.random, "randint", lambda low, high: high)
    monkeypatch.setattr(browse.random, "uniform", lambda *_: 0)
    monkeypatch.setattr(browse.random, "shuffle", lambda _: None)
    monkeypatch.setattr(browse.random, "choice", lambda values: values[0])
    return SimpleNamespace(module=browse, ctx=ctx, page=page, lease=lease, links=links, opened=opened)


def test_linuxdo_zero_reads_are_not_success_or_daily_completion(linuxdo_run) -> None:
    case = linuxdo_run
    case.opened.return_value = False
    case.page.wait_for_selector.side_effect = TimeoutError("topic unavailable")
    outcome = asyncio.run(case.module.run(case.ctx))

    assert not outcome.ok
    assert outcome.data["posts_read"] == 0
    case.ctx.store.put.assert_not_called()


def test_linuxdo_partial_read_does_not_mark_day_complete(linuxdo_run) -> None:
    case = linuxdo_run
    case.opened.side_effect = [True, False]
    case.page.wait_for_selector.side_effect = [None, TimeoutError("topic unavailable")]
    case.links.side_effect = [
        ["https://linux.do/t/1", "https://linux.do/t/2"],
        ["https://linux.do/t/2"],
        [],
    ]
    outcome = asyncio.run(case.module.run(case.ctx))

    assert not outcome.ok
    assert outcome.data["posts_read"] == 1
    case.ctx.store.put.assert_not_called()


def test_linuxdo_refresh_changes_next_topic_and_records_completed_target(linuxdo_run) -> None:
    case = linuxdo_run
    case.links.side_effect = [
        ["https://linux.do/t/1", "https://linux.do/t/2"],
        ["https://linux.do/t/3"],
    ]
    outcome = asyncio.run(case.module.run(case.ctx))

    assert outcome.ok
    assert outcome.data["posts_read"] == outcome.data["target_count"] == 2
    assert outcome.data["topic_urls"] == ["https://linux.do/t/1", "https://linux.do/t/3"]
    saved = case.ctx.store.put.call_args.args[1]
    assert saved["completed"] is True
    assert saved["posts_read"] == 2


def test_linuxdo_zero_history_does_not_skip_current_run(linuxdo_run) -> None:
    case = linuxdo_run
    case.ctx.args["once_per_day"] = True
    case.ctx.store.get.return_value = {"date": case.module.business_date(), "posts_read": 0}
    outcome = asyncio.run(case.module.run(case.ctx))

    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["posts_read"] == 2


def test_linuxdo_completed_history_skips_browsing(linuxdo_run) -> None:
    case = linuxdo_run
    case.ctx.args["once_per_day"] = True
    case.ctx.store.get.return_value = {
        "date": case.module.business_date(), "posts_read": 2, "target_count": 2, "completed": True,
    }
    outcome = asyncio.run(case.module.run(case.ctx))

    assert outcome.verdict is Verdict.ALREADY_DONE
    case.ctx.browser.lease.assert_not_called()


def test_linuxdo_rejects_inverted_reading_bounds_before_browser(linuxdo_run) -> None:
    case = linuxdo_run
    case.ctx.args.update(min_read_seconds=20, max_read_seconds=5)
    with pytest.raises(ConfigError, match="min_read_seconds"):
        asyncio.run(case.module.run(case.ctx))
    case.ctx.browser.lease.assert_not_called()


@pytest.mark.parametrize("site_state", ["", "cached-linuxdo-state"])
@pytest.mark.parametrize("challenge_cleared", [True, False])
def test_linuxdo_login_reuses_shared_state_without_oauth_redirect(monkeypatch, site_state, challenge_cleared) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from browser import bypass
    from core.manifest import LoginOption
    from scripts.tasks import linuxdo_browse as browse

    page = object()
    lease = SimpleNamespace(
        new_page=AsyncMock(return_value=page),
        goto=AsyncMock(),
        dismiss_popups=AsyncMock(),
        mark_authenticated=Mock(),
        oauth=AsyncMock(side_effect=AssertionError("论坛自身不应走 OAuth 回跳")),
    )
    manager = AsyncMock()
    manager.__aenter__.return_value = lease
    ctx = SimpleNamespace(
        credentials=SimpleNamespace(browser_state=site_state),
        base_url="https://linux.do",
        args={"provider": "linuxdo", "account": "secondary"},
        account=SimpleNamespace(login=SimpleNamespace(provider="linuxdo", account="secondary")),
        oauth_state=Mock(return_value="shared-linuxdo-state"),
        browser=SimpleNamespace(lease=Mock(return_value=manager)),
        deadline=None,
        log=Mock(),
    )
    monkeypatch.setattr(bypass, "solve_cloudflare", AsyncMock(return_value=challenge_cleared))
    monkeypatch.setattr(browse, "_shared_browser_state", lambda text: text, raising=False)
    monkeypatch.setattr(browse, "_wait_loaded", AsyncMock(return_value=True))
    # 本组只验证论坛态复用/计数；CF探测及失败路径在专用安全回归中覆盖。
    monkeypatch.setattr(browse, "_is_challenge", AsyncMock(return_value=False))
    # 会话判定的接缝是 _session_probe：它同时回答「是否登录」与「是否被限流」。
    monkeypatch.setattr(browse, "_session_probe", AsyncMock(side_effect=[
        {"authenticated": False, "status": 404, "throttled": False},
        {"authenticated": True, "status": 200, "throttled": False},
    ]))

    result = asyncio.run(browse.login(ctx, LoginOption("oauth")))

    assert result.verified
    ctx.browser.lease.assert_called_once_with(
        reason="linuxdo_login", state_text=site_state or "shared-linuxdo-state"
    )
    lease.mark_authenticated.assert_called_once()
    lease.oauth.assert_not_awaited()
    if not site_state:
        ctx.oauth_state.assert_called_once_with("linuxdo", "secondary")


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("/t/example/123/2?foo=bar#post", "https://linux.do/t/123"),
        ("https://linux.do/t/123", "https://linux.do/t/123"),
        ("https://other.test/t/example/123", ""),
        ("https://linux.do.evil.test/t/example/123", ""),
        ("https://linux.do/latest", ""),
        ("javascript:alert(1)", ""),
    ],
)
def test_linuxdo_normalizes_only_forum_topic_links(url, expected) -> None:
    from scripts.tasks import linuxdo_browse as browse

    assert browse._normalize_topic_url(url) == expected


def test_linuxdo_shared_state_keeps_auth_and_discards_only_stale_waf_cookies() -> None:
    from browser.state import decode_state, encode_state
    from scripts.tasks import linuxdo_browse as browse

    cookies = [
        {"name": name, "value": "test-value", "domain": domain, "path": "/"}
        for name, domain in (
            ("_t", ".linux.do"), ("_forum_session", "linux.do"),
            ("_bypass_cache", "linux.do"), ("cf_clearance", ".linux.do"),
            ("_cfuvid", ".linux.do"), ("cf_clearance", ".other.test"),
        )
    ]
    original = encode_state({"cookies": cookies, "origins": []})
    result = decode_state(browse._shared_browser_state(original))

    assert [(c["name"], c["domain"]) for c in result["cookies"]] == [
        ("_t", ".linux.do"), ("_forum_session", "linux.do"),
        ("_bypass_cache", "linux.do"), ("cf_clearance", ".other.test"),
    ]
    assert decode_state(original)["cookies"] == cookies, "不得改写用户保存的共享登录态"


def test_linuxdo_load_markers_share_one_timeout() -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from scripts.tasks import linuxdo_browse as browse

    page = SimpleNamespace(wait_for_selector=AsyncMock(side_effect=TimeoutError))
    assert not asyncio.run(browse._wait_loaded(page, timeout=100))
    page.wait_for_selector.assert_awaited_once()


def test_linuxdo_read_timeout_retains_partial_count_without_daily_completion(linuxdo_run, monkeypatch) -> None:
    case = linuxdo_run
    case.ctx.remaining_seconds = lambda: 20.05

    async def stalled(*_args, **_kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(case.module, "_simulate_read", stalled)
    outcome = asyncio.run(asyncio.wait_for(case.module.run(case.ctx), timeout=1))

    assert not outcome.ok
    assert outcome.data["posts_read"] == 0
    case.ctx.store.put.assert_not_called()


def _linuxdo_login_ctx(monkeypatch, *, github_fallback: bool, github_state: str = "shared-github-state"):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from browser import bypass
    from scripts.tasks import linuxdo_browse as browse

    page = SimpleNamespace(url="https://linux.do/latest", title=AsyncMock(return_value="LINUX DO"))
    lease = SimpleNamespace(
        new_page=AsyncMock(return_value=page),
        goto=AsyncMock(),
        dismiss_popups=AsyncMock(),
        mark_authenticated=Mock(),
        screenshot=AsyncMock(return_value="shot.png"),
        restore_state=AsyncMock(return_value=True),
        export_state=AsyncMock(return_value="fresh-linuxdo-state"),
        oauth=AsyncMock(side_effect=AssertionError("论坛自身不应走 OAuth 回跳")),
    )
    manager = AsyncMock()
    manager.__aenter__.return_value = lease
    states = {("linuxdo", "default"): "shared-linuxdo-state", ("github", "default"): github_state}
    ctx = SimpleNamespace(
        credentials=SimpleNamespace(browser_state=""),
        base_url="https://linux.do",
        args={"provider": "linuxdo", "account": "default", "github_fallback": github_fallback},
        account=SimpleNamespace(login=SimpleNamespace(provider="linuxdo", account="default")),
        oauth_state=Mock(side_effect=lambda provider, account: states.get((provider, account), "")),
        browser=SimpleNamespace(lease=Mock(return_value=manager)),
        deadline=None,
        log=Mock(),
    )
    monkeypatch.setattr(bypass, "solve_cloudflare", AsyncMock(return_value=True))
    monkeypatch.setattr(browse, "_shared_browser_state", lambda text: text, raising=False)
    monkeypatch.setattr(browse, "_wait_loaded", AsyncMock(return_value=True))
    # 本组只验证论坛态复用/计数；CF探测及失败路径在专用安全回归中覆盖。
    monkeypatch.setattr(browse, "_is_challenge", AsyncMock(return_value=False))
    return SimpleNamespace(module=browse, ctx=ctx, page=page, lease=lease)


def test_linuxdo_login_budget_includes_browser_startup(monkeypatch):
    from types import SimpleNamespace
    from core.errors import LoginRequired
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=False)
    case.ctx.deadline = SimpleNamespace(remaining=lambda: 20.02)

    async def hung_start():
        await asyncio.Event().wait()

    case.ctx.browser.lease.return_value.__aenter__.side_effect = hung_start

    async def scenario():
        with pytest.raises(LoginRequired, match="超时"):
            await asyncio.wait_for(case.module.login(case.ctx, LoginOption("oauth")), timeout=2)

    asyncio.run(scenario())
    case.lease.new_page.assert_not_awaited()


def test_linuxdo_expired_state_without_fallback_requires_login(monkeypatch) -> None:
    from unittest.mock import AsyncMock

    from core.errors import LoginRequired
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=False)
    monkeypatch.setattr(case.module, "_logged_in", AsyncMock(return_value=False))

    with pytest.raises(LoginRequired, match="github_fallback"):
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))
    case.lease.restore_state.assert_not_awaited()
    case.lease.mark_authenticated.assert_not_called()


def test_linuxdo_expired_state_falls_back_to_github_and_persists_new_state(monkeypatch) -> None:
    from unittest.mock import AsyncMock

    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True)
    monkeypatch.setattr(case.module, "_logged_in", AsyncMock(return_value=False))
    relogin = AsyncMock(return_value="fresh-linuxdo-state")
    monkeypatch.setattr(case.module, "_github_relogin", relogin)

    result = asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))

    assert result.verified
    assert result.origin == "oauth"
    assert dict(result.credentials) == {"browser_state": "fresh-linuxdo-state"}
    relogin.assert_awaited_once_with(case.ctx, case.lease, case.page, "default")
    case.lease.mark_authenticated.assert_called_once()


def test_linuxdo_github_relogin_requires_shared_github_state(monkeypatch) -> None:
    from unittest.mock import AsyncMock

    from core.errors import LoginRequired
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True, github_state="")
    monkeypatch.setattr(case.module, "_logged_in", AsyncMock(return_value=False))

    with pytest.raises(LoginRequired, match="github:default"):
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))
    case.lease.restore_state.assert_not_awaited()


def test_linuxdo_github_relogin_clicks_entry_and_waits_for_forum(monkeypatch) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True)
    button = SimpleNamespace(click=AsyncMock(), is_visible=AsyncMock(return_value=True))

    async def click_then_land(*_args, **_kwargs):
        # 第一次点击：论坛登录页 → GitHub 授权页；第二次（Authorize）→ 跳回论坛
        if "github.com" in case.page.url:
            case.page.url = "https://linux.do/"
        else:
            case.page.url = "https://github.com/login/oauth/authorize?client_id=x"

    button.click.side_effect = click_then_land
    case.page.wait_for_selector = AsyncMock(return_value=button)
    case.page.query_selector = AsyncMock(return_value=button)
    case.page.url = "https://linux.do/login"
    checks = AsyncMock(side_effect=[False, True])
    monkeypatch.setattr(case.module, "_logged_in", checks)

    state = asyncio.run(case.module._github_relogin(case.ctx, case.lease, case.page, "default"))

    assert state == "fresh-linuxdo-state"
    case.lease.restore_state.assert_awaited_once_with("shared-github-state")
    assert case.lease.goto.await_args_list[0].args[0] == "https://linux.do/login"
    assert button.click.await_count == 2
    case.lease.export_state.assert_awaited_once()


def test_linuxdo_throttled_probe_is_not_reported_as_logged_out() -> None:
    """HTTP 429/5xx 表示「这次问不出来」，不是「登录态失效」。

    CI 实测（run #52、#53）：/session/current.json 连续返回 429（HTML 响应），
    旧实现退回 DOM 判断后直接当成未登录，把限流报成 need_login，反复要求用户
    重新捕获一份其实还好用的登录态。
    """
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from scripts.tasks import linuxdo_browse as browse

    # 429 + HTML 响应体，随后 DOM 也认不出已登录（限流页没有用户头像）。
    page = SimpleNamespace(
        evaluate=AsyncMock(
            side_effect=[
                {"authenticated": False, "status": 429, "format": "html"},
                False,  # _dom_logged_in
            ]
        )
    )
    probe = asyncio.run(browse._session_probe(page))

    assert probe["throttled"] is True, "429 必须被标记为限流"
    assert probe["authenticated"] is False
    assert probe["status"] == 429

    # 服务端明确回答（404 = 匿名）才是真正的未登录，不能算限流。
    # 这一路不该再查 DOM：服务端的 JSON 答复比页面元素权威。
    page.evaluate = AsyncMock(
        return_value={"authenticated": False, "status": 404, "format": "json"}
    )
    anonymous = asyncio.run(browse._session_probe(page))
    assert anonymous["throttled"] is False
    assert anonymous["authenticated"] is False
    assert page.evaluate.await_count == 1, "服务端已明确回答，不该再退回 DOM 判断"


def test_linuxdo_dom_confirmed_login_outranks_transient_status() -> None:
    """限流状态码下 DOM 仍确认已登录时，判定成功且不报限流。"""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from scripts.tasks import linuxdo_browse as browse

    page = SimpleNamespace(
        evaluate=AsyncMock(
            side_effect=[
                {"authenticated": False, "status": 503, "format": "html"},
                True,  # _dom_logged_in：头像在，登录按钮不在
            ]
        )
    )
    probe = asyncio.run(browse._session_probe(page))

    assert probe["authenticated"] is True
    assert probe["throttled"] is False, "已确认登录就不该再报限流"


def test_linuxdo_throttled_login_raises_transient_not_login_required(monkeypatch) -> None:
    """限流时必须报瞬时错误，且不得用 GitHub 重登覆盖可能完好的登录态。"""
    from unittest.mock import AsyncMock

    from core.errors import TransientError
    from core.manifest import LoginOption

    # 即使开了 github_fallback，限流也不该触发重登 —— 我们并不知道旧态坏了。
    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True)
    monkeypatch.setattr(
        case.module,
        "_session_probe",
        AsyncMock(return_value={"authenticated": False, "status": 429, "throttled": True}),
    )
    relogin = AsyncMock(return_value="should-not-be-used")
    monkeypatch.setattr(case.module, "_github_relogin", relogin)

    with pytest.raises(TransientError, match="限流"):
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))

    relogin.assert_not_awaited()
    case.lease.mark_authenticated.assert_not_called()
    # 未确认登录 → 不续存，保留上次可用的登录态。
    case.lease.export_state.assert_not_awaited()


def test_linuxdo_browse_loop_retries_throttling_instead_of_dropping_progress(monkeypatch, linuxdo_run) -> None:
    """刷帖途中被限流时退避重试，不能把已读进度丢成 need_login。"""
    from unittest.mock import AsyncMock

    case = linuxdo_run
    logged_in = {"authenticated": True, "status": 200, "throttled": False}
    throttled = {"authenticated": False, "status": 429, "throttled": True}
    # 第 2 轮撞上限流，退避后恢复，仍应读满 2 篇。
    monkeypatch.setattr(
        case.module,
        "_session_probe",
        AsyncMock(side_effect=[logged_in, throttled, logged_in, logged_in]),
    )
    sleeps: list[float] = []

    async def _record_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(case.module.asyncio, "sleep", _record_sleep)

    outcome = asyncio.run(case.module.run(case.ctx))

    assert outcome.ok, outcome.message
    assert outcome.data["posts_read"] == 2
    assert case.module._THROTTLE_BACKOFF_SECONDS in sleeps, "限流必须退避后重试"


def test_linuxdo_browse_loop_gives_up_on_persistent_throttling_without_need_login(monkeypatch, linuxdo_run) -> None:
    """持续限流时收敛为「未完成」而非「登录失效」，且不误导用户重新捕获登录态。"""
    from unittest.mock import AsyncMock

    case = linuxdo_run
    throttled = {"authenticated": False, "status": 429, "throttled": True}
    monkeypatch.setattr(case.module, "_session_probe", AsyncMock(return_value=throttled))

    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(case.module.asyncio, "sleep", _no_sleep)

    outcome = asyncio.run(case.module.run(case.ctx))

    assert not outcome.ok
    assert outcome.reason != "need_login", "限流不能报成登录失效"
    assert "限流" in outcome.message
    case.ctx.store.put.assert_not_called()


def test_linuxdo_timeout_while_fighting_challenge_is_not_need_login(monkeypatch) -> None:
    """与 Cloudflare 搏斗到预算耗尽 → need_verification，不是 need_login。

    本机实测：ClickSolver 反复报 "Cloudflare iframes not found"，240s 预算耗尽后
    旧实现一律报「登录校验超时 / need_login」，催用户去重新捕获一份其实还好用的
    登录态，真正的阻塞（出口 IP 被 Cloudflare 风控）反而被隐藏。
    """
    from unittest.mock import AsyncMock

    from core.errors import VerificationRequired
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True)

    async def _fight_then_timeout(_ctx, _lease, _page, observed=None):
        # 真实链路：先看到挑战页，随后在求解中耗尽整体预算。
        if observed is not None:
            observed["challenge_seen"] = True
        raise TimeoutError

    monkeypatch.setattr(case.module, "_verify_session", _fight_then_timeout)
    relogin = AsyncMock(return_value="should-not-be-used")
    monkeypatch.setattr(case.module, "_github_relogin", relogin)

    with pytest.raises(VerificationRequired, match="人机验证"):
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))
    relogin.assert_not_awaited()


def test_linuxdo_timeout_without_challenge_still_reports_login_required(monkeypatch) -> None:
    """没见过挑战也没限流时，超时仍按原样报 need_login（不改变既有行为）。"""
    from core.errors import LoginRequired
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=False)

    async def _plain_timeout(_ctx, _lease, _page, observed=None):
        raise TimeoutError

    monkeypatch.setattr(case.module, "_verify_session", _plain_timeout)

    with pytest.raises(LoginRequired, match="超时"):
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))
