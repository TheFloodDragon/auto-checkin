"""模板层：清单继承、声明式执行、响应映射。

「不写一行 Python 就能加一个站点」这句话成立与否，全看这三件事：
- ``extends`` 能继承登录方式、端点、请求头与响应映射；
- ``[response]`` 能让通用驱动读懂响应；
- 声明不全时必须**明确报错**，而不是猜——猜错会造成「显示成功但没到账」。
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
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

        try:
            from playwright._impl._driver import compute_driver_executable
        except ImportError:
            pytest.skip("需 Node.js 或 Playwright 自带运行时执行页面逻辑")

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


def test_linuxdo_reads_full_configured_target_without_random_reduction(linuxdo_run, monkeypatch) -> None:
    case = linuxdo_run
    case.ctx.args["post_count"] = 10
    case.links.return_value = [f"https://linux.do/t/{i}" for i in range(1, 11)]
    monkeypatch.setattr(case.module.random, "randint", lambda low, high: low)
    outcome = asyncio.run(case.module.run(case.ctx))
    assert outcome.ok and outcome.data["target_count"] == outcome.data["posts_read"] == 10
    assert case.opened.await_count == 10
    assert len(set(outcome.data["topic_urls"])) == 10


def test_linuxdo_checkpoint_resumes_only_finished_topics(linuxdo_run) -> None:
    case = linuxdo_run
    case.ctx.args.update(post_count=3, once_per_day=True)
    case.links.side_effect = [["https://linux.do/t/1"], ["https://linux.do/t/2"], []]
    first = asyncio.run(case.module.run(case.ctx))
    assert not first.ok and first.data["posts_read"] == 2
    checkpoint = case.ctx.store.put.call_args.args[1]
    assert checkpoint["completed"] is False
    assert checkpoint["posts_read"] == len(checkpoint["topic_urls"]) == 2

    case.ctx.store.get.return_value = checkpoint
    case.links.side_effect = None
    case.links.return_value = ["https://linux.do/t/1", "https://linux.do/t/2", "https://linux.do/t/3"]
    case.opened.reset_mock()
    second = asyncio.run(case.module.run(case.ctx))
    assert second.ok and second.data["posts_read"] == 3
    assert second.data["reading_seconds"] == 15.0
    case.opened.assert_awaited_once()
    assert case.opened.await_args.args[2] == "https://linux.do/t/3"
    assert case.ctx.store.put.call_args.args[1]["completed"] is True
    assert "本轮实际阅读 1 篇" in second.message


@pytest.mark.parametrize("change", [
    {"date": "2000-01-01"}, {"min_read_seconds": 1}, {"reading_seconds": 1.0},
    {"posts_read": True}, {"topic_urls": ["https://evil.invalid/t/1"]},
    {"posts_read": 2, "reading_seconds": 10.0, "topic_urls": ["https://linux.do/t/1", "https://linux.do/t/topic/1"]},
])
def test_linuxdo_rejects_unverifiable_checkpoints(change) -> None:
    from scripts.tasks import linuxdo_browse as browse

    checkpoint = {"date": browse.business_date(), "posts_read": 1, "min_read_seconds": 3,
                  "reading_seconds": 5.0, "topic_urls": ["https://linux.do/t/1"], **change}
    assert browse._resume_progress(checkpoint, browse.business_date(), 3) is None


def test_linuxdo_completed_smaller_target_does_not_skip_larger_target(linuxdo_run) -> None:
    case = linuxdo_run
    case.ctx.args.update(post_count=2, once_per_day=True)
    case.ctx.store.get.return_value = {"date": case.module.business_date(), "posts_read": 1,
                                       "target_count": 1, "completed": True}
    result = asyncio.run(case.module.run(case.ctx))
    assert result.verdict is Verdict.SUCCESS and result.data["posts_read"] == 2
    assert case.opened.await_count == 2


def test_linuxdo_waits_for_topic_links_before_collecting(monkeypatch) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from scripts.tasks import linuxdo_browse as browse

    page = SimpleNamespace(wait_for_selector=AsyncMock(), evaluate=AsyncMock())

    async def hrefs(*_args):
        page.wait_for_selector.assert_awaited_once()
        return ["https://linux.do/t/topic/1/2", "https://linux.do/t/1", "https://external.invalid/t/2"]

    page.evaluate.side_effect = hrefs
    assert asyncio.run(browse._collect_topic_links(page)) == ["https://linux.do/t/1"]


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
        {"authenticated": False, "status": 404, "throttled": False, "reason": "anonymous"},
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


def test_linuxdo_reading_retains_bezier_motion_and_elapsed_time(monkeypatch) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from scripts.tasks import linuxdo_browse as browse

    page = SimpleNamespace(
        evaluate=AsyncMock(return_value={"w": 1280, "h": 800}),
        mouse=SimpleNamespace(move=AsyncMock(), wheel=AsyncMock(), click=AsyncMock()),
    )
    monkeypatch.setattr(browse.random, "uniform", lambda low, high: low + (high - low) * 0.75)
    elapsed = asyncio.run(browse._simulate_read(page, 0.01))
    points = [call.args for call in page.mouse.move.await_args_list]

    assert len(points) == 9  # 读帖初始落点保留 8 段贝塞尔移动，而不是普通点击的单步定位。
    assert points[0] == (640.0, 400.0)
    midpoint = tuple((start + end) / 2 for start, end in zip(points[0], points[-1]))
    assert points[4] != midpoint
    assert elapsed >= 0.01
    page.mouse.click.assert_not_awaited()


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


def _linuxdo_login_ctx(
    monkeypatch, *, github_fallback: bool, github_state: str = "shared-github-state", sanitize_state: bool = False,
):
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
    if not sanitize_state:
        monkeypatch.setattr(browse, "_shared_browser_state", lambda text: text, raising=False)
    monkeypatch.setattr(browse, "_wait_loaded", AsyncMock(return_value=True))
    # 本组只验证论坛态复用/计数；CF探测及失败路径在专用安全回归中覆盖。
    monkeypatch.setattr(browse, "_is_challenge", AsyncMock(return_value=False))
    return SimpleNamespace(module=browse, ctx=ctx, page=page, lease=lease)


def _linuxdo_snapshot(auth_value, cf_value):
    from browser.state import encode_state

    return encode_state({"cookies": [
        {"name": "_t", "value": auth_value, "domain": ".linux.do", "path": "/", "expires": -1},
        {"name": "cf_clearance", "value": cf_value, "domain": ".linux.do", "path": "/"},
    ], "origins": []})


def _linuxdo_verify_sequence(monkeypatch, case, *steps):
    """只替换验证接缝，保留 _restore_login 的来源选择、预算与写回决策。"""
    from unittest.mock import AsyncMock

    pending = iter(steps)
    observations = []

    async def verify(ctx, lease, page, observed=None):
        assert (ctx, lease, page) == (case.ctx, case.lease, case.page)
        assert observed is case.module._FLOW.get()
        case.lease.mark_authenticated.assert_not_called()
        reason, cleared = next(pending)
        probe = {
            "reason": reason, "authenticated": reason == "authenticated",
            "status": {"authenticated": 200, "rate_limited": 429, "server_error": 503}.get(reason, 404),
            "throttled": reason not in {"authenticated", "anonymous"},
            "format": "empty" if reason == "anonymous" else "json",
        }
        observed.update(session_probe=probe, throttled=probe["throttled"], challenge_active=not cleared)
        observations.append((observed, observed["deadline"]))
        return probe["authenticated"], cleared, probe["throttled"]

    mocked = AsyncMock(side_effect=verify)
    monkeypatch.setattr(case.module, "_verify_session", mocked)
    return mocked, observations


@pytest.mark.parametrize("github_fallback", [False, True])
def test_linuxdo_expired_account_state_retries_named_shared_state(monkeypatch, github_fallback):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from browser.state import decode_state
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=github_fallback, sanitize_state=True)
    cached = _linuxdo_snapshot("synthetic-expired-auth-secret", "synthetic-old-cf-secret")
    shared = _linuxdo_snapshot("synthetic-shared-auth-secret", "synthetic-shared-cf-secret")
    case.ctx.credentials.browser_state = cached
    case.ctx.args["account"] = "secondary"
    case.ctx.deadline = SimpleNamespace(remaining=Mock(return_value=95))
    case.ctx.oauth_state.side_effect = lambda provider, account: shared if (provider, account) == (
        "linuxdo", "secondary"
    ) else ""
    verify, observations = _linuxdo_verify_sequence(
        monkeypatch, case, ("anonymous", True), ("authenticated", True),
    )
    github = AsyncMock(side_effect=AssertionError("同账号共享会话有效时不应走 GitHub"))
    monkeypatch.setattr(case.module, "_github_relogin", github)

    result = asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))

    assert result.verified is True
    assert result.origin == "browser"
    assert dict(result.credentials) == {}, "共享恢复由 browser service 收尾续存，不伪造 OAuth 新凭据"
    case.ctx.browser.lease.assert_called_once_with(
        reason="linuxdo_login", state_text=case.module._shared_browser_state(cached),
    )
    case.ctx.oauth_state.assert_called_once_with("linuxdo", "secondary")
    case.lease.restore_state.assert_awaited_once_with(case.module._shared_browser_state(shared))
    restored = decode_state(case.lease.restore_state.await_args.args[0])
    assert [(cookie["name"], cookie["value"]) for cookie in restored["cookies"]] == [
        ("_t", "synthetic-shared-auth-secret")
    ]
    assert verify.await_count == 2
    assert observations[0][0] is observations[1][0]
    assert observations[0][1] == observations[1][1], "共享恢复必须沿用同一总 deadline"
    case.ctx.deadline.remaining.assert_called_once()
    case.lease.mark_authenticated.assert_called_once()
    case.lease.export_state.assert_not_awaited()
    case.lease.oauth.assert_not_awaited()
    github.assert_not_awaited()
    assert case.ctx.credentials.browser_state == cached
    assert decode_state(shared)["cookies"][1]["value"] == "synthetic-shared-cf-secret"
    diagnostics = str(case.ctx.log.call_args_list)
    for secret in ("synthetic-expired-auth-secret", "synthetic-shared-auth-secret",
                   "synthetic-old-cf-secret", "synthetic-shared-cf-secret"):
        assert secret not in diagnostics


@pytest.mark.parametrize("shared_cf", ["old-cf", "different-cf"])
def test_linuxdo_shared_retry_deduplicates_state_after_removing_cf(monkeypatch, shared_cf):
    from core.errors import LoginRequired
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=False, sanitize_state=True)
    case.ctx.credentials.browser_state = _linuxdo_snapshot("same-auth", "old-cf")
    case.ctx.oauth_state.side_effect = None
    case.ctx.oauth_state.return_value = _linuxdo_snapshot("same-auth", shared_cf)
    verify, _ = _linuxdo_verify_sequence(monkeypatch, case, ("anonymous", True))

    with pytest.raises(LoginRequired):
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))

    case.ctx.oauth_state.assert_called_once_with("linuxdo", "default")
    assert verify.await_count == 1, "只有 CF Cookie 不同的共享快照不值得重试"
    case.lease.restore_state.assert_not_awaited()
    case.lease.mark_authenticated.assert_not_called()
    case.lease.export_state.assert_not_awaited()


@pytest.mark.parametrize("reason,cleared,error_name", [
    ("unexpected_response", True, "TransientError"),
    ("rate_limited", True, "TransientError"),
    ("server_error", True, "TransientError"),
    ("challenge", True, "TransientError"),
    ("anonymous", False, "VerificationRequired"),
])
def test_linuxdo_uncertain_account_state_never_retries_shared_or_github(monkeypatch, reason, cleared, error_name):
    from unittest.mock import AsyncMock

    from core import errors
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True, sanitize_state=True)
    case.ctx.credentials.browser_state = _linuxdo_snapshot("maybe-valid-auth", "old-cf")
    case.ctx.oauth_state.side_effect = None
    case.ctx.oauth_state.return_value = _linuxdo_snapshot("another-auth", "new-cf")
    verify, _ = _linuxdo_verify_sequence(monkeypatch, case, (reason, cleared))
    github = AsyncMock()
    monkeypatch.setattr(case.module, "_github_relogin", github)

    with pytest.raises(getattr(errors, error_name)):
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))

    assert verify.await_count == 1
    case.ctx.oauth_state.assert_not_called()
    case.lease.restore_state.assert_not_awaited()
    case.lease.mark_authenticated.assert_not_called()
    case.lease.export_state.assert_not_awaited()
    github.assert_not_awaited()


@pytest.mark.parametrize("reason,cleared,error_name", [
    ("anonymous", True, "LoginRequired"),
    ("unexpected_response", True, "TransientError"),
    ("rate_limited", True, "TransientError"),
    ("anonymous", False, "VerificationRequired"),
])
def test_linuxdo_failed_shared_retry_never_marks_or_persists_login(monkeypatch, reason, cleared, error_name):
    from unittest.mock import AsyncMock

    from core import errors
    from core.manifest import LoginOption

    # 再验无法判定/挑战失败时，即使开启 GitHub 也不能继续覆盖共享登录态。
    case = _linuxdo_login_ctx(
        monkeypatch, github_fallback=reason != "anonymous" or not cleared, sanitize_state=True,
    )
    github = AsyncMock(side_effect=AssertionError("共享态再验未知时不能 GitHub 回退"))
    monkeypatch.setattr(case.module, "_github_relogin", github)
    case.ctx.credentials.browser_state = _linuxdo_snapshot("expired-account-auth", "old-cf")
    shared = _linuxdo_snapshot("unverified-shared-auth", "new-cf")
    case.ctx.oauth_state.side_effect = None
    case.ctx.oauth_state.return_value = shared
    verify, observations = _linuxdo_verify_sequence(monkeypatch, case, ("anonymous", True), (reason, cleared))

    with pytest.raises(getattr(errors, error_name)):
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))

    case.lease.restore_state.assert_awaited_once_with(case.module._shared_browser_state(shared))
    assert verify.await_count == 2
    assert observations[0][1] == observations[1][1]
    case.lease.mark_authenticated.assert_not_called()
    case.lease.export_state.assert_not_awaited()
    github.assert_not_awaited()


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
    # 真正的登录失效：探测已识别 Discourse 的明确匿名响应（例如 404 空正文，非 CF 拦截）。
    monkeypatch.setattr(
        case.module, "_session_probe",
        AsyncMock(return_value={"authenticated": False, "status": 404, "throttled": False, "reason": "anonymous"}),
    )
    monkeypatch.setattr(case.module, "_logged_in", AsyncMock(return_value=False))

    with pytest.raises(LoginRequired, match="github_fallback"):
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))
    case.lease.restore_state.assert_not_awaited()
    case.lease.mark_authenticated.assert_not_called()


def test_linuxdo_expired_state_falls_back_to_github_and_persists_new_state(monkeypatch) -> None:
    from unittest.mock import AsyncMock

    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True)
    # 真正的登录失效：已确认匿名协议，区别于 404 HTML 或任意 JSON 缺用户的未知响应。
    monkeypatch.setattr(
        case.module, "_session_probe",
        AsyncMock(return_value={"authenticated": False, "status": 404, "throttled": False, "reason": "anonymous"}),
    )
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
    # 真正的登录失效：服务端响应满足明确匿名协议。
    monkeypatch.setattr(
        case.module, "_session_probe",
        AsyncMock(return_value={"authenticated": False, "status": 404, "throttled": False, "reason": "anonymous"}),
    )
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


_LINUXDO_PROBE_HARNESS = r"""
const vm = require('node:vm');
const fs = require('node:fs');
const {source, scenario} = JSON.parse(fs.readFileSync(0, 'utf8'));
const requests = [], timers = new Set();
let textReads = 0;
class FakeHeaders {
    constructor(values = {}) {
        this.values = new Map(Object.entries(values).map(([key, value]) => [key.toLowerCase(), String(value)]));
    }
    get(key) { return this.values.get(key.toLowerCase()) ?? null; }
}
class FakeResponse {
    constructor() {
        this.status = scenario.status ?? 200;
        this.ok = this.status >= 200 && this.status < 300;
        this.redirected = scenario.redirected ?? false;
        this.url = scenario.response_url ?? 'https://linux.do/session/current.json';
        this.headers = new FakeHeaders({
            'content-type': scenario.content_type ?? 'application/json; charset=utf-8',
            'set-cookie': '_t=synthetic-response-cookie-secret', ...scenario.headers,
        });
    }
    async text() { textReads++; return scenario.text ?? ''; }
}
const location = new URL(scenario.location ?? 'https://linux.do/latest');
const sandbox = {
    URL, AbortController, Response: FakeResponse, Headers: FakeHeaders, location,
    window: {location}, document: {cookie: '_t=synthetic-browser-cookie-secret'},
    setTimeout(callback, delay) {
        const timer = setTimeout(callback, delay); timers.add(timer); return timer;
    },
    clearTimeout(timer) { clearTimeout(timer); timers.delete(timer); },
    async fetch(url, options) {
        requests.push({url: String(url), credentials: options.credentials, cache: options.cache,
            headers: options.headers, method: options.method ?? 'GET'});
        if (scenario.error) {
            const error = new Error('synthetic-network-error-secret');
            error.name = scenario.error;
            throw error;
        }
        return new FakeResponse();
    },
};
(async () => {
    const probe = await vm.runInNewContext('(' + source + ')()', sandbox, {timeout: 1000});
    process.stdout.write(JSON.stringify({probe, requests, textReads, pendingTimers: timers.size}));
})().catch(error => { process.stderr.write(String(error)); process.exitCode = 1; });
"""


@pytest.fixture(scope="module")
def linuxdo_probe_js():
    from playwright._impl._driver import compute_driver_executable

    from scripts.tasks import linuxdo_browse as browse

    node = Path(compute_driver_executable()[0])
    assert node.is_file(), "Playwright 自带 Node 必须可用，不能跳过真实 JavaScript 回归"

    def run(**scenario):
        result = subprocess.run(
            [str(node), "-e", _LINUXDO_PROBE_HARNESS],
            input=json.dumps({"source": browse._SESSION_PROBE_SCRIPT, "scenario": scenario}),
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    return run


@pytest.mark.parametrize("scenario,reason,fmt", [
    pytest.param({"text": json.dumps({"current_user": {
        "id": 23, "username": "synthetic-profile-secret", "email": "synthetic-email-secret",
    }})}, "authenticated", "json", id="positive-integer-user"),
    pytest.param({"status": 404, "text": ""}, "anonymous", "empty", id="empty-404"),
    pytest.param({"status": 404, "text": "", "headers": {"server": "cloudflare"}},
                 "anonymous", "empty", id="cloudflare-proxy-is-not-challenge"),
    pytest.param({"status": 404, "text": "   \n"}, "unexpected_response", "empty", id="whitespace-404"),
    pytest.param({"status": 404, "text": "<html>synthetic-body-secret</html>", "content_type": "text/html"},
                 "unexpected_response", "html", id="html-404"),
    pytest.param({"status": 404, "text": '{"errors":["synthetic-body-secret"]}'},
                 "unexpected_response", "json", id="arbitrary-json-404"),
    pytest.param({"text": ""}, "unexpected_response", "empty", id="empty-200"),
    pytest.param({"text": '{"message":"synthetic-body-secret"}'},
                 "unexpected_response", "json", id="missing-current-user"),
    pytest.param({"text": '{"current_user":null}'}, "anonymous", "json", id="explicit-null-user"),
    pytest.param({"status": 403, "text": '{"error_type":"not_logged_in"}'},
                 "anonymous", "json", id="explicit-not-logged-in"),
    pytest.param({"status": 429, "text": '{"current_user":null,"error_type":"not_logged_in"}'},
                 "rate_limited", "json", id="json-429"),
    pytest.param({"status": 503, "text": '{"current_user":null,"error_type":"not_logged_in"}'},
                 "server_error", "json", id="json-503"),
    pytest.param({"status": 503, "text": '{"current_user":{"id":23}}'},
                 "server_error", "json", id="error-status-outranks-user"),
    pytest.param({"status": 404, "text": "", "headers": {"CF-Mitigated": "challenge"}},
                 "challenge", "empty", id="empty-404-challenge-header"),
    pytest.param({"text": '{"current_user":{"id":23}}', "headers": {"cf-mitigated": "challenge"}},
                 "challenge", "json", id="challenge-header-outranks-user"),
    pytest.param({"status": 404, "text": "<html><title>Just a moment...</title></html>"},
                 "challenge", "html", id="challenge-title"),
    pytest.param({"status": 403, "text": "window._cf_chl_opt = {}; synthetic-body-secret"},
                 "challenge", "text", id="challenge-body-marker"),
    pytest.param({"location": "https://github.com/login"}, "wrong_origin", "wrong_origin", id="github-page"),
    pytest.param({"location": "https://linux.do.evil.invalid/latest"},
                 "wrong_origin", "wrong_origin", id="lookalike-origin"),
    pytest.param({"location": "http://linux.do/latest"}, "wrong_origin", "wrong_origin", id="http-origin"),
    pytest.param({"status": 404, "text": "", "redirected": True},
                 "unexpected_response", "empty", id="redirected-empty-404"),
    pytest.param({"text": '{"current_user":{"id":23}}', "redirected": True,
                  "response_url": "https://github.com/synthetic-response-url-secret"},
                 "unexpected_response", "json", id="redirected-user-response"),
    pytest.param({"status": 404, "response_url": "https://linux.do/login"},
                 "unexpected_response", "empty", id="different-response-path"),
    pytest.param({"error": "TypeError"}, "network_error", "network_error", id="network-failure"),
    pytest.param({"error": "AbortError"}, "network_error", "timeout", id="request-timeout"),
])
def test_linuxdo_real_session_probe_classification(linuxdo_probe_js, scenario, reason, fmt):
    """运行待发布的 JS，再将真实结果交回 Python；不是用预造字典绕过协议判断。"""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from scripts.tasks import linuxdo_browse as browse

    output = linuxdo_probe_js(**scenario)
    raw = output["probe"]
    expected_status = 0 if "error" in scenario or reason == "wrong_origin" else scenario.get("status", 200)
    assert raw["authenticated"] is (reason == "authenticated")
    assert raw["anonymous"] is (reason == "anonymous")
    assert raw["status"] == expected_status
    assert raw["format"] == fmt
    assert output["pendingTimers"] == 0
    if reason == "wrong_origin":
        assert output["requests"] == [], "非 LinuxDO 页面不能携凭据发起会话请求"
        assert output["textReads"] == 0
    else:
        assert output["requests"] == [{
            "url": "https://linux.do/session/current.json", "credentials": "include", "cache": "no-store",
            "headers": {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest",
                        "Discourse-Present": "true"}, "method": "GET",
        }]
        assert output["textReads"] == (0 if "error" in scenario else 1)
        if "error" not in scenario:
            assert raw["body_length"] == len(scenario.get("text", ""))
            assert raw["challenged"] is (reason == "challenge")
            assert raw["content_type"] == scenario.get("content_type", "application/json")
    assert set(raw) <= {
        "authenticated", "anonymous", "status", "format", "challenged", "same_endpoint",
        "body_length", "content_type",
    }, "JS 只能返回脱敏诊断元数据，不能带正文/用户资料/Cookie/URL"

    page = SimpleNamespace(evaluate=AsyncMock(side_effect=[raw, False]))
    log = Mock()
    probe = asyncio.run(browse._session_probe(page, log))
    assert probe["reason"] == reason
    assert probe["authenticated"] is (reason == "authenticated")
    assert probe["throttled"] is (reason not in {"authenticated", "anonymous"})
    assert probe["status"] == expected_status
    assert probe["format"] == fmt
    assert page.evaluate.await_args_list[0].args == (browse._SESSION_PROBE_SCRIPT,)
    assert page.evaluate.await_count == (1 if reason in {"authenticated", "anonymous", "wrong_origin"} else 2)
    summary = browse._probe_summary(probe)
    assert f"HTTP {expected_status}" in summary
    assert f"format={fmt}" in summary
    if "body_length" in raw:
        assert f"body_length={raw['body_length']}" in summary
    log.assert_called_once_with("LinuxDO 会话校验：" + summary)
    diagnostics = json.dumps([raw, probe, summary, log.call_args.args], ensure_ascii=False)
    for secret in ("synthetic-body-secret", "synthetic-profile-secret", "synthetic-email-secret",
                   "synthetic-browser-cookie-secret", "synthetic-response-cookie-secret",
                   "synthetic-response-url-secret", "synthetic-network-error-secret"):
        assert secret not in diagnostics
    assert not ({"body", "text", "current_user", "cookie", "url", "headers"} & set(probe))
    if reason == "unexpected_response" and expected_status == 404:
        assert all(word not in summary for word in ("429", "5xx", "限流"))


@pytest.mark.parametrize("user_id", [0, -1, "23", True, False, None, 1.5, {}, []])
def test_linuxdo_session_probe_rejects_nonpositive_or_noninteger_user_id(linuxdo_probe_js, user_id):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from scripts.tasks import linuxdo_browse as browse

    raw = linuxdo_probe_js(text=json.dumps({"current_user": {"id": user_id}}))["probe"]
    assert raw["authenticated"] is False
    assert raw["anonymous"] is False
    probe = asyncio.run(browse._session_probe(SimpleNamespace(evaluate=AsyncMock(side_effect=[raw, False]))))
    assert probe["reason"] == "unexpected_response"
    assert probe["throttled"] is True


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

    # JS 已识别到明确的匿名协议才算未登录；任意 404 JSON 缺 current_user 不足以确认。
    # 这一路不该再查 DOM：明确的服务端匿名答复比页面元素权威。
    page.evaluate = AsyncMock(
        return_value={"authenticated": False, "anonymous": True, "status": 404, "format": "json"}
    )
    anonymous = asyncio.run(browse._session_probe(page))
    assert anonymous["throttled"] is False
    assert anonymous["authenticated"] is False
    assert page.evaluate.await_count == 1, "服务端已明确回答，不该再退回 DOM 判断"


def test_linuxdo_cf_challenged_xhr_is_indeterminate_not_logged_out() -> None:
    """缺少明确匿名/挑战证据的 HTML 错误与网络失败只能判为未知。

    不能只凭 403/404 或非 JSON 就归因 Cloudflare，也不能据此触发覆盖旧态的回退。
    """
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from scripts.tasks import linuxdo_browse as browse

    for status, fmt in ((404, "html"), (403, "html"), (0, "TypeError")):
        page = SimpleNamespace(
            evaluate=AsyncMock(
                side_effect=[
                    {"authenticated": False, "status": status, "format": fmt},
                    False,  # _dom_logged_in：linux.do 自定义主题下拿不到用户节点
                ]
            )
        )
        probe = asyncio.run(browse._session_probe(page))
        assert probe["throttled"] is True, f"{status} {fmt} 应判为无法判定，而非确认未登录"
        assert probe["authenticated"] is False
        assert probe["status"] == status


@pytest.mark.parametrize("reasons,expected", [
    pytest.param(["anonymous", "anonymous"], (False, True, False), id="anonymous-needs-two-confirmations"),
    pytest.param(["anonymous", "authenticated"], (True, True, False), id="first-anonymous-can-recover"),
    pytest.param(["unexpected_response", "anonymous", "authenticated"],
                 (True, True, False), id="single-anonymous-after-unknown-is-not-final"),
    pytest.param(["unexpected_response"] * 3, (False, True, True), id="unknown-has-bounded-retries"),
    pytest.param(["rate_limited"] * 3, (False, True, True), id="rate-limit-has-bounded-retries"),
    pytest.param(["unexpected_response", "unexpected_response", "anonymous"],
                 (False, True, True), id="last-single-anonymous-is-unconfirmed"),
    pytest.param(["anonymous", "unexpected_response", "anonymous"],
                 (False, True, True), id="unknown-resets-anonymous-confirmations"),
])
def test_linuxdo_verify_session_records_probe_without_final_sleep_or_navigation(monkeypatch, reasons, expected):
    from unittest.mock import AsyncMock

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=False)
    probes = [{
        "reason": reason, "authenticated": reason == "authenticated",
        "status": {"authenticated": 200, "rate_limited": 429}.get(reason, 404),
        "throttled": reason not in {"authenticated", "anonymous"},
        "format": "empty" if reason == "anonymous" else "json",
    } for reason in reasons]
    probe = AsyncMock(side_effect=probes)
    sleep = AsyncMock()
    goto = AsyncMock()
    monkeypatch.setattr(case.module, "_session_probe", probe)
    monkeypatch.setattr(case.module, "_safe_goto", goto)
    monkeypatch.setattr(case.module.asyncio, "sleep", sleep)
    observed = {}

    result = asyncio.run(case.module._verify_session(case.ctx, case.lease, case.page, observed))

    assert result == expected
    assert probe.await_count == len(probes)
    last_probe = probes[-1]
    if reasons[-1] == "anonymous" and expected[2]:
        last_probe = {**last_probe, "throttled": True, "reason": "anonymous_unconfirmed"}
    assert observed["session_probe"] == last_probe
    assert goto.await_count == len(probes), "最终判断后不能再导航一次而不验证"
    assert sleep.await_count == len(probes) - 1, "最后一次判断不再消耗 sleep 预算"
    assert [call.args[0] for call in sleep.await_args_list] == [
        6.0 if probe["throttled"] else 1.5 for probe in probes[:-1]
    ]


def test_linuxdo_reappearing_challenge_resets_anonymous_confirmations(monkeypatch):
    from unittest.mock import AsyncMock

    from core.errors import TransientError
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True, sanitize_state=True)
    case.ctx.credentials.browser_state = _linuxdo_snapshot("synthetic-auth", "synthetic-cf")
    anonymous = {"authenticated": False, "status": 404, "throttled": False, "reason": "anonymous"}
    authenticated = {"authenticated": True, "status": 200, "throttled": False, "reason": "authenticated"}
    probe = AsyncMock(side_effect=[anonymous, authenticated, anonymous])
    challenge = AsyncMock(side_effect=[False, True, False])
    github = AsyncMock()
    monkeypatch.setattr(case.module, "_session_probe", probe)
    monkeypatch.setattr(case.module, "_clear_challenge", AsyncMock(return_value=True))
    monkeypatch.setattr(case.module, "_is_challenge", challenge)
    monkeypatch.setattr(case.module, "_safe_goto", AsyncMock())
    monkeypatch.setattr(case.module.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(case.module, "_github_relogin", github)

    with pytest.raises(TransientError) as caught:
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))

    assert probe.await_count == challenge.await_count == 3
    final_probe = caught.value.data["session_probe"]
    assert final_probe["reason"] == "anonymous_unconfirmed"
    assert final_probe["throttled"] is True
    case.ctx.oauth_state.assert_not_called()
    case.lease.restore_state.assert_not_awaited()
    case.lease.mark_authenticated.assert_not_called()
    case.lease.export_state.assert_not_awaited()
    github.assert_not_awaited()


@pytest.mark.parametrize("scenario,reason", [
    pytest.param({"status": 404, "text": "<html>Not Found</html>", "content_type": "text/html"},
                 "unexpected_response", id="non-json-404"),
    pytest.param({"status": 429, "text": '{"error_type":"not_logged_in"}'},
                 "rate_limited", id="json-429"),
])
def test_linuxdo_unknown_real_response_preserves_state_without_fallback(monkeypatch, linuxdo_probe_js, scenario, reason):
    from unittest.mock import AsyncMock

    from core.errors import TransientError
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True, sanitize_state=True)
    case.ctx.credentials.browser_state = _linuxdo_snapshot("synthetic-auth-secret", "synthetic-cf-secret")
    raw = linuxdo_probe_js(**scenario)["probe"]
    case.page.evaluate = AsyncMock(side_effect=[raw, False] * 3)
    monkeypatch.setattr(case.module.asyncio, "sleep", AsyncMock())
    github = AsyncMock()
    monkeypatch.setattr(case.module, "_github_relogin", github)

    with pytest.raises(TransientError) as caught:
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))

    evidence = caught.value.data
    assert evidence["session_probe"]["reason"] == reason
    assert evidence["session_probe"]["status"] == scenario["status"]
    assert case.page.evaluate.await_count == 6
    case.ctx.oauth_state.assert_not_called()
    case.lease.restore_state.assert_not_awaited()
    case.lease.mark_authenticated.assert_not_called()
    case.lease.export_state.assert_not_awaited()
    github.assert_not_awaited()
    diagnostics = json.dumps([str(caught.value), evidence, str(case.ctx.log.call_args_list)], ensure_ascii=False)
    for secret in ("synthetic-auth-secret", "synthetic-cf-secret"):
        assert secret not in diagnostics
    if reason == "unexpected_response":
        assert all(word not in diagnostics for word in ("429", "5xx", "限流")), "404 未知不能假报限流"


def test_linuxdo_cf_failure_reloads_and_retries_within_budget(monkeypatch) -> None:
    """CF 本轮未放行时，在预算内重载换一张新挑战重试，而不是一次失败就放弃。"""
    import time as _time
    from unittest.mock import AsyncMock

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=False)
    browse = case.module
    clear = AsyncMock(side_effect=[False, True])  # 第 1 轮不过、重载后第 2 轮通过
    monkeypatch.setattr(browse, "_clear_challenge", clear)
    monkeypatch.setattr(browse, "_wait_loaded", AsyncMock(return_value=True))
    monkeypatch.setattr(browse, "_is_challenge", AsyncMock(return_value=False))
    monkeypatch.setattr(
        browse, "_session_probe",
        AsyncMock(return_value={"authenticated": True, "status": 200, "throttled": False}),
    )
    gotos: list[str] = []

    async def fake_goto(_lease, _page, url):
        gotos.append(url)

    monkeypatch.setattr(browse, "_safe_goto", fake_goto)
    monkeypatch.setattr(browse.asyncio, "sleep", AsyncMock())

    notes = {"deadline": _time.monotonic() + 200, "log": case.ctx.log}
    verified, cleared, throttled = asyncio.run(
        browse._verify_session(case.ctx, case.lease, case.page, notes)
    )

    assert verified is True and cleared is True and throttled is False
    assert clear.await_count == 2, "首轮 CF 未过应重载后再试"
    assert gotos.count("https://linux.do/latest") >= 2, "应重载页面换新挑战"


def test_linuxdo_cf_failure_gives_up_after_bounded_reloads(monkeypatch) -> None:
    """CF 始终不放行时，重载重试有界收敛为未通过，不无限循环。"""
    import time as _time
    from unittest.mock import AsyncMock

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=False)
    browse = case.module
    clear = AsyncMock(return_value=False)  # 始终不过
    monkeypatch.setattr(browse, "_clear_challenge", clear)
    monkeypatch.setattr(browse, "_session_probe", AsyncMock(side_effect=AssertionError("CF 未过不应探测会话")))
    gotos: list[str] = []

    async def fake_goto(_lease, _page, url):
        gotos.append(url)

    monkeypatch.setattr(browse, "_safe_goto", fake_goto)
    monkeypatch.setattr(browse.asyncio, "sleep", AsyncMock())

    notes = {"deadline": _time.monotonic() + 200, "log": case.ctx.log}
    verified, cleared, throttled = asyncio.run(
        browse._verify_session(case.ctx, case.lease, case.page, notes)
    )

    assert verified is False and cleared is False
    assert clear.await_count == 3, "最多尝试 3 轮 CF"
    assert gotos.count("https://linux.do/latest") == 3, "初次导航 + 2 次重载"


def test_linuxdo_cf_circuit_open_stops_reload_and_preserves_login_state(monkeypatch) -> None:
    """有限 CF 失败预算耗尽后不再重载制造新挑战，也不触发会话回退。"""
    import time as _time
    from unittest.mock import AsyncMock

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True)
    browse = case.module
    monkeypatch.setattr(browse, "_is_challenge", AsyncMock(return_value=True))
    gotos: list[str] = []

    async def fake_goto(_lease, _page, url):
        gotos.append(url)

    async def circuit_open(_page, _log, notes, stage):
        notes.update(
            challenge_seen=True,
            challenge_active=True,
            cf_diagnostics={"stage": stage, "reason": "circuit_open"},
        )
        return False

    monkeypatch.setattr(browse, "_safe_goto", fake_goto)
    monkeypatch.setattr(browse, "_clear_challenge", circuit_open)
    monkeypatch.setattr(browse, "_session_probe", AsyncMock(side_effect=AssertionError("熔断后不应探测会话")))
    notes = {"deadline": _time.monotonic() + 200, "log": case.ctx.log}

    verified, cleared, throttled = asyncio.run(
        browse._verify_session(case.ctx, case.lease, case.page, notes)
    )

    assert (verified, cleared, throttled) == (False, False, False)
    assert gotos == ["https://linux.do/latest"], "熔断后不应再次重载页面"
    assert notes["stage"] == "session_cf_circuit_open"
    assert notes["cf_diagnostics"]["reason"] == "circuit_open"


def test_linuxdo_cf_reload_rejected_is_verification_not_raw_error(monkeypatch) -> None:
    """重载挑战页被 CF 直接拒绝（NS_ERROR_NET_ERROR_RESPONSE）时收敛为人机验证未通过。"""
    import time as _time
    from unittest.mock import AsyncMock

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=False)
    browse = case.module
    monkeypatch.setattr(browse, "_clear_challenge", AsyncMock(return_value=False))
    calls: list[str] = []

    async def fake_goto(_lease, _page, url):
        calls.append(url)
        if len(calls) > 1:
            raise RuntimeError("Page.goto: NS_ERROR_NET_ERROR_RESPONSE\nCall log:\n  - navigating")

    monkeypatch.setattr(browse, "_safe_goto", fake_goto)
    monkeypatch.setattr(browse.asyncio, "sleep", AsyncMock())

    notes = {"deadline": _time.monotonic() + 200, "log": case.ctx.log}
    verified, cleared, _ = asyncio.run(
        browse._verify_session(case.ctx, case.lease, case.page, notes)
    )

    assert verified is False and cleared is False
    assert notes["cf_diagnostics"]["reason"] == "reload_rejected"
    assert "Call log" not in notes["cf_diagnostics"]["error"]


def test_net_error_response_is_transport_error() -> None:
    from browser import runtime_loop

    assert runtime_loop.is_network_transport_error("Page.goto: NS_ERROR_NET_ERROR_RESPONSE")


def test_linuxdo_cf_reload_skips_when_budget_too_low(monkeypatch) -> None:
    """剩余预算不足时不再重载重试，直接收敛，避免耗尽预算。"""
    import time as _time
    from unittest.mock import AsyncMock

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=False)
    browse = case.module
    clear = AsyncMock(return_value=False)
    monkeypatch.setattr(browse, "_clear_challenge", clear)
    monkeypatch.setattr(browse, "_safe_goto", AsyncMock())
    monkeypatch.setattr(browse.asyncio, "sleep", AsyncMock())

    notes = {"deadline": _time.monotonic() + 5, "log": case.ctx.log}  # 预算仅 5s < 20s 门槛
    verified, cleared, _ = asyncio.run(
        browse._verify_session(case.ctx, case.lease, case.page, notes)
    )

    assert verified is False and cleared is False
    assert clear.await_count == 1, "预算不足时不重载重试"


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


@pytest.mark.parametrize("reason,expected", [
    ("unexpected_response", "unconfirmed"), ("challenge", "need_verification"),
])
def test_linuxdo_single_post_retains_probe_when_outer_retries_exhaust(monkeypatch, linuxdo_run, reason, expected):
    from unittest.mock import AsyncMock

    case = linuxdo_run
    case.ctx.args["post_count"] = 1
    probe = {"authenticated": False, "status": 404, "throttled": True, "reason": reason,
             "format": "html", "body_length": 100}
    check = AsyncMock(return_value=probe)
    sleep = AsyncMock()
    monkeypatch.setattr(case.module, "_session_probe", check)
    monkeypatch.setattr(case.module.asyncio, "sleep", sleep)

    outcome = asyncio.run(case.module.run(case.ctx))

    assert not outcome.ok
    assert outcome.reason == expected
    assert outcome.data["session_probe"] == probe
    assert outcome.data["posts_read"] == 0
    assert check.await_count == 2
    sleep.assert_awaited_once_with(case.module._THROTTLE_BACKOFF_SECONDS)
    assert "没有足够" not in outcome.message
    assert "限流" not in outcome.message
    if reason == "unexpected_response":
        assert "HTTP 404" in outcome.message
    case.opened.assert_not_awaited()
    case.lease.mark_authenticated.assert_not_called()
    case.ctx.store.put.assert_not_called()


@pytest.mark.parametrize("timeout_at", ["sleep", "reload"])
def test_linuxdo_first_anonymous_recheck_timeout_never_falls_back(monkeypatch, linuxdo_probe_js, timeout_at):
    from unittest.mock import AsyncMock

    from core.errors import TransientError
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True, sanitize_state=True)
    case.ctx.credentials.browser_state = _linuxdo_snapshot("synthetic-account-auth", "synthetic-account-cf")
    raw = linuxdo_probe_js(status=404, text="")["probe"]
    case.page.evaluate = AsyncMock(return_value=raw)
    goto = AsyncMock(side_effect=[None, TimeoutError] if timeout_at == "reload" else None)
    sleep = AsyncMock(side_effect=TimeoutError if timeout_at == "sleep" else None)
    github = AsyncMock()
    monkeypatch.setattr(case.module, "_safe_goto", goto)
    monkeypatch.setattr(case.module.asyncio, "sleep", sleep)
    monkeypatch.setattr(case.module, "_github_relogin", github)

    with pytest.raises(TransientError) as caught:
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))

    probe = caught.value.data["session_probe"]
    assert probe["reason"] == "anonymous_unconfirmed"
    assert probe["status"] == 404
    assert probe["throttled"] is True
    case.page.evaluate.assert_awaited_once_with(case.module._SESSION_PROBE_SCRIPT)
    sleep.assert_awaited_once_with(1.5)
    assert goto.await_count == (2 if timeout_at == "reload" else 1)
    case.ctx.oauth_state.assert_not_called()
    case.lease.restore_state.assert_not_awaited()
    case.lease.mark_authenticated.assert_not_called()
    case.lease.export_state.assert_not_awaited()
    github.assert_not_awaited()
    assert all(word not in str(caught.value) for word in ("429", "5xx", "限流"))


def test_linuxdo_shared_restore_timeout_discards_previous_anonymous_evidence(monkeypatch):
    from unittest.mock import AsyncMock

    from core.errors import TransientError
    from core.manifest import LoginOption

    case = _linuxdo_login_ctx(monkeypatch, github_fallback=True, sanitize_state=True)
    case.ctx.credentials.browser_state = _linuxdo_snapshot("expired-account-auth", "old-cf")
    shared = _linuxdo_snapshot("unverified-shared-auth", "new-cf")
    case.ctx.oauth_state.side_effect = None
    case.ctx.oauth_state.return_value = shared
    verify, observations = _linuxdo_verify_sequence(monkeypatch, case, ("anonymous", True))
    case.lease.restore_state.side_effect = TimeoutError
    github = AsyncMock()
    monkeypatch.setattr(case.module, "_github_relogin", github)

    with pytest.raises(TransientError) as caught:
        asyncio.run(case.module.login(case.ctx, LoginOption("oauth")))

    case.lease.restore_state.assert_awaited_once_with(case.module._shared_browser_state(shared))
    assert verify.await_count == 1, "快照恢复未完成，不能声称已验证新快照"
    assert observations[0][0]["throttled"] is True
    evidence = caught.value.data
    assert evidence["timeout_stage"] == "shared_state_restore"
    assert "session_probe" not in evidence, "恢复超时不能沿用旧账号快照的匿名/404 证据"
    assert "404" not in str(caught.value)
    case.lease.mark_authenticated.assert_not_called()
    case.lease.export_state.assert_not_awaited()
    github.assert_not_awaited()


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


@pytest.mark.parametrize("module_name", ["newapi", "sub2api"])
@pytest.mark.parametrize("value,expected", [
    (True, True), (False, False), (1, True), (0, False),
    ("true", True), ("false", False), ("1", True), ("0", False),
    ("unknown", None), ([], None), ({"value": True}, None),
])
def test_builtin_checkin_state_uses_boolean_values_not_truthiness(module_name, value, expected):
    from importlib import import_module
    from types import SimpleNamespace
    from unittest.mock import Mock

    module = import_module(f"templates.builtin.{module_name}")
    ctx = SimpleNamespace(
        http=SimpleNamespace(get=Mock(return_value={"checked_in_today": value})),
        store=SimpleNamespace(get=Mock(return_value=None)),
    )
    state = asyncio.run(module.fetch_state(ctx))
    assert state["checked_in_today"] is expected


@pytest.mark.parametrize("value", [False, 0, "false", "0"])
def test_newapi_false_verification_flags_do_not_require_captcha(value):
    from types import SimpleNamespace
    from unittest.mock import Mock
    from templates.builtin import newapi

    ctx = SimpleNamespace(http=SimpleNamespace(get=Mock(return_value={
        "checked_in_today": False, "code_required": value, "captcha_enabled": value,
    })))
    state = asyncio.run(newapi.fetch_state(ctx))
    assert state["code_required"] is False
    assert state["captcha_enabled"] is False


@pytest.mark.parametrize("module_name", ["newapi", "sub2api"])
@pytest.mark.parametrize("value", [False, 0, "false", "0"])
def test_builtin_false_already_flag_keeps_new_reward_success(module_name, value):
    from types import SimpleNamespace
    from templates.builtin import newapi, sub2api

    if module_name == "newapi":
        outcome = newapi._reward_outcome(SimpleNamespace(), {
            "quota_awarded": 500_000, "checked_in_today": value, "already_checked_in": value,
        })
    else:
        outcome = sub2api._outcome_from_reward({"reward_amount": 1, "already_checked_in": value})
    assert outcome.verdict is Verdict.SUCCESS


@pytest.mark.parametrize("entry", ["run", "run_http"])
def test_jisudeng_failed_checkin_never_runs_quiz(monkeypatch, entry):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock
    from core.outcome import failed
    from scripts.tasks import jisudeng

    ctx = SimpleNamespace(store=SimpleNamespace(shared=Mock()), args={"quiz": True})
    expected = failed("签到未确认", reason="unconfirmed")
    monkeypatch.setattr(jisudeng.common, "http_first", AsyncMock(return_value=expected))
    monkeypatch.setattr(jisudeng.common, "http_attempt", AsyncMock(return_value=expected))
    quiz = Mock()
    monkeypatch.setattr(jisudeng, "run_play_quiz_http", quiz)
    assert asyncio.run(getattr(jisudeng, entry)(ctx)) is expected
    quiz.assert_not_called()


@pytest.mark.parametrize("response", [None, [], "", {}, {"code": 0, "data": None},
                                      {"code": 0, "data": {}}, {"outcome": "unknown"}])
def test_lottery_unconfirmed_draw_is_final_and_does_not_redraw(monkeypatch, response):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock
    from core.chain import is_final
    from scripts.tasks import vcnovb_lottery as lottery

    state = {"pool": {"key": "normal", "enabled": True}, "active": True,
             "base_remaining": 1, "extra_remaining": 0, "period_key": "d:2026-01-01"}
    ctx = SimpleNamespace(
        http=SimpleNamespace(headers={"Authorization": "Bearer synthetic-token"},
                             get=Mock(return_value={"data": {"pools": [state]}}),
                             request=Mock(return_value=response)),
        account=SimpleNamespace(id="synthetic", base_url="https://example.test"),
        log=Mock(),
    )
    browser = AsyncMock()
    monkeypatch.setattr(lottery, "run_browser", browser)
    outcome = asyncio.run(lottery.run_http(ctx))
    assert outcome.verdict is Verdict.FAILED
    assert outcome.reason == "unconfirmed"
    assert is_final(outcome)
    ctx.http.request.assert_called_once()

    ctx.http.request.reset_mock()
    legacy = asyncio.run(lottery.run(ctx))
    assert legacy.verdict is Verdict.FAILED
    assert legacy.reason == "unconfirmed"
    ctx.http.request.assert_called_once()
    browser.assert_not_awaited()


@pytest.mark.parametrize("record", [None, {}, {"outcome": "unknown"}])
def test_lottery_shared_result_parser_rejects_empty_browser_draw(record):
    from core.chain import is_final
    from scripts.tasks import vcnovb_lottery as lottery

    outcome = lottery._outcome({}, record, already=False, extra={"source": "browser_api"})
    assert outcome.verdict is Verdict.FAILED
    assert outcome.reason == "unconfirmed"
    assert is_final(outcome)


@pytest.mark.parametrize("result", ["none", "win", "blessing"])
def test_lottery_recognized_draw_outcomes_remain_successful(result):
    from scripts.tasks import vcnovb_lottery as lottery

    outcome = lottery._outcome({}, {"outcome": result}, already=False)
    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["completion_signal"] == "lottery_draw_response"
    if result == "none":
        assert outcome.display.text == "未中奖"


def test_lottery_already_drawn_without_history_remains_done():
    from scripts.tasks import vcnovb_lottery as lottery

    assert lottery._outcome({}, None, already=True).verdict is Verdict.ALREADY_DONE
