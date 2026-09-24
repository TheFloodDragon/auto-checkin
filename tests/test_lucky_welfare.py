"""Lucky 福利站模板：API 优先、浏览器回退与跨站凭据隔离。"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import urlsplit

import pytest


from config import schema
from config.overlay import Overlay
from core.errors import ConfigError, LoginRequired, TaskError, TransientError, VerificationRequired
from core.manifest import LoginOption
from core.outcome import DisplaySpec, Verdict
from net.http import HttpConfig
from runtime import engine
from scripts.tasks import lucky_welfare as lucky


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if not self.responses:
            raise AssertionError(f"没有为 {method} {path} 准备响应")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def _api_responses(*, checked=False, grant_status="success", bound=True):
    return [
        {"success": True, "data": {"bound": bound}},
        {
            "success": True,
            "data": {
                "checked_today": checked,
                "today": {"quota": 500_000},
                "rules": {"enabled": True},
            },
        },
        {
            "success": True,
            "data": {"quota": 550_000, "bonus": 50_000, "grant_status": grant_status},
        },
        {
            "success": True,
            "data": {
                "checked_today": True,
                "today": {"quota": 550_000, "bonus": 50_000, "grant_status": grant_status},
                "rules": {"enabled": True},
            },
        },
    ]


def _ctx(*, cookie="fuli_session=abc", main_headers=None):
    return SimpleNamespace(
        http=SimpleNamespace(
            headers=main_headers or {"Authorization": "Bearer main-token", "Cookie": "main_session=bad"},
            config=HttpConfig(max_attempts=1),
        ),
        account=SimpleNamespace(
            name="Lucky 主站账号",
            login=SimpleNamespace(method="oauth", provider="linuxdo", account="default"),
        ),
        credentials=SimpleNamespace(session_cookie=cookie, cookie="", browser_state=""),
        args={"timeout_seconds": 5},
        log=Mock(),
    )


def test_manifest_keeps_main_site_identity_and_single_script_candidate():
    assert lucky.MANIFEST.id == "lucky_welfare"
    assert lucky.MANIFEST.login_order() == ("cookie", "browser_state", "oauth")
    assert lucky.MANIFEST.task_order() == ("script",)
    assert lucky.MANIFEST.task_option("script").owns == frozenset({"detect", "confirm"})
    assert lucky.MANIFEST.endpoints["state"] == "/api/checkin"
    assert lucky.MANIFEST.endpoints["submit"] == "/api/checkin"


def test_origin_allowlist_rejects_similar_hosts_and_absolute_api_paths():
    assert lucky._origin("https://fuli.lucky0625.qzz.io/") == lucky.FULI_ORIGIN
    assert lucky._origin("https://fuli.lucky0625.qzz.io:443/checkin") == lucky.FULI_ORIGIN
    assert lucky._origin("http://fuli.lucky0625.qzz.io/") == ""
    assert lucky._origin("https://fuli.lucky0625.qzz.io.evil.test/") == ""
    with pytest.raises(ConfigError):
        lucky._target_url("https://new.lucky0625.qzz.io/api/checkin")
    assert lucky._target_url(lucky.OAUTH_PATH, browser=True).startswith(lucky.FULI_ORIGIN)


def test_target_client_copies_network_config_but_not_main_auth_headers():
    ctx = _ctx()
    client = lucky._target_client(ctx, "fuli_session=good")
    assert client.base_url == lucky.FULI_ORIGIN
    assert client.config is ctx.http.config
    assert client.headers == {
        "Accept": "application/json",
        "Referer": lucky.FULI_ORIGIN + "/",
        "Cookie": "fuli_session=good",
    }
    assert "Authorization" not in client.headers
    assert "New-Api-User" not in client.headers
    assert "main_session" not in client.headers.get("Cookie", "")


def test_api_success_uses_fixed_order_and_disables_post_retry():
    client = FakeClient(_api_responses())
    outcome = lucky._api_checkin(_ctx(), client)
    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["completion_signal"] in {"checked_today", "grant_status"}
    assert [call[:2] for call in client.calls] == [
        ("GET", lucky.SELF_PATH),
        ("GET", lucky.CHECKIN_PATH),
        ("POST", lucky.CHECKIN_PATH),
        ("GET", lucky.CHECKIN_PATH),
    ]
    post_kwargs = client.calls[2][2]
    assert post_kwargs["retry_non_idempotent"] is False
    assert post_kwargs["json_body"] == {}


@pytest.mark.parametrize("bonus", [0, 50_000])
def test_checkin_reward_is_not_mislabeled_as_current_balance(bonus):
    # 实站状态接口 today 是日期字符串；POST 的 quota 是奖励，bonus 可以为零。
    outcome = lucky._success_outcome(
        {"checked_today": True, "today": "2026-09-24", "streak": 1},
        source="api_response",
        action={"quota": 2_248_817, "bonus": bonus, "quota_type": "permanent", "grant_status": "success"},
    )
    assert outcome.data["awarded"] == 2_248_817
    assert outcome.display.text == "$4.50"
    assert outcome.display.text_label == "签到奖励"
    assert ("获得", "$4.50") in outcome.display.extras
    result = engine._with_current_balance(outcome, DisplaySpec())
    assert "获得 $4.50" in result.message
    assert "当前" not in result.message


def test_already_done_without_reward_details_does_not_invent_balance():
    outcome = lucky._already_outcome(
        {"checked_today": True, "today": "2026-09-24", "streak": 1}, source="api_status"
    )
    assert not outcome.display.text
    assert "当前" not in engine._with_current_balance(outcome, DisplaySpec()).message


def test_engine_runs_cached_welfare_cookie_without_starting_browser(monkeypatch, tmp_path):
    calls: list[tuple[str, str, dict[str, str]]] = []
    state_reads = 0

    def fake_send(client, method, request_path, **_kwargs):
        nonlocal state_reads
        path = request_path.split("?", 1)[0]
        url = client.resolve(request_path)
        parsed = urlsplit(url)
        calls.append((method.upper(), url, dict(client.headers)))
        assert parsed.scheme == "https"
        assert parsed.netloc == "fuli.lucky0625.qzz.io"
        assert "Authorization" not in client.headers
        assert "New-Api-User" not in client.headers
        assert client.headers.get("Cookie") == "fuli_session=abc"
        if method.upper() == "GET" and path == lucky.SELF_PATH:
            return {"success": True, "data": {"bound": True}}
        if method.upper() == "GET" and path == lucky.CHECKIN_PATH:
            state_reads += 1
            if state_reads == 1:
                return {"success": True, "data": {"checked_today": False, "rules": {"enabled": True}}}
            return {"success": True, "data": {"checked_today": True, "today": {"quota": 550_000}}}
        if method.upper() == "POST" and path == lucky.CHECKIN_PATH:
            return {"success": True, "data": {"grant_status": "success", "bonus": 50_000}}
        raise AssertionError(f"未预期请求：{method} {url}")

    monkeypatch.setattr("net.http.HttpClient._send", fake_send)
    monkeypatch.setattr(engine.caps_module, "detect", lambda _account: frozenset())
    spec = schema.parse_account(
        {
            "id": "lucky-engine",
            "name": "Lucky 引擎测试",
            "base_url": lucky.MAIN_ORIGIN,
            "template": "scripts/tasks/lucky_welfare.py",
            "login": {"method": "cookie"},
            "credentials": {"session_cookie": "fuli_session=abc"},
            "tasks": [{"id": "daily", "method": "script"}],
        }
    )
    result = asyncio.run(engine.run_account(spec, overlay=Overlay(path=tmp_path / "overlay.json").load()))
    assert result.ok
    assert result.records[0].outcome.verdict is Verdict.SUCCESS
    assert calls
    assert all(url.startswith(lucky.FULI_ORIGIN) for _method, url, _headers in calls)


def test_api_already_done_and_not_open_are_non_failures():
    already_client = FakeClient(
        [
            {"success": True, "data": {"bound": True}},
            {"success": True, "data": {"checked_today": True, "today": {"quota": 500_000}}},
        ]
    )
    already = lucky._api_checkin(_ctx(), already_client)
    assert already.verdict is Verdict.ALREADY_DONE
    assert already.ok
    assert len(already_client.calls) == 2

    closed_client = FakeClient(
        [
            {"success": True, "data": {"bound": True}},
            {"success": True, "data": {"checked_today": False, "rules": {"enabled": False}}},
        ]
    )
    closed = lucky._api_checkin(_ctx(), closed_client)
    assert closed.verdict is Verdict.NO_EFFECT
    assert closed.reason == "not_open"
    assert len(closed_client.calls) == 2


def test_api_unbound_is_need_config_and_never_posts(monkeypatch):
    client = FakeClient(
        [
            {"success": True, "data": {"bound": False}},
        ]
    )
    ctx = _ctx()
    ctx.http.headers = {
        lucky.SESSION_ORIGIN_HEADER: lucky.FULI_ORIGIN,
        "Cookie": "fuli_session=abc",
    }
    monkeypatch.setattr(lucky, "_target_client", lambda _ctx, _cookie: client)
    outcome = asyncio.run(lucky.run(ctx))
    assert outcome.reason == "need_config"
    assert "绑定" in outcome.message
    assert [call[:2] for call in client.calls] == [("GET", lucky.SELF_PATH)]


def test_api_pending_is_success_with_pending_detail():
    responses = _api_responses(grant_status="pending")
    # pending 的状态回读仍可能带 checked_today；只验证结果保留入账状态。
    client = FakeClient(responses)
    outcome = lucky._api_checkin(_ctx(), client)
    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["grant_status"] == "pending"
    assert "到账确认中" in outcome.message


def test_api_failed_grant_is_explicit_failure_without_false_success():
    client = FakeClient(
        [
            {"success": True, "data": {"bound": True}},
            {"success": True, "data": {"checked_today": False, "rules": {"enabled": True}}},
            {"success": True, "data": {"grant_status": "failed", "bonus": 0}},
        ]
    )
    outcome = lucky._api_checkin(_ctx(), client)
    assert outcome.verdict is Verdict.FAILED
    assert outcome.reason == "unconfirmed"
    assert not outcome.ok
    assert len(client.calls) == 3


def test_api_transport_failure_returns_fallback_signal_without_browser_request():
    client = FakeClient(
        [
            TransientError("福利站超时"),
        ]
    )
    ctx = _ctx()
    # _api_checkin 本身只表达「需要回退」，不会擅自触碰 ctx.browser。
    with pytest.raises(Exception) as excinfo:
        lucky._api_checkin(ctx, client)
    assert type(excinfo.value).__name__ == "_ApiFallback"
    assert not hasattr(ctx, "browser")


def test_blocked_http_result_does_not_start_browser(monkeypatch):
    client = FakeClient([TaskError("Cloudflare 已拒绝出口 IP", reason="blocked", status=403)])
    ctx = _ctx()
    ctx.http.headers = {
        lucky.SESSION_ORIGIN_HEADER: lucky.FULI_ORIGIN,
        "Cookie": "fuli_session=abc",
    }
    ctx.browser = SimpleNamespace(lease=Mock(side_effect=AssertionError("封禁时不应启动浏览器")))
    monkeypatch.setattr(lucky, "_target_client", lambda _ctx, _cookie: client)
    outcome = lucky._api_outcome_or_fallback(ctx)
    assert outcome is not None
    assert outcome.reason == "blocked"
    ctx.browser.lease.assert_not_called()


def test_unknown_binding_is_config_error_and_never_posts():
    with pytest.raises(ConfigError, match="无法从 /api/user/self 确认"):
        lucky._check_bound({"id": 123, "username": "demo"})


def test_api_failure_makes_run_enter_browser_only_after_cookie_path(monkeypatch):
    ctx = _ctx()
    ctx.http.headers = {
        lucky.SESSION_ORIGIN_HEADER: lucky.FULI_ORIGIN,
        "Cookie": "fuli_session=abc",
        "Authorization": "Bearer main-token",
    }
    monkeypatch.setattr(
        lucky,
        "_api_checkin",
        Mock(side_effect=lucky._ApiFallback("接口不可用")),
    )
    browser_outcome = object()
    browser = Mock()
    browser.lease = Mock()
    monkeypatch.setattr(lucky, "_browser_checkin", AsyncMock(return_value=browser_outcome))
    ctx.browser = browser
    result = asyncio.run(lucky.run(ctx))
    assert result is browser_outcome
    lucky._browser_checkin.assert_awaited_once()


class FakePage:
    def __init__(self, responses):
        self.url = lucky.FULI_ORIGIN + "/"
        self.responses = list(responses)
        self.evaluated: list[tuple[str, object]] = []
        self.body_text = ""

    async def evaluate(self, script, arg=None):
        self.evaluated.append((script, arg))
        if self.responses:
            response = self.responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response
        raise AssertionError("页面没有准备更多响应")

    async def goto(self, *_args, **_kwargs):
        self.url = lucky.FULI_ORIGIN + "/"

    async def reload(self, *_args, **_kwargs):
        return None

    async def wait_for_timeout(self, _ms):
        return None

    def locator(self, selector):
        if selector == "body":
            return FakeBody(self)
        raise AssertionError(f"未预期的 locator：{selector}")


class FakeBody:
    def __init__(self, page):
        self.page = page

    async def inner_text(self):
        return self.page.body_text


class FakeContext:
    async def cookies(self, *_args):
        return [{"name": "fuli_session", "value": "abc", "domain": "fuli.lucky0625.qzz.io"}]

    async def add_cookies(self, _cookies):
        return None


class FakeLease:
    def __init__(self, page):
        self.page = page
        self.context = FakeContext()
        self.marked = False
        self.clicks = 0

    def mark_authenticated(self):
        self.marked = True

    async def screenshot(self, *_args, **_kwargs):
        return "evidence.png"


class FakeButton:
    def __init__(self, text="摘一片四叶草 · 签到"):
        self.text = text
        self.clicked = 0

    async def is_visible(self):
        return True

    async def inner_text(self):
        return self.text

    async def is_disabled(self):
        return False

    async def click(self, **_kwargs):
        self.clicked += 1

    async def dispatch_event(self, _name):
        self.clicked += 1


class ButtonPage(FakePage):
    def __init__(self, responses):
        super().__init__(responses)
        self.selectors: list[str] = []
        self.button = FakeButton()

    def locator(self, selector):
        self.selectors.append(selector)
        if selector == "body":
            return FakeBody(self)
        if selector == lucky.CHECKIN_BUTTON_SELECTORS[0]:
            return FakeLocator([self.button])
        return FakeLocator([])


class FakeLocator:
    def __init__(self, items):
        self.items = items

    async def count(self):
        return len(self.items)

    def nth(self, index):
        return self.items[index]



def _browser_response(body, *, ok=True, status=200):
    return {"ok": ok, "status": status, "body": body, "text": ""}


def test_browser_api_success_does_not_touch_button():
    page = FakePage(
        [
            _browser_response({"success": True, "data": {"bound": True}}),
            _browser_response({"success": True, "data": {"checked_today": False, "rules": {"enabled": True}}}),
            _browser_response({"success": True, "data": {"grant_status": "success", "bonus": 50_000}}),
            _browser_response({"success": True, "data": {"checked_today": True, "today": {"quota": 550_000}}}),
        ]
    )
    outcome = asyncio.run(lucky._browser_checkin_api(page))
    assert outcome.verdict is Verdict.SUCCESS
    assert not any("#today-checkin" in script for script, _ in page.evaluated)


def test_browser_failed_grant_does_not_fall_back_to_button(monkeypatch):
    page = FakePage(
        [
            _browser_response({"success": True, "data": {"bound": True}}),
            _browser_response({"success": True, "data": {"checked_today": False, "rules": {"enabled": True}}}),
            _browser_response({"success": True, "data": {"grant_status": "failed", "bonus": 0}}),
        ]
    )
    lease = SimpleNamespace(
        new_page=AsyncMock(return_value=page),
        mark_authenticated=Mock(),
    )
    manager = AsyncMock()
    manager.__aenter__.return_value = lease
    browser = SimpleNamespace(lease=Mock(return_value=manager))
    ctx = SimpleNamespace(
        browser=browser,
        args={"timeout_seconds": 5},
        log=Mock(),
        account=SimpleNamespace(login=SimpleNamespace(provider="linuxdo", account="default")),
        credentials=SimpleNamespace(session_cookie="fuli_session=abc"),
    )
    monkeypatch.setattr(
        lucky,
        "_browser_session",
        AsyncMock(return_value=({"bound": True}, "fuli_session=abc")),
    )
    fallback = AsyncMock(side_effect=AssertionError("明确失败时不应点击按钮"))
    monkeypatch.setattr(lucky, "_browser_button_fallback", fallback)
    outcome = asyncio.run(lucky._browser_checkin(ctx))
    assert outcome.verdict is Verdict.FAILED
    assert outcome.reason == "unconfirmed"
    fallback.assert_not_awaited()


def test_browser_blocked_response_propagates_without_button_fallback():
    result = _browser_response("<!doctype html><title>Attention Required! | Cloudflare</title><body>Sorry, you have been blocked</body>", ok=False, status=403)
    with pytest.raises(TaskError) as excinfo:
        lucky._browser_payload(result)
    assert excinfo.value.reason == "blocked"


def test_button_fallback_uses_scoped_selector_and_confirms_state():
    page = ButtonPage(
        [
            _browser_response({"success": True, "data": {"checked_today": True, "today": {"quota": 550_000}}}),
        ]
    )
    lease = FakeLease(page)
    ctx = SimpleNamespace(log=Mock(), evidence=SimpleNamespace(capture=AsyncMock(return_value="evidence.png")))
    outcome = asyncio.run(
        lucky._browser_button_fallback(ctx, lease, page, timeout_seconds=5)
    )
    assert outcome.verdict is Verdict.SUCCESS
    assert page.selectors[0] == lucky.CHECKIN_BUTTON_SELECTORS[0]
    assert page.button.clicked == 1


def test_cookie_login_returns_domain_scoped_jar_without_main_auth_headers(monkeypatch):
    ctx = _ctx()
    ctx.account.login.method = "cookie"
    monkeypatch.setattr(lucky, "_target_request", Mock(return_value={"bound": True}))
    state = lucky.login(ctx, LoginOption("cookie"))
    assert state.verified
    assert state.headers == {"Accept": "application/json"}
    assert "Authorization" not in state.headers
    assert "Cookie" not in state.headers
    assert lucky.SESSION_ORIGIN_HEADER not in state.headers
    assert state.credentials["session_cookie"] == "fuli_session=abc"

    from urllib.request import Request

    main_request = Request(lucky.MAIN_ORIGIN + "/api/user/self")
    state.cookie_jar.add_cookie_header(main_request)
    assert main_request.get_header("Cookie") is None
    welfare_request = Request(lucky.FULI_ORIGIN + lucky.SELF_PATH)
    state.cookie_jar.add_cookie_header(welfare_request)
    assert welfare_request.get_header("Cookie") == "fuli_session=abc"


def test_oauth_login_uses_server_entry_and_shared_authorization_state_machine(monkeypatch):
    page = SimpleNamespace(goto=AsyncMock())
    log = Mock()
    payload = {"landed_back": True, "provider": "linuxdo"}

    async def finish(page_arg, origin, provider, result, log_arg):
        page.goto.assert_awaited_once_with(
            lucky.FULI_ORIGIN + lucky.OAUTH_PATH, wait_until="domcontentloaded", timeout=60000
        )
        assert page_arg is page
        assert origin == lucky.FULI_ORIGIN
        assert provider.key == "linuxdo"
        assert result == {
            "clicked": False,
            "landed_back": False,
            "need_human": False,
            "cloudflare": False,
            "provider": "linuxdo",
        }
        assert log_arg is log
        return payload

    authorize = AsyncMock(side_effect=finish)
    trigger = AsyncMock()
    monkeypatch.setattr(lucky.oauth_flow, "finish_oauth_authorization", authorize)
    monkeypatch.setattr(lucky.oauth_flow, "trigger_oauth", trigger)
    assert asyncio.run(lucky._oauth_login_page(page, log)) is payload
    authorize.assert_awaited_once()
    trigger.assert_not_awaited()  # 不误点游戏入口，也不请求不存在的 /api/status。


@pytest.mark.parametrize("flag", ["cloudflare", "waf_blocked", "need_human"])
def test_oauth_authorization_failure_is_preserved_without_retry(monkeypatch, flag):
    page = SimpleNamespace(goto=AsyncMock())
    payload = {"landed_back": False, flag: True, "provider": "linuxdo"}
    authorize = AsyncMock(return_value=payload)
    monkeypatch.setattr(lucky.oauth_flow, "finish_oauth_authorization", authorize)
    assert asyncio.run(lucky._oauth_login_page(page, None)) is payload
    page.goto.assert_awaited_once()
    authorize.assert_awaited_once()
    assert callable(authorize.await_args.args[4])


@pytest.mark.parametrize("source", ["navigation", "authorization"])
@pytest.mark.parametrize(
    "error",
    [VerificationRequired("需人工验证"), TaskError("站点拒绝访问", reason="blocked")],
)
def test_oauth_structured_errors_are_not_mislabeled_as_login_failure(monkeypatch, source, error):
    page = SimpleNamespace(goto=AsyncMock())
    authorize = AsyncMock()
    monkeypatch.setattr(lucky.oauth_flow, "finish_oauth_authorization", authorize)
    (page.goto if source == "navigation" else authorize).side_effect = error
    with pytest.raises(TaskError) as excinfo:
        asyncio.run(lucky._oauth_login_page(page, Mock()))
    assert excinfo.value is error
    if source == "navigation":
        authorize.assert_not_awaited()


def test_oauth_navigation_failure_does_not_finish_or_expose_exception_details(monkeypatch):
    page = SimpleNamespace(goto=AsyncMock(side_effect=RuntimeError("state=private-value")))
    authorize = AsyncMock()
    monkeypatch.setattr(lucky.oauth_flow, "finish_oauth_authorization", authorize)
    result = asyncio.run(lucky._oauth_login_page(page, None))
    assert result["landed_back"] is False
    assert result["error"] == "RuntimeError"
    assert "private-value" not in repr(result)
    authorize.assert_not_awaited()


def test_browser_session_checks_server_login_after_oauth_return(monkeypatch):
    ctx = _ctx(cookie="")
    ctx.oauth_state = Mock(return_value="shared-state")
    page = SimpleNamespace(url=lucky.FULI_ORIGIN + "/", goto=AsyncMock())
    monkeypatch.setattr(lucky, "_goto_fuli", AsyncMock())
    monkeypatch.setattr(lucky, "_oauth_login_page", AsyncMock(return_value={"landed_back": True}))
    self_info = AsyncMock(side_effect=[LoginRequired("未登录"), LoginRequired("未登录")])
    monkeypatch.setattr(lucky, "_browser_self", self_info)
    with pytest.raises(LoginRequired, match="OAuth 回跳后仍未建立会话"):
        asyncio.run(lucky._browser_session(ctx, SimpleNamespace(context=None), page, allow_oauth=True))
    assert self_info.await_count == 2


def test_browser_login_persists_welfare_cookie_and_full_state(monkeypatch):
    page = object()
    lease = SimpleNamespace(
        new_page=AsyncMock(return_value=page),
        export_state=AsyncMock(return_value="full-browser-state"),
        mark_authenticated=Mock(),
    )
    manager = AsyncMock()
    manager.__aenter__.return_value = lease
    browser = SimpleNamespace(lease=Mock(return_value=manager))
    ctx = SimpleNamespace(
        args={"provider": "linuxdo", "account": "default"},
        account=SimpleNamespace(login=SimpleNamespace(provider="linuxdo", account="default")),
        credentials=SimpleNamespace(browser_state="shared-state", session_cookie=""),
        oauth_state=Mock(return_value="shared-state"),
        browser=browser,
        log=Mock(),
    )
    monkeypatch.setattr(
        lucky,
        "_browser_session",
        AsyncMock(return_value=({"bound": True}, "fuli_session=abc")),
    )
    state = asyncio.run(lucky.login(ctx, LoginOption("oauth")))
    assert state.credentials == {
        "session_cookie": "fuli_session=abc",
        "browser_state": "full-browser-state",
    }
    assert state.headers == {"Accept": "application/json"}
    assert "Cookie" not in state.headers
    assert list(state.cookie_jar)[0].domain == "fuli.lucky0625.qzz.io"
    lease.mark_authenticated.assert_called_once()
    browser.lease.assert_called_once_with(reason="lucky_welfare_login", state_text="shared-state")


def test_example_config_has_main_base_url_without_real_credentials():
    from pathlib import Path
    import json

    raw = json.loads(Path("ACCOUNTS.example.json").read_text(encoding="utf-8"))
    item = next(account for account in raw["accounts"] if account["id"] == "example-lucky-welfare")
    assert item["base_url"] == lucky.MAIN_ORIGIN
    assert item["template"] == "scripts/tasks/lucky_welfare.py"
    assert item["login"] == {"method": "oauth", "provider": "linuxdo", "account": "default"}
    assert "credentials" not in item
    assert "session_cookie" not in repr(item)
    assert "Authorization" not in repr(item)
