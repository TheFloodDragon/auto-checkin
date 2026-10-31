"""访问保活的浏览器兜底必须区分登录、防护与网络故障。"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from browser import bypass, waf
from core.errors import TaskError, TransientError, VerificationRequired
from net.http import HttpConfig
from task import visit


class _Lease:
    def __init__(self, page):
        self.page = page
        self.authenticated = False
        self.goto = AsyncMock()
        self.dismiss_popups = AsyncMock()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def new_page(self):
        return self.page

    def resolve(self, path):
        return "https://example.invalid" + path

    def mark_authenticated(self):
        self.authenticated = True


@pytest.fixture
def browser_context(monkeypatch):
    page = SimpleNamespace(evaluate=AsyncMock(), wait_for_timeout=AsyncMock())
    lease = _Lease(page)
    ctx = SimpleNamespace(
        http=SimpleNamespace(headers={"new-api-user": "7"}, config=HttpConfig()),
        browser=SimpleNamespace(lease=lambda **_kwargs: lease),
        account=SimpleNamespace(base_url="https://example.invalid"),
        log=lambda _message: None,
    )
    monkeypatch.setattr(waf, "is_waf_html", AsyncMock(return_value=False))
    monkeypatch.setattr(waf, "waf_is_blocked", lambda _page: False)
    monkeypatch.setattr(waf, "solve_waf", AsyncMock(return_value=True))
    from solvers.registry import SolveResult
    monkeypatch.setattr(bypass.TurnstileBypass, "solve_result", AsyncMock(return_value=SolveResult.solved("", data={"status": "passed"})))
    return ctx, page, lease


@pytest.mark.parametrize(
    ("status", "body", "reason"),
    [
        (403, "<!doctype html><title>Just a moment...</title>", "need_verification"),
        (503, "<!doctype html><title>Just a moment...</title>", "need_verification"),
        (403, "<!doctype html><title>Sorry, you have been blocked</title>", "blocked"),
        (403, "<!doctype html><script>var arg1='challenge';</script>", "need_verification"),
        (401, {"message": "session expired"}, "need_login"),
        (403, {"message": "session expired"}, "need_login"),
        (403, "<!doctype html><title>Forbidden</title>", ""),
        (522, "<!doctype html><title>Connection timed out | Cloudflare</title>", "network_error"),
        (429, {"message": "too many requests"}, "network_error"),
        (200, "<!doctype html><title>Just a moment...</title>", "need_verification"),
        (200, "<!doctype html><title>Bad Gateway</title>", ""),
        (200, None, "authentication_unknown"),
    ],
)
def test_browser_response_classification(browser_context, status, body, reason):
    ctx, page, lease = browser_context
    page.evaluate.return_value = {"status": status, "body": body}
    with pytest.raises(TaskError) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.reason == reason
    assert not lease.authenticated
    assert "<!doctype" not in caught.value.message.lower()


@pytest.mark.parametrize("status", ["pending", "verifying", "click_unconfirmed", "rejected", "observation_error"])
def test_structured_cf_nonpass_never_fetches_or_reloads(browser_context, monkeypatch, status):
    from solvers.registry import SolveResult
    ctx, page, lease = browser_context
    ctx.remaining_seconds = lambda: 1.0
    result = SolveResult.failure(status, data={"status": status, "stage": "observe", "generation": "g1",
        "input_dispatched": True, "widget_acknowledged": False, "preserve_page": True, "retry_allowed": False})
    solve = AsyncMock(return_value=result)
    monkeypatch.setattr(bypass.TurnstileBypass, "solve_result", solve)
    with pytest.raises(VerificationRequired) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.data["status"] == status
    assert caught.value.data["input_dispatched"] is True
    assert caught.value.data["preserve_page"] is True
    page.evaluate.assert_not_awaited()
    lease.goto.assert_awaited_once()
    assert solve.await_args.kwargs["timeout"] <= 1.0
    assert not lease.authenticated


def test_zero_remaining_budget_never_opens_or_fetches_browser(browser_context):
    ctx, page, lease = browser_context
    ctx.remaining_seconds = lambda: 0.0
    ctx.browser.lease = Mock(side_effect=AssertionError("过期预算不能打开浏览器"))
    with pytest.raises(TaskError) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.reason == "timeout"
    ctx.browser.lease.assert_not_called()
    page.evaluate.assert_not_awaited()
    assert not lease.authenticated


def test_api_guard_then_pending_cf_stops_additional_gets(browser_context, monkeypatch):
    from solvers.registry import SolveResult
    ctx, page, lease = browser_context
    page.evaluate.return_value = {"status": 200, "body": "<!doctype html><title>Just a moment</title>"}
    monkeypatch.setattr(bypass.TurnstileBypass, "solve_result", AsyncMock(side_effect=[
        SolveResult.solved("", data={"status": "passed"}),
        SolveResult.failure("verifying", data={"status": "verifying", "preserve_page": True, "retry_allowed": False})]))
    with pytest.raises(VerificationRequired) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.data["status"] == "verifying"
    page.evaluate.assert_awaited_once()
    lease.goto.assert_awaited_once()
    assert not lease.authenticated


def test_legacy_quota_json_does_not_authenticate_browser_without_identity(browser_context):
    ctx, page, lease = browser_context
    page.evaluate.return_value = {"status": 200, "body": {"data": {"quota": 100}}}
    assert asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self", user_endpoint=True)) == {"quota": 100}
    assert not lease.authenticated


def test_arbitrary_public_get_never_marks_browser_authenticated(browser_context):
    ctx, page, lease = browser_context
    page.evaluate.return_value = {"status": 200, "body": {"data": {"id": 7, "quota": 100}}}
    assert asyncio.run(visit._fetch_in_browser(ctx, "/api/public")) == {"id": 7, "quota": 100}
    assert not lease.authenticated


def test_cf_observation_exception_stops_before_business_fetch(browser_context, monkeypatch):
    ctx, page, lease = browser_context
    monkeypatch.setattr(bypass.TurnstileBypass, "solve_result", AsyncMock(side_effect=RuntimeError("driver lost private-token")))
    with pytest.raises(VerificationRequired) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.data["status"] == "observation_error"
    assert "private-token" not in caught.value.message
    page.evaluate.assert_not_awaited()
    assert not lease.authenticated


@pytest.mark.parametrize("body", [
    {"success": False, "message": "业务拒绝"}, {"login": True}, {"data": {"current_user": None}},
    {"title": "public welcome"}, {"data": {"authenticated": False}},
    {"code": 403, "success": False, "message": "Turnstile verification required", "data": {"id": 7}},
    {"code": 401, "data": {"id": 7, "quota": 100}},
])
def test_browser_user_json_never_confirms_rejected_or_public_response(browser_context, body):
    ctx, page, lease = browser_context
    page.evaluate.return_value = {"status": 200, "body": body}
    with pytest.raises(TaskError):
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert not lease.authenticated
    assert page.evaluate.await_count == 1


@pytest.mark.parametrize("body", [{"success": False, "message": "今日已签到"}, {"login": True}, {"current_user": None}])
def test_http_visit_never_completes_or_writes_baseline_on_rejected_json(body):
    from templates import registry
    ctx = SimpleNamespace(http=SimpleNamespace(get=Mock(return_value=body)),
        store=SimpleNamespace(get=Mock(return_value={}), put=Mock()), browser_service=None, log=Mock())
    outcome = asyncio.run(visit.VisitTask().run(ctx, registry.get("newapi")))
    assert outcome.ok is False
    ctx.store.put.assert_not_called()
    ctx.http.get.assert_called_once_with("/api/user/self")


@pytest.mark.parametrize("confirmation", [True, False, VerificationRequired("验证未确认")])
def test_engine_visit_ensures_authentication_before_its_user_get(confirmation):
    from templates import registry
    order = []
    async def ensure():
        order.append("ensure")
        if isinstance(confirmation, BaseException):
            raise confirmation
        return confirmation
    def get(path):
        order.append("GET")
        assert path == "/api/user/self"
        return {"success": True, "data": {"id": 7, "quota": 100}}
    ctx = SimpleNamespace(login=SimpleNamespace(ensure_authenticated=ensure),
        http=SimpleNamespace(get=Mock(side_effect=get)), store=SimpleNamespace(get=Mock(return_value={}), put=Mock()),
        browser_service=None, log=Mock())
    outcome = asyncio.run(visit.VisitTask().run(ctx, registry.get("newapi")))
    assert order == (["ensure", "GET"] if confirmation is True else ["ensure"])
    assert outcome.ok is (confirmation is True)
    if confirmation is not True:
        ctx.store.put.assert_not_called()


@pytest.mark.parametrize("remaining", [0.0, 0.5])
def test_visit_user_get_respects_remaining_budget_without_any_post(remaining):
    from templates import registry
    ctx = SimpleNamespace(http=SimpleNamespace(get=Mock(return_value={"data": {"id": 7, "quota": 100}}),
        post=Mock(side_effect=AssertionError("visit不能POST")), config=HttpConfig(timeout=10)),
        remaining_seconds=lambda: remaining, store=SimpleNamespace(get=Mock(return_value={}), put=Mock()),
        browser_service=None, log=Mock())
    outcome = asyncio.run(visit.VisitTask().run(ctx, registry.get("newapi")))
    ctx.http.post.assert_not_called()
    if remaining:
        assert outcome.ok
        assert ctx.http.get.call_args.kwargs["timeout"] <= remaining
    else:
        assert outcome.reason == "timeout"
        ctx.http.get.assert_not_called()
        ctx.store.put.assert_not_called()


def test_cf_api_rejection_emits_safe_warning_before_failure(browser_context, capsys):
    from runtime.events import RunEvent
    ctx, page, lease = browser_context
    page.evaluate.return_value = {"status": 403, "body": "<!doctype html><title>Sorry, you have been blocked</title>Cloudflare private-cookie"}
    with pytest.raises(TaskError) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.reason == "blocked"
    assert caught.value.data["status"] == "rejected"
    events = [RunEvent.from_line(line) for line in capsys.readouterr().err.splitlines()]
    warnings = [event for event in events if event is not None and event.level == "warning"]
    assert len(warnings) == 1
    assert "private-cookie" not in warnings[0].to_line()
    page.evaluate.assert_awaited_once()
    assert not lease.authenticated


def test_successful_browser_fetch_waits_for_commit(browser_context):
    ctx, page, lease = browser_context
    page.evaluate.return_value = {"status": 200, "body": {"data": {"id": 7, "quota": 100}}}
    assert asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self", user_endpoint=True)) == {"id": 7, "quota": 100}
    assert lease.authenticated
    assert lease.goto.call_args.kwargs["wait_until"] == "commit"
    assert lease.goto.call_args.kwargs["timeout"] == 30000
    script, args = page.evaluate.call_args.args
    assert "text.slice(0, 200)" not in script
    assert args[1] == {"new-api-user": "7"}


@pytest.mark.parametrize("clears", [True, False])
def test_guard_html_with_http_200_uses_bounded_read_retries(browser_context, clears):
    ctx, page, lease = browser_context
    challenge = {"status": 200, "body": "<!doctype html><title>Just a moment...</title>"}
    payload = {"status": 200, "body": {"data": {"id": 7, "quota": 100}}}
    page.evaluate.side_effect = [challenge, payload] if clears else [challenge] * 3
    if clears:
        assert asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self", user_endpoint=True)) == {"id": 7, "quota": 100}
        assert page.evaluate.await_count == 2
        assert lease.authenticated
    else:
        with pytest.raises(TaskError) as caught:
            asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
        assert caught.value.reason == "need_verification"
        assert page.evaluate.await_count == 3
        assert not lease.authenticated
    lease.goto.assert_awaited_once()


@pytest.mark.parametrize("body", ["fetch timeout", "TypeError: Failed to fetch", "NetworkError"])
def test_missing_browser_response_is_network_error(browser_context, body):
    ctx, page, lease = browser_context
    page.evaluate.return_value = {"status": 0, "body": body}
    with pytest.raises(TransientError) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.reason == "network_error"
    assert page.evaluate.await_count == 3
    assert not lease.authenticated


def test_driver_closed_fails_immediately_without_secret_error(browser_context):
    ctx, page, lease = browser_context
    page.evaluate.side_effect = RuntimeError("Connection closed while reading from the driver private-cookie")
    with pytest.raises(TransientError) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.data["error_code"] == "driver_closed"
    assert "private-cookie" not in caught.value.message
    assert page.evaluate.await_count == 1
    assert not lease.authenticated


def test_navigation_evaluate_failure_can_retry(browser_context):
    ctx, page, lease = browser_context
    page.evaluate.side_effect = [
        RuntimeError("Execution context was destroyed"),
        {"status": 200, "body": {"data": {"id": 7, "quota": 100}}},
    ]
    assert asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self", user_endpoint=True)) == {"id": 7, "quota": 100}
    assert page.evaluate.await_count == 2
    assert lease.authenticated


@pytest.mark.parametrize("guard", ["waf", "cloudflare"])
def test_uncleared_guard_stops_before_fetch(browser_context, monkeypatch, guard):
    ctx, page, lease = browser_context
    if guard == "waf":
        monkeypatch.setattr(waf, "is_waf_html", AsyncMock(return_value=True))
        monkeypatch.setattr(waf, "solve_waf", AsyncMock(return_value=False))
    else:
        from solvers.registry import SolveResult
        monkeypatch.setattr(bypass.TurnstileBypass, "solve_result", AsyncMock(return_value=SolveResult.failure(
            "pending", data={"status": "pending", "stage": "visit_guard", "preserve_page": True, "retry_allowed": False})))
    with pytest.raises(TaskError) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.reason == "need_verification"
    assert caught.value.data["guard"] == "challenge"
    assert caught.value.data["preserve_page"] is True
    assert caught.value.data["retry_allowed"] is False
    assert page.evaluate.await_count == 0
    assert not lease.authenticated


@pytest.mark.parametrize("denied_after_recovery", [False, True])
def test_visit_retries_only_user_read_after_one_auth_recovery(denied_after_recovery):
    from core.errors import LoginRequired
    from core.outcome import Verdict
    from runtime.engine import _LoginHandle
    from templates import registry

    denied = LoginRequired("旧会话被拒绝")
    response = denied if denied_after_recovery else {"data": {"quota": 500000}}
    recovery = AsyncMock(return_value=True)
    ctx = SimpleNamespace(
        http=SimpleNamespace(get=Mock(side_effect=[denied, response])),
        store=SimpleNamespace(get=Mock(return_value={}), put=Mock()),
        login_handle=_LoginHandle(recover_callback=recovery),
        browser_service=None,
        log=lambda _message: None,
    )
    outcome = asyncio.run(visit.VisitTask().run(ctx, registry.get("newapi")))
    assert ctx.http.get.call_count == 2
    assert all(call.args == ("/api/user/self",) for call in ctx.http.get.call_args_list)
    recovery.assert_awaited_once()
    if denied_after_recovery:
        assert outcome.reason == "need_login"
        ctx.store.put.assert_not_called()
    else:
        assert outcome.verdict is Verdict.SUCCESS
        ctx.store.put.assert_called_once()
    assert not asyncio.run(ctx.login_handle.recover())
    recovery.assert_awaited_once()


@pytest.mark.parametrize("reason", ["unreachable", "network_error", "need_verification", "blocked"])
def test_visit_does_not_relogin_on_non_authentication_failures(reason):
    from runtime.engine import _LoginHandle
    from templates import registry

    recovery = AsyncMock(return_value=True)
    ctx = SimpleNamespace(
        http=SimpleNamespace(get=Mock(side_effect=TaskError("未取得认证拒绝证据", reason=reason))),
        store=SimpleNamespace(get=Mock(return_value={}), put=Mock()),
        login_handle=_LoginHandle(recover_callback=recovery),
        browser_service=None,
        log=lambda _message: None,
    )
    outcome = asyncio.run(visit.VisitTask().run(ctx, registry.get("newapi")))
    assert outcome.reason == reason
    recovery.assert_not_awaited()
    ctx.http.get.assert_called_once()
    ctx.store.put.assert_not_called()


def test_visit_reports_recovery_challenge_without_replaying_request():
    from core.errors import LoginRequired, VerificationRequired
    from runtime.engine import _LoginHandle
    from templates import registry

    recovery = AsyncMock(side_effect=VerificationRequired("OAuth 需要人工验证"))
    ctx = SimpleNamespace(
        http=SimpleNamespace(get=Mock(side_effect=LoginRequired("旧会话被拒绝"))),
        store=SimpleNamespace(get=Mock(return_value={}), put=Mock()),
        login_handle=_LoginHandle(recover_callback=recovery),
        browser_service=None,
        log=lambda _message: None,
    )
    outcome = asyncio.run(visit.VisitTask().run(ctx, registry.get("newapi")))
    assert outcome.reason == "need_verification"
    recovery.assert_awaited_once()
    ctx.http.get.assert_called_once()
    ctx.store.put.assert_not_called()
    assert not asyncio.run(ctx.login_handle.recover())


def test_visit_can_recover_authentication_rejected_behind_waf(monkeypatch):
    from core.errors import LoginRequired, VerificationRequired
    from core.outcome import Verdict
    from runtime.engine import _LoginHandle
    from templates import registry

    recovery = AsyncMock(return_value=True)
    browser_fetch = AsyncMock(side_effect=LoginRequired("浏览器接口确认旧会话失效"))
    monkeypatch.setattr(visit, "_fetch_in_browser", browser_fetch)
    ctx = SimpleNamespace(
        http=SimpleNamespace(get=Mock(side_effect=[
            VerificationRequired("HTTP 被 WAF 拦截"), {"data": {"quota": 500000}},
        ])),
        store=SimpleNamespace(get=Mock(return_value={}), put=Mock()),
        login_handle=_LoginHandle(recover_callback=recovery),
        browser_service=object(),
        log=lambda _message: None,
    )
    outcome = asyncio.run(visit.VisitTask().run(ctx, registry.get("newapi")))
    assert outcome.verdict is Verdict.SUCCESS
    recovery.assert_awaited_once()
    browser_fetch.assert_awaited_once()
    assert ctx.http.get.call_count == 2
    ctx.store.put.assert_called_once()


def test_html_markers_past_old_preview_are_classified(browser_context):
    ctx, page, _lease = browser_context
    page.evaluate.return_value = {
        "status": 403,
        "body": "<!doctype html>" + " " * 400 + "<title>Sorry, you have been blocked</title>",
    }
    with pytest.raises(TaskError) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.reason == "blocked"
