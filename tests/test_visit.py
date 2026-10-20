"""访问保活的浏览器兜底必须区分登录、防护与网络故障。"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from browser import bypass, waf
from core.errors import TaskError, TransientError
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
    monkeypatch.setattr(bypass, "solve_cloudflare", AsyncMock(return_value=True))
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
        (200, None, ""),
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


def test_successful_browser_fetch_waits_for_commit(browser_context):
    ctx, page, lease = browser_context
    page.evaluate.return_value = {"status": 200, "body": {"data": {"quota": 100}}}
    assert asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self")) == {"quota": 100}
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
    payload = {"status": 200, "body": {"data": {"quota": 100}}}
    page.evaluate.side_effect = [challenge, payload] if clears else [challenge] * 3
    if clears:
        assert asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self")) == {"quota": 100}
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
        {"status": 200, "body": {"data": {"quota": 100}}},
    ]
    assert asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self")) == {"quota": 100}
    assert page.evaluate.await_count == 2
    assert lease.authenticated


@pytest.mark.parametrize("guard", ["waf", "cloudflare"])
def test_uncleared_guard_stops_before_fetch(browser_context, monkeypatch, guard):
    ctx, page, lease = browser_context
    if guard == "waf":
        monkeypatch.setattr(waf, "is_waf_html", AsyncMock(return_value=True))
        monkeypatch.setattr(waf, "solve_waf", AsyncMock(return_value=False))
    else:
        monkeypatch.setattr(bypass, "solve_cloudflare", AsyncMock(return_value=False))
    with pytest.raises(TaskError) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.reason == "need_verification"
    assert caught.value.data == {"guard": "challenge", "stage": "visit_guard"}
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
