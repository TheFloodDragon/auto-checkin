"""访问保活的浏览器兜底必须区分登录、防护与网络故障。"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

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


def test_html_markers_past_old_preview_are_classified(browser_context):
    ctx, page, _lease = browser_context
    page.evaluate.return_value = {
        "status": 403,
        "body": "<!doctype html>" + " " * 400 + "<title>Sorry, you have been blocked</title>",
    }
    with pytest.raises(TaskError) as caught:
        asyncio.run(visit._fetch_in_browser(ctx, "/api/user/self"))
    assert caught.value.reason == "blocked"
