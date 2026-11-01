"""CI 实测：Linux Chrome（Edge 选项）路径缺 ESA 自愈，前端 /api/oauth/<p> 换取被 WAF 挑战页挡下，
OAuth 已回跳却永远确认不了会话。覆盖：换取结局判定、仅在授权码未被使用时转交一次、Edge 启动挂自愈。"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from browser.oauth_flow import OAuthCallbackHandoff
from login import oauth

CALLBACK = "https://site.invalid/oauth/github?code=private-code&state=private-state"
API = "https://site.invalid/api/oauth/github?code=private-code&state=private-state&mode=login"


def _response(text, *, status=200, headers=None):
    return SimpleNamespace(status=status, headers=headers or {}, text=AsyncMock(return_value=text))


def _request(response=None, *, failure=None, delay=0.0):
    async def get_response():
        if delay:
            await asyncio.sleep(delay)
        return response
    return SimpleNamespace(url=API, failure=failure, response=get_response, post_data=None)


def _handoff(request=None):
    handoff = OAuthCallbackHandoff()
    handoff.url, handoff.provider, handoff.valid = CALLBACK, "github", True
    handoff.page = SimpleNamespace(is_closed=lambda: False, url=CALLBACK)
    if request is not None:
        handoff.consumed, handoff.request = True, request
    return handoff


@pytest.mark.parametrize("response, expected", [
    (_response(json.dumps({"success": True, "data": {"id": 1}})), "success"),
    (_response("<html><script>var arg1='00'</script></html>"), "challenge"),
    (_response("", headers={"x-tengine-error": "denied by Anti-Bot"}), "challenge"),
    (_response("garbage"), "not_json"),
    (_response(json.dumps({"success": False, "message": "state is empty or not same"}), status=403), "failed"),
    (_response("{}", status=429), "http_429"),
])
def test_exchange_outcome_classifies_frontend_exchange(response, expected):
    kind, _message = asyncio.run(_handoff(_request(response)).exchange_outcome())
    assert kind == expected


def test_exchange_outcome_failure_kinds_and_redaction():
    assert asyncio.run(_handoff().exchange_outcome()) == ("unobserved", "")
    assert asyncio.run(_handoff(_request(failure="net::ERR_CONNECTION_RESET")).exchange_outcome())[0] == "network"
    assert asyncio.run(_handoff(_request(failure="net::ERR_ABORTED")).exchange_outcome())[0] == "aborted"
    assert asyncio.run(_handoff(_request(_response("{}"), delay=1)).exchange_outcome(timeout=0.05))[0] == "pending"
    leaked = _response(json.dumps({"success": False, "message": "bad code private-code"}))
    assert asyncio.run(_handoff(_request(leaked)).exchange_outcome()) == ("failed", "")


def test_consumption_keeps_first_matching_request_only():
    handoff = _handoff()
    first, second = _request(), _request()
    handoff.observe_consumption(first)
    handoff.observe_consumption(second)
    assert handoff.consumed and handoff.request is first
    handoff.close()
    assert handoff.request is None


@pytest.mark.parametrize("kind, message, retry", [
    ("challenge", "", True), ("not_json", "", True), ("network", "", True), ("http_429", "", True),
    ("failed", "state is empty or not same", True), ("failed", "用户已被封禁", False),
    ("success", "", False), ("aborted", "", False), ("http_502", "", False), ("unobserved", "", False),
])
def test_only_exchanges_that_never_used_the_code_are_retryable(kind, message, retry):
    assert oauth._exchange_retryable(kind, message) is retry


def _ctx(logs):
    return SimpleNamespace(base_url="https://site.invalid", log=logs.append, deadline=None,
                           endpoint=lambda _name: "/api/user/self")


def _run_confirm(monkeypatch, handoff, confirmations, logs, *, budget=3.5):
    calls = iter(confirmations)
    last = {"value": confirmations[-1]}

    async def confirm(_ctx, _page):
        try:
            last["value"] = next(calls)
        except StopIteration:
            pass
        return last["value"]

    forwarded = []

    async def forward(_ctx, _page, *, handoff=None, deadline=None):
        if handoff.forwarded or (handoff.consumed and not handoff.exchange_retryable):
            return False
        handoff.forwarded = True
        forwarded.append(True)
        return True

    monkeypatch.setattr(oauth, "_server_confirms_login", confirm)
    monkeypatch.setattr(oauth, "_forward_callback_to_api", forward)
    start = time.monotonic()
    page = SimpleNamespace(url="https://site.invalid/login")
    result = asyncio.run(oauth._confirm_after_relogin(
        _ctx(logs), page, start + budget + 1, export_reserve=1, handoff=handoff,
    ))
    return result, forwarded


def test_challenged_frontend_exchange_is_forwarded_once_and_confirms(monkeypatch):
    """CI 场景：前端换取拿到 WAF 挑战页，/api/user/self 也是挑战页（unknown）——旧逻辑从不转交。"""
    handoff = _handoff(_request(_response("<html>var arg1='00'</html>")))
    unknown = {"status": "unknown", "identity": {}, "reason": "challenge_html"}
    ok = {"status": "ok", "identity": {"user_id": "7"}, "reason": "ok", "http": 200, "has_user": True}
    logs: list[str] = []
    result, forwarded = _run_confirm(monkeypatch, handoff, [unknown, unknown, ok], logs)
    assert result and forwarded == [True]
    assert any("前端授权换取结果：challenge" in line for line in logs)
    assert any("原因=challenge_html" in line for line in logs)
    assert "private-code" not in str(logs) and "private-state" not in str(logs)


def test_successful_or_backend_failed_exchange_is_never_resent(monkeypatch):
    for body in ({"success": True, "data": {"id": 7}}, {"success": False, "message": "用户已被封禁"}):
        handoff = _handoff(_request(_response(json.dumps(body))))
        rejected = {"status": "rejected", "identity": {}, "reason": "http_401", "http": 401}
        logs: list[str] = []
        result, forwarded = _run_confirm(monkeypatch, handoff, [rejected], logs, budget=2.5)
        assert not result and forwarded == []
        assert sum("前端授权换取结果" in line for line in logs) == 1


def test_confirm_js_reports_reason_without_values():
    """原因码只是枚举/布尔，确认脚本不把令牌或身份值放进诊断字段。"""
    script = oauth._CONFIRM_LOGIN_JS
    for reason in ("challenge_html", "not_json", "no_identity", "fetch_timeout", "identity_mismatch"):
        assert f"'{reason}'" in script
    detail = oauth._confirmation({"status": "unknown", "reason": "challenge_html", "http": 200,
                                  "has_user": False, "token": "secret-token"}).detail
    assert detail == {"reason": "challenge_html", "http": 200, "has_user": False}


def test_edge_launch_installs_waf_healer(monkeypatch):
    from browser import bypass, waf
    from playwright import async_api

    context = SimpleNamespace(close=AsyncMock(), on=Mock())
    raw_browser = SimpleNamespace(new_context=AsyncMock(return_value=context), close=AsyncMock(), contexts=[context])
    chromium = SimpleNamespace(launch=AsyncMock(return_value=raw_browser))
    manager = SimpleNamespace(start=AsyncMock(return_value=SimpleNamespace(chromium=chromium)), __aexit__=AsyncMock())
    monkeypatch.setenv("CHECKIN_EDGE_NATIVE", "0")
    monkeypatch.delenv("CHECKIN_EDGE_HTTP1", raising=False)
    monkeypatch.setattr(async_api, "async_playwright", Mock(return_value=manager))
    monkeypatch.setattr(bypass, "_edge_executable_path", lambda: "/usr/bin/google-chrome")
    installed = []
    monkeypatch.setattr(waf, "install_esa_healer", lambda ctx: installed.append(ctx) or True)

    async def scenario():
        browser, ctx = await bypass._launch_edge(headless=False, proxy=None, locale="zh-CN", timeout=1000, log=None)
        assert ctx is context
        await browser.close()

    asyncio.run(scenario())
    assert installed == [context]
