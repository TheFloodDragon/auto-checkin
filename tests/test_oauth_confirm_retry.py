"""OAuth 前置会话校验：页面自跳转销毁执行上下文时应在原预算内重读，而不是误判「无法确认」。"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from login import oauth


def _ctx(logs):
    return SimpleNamespace(endpoint=lambda _name: "/api/user/self", base_url="https://anyrouter.top",
                           deadline=None, log=logs.append)


def _page(*results):
    return SimpleNamespace(url="https://anyrouter.top/console", evaluate=AsyncMock(side_effect=list(results)),
                           wait_for_load_state=AsyncMock())


def _run(page, logs, monkeypatch):
    monkeypatch.setattr(oauth.asyncio, "sleep", AsyncMock())
    return asyncio.run(oauth._server_confirms_login(_ctx(logs), page))


def test_navigation_destroyed_context_is_retried(monkeypatch):
    logs: list[str] = []
    page = _page(RuntimeError("Page.evaluate: Execution context was destroyed, most likely because of a navigation"),
                 {"status": "rejected", "identity": {}})
    result = _run(page, logs, monkeypatch)
    assert result.status == "rejected"
    assert page.evaluate.await_count == 2
    page.wait_for_load_state.assert_awaited()
    assert logs == []


def test_unknown_challenge_read_is_retried_until_decisive(monkeypatch):
    logs: list[str] = []
    page = _page({"status": "unknown"}, {"status": "ok", "identity": {"user_id": "7"}})
    result = _run(page, logs, monkeypatch)
    assert result.status == "ok" and result.identity == {"user_id": "7"}
    assert page.evaluate.await_count == 2


def test_attempts_are_bounded_and_stay_unknown(monkeypatch):
    logs: list[str] = []
    page = _page(*([{"status": "unknown"}] * 5))
    assert _run(page, logs, monkeypatch).status == "unknown"
    assert page.evaluate.await_count == oauth._CONFIRM_ATTEMPTS


def test_non_navigation_errors_are_not_retried(monkeypatch):
    logs: list[str] = []
    page = _page(RuntimeError("Target page, context or browser has been closed"), {"status": "ok"})
    assert _run(page, logs, monkeypatch).status == "unknown"
    assert page.evaluate.await_count == 1
    assert logs and "会话校验未能完成" in logs[0]


def test_retry_stops_when_page_left_site_origin(monkeypatch):
    logs: list[str] = []
    page = _page(RuntimeError("Execution context was destroyed"), {"status": "ok"})

    async def leave(*_args, **_kwargs):
        page.url = "https://connect.linux.do/oauth2/authorize"

    page.wait_for_load_state = AsyncMock(side_effect=leave)
    assert _run(page, logs, monkeypatch).status == "unknown"
    assert page.evaluate.await_count == 1
