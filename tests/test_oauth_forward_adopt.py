"""转交 /api/oauth/<p> 后补写前端身份：文档导航不会跑 SPA 回调脚本，缺 localStorage.user
就没有 New-Api-User 头，已成功的登录会被误判为「服务端未确认」（实测 AnyRouter）。"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

from browser.oauth_flow import OAuthCallbackHandoff
from login import oauth

CALLBACK = "https://anyrouter.top/oauth/linuxdo?code=private-code&state=private-state"


def _setup(body, *, page_url="https://anyrouter.top/api/oauth/linuxdo?code=x&state=y", evaluate_result="stored"):
    logs: list[str] = []
    response = SimpleNamespace(text=AsyncMock(return_value=body if isinstance(body, str) else json.dumps(body)))
    page = SimpleNamespace(url=page_url, goto=AsyncMock(return_value=response),
                           evaluate=AsyncMock(return_value=evaluate_result), is_closed=lambda: False)
    ctx = SimpleNamespace(base_url="https://anyrouter.top", log=logs.append)
    handoff = OAuthCallbackHandoff()
    handoff.page, handoff.url, handoff.provider, handoff.valid = page, CALLBACK, "linuxdo", True
    return ctx, page, handoff, logs


def _forward(ctx, page, handoff):
    return asyncio.run(oauth._forward_callback_to_api(ctx, page, handoff=handoff, deadline=time.monotonic() + 3))


def test_successful_forward_stores_frontend_user():
    user = {"id": 128827, "username": "someone", "role": 1}
    ctx, page, handoff, logs = _setup({"success": True, "message": "", "data": user})
    assert _forward(ctx, page, handoff) is True
    page.evaluate.assert_awaited_once()
    script, args = page.evaluate.await_args.args
    assert "localStorage.setItem('user'" in script and args == [user]
    assert any("补写站点前端身份" in line for line in logs)
    joined = str(logs)
    assert "private-code" not in joined and "private-state" not in joined and "128827" not in joined


def _adopt_calls(page):
    return [call for call in page.evaluate.await_args_list if call.args and call.args[0] == oauth._ADOPT_USER_JS]


def test_failed_or_non_json_forward_does_not_store(monkeypatch):
    monkeypatch.setattr(oauth, "_SETTLED_BODY_SECONDS", 0.2)
    for body in ({"success": False, "message": "state 无效"}, {"success": True, "data": {}},
                 {"success": True, "data": {"id": True}}, "<html>var arg1='00'</html>"):
        ctx, page, handoff, _logs = _setup(body, evaluate_result=None)
        assert _forward(ctx, page, handoff) is True  # 已转交（授权码不重送），只是不补写身份
        assert not _adopt_calls(page)


def test_challenge_forward_reads_settled_document_json(monkeypatch):
    """转交导航先拿到 WAF 挑战页，页面脚本放行后重载出接口 JSON：应从最终文档补写身份。"""
    monkeypatch.setattr(oauth, "_SETTLED_BODY_SECONDS", 2.0)
    user = {"id": 178429, "username": "someone"}
    ctx, page, handoff, logs = _setup("<html><script>var arg1='00'</script></html>")
    seen = []

    async def evaluate(script, *args):
        seen.append(script)
        if script == oauth._BODY_JSON_JS:
            if seen.count(script) == 1:
                raise RuntimeError("Execution context was destroyed, most likely because of a navigation")
            return {"success": True, "data": user}
        return "stored"

    page.evaluate = AsyncMock(side_effect=evaluate)
    assert _forward(ctx, page, handoff) is True
    assert _adopt_calls(page) and _adopt_calls(page)[0].args[1] == [user]
    assert any("补写站点前端身份" in line for line in logs)
    assert "178429" not in str(logs) and "private-code" not in str(logs)


def test_cross_origin_page_is_not_written():
    ctx, page, handoff, _logs = _setup({"success": True, "data": {"id": 1}}, page_url="https://connect.linux.do/x")
    assert _forward(ctx, page, handoff) is True
    page.evaluate.assert_not_awaited()


def test_conflicting_existing_identity_is_not_reported_as_stored():
    ctx, page, handoff, logs = _setup({"success": True, "data": {"id": 2}}, evaluate_result="conflict")
    assert _forward(ctx, page, handoff) is True
    assert not any("补写站点前端身份" in line for line in logs)


def test_adopt_script_refuses_to_overwrite_different_identity():
    assert "String(prev.id) !== String(user.id)" in oauth._ADOPT_USER_JS
    assert "return 'conflict'" in oauth._ADOPT_USER_JS


def test_forward_still_sent_only_once():
    ctx, page, handoff, _logs = _setup({"success": True, "data": {"id": 3}})
    assert _forward(ctx, page, handoff) is True
    assert _forward(ctx, page, handoff) is False
    page.goto.assert_awaited_once()
