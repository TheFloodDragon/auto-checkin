"""浏览器登录态的服务端探测：只有「服务端明确拒绝」才该换下一种登录方式。

背景（实测 AnyRouter）：保存的 storage_state 里含一个**六天前就过期**的 ``session``
Cookie。它让浏览器照样过 WAF、照样拿到 Cookie，于是 ``browser_state`` 一路报「登录
成功」，接着每个业务请求都 401，而配置里排在它后面的 OAuth 兜底因为「已经登录成功」
永远不会被尝试。这里把三态判定钉死：rejected 才降级，unknown 保持原行为。
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from core.errors import LoginRequired
from login import browser_state as module
from login.base import LoginContext


BASE_URL = "https://example.test"


def make_ctx(*, page_result="rejected", user_path="/api/user/self", credentials="STATE") -> LoginContext:
    page = SimpleNamespace(
        url=BASE_URL + "/console",
        evaluate=AsyncMock(return_value=page_result),
    )
    lease = SimpleNamespace(
        new_page=AsyncMock(return_value=page),
        context=SimpleNamespace(
            storage_state=AsyncMock(return_value={
                "cookies": [{"name": "session", "value": "dead", "domain": "example.test"}],
                "origins": [],
            }),
        ),
    )
    browser = SimpleNamespace(lease=Mock(return_value=_AsyncCtx(lease)))
    template = SimpleNamespace(manifest=SimpleNamespace(endpoints={"user": user_path}))
    return LoginContext(
        account=SimpleNamespace(
            base_url=BASE_URL,
            credentials=SimpleNamespace(browser_state=credentials),
            network=SimpleNamespace(referer_path=""),
            origin=BASE_URL,
        ),
        template=template,
        http=SimpleNamespace(),
        args={},
        browser=browser,
        deadline=SimpleNamespace(remaining=lambda: 60.0),
        log=Mock(),
    )


class _AsyncCtx:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *exc):
        return False


def run(ctx):
    async def go():
        async def patched_settle(*_a, **_k):
            return None

        original = module.settle_page
        module.settle_page = patched_settle
        try:
            return await module.BrowserStateLogin().authenticate(ctx, None)
        finally:
            module.settle_page = original

    return asyncio.run(go())


def test_rejected_session_raises_need_login_so_fallbacks_run():
    with pytest.raises(LoginRequired) as caught:
        run(make_ctx(page_result="rejected"))
    assert caught.value.reason == "need_login"


def test_unknown_probe_keeps_legacy_unverified_behaviour():
    state = run(make_ctx(page_result="unknown"))
    assert state.verified is False
    assert state.credentials["session_cookie"].startswith("session=dead")


def test_confirmed_session_is_marked_verified():
    state = run(make_ctx(page_result="ok"))
    assert state.verified is True


def test_missing_user_endpoint_never_probes():
    ctx = make_ctx(page_result="rejected", user_path="")
    state = run(ctx)
    assert state.verified is False


def test_probe_is_three_state_and_swallows_errors():
    from browser.storage_scope import same_origin

    # 页面不在站点 origin 时直接放弃判定，不发请求。
    ctx = make_ctx()
    page = SimpleNamespace(url="https://elsewhere.invalid/", evaluate=AsyncMock(side_effect=AssertionError))
    assert asyncio.run(module.probe_server(ctx, page)) == "unknown"
    page.evaluate.assert_not_called()
    assert same_origin(BASE_URL, BASE_URL)
