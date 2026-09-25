"""登录经纪人：候选链、跳过原因、终局失败、请求中途续期。

这些语义取代了旧实现里四处各写一遍的降级逻辑。最重要的一条不变量是
**「为什么没走这条路」必须可读**：旧代码只能靠读源码推断，用户看到的永远是一句
「登录态无效或已过期」。
"""

from __future__ import annotations

import asyncio
from typing import Any

from config import schema
from core.flow import StagePlan
from login import LOGINS
from login.base import Availability, LoginContext, LoginState, READY
from net import http as net_http
from templates import registry as templates


def _ctx(**overrides: Any) -> LoginContext:
    payload = {
        "id": "demo",
        "name": "demo",
        "base_url": "https://demo.invalid",
        "template": "newapi",
        "tasks": [{"id": "daily"}],
    }
    payload.update(overrides.pop("account", {}))
    spec = schema.parse_account(payload)
    from config.overlay import Overlay

    # 直接用覆盖层解析：这样测试走的是与运行期完全相同的凭据来源路径。
    account = Overlay(path=overrides.pop("overlay_path", None)).apply(spec)
    logs: list[str] = []
    ctx = LoginContext(
        account=account,
        template=templates.get("newapi"),
        http=net_http.HttpClient(base_url=spec.base_url),
        capabilities=overrides.pop("capabilities", frozenset()),
        log=logs.append,
        **overrides,
    )
    ctx.logs = logs  # type: ignore[attr-defined]
    return ctx


def _plan(*candidates: str, locked: bool = False) -> StagePlan:
    return StagePlan(
        stage="login", mode="fixed" if locked else "auto", candidates=tuple(candidates), source="config"
    )


def test_missing_credentials_are_reported_per_candidate() -> None:
    """每个候选为什么没走通都要说清楚，而不是一句「登录失效」。"""
    ctx = _ctx()
    result = asyncio.run(LOGINS.establish(ctx, _plan("access_token", "cookie")))

    assert result.state is None
    assert result.outcome is not None and result.outcome.reason == "need_config"
    described = result.describe()
    assert "access_token=跳过" in described and "cookie=跳过" in described
    assert "为空" in described


def test_first_usable_candidate_wins_and_is_recorded() -> None:
    ctx = _ctx(account={"credentials": {"cookie": "s=1"}})
    result = asyncio.run(LOGINS.establish(ctx, _plan("access_token", "cookie")))

    assert result.state is not None and result.state.method == "cookie"
    assert result.discovery is not None and result.discovery.value == "cookie"
    assert result.state.headers["Cookie"] == "s=1"


def test_cookie_login_never_sends_bearer() -> None:
    """选了 Cookie 就走 Cookie。

    旧实现同时返回两者，客户端只要看见 token 就发 Bearer 并剥掉 session cookie，
    于是「选了 Cookie 实际走 Token」——可能是另一个账号的身份，且极难定位。
    """
    ctx = _ctx(account={"credentials": {"cookie": "s=1", "access_token": "a.b.c"}})
    result = asyncio.run(LOGINS.establish(ctx, _plan("cookie")))

    assert "Authorization" not in result.state.headers


def test_missing_capability_skips_without_trying() -> None:
    """没有浏览器时，浏览器类候选直接跳过并说明原因，不该跑到一半才发现。"""
    ctx = _ctx(account={"credentials": {"browser_state": "state"}}, capabilities=frozenset())
    result = asyncio.run(LOGINS.establish(ctx, _plan("browser_state")))

    assert result.state is None
    assert "浏览器" in result.describe()


def test_locked_chain_stops_at_first_failure() -> None:
    """固定登录方式时不许自行扩大候选：失败就失败。"""
    ctx = _ctx(account={"credentials": {"cookie": "s=1"}})
    result = asyncio.run(LOGINS.establish(ctx, _plan("access_token", locked=True)))

    assert result.state is None
    assert "cookie" not in result.describe(), "锁定时不得尝试没被列出的方式"


def test_verification_failure_is_terminal_for_the_whole_chain() -> None:
    """人机验证是站点层面的拒绝，与用哪把钥匙无关，继续换方式只是空耗。"""
    from core.errors import VerificationRequired

    class Blocked:
        id = "access_token"
        requires: frozenset[str] = frozenset()

        def available(self, ctx: LoginContext, option: Any = None) -> Availability:
            return READY

        def authenticate(self, ctx: LoginContext, option: Any = None) -> LoginState:
            raise VerificationRequired("站点要求人机验证")

    broker = type(LOGINS)({"access_token": Blocked(), "cookie": LOGINS.get("cookie")})
    ctx = _ctx(account={"credentials": {"cookie": "s=1"}})
    result = asyncio.run(broker.establish(ctx, _plan("access_token", "cookie")))

    assert result.state is None
    assert result.outcome.reason == "need_verification"
    assert "cookie" not in result.describe()


def test_sync_renewal_skips_browser_candidates_with_a_clear_reason() -> None:
    """请求中途续期只能用同步方式：此刻调用栈正在同步的 HTTP 调用里。"""
    ctx = _ctx(account={"credentials": {"browser_state": "state"}}, capabilities=frozenset({"browser"}))
    ctx.browser = object()  # 让 available() 通过
    state = LOGINS.renew_sync(ctx, _plan("browser_state"), current="access_token")

    assert state is None
    assert any("浏览器" in line for line in ctx.logs)  # type: ignore[attr-defined]


def test_unknown_method_is_reported_not_crashed() -> None:
    ctx = _ctx()
    result = asyncio.run(LOGINS.establish(ctx, _plan("telepathy")))
    assert "未知登录方式" in result.describe()


def test_normal_oauth_still_reuses_server_confirmed_cached_site_session(monkeypatch) -> None:
    """强制新授权只属于 relogin，不能让正常登录重复 OAuth。"""
    from contextlib import asynccontextmanager
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock

    from browser.service import encode_state
    from login import oauth

    state_text = encode_state({
        "cookies": [{"name": "session", "value": "cached", "domain": "demo.invalid", "path": "/"}],
        "origins": [],
    })
    context = SimpleNamespace(storage_state=AsyncMock(return_value={
        "cookies": [{"name": "session", "value": "cached", "domain": "demo.invalid", "path": "/"}],
        "origins": [],
    }))
    page = SimpleNamespace(url="https://demo.invalid", evaluate=AsyncMock(return_value=True))
    lease = SimpleNamespace(
        new_page=AsyncMock(return_value=page), context=context,
        oauth=AsyncMock(side_effect=AssertionError("普通 OAuth 缓存有效时不得新授权")),
    )
    used = []

    @asynccontextmanager
    async def borrow(**kwargs):
        used.append(kwargs)
        yield lease

    shared_state = Mock(side_effect=AssertionError("站点缓存有效时不需要读取共享态"))
    ctx = _ctx(
        account={"credentials": {"browser_state": state_text}, "login": {"method": "oauth", "provider": "github"}},
        capabilities=frozenset({"browser"}),
        browser=SimpleNamespace(lease=borrow),
        oauth_state=shared_state,
    )
    monkeypatch.setattr(oauth, "settle_page", AsyncMock())
    result = asyncio.run(LOGINS.establish(ctx, _plan("oauth", locked=True)))

    assert result.outcome is None
    assert result.state is not None and result.state.verified
    assert result.state.headers["Cookie"] == "session=cached"
    assert len(used) == 1 and used[0]["state_text"] == state_text
    assert "复用" in result.state.note
    lease.oauth.assert_not_awaited()
    shared_state.assert_not_called()
    page.evaluate.assert_awaited_once()


    def test_refresh_request_disables_auth_refresher_to_avoid_recursion(monkeypatch) -> None:
        """续期请求自身 401 不得再触发 auth_refresher，否则续期钩子会递归调用自己、把
        /api/v1/auth/refresh 反复打到 429（vcnovb / 极速蹬 日志里数百次 invalid refresh
        token 即由此产生）。"""
        from core.errors import LoginRequired
        from login.refresh import RefreshLogin

        seen: list[Any] = []

        def fake_send(self, method, path, **kwargs):
            seen.append(self.auth_refresher)
            raise LoginRequired("续期端点 401", status=401)

        monkeypatch.setattr(net_http.HttpClient, "_send", fake_send)

        def sentinel(_exc):
            raise AssertionError("续期请求不得再触发 auth_refresher（会无限递归）")

        ctx = _ctx(account={"credentials": {"refresh_token": "rt_demo"}})
        ctx.http.auth_refresher = sentinel

        try:
            RefreshLogin().authenticate(ctx)
        except LoginRequired:
            pass
        else:
            raise AssertionError("续期端点返回 401 时应抛 LoginRequired")

        assert seen == [None], f"续期请求应在禁用 auth_refresher 的客户端上发出，实际记录 {seen}"
