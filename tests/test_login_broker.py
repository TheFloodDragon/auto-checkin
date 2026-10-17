"""登录经纪人：候选链、跳过原因、终局失败、请求中途续期。

这些语义取代了旧实现里四处各写一遍的降级逻辑。最重要的一条不变量是
**「为什么没走这条路」必须可读**：旧代码只能靠读源码推断，用户看到的永远是一句
「登录态无效或已过期」。
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from config import schema
from core.errors import ConfigError, LoginRequired, TaskError, TransientError, VerificationRequired
from core.flow import StagePlan
from login import LOGINS
from login.base import Availability, LoginContext, LoginState, READY
from login.refresh import RefreshLogin
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
    """续期请求自身 401 不得再触发 auth_refresher，避免递归续期直到撞上 429。"""
    seen: list[Any] = []
    rejected = LoginRequired("续期端点 401", status=401)

    def fake_send(self, method, path, **kwargs):
        seen.append(self.auth_refresher)
        raise rejected

    monkeypatch.setattr(net_http.HttpClient, "_send", fake_send)

    def sentinel(_exc):
        raise AssertionError("续期请求不得再触发 auth_refresher（会无限递归）")

    ctx = _ctx(account={"credentials": {"refresh_token": "rt_demo"}})
    ctx.http.auth_refresher = sentinel

    with pytest.raises(LoginRequired) as caught:
        RefreshLogin().authenticate(ctx)

    assert caught.value is rejected
    assert seen == [None], f"续期请求应在禁用 auth_refresher 的客户端上发出，实际记录 {seen}"
    assert ctx.http.auth_refresher is sentinel, "只禁用派生客户端，不得清除基线客户端的续期钩子"


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(LoginRequired("凭据被拒绝", status=401), id="login-required-401"),
        pytest.param(LoginRequired("凭据被拒绝", status=403), id="login-required-403"),
        pytest.param(VerificationRequired("需要人机验证", status=403), id="verification-403"),
        pytest.param(VerificationRequired("需要人机验证", status=503), id="verification-503"),
        pytest.param(TransientError("请求过多", status=429), id="rate-limited-429"),
        pytest.param(TransientError("服务端暂时失败", status=500), id="transient-500"),
        pytest.param(TransientError("网关暂时失败", status=502), id="transient-502"),
        pytest.param(TransientError("服务暂不可用", status=503), id="transient-503"),
        pytest.param(TransientError("网关超时", status=504), id="transient-504"),
        pytest.param(TransientError("网络失败", status=403), id="transient-403"),
        pytest.param(
            TransientError("连接超时", data={"stage": "connection", "error_code": "TimeoutError"}),
            id="transient-timeout",
        ),
        pytest.param(TaskError("普通服务端失败", status=500), id="generic-server-error"),
        pytest.param(TaskError("请求内容错误", status=400), id="generic-bad-request"),
        pytest.param(
            TaskError("上游连接失败", reason="network_error", status=401), id="network-error-401"
        ),
        pytest.param(
            TaskError("上游连接失败", reason="network_error", status=403), id="network-error-403"
        ),
        pytest.param(TaskError("需要人工验证", reason="need_verification", status=403), id="verification-reason-403"),
        pytest.param(ConfigError("TLS 证书无效"), id="tls-configuration-error"),
        pytest.param(
            net_http._http_error(403, "<html><body>Forbidden</body></html>", retry_statuses=frozenset()),
            id="unclassified-html-403",
        ),
    ],
)
def test_refresh_preserves_classified_failures(monkeypatch, error: TaskError) -> None:
    """错误类型与结论由 HTTP 层决定，续期不能把所有失败重包成登录失效。"""
    expected_outcome = error.to_outcome()
    original_payload = error.payload
    seen: list[Any] = []

    def fake_send(self, method, path, **kwargs):
        seen.append(self.auth_refresher)
        raise error

    monkeypatch.setattr(net_http.HttpClient, "_send", fake_send)
    ctx = _ctx(account={"credentials": {"refresh_token": "rt_demo"}})

    with pytest.raises(type(error)) as caught:
        RefreshLogin().authenticate(ctx)

    assert caught.value is error
    assert caught.value.to_outcome() == expected_outcome
    assert caught.value.payload is original_payload
    assert seen == [None]


@pytest.mark.parametrize("status", [401, 403])
def test_refresh_keeps_explicit_http_credential_rejection_as_need_login(monkeypatch, status: int) -> None:
    """普通 HTTP 认证拒绝已由统一分类器转为 LoginRequired，仍允许候选链降级。"""
    error = net_http._http_error(status, '{"message": "invalid refresh token"}', retry_statuses=frozenset())
    assert isinstance(error, LoginRequired)

    def fake_send(self, method, path, **kwargs):
        raise error

    monkeypatch.setattr(net_http.HttpClient, "_send", fake_send)
    ctx = _ctx(account={"credentials": {"refresh_token": "rt_demo"}})

    with pytest.raises(LoginRequired) as caught:
        RefreshLogin().authenticate(ctx)

    assert caught.value is error
    assert caught.value.reason == "need_login"
    assert caught.value.status == status
    assert caught.value.payload == {"message": "invalid refresh token"}


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(TimeoutError("连接超时"), id="timeout"),
        pytest.param(ConnectionError("连接断开"), id="connection-error"),
    ],
)
def test_refresh_preserves_unclassified_network_failures(monkeypatch, error: Exception) -> None:
    def fake_send(self, method, path, **kwargs):
        raise error

    monkeypatch.setattr(net_http.HttpClient, "_send", fake_send)
    ctx = _ctx(account={"credentials": {"refresh_token": "rt_demo"}})

    with pytest.raises(type(error)) as caught:
        RefreshLogin().authenticate(ctx)

    assert caught.value is error


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({}, id="empty-response"),
        pytest.param({"data": {"refresh_token": "rt_rotated"}}, id="refresh-token-only"),
        pytest.param({"data": {"access_token": ""}}, id="empty-access-token"),
    ],
)
def test_refresh_response_without_access_token_requires_login(monkeypatch, payload: Any) -> None:
    def fake_send(self, method, path, **kwargs):
        assert self.auth_refresher is None
        return payload

    monkeypatch.setattr(net_http.HttpClient, "_send", fake_send)
    ctx = _ctx(account={"credentials": {"access_token": "at_old", "refresh_token": "rt_old"}})

    with pytest.raises(LoginRequired, match="没有可用的 access_token") as caught:
        RefreshLogin().authenticate(ctx)

    assert caught.value.reason == "need_login"
    assert ctx.credentials.access_token == "at_old"
    assert ctx.credentials.refresh_token == "rt_old"


@pytest.mark.parametrize("rotated", ["rt_rotated", None, "rt_original"], ids=["rotation", "omitted", "unchanged"])
def test_refresh_rotation_updates_context_for_subsequent_renewal(monkeypatch, rotated: str | None) -> None:
    """首次续期合并凭据后，下次同步续期要使用最新 RT；没返回 RT 时保留原值。"""
    from unittest.mock import Mock

    initial_credentials = {
        "access_token": "at_original",
        "refresh_token": "rt_original",
        "cookie": "session=keep",
        "browser_state": "synthetic-browser-state",
    }
    first_payload = {"access_token": "at_first"}
    if rotated is not None:
        first_payload["refresh_token"] = rotated
    responses = iter([{"data": first_payload}, {"data": {"access_token": "at_second"}}])
    sent_tokens: list[str] = []

    def fake_send(self, method, path, **kwargs):
        assert method == "POST"
        assert path == "/api/v1/auth/refresh"
        assert self.auth_refresher is None
        sent_tokens.append(kwargs["json_body"]["refresh_token"])
        return next(responses)

    monkeypatch.setattr(net_http.HttpClient, "_send", fake_send)
    browser = Mock()
    sentinel = Mock(side_effect=AssertionError("续期请求不得调用续期钩子"))
    ctx = _ctx(account={"credentials": initial_credentials}, browser=browser)
    ctx.http.auth_refresher = sentinel
    persisted: list[tuple[dict[str, str], str]] = []

    def on_credentials(credentials, origin):
        persisted.append((dict(credentials), origin))

    result = asyncio.run(LOGINS.establish(ctx, _plan("refresh", locked=True), on_credentials=on_credentials))

    assert result.outcome is None
    assert result.state is not None and result.state.verified
    assert result.state.method == "refresh"
    assert result.state.origin == "refresh"
    assert result.state.headers["Authorization"] == "Bearer at_first"
    expected_first = {"access_token": "at_first"}
    if rotated and rotated != "rt_original":
        expected_first["refresh_token"] = rotated
    assert result.state.credentials == expected_first
    assert ctx.credentials.access_token == "at_first"
    assert ctx.credentials.refresh_token == (rotated or "rt_original")

    renewed = LOGINS.renew_sync(
        ctx, _plan("refresh", locked=True), current="access_token", on_credentials=on_credentials
    )

    assert renewed is not None and renewed.verified
    assert renewed.credentials == {"access_token": "at_second"}
    assert renewed.headers["Authorization"] == "Bearer at_second"
    assert sent_tokens == ["rt_original", rotated or "rt_original"]
    assert ctx.credentials.access_token == "at_second"
    assert ctx.credentials.refresh_token == (rotated or "rt_original")
    assert ctx.credentials.cookie == initial_credentials["cookie"]
    assert ctx.credentials.browser_state == initial_credentials["browser_state"]
    assert persisted == [(expected_first, "refresh"), ({"access_token": "at_second"}, "refresh")]
    assert ctx.http.auth_refresher is sentinel
    sentinel.assert_not_called()
    browser.mark_authenticated.assert_not_called()
