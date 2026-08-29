"""HTTP 层：重试边界、代理显式化、防护页判别与一次性续期。

这四条都是踩过的坑，不是理论洁癖：
- 非幂等请求默认不重试，否则一次网络抖动可能变成两次真实签到；
- 代理必须显式，进程环境里的隐式代理会造成「本机能跑、CI 走了别的出口」；
- Cloudflare 拦截页与挑战页要分开，否则会为一个浏览器同样过不去的 IP 封禁白开浏览器；
- 401 的续期只做一次，多于一次说明续期没解决问题，继续重放只是空耗。
"""

from __future__ import annotations

import urllib.request

import pytest

from core.errors import ConfigError, LoginRequired, TaskError, TransientError
from net import guard
from net.http import HttpClient, HttpConfig


def _client(**overrides) -> HttpClient:
    config = HttpConfig(timeout=1, max_attempts=3, backoff_base=0, backoff_cap=0, **overrides)
    return HttpClient(base_url="https://example.invalid", config=config)


def test_retry_only_for_idempotent_methods(monkeypatch) -> None:
    calls: list[str] = []
    client = _client()

    def fake_once(self, url, *, method, headers, body, timeout):
        calls.append(method)
        if len(calls) == 1:
            raise TransientError("temporary", status=503)
        return '{"ok": true}'

    monkeypatch.setattr(HttpClient, "_once", fake_once)
    monkeypatch.setattr("time.sleep", lambda _delay: None)

    assert client.get("/x") == {"ok": True}
    assert calls == ["GET", "GET"]

    calls.clear()
    with pytest.raises(TransientError):
        client.post("/x")
    assert calls == ["POST"], "POST 默认只发一次：重放可能造成两次真实写入"


def test_non_idempotent_retry_requires_opt_in(monkeypatch) -> None:
    calls: list[str] = []
    client = _client()

    def fake_once(self, url, *, method, headers, body, timeout):
        calls.append(method)
        if len(calls) == 1:
            raise TransientError("temporary", status=503)
        return '{"ok": true}'

    monkeypatch.setattr(HttpClient, "_once", fake_once)
    monkeypatch.setattr("time.sleep", lambda _delay: None)

    assert client.request("POST", "/x", retry_non_idempotent=True) == {"ok": True}
    assert calls == ["POST", "POST"]


def test_proxy_handler_is_explicit() -> None:
    opener = _client(proxy="http://user:pass@proxy.invalid:8080")._opener()
    handlers = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert len(handlers) == 1
    assert handlers[0].proxies["https"] == "http://user:pass@proxy.invalid:8080"


def test_direct_connection_ignores_process_proxy_env(monkeypatch) -> None:
    """没配代理时，进程环境里的 HTTP_PROXY 不得生效。

    否则会出现「本机直连能跑、CI 悄悄走了别的出口」，而出口 IP 恰恰决定会不会被
    站点风控。实现方式是显式传一个空 ``ProxyHandler``，让 ``build_opener`` 不再装
    那个会读环境变量的默认代理处理器。
    """
    monkeypatch.setenv("HTTP_PROXY", "http://should-not-be-used.invalid:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://should-not-be-used.invalid:3128")

    opener = _client()._opener()
    configured = [
        proxies
        for handler in opener.handlers
        if isinstance(handler, urllib.request.ProxyHandler)
        for proxies in (handler.proxies,)
    ]
    assert all(not proxies for proxies in configured)
    assert "should-not-be-used.invalid" not in repr(opener.handlers)


def test_socks_proxy_is_rejected_with_actionable_message() -> None:
    with pytest.raises(ConfigError, match="SOCKS"):
        _client(proxy="socks5://127.0.0.1:1080")._opener()


def test_cloudflare_block_and_challenge_are_distinguished() -> None:
    """拦截页与挑战页必须分开：前者浏览器也过不去，开浏览器纯属空耗。"""
    block = (
        "<!doctype html><html><head><title>Attention Required! | Cloudflare</title></head>"
        '<body>Sorry, you have been blocked<div id="cf-footer-ip">1.2.3.4</div>'
        "Cloudflare Ray ID: 8a1b2c3d4e5f</body></html>"
    )
    challenge = "<!doctype html><html><body>Just a moment... cf_chl_opt</body></html>"

    assert guard.guard_kind(block) is guard.GuardKind.BLOCK
    assert guard.guard_kind(challenge) is guard.GuardKind.CHALLENGE

    described = guard.describe_html_body(block)
    assert "出口 IP" in described and "1.2.3.4" in described
    assert "8a1b2c3d4e5f" in described


def test_auth_refresher_replays_once_and_only_once(monkeypatch) -> None:
    """401 触发一次续期并重放；第二次 401 直接上报，不再无限续期。"""
    attempts: list[str] = []
    client = _client()

    def fake_once(self, url, *, method, headers, body, timeout):
        attempts.append(str(headers.get("Authorization") or "-"))
        raise LoginRequired("token expired", status=401)

    monkeypatch.setattr(HttpClient, "_once", fake_once)

    renewals: list[int] = []

    def refresher(_exc: TaskError) -> HttpClient:
        renewals.append(1)
        return client.with_auth(access_token="fresh")

    client.auth_refresher = refresher
    with pytest.raises(LoginRequired):
        client.get("/x")

    assert len(renewals) == 1, "续期只做一次"
    assert attempts == ["-", "Bearer fresh"], "续期后必须用新凭据重放同一请求"


def test_auth_refresher_failure_keeps_original_conclusion(monkeypatch) -> None:
    """续期本身出错时，调用方拿到的仍是「登录失效」而不是续期的内部异常。"""
    client = _client()

    def fake_once(self, url, *, method, headers, body, timeout):
        raise LoginRequired("token expired", status=401)

    monkeypatch.setattr(HttpClient, "_once", fake_once)

    def broken(_exc: TaskError):
        raise RuntimeError("refresh endpoint down")

    client.auth_refresher = broken
    with pytest.raises(LoginRequired, match="token expired"):
        client.get("/x")
