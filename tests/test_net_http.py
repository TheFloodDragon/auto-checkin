"""HTTP 层：重试边界、代理显式化、防护页判别与一次性续期。

这四条都是踩过的坑，不是理论洁癖：
- 非幂等请求默认不重试，否则一次网络抖动可能变成两次真实签到；
- 代理必须显式，进程环境里的隐式代理会造成「本机能跑、CI 走了别的出口」；
- Cloudflare 拦截页与挑战页要分开，否则会为一个浏览器同样过不去的 IP 封禁白开浏览器；
- 401 的续期只做一次，多于一次说明续期没解决问题，继续重放只是空耗。
"""

from __future__ import annotations

import io
import json
import ssl
import urllib.error
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


def _raise_on_open(monkeypatch, exc: BaseException) -> None:
    """让底层 opener.open 抛出给定异常，用于验证 _once 的连接层错误分类。"""

    class _FakeOpener:
        def open(self, _request, timeout=None):  # noqa: ARG002
            raise exc

    monkeypatch.setattr(HttpClient, "_opener", lambda self: _FakeOpener())


def test_ssl_eof_is_classified_as_retryable_transport_error(monkeypatch) -> None:
    """SSL: UNEXPECTED_EOF_WHILE_READING 是连接层失败，归为可重试且不外泄 _ssl.c 行。"""
    client = _client()
    _raise_on_open(
        monkeypatch,
        ssl.SSLError("UNEXPECTED_EOF_WHILE_READING", "EOF occurred in violation of protocol (_ssl.c:1082)"),
    )
    monkeypatch.setattr("time.sleep", lambda _delay: None)

    with pytest.raises(TransientError) as excinfo:
        client.get("/x")

    error = excinfo.value
    assert error.reason == "network_error"
    assert (error.data or {}).get("stage") == "tls"
    assert "_ssl.c" not in error.message and "TLS" in error.message


def test_urlerror_wrapping_ssl_is_classified_as_transport(monkeypatch) -> None:
    """URLError 常把真正的 SSLError 包在 reason 里，也要归入连接层可重试错误。"""
    client = _client()
    inner = ssl.SSLError("UNEXPECTED_EOF_WHILE_READING", "EOF occurred")
    _raise_on_open(monkeypatch, urllib.error.URLError(inner))
    monkeypatch.setattr("time.sleep", lambda _delay: None)

    with pytest.raises(TransientError) as excinfo:
        client.get("/x")

    assert (excinfo.value.data or {}).get("stage") == "tls"


def test_connection_reset_is_classified_as_transport(monkeypatch) -> None:
    client = _client()
    _raise_on_open(monkeypatch, ConnectionResetError("connection reset by peer"))
    monkeypatch.setattr("time.sleep", lambda _delay: None)

    with pytest.raises(TransientError) as excinfo:
        client.get("/x")

    assert (excinfo.value.data or {}).get("stage") == "connection"


def test_ssl_eof_retries_when_idempotent_and_stops_at_one_attempt(monkeypatch) -> None:
    """连接层错误是可重试的：幂等请求按 max_attempts 重试，单次预算则只发一次。"""
    calls: list[str] = []

    class _FakeOpener:
        def open(self, _request, timeout=None):  # noqa: ARG002
            calls.append("open")
            raise ssl.SSLError("UNEXPECTED_EOF_WHILE_READING", "EOF occurred")

    monkeypatch.setattr(HttpClient, "_opener", lambda self: _FakeOpener())
    monkeypatch.setattr("time.sleep", lambda _delay: None)

    def client(max_attempts: int) -> HttpClient:
        config = HttpConfig(timeout=1, max_attempts=max_attempts, backoff_base=0, backoff_cap=0)
        return HttpClient(base_url="https://example.invalid", config=config)

    with pytest.raises(TransientError):
        client(3).get("/x")
    assert calls == ["open", "open", "open"]

    calls.clear()
    with pytest.raises(TransientError):
        client(1).get("/x")
    assert calls == ["open"], "max_attempts=1（如 relogin 只读比较）时不重试"


@pytest.mark.parametrize("wrapped", [False, True])
def test_certificate_failure_is_not_retried_or_reported_as_eof(monkeypatch, wrapped) -> None:
    from unittest.mock import Mock

    error = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    opener = Mock()
    opener.open.side_effect = urllib.error.URLError(error) if wrapped else error
    monkeypatch.setattr(HttpClient, "_opener", lambda self: opener)
    client = _client()

    with pytest.raises(ConfigError) as caught:
        client.get("/x")

    assert client.config.verify_ssl is True
    assert caught.value.data["error_code"] == "CERTIFICATE_VERIFY_FAILED"
    assert "提前关闭" not in caught.value.message
    opener.open.assert_called_once()


def test_generic_ssl_failure_does_not_claim_connection_reset(monkeypatch) -> None:
    error = ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] unsupported protocol (_ssl.c:1082)")
    _raise_on_open(monkeypatch, error)
    monkeypatch.setattr("time.sleep", lambda delay: None)
    with pytest.raises(TransientError) as caught:
        _client().get("/x")
    assert "TLS 通信失败" in caught.value.message
    assert "重置" not in caught.value.message
    assert "_ssl.c" not in caught.value.message


def test_ssl_eof_recovers_without_disabling_tls_or_switching_proxy(monkeypatch) -> None:
    from unittest.mock import MagicMock, Mock

    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"ok": true}'
    response.headers = {}
    error = ssl.SSLEOFError(8, "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred")
    opener = Mock()
    opener.open.side_effect = [urllib.error.URLError(error), response]
    monkeypatch.setattr(HttpClient, "_opener", lambda self: opener)
    monkeypatch.setattr("time.sleep", lambda delay: None)
    client = _client(proxy="http://127.0.0.1:7897")
    client.auth_refresher = Mock()

    assert client.get("/x") == {"ok": True}
    assert opener.open.call_count == 2
    assert client.config.verify_ssl is True
    assert client.config.proxy == "http://127.0.0.1:7897"
    client.auth_refresher.assert_not_called()


def test_ssl_eof_does_not_replay_post(monkeypatch) -> None:
    from unittest.mock import Mock

    opener = Mock()
    opener.open.side_effect = ssl.SSLEOFError(8, "[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred")
    monkeypatch.setattr(HttpClient, "_opener", lambda self: opener)
    with pytest.raises(TransientError) as caught:
        _client().post("/x")
    assert caught.value.data["error_code"] == "UNEXPECTED_EOF_WHILE_READING"
    opener.open.assert_called_once()


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


@pytest.mark.parametrize(
    ("status", "title"),
    [
        (520, "Web server is returning an unknown error"),
        (521, "Web server is down"),
        (522, "Connection timed out"),
        (523, "Origin is unreachable"),
        (524, "A timeout occurred"),
        (525, "SSL handshake failed"),
        (526, "Invalid SSL certificate"),
        (530, "Error 1033: Cloudflare Tunnel error"),
    ],
)
def test_cloudflare_origin_html_is_not_a_challenge_or_ip_block(status, title) -> None:
    from net.http import _http_error, parse_json
    from templates.builtin.newapi import classify

    text = (
        f"<!doctype html><html><head><title>{title} | {status}</title></head>"
        f'<body><div id="cf-error-details"><h1>{title}</h1>Cloudflare</div>'
        '<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script></body></html>'
    )
    assert guard.guard_kind(text) is guard.GuardKind.NONE
    assert guard.cloudflare_block_details(text) is None
    assert not guard.looks_like_verification(text)
    assert "封禁" not in guard.describe_html_body(text)

    error = _http_error(status, text, retry_statuses=frozenset())
    assert error.reason == "network_error"
    assert error.status == status
    assert classify(error) == "network_error"
    assert title in error.message
    assert "<html" not in error.message
    assert len(error.payload) <= guard.BODY_PREVIEW_MAX

    # 没有 HTTP 状态的 HTML 解析也不能凭通用 CF 页面结构判成验证或封禁。
    with pytest.raises(TaskError) as caught:
        parse_json(text)
    assert caught.value.reason not in {"need_verification", "blocked"}
    assert classify(caught.value) not in {"need_verification", "blocked"}


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize(
    "message",
    [
        "Cloudflare could not establish a TCP connection to the origin server. The TCP handshake timed out.",
        "The origin web server returned an invalid or incomplete response to Cloudflare. "
        "This typically indicates the origin is overloaded or misconfigured.",
        "The host is configured as a Cloudflare Tunnel, but Cloudflare is currently unable to reach it.",
    ],
)
def test_cloudflare_origin_message_keeps_network_conclusion(as_json, message) -> None:
    from net.http import _http_error, parse_json
    from templates.builtin.newapi import _outcome_from_error, classify

    # 脱敏日志中的源站报错；也可能被站点包装成 HTTP 200 业务 JSON。
    text = json.dumps({"success": False, "message": message}) if as_json else message
    assert not guard.looks_like_verification(text)
    error = _http_error(522, text, retry_statuses=HttpConfig().retry_statuses)
    assert error.message == message
    assert error.reason == "network_error"
    assert classify(error) == "network_error"
    if as_json:
        payload = parse_json(text)
        for status in (None, 200):
            error = TaskError(payload["message"], status=status, payload=payload)
            assert classify(error) == "network_error"
            assert _outcome_from_error(error).reason == "network_error"
    else:
        with pytest.raises(TaskError) as caught:
            parse_json(text)
        assert caught.value.reason == "network_error"


@pytest.mark.parametrize("status", [522, 523, 524])
def test_newapi_origin_status_precedes_incidental_verification_words(status) -> None:
    from templates.builtin.newapi import classify

    error = TransientError("Origin unavailable", status=status, payload="captcha / token / Cloudflare")
    assert classify(error) == "network_error"


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("retry_origin", [False, True])
@pytest.mark.parametrize(
    ("status", "message"),
    [
        (522, "Cloudflare could not establish a TCP connection to the origin server."),
        (400, 'Post "https://challenges.cloudflare.com/turnstile/v0/siteverify": unexpected EOF'),
    ],
)
def test_origin_error_respects_retry_policy_and_never_refreshes_auth(
    monkeypatch, method, retry_origin, status, message
) -> None:
    from unittest.mock import Mock

    calls: list[str] = []

    def fail(request, timeout=None):
        calls.append(request.get_method())
        raise urllib.error.HTTPError(request.full_url, status, message, {}, io.BytesIO(message.encode()))

    opener = Mock()
    opener.open.side_effect = fail
    monkeypatch.setattr(HttpClient, "_opener", lambda self: opener)
    client = _client(retry_statuses=frozenset({status}) if retry_origin else frozenset())
    client.auth_refresher = Mock()

    with pytest.raises(TaskError) as caught:
        client.request(method, "/x")
    assert caught.value.reason == "network_error"
    assert isinstance(caught.value, TransientError) is retry_origin
    assert calls == [method] * (3 if retry_origin and method == "GET" else 1)
    assert client.config.verify_ssl is True
    client.auth_refresher.assert_not_called()


@pytest.mark.parametrize(
    "message",
    [
        "Turnstile token 为空", "captcha is required", "请输入验证码", "安全验证", "人机验证",
        "Cloudflare verification required", "Cloudflare challenge required", "checking your browser",
        "Just a moment...", "cf_chl_opt", "cf-challenge",
    ],
)
def test_explicit_verification_messages_keep_their_route(message) -> None:
    from net.http import parse_json
    from templates.builtin.newapi import classify

    assert guard.looks_like_verification(message)
    with pytest.raises(TaskError) as caught:
        parse_json(message)
    assert caught.value.reason == "need_verification"
    assert classify(TaskError(message)) == "need_verification"


@pytest.mark.parametrize("status", [403, 503])
def test_cloudflare_challenge_http_response_keeps_verification_route(status) -> None:
    from net.http import _http_error
    from templates.builtin.newapi import classify

    text = "<!doctype html><html><title>Just a moment...</title><body>cf_chl_opt</body></html>"
    error = _http_error(status, text, retry_statuses=HttpConfig().retry_statuses)
    assert error.reason == "need_verification"
    assert classify(error) == "need_verification"


def test_newapi_keeps_tls_network_reason_even_when_message_mentions_login() -> None:
    from net.http import _transport_error
    from templates.builtin.newapi import _outcome_from_error, classify

    error = _transport_error(ssl.SSLEOFError(8, "UNEXPECTED_EOF_WHILE_READING"))
    assert "登录失效" in error.message
    assert classify(error) == "network_error"
    outcome = _outcome_from_error(error)
    assert outcome.reason == "network_error"
    assert outcome.message == error.message
    assert outcome.data["error_code"] == "UNEXPECTED_EOF_WHILE_READING"


@pytest.mark.parametrize("reason", ["", "network_error"])
def test_newapi_preserves_origin_error_metadata_in_final_outcome(reason) -> None:
    from templates.builtin.newapi import _outcome_from_error

    error = TaskError("Origin unavailable", reason=reason, status=522, data={"stage": "http"})
    outcome = _outcome_from_error(error)
    assert outcome.reason == "network_error"
    assert outcome.data == {"stage": "http", "http_status": 522}


@pytest.mark.parametrize("as_json", [False, True])
def test_turnstile_siteverify_eof_is_an_upstream_network_error(as_json) -> None:
    from net.http import _http_error, parse_json
    from templates.builtin.newapi import _outcome_from_error, classify

    message = 'Post "https://challenges.cloudflare.com/turnstile/v0/siteverify": unexpected EOF'
    payload = {"success": False, "message": message}
    text = json.dumps(payload) if as_json else message
    assert not guard.looks_like_verification(text)
    error = _http_error(400, text, retry_statuses=frozenset())
    assert error.reason == "network_error"
    assert not isinstance(error, TransientError), "只修分类，不增加重放提交的机会"
    assert classify(error) == "network_error"
    outcome = _outcome_from_error(TaskError(message, payload=payload))
    assert outcome.reason == "network_error"
    assert outcome.message == message
    if not as_json:
        with pytest.raises(TaskError) as caught:
            parse_json(message)
        assert caught.value.reason == "network_error"


@pytest.mark.parametrize("message", ["Turnstile siteverify: invalid-input-response", "Turnstile timeout-or-duplicate"])
def test_turnstile_siteverify_rejection_is_still_verification(message) -> None:
    from templates.builtin.newapi import classify

    assert classify(TaskError(message)) == "need_verification"


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
