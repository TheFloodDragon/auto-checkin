from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from core.errors import ConfigError, TaskError, TransientError, VerificationRequired
from core.masking import mask_secrets, sanitize_data
from net.http import HttpClient, HttpConfig
from solvers.registry import SolveResult
from templates.builtin import newapi, newapi_tencent as tencent, newapi_verify as verify

TICKET = "ticket-PRIVATE-1234567890"
RANDSTR = "random-PRIVATE-1234567890"
TOKEN = "token-PRIVATE+/=&0123456789"
OPTIONS = {"captcha_type": "tencent", "captcha_checkin_enabled": True,
           "tencent_captcha_app_id": "192203696"}


def context(*, result=None, responses=None):
    result = result if result is not None else SolveResult.solved("", data={"ticket": TICKET, "randstr": RANDSTR})
    responses = responses if responses is not None else [
        {"code": 0, "token": TOKEN}, {"success": True, "data": {"quota_awarded": 1000}},
    ]
    http = Mock(base_url="https://site.invalid")
    http.request.side_effect = responses
    return SimpleNamespace(http=http, solve=AsyncMock(return_value=result), log=Mock(),
                           account=SimpleNamespace(base_url="https://site.invalid"),
                           remaining_seconds=lambda: 120.0)


def run(ctx, options=None):
    return asyncio.run(verify.run_mechanism(ctx, "tencent", options if options is not None else OPTIONS))


def test_tencent_detection_does_not_probe_character_dialects():
    assert verify.detect_modes(OPTIONS, {}) == ["tencent"]
    assert verify.detect_modes({"captcha_type": "tencent"}, {"captcha_enabled": True}) == ["tencent"]
    assert verify.detect_modes({"captcha_type": "tencent"}, {}) == []
    options = {**OPTIONS, "turnstile_check": True, "turnstile_site_key": "sitekey"}
    assert verify.detect_modes(options, {}) == ["tencent"]


def test_tencent_success_exchanges_ticket_then_submits_once():
    ctx = context()
    result = run(ctx)
    assert result == {"quota_awarded": 1000, "verification_mode": "tencent"}
    ctx.solve.assert_awaited_once_with("tencent", app_id="192203696", origin="https://site.invalid", budget=90.0)
    assert ctx.http.request.call_count == 2
    exchange, submit = ctx.http.request.call_args_list
    assert exchange.args == ("POST", tencent.EXCHANGE_PATH)
    assert b'name="ticket"' in exchange.kwargs["data"]
    assert b'name="randstr"' in exchange.kwargs["data"]
    assert TICKET.encode() in exchange.kwargs["data"] and RANDSTR.encode() in exchange.kwargs["data"]
    assert exchange.kwargs["headers"]["Content-Type"].startswith("multipart/form-data; boundary=")
    assert submit.args == ("POST", "/api/user/checkin?captcha_token=token-PRIVATE%2B%2F%3D%260123456789")
    assert all(call.kwargs["retry_non_idempotent"] is False for call in (exchange, submit))
    assert all(0 < call.kwargs["timeout"] <= 15 for call in (exchange, submit))
    assert not any(secret in str(ctx.log.call_args_list) + str(result) for secret in (TICKET, RANDSTR, TOKEN))


@pytest.mark.parametrize("app_id", [None, "", "abc", True, False, "12\n", {}, "1" * 33])
def test_missing_or_invalid_app_id_does_not_open_browser(app_id):
    ctx = context()
    with pytest.raises(ConfigError):
        run(ctx, {**OPTIONS, "tencent_captcha_app_id": app_id})
    ctx.solve.assert_not_awaited()
    ctx.http.request.assert_not_called()


@pytest.mark.parametrize("reason", ["need_human", "pending", "cancelled", "timeout", "sdk_error", "unavailable"])
def test_non_successful_sdk_never_exchanges_or_submits(reason):
    ctx = context(result=SolveResult.failure(reason, "private " + TICKET, data={"ticket": TICKET, "randstr": RANDSTR}))
    with pytest.raises(VerificationRequired) as caught:
        run(ctx)
    assert caught.value.reason == "need_verification"
    assert not any(secret in str(caught.value) + str(caught.value.data) for secret in (TICKET, RANDSTR))
    ctx.http.request.assert_not_called()


@pytest.mark.parametrize("reason", ["network_error", "transport_error"])
def test_sdk_network_failure_stays_network_failure(reason):
    ctx = context(result=SolveResult.failure(reason))
    with pytest.raises(TransientError) as caught:
        run(ctx)
    assert caught.value.reason == "network_error"
    ctx.http.request.assert_not_called()


@pytest.mark.parametrize("fields", [
    {}, {"ticket": TICKET}, {"ticket": "", "randstr": RANDSTR},
    {"ticket": "trerror_bad", "randstr": RANDSTR},
    {"ticket": 12, "randstr": RANDSTR}, {"ticket": TICKET, "randstr": "a\r\nb"},
    {"ticket": "x" * 8193, "randstr": RANDSTR},
])
def test_incomplete_or_unsafe_sdk_pair_never_posts(fields):
    ctx = context(result=SolveResult.solved("", data=fields))
    with pytest.raises(VerificationRequired):
        run(ctx)
    ctx.http.request.assert_not_called()


@pytest.mark.parametrize("payload", [
    None, "html", {}, {"code": 1, "token": TOKEN}, {"code": False, "token": TOKEN},
    {"code": 0, "success": False, "token": TOKEN}, {"success": True, "token": TOKEN},
    {"code": 0}, {"code": 0, "token": 12}, {"code": 0, "token": "a\nb"},
])
def test_exchange_rejection_does_not_fall_back_or_submit(payload):
    ctx = context(responses=[payload])
    with pytest.raises(VerificationRequired) as caught:
        run(ctx)
    assert caught.value.data["stage"] == "exchange"
    assert not verify.not_applicable(caught.value)
    assert ctx.http.request.call_count == 1


def test_http_error_never_replays_ticket_and_redacts_reflected_pair():
    ctx = context(responses=[TaskError("ticket=" + TICKET + " randstr=" + RANDSTR, status=404)])
    with pytest.raises(TaskError) as caught:
        run(ctx)
    assert not verify.not_applicable(caught.value)
    assert caught.value.payload is None
    assert not any(secret in str(caught.value) + str(caught.value.data) for secret in (TICKET, RANDSTR))
    assert ctx.http.request.call_count == 1


def test_submit_business_failure_cannot_be_reported_as_success():
    ctx = context(responses=[{"code": 0, "token": TOKEN}, {"success": False, "message": "请先完成人机验证"}])
    with pytest.raises(TaskError) as caught:
        run(ctx)
    assert caught.value.data["stage"] == "submit"
    assert not verify.not_applicable(caught.value)
    assert ctx.http.request.call_count == 2


def test_reflected_secrets_never_escape_success_result():
    ctx = context(responses=[{"code": 0, "token": TOKEN},
                             {"success": True, "data": {"quota_awarded": 1, "ticket": TICKET,
                                                        "note": TOKEN + " " + RANDSTR}}])
    result = run(ctx)
    assert result["quota_awarded"] == 1
    assert not any(secret in str(result) for secret in (TICKET, RANDSTR, TOKEN))


def test_real_http_client_preserves_auth_proxy_and_disables_hidden_replays(monkeypatch):
    from http.cookiejar import CookieJar

    calls = []
    logs = []
    renewal = Mock()
    http = HttpClient("https://site.invalid", config=HttpConfig(proxy="http://proxy.invalid:7897", max_attempts=4),
                      headers={"Authorization": "Bearer auth-secret", "New-Api-User": "123"},
                      cookie_jar=CookieJar(), log=logs.append, auth_refresher=renewal)

    def request(client, method, path, **kwargs):
        calls.append((client, method, path, kwargs))
        return {"code": 0, "token": TOKEN} if len(calls) == 1 else {"success": True, "data": {"quota_awarded": 1}}

    monkeypatch.setattr(HttpClient, "request", request)
    ctx = context()
    ctx.http = http
    run(ctx)
    for clone, _method, _path, kwargs in calls:
        assert clone is not http and clone.cookie_jar is http.cookie_jar
        assert clone.config.proxy == http.config.proxy and clone.headers == http.headers
        assert clone.config.max_attempts == 1 and clone.config.log_body is False
        assert clone.auth_refresher is None and clone.renew_ahead is False and clone.log is None
        assert kwargs["retry_non_idempotent"] is False
    assert http.config.max_attempts == 4 and http.auth_refresher is renewal
    assert not logs


def test_real_http_exchange_has_no_secret_output_when_log_is_none(monkeypatch, capsys):
    import json

    def once(client, url, **kwargs):
        payload = {"code": 0, "token": TOKEN} if url.endswith(tencent.EXCHANGE_PATH) else {
            "success": True, "data": {"quota_awarded": 1, "ticket": TICKET, "note": RANDSTR},
        }
        return json.dumps(payload)

    monkeypatch.setattr(HttpClient, "_once", once)
    ctx = context()
    ctx.http = HttpClient("https://site.invalid", config=HttpConfig(log_body=True), log=None)
    result = run(ctx)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert not any(secret in str(result) for secret in (TICKET, RANDSTR, TOKEN))
    assert ctx.http.config.log_body is True


def test_tencent_and_turnstile_require_both_before_single_checkin():
    ctx = context()
    ctx.solve.side_effect = [SolveResult.solved("", data={"ticket": TICKET, "randstr": RANDSTR}),
                             SolveResult.solved("turnstile-private")]
    run(ctx, {**OPTIONS, "turnstile_check": True, "turnstile_site_key": "sitekey"})
    assert ctx.solve.await_count == 2
    assert "&turnstile=turnstile-private" in ctx.http.request.call_args.args[1]
    assert ctx.http.request.call_count == 2


def test_missing_second_verification_never_submits_checkin():
    ctx = context(responses=[{"code": 0, "token": TOKEN}])
    ctx.solve.side_effect = [SolveResult.solved("", data={"ticket": TICKET, "randstr": RANDSTR}),
                             SolveResult.failure("pending")]
    with pytest.raises(VerificationRequired):
        run(ctx, {**OPTIONS, "turnstile_check": True, "turnstile_site_key": "sitekey"})
    assert ctx.http.request.call_count == 1


def test_task_budget_exhausted_before_exchange_never_posts():
    ctx = context()
    ctx.remaining_seconds = lambda: 0
    with pytest.raises(VerificationRequired):
        run(ctx)
    ctx.solve.assert_not_awaited()
    ctx.http.request.assert_not_called()


def test_cancellation_propagates_without_posting():
    ctx = context()
    ctx.solve.side_effect = asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        run(ctx)
    ctx.http.request.assert_not_called()


@pytest.mark.parametrize("preference", ["auto", "click_shape", "bitmap_code", "turnstile", "unknown"])
def test_stale_preference_cannot_bypass_public_tencent_type(monkeypatch, preference):
    ctx = context()
    ctx.flow = SimpleNamespace(enabled=lambda _stage: True, get=lambda _stage: SimpleNamespace(primary=preference))
    monkeypatch.setattr(newapi, "_status_options", lambda _ctx: OPTIONS)
    mechanism = AsyncMock(side_effect=VerificationRequired("腾讯验证码尚未完成"))
    monkeypatch.setattr(verify, "run_mechanism", mechanism)
    result = asyncio.run(newapi._verified_checkin(ctx, {}))
    assert not result.ok and result.reason == "need_verification"
    assert mechanism.await_args.args[1] == "tencent" and mechanism.await_count == 1
    ctx.http.request.assert_not_called()


def test_tencent_verification_off_does_not_submit_naked_request(monkeypatch):
    ctx = context()
    ctx.flow = SimpleNamespace(enabled=lambda _stage: False)
    monkeypatch.setattr(newapi, "_status_options", lambda _ctx: OPTIONS)
    result = asyncio.run(newapi._verified_checkin(ctx, {}))
    assert not result.ok and result.reason == "need_verification"
    ctx.solve.assert_not_awaited()
    ctx.http.request.assert_not_called()


def test_tencent_none_result_is_failure_not_default_submit(monkeypatch):
    ctx = context()
    ctx.flow = SimpleNamespace(enabled=lambda _stage: True, get=lambda _stage: SimpleNamespace(primary="auto"))
    monkeypatch.setattr(newapi, "_status_options", lambda _ctx: OPTIONS)
    monkeypatch.setattr(verify, "run_mechanism", AsyncMock(return_value=None))
    result = asyncio.run(newapi._verified_checkin(ctx, {}))
    assert not result.ok and result.reason == "need_verification"


def test_go_captcha_business_error_is_not_mechanism_absence():
    error = VerificationRequired("click-shape 挑战接口异常：验证码已过期或不存在")
    assert not verify.not_applicable(error)
    assert verify.not_applicable(TaskError("Invalid URL", status=404))


def test_tencent_pair_is_masked_in_structured_and_text_outputs():
    assert sanitize_data({"ticket": TICKET, "randstr": RANDSTR}) == {"ticket": "<redacted>", "randstr": "<redacted>"}
    text = mask_secrets(f'{{"ticket":"{TICKET}","randstr":"{RANDSTR}"}}')
    assert TICKET not in text and RANDSTR not in text


def test_solver_registration_declares_browser_without_eager_sdk_import():
    from solvers import SOLVERS
    assert SOLVERS.get("tencent").requires == frozenset({"browser"})
    assert SOLVERS.get("tencent").default_budget == 90


def test_explicit_tencent_config_requires_browser_in_ci(monkeypatch, capsys):
    from apps import cli
    from config.schema import parse_document
    from runtime import capabilities

    document = parse_document({"version": 3, "accounts": [{"id": "site", "base_url": "https://site.invalid",
        "template": "newapi", "login": {"method": "access_token"}, "flow": {"verification": "tencent"},
        "tasks": [{"id": "daily", "method": "http_api"}]}]})
    monkeypatch.setattr(capabilities, "required_by", lambda _manifest: frozenset())
    cli._requires(document, "browser", oauth_renew_hours=0)
    assert capsys.readouterr().out.strip() == "true"
