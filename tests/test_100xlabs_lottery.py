"""百倍/林夕每日抽奖：赠送优先、禁止活跃度、逐次确认以及独立任务分派。"""
from __future__ import annotations

import asyncio
import importlib
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import urlsplit

import pytest

from core.chain import is_final
from core.errors import LoginRequired, TaskError
from core.outcome import Verdict, failed, success


@pytest.fixture
def lottery(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts" / "tasks"))
    return importlib.import_module("_100xlabs_lottery")


class FakeHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {"Authorization": "Bearer test-only-token"}

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        assert self.responses, f"禁止未经准备的请求：{method} {path}"
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)


class FakePage:
    def __init__(self, origin, responses):
        self.url = origin + "/lottery"
        self.http = FakeHttp(responses)
        self.scripts = []
        self.evaluate = AsyncMock(side_effect=self._evaluate)

    async def _evaluate(self, script, args):
        self.scripts.append(script)
        assert args["baseUrl"] == "https://lottery.test"
        result = self.http.request(args["method"], args["path"], json_body=args["body"])
        return {"status": 200, "payload": result}


def ctx(responses=(), *, transport="http", args=None, expired=None):
    origin = "https://lottery.test"
    context = SimpleNamespace(
        account=SimpleNamespace(id="fake", task_id="lottery", base_url=origin),
        args=args or {}, http=FakeHttp(responses if transport == "http" else ()),
        log=Mock(), expired=expired or Mock(return_value=False),
    )
    page = FakePage(origin, responses) if transport == "browser" else None
    return context, page


def ok(data):
    return {"code": 0, "data": data}


def state(remaining=3, bonus=2, **extra):
    result = dict(
        enabled=True, window_open=True, can_draw=remaining > 0,
        daily_draw_limit=3, today_draws=3 - remaining, today_remaining=remaining,
        bonus_draws=bonus, costs={"free": {"enabled": True, "amount": "5"}},
        free_balance="100", activity_score=500,
        boost={"enabled": True, "available": True, "activity_cost": 10},
    )
    result.update(extra)
    return ok(result)


def drawn(cost_type="bonus", **extra):
    result = dict(
        id=123, status="miss", cost_type=cost_type, cost_activity=0,
        boost_activity_cost=0, cost_paid="0", cost_free="5" if cost_type == "free" else "0",
    )
    result.update(extra)
    return ok({"draw": result})


def calls(context, page):
    return context.http.calls if page is None else page.http.calls


def posts(context, page):
    return [kw["json_body"] for method, _, kw in calls(context, page) if method == "POST"]


def assert_safe(context, page):
    for method, path, kw in calls(context, page):
        assert urlsplit(path).path == (
            "/api/v1/lottery" if method == "POST" else "/api/v1/lottery/status"
        ), "不能购买次数、攻击结界或调用其他业务端点"
        if page is None:
            assert kw.get("retry_non_idempotent") is False
        if method == "POST":
            body = kw["json_body"]
            assert set(body) == {"cost_type", "idempotency_key", "boost"}
            assert body["cost_type"] in {"bonus", "free"}
            assert body["boost"] is False
            assert isinstance(body["idempotency_key"], str) and body["idempotency_key"]


@pytest.mark.parametrize("transport", ["http", "browser"])
def test_bonus_first_then_free_balance_until_server_confirms_zero(lottery, transport):
    context, page = ctx([
        state(), drawn(id=1), state(2, 1), drawn(id=2), state(1, 0), drawn("free", id=3), state(0, 0),
    ], transport=transport, args={"cost_type": "activity", "boost": True, "allow_paid": True})
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.SUCCESS
    assert [p["cost_type"] for p in posts(context, page)] == ["bonus", "bonus", "free"]
    assert len({p["idempotency_key"] for p in posts(context, page)}) == 3
    assert [method for method, _, _ in calls(context, page)] == ["GET", "POST", "GET", "POST", "GET", "POST", "GET"]
    assert_safe(context, page)


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize("kind", ["bonus", "free"])
def test_live_receipt_without_boost_cost_accepts_explicit_unchanged_activity(lottery, transport, kind):
    receipt = drawn(kind, activity_before=500, activity_after=500)
    del receipt["data"]["draw"]["boost_activity_cost"]
    receipt["data"]["activity_score"] = 500
    context, page = ctx([state(1, 1 if kind == "bonus" else 0), receipt, state(0, 0)], transport=transport)
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["draws"] == 1
    assert outcome.data["activity_spent"] == 0
    assert_safe(context, page)


@pytest.mark.parametrize("change", [
    {"activity_before": 499}, {"activity_after": 499}, {"activity_after": None},
    {"activity_before": True}, {"activity_after": "500"}, {"boost": True},
])
def test_missing_boost_cost_requires_valid_unchanged_activity_proof(lottery, change):
    receipt = drawn(activity_before=500, activity_after=500, **{"boost": False})
    del receipt["data"]["draw"]["boost_activity_cost"]
    receipt["data"]["draw"].update(change)
    receipt["data"]["activity_score"] = 500
    context, page = ctx([state(1, 1), receipt, state(0, 0)])
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED
    assert len(posts(context, page)) == 1
    assert is_final(outcome)


def test_missing_boost_cost_does_not_accept_missing_response_activity(lottery):
    receipt = drawn(activity_before=500, activity_after=500)
    del receipt["data"]["draw"]["boost_activity_cost"]
    context, page = ctx([state(1, 1), receipt, state(0, 0)])
    assert asyncio.run(lottery.run_lottery(context, page)).verdict is Verdict.FAILED
    assert len(posts(context, page)) == 1


def test_missing_boost_cost_accepts_activity_reward_without_activity_spend(lottery):
    receipt = drawn(activity_before=500, activity_after=501)
    del receipt["data"]["draw"]["boost_activity_cost"]
    receipt["data"]["activity_score"] = 501
    context, page = ctx([state(1, 1), receipt, state(0, 0)])
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["draws"] == 1
    assert outcome.data["activity_spent"] == 0
    assert len(posts(context, page)) == 1


@pytest.mark.parametrize("transport", ["http", "browser"])
def test_daily_limit_reached_does_not_consume_extra_bonus(lottery, transport):
    context, page = ctx([state(0, 100)], transport=transport)
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.ALREADY_DONE
    assert not posts(context, page)
    assert_safe(context, page)


@pytest.mark.parametrize("transport", ["http", "browser"])
def test_bonus_works_without_free_payment_channel(lottery, transport):
    context, page = ctx([
        state(1, 1, costs={"activity": {"enabled": True, "amount": 5}}, free_balance=0),
        drawn(), state(0, 0),
    ], transport=transport)
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.SUCCESS
    assert [p["cost_type"] for p in posts(context, page)] == ["bonus"]
    assert_safe(context, page)


@pytest.mark.parametrize("extra", [
    {"costs": {"activity": {"enabled": True, "amount": 1}, "paid": {"enabled": True, "amount": 1}}},
    {"costs": {"free": {"enabled": False, "amount": 0}}},
    {"free_balance": "4.99"},
])
def test_no_fallback_to_activity_or_paid_when_bonus_exhausted(lottery, extra):
    """赠送资源用尽 = 服务端状态给出的正常终点，不算失败（实测林夕/百倍天天如此）。"""
    context, page = ctx([state(1, 0, **extra)])
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.NO_EFFECT
    assert outcome.reason == "not_applicable"
    assert not posts(context, page)


@pytest.mark.parametrize("transport", ["http", "browser"])
def test_drawing_then_free_resources_running_out_is_success(lottery, transport):
    """当天先抽了 1 次、随后赠送额度耗尽：这是今天全部赠送抽奖，不是失败。

    实测百倍：赠送池 301 → 101，单抽 200，于是抽完 1 次就抽不动了。旧逻辑
    因为 attempted=True 仍判 failed，让整轮 CI 变红。
    """
    context, page = ctx([
        state(3, 1), drawn(id=1), state(2, 2, bonus_draws=0, costs={"free": {"enabled": True, "amount": 200}},
                              free_balance=101),
    ], transport=transport)
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["draws"] == 1
    assert outcome.data["completion_signal"] == "free_resources_exhausted"
    assert [p["cost_type"] for p in posts(context, page)] == ["bonus"]
    assert_safe(context, page)


def test_unconfirmed_submission_stays_failed_even_when_resources_run_out(lottery):
    """待确认的提交绝不能被「资源耗尽」洗成成功。"""
    context, page = ctx([
        state(3, 1), drawn(id=1),
        ok({"draw": {"id": 1, "status": "miss", "cost_type": "paid", "cost_paid": "0",
                     "cost_free": "0", "cost_activity": 0, "boost_activity_cost": 0}}),
    ])
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED
    assert len(posts(context, page)) == 1


@pytest.mark.parametrize("extra", [
    {"today_remaining": True}, {"today_remaining": -1}, {"today_remaining": "3"},
    {"today_draws": -1}, {"daily_draw_limit": 0, "today_remaining": -1},
    {"daily_draw_limit": 4}, {"bonus_draws": -1}, {"bonus_draws": True},
    {"today_remaining": None}, {"can_draw": False}, {"enabled": False}, {"window_open": False},
    {"free_balance": "NaN", "bonus_draws": 0},
    {"free_balance": "Infinity", "bonus_draws": 0},
    {"free_balance": -1, "bonus_draws": 0},
    {"costs": {"free": {"enabled": True, "amount": "NaN"}}, "bonus_draws": 0},
    {"costs": {"free": {"enabled": True, "amount": -1}}, "bonus_draws": 0},
])
def test_invalid_or_unavailable_state_never_submits(lottery, extra):
    context, page = ctx([state(**extra)])
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED
    assert not posts(context, page)


@pytest.mark.parametrize("field", ["today_remaining", "daily_draw_limit", "today_draws", "bonus_draws"])
def test_missing_required_state_is_not_mistaken_for_zero(lottery, field):
    raw = state()
    del raw["data"][field]
    context, page = ctx([raw])
    assert asyncio.run(lottery.run_lottery(context, page)).verdict is Verdict.FAILED
    assert not posts(context, page)


@pytest.mark.parametrize("raw", [None, {}, [], {"code": 500, "data": state()["data"]}, {"success": False}])
def test_invalid_envelope_is_not_completion(lottery, raw):
    context, page = ctx([raw])
    assert asyncio.run(lottery.run_lottery(context, page)).verdict is Verdict.FAILED
    assert not posts(context, page)


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize("change", [
    {"cost_type": "activity"}, {"cost_type": "paid"}, {"cost_activity": 1},
    {"boost_activity_cost": 1}, {"cost_paid": "0.01"}, {"cost_activity": None},
    {"boost_activity_cost": "NaN"}, {"status": "unknown"}, {"id": None},
])
def test_bad_draw_receipt_stops_without_second_submission(lottery, transport, change):
    context, page = ctx([state(), drawn(**change), state(2, 1)], transport=transport)
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED
    assert len(posts(context, page)) == 1
    assert is_final(outcome)
    assert_safe(context, page)


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize("error", [
    TaskError("请求断开", reason="network_error"), LoginRequired("认证拒绝"),
    RuntimeError("unexpected"), asyncio.CancelledError(),
])
def test_uncertain_post_does_not_retry_or_fallback(lottery, transport, error):
    context, page = ctx([state(), error, state(2, 1)], transport=transport)
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED
    assert is_final(outcome)
    assert len(posts(context, page)) == 1
    assert_safe(context, page)


@pytest.mark.parametrize("after", [state(), state(3, 1), state(1, 1), state(2, 1, today_draws=2)])
def test_stale_or_jumping_confirmation_never_continues(lottery, after):
    context, page = ctx([state(), drawn(), deepcopy(after)])
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED
    assert is_final(outcome)
    assert len(posts(context, page)) == 1


def test_expired_task_never_draws(lottery):
    context, page = ctx([state()], expired=Mock(return_value=True))
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED
    assert not posts(context, page)


def test_browser_cannot_send_credentials_to_another_origin(lottery):
    context, page = ctx([state()], transport="browser")
    page.url = "https://elsewhere.test/lottery"
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED
    page.evaluate.assert_not_awaited()


@pytest.mark.parametrize("entry", ["run", "run_http", "run_browser"])
def test_lottery_task_dispatch_does_not_invoke_checkin_or_tree(lottery, monkeypatch, entry):
    template = importlib.import_module("scripts.tasks.100xlabs")
    expected = success("抽奖完成")
    handler = AsyncMock(return_value=expected)
    monkeypatch.setattr(lottery, entry, handler)
    forbidden = AsyncMock(side_effect=AssertionError("抽奖不能触发签到或砍树"))
    monkeypatch.setattr(template.tree, entry, forbidden)
    for name in ("http_first", "http_attempt", "run_flow"):
        monkeypatch.setattr(template.flow, name, forbidden)
    context, _ = ctx()
    assert asyncio.run(getattr(template, entry)(context)) is expected
    handler.assert_awaited_once_with(context, template.SPEC)
    forbidden.assert_not_awaited()


@pytest.mark.parametrize("entry", ["run", "run_http", "run_browser"])
def test_daily_and_tree_never_dispatch_to_lottery(lottery, monkeypatch, entry):
    template = importlib.import_module("scripts.tasks.100xlabs")
    forbidden = AsyncMock(side_effect=AssertionError("其他任务不能顺带抽奖"))
    monkeypatch.setattr(lottery, entry, forbidden)
    expected = success("原任务完成")
    monkeypatch.setattr(template.tree, entry, AsyncMock(return_value=expected))
    context, _ = ctx()
    context.account.task_id = "chop_tree"
    assert asyncio.run(getattr(template, entry)(context)) is expected
    if entry != "run_browser":
        context.account.task_id = "daily"
        name = "http_first" if entry == "run" else "http_attempt"
        monkeypatch.setattr(template.flow, name, AsyncMock(return_value=expected))
        assert asyncio.run(getattr(template, entry)(context)) is expected
    forbidden.assert_not_awaited()


def test_http_initial_login_failure_can_fallback_but_post_failure_cannot(lottery):
    template = importlib.import_module("scripts.tasks.100xlabs")
    context, _ = ctx([LoginRequired("initial")])
    assert not is_final(asyncio.run(lottery.run_http(context, template.SPEC)))
    context, _ = ctx([state(), TaskError("断开", reason="network_error"), state(2, 1)])
    assert is_final(asyncio.run(lottery.run_http(context, template.SPEC)))


def test_legacy_run_stops_after_final_failure(lottery, monkeypatch):
    from sdk import chain_final

    template = importlib.import_module("scripts.tasks.100xlabs")
    outcome = chain_final(failed("不确定的抽奖结果", reason="unconfirmed"))
    monkeypatch.setattr(lottery, "run_http", AsyncMock(return_value=outcome))
    browser = AsyncMock(side_effect=AssertionError("POST后不能换浏览器重抽"))
    monkeypatch.setattr(lottery, "run_browser", browser)
    context, _ = ctx()
    context.browser_service = object()
    assert asyncio.run(lottery.run(context, template.SPEC)).verdict is Verdict.FAILED
    browser.assert_not_awaited()


@pytest.mark.parametrize("field", ["cost_activity", "boost_activity_cost", "cost_paid", "cost_free", "cost_type"])
def test_missing_cost_evidence_stops_after_one_draw(lottery, field):
    receipt = drawn()
    del receipt["data"]["draw"][field]
    context, page = ctx([state(), receipt, state(2, 1)])
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED and is_final(outcome)
    assert len(posts(context, page)) == 1


def test_free_draw_cost_must_match_preflight_amount(lottery):
    context, page = ctx([state(1, 0), drawn("free", cost_free="6"), state(0, 0)])
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED and is_final(outcome)
    assert len(posts(context, page)) == 1


def test_zero_cost_free_draw_does_not_need_balance(lottery):
    context, page = ctx([
        state(1, 0, free_balance="0", costs={"free": {"enabled": True, "amount": "0"}}),
        drawn("free", cost_free="0"), state(0, 0),
    ])
    assert asyncio.run(lottery.run_lottery(context, page)).verdict is Verdict.SUCCESS
    assert_safe(context, page)


@pytest.mark.parametrize("authenticated", [True, False])
def test_browser_entry_only_authenticates_and_opens_lottery(lottery, monkeypatch, authenticated):
    template = importlib.import_module("scripts.tasks.100xlabs")
    context, page = ctx([state(0, 0)], transport="browser")
    lease = SimpleNamespace(
        page=page, new_page=AsyncMock(return_value=page), mark_authenticated=Mock(),
        context=SimpleNamespace(clear_cookies=AsyncMock(), add_init_script=AsyncMock()),
    )
    manager = AsyncMock()
    manager.__aenter__.return_value = lease
    context.browser = SimpleNamespace(lease=Mock(return_value=manager))
    helpers = SimpleNamespace(resolve_url=lambda path: context.account.base_url + path)
    monkeypatch.setattr(lottery, "PageHelpers", Mock(return_value=helpers))
    navigation = AsyncMock()
    monkeypatch.setattr(lottery.flow, "navigate_and_settle", navigation)
    monkeypatch.setattr(lottery.flow, "add_init_script", AsyncMock())
    monkeypatch.setattr(lottery.flow, "_authenticated_with_probe", AsyncMock(return_value=authenticated))
    login = AsyncMock(return_value=None)
    monkeypatch.setattr(lottery.flow, "login_with_password", login)
    monkeypatch.setattr(lottery.flow, "confirm_login_session", AsyncMock(return_value=None))
    monkeypatch.setattr(lottery.flow, "_record_new_tokens", AsyncMock())
    for name in ("run_flow", "http_first", "api_checkin"):
        monkeypatch.setattr(lottery.flow, name, AsyncMock(side_effect=AssertionError("禁止签到")))
    outcome = asyncio.run(lottery.run_browser(context, template.SPEC))
    assert outcome.verdict is Verdict.ALREADY_DONE
    assert all(c.args[2] == "/lottery" for c in navigation.await_args_list)
    assert navigation.await_count == (1 if authenticated else 2)
    assert login.await_count == (0 if authenticated else 1)
    lease.mark_authenticated.assert_called_once()
    lease.context.clear_cookies.assert_not_awaited()
    assert not posts(context, page)
    assert_safe(context, page)


@pytest.mark.parametrize("authentication_retry", [False, True])
def test_real_http_client_never_changes_cost_or_idempotency_on_retry(lottery, monkeypatch, authentication_retry):
    import json

    from net.http import HttpClient
    from core.errors import TransientError

    context, _ = ctx()
    error = LoginRequired("expired") if authentication_retry else TransientError("lost response")
    responses = [state(1, 1), error]
    responses += [drawn(), state(0, 0)] if authentication_retry else [state(0, 0)]
    wire = []

    def once(self, url, **kwargs):
        wire.append((kwargs["method"], json.loads(kwargs["body"]) if kwargs["body"] else None))
        response = responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return json.dumps(response)

    monkeypatch.setattr(HttpClient, "_once", once)
    client = HttpClient(context.account.base_url)
    client.auth_refresher = Mock(return_value=HttpClient(context.account.base_url))
    context.http = client
    outcome = asyncio.run(lottery.run_lottery(context))
    submissions = [body for method, body in wire if method == "POST"]
    assert len(submissions) == (2 if authentication_retry else 1)
    assert all(body == submissions[0] for body in submissions)
    assert submissions[0]["cost_type"] == "bonus" and submissions[0]["boost"] is False
    if authentication_retry:
        assert outcome.verdict is Verdict.SUCCESS
        client.auth_refresher.assert_called_once()
    else:
        assert outcome.verdict is Verdict.FAILED and is_final(outcome)
        client.auth_refresher.assert_not_called()


def test_safety_cap_cannot_be_overridden_by_task_arguments(lottery, monkeypatch):
    monkeypatch.setattr(lottery, "MAX_DRAWS", 1)
    context, page = ctx([state(), drawn(), state(2, 1)], args={"max_draws": 99999})
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED and is_final(outcome)
    assert len(posts(context, page)) == 1


def test_activity_decrease_in_post_readback_stops_even_with_zero_cost_receipt(lottery):
    context, page = ctx([state(), drawn(), state(2, 1, activity_score=499)])
    outcome = asyncio.run(lottery.run_lottery(context, page))
    assert outcome.verdict is Verdict.FAILED and is_final(outcome)
    assert "activity_spent" not in outcome.data
    assert len(posts(context, page)) == 1


@pytest.mark.parametrize("costs", [
    {}, {"free": {"enabled": False}},
    {"paid": None, "activity": {"enabled": False}},
])
def test_bonus_does_not_depend_on_unused_payment_channels_or_boost_config(lottery, costs):
    before = state(1, 1, costs=costs)
    del before["data"]["boost"]
    context, page = ctx([before, drawn(), state(0, 0)])
    assert asyncio.run(lottery.run_lottery(context, page)).verdict is Verdict.SUCCESS
    assert_safe(context, page)
