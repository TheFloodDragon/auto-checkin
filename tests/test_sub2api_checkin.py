"""Sub2API 严格签到协议回归：全部使用合成响应，绝不请求真实站点。"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from core.errors import LoginRequired, TaskError
from core.outcome import Verdict
from scripts.tasks import _sub2api_flow as flow
from sdk import PageHelpers
from solvers.registry import SolveResult


ORIGIN = "https://example.test"
SPEC = flow.SiteSpec(
    site_label="测试站点",
    checkin_path="/api/v1/check-in",
    status_path="/api/v1/check-in/status",
    login_reset_sentinel="test_reset",
    screenshot_prefix="test",
    checkin_texts=("签到",),
    already_texts=("已签到",),
    success_texts=("签到成功",),
    response_match=("/check-in",),
    strict_checkin=True,
)


def state(checked=False, required=False, **fields):
    return {"code": 0, "data": {
        "checked_in_today": checked,
        "turnstile_required": required,
        "turnstile_site_key": "public-site-key",
        "enabled": True,
        "balance": 0,
        **fields,
    }}


def normalized_state(checked=False, required=False, **fields):
    return flow._strict_checkin_response(state(checked, required, **fields), state=True)


def http_ctx(*, before=None, after=None, response=None):
    return SimpleNamespace(
        http=SimpleNamespace(
            headers={"Authorization": "Bearer synthetic-access"},
            get=Mock(side_effect=[before or state(), after or state(True)]),
            request=Mock(return_value=response),
        ),
        log=Mock(),
    )


@pytest.mark.parametrize("required", [True, "true", 1])
def test_http_required_turnstile_never_posts(required):
    ctx = http_ctx(before=state(required=required))
    assert asyncio.run(flow.http_first(ctx, SPEC)) is None
    ctx.http.request.assert_not_called()
    ctx.http.get.assert_called_once_with(SPEC.status_path)


@pytest.mark.parametrize("checked", [True, "true", 1])
def test_http_already_precedes_turnstile_and_preserves_zero_balance(checked):
    ctx = http_ctx(before=state(checked, True, balance=0, free_balance=15))
    result = asyncio.run(flow.http_first(ctx, SPEC))
    assert result.verdict is Verdict.ALREADY_DONE
    assert result.data["balance"] == 0
    assert result.display.text == "$0.0000"
    ctx.http.request.assert_not_called()


@pytest.mark.parametrize("false", [False, "false", "0", 0])
def test_http_false_flags_submit_expected_body_and_do_not_misclassify_new_success(false):
    ctx = http_ctx(
        before=state(false, false),
        response={"code": 0, "data": {
            "checked_in_today": True, "already_checked_in": false, "reward_amount": 0, "balance": 0,
        }},
    )
    result = asyncio.run(flow.http_first(ctx, SPEC))
    assert result.verdict is Verdict.SUCCESS
    assert result.data["balance"] == 0
    assert result.data["reward"] == 0
    assert result.display.text == "$0.0000"
    ctx.http.request.assert_called_once_with(
        "POST", SPEC.checkin_path, json_body={"turnstile_token": ""}, retry_non_idempotent=False,
    )
    assert ctx.http.get.call_count == 2


@pytest.mark.parametrize("body,reason", [
    (None, "unconfirmed"),
    ("", "unconfirmed"),
    ("<html>synthetic-secret</html>", "unconfirmed"),
    ([], "unconfirmed"),
    ({}, "unconfirmed"),
    ({"data": []}, "unconfirmed"),
    ({"code": 0, "data": {}}, "unconfirmed"),
    ({"code": 0, "data": None}, "unconfirmed"),
    ({"code": 9, "data": {"reward_amount": 5}}, "checkin_failed"),
    ({"code": "FAILED", "data": {"checked_in_today": True}}, "checkin_failed"),
    ({"success": False, "data": {"already_checked_in": True}}, "checkin_failed"),
    ({"success": "false", "data": {"reward_amount": 5}}, "checkin_failed"),
    ({"code": 0, "data": {"success": False, "reward_amount": 5}}, "checkin_failed"),
    ({"code": True, "reward_amount": 5}, "checkin_failed"),
    ({"error": "synthetic-secret", "reward_amount": 5}, "checkin_failed"),
    ({"code": "TOKEN_EXPIRED", "data": None}, "need_login"),
    ({"code": "TURNSTILE_FAILED", "data": None}, "need_verification"),
])
def test_http_rejects_empty_and_failed_business_responses(body, reason):
    ctx = http_ctx(response=body)
    result = asyncio.run(flow.http_first(ctx, SPEC))
    assert result.verdict is Verdict.FAILED
    assert result.reason == reason
    assert "synthetic-secret" not in str(result.to_payload())
    assert ctx.http.get.call_count == 1


@pytest.mark.parametrize("body", [
    {"code": 1, "data": {"checked_in_today": True}},
    {"success": "false", "data": {"checked_in_today": True}},
    {"code": 0, "data": {"checked_in_today": "unknown"}},
    {"code": 0, "data": {"checked_in_today": False}},
])
def test_http_bad_status_cannot_authorize_an_empty_post(body):
    ctx = http_ctx(before=body)
    result = asyncio.run(flow.http_first(ctx, SPEC))
    assert result.verdict is Verdict.FAILED
    ctx.http.request.assert_not_called()


def test_http_disabled_checkin_does_not_post():
    ctx = http_ctx(before=state(enabled="false"))
    result = asyncio.run(flow.http_first(ctx, SPEC))
    assert result.verdict is Verdict.NO_EFFECT
    assert result.reason == "not_open"
    ctx.http.request.assert_not_called()


@pytest.mark.parametrize("after", [state(), {"success": False, "data": {"checked_in_today": True}}])
def test_http_success_requires_server_confirmation(after):
    ctx = http_ctx(after=after, response={"code": 0, "data": {"reward_amount": 5}})
    result = asyncio.run(flow.http_first(ctx, SPEC))
    assert result.verdict is Verdict.FAILED
    assert result.reason in {"unconfirmed", "checkin_failed"}


@pytest.mark.parametrize("already,verdict", [(True, Verdict.ALREADY_DONE), ("true", Verdict.ALREADY_DONE),
                                             (False, Verdict.SUCCESS), ("false", Verdict.SUCCESS)])
def test_http_explicit_already_flag(already, verdict):
    ctx = http_ctx(response={"code": 0, "data": {
        "already_checked_in": already, "reward_amount": 3, "free_balance": 0,
    }})
    result = asyncio.run(flow.http_first(ctx, SPEC))
    assert result.verdict is verdict
    assert result.data["balance"] == 0


@pytest.mark.parametrize("checked,verdict", [(False, Verdict.FAILED), (True, Verdict.ALREADY_DONE)])
def test_http_409_and_already_message_require_read_only_confirmation(checked, verdict):
    ctx = http_ctx(after=state(checked))
    ctx.http.request.side_effect = TaskError("already synthetic-secret", status=409, payload={"message": "already"})
    result = asyncio.run(flow.http_first(ctx, SPEC))
    assert result.verdict is verdict
    assert "synthetic-secret" not in str(result.to_payload())
    assert all("synthetic-secret" not in str(call) for call in ctx.log.call_args_list)


def test_http_expired_session_is_left_to_existing_http_auth_refresher():
    ctx = http_ctx()
    ctx.http.get.side_effect = LoginRequired("synthetic-secret", status=401)
    assert asyncio.run(flow.http_first(ctx, SPEC)) is None
    ctx.http.request.assert_not_called()
    assert "synthetic-secret" not in str(ctx.log.call_args_list)


def test_http_no_auth_does_not_read_or_write():
    ctx = http_ctx()
    ctx.http.headers.clear()
    assert asyncio.run(flow.http_first(ctx, SPEC)) is None
    ctx.http.get.assert_not_called()
    ctx.http.request.assert_not_called()


def test_strict_mode_is_opt_in_and_legacy_http_contract_is_unchanged():
    legacy = replace(SPEC, strict_checkin=False)
    assert flow.SiteSpec("legacy", "/checkin", "reset", "shot").strict_checkin is False
    ctx = http_ctx(before=state(required=True), response=None)
    result = asyncio.run(flow.http_first(ctx, legacy))
    assert result.verdict is Verdict.SUCCESS
    ctx.http.request.assert_called_once_with("POST", SPEC.checkin_path, json_body={}, retry_non_idempotent=True)


@pytest.fixture(scope="module")
def node_executable():
    node = shutil.which("node")
    if not node:
        # Playwright 自带 Node，可离线执行生成的 JS，不启动或下载浏览器。
        try:
            from playwright._impl._driver import compute_driver_executable
            node = compute_driver_executable()[0]
        except ImportError:
            pytest.skip("缺少 Node/Playwright driver，无法执行页内 JS")
    if not Path(node).exists():
        pytest.skip("本机无 JavaScript 运行时")
    return str(node)


NODE_HARNESS = r"""
const fs = require('fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const storage = {...input.storage};
const session = {...input.session};
const storageApi = data => ({
  getItem: key => data[key] ?? null,
  setItem: (key, value) => {data[key] = String(value);},
  removeItem: key => {delete data[key];},
});
global.localStorage = storageApi(storage);
global.sessionStorage = storageApi(session);
const calls = [];
// 覆盖全局 fetch；此测试进程没有任何真实网络调用路径。
global.fetch = async (url, options = {}) => {
  const reply = input.replies[calls.length];
  if (!reply) throw new Error('unexpected fetch');
  calls.push({url, ...options});
  return {
    status: reply.status ?? 200,
    ok: (reply.status ?? 200) >= 200 && (reply.status ?? 200) < 300,
    text: async () => reply.text === undefined ? JSON.stringify(reply.raw) : reply.text,
  };
};
(async () => {
  const result = await eval('(' + input.script + ')')(input.argument);
  process.stdout.write(JSON.stringify({result, calls, storage, session}));
})().catch(error => {console.error(error); process.exitCode = 1;});
"""


class ScriptPage:
    def __init__(self, node, replies, storage=None):
        self.node = node
        self.replies = list(replies)
        self.storage = {"auth_token": "synthetic-access", **(storage or {})}
        self.session = {}
        self.calls = []

    async def evaluate(self, script, argument):
        execution = subprocess.run(
            [self.node, "-e", NODE_HARNESS],
            input=json.dumps({"script": script, "argument": argument,
                              "replies": self.replies, "storage": self.storage, "session": self.session}),
            text=True, encoding="utf-8", capture_output=True, check=True, timeout=15,
        )
        output = json.loads(execution.stdout)
        del self.replies[:len(output["calls"])]
        self.calls.extend(output["calls"])
        self.storage = output["storage"]
        self.session = output["session"]
        return output["result"]

    async def run_init(self, script):
        return await self.evaluate("() => {\n" + script + "\n return null;\n}", None)


@pytest.mark.parametrize("strict", [True, False])
def test_expired_preflight_keeps_refresh_only_in_strict_mode(node_executable, strict):
    stash_key = flow.session_stash_key(SPEC.login_reset_sentinel)
    page = ScriptPage(node_executable, [], storage={
        "auth_token": "synthetic-expired", "refresh_token": "synthetic-refresh",
        "auth_user": '{"id":1}', "token_expires_at": "1",
        stash_key: '{"auth_token":"synthetic-expired","token_expires_at":"1"}',
        "native_device": "synthetic-device",
    })
    page.session = {"auth_expired": "true", "other": "keep"}
    script = (flow.preflight_init_script(stash_key, preserve_refresh=True)
              if strict else flow.preflight_init_script(stash_key))
    asyncio.run(page.run_init(script))
    assert all(key not in page.storage for key in ("auth_token", "auth_user", "token_expires_at", stash_key))
    assert page.storage.get("refresh_token") == ("synthetic-refresh" if strict else None)
    assert page.storage["native_device"] == "synthetic-device"
    assert page.storage[flow.NOTICE_KEY] == "accepted"
    assert page.session == {"other": "keep"}
    assert page.calls == []


@pytest.mark.parametrize("strict", [True, False])
@pytest.mark.parametrize("expires", [None, "0", "invalid", "4102444800000"])
def test_preflight_does_not_clear_nonexpired_or_unknown_session(node_executable, strict, expires):
    stash_key = flow.session_stash_key(SPEC.login_reset_sentinel)
    page = ScriptPage(node_executable, [], storage={
        "refresh_token": "synthetic-refresh", "auth_user": '{"id":1}', stash_key: "synthetic-stash",
    })
    if expires is not None:
        page.storage["token_expires_at"] = expires
    before = dict(page.storage)
    asyncio.run(page.run_init(flow.preflight_init_script(stash_key, preserve_refresh=strict)))
    assert page.storage == {**before, flow.NOTICE_KEY: "accepted"}
    assert page.calls == []


@pytest.mark.parametrize("refresh_ok", [True, False])
def test_real_preflight_then_auth_refresh_never_sends_expired_token(node_executable, refresh_ok):
    stash_key = flow.session_stash_key(SPEC.login_reset_sentinel)
    replies = ([{"raw": {"code": 0, "data": {"access_token": "synthetic-renewed", "expires_in": 3600}}},
                {"raw": {"code": 0, "data": {"id": 1}}}] if refresh_ok else
               [{"status": 401, "raw": {"code": "REFRESH_TOKEN_INVALID"}}])
    page = ScriptPage(node_executable, replies, storage={
        "auth_token": "synthetic-expired", "refresh_token": "synthetic-refresh",
        "auth_user": '{"id":1}', "token_expires_at": "1", stash_key: "synthetic-old-stash",
    })

    async def run():
        await page.run_init(flow.preflight_init_script(stash_key, preserve_refresh=True))
        return await flow.authenticated(page, ORIGIN)

    assert asyncio.run(run()) is refresh_ok
    assert page.calls[0]["url"] == ORIGIN + "/api/v1/auth/refresh"
    assert json.loads(page.calls[0]["body"]) == {"refresh_token": "synthetic-refresh"}
    assert all("synthetic-expired" not in str(call) for call in page.calls)
    if refresh_ok:
        assert page.calls[1]["url"] == ORIGIN + "/api/v1/auth/me"
        assert page.calls[1]["headers"]["Authorization"] == "Bearer synthetic-renewed"
    else:
        assert len(page.calls) == 1
        assert "auth_token" not in page.storage


@pytest.mark.parametrize("strict", [True, False])
def test_query_status_preserves_real_booleans_and_turnstile_metadata(node_executable, strict):
    page = ScriptPage(node_executable, [{"raw": state("false", "true", enabled="false", free_balance=7)}])
    result = asyncio.run(flow.query_status(page, replace(SPEC, strict_checkin=strict), ORIGIN))
    assert result["checked_in_today"] is False
    assert result["turnstile_required"] is True
    assert result["enabled"] is False
    assert result["turnstile_site_key"] == "public-site-key"
    assert result["balance"] == 0
    assert page.calls[0].get("method", "GET") == "GET"


def test_api_transmits_solver_token_and_refreshes_expired_auth_without_login(node_executable):
    page = ScriptPage(node_executable, [
        {"raw": state(required=True)},
        {"status": 401, "raw": {"code": "TOKEN_EXPIRED"}},
        {"raw": {"code": 0, "data": {"access_token": "synthetic-renewed", "refresh_token": "synthetic-next"}}},
        {"raw": {"code": 0, "data": {"reward_amount": 1, "balance": 0, "checked_in_today": True,
                                        "already_checked_in": False}}},
        {"raw": state(True, True)},
    ], storage={"refresh_token": "synthetic-refresh"})
    result = asyncio.run(flow.api_checkin(page, SPEC, ORIGIN, turnstile_token="synthetic-turnstile"))
    assert result["ok"] is True
    assert result["already"] is False
    assert result["balance"] == 0
    calls = page.calls
    assert [item["url"].removeprefix(ORIGIN) for item in calls] == [
        SPEC.status_path, SPEC.checkin_path, "/api/v1/auth/refresh", SPEC.checkin_path, SPEC.status_path,
    ]
    for index in (1, 3):
        assert json.loads(calls[index]["body"]) == {"turnstile_token": "synthetic-turnstile"}
    assert calls[3]["headers"]["Authorization"] == "Bearer synthetic-renewed"
    assert "synthetic-turnstile" not in str(result)


def test_api_required_without_token_does_not_post(node_executable):
    page = ScriptPage(node_executable, [{"raw": state(required=True)}])
    result = asyncio.run(flow.api_checkin(page, SPEC, ORIGIN))
    assert result["reason"] == "need_verification"
    assert len(page.calls) == 1


@pytest.mark.parametrize("reply,reason", [
    ({"text": ""}, "unconfirmed"),
    ({"text": "<html>synthetic-secret</html>"}, "unconfirmed"),
    ({"raw": {"code": 1, "data": {"checked_in_today": True}}}, "checkin_failed"),
    ({"raw": {"success": "false", "data": {"reward_amount": 5}}}, "checkin_failed"),
    ({"status": 403, "raw": {"message": "Turnstile failed synthetic-secret"}}, "need_verification"),
])
def test_api_rejects_empty_and_business_failure_2xx(node_executable, reply, reason):
    page = ScriptPage(node_executable, [{"raw": state()}, reply])
    result = asyncio.run(flow.api_checkin(page, SPEC, ORIGIN))
    assert result["ok"] is False
    assert result["reason"] == reason
    assert "synthetic-secret" not in str(result)
    assert json.loads(page.calls[1]["body"]) == {"turnstile_token": ""}


@pytest.mark.parametrize("already,expected", [(True, True), ("false", False)])
def test_api_distinguishes_already_from_new_checked_in_today(node_executable, already, expected):
    page = ScriptPage(node_executable, [
        {"raw": state()},
        {"raw": {"code": 0, "data": {"checked_in_today": True, "already_checked_in": already, "reward_amount": 0}}},
        {"raw": state(True)},
    ])
    result = asyncio.run(flow.api_checkin(page, SPEC, ORIGIN))
    assert result["ok"] is True
    assert result["already"] is expected


def test_legacy_api_still_accepts_original_three_arguments(node_executable):
    page = ScriptPage(node_executable, [{"raw": {"data": {"reward_amount": 3}}}])
    result = asyncio.run(flow.api_checkin(page, replace(SPEC, strict_checkin=False), ORIGIN))
    assert result["ok"] is True
    assert len(page.calls) == 1
    assert json.loads(page.calls[0]["body"]) == {}


class MutableHelpers(PageHelpers):
    """保留真实 Outcome 构造器，同时允许每个测试替换 I/O。"""


@pytest.fixture
def run_case(monkeypatch):
    import sdk

    ctx = SimpleNamespace(args={"login_timeout_ms": 12000}, log=Mock())
    page = SimpleNamespace()
    lease = SimpleNamespace(page=page, context=object(), mark_authenticated=Mock())
    helpers = MutableHelpers(ctx, lease, page)
    helpers.resolve_url = lambda path: ORIGIN + path
    helpers.solve = AsyncMock(return_value=SolveResult.solved("synthetic-turnstile"))
    helpers.success = Mock(wraps=helpers.success)
    helpers.already_done = Mock(wraps=helpers.already_done)
    helpers.need_verification = Mock(wraps=helpers.need_verification)
    monkeypatch.setattr(sdk, "PageHelpers", lambda *_: helpers)
    for name in ("add_init_script", "navigate_and_settle", "dismiss_notice"):
        monkeypatch.setattr(flow, name, AsyncMock())
    monkeypatch.setattr(flow, "on_login_page", AsyncMock(return_value=False))
    monkeypatch.setattr(flow, "authenticated", AsyncMock(return_value=True))
    monkeypatch.setattr(flow, "query_status", AsyncMock(return_value=normalized_state(required=True)))
    checkin = AsyncMock(return_value={"ok": True, "already": False, "status": 200, "balance": 0, "reward": 1})
    monkeypatch.setattr(flow, "api_checkin", checkin)
    login = AsyncMock()
    monkeypatch.setattr(flow, "login_with_password", login)
    return SimpleNamespace(ctx=ctx, lease=lease, helpers=helpers, checkin=checkin, login=login)


def test_run_flow_uses_solve_result_value_and_returns_helpers_result(run_case):
    expected = object()
    run_case.helpers.success.return_value = expected
    result = asyncio.run(flow.run_flow(run_case.ctx, run_case.lease, SPEC))
    assert result is expected
    run_case.helpers.solve.assert_awaited_once_with("turnstile", budget=12.0)
    run_case.checkin.assert_awaited_once_with(
        run_case.lease.page, SPEC, ORIGIN, turnstile_token="synthetic-turnstile",
    )
    run_case.lease.mark_authenticated.assert_called_once()
    run_case.login.assert_not_called()


@pytest.mark.parametrize("solved", [None, SolveResult.failure("timeout", "synthetic-secret"),
                                   SolveResult.solved("  "), SolveResult(ok=False, value="synthetic-secret")])
def test_run_flow_solver_failure_never_posts_or_exposes_credentials(run_case, solved):
    run_case.helpers.solve.return_value = solved
    result = asyncio.run(flow.run_flow(run_case.ctx, run_case.lease, SPEC))
    assert result.verdict is Verdict.FAILED
    assert result.reason == "need_verification"
    run_case.checkin.assert_not_called()
    run_case.login.assert_not_called()
    assert "synthetic-secret" not in str(result.to_payload())


def test_run_flow_solver_exception_is_a_verification_failure(run_case):
    run_case.helpers.solve.side_effect = RuntimeError("synthetic-secret")
    result = asyncio.run(flow.run_flow(run_case.ctx, run_case.lease, SPEC))
    assert result.reason == "need_verification"
    run_case.checkin.assert_not_called()
    assert "synthetic-secret" not in str(result.to_payload())


def test_run_flow_already_does_not_solve_or_post(monkeypatch, run_case):
    monkeypatch.setattr(flow, "query_status", AsyncMock(return_value=normalized_state(True, True)))
    result = asyncio.run(flow.run_flow(run_case.ctx, run_case.lease, SPEC))
    assert result.verdict is Verdict.ALREADY_DONE
    run_case.helpers.solve.assert_not_called()
    run_case.checkin.assert_not_called()


def test_run_flow_no_turnstile_skips_solver(monkeypatch, run_case):
    monkeypatch.setattr(flow, "query_status", AsyncMock(return_value=normalized_state()))
    result = asyncio.run(flow.run_flow(run_case.ctx, run_case.lease, SPEC))
    assert result.verdict is Verdict.SUCCESS
    run_case.helpers.solve.assert_not_called()
    run_case.checkin.assert_awaited_once_with(run_case.lease.page, SPEC, ORIGIN, turnstile_token="")


def test_run_flow_auth_expiry_after_verification_never_restarts_login(run_case):
    run_case.checkin.return_value = flow._checkin_failure("need_login", 401)
    result = asyncio.run(flow.run_flow(run_case.ctx, run_case.lease, SPEC))
    assert result.verdict is Verdict.FAILED
    assert result.reason == "need_login"
    run_case.login.assert_not_called()


@pytest.fixture
def click_case(monkeypatch):
    response_hooks = []
    page = SimpleNamespace(
        on=Mock(side_effect=lambda event, callback: response_hooks.append(callback)),
        remove_listener=Mock(), wait_for_timeout=AsyncMock(),
    )
    ctx = SimpleNamespace(log=Mock())
    helpers = MutableHelpers(ctx, SimpleNamespace(page=page), page)
    helpers.screenshot = AsyncMock(return_value="synthetic-screenshot")
    locator = object()
    control = ("签到", locator, "button")
    click = AsyncMock(return_value=(*control, "normal"))
    monkeypatch.setattr(flow, "click_checkin", click)
    monkeypatch.setattr(flow, "is_visible", AsyncMock(return_value=False))
    monkeypatch.setattr(flow, "visible_text", AsyncMock(return_value=True))
    monkeypatch.setattr(flow, "find_already_control", AsyncMock(return_value=("已签到", locator)))
    monkeypatch.setattr(flow, "find_already_text", AsyncMock(return_value="已签到"))
    query = AsyncMock(return_value=normalized_state())
    monkeypatch.setattr(flow, "query_status", query)
    opts = flow.parse_options(SPEC, {"completion_timeout_ms": 0, "button_wait_ms": 0})

    def emit(*, raw=None, status=200, path=None, method="POST", non_json=False):
        async def clicking(*args, **kwargs):
            response = SimpleNamespace(
                status=status, url=path or ORIGIN + SPEC.checkin_path,
                request=SimpleNamespace(method=method), json=AsyncMock(return_value=raw),
            )
            if non_json:
                response.json.side_effect = ValueError("synthetic-secret")
            response_hooks[0](response)
            return (*control, "normal")
        click.side_effect = clicking

    def run(spec=SPEC):
        return asyncio.run(flow.click_and_confirm(page, helpers, spec, opts, control, resolved_url=ORIGIN + "/check-in"))

    return SimpleNamespace(run=run, emit=emit, query=query, click=click, page=page, helpers=helpers)


def test_strict_click_rejects_all_dom_only_success_signals(click_case):
    result = click_case.run()
    assert result.verdict is Verdict.FAILED
    assert result.reason == "unconfirmed"
    click_case.page.remove_listener.assert_called_once()


@pytest.mark.parametrize("raw", [None, {}, {"success": False, "data": {"reward_amount": 5}},
                                  {"code": 9, "data": {"checked_in_today": True}}])
def test_strict_click_2xx_is_not_business_success(click_case, raw):
    click_case.emit(raw=raw)
    result = click_case.run()
    assert result.verdict is Verdict.FAILED
    assert result.reason in {"checkin_failed", "unconfirmed"}


def test_strict_click_non_json_cannot_succeed(click_case):
    click_case.emit(non_json=True)
    result = click_case.run()
    assert result.reason == "unconfirmed"
    assert "synthetic-secret" not in str(result.to_payload())


@pytest.mark.parametrize("path", [
    ORIGIN + "/api/v1/check-in/makeup", ORIGIN + "/api/v1/check-in/preview",
    ORIGIN + "/api/v1/check-in/status", ORIGIN + "/api/v1/check-in-other",
    ORIGIN + "/preview?next=/api/v1/check-in", "https://other.test/api/v1/check-in",
])
def test_strict_click_only_accepts_exact_same_origin_checkin_post(click_case, path):
    click_case.emit(raw={"code": 0, "data": {"reward_amount": 5}}, path=path)
    result = click_case.run()
    assert result.verdict is Verdict.FAILED
    assert result.reason == "unconfirmed"


def test_strict_click_get_response_is_not_checkin(click_case):
    click_case.emit(raw={"code": 0, "data": {"reward_amount": 5}}, method="GET")
    assert click_case.run().reason == "unconfirmed"


@pytest.mark.parametrize("already,verdict", [(False, Verdict.SUCCESS), (True, Verdict.ALREADY_DONE)])
def test_strict_click_confirms_real_business_success_and_already(click_case, already, verdict):
    click_case.query.side_effect = [normalized_state(), normalized_state(True)]
    click_case.emit(raw={"code": 0, "data": {
        "reward_amount": 1, "free_balance": 0, "already_checked_in": already, "checked_in_today": True,
    }})
    result = click_case.run()
    assert result.verdict is verdict
    assert result.data["balance"] == 0


def test_strict_click_can_confirm_with_server_state_without_dom_evidence(click_case):
    click_case.query.side_effect = [normalized_state(), normalized_state(True)]
    assert click_case.run().verdict is Verdict.SUCCESS


@pytest.mark.parametrize("checked,verdict", [(False, Verdict.FAILED), (True, Verdict.ALREADY_DONE)])
def test_strict_click_409_is_not_unconditionally_already(click_case, checked, verdict):
    click_case.query.side_effect = [normalized_state(), normalized_state(checked)]
    click_case.emit(status=409, raw={"message": "already"})
    assert click_case.run().verdict is verdict


def test_legacy_click_dom_success_contract_remains_unchanged(click_case):
    assert click_case.run(replace(SPEC, strict_checkin=False)).verdict is Verdict.SUCCESS
    click_case.query.assert_not_called()


def test_wait_for_control_does_not_trust_dom_already_in_strict_mode(monkeypatch, click_case):
    result = asyncio.run(flow.wait_for_checkin_control(
        click_case.page, click_case.helpers, SPEC, flow.parse_options(SPEC, {"button_wait_ms": 0}),
        resolved_url=ORIGIN + "/check-in", login_detail={},
    ))
    assert result == (None, None)


def test_run_flow_runs_real_preflight_before_refresh_and_preserves_refreshed_session(monkeypatch, node_executable):
    import sdk

    stash_key = flow.session_stash_key(SPEC.login_reset_sentinel)
    page = ScriptPage(node_executable, [
        {"raw": {"code": 0, "data": {"access_token": "synthetic-renewed",
                                      "refresh_token": "synthetic-rotated", "expires_in": 3600}}},
        {"raw": {"code": 0, "data": {"id": 1}}},
        {"raw": state(True)},
    ], storage={
        "auth_token": "synthetic-expired", "refresh_token": "synthetic-refresh",
        "auth_user": '{"id":1}', "token_expires_at": "1", stash_key: "synthetic-old-stash",
    })
    scripts = []
    snapshots = []
    context = SimpleNamespace(add_init_script=AsyncMock(side_effect=scripts.append))
    ctx = SimpleNamespace(args={}, log=Mock())
    lease = SimpleNamespace(page=page, context=context, mark_authenticated=Mock())
    helpers = MutableHelpers(ctx, lease, page)
    helpers.resolve_url = lambda path: ORIGIN + path
    helpers.solve = AsyncMock()
    monkeypatch.setattr(sdk, "PageHelpers", lambda *_: helpers)

    async def navigate(*_):
        for script in scripts:
            await page.run_init(script)
        snapshots.append(dict(page.storage))
        page.url = ORIGIN + ("/check-in" if page.storage.get("auth_token") else "/login")

    monkeypatch.setattr(flow, "navigate_and_settle", navigate)
    login = AsyncMock(side_effect=AssertionError("可刷新的会话不能重走密码登录"))
    monkeypatch.setattr(flow, "login_with_password", login)
    result = asyncio.run(flow.run_flow(ctx, lease, SPEC))
    assert result.verdict is Verdict.ALREADY_DONE
    assert len(scripts) == 1
    assert len(snapshots) == 2
    assert "auth_token" not in snapshots[0]
    assert "auth_user" not in snapshots[0]
    assert "token_expires_at" not in snapshots[0]
    assert stash_key not in snapshots[0]
    assert snapshots[0]["refresh_token"] == "synthetic-refresh"
    assert snapshots[1]["auth_token"] == "synthetic-renewed"
    assert snapshots[1]["refresh_token"] == "synthetic-rotated"
    assert [call["url"].removeprefix(ORIGIN) for call in page.calls] == [
        "/api/v1/auth/refresh", "/api/v1/auth/me", SPEC.status_path,
    ]
    login.assert_not_called()
    helpers.solve.assert_not_called()
    lease.mark_authenticated.assert_called_once()


def test_run_flow_login_route_refreshes_before_password_reset(monkeypatch, run_case):
    monkeypatch.setattr(flow, "on_login_page", AsyncMock(return_value=True))
    monkeypatch.setattr(flow, "query_status", AsyncMock(return_value=normalized_state()))
    result = asyncio.run(flow.run_flow(run_case.ctx, run_case.lease, SPEC))
    assert result.verdict is Verdict.SUCCESS
    run_case.login.assert_not_called()
    run_case.lease.mark_authenticated.assert_called_once()
    assert flow.navigate_and_settle.await_count == 2


def test_run_flow_unauthenticated_spa_enters_login_without_waiting_for_checkin(monkeypatch, run_case):
    monkeypatch.setattr(flow, "authenticated", AsyncMock(side_effect=[False, True]))
    monkeypatch.setattr(flow, "query_status", AsyncMock(return_value=normalized_state()))
    waiting = AsyncMock(side_effect=AssertionError("不应先等待签到按钮"))
    monkeypatch.setattr(flow, "wait_for_checkin_control", waiting)
    run_case.login.return_value = None
    result = asyncio.run(flow.run_flow(run_case.ctx, run_case.lease, SPEC))
    assert result.verdict is Verdict.SUCCESS
    run_case.login.assert_awaited_once()
    waiting.assert_not_called()


@pytest.mark.parametrize("strict,verdict", [(True, Verdict.SUCCESS), (False, Verdict.FAILED)])
def test_login_form_wait_honors_strict_budget_instead_of_thirty_second_cap(monkeypatch, strict, verdict):
    """用虚拟时钟模拟第 40 秒才出现的 SPA 表单，不实际等待。"""
    elapsed = [0.0]
    monkeypatch.setattr(flow, "asyncio", SimpleNamespace(get_running_loop=lambda: SimpleNamespace(time=lambda: elapsed[0])))

    async def wait(milliseconds):
        elapsed[0] += milliseconds / 1000

    page = SimpleNamespace(evaluate=AsyncMock(return_value=False), wait_for_load_state=AsyncMock(),
                           wait_for_timeout=wait)
    ctx = SimpleNamespace(log=Mock())
    helpers = MutableHelpers(ctx, SimpleNamespace(page=page), page)
    helpers.goto = AsyncMock()
    helpers.screenshot = AsyncMock(return_value="synthetic-screenshot")
    helpers.solve = AsyncMock(return_value=SolveResult.solved("synthetic-turnstile"))
    for name in ("add_init_script", "keep_waf_cookies", "dismiss_notice", "_record_new_tokens"):
        monkeypatch.setattr(flow, name, AsyncMock())
    for name in ("authenticated", "stash_session", "mark_login_done"):
        monkeypatch.setattr(flow, name, AsyncMock(return_value=True))
    monkeypatch.setattr(flow, "fill_login_form", AsyncMock(side_effect=lambda *_: elapsed[0] >= 40))
    submit = AsyncMock(return_value={"ok": True, "status": 200})
    monkeypatch.setattr(flow, "submit_login", submit)
    spec = replace(SPEC, strict_checkin=strict)
    opts = flow.parse_options(spec, {"email": "synthetic@example.test", "password": "synthetic-secret",
                                     "login_timeout_ms": 60000})
    result = asyncio.run(flow.login_with_password(page, object(), helpers, spec, opts,
                                                  ORIGIN + "/check-in", ORIGIN, {}))
    if verdict is Verdict.SUCCESS:
        assert result is None
        assert elapsed[0] >= 40
        submit.assert_awaited_once()
        helpers.solve.assert_awaited_once_with("turnstile", budget=60.0, poll_interval_ms=100)
    else:
        assert result.reason == "need_config"
        assert elapsed[0] < 40
        submit.assert_not_called()


@pytest.mark.parametrize("phase", ["page", "form"])
def test_strict_unavailable_login_ui_is_unconfirmed_not_missing_config(monkeypatch, phase):
    ticks = iter(range(0, 100, 2))
    monkeypatch.setattr(flow, "asyncio", SimpleNamespace(get_running_loop=lambda: SimpleNamespace(time=lambda: next(ticks))))
    page = SimpleNamespace(evaluate=AsyncMock(return_value=phase == "page"),
                           wait_for_load_state=AsyncMock(), wait_for_timeout=AsyncMock())
    ctx = SimpleNamespace(log=Mock())
    helpers = MutableHelpers(ctx, SimpleNamespace(page=page), page)
    helpers.goto = AsyncMock()
    helpers.screenshot = AsyncMock(return_value="synthetic-screenshot")
    helpers.solve = AsyncMock()
    for name in ("add_init_script", "keep_waf_cookies", "dismiss_notice"):
        monkeypatch.setattr(flow, name, AsyncMock())
    monkeypatch.setattr(flow, "fill_login_form", AsyncMock(return_value=False))
    opts = flow.parse_options(SPEC, {"email": "synthetic@example.test", "password": "synthetic-secret",
                                    "login_timeout_ms": 1000})
    result = asyncio.run(flow.login_with_password(page, object(), helpers, SPEC, opts,
                                                  ORIGIN + "/check-in", ORIGIN, {}))
    assert result.verdict is Verdict.FAILED
    assert result.reason == "unconfirmed"
    assert result.data["screenshot"] == "synthetic-screenshot"
    helpers.solve.assert_not_called()
    assert "synthetic-secret" not in str(result.to_payload())


def test_strict_login_missing_credentials_remains_need_login(monkeypatch):
    monkeypatch.setattr(flow.os, "getenv", lambda *args: "")
    helpers = MutableHelpers(SimpleNamespace(log=Mock()), SimpleNamespace(page=object()))
    result = asyncio.run(flow.login_with_password(object(), object(), helpers, SPEC, flow.parse_options(SPEC, {}),
                                                  ORIGIN + "/check-in", ORIGIN, {}))
    assert result.reason == "need_login"
    assert result.data["login_fallback"] == "missing_credentials"


def test_strict_login_401_keeps_need_login_and_does_not_leak_response_message(monkeypatch):
    page = SimpleNamespace(evaluate=AsyncMock(return_value=False), wait_for_load_state=AsyncMock(),
                           wait_for_timeout=AsyncMock())
    ctx = SimpleNamespace(log=Mock())
    helpers = MutableHelpers(ctx, SimpleNamespace(page=page), page)
    helpers.goto = AsyncMock()
    helpers.solve = AsyncMock(return_value=SolveResult.solved("synthetic-turnstile"))
    for name in ("add_init_script", "keep_waf_cookies", "dismiss_notice"):
        monkeypatch.setattr(flow, name, AsyncMock())
    monkeypatch.setattr(flow, "fill_login_form", AsyncMock(return_value=True))
    record = AsyncMock()
    monkeypatch.setattr(flow, "_record_new_tokens", record)
    monkeypatch.setattr(flow, "submit_login", AsyncMock(return_value={
        "ok": False, "status": 401, "message": "INVALID_CREDENTIALS synthetic-secret",
    }))
    opts = flow.parse_options(SPEC, {"email": "synthetic@example.test", "password": "synthetic-secret"})
    result = asyncio.run(flow.login_with_password(page, object(), helpers, SPEC, opts,
                                                  ORIGIN + "/check-in", ORIGIN, {}))
    assert result.reason == "need_login"
    record.assert_not_called()
    assert "synthetic-secret" not in str(result.to_payload())
    assert "synthetic-secret" not in str(ctx.log.call_args_list)


def test_api_failed_refresh_does_not_restart_login(node_executable):
    page = ScriptPage(node_executable, [
        {"raw": state()},
        {"status": 401, "raw": {"code": "TOKEN_EXPIRED"}},
        {"status": 401, "raw": {"code": "REFRESH_TOKEN_INVALID"}},
    ], storage={"refresh_token": "synthetic-refresh"})
    result = asyncio.run(flow.api_checkin(page, SPEC, ORIGIN))
    assert result["reason"] == "need_login"
    assert [call["url"].removeprefix(ORIGIN) for call in page.calls] == [
        SPEC.status_path, SPEC.checkin_path, "/api/v1/auth/refresh",
    ]


def test_api_success_with_negative_server_state_is_unconfirmed(node_executable):
    page = ScriptPage(node_executable, [
        {"raw": state()}, {"raw": {"code": 0, "data": {"reward_amount": 1}}}, {"raw": state()},
    ])
    result = asyncio.run(flow.api_checkin(page, SPEC, ORIGIN))
    assert result["ok"] is False
    assert result["reason"] == "unconfirmed"


def test_api_already_state_skips_even_required_turnstile(node_executable):
    page = ScriptPage(node_executable, [{"raw": state(True, True)}])
    result = asyncio.run(flow.api_checkin(page, SPEC, ORIGIN))
    assert result["already"] is True
    assert len(page.calls) == 1


def test_http_non_json_transport_error_is_unconfirmed():
    ctx = http_ctx()
    ctx.http.request.side_effect = TaskError("invalid JSON synthetic-secret", payload="synthetic-secret")
    result = asyncio.run(flow.http_first(ctx, SPEC))
    assert result.reason == "unconfirmed"
    assert "synthetic-secret" not in str(result.to_payload())


def test_strict_click_business_failure_is_not_overridden_by_dom_or_later_state(click_case):
    click_case.query.side_effect = [normalized_state(), normalized_state(True)]
    click_case.emit(raw={"success": False, "data": {"checked_in_today": True}})
    assert click_case.run().reason == "checkin_failed"
    assert click_case.query.await_count == 1


def test_strict_api_fallback_does_not_restart_password_login(monkeypatch, click_case):
    monkeypatch.setattr(flow, "query_status", AsyncMock(return_value=flow._checkin_failure("need_login", 401)))
    do_login = AsyncMock()
    result = asyncio.run(flow.api_fallback(
        click_case.page, click_case.helpers, SPEC, flow.parse_options(SPEC, {}),
        ORIGIN, ORIGIN + "/check-in", False, do_login,
    ))
    assert result.reason == "need_login"
    do_login.assert_not_called()
