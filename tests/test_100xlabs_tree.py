"""百倍独立砍树任务：任务分派、服务端确认、幂等边界和账号设备隔离。"""

from __future__ import annotations

import asyncio
import importlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from core.errors import LoginRequired, TaskError, TransientError
from core.outcome import DisplaySpec, Evidence, Verdict, already_done, failed, no_effect, success


class FakeStore:
    """只保存当前假账号的数据，不接触覆盖层或真实账号缓存。"""

    def __init__(self, values=None, *, writable=True):
        self.values = dict(values or {})
        self.writable = writable
        self.reads = []
        self.writes = []

    def get(self, key, default=None):
        self.reads.append(key)
        return self.values.get(key, default)

    def put(self, key, value):
        self.writes.append((key, value))
        if self.writable:
            self.values[key] = value
        return self.writable


class FakeHttp:
    def __init__(self, responses=()):
        self.responses = list(responses)
        self.calls = []
        self.headers = {"Authorization": "Bearer test-only-token"}

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        return _response(self.responses, method, path)

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)


def _response(responses, method, path):
    assert responses, f"没有为 {method} {path} 准备响应；禁止真实网络或额外重试"
    response = responses.pop(0)
    if isinstance(response, BaseException):
        raise response
    return response


class FakePage:
    """模拟 evaluate 的设备存储/请求边界，不启动浏览器或执行真实 fetch。"""

    def __init__(self, url, responses=(), local_storage=None):
        self.url = url
        self.responses = list(responses)
        self.local_storage = dict(local_storage or {})
        self.calls = []
        self.evaluate = AsyncMock(side_effect=self._evaluate)

    async def _evaluate(self, script, args):
        if "key" in args:
            assert "localStorage.getItem" in script
            assert "localStorage.setItem" in script
            existing = self.local_storage.get(args["key"], "")
            if args["saved"] and existing and args["saved"] != existing:
                # 同时检查实际脚本含冲突保护，不能只靠假对象替实现拦截换设备。
                guard = "if (saved && existing && saved !== existing) return null;"
                assert guard in script
                assert script.index(guard) < script.index("localStorage.setItem")
                return None
            device = existing or args["saved"] or args["fresh"]
            self.local_storage[args["key"]] = device
            return device
        assert "requestWithAuth" in script
        assert "AbortController" in script
        self.calls.append((args["method"], args["path"], {"json_body": args["body"]}))
        payload = _response(self.responses, args["method"], args["path"])
        return {"status": 200, "payload": payload}


class FakeLease:
    def __init__(self, page):
        self.page = page
        self.new_page = AsyncMock(return_value=page)
        self.context = SimpleNamespace(clear_cookies=AsyncMock(), add_init_script=AsyncMock())
        self.mark_authenticated = Mock()
        self.entered = False
        self.exited = False

    async def __aenter__(self):
        self.entered = True
        return self

    async def __aexit__(self, *_):
        self.exited = True


@pytest.fixture
def tree(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts" / "tasks"))
    return importlib.import_module("_100xlabs_tree")


@pytest.fixture
def template(tree):
    module = importlib.import_module("scripts.tasks.100xlabs")
    assert module.tree is tree
    return module


def _ctx(
    responses=(), *, args=None, base_url="https://compatible.test", store=None,
    expired=None, task_id="daily",
):
    return SimpleNamespace(
        account=SimpleNamespace(id="fake-account", base_url=base_url, task_id=task_id),
        args=dict(args or {}),
        http=FakeHttp(responses),
        store=store if store is not None else FakeStore(),
        expired=expired if expired is not None else Mock(return_value=False),
        log=Mock(),
    )


def _case(responses=(), *, transport="http", base_url="https://compatible.test", **kwargs):
    ctx = _ctx(responses if transport == "http" else (), base_url=base_url, **kwargs)
    page = None if transport == "http" else FakePage(base_url + "/lottery", responses)
    return ctx, page


def _calls(ctx, page=None):
    return ctx.http.calls if page is None else page.calls


def _state(remain, batch_max=10, *, enabled=True, bind_blocked=False, **extra):
    return {
        "chop": {
            "enabled": enabled,
            "bind_blocked": bind_blocked,
            "stamina": {"remain": remain},
            "batch_max": batch_max,
        },
        **extra,
    }


def _ok(data):
    return {"code": 0, "data": data}


def _chopped(remain, batch_max=10):
    return _ok({"status": _state(remain, batch_max)})


def _wire_entry(monkeypatch, template, ctx, checkin, transport, page=None):
    lease = FakeLease(page or FakePage(ctx.account.base_url + "/check-in"))
    ctx.browser = SimpleNamespace(lease=Mock(return_value=lease))
    http_first = AsyncMock(return_value=checkin if transport == "http" else None)
    run_flow = AsyncMock(return_value=checkin)
    monkeypatch.setattr(template.flow, "http_first", http_first)
    monkeypatch.setattr(template.flow, "run_flow", run_flow)
    return lease, http_first, run_flow


def _assert_methods(calls, expected):
    assert [method for method, _, _ in calls] == expected
    for method, path, _ in calls:
        assert urlsplit(path).path == (
            "/api/v1/game/chop" if method == "POST" else "/api/v1/game/status"
        ), "砍树只能查询状态和消费斧力，不能购买、装备或分解"


def _forbid_checkin(monkeypatch, flow):
    calls = []
    for name in ("http_first", "run_flow", "api_checkin", "query_status"):
        call = AsyncMock(side_effect=AssertionError(f"独立砍树不能调用签到函数 {name}"))
        monkeypatch.setattr(flow, name, call)
        calls.append(call)
    return calls


def _wire_tree_browser(monkeypatch, tree, ctx, page, *, authenticated=(True,)):
    lease = FakeLease(page)
    ctx.browser_service = object()
    ctx.browser = SimpleNamespace(lease=Mock(return_value=lease))
    origin = f"{urlsplit(ctx.account.base_url).scheme}://{urlsplit(ctx.account.base_url).netloc}"
    helpers = SimpleNamespace(resolve_url=lambda path: origin + path)
    helper_factory = Mock(return_value=helpers)
    monkeypatch.setattr(tree, "PageHelpers", helper_factory)

    async def navigate(actual_page, actual_helpers, path, _opts):
        assert actual_page is page and actual_helpers is helpers
        assert path == "/lingtai", "砍树登录只能导航到灵台，不打开签到入口"
        page.url = origin + path

    nav = AsyncMock(side_effect=navigate)
    auth = AsyncMock(side_effect=authenticated)
    login = AsyncMock(return_value=None)
    init = AsyncMock()
    preflight = Mock(wraps=tree.flow.preflight_init_script)
    monkeypatch.setattr(tree.flow, "navigate_and_settle", nav)
    monkeypatch.setattr(tree.flow, "authenticated", auth)
    monkeypatch.setattr(tree.flow, "login_with_password", login)
    monkeypatch.setattr(tree.flow, "add_init_script", init)
    monkeypatch.setattr(tree.flow, "preflight_init_script", preflight)
    return SimpleNamespace(
        lease=lease, helpers=helpers, helper_factory=helper_factory,
        navigate=nav, authenticated=auth, login=login, init=init, preflight=preflight,
        checkin_calls=_forbid_checkin(monkeypatch, tree.flow),
    )


def _assert_tree_browser_only(ctx, harness):
    ctx.browser.lease.assert_called_once_with(reason="100xlabs-lingtai")
    harness.lease.new_page.assert_awaited_once()
    harness.helper_factory.assert_called_once_with(ctx, harness.lease, harness.lease.page)
    assert harness.lease.entered and harness.lease.exited
    harness.lease.context.clear_cookies.assert_not_awaited()
    for call in harness.checkin_calls:
        call.assert_not_awaited()
    assert all(call.args[2] == "/lingtai" for call in harness.navigate.await_args_list)


def test_manifest_removes_legacy_flag_and_keeps_strict_checkin(template):
    option = template.MANIFEST.task_option("script")
    assert option.args.get("chop_tree") is None
    assert template.SPEC.strict_checkin is True
    assert "browser" not in option.requires


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize("task_id", ["daily", "other-checkin", ""])
@pytest.mark.parametrize(
    "args", [{}, {"chop_tree": False}, {"chop_tree": "false"}, {"chop_tree": True}, {"chop_tree": "true"}],
    ids=["default", "boolean-false", "string-false", "boolean-true", "string-true"],
)
def test_non_tree_task_only_checks_in_and_ignores_legacy_flag(
    monkeypatch, template, transport, task_id, args,
):
    ctx = _ctx(args=args, task_id=task_id)
    checkin = success("每日签到成功", data={"balance": 12}).with_display(text="$12.00", text_label="额度")
    lease, http_first, run_flow = _wire_entry(monkeypatch, template, ctx, checkin, transport)
    tree_run = AsyncMock(side_effect=AssertionError("签到任务不能进入独立砍树"))
    chop = AsyncMock(side_effect=AssertionError("签到任务不能直接调用砍树 helper"))
    monkeypatch.setattr(template.tree, "run", tree_run)
    monkeypatch.setattr(template.tree, "run_chop_tree", chop)

    outcome = asyncio.run(template.run(ctx))

    assert outcome is checkin
    assert outcome.data == {"balance": 12}
    http_first.assert_awaited_once_with(ctx, template.SPEC)
    tree_run.assert_not_awaited()
    chop.assert_not_awaited()
    assert ctx.http.calls == []
    assert ctx.store.reads == ctx.store.writes == []
    lease.page.evaluate.assert_not_awaited()
    if transport == "browser":
        ctx.browser.lease.assert_called_once_with(reason="checkin")
        lease.new_page.assert_awaited_once()
        run_flow.assert_awaited_once_with(ctx, lease, template.SPEC)
        assert lease.entered and lease.exited
    else:
        ctx.browser.lease.assert_not_called()
        run_flow.assert_not_awaited()


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize("factory", [success, already_done, failed, no_effect])
def test_daily_returns_its_own_outcome_unchanged(monkeypatch, template, transport, factory):
    ctx = _ctx(args={"chop_tree": True}, task_id="daily")
    checkin = factory("签到独立结果", data={"source": "checkin-only"})
    checkin = checkin.with_display(text="$6.00", text_label="额度")
    checkin = checkin.with_evidence(Evidence(responses=("checkin-response",)))
    _wire_entry(monkeypatch, template, ctx, checkin, transport)
    tree_run = AsyncMock(side_effect=AssertionError("任何签到结论都不能自动追加砍树"))
    monkeypatch.setattr(template.tree, "run", tree_run)

    outcome = asyncio.run(template.run(ctx))

    assert outcome is checkin
    assert outcome.data == {"source": "checkin-only"}
    assert outcome.evidence.responses == ("checkin-response",)
    tree_run.assert_not_awaited()


@pytest.mark.parametrize("base_url", ["https://unrelated-sub2api.test", "https://another.test:8443/app"])
@pytest.mark.parametrize("factory", [success, already_done, failed, no_effect])
@pytest.mark.parametrize("args", [{}, {"chop_tree": False}, {"chop_tree": "false"}, {"chop_tree": True}])
def test_chop_tree_task_dispatches_directly_and_preserves_independent_outcome(
    monkeypatch, template, base_url, factory, args,
):
    ctx = _ctx(args=args, base_url=base_url, task_id="chop_tree")
    ctx.browser = SimpleNamespace(lease=Mock(side_effect=AssertionError("页面租用由独立砍树入口决定")))
    checkin_calls = _forbid_checkin(monkeypatch, template.flow)
    expected = factory("砍树独立结果", data={"source": "lingtai", "remaining_stamina": 2})
    expected = expected.with_display(DisplaySpec(text="剩余 2", text_label="斧力"))
    expected = expected.with_evidence(Evidence(responses=("tree-response",)))
    tree_run = AsyncMock(return_value=expected)
    monkeypatch.setattr(template.tree, "run", tree_run)

    outcome = asyncio.run(template.run(ctx))

    assert outcome is expected
    assert outcome.data == {"source": "lingtai", "remaining_stamina": 2}
    assert outcome.evidence.responses == ("tree-response",)
    tree_run.assert_awaited_once_with(ctx, template.SPEC)
    for call in checkin_calls:
        call.assert_not_awaited()
    ctx.browser.lease.assert_not_called()
    assert ctx.http.calls == [] and ctx.store.reads == []


@pytest.mark.parametrize(
    "checkin_factory,tree_factory",
    [(failed, success), (no_effect, success), (already_done, success), (success, failed)],
    ids=["failed-daily-tree-success", "closed-daily-tree-success", "done-daily-tree-success", "daily-success-tree-failed"],
)
def test_daily_and_tree_keep_separate_results_without_success_or_failure_gates(
    monkeypatch, template, checkin_factory, tree_factory,
):
    checkin = checkin_factory("签到独立结论", data={"balance": 9})
    tree_result = tree_factory("砍树独立结论", data={"remaining_stamina": 3})
    daily_ctx = _ctx(task_id="daily", args={"chop_tree": True})
    tree_ctx = _ctx(task_id="chop_tree", args={"chop_tree": False}, store=daily_ctx.store)
    _, http_first, run_flow = _wire_entry(monkeypatch, template, daily_ctx, checkin, "http")
    tree_run = AsyncMock(return_value=tree_result)
    monkeypatch.setattr(template.tree, "run", tree_run)

    assert asyncio.run(template.run(daily_ctx)) is checkin
    assert asyncio.run(template.run(tree_ctx)) is tree_result
    http_first.assert_awaited_once_with(daily_ctx, template.SPEC)
    run_flow.assert_not_awaited()
    tree_run.assert_awaited_once_with(tree_ctx, template.SPEC)
    assert checkin.data == {"balance": 9}
    assert tree_result.data == {"remaining_stamina": 3}


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize("base_url", ["https://unrelated-sub2api.test", "https://another.test:8443/app"])
def test_helper_runs_without_any_checkin_on_any_compatible_domain(monkeypatch, tree, transport, base_url):
    ctx, page = _case(
        [_ok(_state(3)), _chopped(0), _ok(_state(0))],
        transport=transport, base_url=base_url, task_id="chop_tree",
    )
    checkin_calls = _forbid_checkin(monkeypatch, tree.flow)

    outcome = asyncio.run(tree.run_chop_tree(ctx, page))

    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["remaining_stamina"] == 0
    assert "checkin" not in outcome.data and "chop_tree" not in outcome.data
    _assert_methods(_calls(ctx, page), ["GET", "POST", "GET"])
    for call in checkin_calls:
        call.assert_not_awaited()
    if page is not None:
        assert ctx.http.calls == []
        origin = f"{urlsplit(base_url).scheme}://{urlsplit(base_url).netloc}"
        request_args = [call.args[1] for call in page.evaluate.await_args_list if "path" in call.args[1]]
        assert all(args["baseUrl"] == origin for args in request_args)


@pytest.mark.parametrize("transport", ["http", "browser"])
def test_dynamic_server_batches_drain_stamina_then_confirm_with_get(tree, transport):
    ctx, page = _case(
        [
            _ok(_state(35, 12)),
            _chopped(23, 7),
            _chopped(16, 20),
            _chopped(0),
            _ok(_state(0, None, balance=25.25, free_balance=True, wood=4)),
        ],
        transport=transport,
    )

    outcome = asyncio.run(tree.run_chop_tree(ctx, page))

    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["initial_stamina"] == 35
    assert outcome.data["remaining_stamina"] == 0
    assert outcome.data["consumed"] == 35
    assert outcome.data["batches"] == 3
    assert outcome.data["completion_signal"] == "game_status"
    assert outcome.data["balance"] == 25.25 and outcome.data["wood"] == 4
    assert "free_balance" not in outcome.data
    calls = _calls(ctx, page)
    _assert_methods(calls, ["GET", "POST", "POST", "POST", "GET"])
    bodies = [kwargs["json_body"] for method, _, kwargs in calls if method == "POST"]
    assert [body["count"] for body in bodies] == [12, 7, 16]
    assert all(set(body) == {"count", "batch_key", "device_id"} for body in bodies)
    assert len({body["batch_key"] for body in bodies}) == 3
    assert all(isinstance(body["batch_key"], str) and body["batch_key"] for body in bodies)
    devices = {body["device_id"] for body in bodies}
    assert len(devices) == 1
    device = devices.pop()
    assert all(parse_qs(urlsplit(path).query) == {"device_id": [device]}
               for method, path, _ in calls if method == "GET")
    if page is None:
        assert all(kwargs["retry_non_idempotent"] is False for _, _, kwargs in calls)
    else:
        assert ctx.http.calls == []


@pytest.mark.parametrize("transport", ["http", "browser"])
def test_initial_zero_never_posts_or_requires_a_batch_limit(tree, transport):
    state = _state(0)
    del state["chop"]["batch_max"]
    ctx, page = _case([_ok(state)], transport=transport)

    outcome = asyncio.run(tree.run_chop_tree(ctx, page))

    assert outcome.verdict is Verdict.ALREADY_DONE
    assert outcome.data["remaining_stamina"] == outcome.data["consumed"] == outcome.data["batches"] == 0
    _assert_methods(_calls(ctx, page), ["GET"])


@pytest.mark.parametrize("transport", ["http", "browser"])
def test_post_zero_without_final_server_zero_is_not_success(tree, transport):
    ctx, page = _case([_ok(_state(4)), _chopped(0), _ok(_state(2))], transport=transport)

    outcome = asyncio.run(tree.run_chop_tree(ctx, page))

    assert outcome.verdict is Verdict.FAILED
    assert outcome.reason == "unconfirmed"
    assert outcome.data["remaining_stamina"] == 2
    assert "completion_signal" not in outcome.data
    _assert_methods(_calls(ctx, page), ["GET", "POST", "GET"])


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize(
    "raw,reason",
    [
        (None, "unconfirmed"),
        ("<html>not JSON</html>", "unconfirmed"),
        ([], "unconfirmed"),
        ({}, "unconfirmed"),
        ({"data": None}, "unconfirmed"),
        ({"data": []}, "unconfirmed"),
        ({"data": {}}, "unconfirmed"),
        (_ok({"balance": 5}), "unconfirmed"),
        (_ok({"chop": []}), "unconfirmed"),
        (_ok(_state(3, enabled=False)), "not_open"),
        (_ok(_state(0, enabled=False)), "not_open"),
        (_ok(_state(3, enabled="true")), "not_open"),
        (_ok(_state(3, enabled=1)), "not_open"),
        (_ok(_state(3, bind_blocked=True)), "need_config"),
        (_ok(_state(0, bind_blocked=True)), "need_config"),
        ({"success": False, "data": _state(0)}, "unconfirmed"),
        ({"code": 403, "data": _state(0)}, "unconfirmed"),
        ({"code": "500", "data": _state(0)}, "unconfirmed"),
    ],
    ids=[
        "null", "html", "array", "empty", "null-data", "array-data", "empty-data",
        "missing-chop", "invalid-chop", "disabled", "disabled-zero", "enabled-string",
        "enabled-integer", "binding-blocked", "binding-blocked-zero", "business-false",
        "business-code", "business-string-code",
    ],
)
def test_invalid_or_refused_initial_state_never_succeeds_or_posts(tree, transport, raw, reason):
    ctx, page = _case([raw], transport=transport)

    outcome = asyncio.run(tree.run_chop_tree(ctx, page))

    assert outcome.verdict is Verdict.FAILED
    assert outcome.reason == reason
    assert not outcome.ok
    _assert_methods(_calls(ctx, page), ["GET"])


@pytest.mark.parametrize("value", [None, True, -1, 1.5, "3"])
@pytest.mark.parametrize("field", ["remain", "batch_max"])
def test_stamina_and_batch_limit_must_be_non_boolean_integers(tree, field, value):
    state = _state(5)
    target = state["chop"]["stamina"] if field == "remain" else state["chop"]
    target[field] = value
    ctx = _ctx([_ok(state)])

    outcome = asyncio.run(tree.run_chop_tree(ctx))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == "unconfirmed"
    _assert_methods(ctx.http.calls, ["GET"])


@pytest.mark.parametrize("chop", [
    {"enabled": True, "batch_max": 3},
    {"enabled": True, "batch_max": 3, "stamina": []},
    {"enabled": True, "batch_max": 3, "stamina": {}},
    {"enabled": True, "batch_max": 0, "stamina": {"remain": 3}},
    {"enabled": True, "stamina": {"remain": 3}},
])
def test_missing_stamina_or_invalid_batch_limit_is_not_guessed(tree, chop):
    ctx = _ctx([_ok({"chop": chop})])
    outcome = asyncio.run(tree.run_chop_tree(ctx))
    assert outcome.verdict is Verdict.FAILED
    _assert_methods(ctx.http.calls, ["GET"])


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize("raw", [
    _ok({"reward": 1}),
    _ok({"status": None}),
    _ok({"status": []}),
    _ok({"status": {}}),
    _ok({"status": _state("0")}),
    _ok({"status": _state(0, enabled=False)}),
    _ok({"status": _state(0, bind_blocked=True)}),
    {"success": False, "data": {"status": _state(0)}},
    {"code": 500, "data": {"status": _state(0)}},
])
def test_unknown_or_refused_chop_response_is_not_treated_as_completion(tree, transport, raw):
    ctx, page = _case([_ok(_state(4)), raw, _ok(_state(4))], transport=transport)

    outcome = asyncio.run(tree.run_chop_tree(ctx, page))

    assert outcome.verdict is Verdict.FAILED
    assert outcome.data["remaining_stamina"] == 4
    assert "completion_signal" not in outcome.data
    calls = _calls(ctx, page)
    assert [method for method, _, _ in calls].count("POST") == 1
    assert len(calls) <= 3, "无效响应不能触发重新砍树"


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize(
    "raw",
    [{"success": False, "data": {"status": _state(0)}}, _ok({"reward": 1})],
    ids=["business-refusal", "missing-updated-status"],
)
def test_failed_post_with_independent_get_zero_confirms_goal_and_preserves_error(tree, transport, raw):
    ctx, page = _case([_ok(_state(4)), raw, _ok(_state(0))], transport=transport)

    outcome = asyncio.run(tree.run_chop_tree(ctx, page))

    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["completion_signal"] == "status_after_error"
    assert outcome.data["remaining_stamina"] == 0 and outcome.data["consumed"] == 4
    assert outcome.data["request_error"]["reason"] == "unconfirmed"
    assert outcome.data["request_error"].get("status") in (None, 0)
    assert "清空" in outcome.message
    assert "POST成功" not in outcome.message and "请求成功" not in outcome.message
    _assert_methods(_calls(ctx, page), ["GET", "POST", "GET"])
    if page is None:
        assert ctx.http.calls[1][2]["retry_non_idempotent"] is False
    else:
        assert ctx.http.calls == []


def test_post_http_error_status_is_retained_after_get_confirms_zero(tree):
    ctx = _ctx([_ok(_state(4)), TransientError("HTTP 503", status=503), _ok(_state(0))])

    outcome = asyncio.run(tree.run_chop_tree(ctx))

    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["completion_signal"] == "status_after_error"
    assert outcome.data["request_error"]["reason"] == "network_error"
    assert outcome.data["request_error"]["status"] == 503
    assert outcome.data["remaining_stamina"] == 0
    _assert_methods(ctx.http.calls, ["GET", "POST", "GET"])
    assert ctx.http.calls[1][2]["retry_non_idempotent"] is False


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize(
    "readback",
    [_state(0, enabled=False), _state(0, bind_blocked=True), _state("0")],
    ids=["disabled-zero", "binding-blocked-zero", "invalid-zero"],
)
def test_post_error_requires_valid_enabled_unblocked_zero_for_recovery(tree, transport, readback):
    ctx, page = _case(
        [_ok(_state(4)), _ok({"reward": 1}), _ok(readback)], transport=transport,
    )

    outcome = asyncio.run(tree.run_chop_tree(ctx, page))

    assert outcome.verdict is Verdict.FAILED
    assert outcome.data["remaining_stamina"] == 4
    assert "completion_signal" not in outcome.data
    assert outcome.data["request_error"]["reason"] == "unconfirmed"
    _assert_methods(_calls(ctx, page), ["GET", "POST", "GET"])


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize("remaining", [0, 3, 6])
def test_post_timeout_is_never_reposted_and_only_confirmed_zero_succeeds(
    monkeypatch, tree, transport, remaining,
):
    # 关闭退避重试时，旧的「不盲目重发」语义保持不变。
    monkeypatch.setattr(tree, "RETRY_DELAYS", ())
    error = TransientError("POST timed out") if transport == "http" else TimeoutError("POST timed out")
    ctx, page = _case([_ok(_state(6)), error, _ok(_state(remaining))], transport=transport)

    outcome = asyncio.run(tree.run_chop_tree(ctx, page))

    assert outcome.data["remaining_stamina"] == remaining
    assert outcome.data["consumed"] == 6 - remaining
    _assert_methods(_calls(ctx, page), ["GET", "POST", "GET"])
    if remaining == 0:
        assert outcome.verdict is Verdict.SUCCESS
        assert outcome.data["completion_signal"] == "status_after_error"
    else:
        assert outcome.verdict is Verdict.FAILED and outcome.reason == "network_error"
        assert "completion_signal" not in outcome.data
    if page is None:
        assert ctx.http.calls[1][2]["retry_non_idempotent"] is False


@pytest.mark.parametrize("recheck", [TransientError("GET timed out"), None, _ok({"unexpected": True})])
def test_timeout_and_failed_readback_keep_last_known_remaining_without_retry(tree, recheck):
    ctx = _ctx([_ok(_state(5)), TransientError("POST timed out"), recheck])

    outcome = asyncio.run(tree.run_chop_tree(ctx))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == "network_error"
    assert outcome.data["remaining_stamina"] == 5
    _assert_methods(ctx.http.calls, ["GET", "POST", "GET"])


@pytest.mark.parametrize("raw", [None, _ok({"chop": {}}), TransientError("final GET failed")])
def test_missing_final_confirmation_fails_even_after_post_reports_zero(tree, raw):
    ctx = _ctx([_ok(_state(5)), _chopped(0), raw])
    outcome = asyncio.run(tree.run_chop_tree(ctx))
    assert outcome.verdict is Verdict.FAILED
    assert "completion_signal" not in outcome.data
    _assert_methods(ctx.http.calls, ["GET", "POST", "GET"])


def test_initial_status_network_failure_never_posts(tree):
    ctx = _ctx([TransientError("status unavailable")])
    outcome = asyncio.run(tree.run_chop_tree(ctx))
    assert outcome.verdict is Verdict.FAILED and outcome.reason == "network_error"
    _assert_methods(ctx.http.calls, ["GET"])


@pytest.mark.parametrize("transport", ["http", "browser"])
@pytest.mark.parametrize("after", [5, 8], ids=["no-progress", "increased-stamina"])
def test_non_decreasing_stamina_stops_without_another_post(tree, transport, after):
    ctx, page = _case([_ok(_state(5)), _chopped(after)], transport=transport)
    outcome = asyncio.run(tree.run_chop_tree(ctx, page))
    assert outcome.verdict is Verdict.FAILED and outcome.reason == "unconfirmed"
    assert outcome.data["remaining_stamina"] == after
    assert outcome.data["consumed"] == 0 and outcome.data["batches"] == 1
    _assert_methods(_calls(ctx, page), ["GET", "POST"])


def test_loop_cap_stops_with_remaining_instead_of_claiming_success(monkeypatch, tree):
    monkeypatch.setattr(tree, "MAX_BATCHES", 3)
    ctx = _ctx([_ok(_state(10, 2)), _chopped(8, 2), _chopped(6, 2), _chopped(4, 2)])

    outcome = asyncio.run(tree.run_chop_tree(ctx))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == "unconfirmed"
    assert outcome.data["batches"] == 3
    assert outcome.data["remaining_stamina"] == 4 and outcome.data["consumed"] == 6
    _assert_methods(ctx.http.calls, ["GET", "POST", "POST", "POST"])


@pytest.mark.parametrize("expire_after_first", [False, True])
def test_expired_context_prevents_next_chop_and_reports_remaining(tree, expire_after_first):
    expiration = Mock(side_effect=[False, True] if expire_after_first else [True])
    responses = [_ok(_state(5, 2))] + ([_chopped(3, 2)] if expire_after_first else [])
    ctx = _ctx(responses, expired=expiration)

    outcome = asyncio.run(tree.run_chop_tree(ctx))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == "unconfirmed"
    assert outcome.data["remaining_stamina"] == (3 if expire_after_first else 5)
    assert outcome.data["batches"] == int(expire_after_first)
    _assert_methods(ctx.http.calls, ["GET", "POST"] if expire_after_first else ["GET"])


def test_device_id_is_persistent_per_account_store_and_not_shared(monkeypatch, tree):
    generate = Mock(side_effect=["account-a-device", "account-b-device"])
    monkeypatch.setattr(tree, "uuid4", generate)
    account_a = FakeStore()
    account_b = FakeStore()
    contexts = [
        _ctx([_ok(_state(0))], store=account_a),
        _ctx([_ok(_state(0))], store=account_a),
        _ctx([_ok(_state(0))], store=account_b),
    ]
    devices = []
    for ctx in contexts:
        assert asyncio.run(tree.run_chop_tree(ctx)).verdict is Verdict.ALREADY_DONE
        devices.append(parse_qs(urlsplit(ctx.http.calls[0][1]).query)["device_id"][0])

    assert devices == ["account-a-device", "account-a-device", "account-b-device"]
    assert generate.call_count == 2
    assert len(account_a.writes) == len(account_b.writes) == 1
    assert account_a.reads[0] == account_b.reads[0]
    assert "https://compatible.test" in account_a.reads[0]


def test_same_store_keeps_distinct_devices_per_origin_but_reuses_paths(monkeypatch, tree):
    generate = Mock(side_effect=["origin-one-device", "origin-two-device"])
    monkeypatch.setattr(tree, "uuid4", generate)
    store = FakeStore()
    devices = []
    for base_url in ["https://one.test/start", "https://two.test", "https://one.test/other"]:
        ctx = _ctx([_ok(_state(0))], store=store, base_url=base_url)
        asyncio.run(tree.run_chop_tree(ctx))
        devices.append(parse_qs(urlsplit(ctx.http.calls[0][1]).query)["device_id"][0])
    assert devices == ["origin-one-device", "origin-two-device", "origin-one-device"]
    assert len(store.writes) == 2 and generate.call_count == 2


@pytest.mark.parametrize("local_device", ["account-saved-device", ""])
def test_browser_reuses_matching_or_empty_local_storage_with_account_device(tree, local_device):
    key = "chop_tree.device_id:https://compatible.test"
    store = FakeStore({key: "account-saved-device"})
    ctx = _ctx(store=store)
    page = FakePage(
        "https://compatible.test/lottery", [_ok(_state(0)), _ok(_state(0))],
        {tree.DEVICE_KEY: local_device} if local_device else {},
    )
    expected = local_device or "account-saved-device"

    for _ in range(2):
        assert asyncio.run(tree.run_chop_tree(ctx, page)).verdict is Verdict.ALREADY_DONE
    assert page.local_storage[tree.DEVICE_KEY] == store.values[key] == expected
    assert store.writes == []
    assert all(parse_qs(urlsplit(path).query)["device_id"] == [expected] for _, path, _ in page.calls)
    http_ctx = _ctx([_ok(_state(0))], store=store)
    assert asyncio.run(tree.run_chop_tree(http_ctx)).verdict is Verdict.ALREADY_DONE
    assert parse_qs(urlsplit(http_ctx.http.calls[0][1]).query)["device_id"] == [expected]
    assert ctx.http.calls == []


def test_existing_frontend_device_is_adopted_only_when_account_has_no_saved_device(tree):
    ctx = _ctx()
    page = FakePage(
        "https://compatible.test/lottery", [_ok(_state(0))],
        {tree.DEVICE_KEY: "frontend-device"},
    )

    assert asyncio.run(tree.run_chop_tree(ctx, page)).verdict is Verdict.ALREADY_DONE
    assert list(ctx.store.values.values()) == ["frontend-device"]
    assert page.local_storage[tree.DEVICE_KEY] == "frontend-device"
    assert parse_qs(urlsplit(page.calls[0][1]).query)["device_id"] == ["frontend-device"]


def test_conflicting_frontend_and_account_device_ids_fail_without_switching_device(tree):
    key = "chop_tree.device_id:https://compatible.test"
    store = FakeStore({key: "account-device"})
    ctx = _ctx(store=store)
    page = FakePage("https://compatible.test/lottery", local_storage={tree.DEVICE_KEY: "other-device"})

    outcome = asyncio.run(tree.run_chop_tree(ctx, page))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == "need_config"
    assert page.calls == ctx.http.calls == []
    assert page.local_storage[tree.DEVICE_KEY] == "other-device"
    assert store.values[key] == "account-device" and store.writes == []


def test_fresh_browser_device_is_saved_and_reused(tree):
    ctx = _ctx()
    page = FakePage("https://compatible.test/lottery", [_ok(_state(0)), _ok(_state(0))])
    asyncio.run(tree.run_chop_tree(ctx, page))
    device = page.local_storage[tree.DEVICE_KEY]
    asyncio.run(tree.run_chop_tree(ctx, page))
    assert device and page.local_storage[tree.DEVICE_KEY] == device
    assert list(ctx.store.values.values()) == [device]
    assert len(ctx.store.writes) == 1


@pytest.mark.parametrize("foreign_url", [
    "https://different.test/lottery", "https://compatible.test.attacker.test/lottery",
    "http://compatible.test/lottery", "https://compatible.test:8443/lottery", "about:blank",
])
def test_browser_device_never_reads_local_storage_on_another_origin(tree, foreign_url):
    ctx = _ctx()
    page = FakePage(foreign_url)

    outcome = asyncio.run(tree.run_chop_tree(ctx, page))

    assert outcome.verdict is Verdict.FAILED
    page.evaluate.assert_not_awaited()
    assert ctx.http.calls == [] and ctx.store.writes == []


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_client_checks_origin_again_before_every_browser_request(tree, method):
    ctx = _ctx()
    page = FakePage("https://compatible.test/lottery")
    client = tree._GameClient(ctx, "stable-device", page)
    page.url = "https://foreign.test/login"

    with pytest.raises(LoginRequired):
        asyncio.run(client.state() if method == "GET" else client.chop(1))
    page.evaluate.assert_not_awaited()
    assert ctx.http.calls == []


@pytest.mark.parametrize("transport", ["http", "browser"])
def test_device_persistence_failure_stops_before_game_requests(tree, transport):
    ctx, page = _case(transport=transport, store=FakeStore(writable=False))
    outcome = asyncio.run(tree.run_chop_tree(ctx, page))
    assert outcome.verdict is Verdict.FAILED and outcome.reason == "need_config"
    assert _calls(ctx, page) == []


@pytest.mark.parametrize("invalid", [None, "", "   ", "x" * 201, 42])
def test_invalid_browser_device_id_stops_before_game_requests(tree, invalid):
    ctx = _ctx()
    page = SimpleNamespace(url="https://compatible.test/lottery", evaluate=AsyncMock(return_value=invalid))
    outcome = asyncio.run(tree.run_chop_tree(ctx, page))
    assert outcome.verdict is Verdict.FAILED and outcome.reason == "need_config"
    page.evaluate.assert_awaited_once()
    assert ctx.http.calls == [] and ctx.store.writes == []


@pytest.mark.parametrize("response,reason", [
    ({"status": 401}, "need_login"),
    ({"status": 403, "payload": _state(0)}, "unconfirmed"),
    ({"status": 500, "payload": _state(0)}, "unconfirmed"),
    ({}, "unconfirmed"),
    (None, "unconfirmed"),
    ({"status": 200, "payload": "not-json"}, "unconfirmed"),
])
def test_browser_client_rejects_http_and_payload_errors(tree, response, reason):
    ctx = _ctx()
    page = SimpleNamespace(url="https://compatible.test/lottery", evaluate=AsyncMock(return_value=response))
    client = tree._GameClient(ctx, "test-device", page)
    with pytest.raises(TaskError) as exc_info:
        asyncio.run(client.state())
    assert exc_info.value.reason == reason
    page.evaluate.assert_awaited_once()
    assert ctx.http.calls == []


def test_device_id_is_query_encoded_not_interpolated(tree):
    ctx = _ctx([_ok(_state(0))])
    device = "stored id + / ? & #"
    client = tree._GameClient(ctx, device)
    assert asyncio.run(client.state())["chop"]["stamina"]["remain"] == 0
    assert parse_qs(urlsplit(ctx.http.calls[0][1]).query) == {"device_id": [device]}


@pytest.mark.parametrize("has_browser", [False, True])
@pytest.mark.parametrize("initial", [0, 3])
def test_wrapper_with_saved_device_prefers_http_without_checkin(monkeypatch, template, has_browser, initial):
    responses = [_ok(_state(initial))]
    if initial:
        responses += [_chopped(0), _ok(_state(0))]
    store = FakeStore({"chop_tree.device_id:https://compatible.test": "persistent-device"})
    ctx = _ctx(responses, store=store, task_id="chop_tree")
    ctx.browser_service = object() if has_browser else None
    ctx.browser = SimpleNamespace(lease=Mock(side_effect=AssertionError("已有设备的 HTTP 完成不启动浏览器")))
    checkin_calls = _forbid_checkin(monkeypatch, template.flow)

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is (Verdict.SUCCESS if initial else Verdict.ALREADY_DONE)
    assert outcome.data["remaining_stamina"] == 0
    assert "checkin" not in outcome.data and "chop_tree" not in outcome.data
    _assert_methods(ctx.http.calls, ["GET", "POST", "GET"] if initial else ["GET"])
    assert parse_qs(urlsplit(ctx.http.calls[0][1]).query)["device_id"] == ["persistent-device"]
    assert store.writes == []
    ctx.browser.lease.assert_not_called()
    for call in checkin_calls:
        call.assert_not_awaited()


def test_wrapper_without_browser_can_create_and_persist_an_http_device(monkeypatch, template):
    ctx = _ctx([_ok(_state(0))], task_id="chop_tree")
    ctx.browser = SimpleNamespace(lease=Mock(side_effect=AssertionError("无浏览器服务不能租用页面")))
    checkin_calls = _forbid_checkin(monkeypatch, template.flow)

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is Verdict.ALREADY_DONE
    assert len(ctx.store.writes) == 1
    device = ctx.store.writes[0][1]
    assert device and parse_qs(urlsplit(ctx.http.calls[0][1]).query)["device_id"] == [device]
    _assert_methods(ctx.http.calls, ["GET"])
    ctx.browser.lease.assert_not_called()
    for call in checkin_calls:
        call.assert_not_awaited()


@pytest.mark.parametrize("local_device", ["frontend-device", ""])
@pytest.mark.parametrize("base_url", ["https://independent-tree.test", "https://compatible.test:8443/app"])
def test_wrapper_without_saved_device_opens_lingtai_first_and_preserves_page_state(
    monkeypatch, template, local_device, base_url,
):
    ctx = _ctx(task_id="chop_tree", base_url=base_url, args={"start_path": "/check-in", "chop_tree": False})
    original_storage = {"auth_token": "test-access", "refresh_token": "test-refresh", "theme": "dark"}
    if local_device:
        original_storage[template.tree.DEVICE_KEY] = local_device
    page = FakePage("about:blank", [_ok(_state(3)), _chopped(0), _ok(_state(0))], original_storage)
    harness = _wire_tree_browser(monkeypatch, template.tree, ctx, page)

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is Verdict.SUCCESS
    assert ctx.http.calls == [], "无已存设备时不能先随机创建 ID 发 HTTP 绑定"
    assert all(page.local_storage[key] == value for key, value in original_storage.items())
    assert len(ctx.store.writes) == 1
    device = page.local_storage[template.tree.DEVICE_KEY]
    assert device == ctx.store.writes[0][1]
    if local_device:
        assert device == local_device
    assert all(parse_qs(urlsplit(path).query)["device_id"] == [device]
               for method, path, _ in page.calls if method == "GET")
    _assert_methods(page.calls, ["GET", "POST", "GET"])
    _assert_tree_browser_only(ctx, harness)
    harness.navigate.assert_awaited_once()
    harness.login.assert_not_awaited()
    harness.lease.mark_authenticated.assert_called_once()
    harness.preflight.assert_called_once_with(
        template.flow.session_stash_key(template.SPEC.login_reset_sentinel), preserve_refresh=True,
    )
    harness.init.assert_awaited_once()
    init_script = harness.init.await_args.args[1]
    assert "'refresh_token'" not in init_script
    assert "localStorage.clear(" not in init_script
    assert template.tree.DEVICE_KEY not in init_script


@pytest.mark.parametrize("reason", ["need_login", "need_verification", "network_error"])
def test_wrapper_only_initial_read_failure_can_restore_browser_auth(monkeypatch, template, reason):
    store = FakeStore({"chop_tree.device_id:https://compatible.test": "persistent-device"})
    ctx = _ctx([TaskError("首次状态读取失败", reason=reason)], store=store, task_id="chop_tree")
    page = FakePage(
        "about:blank", [_ok(_state(0))], {template.tree.DEVICE_KEY: "persistent-device"},
    )
    harness = _wire_tree_browser(monkeypatch, template.tree, ctx, page)

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is Verdict.ALREADY_DONE
    _assert_methods(ctx.http.calls, ["GET"])
    _assert_methods(page.calls, ["GET"])
    _assert_tree_browser_only(ctx, harness)
    harness.login.assert_not_awaited()
    harness.lease.mark_authenticated.assert_called_once()
    assert store.writes == []
    assert harness.init.await_count == 2
    seed_script = harness.init.await_args_list[1].args[1]
    assert "persistent-device" in seed_script and template.tree.DEVICE_KEY in seed_script
    assert "location.origin === origin" in seed_script
    assert "!localStorage.getItem(key)" in seed_script, "只能为页面空设备槽续入账号 ID，不能覆盖现有设备"


@pytest.mark.parametrize("raw", [
    None,
    {"code": 403, "data": _state(0)},
    _ok(_state(0, enabled=False)),
    _ok(_state(0, bind_blocked=True)),
    _ok(_state("0")),
])
def test_wrapper_does_not_open_browser_for_invalid_or_refused_initial_state(monkeypatch, template, raw):
    store = FakeStore({"chop_tree.device_id:https://compatible.test": "persistent-device"})
    ctx = _ctx([raw], store=store, task_id="chop_tree")
    ctx.browser_service = object()
    ctx.browser = SimpleNamespace(lease=Mock(side_effect=AssertionError("业务/状态拒绝不能靠换浏览器绕过")))
    checkin_calls = _forbid_checkin(monkeypatch, template.flow)

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is Verdict.FAILED
    _assert_methods(ctx.http.calls, ["GET"])
    ctx.browser.lease.assert_not_called()
    for call in checkin_calls:
        call.assert_not_awaited()


@pytest.mark.parametrize("reason", ["need_login", "need_verification", "network_error"])
@pytest.mark.parametrize("remaining", [0, 4])
def test_wrapper_never_falls_back_to_browser_after_a_post(monkeypatch, template, reason, remaining):
    monkeypatch.setattr(template.tree, "RETRY_DELAYS", ())
    store = FakeStore({"chop_tree.device_id:https://compatible.test": "persistent-device"})
    ctx = _ctx(
        [_ok(_state(4)), TaskError("POST 结果未确认", reason=reason), _ok(_state(remaining))],
        store=store, task_id="chop_tree",
    )
    ctx.browser_service = object()
    ctx.browser = SimpleNamespace(lease=Mock(side_effect=AssertionError("POST 后不切换传输路径重复砍树")))
    checkin_calls = _forbid_checkin(monkeypatch, template.flow)

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is (Verdict.SUCCESS if remaining == 0 else Verdict.FAILED)
    assert outcome.data["initial_stamina"] == 4
    assert outcome.data["remaining_stamina"] == remaining
    assert outcome.data["request_error"]["reason"] == reason
    _assert_methods(ctx.http.calls, ["GET", "POST", "GET"])
    assert ctx.http.calls[1][2]["retry_non_idempotent"] is False
    ctx.browser.lease.assert_not_called()
    for call in checkin_calls:
        call.assert_not_awaited()


def test_wrapper_preserves_conflicting_browser_device_after_http_auth_failure(monkeypatch, template):
    store = FakeStore({"chop_tree.device_id:https://compatible.test": "account-device"})
    ctx = _ctx([LoginRequired("HTTP 登录已过期")], store=store, task_id="chop_tree")
    page = FakePage("about:blank", local_storage={template.tree.DEVICE_KEY: "other-device"})
    harness = _wire_tree_browser(monkeypatch, template.tree, ctx, page)

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == "need_config"
    _assert_methods(ctx.http.calls, ["GET"])
    assert page.calls == [] and store.writes == []
    assert page.local_storage[template.tree.DEVICE_KEY] == "other-device"
    assert list(store.values.values()) == ["account-device"]
    _assert_tree_browser_only(ctx, harness)


def test_wrapper_password_login_only_restores_auth_then_runs_tree_on_same_page(monkeypatch, template):
    ctx = _ctx(task_id="chop_tree", args={"email": "test@example.test", "password": "test-password"})
    page = FakePage("about:blank", [_ok(_state(2)), _chopped(0), _ok(_state(0))])
    harness = _wire_tree_browser(monkeypatch, template.tree, ctx, page, authenticated=(False, True))

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is Verdict.SUCCESS
    assert ctx.http.calls == []
    _assert_methods(page.calls, ["GET", "POST", "GET"])
    _assert_tree_browser_only(ctx, harness)
    assert harness.navigate.await_count == 2
    assert harness.authenticated.await_count == 2
    harness.login.assert_awaited_once()
    login_args = harness.login.await_args
    assert login_args.args[:4] == (page, harness.lease.context, harness.helpers, template.SPEC)
    assert login_args.kwargs["resolved_url"] == "https://compatible.test/lingtai"
    assert login_args.kwargs["origin"] == "https://compatible.test"
    harness.lease.mark_authenticated.assert_called_once()


@pytest.mark.parametrize("reason", ["need_config", "need_login", "need_verification"])
def test_wrapper_login_failure_returns_its_own_failure_without_tree_or_checkin(monkeypatch, template, reason):
    ctx = _ctx(task_id="chop_tree")
    page = FakePage("about:blank")
    harness = _wire_tree_browser(monkeypatch, template.tree, ctx, page, authenticated=(False,))
    login_failure = failed("独立登录失败", reason=reason, data={"login_stage": "password"})
    login_failure = login_failure.with_evidence(Evidence(responses=("login-failed",)))
    harness.login.return_value = login_failure

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == reason
    assert outcome.data == {"source": "lingtai", "login_stage": "password"}
    assert outcome.evidence == login_failure.evidence
    assert page.calls == ctx.http.calls == [] and ctx.store.writes == []
    page.evaluate.assert_not_awaited()
    harness.lease.mark_authenticated.assert_not_called()
    _assert_tree_browser_only(ctx, harness)


def test_wrapper_requires_authentication_confirmation_after_login(monkeypatch, template):
    ctx = _ctx(task_id="chop_tree")
    page = FakePage("about:blank")
    harness = _wire_tree_browser(monkeypatch, template.tree, ctx, page, authenticated=(False, False))

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == "need_login"
    assert outcome.data["source"] == "lingtai"
    assert page.calls == ctx.http.calls == [] and ctx.store.writes == []
    page.evaluate.assert_not_awaited()
    assert harness.authenticated.await_count == 2 and harness.navigate.await_count == 2
    harness.lease.mark_authenticated.assert_not_called()
    _assert_tree_browser_only(ctx, harness)


def test_wrapper_navigation_failure_is_a_tree_failure_not_a_checkin_fallback(monkeypatch, template):
    ctx = _ctx(task_id="chop_tree")
    page = FakePage("about:blank")
    harness = _wire_tree_browser(monkeypatch, template.tree, ctx, page)
    harness.navigate.side_effect = TransientError("灵台导航超时")

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == "network_error"
    assert outcome.data["source"] == "lingtai"
    assert page.calls == ctx.http.calls == []
    harness.authenticated.assert_not_awaited()
    harness.login.assert_not_awaited()
    _assert_tree_browser_only(ctx, harness)


@pytest.mark.parametrize("stage", ["initial-navigation", "after-login"])
@pytest.mark.parametrize("foreign_url", [
    "https://other.test/lingtai", "https://compatible.test.attacker.test/lingtai",
    "http://compatible.test/lingtai",
])
def test_wrapper_stops_before_reading_auth_when_navigation_leaves_origin(
    monkeypatch, template, stage, foreign_url,
):
    ctx = _ctx(task_id="chop_tree")
    page = FakePage("about:blank")
    harness = _wire_tree_browser(monkeypatch, template.tree, ctx, page, authenticated=(False,))
    visits = []

    async def navigate(actual_page, _helpers, path, _opts):
        visits.append(path)
        actual_page.url = (
            "https://compatible.test/lingtai"
            if stage == "after-login" and len(visits) == 1 else foreign_url
        )

    harness.navigate.side_effect = navigate
    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == "need_login"
    assert page.calls == ctx.http.calls == [] and ctx.store.writes == []
    page.evaluate.assert_not_awaited()
    harness.lease.mark_authenticated.assert_not_called()
    _assert_tree_browser_only(ctx, harness)
    if stage == "after-login":
        assert visits == ["/lingtai", "/lingtai"]
        harness.authenticated.assert_awaited_once_with(page, "https://compatible.test")
        harness.login.assert_awaited_once()
    else:
        assert visits == ["/lingtai"]
        harness.authenticated.assert_not_awaited()
        harness.login.assert_not_awaited()


@pytest.mark.parametrize("error", [LoginRequired("登录过期"), TransientError("状态网络失败")])
def test_wrapper_without_browser_returns_initial_http_error_without_checkin(monkeypatch, template, error):
    ctx = _ctx([error], task_id="chop_tree")
    ctx.browser = SimpleNamespace(lease=Mock(side_effect=AssertionError("无浏览器时不能回退")))
    checkin_calls = _forbid_checkin(monkeypatch, template.flow)

    outcome = asyncio.run(template.run(ctx))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == error.reason
    assert "initial_stamina" not in outcome.data
    _assert_methods(ctx.http.calls, ["GET"])
    ctx.browser.lease.assert_not_called()
    for call in checkin_calls:
        call.assert_not_awaited()


def _no_sleep(monkeypatch, tree):
    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(tree.asyncio, "sleep", fake_sleep)
    return sleeps


def test_server_500_is_retried_after_status_confirms_remaining(monkeypatch, tree):
    sleeps = _no_sleep(monkeypatch, tree)
    ctx = _ctx([
        _ok(_state(6)),
        TransientError("HTTP 500", status=500),
        _ok(_state(6)),
        _ok({"status": _state(0)}),
        _ok(_state(0)),
    ])

    outcome = asyncio.run(tree.run_chop_tree(ctx))

    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["retries"] == 1 and outcome.data["consumed"] == 6
    assert sleeps == [tree.RETRY_DELAYS[0]]
    _assert_methods(ctx.http.calls, ["GET", "POST", "GET", "POST", "GET"])
    keys = [call[2]["json_body"]["batch_key"] for call in ctx.http.calls if call[0] == "POST"]
    assert len(set(keys)) == 2, "重试必须换新 batch_key"


def test_retry_uses_confirmed_remaining_not_stale_value(monkeypatch, tree):
    _no_sleep(monkeypatch, tree)
    ctx = _ctx([
        _ok(_state(6)),
        TransientError("timeout"),
        _ok(_state(2)),
        _ok({"status": _state(0)}),
        _ok(_state(0)),
    ])

    outcome = asyncio.run(tree.run_chop_tree(ctx))

    assert outcome.verdict is Verdict.SUCCESS
    posts = [call[2]["json_body"]["count"] for call in ctx.http.calls if call[0] == "POST"]
    assert posts[1] == 2


def test_retries_are_bounded(monkeypatch, tree):
    sleeps = _no_sleep(monkeypatch, tree)
    responses = [_ok(_state(4))]
    for _ in range(len(tree.RETRY_DELAYS) + 1):
        responses += [TransientError("HTTP 502", status=502), _ok(_state(4))]
    ctx = _ctx(responses)

    outcome = asyncio.run(tree.run_chop_tree(ctx))

    assert outcome.verdict is Verdict.FAILED and outcome.reason == "network_error"
    assert sleeps == list(tree.RETRY_DELAYS)
    assert [c[0] for c in ctx.http.calls].count("POST") == len(tree.RETRY_DELAYS) + 1


@pytest.mark.parametrize("error", [
    TaskError("拒绝", reason="unconfirmed"),
    LoginRequired("登录失效"),
])
def test_non_transient_errors_are_not_retried(monkeypatch, tree, error):
    sleeps = _no_sleep(monkeypatch, tree)
    ctx = _ctx([_ok(_state(4)), error, _ok(_state(4))])

    outcome = asyncio.run(tree.run_chop_tree(ctx))

    assert outcome.verdict is not Verdict.SUCCESS
    assert sleeps == []
    assert [c[0] for c in ctx.http.calls].count("POST") == 1


def test_no_retry_when_status_readback_fails(monkeypatch, tree):
    sleeps = _no_sleep(monkeypatch, tree)
    ctx = _ctx([_ok(_state(4)), TransientError("HTTP 500", status=500), TransientError("HTTP 500", status=500)])

    outcome = asyncio.run(tree.run_chop_tree(ctx))

    assert outcome.verdict is Verdict.FAILED
    assert sleeps == []
