"""腾讯 SDK 的离线回归：真实 BrowserLease 生命周期 + Node 执行实际 JS，不访问任何站点。"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
from types import SimpleNamespace
from typing import Any

import pytest

from browser.service import BrowserService
from solvers import tencent_widget as widget


@dataclass
class _Scenario:
    state: str = "done"
    ret: Any = 0
    ticket: Any = "offline-ticket-SENSITIVE"
    randstr: Any = "offline-randstr-SENSITIVE"
    error: dict[str, Exception] = field(default_factory=dict)
    stalls: set[str] = field(default_factory=set)
    entered: dict[str, asyncio.Event] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)
    pages: list[Any] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    captures: list[str] = field(default_factory=list)
    navigation_url: str | None = None
    info: Any = None
    wrong_instance: bool = False
    screenshot_state: str = ""
    delayed_success: bool = False
    legacy_binding: bool = False
    callback_source: str = "main"

    async def operation(self, name):
        self.calls.append(name)
        if name in self.entered:
            self.entered[name].set()
        if name in self.error:
            raise self.error[name]
        if name in self.stalls:
            await asyncio.Future()

    async def capture(self, name, *, target=None, page=None):
        self.captures.append(name)
        self.screenshot_state = page.state
        assert page.ticket == page.randstr == ""  # 先失效并清空回调，再采集失败截图。
        await self.operation("screenshot")
        return "offline-evidence.png"


class _MemoryPage:
    def __init__(self, scenario):
        self.case = scenario
        self.url = "about:blank"
        self.main_frame = SimpleNamespace(url=self.url)
        self.closed = False
        self.state = "missing"
        self.key = self.instance = self.app_id = self.script = ""
        self.ticket = self.randstr = ""
        self.routes = {}
        self.navigations = []
        self.fulfilled = []
        self.callback_reads = 0
        self.stopped = False
        self.disposed = False
        self.binding_name = ""
        self.callback = None
        self.binding_closed = False
        self.delayed = None

    async def route(self, target, handler):
        await self.case.operation("route")
        self.routes[target] = handler

    async def goto(self, target, **kwargs):
        await self.case.operation("navigate")
        self.navigations.append((target, kwargs))
        assert target in self.routes  # 不能回退到真实首页或任意外站。

        async def fulfill(**response):
            self.fulfilled.append(response)

        await self.routes[target](SimpleNamespace(fulfill=fulfill))
        self.url = self.main_frame.url = self.case.navigation_url or target

    async def expose_binding(self, name, callback):
        await self.case.operation("binding")
        self.binding_name, self.callback = name, callback

        async def close():
            await self.case.operation("binding_close")
            self.binding_closed = True

        return None if self.case.legacy_binding else SimpleNamespace(close=close)

    def deliver(self, state):
        self.callback_reads += 1
        payload = self.case.info if self.case.info is not None else {
            "state": state, "instance": "old-instance" if self.case.wrong_instance else self.instance,
            "ret": self.case.ret, "ticket": self.ticket, "randstr": self.randstr,
        }
        source = {"page": self, "frame": self.main_frame}
        if self.case.callback_source == "other_page":
            source["page"] = object()
        if self.case.callback_source == "iframe":
            source["frame"] = SimpleNamespace(url=self.url)
        return self.callback(source, payload)

    async def add_script_tag(self, *, content):
        if "bridge.dispose()" in content:
            await self.case.operation("dispose")
            self.disposed = True
            self.state, self.ticket, self.randstr = "closed", "", ""
            return None
        if "bridge.stop()" in content:
            await self.case.operation("stop")
            self.stopped = True
            self.state, self.ticket, self.randstr = "closed", "", ""
            return None
        await self.case.operation("script")
        values = re.search(r"const KEY = (.*?), ID = (.*?), APP_ID = (.*?);", content)
        assert values and self.callback is not None
        self.key, self.instance, self.app_id = (json.loads(value) for value in values.groups())
        self.script = content
        self.state, self.ticket, self.randstr = self.case.state, self.case.ticket, self.case.randstr
        self.deliver(self.state)
        if self.case.delayed_success:
            async def later():
                await asyncio.sleep(0.015)
                self.state = "done"
                self.deliver("done")
            self.delayed = asyncio.create_task(later())

    async def evaluate(self, script):
        # 严格模拟隔离世界：不允许用 evaluate 读取主世界的 window/闭包。
        assert script == widget._LOCATION_JS
        await self.case.operation("origin")
        return self.url

    async def close(self):
        await self.case.operation("close")
        self.closed = True
        self.ticket = self.randstr = ""
        if self.delayed is not None and not self.delayed.done():
            self.delayed.cancel()


class _MemoryContext:
    def __init__(self, scenario):
        self.case = scenario

    async def new_page(self):
        await self.case.operation("new_page")
        page = _MemoryPage(self.case)
        self.case.pages.append(page)
        return page


class _MemoryService(BrowserService):
    """复用真正的 lease()/BrowserLease；仅把浏览器驱动换成有状态的内存页面。"""

    def __init__(self, scenario):
        super().__init__(
            base_url="https://site.invalid", proxy="http://offline-proxy.invalid:8080", headless=False,
            evidence=scenario,
        )
        self.case = scenario
        self._context = _MemoryContext(scenario)
        self._verified_generation = self._generation
        self._published_credentials = {"access_token": "existing-offline-credential"}
        self.reasons = []

    async def _ensure_started(self, *, reason):
        await self.case.operation("launch")
        self._started = True

    def lease(self, *, reason="", state_text=""):
        self.reasons.append((reason, state_text))
        return super().lease(reason=reason, state_text=state_text)


@pytest.fixture
def case(monkeypatch):
    value = _Scenario()
    value.service = _MemoryService(value)
    value.ctx = SimpleNamespace(browser_service=value.service, log=value.logs.append)
    monkeypatch.setattr(widget, "DEFAULT_BUDGET_SECONDS", 0.5)
    monkeypatch.setattr(widget, "RPC_TIMEOUT_SECONDS", 0.06)
    monkeypatch.setattr(widget, "PAGE_CREATE_TIMEOUT_SECONDS", 0.06)
    monkeypatch.setattr(widget, "NAVIGATION_TIMEOUT_SECONDS", 0.06)
    monkeypatch.setattr(widget, "SDK_LOAD_TIMEOUT_SECONDS", 0.08)
    monkeypatch.setattr(widget, "POLL_INTERVAL_SECONDS", 0.003)
    monkeypatch.setattr(widget, "SCREENSHOT_TIMEOUT_SECONDS", 0.02)
    monkeypatch.setattr(widget, "CLEANUP_RESERVE_SECONDS", 0.15)
    return value


def _run(case, **kwargs):
    async def scenario():
        return await asyncio.wait_for(widget.TencentCaptchaSolver().solve(
            case.ctx, app_id=kwargs.pop("app_id", "1234567890"), **kwargs,
        ), timeout=3)

    return asyncio.run(scenario())


def test_success_returns_only_ephemeral_callback_pair_and_preserves_auth(case):
    before = (case.service._generation, case.service._verified_generation, dict(case.service._published_credentials))
    result = _run(case)
    assert result.ok and result.value == "" and result.attempts == 1
    assert result.data == {"ticket": case.ticket, "randstr": case.randstr}
    assert result.evidence.screenshots == ()
    assert case.service.reasons == [("tencent", "")]
    assert before == (case.service._generation, case.service._verified_generation, case.service._published_credentials)
    assert case.service.headless is False and case.service.proxy == "http://offline-proxy.invalid:8080"
    page, = case.pages
    assert page.closed and page.stopped and page.disposed and page.binding_closed
    assert page.callback.__self__.info == {"state": "closed"} and not page.callback.__self__.accepting
    assert page.app_id == "1234567890" and "https://turing.captcha.qcloud.com/TJCaptcha.js" in page.script
    assert list(page.routes) == ["https://site.invalid" + widget.HOST_PATH]
    assert page.navigations[0][0] == "https://site.invalid" + widget.HOST_PATH
    assert page.fulfilled[0]["status"] == 200
    assert case.captures == []
    assert case.ticket not in str(case.logs) and case.randstr not in str(case.logs)
    assert case.service.started  # 不能关闭供后续步骤复用的共享浏览器。


@pytest.mark.parametrize("app_id", ["", " 123", "12 3", "x123", "1\n", "0" * 33, 123, None, True])
def test_invalid_app_id_never_starts_browser(case, app_id):
    assert _run(case, app_id=app_id).reason == "invalid_app_id"
    assert case.service.reasons == [] and case.calls == []


@pytest.mark.parametrize("budget,reason", [(0, "timeout"), (-1, "timeout"),
    (float("inf"), "invalid"), (float("nan"), "invalid"), ("bad", "invalid"), (True, "invalid")])
def test_invalid_or_exhausted_budget_never_starts_browser(case, budget, reason):
    assert _run(case, budget=budget).reason == reason
    assert case.service.reasons == []


def test_absent_browser_is_unavailable_and_does_not_read_credentials(case):
    case.ctx.browser_service = None
    case.ctx.account = SimpleNamespace(credentials=object())
    assert _run(case).reason == "unavailable"
    assert case.calls == []


@pytest.mark.parametrize("base,expected", [
    ("https://site.invalid", "https://evil.invalid"),
    ("https://site.invalid", "https://site.invalid.evil.invalid"),
    ("https://site.invalid", "http://site.invalid"),
    ("https://site.invalid", "https://site.invalid:444"),
    ("https://user:secret@site.invalid", ""),
    ("file:///tmp/widget", ""),
    ("javascript:alert(1)", ""),
    ("https://site.invalid:bad", ""),
    ("https://site.invalid:0", ""),
    ("https://site.invalid\n.evil.invalid", ""),
])
def test_invalid_or_cross_origin_source_never_starts_browser(case, base, expected):
    case.service.base_url = base
    assert _run(case, origin=expected).reason == "invalid_origin"
    assert case.service.reasons == [] and not case.pages


def test_default_port_and_same_origin_path_are_allowed_but_fixed_host_is_used(case):
    case.service.base_url = "https://site.invalid:443/subdirectory/"
    assert _run(case, origin="https://site.invalid/login?from=checkin").ok
    assert case.pages[0].navigations[0][0] == "https://site.invalid" + widget.HOST_PATH


@pytest.mark.parametrize("url", ["https://evil.invalid/", "https://site.invalid/", "about:blank",
    "https://site.invalid" + widget.HOST_PATH + "?redirected=1"])
def test_navigation_drift_never_receives_sdk_and_page_is_closed(case, url):
    case.navigation_url = url
    assert _run(case).reason == "invalid_origin"
    assert "script" not in case.calls and case.pages[0].closed
    assert not case.captures


def test_changed_lease_origin_is_rejected_before_creating_page(case):
    real_lease = case.service.lease

    def lease(**kwargs):
        manager = real_lease(**kwargs)
        manager._service = SimpleNamespace(_ensure_started=case.service._ensure_started, base_url="https://other.invalid")
        return manager

    case.service.lease = lease
    assert _run(case).reason == "invalid_origin"
    assert not case.pages


@pytest.mark.parametrize("remaining", [0.0, 19.0, 20.0])
def test_context_remaining_budget_keeps_registry_teardown_reserve(case, remaining):
    case.ctx.remaining_seconds = lambda: remaining
    assert _run(case, budget=90).reason == "timeout"
    assert case.service.reasons == []


def test_registry_reserve_and_context_remaining_cap_default_and_explicit_budget(case, monkeypatch):
    monkeypatch.setattr(widget.registry, "TEARDOWN_RESERVE_SECONDS", 0.1)
    case.ctx.remaining_seconds = lambda: 0.32
    case.stalls.add("launch")
    started = time.monotonic()
    result = _run(case, budget=90)
    assert result.reason == "timeout" and result.data["stage"] == "启动浏览器"
    assert time.monotonic() - started < 0.65


@pytest.mark.parametrize("state,reason", list(widget._STATE_FAILURES.items()))
def test_explicit_sdk_states_never_claim_success_or_expose_callback_pair(case, state, reason):
    case.state = state
    result = _run(case)
    assert not result.ok and result.reason == reason[0]
    assert not result.data and result.value == ""
    assert case.pages[0].closed
    public = str(case.logs) + result.message + str(case.captures) + str(result.evidence)
    assert case.ticket not in public and case.randstr not in public
    assert len(case.captures) <= 1
    if result.reason != "cancelled":
        assert case.screenshot_state == "closed"


@pytest.mark.parametrize("field,value", [
    ("ticket", ""), ("ticket", " "), ("ticket", None), ("ticket", 1),
    ("ticket", "ticket\nsecret"), ("ticket", "ticket space"), ("ticket", "a" * 8193),
    ("ticket", "trerror_1001_not-a-real-ticket"),
    ("randstr", ""), ("randstr", False), ("randstr", "bad\x00randstr"), ("randstr", "a" * 1025),
    ("ret", 2), ("ret", 1), ("ret", False), ("ret", "0"), ("ret", None),
])
def test_done_without_strict_ret_and_valid_pair_is_not_success(case, field, value):
    setattr(case, field, value)
    result = _run(case)
    expected = "network_error" if field == "ticket" and str(value).startswith("trerror_") else "invalid_result"
    assert not result.ok and result.reason == expected
    assert result.data == {} and case.pages[0].closed


def test_done_from_old_instance_is_not_success(case):
    case.wrong_instance = True
    assert _run(case).reason == "invalid_result"


@pytest.mark.parametrize("info", ["secret-driver-value", ["unexpected"], {"state": "invented"}])
def test_malformed_state_is_rejected_without_echoing_it(case, info):
    case.info = info
    result = _run(case)
    assert result.reason == "invalid_result"
    assert "secret-driver-value" not in result.message + str(case.logs)


def test_pending_cannot_be_reported_as_passed_and_is_not_retried(case):
    case.state = "pending"
    result = _run(case, budget=0.2)
    assert not result.ok and result.reason == "need_human"
    assert case.calls.count("script") == 1 and case.calls.count("navigate") == 1
    assert case.pages[0].callback_reads == 1 and case.pages[0].closed
    assert not any(name in case.calls for name in ("mouse", "drag", "click", "reset"))


def test_sdk_loading_has_its_own_bounded_timeout(case):
    case.state = "sdk_loading"
    result = _run(case)
    assert result.reason == "timeout" and result.data["stage"] == "加载官方 SDK"
    assert case.pages[0].closed


@pytest.mark.parametrize("operation,stage", [
    ("launch", "启动浏览器"), ("new_page", "创建验证页面"), ("route", "设置承载页路由"),
    ("navigate", "打开同源承载页"), ("origin", "确认承载页来源"),
    ("script", "加载官方 SDK"), ("binding", "建立验证码回调"),
])
def test_each_hung_driver_operation_is_bounded_and_lease_pages_are_closed(case, operation, stage):
    case.stalls.add(operation)
    started = time.monotonic()
    result = _run(case, budget=0.3)
    assert result.reason == "timeout" and result.data["stage"] == stage
    assert time.monotonic() - started < 0.85
    assert all(page.closed for page in case.pages)


@pytest.mark.parametrize("operation,reason", [("launch", "unavailable"), ("navigate", "network_error"),
    ("script", "error"), ("binding", "error")])
def test_driver_errors_show_only_class_never_sensitive_error_text(case, operation, reason):
    error_type = ConnectionError if operation == "navigate" else RuntimeError
    case.error[operation] = error_type("raw-driver-ticket=" + case.ticket + "&randstr=" + case.randstr)
    result = _run(case)
    assert not result.ok and result.reason == reason
    text = result.message + str(result.data) + str(case.logs) + str(case.captures)
    assert case.ticket not in text and case.randstr not in text and "raw-driver-ticket" not in text
    assert all(page.closed for page in case.pages)


def test_delayed_callback_succeeds_without_reading_main_world_from_evaluate(case):
    case.state = "pending"
    case.delayed_success = True
    assert _run(case).ok
    assert case.pages[0].callback_reads == 2 and len(case.pages) == 1


@pytest.mark.parametrize("source", ["other_page", "iframe"])
def test_callbacks_from_other_page_or_iframe_are_ignored(case, source):
    case.callback_source = source
    assert _run(case).reason == "timeout"
    assert case.pages[0].closed


def test_legacy_binding_without_disposable_is_cleaned_by_page_close(case):
    case.legacy_binding = True
    assert _run(case).ok
    assert case.pages[0].closed and "binding_close" not in case.calls


def test_no_binding_api_returns_unavailable_and_releases_page(case, monkeypatch):
    monkeypatch.setattr(_MemoryPage, "expose_binding", None)
    assert _run(case).reason == "unavailable"
    assert case.pages[0].closed and not case.pages[0].navigations


def test_receiver_rejects_after_close_deadline_navigation_and_stale_app_id():
    target = "https://site.invalid" + widget.HOST_PATH
    page = SimpleNamespace(url=target, main_frame=SimpleNamespace(url=target))
    source = {"page": page, "frame": page.main_frame}
    payload = {"state": "done", "instance": "one", "ret": 0, "ticket": "fresh", "randstr": "random"}

    def receiver():
        return widget._CallbackState(page, instance="one", target=target, app_id="123", deadline=time.monotonic() + 2)

    closed = receiver()
    closed.close()
    assert not closed.receive(source, payload) and closed.info == {"state": "closed"}
    expired = receiver()
    expired.deadline = time.monotonic() - 1
    assert not expired.receive(source, payload) and "ticket" not in expired.info
    wrong_app = receiver()
    assert not wrong_app.receive(source, {**payload, "appid": "456"})
    assert wrong_app.info == {"state": "appid_mismatch"}
    changed = receiver()
    page.main_frame.url = "https://other.invalid/"
    assert not changed.receive(source, payload) and changed.info == {"state": "source_mismatch"}
    page.main_frame.url = target
    consumed = receiver()
    assert consumed.receive(source, payload)
    assert not consumed.receive(source, {**payload, "ticket": "stale"})
    assert consumed.info["ticket"] == "fresh"


@pytest.mark.parametrize("operation", ["stop", "screenshot", "dispose", "binding_close", "close"])
def test_cleanup_stalls_never_extend_total_budget_or_discard_result(case, operation):
    if operation == "screenshot":
        case.state = "sdk_error"
    case.stalls.add(operation)
    started = time.monotonic()
    result = _run(case, budget=0.3)
    assert result.ok is (operation != "screenshot")
    assert time.monotonic() - started < 0.85
    if operation != "close":
        assert case.pages[0].closed
    assert len(case.captures) <= 1


@pytest.mark.parametrize("operation", ["launch", "new_page", "navigate", "binding", "script"])
def test_external_task_cancellation_propagates_but_always_returns_lease_pages(case, operation):
    async def scenario():
        case.entered[operation] = asyncio.Event()
        case.stalls.add(operation)
        task = asyncio.create_task(widget.TencentCaptchaSolver().solve(case.ctx, app_id="1234567890", budget=0.5))
        await asyncio.wait_for(case.entered[operation].wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert all(page.closed for page in case.pages)
        assert not case.captures
    asyncio.run(scenario())


def test_cancel_while_waiting_for_human_disables_callback_before_cleanup(case):
    case.state = "pending"

    async def scenario():
        pending = asyncio.Event()

        def log(message):
            case.logs.append(message)
            if "仅等待" in message:
                pending.set()

        case.ctx.log = log
        task = asyncio.create_task(widget.TencentCaptchaSolver().solve(case.ctx, app_id="1234567890", budget=1))
        await asyncio.wait_for(pending.wait(), timeout=1)
        page, = case.pages
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert page.closed and page.binding_closed
        receiver = page.callback.__self__
        assert not receiver.accepting and receiver.info == {"state": "closed"}
        page.ticket, page.randstr = "late-ticket", "late-randstr"
        assert page.deliver("done") is False and receiver.info == {"state": "closed"}

    asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["stop", "screenshot", "dispose", "binding_close"])
def test_cancel_during_cleanup_still_closes_page(case, operation):
    async def scenario():
        case.state = "sdk_error"
        case.entered[operation] = asyncio.Event()
        case.stalls.add(operation)
        task = asyncio.create_task(widget.TencentCaptchaSolver().solve(case.ctx, app_id="1234567890", budget=1))
        await asyncio.wait_for(case.entered[operation].wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert case.pages[0].closed and not case.pages[0].callback.__self__.accepting

    asyncio.run(scenario())


def test_every_run_has_new_page_and_unique_bridge_without_changing_account_state(case):
    async def scenario():
        solver = widget.TencentCaptchaSolver()
        first = await solver.solve(case.ctx, app_id="1234567890", budget=0.5)
        second = await solver.solve(case.ctx, app_id="1234567890", budget=0.5)
        assert first.ok and second.ok
    asyncio.run(scenario())
    assert len({page.key for page in case.pages}) == len({page.instance for page in case.pages}) == 2
    assert all(page.closed and page.disposed for page in case.pages)
    assert case.service._published_credentials == {"access_token": "existing-offline-credential"}


def _node(data):
    node = shutil.which("node")
    if node is None:
        spec = importlib.util.find_spec("playwright")
        if spec and spec.origin:
            driver = Path(spec.origin).parent / "driver"
            node = next((str(path) for path in (driver / "node.exe", driver / "node") if path.is_file()), None)
    if node is None:
        pytest.skip("需要离线 Node 执行真实 SDK 桥接 JS；不启动浏览器")
    result = subprocess.run([node, "-e", _NODE_RUNNER], input=json.dumps(data), text=True,
                            capture_output=True, check=True, timeout=10)
    return json.loads(result.stdout)


_NODE_RUNNER = r"""
const vm = require('node:vm');
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const scripts = [], callbacks = [], constructors = [], messages = [], deliveries = [];
let shown = 0, destroyed = 0;
const target = 'https://site.invalid/__checkin_tencent__';
const location = {href: input.initialLocation || target};
const context = {window: {}, location, console: {log: (...args) => messages.push(args)}, document: {
  createElement: tag => {
    if (tag !== 'script') throw Error('unexpected DOM persistence');
    return {src: '', removed: false, remove() { this.removed = true; }};
  }, head: {appendChild(script) { scripts.push(script); }},
  body: {appendChild() { throw Error('callback secrets must not enter DOM'); }},
}};
context.window.localStorage = {setItem() { throw Error('no persistence'); }};
context.window.sessionStorage = context.window.localStorage;
context.window.TencentCaptcha = function(appId, callback, options) {
  constructors.push({appId, options}); callbacks.push(callback);
  if (input.constructorError) throw Error('SENSITIVE-constructor-driver-error');
  this.show = () => { shown++; if (input.showError) throw Error('SENSITIVE-show-error'); };
  this.destroy = () => { destroyed++; };
};
if (input.missingGlobal) delete context.window.TencentCaptcha;
const binding = instance => '__checkin_tencent_callback_' + instance;
for (const instance of ['instance-one', 'instance-two']) {
  context.window[binding(instance)] = payload => {
    deliveries.push(JSON.parse(JSON.stringify(payload)));
    return Promise.resolve(true);
  };
}
if (input.missingBinding) delete context.window[binding('instance-one')];
const code = (template, instance = 'instance-one') => template
  .replaceAll('__KEY_JSON__', JSON.stringify('__checkin_tencent_' + instance))
  .replaceAll('__ID_JSON__', JSON.stringify(instance))
  .replaceAll('__TARGET_JSON__', JSON.stringify(target))
  .replaceAll('__APP_ID_JSON__', JSON.stringify('1234567890'))
  .replaceAll('__BINDING_JSON__', JSON.stringify(binding(instance)))
  .replaceAll('__SDK_URL_JSON__', JSON.stringify(input.sdkUrl));
const run = (template, instance) => vm.runInNewContext(code(template, instance), context);
const latest = () => deliveries.length ? deliveries[deliveries.length - 1] : null;
run(input.bootstrap);
const before = latest();
if (scripts.length) {
  if (input.loadError) scripts[0].onerror();
  else scripts[0].onload();
}
const ready = latest();
if (input.stopBeforeCallback) run(input.stop);
if (input.navigateAfterLoad) location.href = input.navigateAfterLoad;
if (callbacks.length && input.callback !== undefined) callbacks[0](input.callback);
const result = latest();
const countBeforeLate = deliveries.length;
if (callbacks.length && input.lateCallback) callbacks[0](input.lateCallback);
const countAfterLate = deliveries.length;
if (input.secondInstance) {
  run(input.dispose);
  run(input.bootstrap, 'instance-two');
  scripts[scripts.length - 1].onload();
  callbacks[0]({ret: 0, ticket: 'stale-first-ticket', randstr: 'stale-first-randstr'});
}
const second = input.secondInstance ? latest() : null;
run(input.stop, input.secondInstance ? 'instance-two' : undefined);
run(input.dispose, input.secondInstance ? 'instance-two' : undefined);
process.stdout.write(JSON.stringify({before, ready, result, countBeforeLate, countAfterLate, second, deliveries,
  scripts: scripts.map(s => ({src: s.src, removed: s.removed})), constructors, shown, destroyed, messages,
  keys: Object.keys(context.window).filter(k => k.startsWith('__checkin_') && !k.includes('_callback_')),
}));
"""


def _js_case(**kwargs):
    return _node({"bootstrap": widget._BOOTSTRAP_JS, "stop": widget._STOP_JS,
                  "dispose": widget._DISPOSE_JS, "sdkUrl": widget.SDK_URL, **kwargs})


def test_real_js_constructs_official_sdk_and_consumes_callback_only_once():
    value = _js_case(callback={"ret": 0, "ticket": "fresh-ticket", "randstr": "fresh-randstr"},
                     lateCallback={"ret": 0, "ticket": "late-ticket", "randstr": "late-randstr"})
    assert value["scripts"] == [{"src": "https://turing.captcha.qcloud.com/TJCaptcha.js", "removed": True}]
    assert value["constructors"] == [{"appId": "1234567890", "options": {"userLanguage": "zh-cn",
                                        "bizState": "instance-one"}}]
    assert value["before"]["state"] == "sdk_loading" and value["ready"]["state"] == "pending"
    assert value["result"] == {"state": "done", "instance": "instance-one", "ret": 0,
                               "ticket": "fresh-ticket", "randstr": "fresh-randstr"}
    assert value["countBeforeLate"] == value["countAfterLate"] == 3
    assert sum(item["state"] == "done" for item in value["deliveries"]) == 1
    assert value["shown"] == value["destroyed"] == 1 and not value["messages"] and not value["keys"]


@pytest.mark.parametrize("callback,state", [
    ({"ret": 2, "ticket": "ignored", "randstr": "ignored"}, "cancelled"),
    ({"ret": 1, "ticket": "ignored", "randstr": "ignored"}, "verification_failed"),
    ({"ret": "0", "ticket": "ignored", "randstr": "ignored"}, "verification_failed"),
    ({"ret": False, "ticket": "ignored", "randstr": "ignored"}, "verification_failed"),
    ({"ret": 0, "ticket": "", "randstr": "random"}, "invalid_result"),
    ({"ret": 0, "ticket": "ticket", "randstr": None}, "invalid_result"),
    ({"ret": 0, "ticket": "ticket\nsecret", "randstr": "random"}, "invalid_result"),
    ({"ret": 0, "ticket": "trerror_1001_fake", "randstr": "random"}, "sdk_error"),
    ({"ret": 0, "ticket": "ticket", "randstr": "random", "errorCode": 1006,
      "errorMessage": "private-error-string"}, "sdk_error"),
    ({"ret": 0, "ticket": "ticket", "randstr": "random", "appid": "wrong"}, "appid_mismatch"),
    ({"ret": 0, "ticket": "ticket", "randstr": "random", "CaptchaAppId": "wrong"}, "appid_mismatch"),
    ({"ret": 0, "ticket": "ticket", "randstr": "random", "bizState": "old-instance"}, "instance_mismatch"),
    (None, "invalid_result"),
])
def test_real_js_rejects_bad_callback_without_retaining_any_fields(callback, state):
    value = _js_case(callback=callback)
    assert value["result"]["state"] == state
    assert "ticket" not in value["result"] and "randstr" not in value["result"]
    assert "errorMessage" not in value["result"] and not value["messages"] and not value["keys"]


@pytest.mark.parametrize("extra", [{"appid": "1234567890"}, {"CaptchaAppId": "1234567890"},
    {"appid": 1234567890}, {"bizState": "instance-one"}, {"errorCode": 0}])
def test_real_js_accepts_documented_optional_callback_fields_when_matching(extra):
    assert _js_case(callback={"ret": 0, "ticket": "ticket", "randstr": "randstr", **extra})["result"]["state"] == "done"


@pytest.mark.parametrize("flag,state", [("loadError", "sdk_load_error"), ("missingGlobal", "sdk_missing"),
    ("constructorError", "sdk_error"), ("showError", "sdk_error")])
def test_real_js_sdk_errors_never_manufacture_disaster_tickets(flag, state):
    value = _js_case(**{flag: True})
    assert value["result"]["state"] == state
    assert "ticket" not in value["result"] and "randstr" not in value["result"]
    assert "SENSITIVE" not in json.dumps(value) and not value["messages"]


def test_real_js_stop_rejects_late_callback_and_instance_isolation_rejects_old_callback():
    value = _js_case(stopBeforeCallback=True, callback={"ret": 0, "ticket": "late", "randstr": "late"})
    assert value["result"]["state"] == "pending" and "ticket" not in value["result"]
    value = _js_case(secondInstance=True)
    assert value["second"]["state"] == "pending" and "ticket" not in value["second"]
    assert value["destroyed"] == 2 and not value["keys"]


def test_real_js_never_loads_sdk_on_wrong_initial_page_or_accepts_callback_after_navigation():
    value = _js_case(initialLocation="https://evil.invalid/")
    assert not value["scripts"] and not value["constructors"]
    value = _js_case(navigateAfterLoad="https://evil.invalid/", callback={"ret": 0, "ticket": "late", "randstr": "late"})
    assert value["result"]["state"] == "pending"  # 导航后不再发送任何回调；Python 另行核对 page/frame 来源。
    assert "ticket" not in value["result"] and not value["keys"]
    value = _js_case(missingBinding=True)
    assert not value["scripts"] and not value["constructors"]
