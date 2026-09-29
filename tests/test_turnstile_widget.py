"""注入式 Turnstile 的预算与收尾回归，不访问站点、不启动真实浏览器。"""
from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import shutil
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from solvers import turnstile_widget as widget


@pytest.fixture
def case(monkeypatch):
    value = SimpleNamespace(token="", state="rendered", error="", interactive=True, origin="https://site.invalid")
    page = SimpleNamespace(route=AsyncMock(), add_script_tag=AsyncMock(), mouse=SimpleNamespace())

    async def evaluate(script):
        if script == "() => location.origin":
            return value.origin
        if script == widget._RESET_JS:
            value.state, value.error = "rendered", ""
            return None
        assert script == widget._STATE_JS
        return {
            "state": value.state, "error": value.error, "token": value.token,
            "interactive": value.interactive,
            "slot": {"x": 28, "y": 28, "w": 300, "h": 74},
        }

    async def click(*_args, **_kwargs):
        value.token = "test-real-token"

    page.evaluate = AsyncMock(side_effect=evaluate)
    page.mouse.move = AsyncMock()
    page.mouse.click = AsyncMock(side_effect=click)
    lease = SimpleNamespace(
        new_page=AsyncMock(return_value=page), goto=AsyncMock(),
        screenshot=AsyncMock(return_value="evidence.png"), service=SimpleNamespace(base_url=value.origin),
    )
    manager = SimpleNamespace(__aenter__=AsyncMock(return_value=lease), __aexit__=AsyncMock(return_value=False))
    browser = SimpleNamespace(lease=Mock(return_value=manager))
    ctx = SimpleNamespace(browser_service=browser, log=Mock())
    monkeypatch.setattr(widget, "RPC_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(widget, "PAGE_CREATE_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(widget, "NAVIGATION_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(widget, "CLICK_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(widget, "SCREENSHOT_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(widget, "CLEANUP_RESERVE_SECONDS", 0.5)
    monkeypatch.setattr(widget, "AUTO_WAIT_SECONDS", 0.01)
    monkeypatch.setattr(widget, "ERROR_GRACE_MS", 10)
    monkeypatch.setattr(widget, "POLL_INTERVAL_MS", 5)
    monkeypatch.setattr(widget, "TOKEN_WAIT_MS", 40)
    monkeypatch.setattr(widget, "RETRY_COOLDOWN_MS", 5)
    return SimpleNamespace(ctx=ctx, browser=browser, manager=manager, lease=lease, page=page, value=value)


def run(case, **kwargs):
    async def scenario():
        return await asyncio.wait_for(widget.TurnstileInjectSolver().solve(
            case.ctx, sitekey="public-test-sitekey", **kwargs,
        ), timeout=3)
    return asyncio.run(scenario())


@pytest.mark.parametrize("budget", [0, -1])
def test_exhausted_budget_never_launches_browser(case, budget):
    result = run(case, budget=budget)
    assert result.reason == "timeout"
    case.browser.lease.assert_not_called()


@pytest.mark.parametrize("budget", [float("nan"), float("inf")])
def test_nonfinite_budget_is_rejected(case, budget):
    assert run(case, budget=budget).reason == "invalid"
    case.browser.lease.assert_not_called()


def test_success_clicks_once_and_closes_without_guard(case):
    result = run(case, budget=2)
    assert result.ok and result.value == "test-real-token" and result.attempts == 1
    case.lease.new_page.assert_awaited_once_with(guard_origin="")
    case.page.mouse.move.assert_awaited_once_with(58.0, 65.0, steps=1)
    case.page.mouse.click.assert_awaited_once_with(58.0, 65.0)
    case.manager.__aexit__.assert_awaited_once()
    assert not any(call.args[0] == widget._RESET_JS for call in case.page.evaluate.await_args_list)
    assert "真实鼠标点击已完成" in " ".join(str(call.args[0]) for call in case.ctx.log.call_args_list)
    assert "test-real-token" not in str(case.ctx.log.call_args_list)


def test_auto_issued_token_does_not_click(case):
    case.value.token = "automatically-issued"
    result = run(case)
    assert result.ok and result.value == "automatically-issued"
    case.page.mouse.click.assert_not_awaited()
    case.page.mouse.move.assert_not_awaited()


def test_pending_challenge_is_not_reset_or_reclicked(case):
    case.page.mouse.click.side_effect = None
    result = run(case)
    assert not result.ok and result.reason == "timeout" and result.attempts == 1
    case.page.mouse.click.assert_awaited_once()
    assert all(call.args[0] != widget._RESET_JS for call in case.page.evaluate.await_args_list)
    case.lease.screenshot.assert_awaited_once()
    assert "IP" not in result.message


def test_explicit_widget_error_can_reset_once(case, monkeypatch):
    # 本例验证错误宽限期后的单次重置，不验证墙钟性能。使用模块内虚拟时钟，
    # 避免 Windows 调度抖动令 40ms 的测试窗口在第二次状态观察前就耗尽；
    # 独立的 stalled_rpc/deadline 用例仍使用真实时钟检查超时边界。
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(widget, "time", SimpleNamespace(monotonic=lambda: clock.now))

    async def pause(deadline, milliseconds=None):
        interval = widget.POLL_INTERVAL_MS if milliseconds is None else milliseconds
        clock.now += min(interval / 1000, max(0.0, deadline - clock.now))
        await asyncio.sleep(0)

    monkeypatch.setattr(widget, "_pause", pause)

    async def click(*_args):
        if case.page.mouse.click.await_count == 1:
            case.value.state, case.value.error = "error", "600010"
        else:
            case.value.token = "token-after-reset"

    case.page.mouse.click.side_effect = click
    result = run(case)
    assert result.ok and result.attempts == 2
    assert case.page.mouse.click.await_count == 2
    assert sum(call.args[0] == widget._RESET_JS for call in case.page.evaluate.await_args_list) == 1


@pytest.mark.parametrize("operation,expected_stage", [
    ("launch", "启动浏览器"), ("new_page", "创建验证页面"), ("route", "设置承载页路由"),
    ("navigate", "打开最小承载页"), ("script", "注入 Turnstile widget"),
    ("state", "读取 widget 挂载状态"), ("move", "移动到 CF 复选框"), ("click", "点击 CF 复选框"),
    ("token", "点击后等待令牌"), ("reset", "重置错误 widget"),
])
def test_stalled_rpc_returns_stage_timeout_not_account_timeout(case, monkeypatch, operation, expected_stage):
    async def hung(*_args, **_kwargs):
        await asyncio.Future()

    operations = {
        "launch": case.manager.__aenter__, "new_page": case.lease.new_page, "route": case.page.route,
        "navigate": case.lease.goto, "script": case.page.add_script_tag,
        "move": case.page.mouse.move, "click": case.page.mouse.click,
    }
    if operation in operations:
        operations[operation].side_effect = hung
    else:
        evaluate = case.page.evaluate.side_effect

        async def conditional(script):
            stall = (operation == "state" and script == widget._STATE_JS) or (
                operation == "token" and script == widget._STATE_JS and case.page.mouse.click.await_count > 0
            ) or (operation == "reset" and script == widget._RESET_JS)
            if stall:
                return await hung()
            return await evaluate(script)

        case.page.evaluate.side_effect = conditional
        if operation == "reset":
            case.value.state, case.value.error = "error", "600010"
    if operation in {"move", "click"}:
        # 单步上限大于整轮预算：卡住的鼠标 RPC 一直占到预算耗尽时，必须按该阶段超时上报。
        # 单步上限先到（仅主机繁忙）的降级路径见下方专门用例。
        monkeypatch.setattr(widget, "CLICK_TIMEOUT_SECONDS", 5)
    # 操作使用缩短后的独立上限，总预算留足余量；不要求 Windows 在70ms内完成收尾。
    result = run(case, budget=2)
    assert not result.ok and result.reason == "timeout"
    assert result.data["stage"] == expected_stage
    assert expected_stage in result.message
    if operation != "launch":
        case.manager.__aexit__.assert_awaited_once()
    if operation in {"move", "click"}:
        assert "真实鼠标点击已完成" not in str(case.ctx.log.call_args_list)


async def _hung(*_args, **_kwargs):
    await asyncio.Future()


def test_slow_cf_move_degrades_to_one_direct_click(case):
    """实测：高负载主机上 8 步移动超过单步上限。改为按坐标直接点击一次，不判本轮超时。"""
    case.page.mouse.move.side_effect = _hung
    result = run(case, budget=2)
    assert result.ok and result.value == "test-real-token"
    case.page.mouse.click.assert_awaited_once_with(58.0, 65.0)
    logs = str(case.ctx.log.call_args_list)
    assert "改为按坐标直接点击一次" in logs and "真实鼠标点击已完成" in logs


def test_unconfirmed_click_is_never_repeated_or_reported_as_done(case):
    """点击 RPC 迟迟不返回：不重复点击、不 reset，只等令牌；等不到令牌不能报成功。"""
    case.page.mouse.click.side_effect = _hung
    result = run(case, budget=2)
    assert not result.ok and result.reason == "timeout"
    case.page.mouse.click.assert_awaited_once()
    assert all(call.args[0] != widget._RESET_JS for call in case.page.evaluate.await_args_list)
    assert "真实鼠标点击已完成" not in str(case.ctx.log.call_args_list)


def test_unconfirmed_click_still_accepts_later_token(case):
    """点击已生效但回包慢，或 managed widget 自行签发：继续等令牌即可成功，且只点一次。"""
    async def pending_ack(*_args, **_kwargs):
        case.value.token = "issued-while-click-pending"
        await asyncio.Future()

    case.page.mouse.click.side_effect = pending_ack
    result = run(case, budget=2)
    assert result.ok and result.value == "issued-while-click-pending"
    case.page.mouse.click.assert_awaited_once()


def test_slow_state_reads_are_retried_not_reported_as_failure(case):
    """单次读取超过 RPC 上限只说明主机繁忙：窗口内重读，拿到状态后照常完成。"""
    evaluate = case.page.evaluate.side_effect
    slow_reads = [2]

    async def sometimes_slow(script):
        if script == widget._STATE_JS and slow_reads[0] > 0:
            slow_reads[0] -= 1
            await asyncio.Future()
        return await evaluate(script)

    case.page.evaluate.side_effect = sometimes_slow
    result = run(case, budget=2)
    assert result.ok and result.value == "test-real-token"
    case.page.mouse.click.assert_awaited_once()


def test_slow_page_creation_uses_spare_budget_but_keeps_post_page_reserve(case, monkeypatch):
    """两个浏览器并发启动时实测建页超过 30s：超过下限仍继续等，但给挂载、点击和等令牌留足预留时间。"""
    monkeypatch.setattr(widget, "POST_PAGE_RESERVE_SECONDS", 0.5)
    seen = {}
    original = widget._within

    async def recording(operation, deadline, stage, limit=None):
        if stage == "创建验证页面":
            seen.update(limit=limit, remaining=deadline - time.monotonic())
        return await original(operation, deadline, stage, limit)

    async def slow_new_page(**_kwargs):
        await asyncio.sleep(0.3)  # 超过本测试 0.1s 的建页下限
        return case.page

    monkeypatch.setattr(widget, "_within", recording)
    case.lease.new_page.side_effect = slow_new_page
    result = run(case, budget=2)
    assert result.ok and result.value == "test-real-token"
    assert seen["limit"] > widget.PAGE_CREATE_TIMEOUT_SECONDS
    assert seen["limit"] == pytest.approx(seen["remaining"] - 0.5, abs=0.05)
    assert "主机繁忙" in str(case.ctx.log.call_args_list)


def test_default_windows_cover_measured_slow_host_timings():
    """2 核高负载主机实测：启动最长 19s、建页 8.9s（并发时超过 30s）、就绪后 14.8s 才自动签发；默认窗口必须放得下。"""
    captured = {}
    widget.register(SimpleNamespace(register=lambda *_args, **kwargs: captured.update(kwargs)))
    assert captured["default_budget"] == widget.DEFAULT_BUDGET_SECONDS
    assert widget.PAGE_CREATE_TIMEOUT_SECONDS > 8.9
    assert widget.TOKEN_WAIT_MS / 1000 > 14.8
    one_attempt = 19 + 8.9 + 6.6 + widget.AUTO_WAIT_SECONDS + 14.8 + widget.CLEANUP_RESERVE_SECONDS
    assert widget.DEFAULT_BUDGET_SECONDS > one_attempt
    # 建页之后的一次尝试（打开承载页 3.8s + 挂载 6.8s + 就绪到签发 14.8s）要落在预留内；
    # 启动 19s 后，建页仍可等到下限的两倍以上。
    assert widget.POST_PAGE_RESERVE_SECONDS > 3.8 + 6.8 + 14.8
    work = widget.DEFAULT_BUDGET_SECONDS - widget.CLEANUP_RESERVE_SECONDS
    assert work - 19 - widget.POST_PAGE_RESERVE_SECONDS >= 2 * widget.PAGE_CREATE_TIMEOUT_SECONDS


@pytest.mark.parametrize("cleanup", ["screenshot", "close"])
def test_stalled_cleanup_cannot_discard_result(case, cleanup):
    async def hung(*_args, **_kwargs):
        await asyncio.Future()

    if cleanup == "screenshot":
        case.page.mouse.click.side_effect = None
        case.lease.screenshot.side_effect = hung
    else:
        case.manager.__aexit__.side_effect = hung
    result = run(case, budget=0.7)
    assert result.ok is (cleanup == "close")
    if cleanup == "close":
        assert result.value == "test-real-token"
    else:
        assert result.reason == "timeout"


def test_explicit_zero_budget_does_not_expand_to_default(case):
    assert run(case, budget=0).attempts == 0
    case.lease.new_page.assert_not_awaited()


def test_external_cancellation_propagates_and_releases_lease(case):
    async def scenario():
        entered = asyncio.Event()

        async def hung(*args, **kwargs):
            entered.set()
            await asyncio.Future()

        case.page.mouse.click.side_effect = hung
        task = asyncio.create_task(widget.TurnstileInjectSolver().solve(case.ctx, sitekey="test", budget=2))
        await asyncio.wait_for(entered.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        case.manager.__aexit__.assert_awaited_once()

    asyncio.run(scenario())


def test_unexpected_driver_exception_does_not_echo_token_or_claim_ip_block(case):
    case.page.mouse.click.side_effect = RuntimeError("private-token=SHOULD-NOT-LOG")
    result = run(case)
    assert not result.ok and result.reason == "error"
    assert "SHOULD-NOT-LOG" not in result.message + str(case.ctx.log.call_args_list)
    assert "IP" not in result.message


def test_wrong_origin_never_receives_widget(case, monkeypatch):
    from browser import bypass

    case.value.origin = "https://site.invalid.evil.example"
    monkeypatch.setattr(bypass, "solve_cloudflare", AsyncMock(return_value=True))
    result = run(case)
    assert not result.ok
    case.page.add_script_tag.assert_not_awaited()


def test_failed_solver_never_submits_checkin(case):
    from core.errors import TransientError
    from solvers.registry import SolveResult
    from templates.builtin import newapi_verify

    ctx = SimpleNamespace(log=Mock(), http=Mock(), solve=AsyncMock(return_value=SolveResult.failure(
        "timeout", "点击 CF 复选框超时", data={"stage": "点击 CF 复选框"},
    )))
    with pytest.raises(TransientError) as excinfo:
        asyncio.run(newapi_verify._turnstile_checkin(ctx, {"turnstile_check": True, "turnstile_site_key": "test"}))
    assert excinfo.value.data["stage"] == "点击 CF 复选框"
    ctx.http.request.assert_not_called()


def test_browser_context_close_is_bounded(monkeypatch):
    from browser import runtime_loop
    from browser.service import BrowserService

    async def hung():
        await asyncio.Future()

    monkeypatch.setattr(runtime_loop, "BROWSER_CLOSE_TIMEOUT_SECONDS", 0.03)
    service = BrowserService(base_url="https://site.invalid")
    browser = SimpleNamespace(close=AsyncMock())
    service._started = True
    service._context = SimpleNamespace(close=AsyncMock(side_effect=hung))
    service._browser = browser

    async def scenario():
        await asyncio.wait_for(service.aclose(), timeout=2)

    asyncio.run(scenario())
    browser.close.assert_awaited_once()
    assert not service.started


def test_state_reader_reads_suffixed_response_only_from_injected_host():
    import subprocess

    node = shutil.which("node")
    if node is None:
        spec = importlib.util.find_spec("playwright")
        if spec is not None and spec.origin:
            driver = Path(spec.origin).parent / "driver"
            node = next((str(path) for path in (driver / "node.exe", driver / "node") if path.is_file()), None)
    if node is None:
        pytest.skip("需要 Node（可复用 Playwright 自带 Node），不启动浏览器")
    runner = r'''
const read = eval('(' + JSON.parse(process.argv[1]) + ')');
const host = {
  getAttribute: n => n === 'data-state' ? 'rendered' : '',
  querySelectorAll: selector => {
    if (!selector.includes('name^="cf-turnstile-response"')) throw Error('requires prefix');
    return [{value:''}, {value:' signed-token '}];
  }
};
const document = {getElementById: id => id === 'ck-ts-host' ? host : null};
console.log(JSON.stringify(read()));
'''
    result = subprocess.run([node, "-e", runner, json.dumps(widget._STATE_JS)],
                            capture_output=True, text=True, check=True, timeout=5)
    assert json.loads(result.stdout)["token"] == "signed-token"


def test_cf_widget_click_uses_bounded_multi_step_move_when_enabled(case):
    from browser import turnstile

    case.page.context = SimpleNamespace()
    turnstile.set_cf_humanize(case.page.context, True)
    result = run(case, budget=2)
    assert result.ok
    case.page.mouse.move.assert_awaited_once_with(58.0, 65.0, steps=turnstile.CF_MOVE_STEPS)
    case.page.mouse.click.assert_awaited_once_with(58.0, 65.0)
