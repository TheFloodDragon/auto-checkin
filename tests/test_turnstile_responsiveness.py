# -*- coding: utf-8 -*-
"""Turnstile 等待的响应性回归。

修的是三个实测症状（百倍/极速蹬登录页）：
1. 首次点击太慢：旧实现先读一次令牌（必然为空）、再 sleep 一整个轮询间隔才点，
   白等约 1 秒；
2. 人工完成后不继续识别：旧实现点击成功后固定 sleep 1.5–3 秒才再看令牌，
   人在这期间点完也要等满整段；
3. 找不到 widget 就没事可做：应继续观察令牌（有头模式下人工完成走这条路径），
   而不是反复空点。

这里用假 Page 记录每次 wait_for_timeout 的时长，从而断言「等待节奏」本身，
而不是只断言最终拿到了令牌 —— 后者在旧实现下同样成立，测不出响应性差异。
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from browser import turnstile

BOX = {"x": 100.0, "y": 200.0, "width": 300.0, "height": 65.0}


class FakePage:
    """可控 widget / 令牌的假 Page，记录鼠标点击与每次等待时长。"""

    def __init__(
        self,
        *,
        has_widget: bool = True,
        token_after_clicks: int | None = 1,
        token_after_waits: int | None = None,
        token: str = "tk",
    ) -> None:
        self._has_widget = has_widget
        self._token_after_clicks = token_after_clicks
        self._token_after_waits = token_after_waits
        self._issue = token
        self._token = ""
        self.clicks = 0
        self.click_positions: list[tuple[float, float]] = []
        self.waits: list[int] = []
        # 按发生顺序记录 move / click / wait：区分「点击手势内部的短等待」和
        # 「轮询空等」，否则无法断言「首次点击前没有空等一轮」。
        self.events: list[tuple[str, int]] = []
        self.script_tags = 0
        self.mouse = _FakeMouse(self)
        self.frames = [_Frame(owner=_Element(BOX))] if has_widget else []
        self.viewport_size = {"width": 1280, "height": 720}

    # -- turnstile 依赖的 page 接口 --
    async def add_script_tag(self, *, content: str = "") -> None:
        # solve() 开头会注入令牌桥接脚本；这里只计数，不执行。
        self.script_tags += 1

    async def evaluate_handle(self, expression, trusted):
        assert expression == turnstile._FIND_CHECKBOX_JS and trusted is False
        return _NullHandle()

    async def evaluate(self, expr: str, arg=None):
        if expr == turnstile._PROBE_STATE_JS:
            return {"present": False, "processing": False, "reason": "target_not_found"}
        if expr == turnstile._READ_TOKEN_JS:
            return self._token
        return None

    async def wait_for_timeout(self, ms: int) -> None:
        self.waits.append(int(ms))
        self.events.append(("wait", int(ms)))
        if self._token_after_waits is not None and len(self.waits) >= self._token_after_waits:
            self._token = self._issue
        await asyncio.sleep(0)

    def on_click(self) -> None:
        self.clicks += 1
        self.events.append(("click", self.clicks))
        if self._token_after_clicks is not None and self.clicks >= self._token_after_clicks:
            self._token = self._issue


class _FakeMouse:
    def __init__(self, page: FakePage) -> None:
        self.page = page

    async def move(self, x: float, y: float, steps: int = 1) -> None:
        self.page.events.append(("move", 0))
        await asyncio.sleep(0)

    async def click(self, x: float, y: float) -> None:
        self.page.click_positions.append((x, y))
        self.page.on_click()


class _MultiFieldPage(FakePage):
    """模拟第一个响应字段为空、后续字段已有令牌的页面。"""

    async def evaluate(self, expr: str, arg=None):
        if "cf-turnstile-response" in expr and "getBoundingClientRect" not in expr:
            return "later-widget-token" if "querySelectorAll" in expr else ""
        return await super().evaluate(expr, arg)


class _SlowPollPage(FakePage):
    """推进模拟时钟，验证长人工挑战不会被再次点击，不依赖机器调度速度。"""

    def __init__(self, clock: list[float]) -> None:
        super().__init__(token_after_clicks=None, token_after_waits=15)
        self.clock = clock

    async def wait_for_timeout(self, ms: int) -> None:
        self.waits.append(int(ms))
        self.events.append(("wait", int(ms)))
        if self._token_after_waits is not None and len(self.waits) >= self._token_after_waits:
            self._token = self._issue
        self.clock[0] += max(0, ms) / 1000


def _solve(page: FakePage, *, timeout_ms: int = 5000, log=None) -> str:
    return asyncio.run(turnstile.solve(page, timeout_ms=timeout_ms, poll_interval_ms=250, log=log))


# ── 1. 首次点击不再空等一轮 ──────────────────────────────────────────────────
def test_first_click_happens_before_any_wait() -> None:
    """widget 就绪时应立刻点击，而不是先 sleep 一个轮询间隔。

    旧实现的等待序列是 [1000, ...]（先等再点）；现在点击必须发生在第一次
    wait_for_timeout 之前，所以拿到令牌时点击数已 >=1。
    """
    page = FakePage()
    assert _solve(page) == "tk"
    assert page.clicks == 1
    # 断言首个事件是点击手势的鼠标移动，而不是轮询空等。
    # 注意不能直接断言 page.waits == []：click() 内部的人类化轨迹本身含
    # wait_for_timeout(200/150)，那属于点击手势的一部分，不是「先等一轮再点」。
    assert page.events, "应至少产生一次交互事件"
    assert page.events[0][0] == "move", f"首个事件应是点击手势，实际 {page.events}"
    # 点击之前不应出现轮询粒度（>=250ms）的等待。
    before_click = page.events[: [kind for kind, _ in page.events].index("click")]
    assert not [ms for kind, ms in before_click if kind == "wait" and ms >= 250], (
        f"首次点击前不该有轮询等待，实际 {before_click}"
    )


# ── 2. 点击后保持密集轮询（人工完成能被及时发现）──────────────────────────
def test_polling_after_click_uses_fine_grained_steps() -> None:
    """点击后不能固定 sleep 数秒：必须按小步长持续查，令牌一出现立即返回。"""
    # 令牌在第 3 次等待后才出现（模拟 Cloudflare 处理中 / 人工刚点完）。
    page = FakePage(token_after_clicks=None, token_after_waits=3)
    assert _solve(page) == "tk"
    assert page.waits, "应有轮询等待"
    assert max(page.waits) <= 500, f"轮询步长不得超过 500ms，实际 {page.waits}"
    assert len(page.waits) == 3, f"令牌出现后应立即返回，实际等待 {page.waits}"


def test_human_completion_is_detected_without_extra_click() -> None:
    """有头模式下人工点完验证：即使脚本没点成功，也要认出令牌已签发。"""
    page = FakePage(has_widget=False, token_after_clicks=None, token_after_waits=2)
    logs: list[str] = []
    assert _solve(page, log=logs.append) == "tk"
    assert page.clicks == 0, "定位不到 widget 时不应点击"
    assert any("人工" in line for line in logs), "应提示可人工完成验证"
    assert any("已完成" in line for line in logs)


# ── 3. 不重复点击已在处理中的 widget ────────────────────────────────────────
def test_widget_is_not_reclicked_while_cloudflare_processes() -> None:
    """处理中重复点击会重置挑战。等待窗口内只应点一次。"""
    # 永不签发令牌：跑满超时，用点击次数衡量点击节奏。
    page = FakePage(token_after_clicks=None, token_after_waits=None)
    assert _solve(page, timeout_ms=1200) == ""
    # 窗口 3s > 超时 1.2s，因此整个过程只该点一次。
    assert page.clicks == 1, f"等待窗口内只应点一次，实际 {page.clicks}"


def test_timeout_returns_empty_token() -> None:
    page = FakePage(token_after_clicks=None, token_after_waits=None)
    assert _solve(page, timeout_ms=300) == ""


def test_already_issued_token_short_circuits() -> None:
    """非交互式 widget 可能已自动签发：不该再点一次。"""
    page = FakePage()
    page._token = "pre-issued"
    assert _solve(page) == "pre-issued"
    assert page.clicks == 0
    assert page.waits == []


def test_reads_non_empty_token_from_later_response_field() -> None:
    page = _MultiFieldPage()

    assert _solve(page) == "later-widget-token"
    assert page.clicks == 0


def test_long_manual_challenge_is_not_reset_by_a_second_click(monkeypatch) -> None:
    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        clock = [loop.time()]
        page = _SlowPollPage(clock)
        with monkeypatch.context() as patch:
            patch.setattr(loop, "time", lambda: clock[0])
            assert await turnstile.solve(page, timeout_ms=5000, poll_interval_ms=250) == "tk"
        assert sum(page.waits) > 3000, "模拟验证必须超过旧的 3 秒处理窗口"
        assert page.clicks == 1, "人工验证超过原处理窗口时也不能再次点击重置 challenge"

    asyncio.run(scenario())


# ── 4. 令牌落点覆盖：后缀字段 / 桥接属性 / 主世界桥接注入 ─────────────────────
# 真实症状（百倍/极速蹬）：站点用 explicit render + JS callback，令牌只进框架状态，
# 既不写标准 cf-turnstile-response、也读不到隔离世界的 window.turnstile。旧
# read_token 只精确匹配 cf-turnstile-response，于是用户明明完成了验证仍报「未签发」，
# 60 秒后关浏览器（表现为「完成 CF 验证后立马闪退」）。这里用真实 _READ_TOKEN_JS
# 语义驱动的假 DOM，守护三处令牌落点都能读到，且桥接脚本确实被注入。


class _DomPage:
    """按真实 _READ_TOKEN_JS / _BRIDGE 语义模拟 DOM 的假 Page。

    只实现 turnstile 模块用到的 evaluate / add_script_tag / wait_for_timeout。
    令牌落点由构造参数指定：隐藏域名字（支持 explicit render 的后缀）或桥接属性。
    """

    def __init__(self, *, field_name: str = "", field_token: str = "", bridged_token: str = "") -> None:
        self._field_name = field_name
        self._field_token = field_token
        # 桥接令牌初始不在 DOM 上，只有主世界桥接脚本注入后才会「出现」，
        # 以此验证 install_token_bridge 真的被调用。
        self._pending_bridge = bridged_token
        self._bridge_attr = ""
        self.bridge_installed = 0
        self.mouse = _FakeMouse(FakePage())

    async def add_script_tag(self, *, content: str = "") -> None:
        # 只认桥接脚本；注入后把待发布的桥接令牌落到 DOM 属性（模拟 getResponse→属性）。
        if "__ckTsBridge" in content:
            self.bridge_installed += 1
            if self._pending_bridge:
                self._bridge_attr = self._pending_bridge

    async def evaluate(self, expr: str, arg=None):
        if "getBoundingClientRect" in expr:
            return None  # 无 widget：走「等待令牌」路径，不点击
        if "data-ck-ts-token" in expr and "getResponse" not in expr:
            # _READ_TOKEN_JS：先查前缀匹配的隐藏域，再回退桥接属性。
            if self._field_name.startswith("cf-turnstile-response") and self._field_token:
                return self._field_token
            return self._bridge_attr
        return None

    async def wait_for_timeout(self, ms: int) -> None:
        await asyncio.sleep(0)


def test_reads_token_from_explicit_render_suffixed_field() -> None:
    """explicit render 生成 cf-turnstile-response-<id>：前缀匹配必须能读到。"""
    page = _DomPage(field_name="cf-turnstile-response-0x4AAAA", field_token="explicit-token")
    assert asyncio.run(turnstile.solve(page, timeout_ms=1000, poll_interval_ms=100)) == "explicit-token"


def test_reads_callback_only_token_via_dom_bridge() -> None:
    """callback-only（不写隐藏域）：靠主世界桥接把令牌搬到 DOM 属性后读到。"""
    page = _DomPage(bridged_token="callback-token")
    assert asyncio.run(turnstile.solve(page, timeout_ms=1000, poll_interval_ms=100)) == "callback-token"
    assert page.bridge_installed >= 1, "solve 必须注入主世界令牌桥接脚本"


def test_bridge_is_installed_even_when_widget_absent() -> None:
    """无 widget 也要装桥接：有头模式人工完成时令牌才可能是 callback-only。"""
    page = _DomPage()
    assert asyncio.run(turnstile.solve(page, timeout_ms=300, poll_interval_ms=100)) == ""
    assert page.bridge_installed >= 1


# ── 5. Playwright handle/frame mocks：主 viewport 坐标和关闭 shadow 的 owner ──
CHECKBOX = {"x": 412.0, "y": 233.0, "width": 24.0, "height": 24.0}
OWNER = {"x": 400.0, "y": 220.0, "width": 300.0, "height": 65.0}
CF_URL = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/turnstile/test"


class _NullHandle:
    def as_element(self):
        return None

    async def dispose(self):
        pass


class _Element(_NullHandle):
    def __init__(self, box=None, *, visible=True, checked=False, disabled=False):
        self.box = dict(CHECKBOX if box is None else box)
        self.visible = visible
        self.checked = checked
        self.disabled = disabled
        self.bbox_calls = 0
        self.disposed = 0
        self.after_bbox = None

    def as_element(self):
        return self

    async def bounding_box(self):
        self.bbox_calls += 1
        if self.after_bbox:
            self.after_bbox()
        return self.box if self.visible else None

    async def evaluate(self, expression):
        if expression == turnstile._ACTIONABLE_ELEMENT_JS:
            return self.visible and not self.checked and not self.disabled
        assert expression == turnstile._VISIBLE_ELEMENT_JS
        return self.visible

    async def dispose(self):
        self.disposed += 1


class _Frame:
    def __init__(self, checkbox=None, *, url=CF_URL, owner=None):
        self.url = url
        self.checkbox = checkbox
        self.owner = owner or _Element(OWNER)
        self.parent_frame = SimpleNamespace(parent_frame=None)
        self.detached = False
        self.processing = False
        self.hang = False
        self.queries = 0
        self.owner_queries = 0
        self.local_rect = {"x": 12, "y": 13, "width": 24, "height": 24}

    def is_detached(self):
        return self.detached

    async def evaluate_handle(self, expression, trusted):
        self.queries += 1
        assert expression == turnstile._FIND_CHECKBOX_JS
        assert trusted is True
        if self.hang:
            await asyncio.Future()
        if self.detached:
            raise RuntimeError("frame detached")
        if self.checkbox and not self.processing and await self.checkbox.evaluate(turnstile._ACTIONABLE_ELEMENT_JS):
            return self.checkbox
        return _NullHandle()

    async def evaluate(self, expression, trusted=None):
        assert expression == turnstile._PROBE_STATE_JS, "不能把 frame 局部 rect 当成主 viewport 坐标"
        assert trusted is True
        if self.hang:
            await asyncio.Future()
        processing = self.processing or bool(self.checkbox and self.checkbox.checked)
        ready = bool(self.checkbox and not processing
                     and await self.checkbox.evaluate(turnstile._ACTIONABLE_ELEMENT_JS))
        return {"present": True, "processing": processing, "actionable": ready,
                "fallback_allowed": self.checkbox is None and not processing,
                "reason": "processing" if processing else "ready" if ready else
                          "checkbox_unusable" if self.checkbox else "frame_owner_ready"}

    async def frame_element(self):
        self.owner_queries += 1
        if self.detached:
            raise RuntimeError("frame detached")
        return self.owner


class _LocatorPage(FakePage):
    def __init__(self, *, frames=(), checkbox=None, fallback=None, token_after_clicks=1):
        super().__init__(has_widget=False, token_after_clicks=token_after_clicks)
        self.frames = list(frames)
        self.checkbox = checkbox
        self.fallback = fallback
        self.viewport_size = {"width": 1280, "height": 720}
        self.main_queries = 0
        self.fallback_queries = 0

    async def evaluate_handle(self, expression, trusted):
        assert expression == turnstile._FIND_CHECKBOX_JS
        assert trusted is False
        self.main_queries += 1
        if self.checkbox and await self.checkbox.evaluate(turnstile._ACTIONABLE_ELEMENT_JS):
            return self.checkbox
        return _NullHandle()

    async def evaluate(self, expression, arg=None):
        if expression == turnstile._PROBE_STATE_JS:
            assert arg is False
            processing = bool(self.checkbox and self.checkbox.checked)
            ready = bool(self.checkbox and await self.checkbox.evaluate(turnstile._ACTIONABLE_ELEMENT_JS))
            return {"present": self.checkbox is not None, "processing": processing, "actionable": ready,
                    "reason": "processing" if processing else "ready" if ready else
                              "checkbox_unusable" if self.checkbox else "target_not_found"}
        if expression == turnstile._FIND_BOX_JS:
            self.fallback_queries += 1
            return self.fallback
        return await super().evaluate(expression, arg)


def test_cf_frame_checkbox_uses_element_bbox_in_main_viewport():
    checkbox = _Element()
    frame = _Frame(checkbox)
    page = _LocatorPage(frames=[frame], checkbox=_Element())

    async def scenario():
        box = await turnstile.find_checkbox(page)
        assert box == {**CHECKBOX, "kind": "checkbox"}
        assert box != {**frame.local_rect, "kind": "checkbox"}
        assert await turnstile.click(page, box=box)

    asyncio.run(scenario())
    assert page.click_positions == [(424.0, 245.0)]
    assert checkbox.bbox_calls == 1
    assert checkbox.disposed == 1
    assert frame.owner_queries >= 1
    assert page.main_queries == 0, "真实可信 frame 优先于主页面"


def test_find_box_prefers_real_checkbox_over_widget_fallback():
    page = _LocatorPage(checkbox=_Element(), fallback=BOX)
    assert asyncio.run(turnstile.find_box(page)) == {**CHECKBOX, "kind": "checkbox"}
    assert page.fallback_queries == 0


def test_frame_owner_in_parent_closed_shadow_is_usable_without_main_dom_access():
    # 主页面 DOM 完全没有候选；frame_element 是获得 closed shadow owner 的唯一入口。
    frame = _Frame()
    page = _LocatorPage(frames=[frame])
    assert asyncio.run(turnstile.find_checkbox(page)) is None
    assert asyncio.run(turnstile.find_box(page)) == OWNER
    assert asyncio.run(turnstile.click(page)) is True
    assert page.click_positions == [(430.0, 252.5)]
    assert frame.owner_queries >= 1
    assert page.script_tags == 0, "不能注入 attachShadow 补丁来暴露 closed root"


@pytest.mark.parametrize("state", ["hidden", "checked", "disabled", "processing", "hidden_owner", "detached"])
def test_unusable_frame_checkbox_never_falls_back_to_clicking_widget(state):
    checkbox = _Element(visible=state != "hidden", checked=state == "checked", disabled=state == "disabled")
    frame = _Frame(checkbox, owner=_Element(OWNER, visible=state != "hidden_owner"))
    frame.processing = state == "processing"
    frame.detached = state == "detached"
    page = _LocatorPage(frames=[frame])
    assert asyncio.run(turnstile.find_checkbox(page)) is None
    assert asyncio.run(turnstile.find_box(page)) is None
    assert asyncio.run(turnstile.click(page)) is False
    assert not page.click_positions


@pytest.mark.parametrize("changed", ["detached", "navigated"])
def test_frame_rechecked_after_bbox_when_it_detaches_or_navigates(changed):
    checkbox = _Element()
    frame = _Frame(checkbox)
    checkbox.after_bbox = lambda: setattr(
        frame,
        "detached" if changed == "detached" else "url",
        True if changed == "detached" else "https://evil.example/",
    )
    page = _LocatorPage(frames=[frame])
    assert asyncio.run(turnstile.find_checkbox(page)) is None
    assert not page.click_positions


@pytest.mark.parametrize(
    "url",
    [
        "https://challenges.cloudflare.com.evil.example/widget",
        "https://evil.example/challenges.cloudflare.com/widget",
        "https://challenges.cloudflare.com@evil.example/widget",
        "https://evil.challenges.cloudflare.com/widget",
        "https://evil.example/?host=challenges.cloudflare.com",
        "about:blank",
        "data:text/html,challenges.cloudflare.com",
        "http://challenges.cloudflare.com/widget",
        "https://challenges.cloudflare.com:444/widget",
        "https://user:pass@challenges.cloudflare.com/widget",
        "https://challenges.cloudflare.com:bad/widget",
    ],
)
def test_spoofed_cloudflare_frame_host_is_never_queried_or_clicked(url):
    frame = _Frame(_Element(), url=url)
    page = _LocatorPage(frames=[frame])
    assert asyncio.run(turnstile.find_checkbox(page)) is None
    assert asyncio.run(turnstile.click(page)) is False
    assert frame.queries == 0
    assert frame.owner_queries == 0
    assert page.clicks == 0


def test_single_hanging_frame_cannot_consume_query_budget(monkeypatch):
    first = _Frame(_Element())
    first.hang = True
    second = _Frame(_Element())
    page = _LocatorPage(frames=[first, second])
    # 第一帧会超时，但要给后续正常帧留足 Windows 调度余量。
    monkeypatch.setattr(turnstile, "_FRAME_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(turnstile, "_QUERY_TIMEOUT_SECONDS", 2.0)
    assert asyncio.run(turnstile.find_checkbox(page)) == {**CHECKBOX, "kind": "checkbox"}
    assert first.queries == second.queries == 1


@pytest.mark.parametrize(
    "box",
    [
        {**CHECKBOX, "x": float("nan")},
        {**CHECKBOX, "y": float("inf")},
        {**CHECKBOX, "width": 0},
        {**CHECKBOX, "height": -1},
        {**CHECKBOX, "x": -100},
        {**CHECKBOX, "x": 1279},
        {**CHECKBOX, "y": 719},
        {**CHECKBOX, "width": True},
        {**CHECKBOX, "x": "412"},
        {"kind": "checkbox"},
    ],
)
def test_invalid_or_offscreen_box_does_not_emit_mouse_input(box):
    page = _LocatorPage()
    assert asyncio.run(turnstile.click(page, box={**box, "kind": "checkbox"})) is False
    assert not page.events


def test_explicit_widget_box_keeps_legacy_offset_without_relocating():
    page = _LocatorPage()
    assert asyncio.run(turnstile.click(page, box=BOX)) is True
    assert page.click_positions == [(130.0, 232.5)]
    assert page.main_queries == page.fallback_queries == 0


def test_delayed_cf_frame_is_located_after_initial_absence(monkeypatch):
    page = _LocatorPage()
    original_wait = page.wait_for_timeout

    async def wait(ms):
        await original_wait(ms)
        if len(page.waits) == 3:
            page.frames.append(_Frame(_Element()))
        await asyncio.sleep(0.001)

    page.wait_for_timeout = wait
    monkeypatch.setattr(turnstile, "_RETRY_GAP_SECONDS", 0.001)
    assert asyncio.run(turnstile.solve(page, timeout_ms=5000)) == "tk"
    assert page.clicks == 1
    assert page.click_positions == [(424.0, 245.0)]


def test_completed_predicate_exits_without_fabricating_token():
    page = _LocatorPage(token_after_clicks=None)
    checks = []

    async def completed():
        checks.append(True)
        return len(page.waits) >= 2

    token = asyncio.run(turnstile.solve(page, timeout_ms=1000, completed=completed))
    assert token == ""
    assert page._token == ""
    assert len(page.waits) == 2
    assert len(checks) == 3
    assert page.clicks == 0


def test_completed_page_does_not_receive_a_checkbox_click():
    page = _LocatorPage(checkbox=_Element())

    async def completed():
        return True

    assert asyncio.run(turnstile.solve(page, timeout_ms=500, completed=completed)) == ""
    assert page.clicks == 0
    assert page.main_queries == 0


def test_completed_after_click_returns_empty_instead_of_waiting_for_token():
    page = _LocatorPage(frames=[_Frame(_Element())], token_after_clicks=None)

    async def completed():
        return page.clicks == 1

    assert asyncio.run(turnstile.solve(page, timeout_ms=1000, completed=completed)) == ""
    assert page.clicks == 1
    assert page._token == ""
    assert page.waits == [], "一步移动后立即 click，放行后无需空等"


@pytest.mark.parametrize("timeout_ms", [0, -1])
def test_exhausted_solve_budget_does_not_start_any_browser_operation(timeout_ms):
    page = _LocatorPage(checkbox=_Element())
    assert asyncio.run(turnstile.solve(page, timeout_ms=timeout_ms)) == ""
    assert page.script_tags == page.main_queries == page.clicks == 0


def test_actual_frame_checkbox_is_not_reclicked_while_processing(monkeypatch):
    checkbox = _Element()
    frame = _Frame(checkbox)
    page = _LocatorPage(frames=[frame], token_after_clicks=None)
    original_click = page.on_click

    def on_click():
        original_click()
        frame.processing = True
        checkbox.checked = True

    page.on_click = on_click
    assert _solve_virtual(page, monkeypatch, timeout_ms=1000) == ""
    assert page.clicks == 1
    assert frame.queries == 2  # 初次定位 + 移动后的选中 frame 重验；处理中不再查找/点击。


# ── 6. 每个入口的有限等待与 solve 硬截止（不启动浏览器）──────────────────────
@pytest.mark.parametrize(
    "operation", ["evaluate", "add_script_tag", "evaluate_handle", "wait_for_timeout", "move", "click", "completed"]
)
def test_solve_hard_deadline_includes_every_browser_rpc(operation, monkeypatch):
    # RPC 预算故意远大于整体预算，避免把某个 helper 的超时误当成 solve 硬截止。
    # 给 Windows 并行调度留足一秒；仍小于 5s RPC 上限，并核对提交的整体截止。
    for name in ("_OPERATION_TIMEOUT_SECONDS", "_FRAME_TIMEOUT_SECONDS", "_QUERY_TIMEOUT_SECONDS"):
        monkeypatch.setattr(turnstile, name, 5.0)
    bounded = turnstile._bounded
    budgets = []

    async def recording_bounded(awaitable, seconds):
        budgets.append((seconds, min(seconds, turnstile._remaining())))
        return await bounded(awaitable, seconds)

    monkeypatch.setattr(turnstile, "_bounded", recording_bounded)

    async def scenario():
        page = _LocatorPage(checkbox=_Element(), token_after_clicks=None)
        cancelled = asyncio.Event()

        async def hung(*args, **kwargs):
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        kwargs = {}
        if operation == "completed":
            kwargs["completed"] = hung
        elif operation in {"move", "click"}:
            setattr(page.mouse, operation, hung)
        else:
            setattr(page, operation, hung)
        loop = asyncio.get_running_loop()
        start = loop.time()
        assert await asyncio.wait_for(turnstile.solve(page, timeout_ms=1000, **kwargs), timeout=5) == ""
        assert budgets[0][0] == 1.0
        assert all(effective <= 1.0 for _requested, effective in budgets), "所有子操作只能使用整体剩余预算"
        assert loop.time() - start < 4.0, "1s 整体截止不能被 5s RPC 预算替代"
        await asyncio.wait_for(cancelled.wait(), 3)

    asyncio.run(scenario())


@pytest.mark.parametrize("entrypoint", ["read_token", "install_token_bridge", "find_checkbox", "find_box"])
def test_standalone_helpers_also_have_short_operation_limits(entrypoint, monkeypatch):
    async def hung(*args, **kwargs):
        await asyncio.Future()

    page = _LocatorPage()
    page.evaluate = page.evaluate_handle = page.add_script_tag = hung
    monkeypatch.setattr(turnstile, "_OPERATION_TIMEOUT_SECONDS", 0.02)
    monkeypatch.setattr(turnstile, "_FRAME_TIMEOUT_SECONDS", 0.02)
    monkeypatch.setattr(turnstile, "_QUERY_TIMEOUT_SECONDS", 0.04)

    async def scenario():
        start = asyncio.get_running_loop().time()
        result = await getattr(turnstile, entrypoint)(page)
        assert result is None or result == ""
        # 保留短操作预算，墙钟只用于发现无界等待；给 Windows 调度留出余量。
        assert asyncio.get_running_loop().time() - start < 1.0

    asyncio.run(scenario())


def test_solve_does_not_wait_for_slow_cancellation_cleanup():
    async def scenario():
        page = _LocatorPage()
        release = asyncio.Event()
        cancelling = asyncio.Event()

        async def delayed_cancel(*args, **kwargs):
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancelling.set()
                await release.wait()
                raise

        page.evaluate = delayed_cancel
        task = asyncio.create_task(turnstile.solve(page, timeout_ms=500))
        try:
            # Windows/并发测试调度留余量；关键是清理仍被锁住时 solve 已独立返回。
            done, _ = await asyncio.wait({task}, timeout=3)
            assert task in done, "solve 的超时不能等待 RPC 的取消清理"
            assert task.result() == ""
            assert not release.is_set()
            await asyncio.wait_for(cancelling.wait(), 3)
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.sleep(0)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "entrypoint", ["read_token", "install_token_bridge", "find_checkbox", "find_box", "click", "solve"]
)
def test_external_cancelled_error_is_never_swallowed(entrypoint):
    async def scenario():
        page = _LocatorPage()
        entered = asyncio.Event()

        async def hung(*args, **kwargs):
            entered.set()
            await asyncio.Future()

        page.evaluate = page.evaluate_handle = page.add_script_tag = hung
        kwargs = {"timeout_ms": 5000} if entrypoint == "solve" else {}
        task = asyncio.create_task(getattr(turnstile, entrypoint)(page, **kwargs))
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())


# ── 7. 运行真实查询脚本的 mock DOM（仅 Node，不加载 Playwright/浏览器）───────
# 优先复用 Playwright 随包 Node，不添加 JS DOM 库依赖。该模型只有测试所需的 DOM
# 结构、CSS/属性和几何数据；查询/跨 shadow 遍历/安全过滤运行的是生产脚本本身。
_DOM_RUNNER_JS = r"""
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const output = {};
for (const item of input.cases) {
    const document = {nodeType: 9, children: [], baseURI: item.url || 'https://login.example/'};
    function element(spec, parent, root) {
        const attrs = spec.attrs || {};
        const el = {
            nodeType: 1, tagName: (spec.tag || 'div').toUpperCase(), parentElement: parent,
            children: [], shadowRoot: null, isConnected: !spec.detached,
            checked: !!spec.checked, indeterminate: !!spec.indeterminate, disabled: !!spec.disabled,
            hidden: !!spec.hidden, inert: !!spec.inert, src: attrs.src || '',
            getRootNode: () => root,
            getAttribute: name => Object.hasOwn(attrs, name) ? String(attrs[name]) : null,
            getBoundingClientRect: () => spec.box || {x: 20, y: 20, width: 24, height: 24},
            matches: selector => selector.split(',').some(part => {
                const s = part.trim();
                if (s === ':disabled') {
                    for (let node = el; node; node = node.parentElement) if (node.disabled) return true;
                    return false;
                }
                const tag = s.match(/^[a-z]+/i);
                if (tag && el.tagName !== tag[0].toUpperCase()) return false;
                const id = s.match(/#([\w-]+)/);
                if (id && attrs.id !== id[1]) return false;
                const cls = s.match(/\.([\w-]+)/);
                if (cls && !(attrs.class || '').split(/\s+/).includes(cls[1])) return false;
                for (const match of s.matchAll(/\[([\w-]+)(?:(\^?=)"([^"]*)")?\]/g)) {
                    const value = attrs[match[1]];
                    if (value === undefined) return false;
                    if (match[2] === '=' && String(value) !== match[3]) return false;
                    if (match[2] === '^=' && !String(value).startsWith(match[3])) return false;
                }
                return true;
            }),
            style: {display: 'block', visibility: 'visible', opacity: '1', pointerEvents: 'auto', ...spec.style},
        };
        el.children = (spec.children || []).map(child => element(child, el, root));
        if (spec.shadow) {
            const shadow = {nodeType: 11, host: el, children: []};
            shadow.children = spec.shadow.map(child => element(child, null, shadow));
            if (!spec.closed) el.shadowRoot = shadow;
        }
        return el;
    }
    document.children = item.nodes.map(node => element(node, null, document));
    const window = {
        innerWidth: 1280, innerHeight: 720, location: {href: document.baseURI},
        getComputedStyle: el => el.style,
    };
    const checkbox = eval('(' + input.checkbox + ')')(!!item.trusted);
    const fallback = eval('(' + input.fallback + ')')(item.scanIframes !== false);
    const state = eval('(' + input.state + ')')(!!item.trusted);
    output[item.name] = {checkbox: checkbox ? checkbox.getAttribute('id') : null, fallback, state};
}
process.stdout.write(JSON.stringify(output));
"""


def _dom_checkbox(**changes):
    return {"tag": "input", "attrs": {"type": "checkbox", "id": "cb"}, "box": CHECKBOX, **changes}


def _dom_container(*children, **changes):
    return {"attrs": {"class": "cf-turnstile"}, "box": BOX, "children": list(children), **changes}


_DOM_CASES = [
    {"name": "remember-me", "nodes": [_dom_checkbox()]},
    {"name": "foreign-sitekey", "nodes": [_dom_container(_dom_checkbox(), attrs={"data-sitekey": "hcaptcha"})]},
    {"name": "foreign-service", "nodes": [_dom_container(attrs={"class": "h-captcha", "data-sitekey": "key"})]},
    {"name": "open-shadow", "nodes": [_dom_container(shadow=[_dom_checkbox()])], "expected": "cb"},
    {"name": "nested-open-shadow", "nodes": [_dom_container(shadow=[{"shadow": [_dom_checkbox()]}])], "expected": "cb"},
    {"name": "unscoped-shadow", "nodes": [{"shadow": [_dom_checkbox()]}]},
    {"name": "checked", "nodes": [_dom_container(_dom_checkbox(checked=True))]},
    {"name": "disabled", "nodes": [_dom_container(_dom_checkbox(disabled=True))]},
    {
        "name": "disabled-fieldset",
        "nodes": [_dom_container({"tag": "fieldset", "disabled": True, "children": [_dom_checkbox()]})],
    },
    {"name": "hidden", "nodes": [_dom_container(_dom_checkbox(style={"display": "none"}))]},
    {"name": "opacity-zero", "nodes": [_dom_container(_dom_checkbox(style={"opacity": "0.0"}))]},
    {"name": "hidden-shadow-host", "nodes": [_dom_container(shadow=[_dom_checkbox()], style={"visibility": "hidden"})]},
    {"name": "indeterminate", "nodes": [_dom_container(_dom_checkbox(indeterminate=True))]},
    {
        "name": "aria-disabled-ancestor",
        "nodes": [_dom_container(_dom_checkbox(), attrs={"class": "cf-turnstile", "aria-disabled": "true"})],
    },
    {"name": "busy", "nodes": [_dom_container(_dom_checkbox(), {"attrs": {"role": "progressbar"}})]},
    {"name": "success", "nodes": [_dom_container(_dom_checkbox(), {"attrs": {"id": "success"}})]},
    {
        "name": "aria-checkbox",
        "nodes": [_dom_container({"attrs": {"role": "checkbox", "aria-checked": "false", "id": "cb"}})],
        "expected": "cb",
    },
    {"name": "aria-mixed", "nodes": [_dom_container({"attrs": {"role": "checkbox", "aria-checked": "mixed"}})]},
    {"name": "aria-unknown", "nodes": [_dom_container({"attrs": {"role": "checkbox"}})]},
    {"name": "offscreen", "nodes": [_dom_container(_dom_checkbox(box={**CHECKBOX, "x": 1300}))]},
    {"name": "widget-open-shadow", "nodes": [{"shadow": [_dom_container()]}], "expected_box": BOX},
    {
        "name": "token-parent",
        "nodes": [{"box": BOX, "children": [{"tag": "input", "attrs": {"name": "cf-turnstile-response-id"}}]}],
        "expected_box": BOX,
    },
    {
        "name": "token-parent-login-checkbox",
        "nodes": [
            {"box": BOX, "children": [_dom_checkbox(), {"tag": "input", "attrs": {"name": "cf-turnstile-response"}}]}
        ],
    },
    {
        "name": "whole-login-form",
        "nodes": [
            {"box": {**BOX, "height": 500}, "children": [{"tag": "input", "attrs": {"name": "cf-turnstile-response"}}]}
        ],
    },
    {"name": "trusted-iframe", "nodes": [{"tag": "iframe", "attrs": {"src": CF_URL}, "box": BOX}], "expected_box": BOX},
    {
        "name": "frames-authoritative",
        "nodes": [_dom_container({"tag": "iframe", "attrs": {"src": CF_URL}, "box": BOX})],
        "scanIframes": False,
    },
    {"name": "trusted-frame-document", "nodes": [_dom_checkbox()], "trusted": True, "url": CF_URL, "expected": "cb"},
    {"name": "navigated-frame-document", "nodes": [_dom_checkbox()], "trusted": True, "url": "https://evil.example/"},
]
for _index, _url in enumerate(
    [
        "https://challenges.cloudflare.com.evil.example/widget",
        "https://evil.example/challenges.cloudflare.com",
        "https://challenges.cloudflare.com@evil.example/",
        "https://evil.challenges.cloudflare.com/",
        "about:blank",
    ]
):
    _iframe = {"tag": "iframe", "attrs": {"src": _url, "title": "Cloudflare"}, "box": BOX}
    _DOM_CASES.extend(
        [
            {"name": f"spoofed-iframe-{_index}", "nodes": [_iframe]},
            {"name": f"spoofed-widget-{_index}", "nodes": [_dom_container(_iframe)]},
        ]
    )


_DOM_CASES.extend([
    {"name": "state-empty-cf-frame", "nodes": [], "trusted": True, "url": CF_URL,
     "state_reason": "frame_owner_ready", "allow_fallback": True},
    {"name": "state-hidden-frame-checkbox", "nodes": [_dom_checkbox(hidden=True)], "trusted": True,
     "url": CF_URL, "state_reason": "checkbox_unusable"},
    {"name": "state-disabled-frame-checkbox", "nodes": [_dom_checkbox(disabled=True)], "trusted": True,
     "url": CF_URL, "state_reason": "checkbox_unusable"},
    {"name": "state-checked-frame-checkbox", "nodes": [_dom_checkbox(checked=True)], "trusted": True,
     "url": CF_URL, "state_reason": "processing", "processing": True},
    {"name": "state-busy-no-checkbox", "nodes": [{"attrs": {"aria-busy": "true"}}], "trusted": True,
     "url": CF_URL, "state_reason": "processing", "processing": True},
    {"name": "state-success-no-checkbox", "nodes": [{"attrs": {"id": "success"}}], "trusted": True,
     "url": CF_URL, "state_reason": "processing", "processing": True},
])


@pytest.fixture(scope="module")
def dom_query_results():
    node = shutil.which("node")
    if node is None:
        spec = importlib.util.find_spec("playwright")
        if spec is not None and spec.origin:
            driver = Path(spec.origin).parent / "driver"
            node = next((str(path) for path in (driver / "node.exe", driver / "node") if path.is_file()), None)
    if node is None:
        pytest.skip("mock DOM 脚本需要 Node（可复用 Playwright 自带 Node），不启动浏览器")
    payload = {"checkbox": turnstile._FIND_CHECKBOX_JS, "fallback": turnstile._FIND_BOX_JS,
               "state": turnstile._PROBE_STATE_JS, "cases": _DOM_CASES}
    assert "attachShadow" not in payload["checkbox"] + payload["fallback"]
    result = subprocess.run(
        [node, "-e", _DOM_RUNNER_JS], input=json.dumps(payload), text=True, capture_output=True, check=True, timeout=10
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("case", _DOM_CASES, ids=[case["name"] for case in _DOM_CASES])
def test_real_query_scripts_on_mock_dom(case, dom_query_results):
    actual = dom_query_results[case["name"]]
    assert actual["checkbox"] == case.get("expected")
    assert actual["fallback"] == case.get("expected_box")
    if case.get("state_reason"):
        assert actual["state"]["reason"] == case["state_reason"]
        assert actual["state"]["fallback_allowed"] is case.get("allow_fallback", False)
        assert actual["state"]["processing"] is case.get("processing", False)


# ── 8. 统一 probe / 分阶段诊断 / 有限重试（虚拟时钟，不依赖 Windows 亚秒调度） ──
def _solve_virtual(page, monkeypatch, *, timeout_ms=5000, diagnostics=None, completed=None):
    async def scenario():
        loop = asyncio.get_running_loop()
        clock = [loop.time()]
        wait = page.wait_for_timeout

        async def advance(ms):
            await wait(ms)
            clock[0] += ms / 1000

        page.wait_for_timeout = advance
        with monkeypatch.context() as patch:
            patch.setattr(loop, "time", lambda: clock[0])
            return await turnstile.solve(page, timeout_ms=timeout_ms, poll_interval_ms=250,
                                         diagnostics=diagnostics, completed=completed)

    return asyncio.run(scenario())


@pytest.mark.parametrize("checkbox,state,reason", [
    (None, "ready", "ready"),
    (_Element(visible=False), "hidden", "checkbox_unusable"),
    (_Element(disabled=True), "disabled", "checkbox_unusable"),
    (_Element(checked=True), "checked", "processing"),
    (None, "processing", "processing"),
])
def test_probe_exposes_safe_target_kind_processing_and_reason(checkbox, state, reason):
    frame = _Frame(checkbox)
    frame.processing = state == "processing"
    page = _LocatorPage(frames=[frame])
    result = asyncio.run(turnstile.probe(page))
    assert result["reason"] == reason
    assert result["processing"] is (state in {"checked", "processing"})
    assert result["present"] is True
    assert result["target_kind"] == ("frame_owner" if state == "ready" else None)
    assert result["target"] == (OWNER if state == "ready" else None)


def test_probe_prioritizes_real_checkbox_over_earlier_fallback_frame():
    first, second = _Frame(), _Frame(_Element())
    page = _LocatorPage(frames=[first, second])
    result = asyncio.run(turnstile.probe(page))
    assert result["target_kind"] == "checkbox"
    assert result["target"] == {**CHECKBOX, "kind": "checkbox"}
    assert first.owner_queries == 0


def test_probe_does_not_forget_processing_when_later_frame_is_empty():
    first, second = _Frame(_Element(checked=True)), _Frame()
    result = asyncio.run(turnstile.probe(_LocatorPage(frames=[first, second])))
    assert result["target"] is None
    assert result["processing"] is True
    assert result["reason"] == "processing"


def test_empty_widget_container_cannot_be_clicked_as_a_guess():
    page = _LocatorPage(fallback=BOX)
    assert asyncio.run(turnstile.find_box(page)) is None
    assert asyncio.run(turnstile.click(page)) is False
    assert not page.events
    assert page.fallback_queries == 0


@pytest.mark.parametrize("change", ["processing", "checked", "hidden", "moved", "untrusted", "detached"])
def test_movement_revalidates_target_before_emitting_click(change):
    element = _Element()
    frame = _Frame(element)
    page = _LocatorPage(frames=[frame])
    original_move = page.mouse.move

    async def move(*args, **kwargs):
        await original_move(*args, **kwargs)
        if change == "processing":
            frame.processing = True
        elif change == "checked":
            element.checked = True
        elif change == "hidden":
            element.visible = False
        elif change == "moved":
            element.box["x"] += 20
        elif change == "untrusted":
            frame.url = "https://challenges.cloudflare.com.evil.example/widget"
        else:
            frame.detached = True

    page.mouse.move = move
    data = {}
    assert asyncio.run(turnstile.click(page, diagnostics=data)) is False
    assert not data["clicked"] and data["moved"] and not data["click_started"]
    assert data["reason"] == "target_changed"
    assert page.clicks == 0


def test_slow_mouse_uses_one_step_and_logs_only_completed_phases(monkeypatch):
    async def scenario():
        page = _LocatorPage(frames=[_Frame()])
        loop = asyncio.get_running_loop()
        clock = [loop.time()]
        steps_seen = []
        logs, data = [], {}
        original_click = page.mouse.click

        async def move(x, y, steps=1):
            steps_seen.append(steps)
            clock[0] += steps * 0.45  # 原 8+12 步会耗 9 秒，3 秒预算内无法 click。

        async def click(x, y):
            clock[0] += 0.2
            await original_click(x, y)

        page.mouse.move, page.mouse.click = move, click
        with monkeypatch.context() as patch:
            patch.setattr(loop, "time", lambda: clock[0])
            assert await turnstile.solve(page, timeout_ms=3000, diagnostics=data, log=logs.append) == "tk"
        assert steps_seen == [1]
        assert data["clicked"] and data["moved"] and data["click_started"]
        assert data["target_kind"] == "frame_owner"
        assert data["stage"] == "complete" and data["reason"] == "token_issued"
        located = next(i for i, line in enumerate(logs) if "已定位" in line)
        moved = next(i for i, line in enumerate(logs) if "移动已完成" in line)
        clicked = next(i for i, line in enumerate(logs) if "真实鼠标点击已完成" in line)
        assert located < moved < clicked

    asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["move", "click"])
def test_stalled_mouse_reports_exact_timeout_phase_without_claiming_click(operation, monkeypatch):
    from unittest.mock import AsyncMock

    async def scenario():
        page = _LocatorPage(frames=[_Frame()])
        data, logs = {}, []

        async def hung(*args, **kwargs):
            await asyncio.Future()

        setattr(page.mouse, operation, AsyncMock(side_effect=hung))
        monkeypatch.setattr(turnstile, "_OPERATION_TIMEOUT_SECONDS", 0.1)
        assert not await asyncio.wait_for(turnstile.click(page, timeout_ms=4000, diagnostics=data,
                                                         log=logs.append), timeout=5)
        assert data["timeout_stage"] == operation and data["reason"] == "timeout"
        assert data["clicked"] is False
        assert data["moved"] is (operation == "click")
        assert data["click_started"] is (operation == "click")
        assert not any("真实鼠标点击已完成" in line for line in logs)

    asyncio.run(scenario())


def test_frame_replacement_can_click_once_more_but_same_frame_never_repeats(monkeypatch):
    first, second = _Frame(_Element()), _Frame(_Element())
    page = _LocatorPage(frames=[first], token_after_clicks=2)
    wait = page.wait_for_timeout

    async def replace(ms):
        await wait(ms)
        if len(page.waits) == 2:
            first.detached = True
            page.frames[:] = [second]

    page.wait_for_timeout = replace
    data = {}
    assert _solve_virtual(page, monkeypatch, diagnostics=data) == "tk"
    assert page.clicks == data["attempts"] == 2


@pytest.mark.parametrize("phase", ["move", "click"])
def test_only_definitely_unclicked_mouse_failure_is_retried(phase, monkeypatch):
    page = _LocatorPage(frames=[_Frame()], token_after_clicks=1)
    original = getattr(page.mouse, phase)
    calls = []

    async def fail_once(*args, **kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("private-token-do-not-log")
        await original(*args, **kwargs)

    setattr(page.mouse, phase, fail_once)
    data = {}
    token = _solve_virtual(page, monkeypatch, diagnostics=data)
    assert token == ("tk" if phase == "move" else "")
    assert len(calls) == (2 if phase == "move" else 1)
    assert data["attempts"] == len(calls)
    assert "private-token" not in str(data)


def test_already_cleared_page_does_not_even_read_a_stalled_token(monkeypatch):
    from unittest.mock import AsyncMock

    page = _LocatorPage(frames=[_Frame()])
    page.evaluate = AsyncMock(side_effect=AssertionError("放行后不应读取 token 或 probe"))
    data = {}
    assert _solve_virtual(page, monkeypatch, completed=AsyncMock(return_value=True), diagnostics=data) == ""
    assert data["reason"] == "page_cleared"
    page.evaluate.assert_not_awaited()
    assert page.script_tags == page.clicks == 0


def test_probe_cleanup_timeout_keeps_result_and_cancels_disposal(monkeypatch):
    async def scenario():
        element = _Element()
        page = _LocatorPage(checkbox=element)
        cancelled = asyncio.Event()

        async def dispose():
            try:
                await asyncio.Future()
            finally:
                cancelled.set()

        element.dispose = dispose
        result = await asyncio.wait_for(turnstile.probe(page, timeout_ms=3000), timeout=4)
        assert result["target_kind"] == "checkbox"
        await asyncio.wait_for(cancelled.wait(), timeout=2)

    asyncio.run(scenario())


@pytest.mark.parametrize("entrypoint", ["probe", "click", "solve"])
def test_absolute_expired_deadline_performs_no_browser_rpc(entrypoint):
    async def scenario():
        page = _LocatorPage(frames=[_Frame()])
        kwargs = {"timeout_ms": 5000} if entrypoint == "solve" else {}
        result = await getattr(turnstile, entrypoint)(page, deadline=asyncio.get_running_loop().time() - 1, **kwargs)
        assert result in (False, "") or isinstance(result, dict) and result["target"] is None
        assert page.main_queries == page.script_tags == page.clicks == 0
        assert page.frames[0].queries == page.frames[0].owner_queries == 0

    asyncio.run(scenario())
