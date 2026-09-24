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
        self.waits: list[int] = []
        # 按发生顺序记录 move / click / wait：区分「点击手势内部的短等待」和
        # 「轮询空等」，否则无法断言「首次点击前没有空等一轮」。
        self.events: list[tuple[str, int]] = []
        self.script_tags = 0
        self.mouse = _FakeMouse(self)

    # -- turnstile 依赖的 page 接口 --
    async def add_script_tag(self, *, content: str = "") -> None:
        # solve() 开头会注入令牌桥接脚本；这里只计数，不执行。
        self.script_tags += 1

    async def evaluate(self, expr: str, arg=None):
        # 顺序与真实脚本一致：_FIND_BOX_JS 里也含 cf-turnstile-response。
        if "getBoundingClientRect" in expr:
            return BOX if self._has_widget else None
        if "cf-turnstile-response" in expr:
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
