# -*- coding: utf-8 -*-
"""Cloudflare / Turnstile 处理策略回归测试。

守护三条曾出问题的语义：
1. 检测覆盖：新版 managed challenge、JS/cookie 提示页、challenge-platform iframe
   等变体必须被识别为挑战页。旧实现只认 "Just a moment" / "Checking your browser"，
   漏判时 solve_cloudflare 直接返回 True，调用方在仍被拦截的页面上继续操作。
2. 交互式 widget 必须走真实鼠标点击（Cloudflare 校验事件 isTrusted），
   被动等待与 ClickSolver 的 interstitial 策略都拿不到令牌。
3. 不谎报成功：拿到令牌 ≠ 挑战已通过，必须回读页面确认后才返回 True。
"""

from __future__ import annotations

import asyncio

import pytest

from browser import bypass, turnstile, waf


# ── 检测覆盖 ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("title", "html", "expected"),
    [
        ("Just a moment...", "<html><body>please wait</body></html>", True),
        ("", "<html><body>Checking your browser before accessing</body></html>", True),
        # 新版 managed challenge：旧词表漏判
        ("Just a moment...", "<html><body>Verifying you are human</body></html>", True),
        ("", "<html><body>Enable JavaScript and cookies to continue</body></html>", True),
        ("", '<html><body><div id="cf-chl-widget"></div></body></html>', True),
        ("Attention Required!", "<html><body>blocked</body></html>", True),
        ("", '<html><body><div class="cf-wrapper">blocked</div></body></html>', True),
        ("", '<html><body><form id="challenge-form"></form></body></html>', True),
        # 正常页面不得误判
        ("Dashboard", "<html><body>welcome back</body></html>", False),
        ("极速蹬", "<html><body>余额 $1.00</body></html>", False),
        # challenge-platform 是「受 CF 保护」的环境脚本，正常页面同样会加载它，
        # 不能作为挑战页判据。实测 Linux DO 授权页（title="authorize - linux do
        # connect"，无任何 CF 容器）仅因含该脚本就被误报「检测到 Cloudflare 挑战」，
        # 白跑一轮 ClickSolver 并掩盖真实失败原因。
        ("authorize - linux do connect", '<html><body><script src="/cdn-cgi/challenge-platform/x.js"></script></body></html>', False),
        # 含 hCaptcha widget 的正常业务页同样不得误判
        ("签到 - 福利站", '<html><body><iframe src="https://newassets.hcaptcha.com/captcha/v1/x"></iframe></body></html>', False),
    ],
)
def test_cf_challenge_detection_covers_modern_variants(title: str, html: str, expected: bool) -> None:
    assert bypass._is_cf_challenge(title.lower(), html.lower()) is expected


@pytest.mark.parametrize(
    ("html", "expected"),
    [
        ('<input name="cf-turnstile-response">', True),
        ('<div class="turnstile-container"></div>', True),
        ('<iframe src="https://challenges.cloudflare.com/turnstile/v0/api.js"></iframe>', True),
        # interstitial 页没有可点复选框
        ("<html><body>Verifying you are human</body></html>", False),
        ("<html><body>welcome</body></html>", False),
    ],
)
def test_interactive_widget_detection(html: str, expected: bool) -> None:
    assert bypass._has_interactive_widget(html.lower()) is expected


# ── 伪造 Page ───────────────────────────────────────────────────────────────
class FakeMouse:
    """记录真实鼠标事件；click 通知 page 签发令牌。"""

    def __init__(self) -> None:
        self.clicks: list[tuple[float, float]] = []
        self.moves: list[tuple[float, float]] = []
        self.page: "FakePage | None" = None

    async def move(self, x: float, y: float, steps: int = 1) -> None:
        self.moves.append((x, y))

    async def click(self, x: float, y: float) -> None:
        self.clicks.append((x, y))
        if self.page is not None:
            self.page.on_click()


class FakePage:
    def __init__(
        self,
        title: str,
        html: str,
        *,
        clears_after_click: bool = True,
        clear_after_waits: int | None = None,
        token: str = "real-turnstile-token",
    ) -> None:
        self._title = title
        self._html = html
        self._clears = clears_after_click
        self._clear_after_waits = clear_after_waits
        self._wait_count = 0
        self._issue = token
        self._token = ""
        self.mouse = FakeMouse()
        self.mouse.page = self

    def on_click(self) -> None:
        self._token = self._issue
        if self._clears:
            self._title = "Dashboard"
            self._html = "<html><body>ok</body></html>"

    async def title(self) -> str:
        return self._title

    async def content(self) -> str:
        return self._html

    async def evaluate(self, expr: str, arg=None):
        # 顺序关键：_FIND_BOX_JS 里同时含 cf-turnstile-response，
        # 必须先判 getBoundingClientRect，否则 find_box 会拿到令牌字符串。
        if "getBoundingClientRect" in expr:
            return {"x": 100.0, "y": 200.0, "width": 300.0, "height": 65.0}
        if "cf-turnstile-response" in expr:
            return self._token
        return None

    async def wait_for_timeout(self, ms: int) -> None:
        del ms
        self._wait_count += 1
        if self._clear_after_waits is not None and self._wait_count >= self._clear_after_waits:
            self._title = "Dashboard"
            self._html = "<html><body>ok</body></html>"
        await asyncio.sleep(0)


# ── turnstile 真实点击 ──────────────────────────────────────────────────────
def test_turnstile_clicks_checkbox_at_measured_offset() -> None:
    """复选框在 widget 左侧 30px、垂直居中（实测结论），且必须用真实鼠标事件。"""
    page = FakePage("Sign in", '<input name="cf-turnstile-response">')

    token = asyncio.run(turnstile.solve(page, timeout_ms=2000, poll_interval_ms=20))

    assert token == "real-turnstile-token"
    assert page.mouse.clicks == [(130.0, 232.5)]  # x+30, y+height/2
    assert page.mouse.moves, "点击前应有人类化鼠标移动轨迹"


def test_turnstile_returns_empty_on_timeout_without_token() -> None:
    page = FakePage("Sign in", '<input name="cf-turnstile-response">', token="")

    token = asyncio.run(turnstile.solve(page, timeout_ms=200, poll_interval_ms=20))

    assert token == ""


def test_waf_solver_uses_existing_interactive_cloudflare_click(monkeypatch) -> None:
    page = FakePage(
        "Just a moment...",
        '<input name="cf-turnstile-response">',
    )
    logs: list[str] = []
    calls: list[tuple[int, int]] = []

    async def fake_goto(*_args, **_kwargs) -> None:
        return None

    async def fake_find_box(_page):
        return {"x": 100, "y": 200, "width": 300, "height": 65}

    async def fake_solve(_page, *, timeout_ms: int, poll_interval_ms: int, log) -> str:
        calls.append((timeout_ms, poll_interval_ms))
        _page.on_click()
        log("真实点击完成")
        return "real-turnstile-token"

    monkeypatch.setattr(waf, "safe_goto", fake_goto)
    monkeypatch.setattr(turnstile, "find_box", fake_find_box)
    monkeypatch.setattr(turnstile, "solve", fake_solve)

    assert asyncio.run(waf.solve_waf(page, "https://site.invalid", logs.append, rounds=1)) is True
    assert calls == [(20_000, 250)]
    assert "真实点击完成" in logs
def test_interactive_challenge_uses_real_mouse_click(monkeypatch) -> None:
    """交互式 widget 必须真实点击，而不是被动等待签发。"""
    monkeypatch.setattr(bypass, "_check_camoufox", lambda: None)
    page = FakePage("Sign in", '<div class="turnstile-container"><input name="cf-turnstile-response"></div>')
    logs: list[str] = []

    ok = asyncio.run(bypass.solve_cloudflare(page, log=logs.append, wait_seconds=1))

    assert ok is True
    assert len(page.mouse.clicks) == 1
    assert any("真实鼠标点击" in line for line in logs)


def test_no_challenge_page_is_passed_through_without_clicking(monkeypatch) -> None:
    monkeypatch.setattr(bypass, "_check_camoufox", lambda: None)
    page = FakePage("Dashboard", "<html><body>welcome</body></html>")
    logs: list[str] = []

    ok = asyncio.run(bypass.solve_cloudflare(page, log=logs.append, wait_seconds=1))

    assert ok is True
    assert page.mouse.clicks == []
    assert logs == []


def test_fullscreen_interstitial_clears_by_passive_wait_without_click(monkeypatch) -> None:
    """全屏 interstitial（"Just a moment"）自动放行时应被动等待通过，绝不点击。

    这类 managed challenge 内嵌的 turnstile 由 Cloudflare 自动执行，放行体现为
    页面级跳转/刷新，而非写入 cf-turnstile-response。实测 connect.linux.do 授权页
    约 40 秒自行放行；此时若去点那个自动 widget，反而可能重置校验、错过放行窗口
    （生产表现为反复「已点击复选框…挑战未通过」最终误判 need_verification）。
    因此必须先被动等待自动放行，不点击。
    """
    monkeypatch.setattr(bypass, "_check_camoufox", lambda: None)
    page = FakePage(
        "Just a moment...",
        '<div class="turnstile-container"><input name="cf-turnstile-response"></div>',
        clear_after_waits=2,
    )
    logs: list[str] = []

    ok = asyncio.run(bypass.solve_cloudflare(page, log=logs.append, wait_seconds=1))

    assert ok is True
    assert page.mouse.clicks == [], "interstitial 自动放行不应点击内嵌 widget"
    assert any("自动放行" in line for line in logs)


def test_token_issued_but_page_still_blocked_is_not_success(monkeypatch) -> None:
    """拿到令牌 ≠ 挑战已通过：页面仍是挑战页时必须返回 False。

    旧实现在交互式分支拿到令牌就 return True，导致调用方在仍被拦截的页面上
    继续操作（表现为后续读额度/点签到全部失败但报「已通过」）。
    """
    monkeypatch.setattr(bypass, "_check_camoufox", lambda: None)
    page = FakePage(
        "Just a moment...",
        '<div class="turnstile-container"><input name="cf-turnstile-response"></div>',
        clears_after_click=False,
    )
    logs: list[str] = []

    async def checkbox(_page):
        return {"x": 100, "y": 200, "width": 20, "height": 20, "kind": "checkbox"}

    monkeypatch.setattr(turnstile, "find_checkbox", checkbox)
    ok = asyncio.run(bypass.solve_cloudflare(page, log=logs.append, wait_seconds=1))

    assert ok is False
    assert len(page.mouse.clicks) >= 1, "仍应尝试过真实点击"
    assert any("未能通过" in line for line in logs)


def test_managed_challenge_without_widget_is_reported_unsolved(monkeypatch) -> None:
    """新版 managed challenge 无可点 widget：ClickSolver 失败后不得谎报成功。"""
    monkeypatch.setattr(bypass, "_check_camoufox", lambda: None)

    class _FailingSolver:
        def __init__(self, **_kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc) -> None:
            return None

        async def solve_captcha(self, **_kwargs) -> None:
            raise RuntimeError("Cloudflare iframes not found")

    monkeypatch.setattr(bypass, "ClickSolver", _FailingSolver)
    page = FakePage("Just a moment...", "<html><body>Verifying you are human</body></html>", clears_after_click=False)
    logs: list[str] = []

    ok = asyncio.run(bypass.solve_cloudflare(page, log=logs.append, wait_seconds=1))

    assert ok is False
    assert page.mouse.clicks == []  # 无 widget，不该尝试点击


@pytest.mark.parametrize("ready_after_waits", [0, 3])
def test_managed_checkbox_is_clicked_as_soon_as_ready_and_needs_no_token(monkeypatch, ready_after_waits):
    from unittest.mock import Mock

    monkeypatch.setattr(bypass, "_check_camoufox", lambda: None)
    # managed challenge 的放行信号是导航，不一定有 response token。
    page = FakePage("Just a moment...", "<body>Verify you are human</body>", token="")

    async def checkbox(current):
        if current._title == "Just a moment..." and current._wait_count >= ready_after_waits:
            return {"x": 100, "y": 200, "width": 20, "height": 20, "kind": "checkbox"}
        return None

    solver = Mock(side_effect=AssertionError("不得追加 ClickSolver 的独立等待轮次"))
    monkeypatch.setattr(turnstile, "find_checkbox", checkbox)
    monkeypatch.setattr(bypass, "ClickSolver", solver)
    assert asyncio.run(bypass.solve_cloudflare(page, wait_seconds=1)) is True
    assert page.mouse.clicks == [(110.0, 210.0)]
    assert page._token == ""
    assert page._wait_count <= ready_after_waits + 2  # 仅控件出现前等待 + 两段鼠标轨迹。
    solver.assert_not_called()


def test_normal_title_does_not_hide_a_cf_checkbox(monkeypatch):
    from unittest.mock import AsyncMock

    page = FakePage("Sign in", "<custom-shadow-host></custom-shadow-host>")
    monkeypatch.setattr(turnstile, "find_checkbox", AsyncMock(return_value={
        "x": 10, "y": 10, "width": 20, "height": 20, "kind": "checkbox",
    }))
    assert asyncio.run(bypass.has_cloudflare_challenge(page)) is True


def test_cf_container_without_response_field_is_detected():
    assert bypass._has_interactive_widget('<div class="cf-turnstile" data-sitekey="public"></div>')


def test_normal_title_with_pending_widget_is_not_passed_through(monkeypatch):
    from unittest.mock import AsyncMock

    page = FakePage("Login", '<div class="cf-turnstile"></div>', clears_after_click=False)
    monkeypatch.setattr(turnstile, "find_checkbox", AsyncMock(return_value=None))
    assert asyncio.run(bypass._wait_until_challenge_clears(page, 0.02, lambda _m: None)) is False


@pytest.mark.parametrize("operation", ["title", "content", "wait_for_timeout"])
def test_cf_budget_bounds_stalled_browser_operations(monkeypatch, operation):
    from unittest.mock import AsyncMock

    monkeypatch.setattr(bypass, "_check_camoufox", lambda: None)
    page = FakePage("Just a moment...", "<body>Verifying you are human</body>", clears_after_click=False)

    async def hung(*args, **kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(page, operation, hung)
    monkeypatch.setattr(turnstile, "find_checkbox", AsyncMock(return_value=None))

    async def scenario():
        # 外部 watchdog 只防回归挂死；必须由求解器自己的20ms预算返回False。
        return await asyncio.wait_for(bypass.solve_cloudflare(page, wait_seconds=0.02), timeout=2)

    assert asyncio.run(scenario()) is False


def test_failed_page_reads_are_not_a_success_signal(monkeypatch):
    from unittest.mock import AsyncMock

    monkeypatch.setattr(bypass, "_check_camoufox", lambda: None)
    page = FakePage("Just a moment...", "")
    page.title = AsyncMock(side_effect=RuntimeError("navigation"))
    page.content = AsyncMock(side_effect=RuntimeError("navigation"))
    monkeypatch.setattr(turnstile, "find_checkbox", AsyncMock(return_value=None))
    assert asyncio.run(bypass.solve_cloudflare(page, wait_seconds=0.02)) is False


def test_oauth_stops_before_authorization_when_cf_is_unsolved(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock
    from browser import oauth_flow, oauth_providers

    page = SimpleNamespace(query_selector=AsyncMock(), wait_for_url=AsyncMock())
    monkeypatch.setattr(bypass, "solve_cloudflare", AsyncMock(return_value=False))
    monkeypatch.setattr(oauth_flow, "site_error_messages", AsyncMock(return_value=[]))
    result = {"clicked": False, "landed_back": False, "cloudflare": False}
    actual = asyncio.run(oauth_flow.finish_oauth_authorization(
        page, "https://site.invalid", oauth_providers.get_oauth_provider("linuxdo"), result, Mock()
    ))
    assert actual["cloudflare"] is True
    assert actual["landed_back"] is False
    page.query_selector.assert_not_awaited()
    page.wait_for_url.assert_not_awaited()


def test_oauth_polls_cf_even_when_page_title_is_normal(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, Mock
    from browser import oauth_flow, oauth_providers

    page = SimpleNamespace(
        url="https://connect.linux.do/oauth2/authorize", query_selector=AsyncMock(return_value=None),
        wait_for_url=AsyncMock(), title=AsyncMock(return_value="Authorize"),
    )
    solve = AsyncMock(side_effect=[True, False])
    monkeypatch.setattr(bypass, "solve_cloudflare", solve)
    monkeypatch.setattr(bypass, "has_cloudflare_challenge", AsyncMock(return_value=True))
    monkeypatch.setattr(oauth_flow, "APPROVE_WAIT_SECONDS", 1)
    result = {"clicked": False, "landed_back": False, "cloudflare": False}
    actual = asyncio.run(oauth_flow.finish_oauth_authorization(
        page, "https://site.invalid", oauth_providers.get_oauth_provider("linuxdo"), result, Mock()
    ))
    assert solve.await_count == 2
    assert 0 < solve.await_args.kwargs["wait_seconds"] <= 1
    assert actual["cloudflare"] is True
    page.wait_for_url.assert_not_awaited()


def test_oauth_total_deadline_bounds_a_stalled_driver(monkeypatch):
    from unittest.mock import Mock
    from browser import oauth_flow

    async def hung(*args, **kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(oauth_flow, "_finish_oauth_authorization", hung)
    monkeypatch.setattr(oauth_flow, "OAUTH_CF_WAIT_SECONDS", 0.02)
    monkeypatch.setattr(oauth_flow, "APPROVE_WAIT_SECONDS", 0.02)
    monkeypatch.setattr(oauth_flow, "OAUTH_WAIT_SECONDS", 0.02)
    result = {"clicked": False, "landed_back": False, "cloudflare": False}

    async def scenario():
        return await asyncio.wait_for(oauth_flow.finish_oauth_authorization(
            object(), "https://site.invalid", object(), result, Mock()
        ), timeout=2)

    assert asyncio.run(scenario())["error"] == "oauth_timeout"
    assert result["landed_back"] is False


# ── CF 熔断：同站连续失败后不再重复昂贵求解 ─────────────────────────────────
def test_solve_cloudflare_circuit_breaks_after_repeated_failures(monkeypatch) -> None:
    """同一出口 IP 对同站连续失败到阈值后，后续 solve_cloudflare 立即返回 False。

    实测 AgentRouter(L)：OAuth 流程里 solve_cloudflare 被调用四五次，出口 IP 被
    Cloudflare 风控时每次都注定失败，一轮完整求解（被动等待 → 点击 → ClickSolver
    5 次 → 再点）可达 1~2 分钟，最终耗尽 360 秒账号预算被判「执行超时」——把本该是
    need_verification/换代理的结论盖成了看不出原因的超时。熔断后第 3 次起立即返回，
    不再进入昂贵的 _solve_cloudflare_once。
    """
    monkeypatch.setattr(bypass, "_check_camoufox", lambda: None)

    calls = {"n": 0}
    real_once = bypass._solve_cloudflare_once

    async def _counting_once(page, log=None, wait_seconds: int = 10):
        calls["n"] += 1
        return await real_once(page, log=log, wait_seconds=wait_seconds)

    monkeypatch.setattr(bypass, "_solve_cloudflare_once", _counting_once)

    class _FailingSolver:
        def __init__(self, **_kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_exc) -> None:
            return None

        async def solve_captcha(self, **_kwargs) -> None:
            raise RuntimeError("Cloudflare iframes not found")

    monkeypatch.setattr(bypass, "ClickSolver", _FailingSolver)

    async def _run() -> tuple[list[bool], int]:
        page = FakePage(
            "Just a moment...",
            "<html><body>Verifying you are human</body></html>",
            clears_after_click=False,
        )
        outcomes = [
            await bypass.solve_cloudflare(page, log=lambda _m: None, wait_seconds=1)
            for _ in range(4)
        ]
        return outcomes, calls["n"]

    outcomes, once_calls = asyncio.run(_run())

    assert outcomes == [False, False, False, False]
    # 阈值为 2：前两次真正求解，达到阈值后第 3、4 次直接短路，不再进昂贵流程。
    assert once_calls == bypass.CF_BLOCK_THRESHOLD == 2


def test_solve_cloudflare_circuit_resets_on_success(monkeypatch) -> None:
    """一次成功求解会清零失败计数：偶发失败不该永久熔断一个仍可用的站点。"""
    monkeypatch.setattr(bypass, "_check_camoufox", lambda: None)

    outcomes = iter([False, True, False])

    async def _fake_once(page, log=None, wait_seconds: int = 10):
        return next(outcomes)

    monkeypatch.setattr(bypass, "_solve_cloudflare_once", _fake_once)

    async def _run() -> list[bool]:
        page = FakePage(
            "Just a moment...",
            "<html><body>Verifying you are human</body></html>",
            clears_after_click=False,
        )
        # 失败(1) → 成功(清零) → 失败(1)：三次都真正求解，均未触发熔断短路。
        return [
            await bypass.solve_cloudflare(page, log=lambda _m: None, wait_seconds=1)
            for _ in range(3)
        ]

    assert asyncio.run(_run()) == [False, True, False]
