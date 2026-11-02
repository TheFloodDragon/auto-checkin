"""CI 实测（run 41283216253）：前端授权换取 success、会话已建立，但页面内 fetch /api/user/self
持续拿到阿里云 WAF 挑战页（不带 X-Tengine-Error），确认 3 分钟全是 challenge_html 直至超时。
fetch 拿到的挑战页不会被执行，必须主动求解：按算法写 acw_sc__v2，或同源文档导航让脚本放行。"""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace

from browser import waf
from login import oauth
from net import esa

ARG1 = "4CCED7F54A71A957C842FB06D52EEC4DD6A7CF31"
POSITIONS = ",".join(hex(p) for p in esa.ACW_POSITIONS)
ACW_PAGE = f"<html><script>var arg1='{ARG1}';var m=[{POSITIONS}];document.cookie='x';</script></html>"
SLIDER_PAGE = "<html><div id='nc_1_wrapper'>slidecaptcha</div></html>"
UNKNOWN_PAGE = "<html><script>location.reload()</script></html>"
JSON_401 = json.dumps({"success": False, "message": "未登录"})


class _Site:
    """模拟 WAF：未持有正确 acw_sc__v2 时，页面内 fetch 一律返回挑战页。"""

    def __init__(self, challenge=ACW_PAGE, *, navigation_clears=False):
        self.challenge = challenge
        self.cookies: dict[str, str] = {}
        self.navigation_clears = navigation_clears
        self.navigations: list[str] = []

    def cleared(self) -> bool:
        return self.cookies.get("acw_sc__v2") == esa.acw_sc_v2(ARG1) or self.cookies.get("navigated") == "1"

    def body(self) -> str:
        return JSON_401 if self.cleared() else self.challenge


class _Context:
    def __init__(self, site):
        self.site = site
        self.added: list[dict] = []
        self.pages: list[_Page] = []

    async def add_cookies(self, cookies):
        self.added.extend(cookies)
        for cookie in cookies:
            self.site.cookies[cookie["name"]] = cookie["value"]

    async def new_page(self):
        page = _Page(self.site, self)
        self.pages.append(page)
        return page


class _Page:
    def __init__(self, site, context=None):
        self.site = site
        self.url = "https://agentrouter.org/console/token"
        self.context = context or _Context(site)
        self.closed = False
        self.evaluations = 0

    async def evaluate(self, script, args=None):
        self.evaluations += 1
        if script == waf._PROBE_JS:
            return {"status": 200, "marker": "", "body": self.site.body()}
        raise AssertionError("unexpected script")

    async def goto(self, url, **_kwargs):
        self.site.navigations.append(url)
        if self.site.navigation_clears:
            self.site.cookies["navigated"] = "1"

    async def content(self):
        return self.site.body()

    async def close(self):
        self.closed = True

    def is_closed(self):
        return self.closed


def _clear(page, *, budget=30.0):
    logs: list[str] = []
    result = asyncio.run(waf.clear_page_challenge(
        page, "https://agentrouter.org", "/api/user/self", time.monotonic() + budget, logs.append,
    ))
    return result, logs


def test_markerless_acw_challenge_is_solved_by_algorithm(monkeypatch):
    site = _Site()
    page = _Page(site)
    result, logs = _clear(page)
    assert result == "cleared:acw"
    added = page.context.added[0]
    assert added["name"] == "acw_sc__v2" and added["domain"] == "agentrouter.org" and added["secure"] is True
    assert site.navigations == []  # 算法可解时不打开额外页面
    assert esa.acw_sc_v2(ARG1) not in str(logs) and ARG1 not in str(logs)


def test_unknown_challenge_falls_back_to_document_navigation(monkeypatch):
    site = _Site(UNKNOWN_PAGE, navigation_clears=True)
    page = _Page(site)
    result, logs = _clear(page)
    assert result == "cleared:navigation"
    assert site.navigations == ["https://agentrouter.org/api/user/self"]
    assert page.context.pages and page.context.pages[0].closed  # 辅助页必关
    assert page.context.added == []


def test_slider_still_blocking_original_endpoint_is_unsolved(monkeypatch):
    from unittest.mock import AsyncMock
    from browser import bypass

    solver = AsyncMock(return_value=True)  # 输入返回成功也不能当作接口放行。
    monkeypatch.setattr(bypass, "aliyun_captcha_solver", solver)
    site = _Site(SLIDER_PAGE)
    page = _Page(site)
    result, logs = _clear(page)
    assert result == "unsolved:slider"
    assert site.navigations == ["https://agentrouter.org/api/user/self"]
    solver.assert_awaited_once()
    assert page.context.pages[0].closed
    assert any("滑块" in line for line in logs)


def test_slider_navigation_rechecks_original_endpoint_after_interaction(monkeypatch):
    from unittest.mock import AsyncMock
    from browser import bypass

    site = _Site(SLIDER_PAGE)
    page = _Page(site)

    async def solve(helper, **kwargs):
        assert helper is not page and helper.context is page.context
        assert kwargs["deadline"] > time.monotonic()
        site.cookies["navigated"] = "1"
        return True

    solver = AsyncMock(side_effect=solve)
    monkeypatch.setattr(bypass, "aliyun_captcha_solver", solver)
    assert _clear(page)[0] == "cleared:navigation"
    solver.assert_awaited_once()
    assert page.evaluations == 2
    assert page.context.pages[0].closed


def test_slider_failure_does_not_repeat_or_modify_authentication(monkeypatch):
    from unittest.mock import AsyncMock
    from browser import bypass

    page = _Page(_Site(SLIDER_PAGE))
    solver = AsyncMock(return_value=False)
    monkeypatch.setattr(bypass, "aliyun_captcha_solver", solver)
    assert _clear(page)[0] == "unsolved:slider"
    solver.assert_awaited_once()
    assert page.context.added == []
    assert page.context.pages[0].closed


def test_clean_response_needs_no_action():
    site = _Site()
    site.cookies["navigated"] = "1"
    assert _clear(_Page(site))[0] == "cleared:none"


def _ctx(logs):
    return SimpleNamespace(base_url="https://agentrouter.org", log=logs.append, deadline=None,
                           endpoint=lambda _name: "/api/user/self")


def test_confirm_loop_heals_challenge_then_confirms(monkeypatch):
    """复现 CI：确认一直是 challenge_html；求解后同一会话立即确认成功。"""
    site = _Site()
    page = _Page(site)
    calls = []

    async def confirm(_ctx, _page):
        calls.append(site.cleared())
        if site.cleared():
            return {"status": "ok", "identity": {"user_id": "178429"}, "reason": "ok", "http": 200, "has_user": True}
        return {"status": "unknown", "identity": {}, "reason": "challenge_html", "http": 200,
                "has_user": True, "challenge": "acw", "marker": False}

    monkeypatch.setattr(oauth, "_server_confirms_login", confirm)
    logs: list[str] = []
    start = time.monotonic()
    result = asyncio.run(oauth._confirm_after_relogin(_ctx(logs), page, start + 20, export_reserve=1))
    assert result and result.identity == {"user_id": "178429"}
    assert calls == [False, True]
    assert any("原因=challenge_html/acw" in line for line in logs)
    assert any("求解结果：cleared:acw" in line for line in logs)
    assert time.monotonic() - start < 5  # 不再空耗确认预算
    assert "178429" not in str(logs)


def test_confirm_loop_heal_attempts_are_bounded(monkeypatch):
    site = _Site(SLIDER_PAGE)
    page = _Page(site)

    async def confirm(_ctx, _page):
        return {"status": "unknown", "identity": {}, "reason": "challenge_html", "challenge": "slider"}

    healed = []
    original = waf.clear_page_challenge

    async def counting(*args, **kwargs):
        healed.append(True)
        return await original(*args, **kwargs)

    monkeypatch.setattr(oauth, "_server_confirms_login", confirm)
    monkeypatch.setattr(waf, "clear_page_challenge", counting)
    logs: list[str] = []
    result = asyncio.run(oauth._confirm_after_relogin(_ctx(logs), page, time.monotonic() + 4.5, export_reserve=1))
    assert not result
    assert len(healed) == oauth._CHALLENGE_HEAL_ATTEMPTS


def _slider_page():
    from unittest.mock import AsyncMock

    track = SimpleNamespace(is_visible=AsyncMock(return_value=True),
                            bounding_box=AsyncMock(return_value={"x": 100, "y": 60, "width": 300, "height": 40}))
    grip = SimpleNamespace(is_visible=AsyncMock(return_value=True),
                           bounding_box=AsyncMock(return_value={"x": 100, "y": 60, "width": 40, "height": 40}))
    mouse = SimpleNamespace(move=AsyncMock(), down=AsyncMock(), up=AsyncMock())
    page = SimpleNamespace(evaluate=AsyncMock(return_value=True), wait_for_selector=AsyncMock(), mouse=mouse,
                           query_selector=AsyncMock(side_effect=[track, grip, None]))
    return page


def test_slider_trajectory_advances_to_right_edge_and_releases_mouse(monkeypatch):
    from browser import bypass

    page = _slider_page()
    monkeypatch.setattr(bypass.random, "uniform", lambda *_: 0.0)
    monkeypatch.setattr(bypass.random, "randint", lambda *_: 15)
    assert asyncio.run(bypass.aliyun_captcha_solver(page, wait_seconds=0))
    points = [call.args for call in page.mouse.move.await_args_list]
    assert points[0] == (120, 80)
    assert points[-1] == (380, 80)
    assert all(first[0] <= second[0] for first, second in zip(points, points[1:]))
    page.mouse.down.assert_awaited_once()
    page.mouse.up.assert_awaited_once()


def test_slider_failure_releases_pressed_mouse_without_echoing_exception(monkeypatch):
    from browser import bypass

    page = _slider_page()
    page.mouse.move.side_effect = [None, RuntimeError("private-response-body")]
    monkeypatch.setattr(bypass.random, "uniform", lambda *_: 0.0)
    logs = []
    assert not asyncio.run(bypass.aliyun_captcha_solver(page, wait_seconds=0, log=logs.append))
    page.mouse.down.assert_awaited_once()
    page.mouse.up.assert_awaited_once()
    assert "private-response-body" not in str(logs)


def test_slider_expired_budget_performs_no_browser_operations():
    from browser import bypass

    page = _slider_page()
    assert not asyncio.run(bypass.aliyun_captcha_solver(page, deadline=time.monotonic() - 1))
    page.evaluate.assert_not_awaited()
    page.mouse.down.assert_not_awaited()
