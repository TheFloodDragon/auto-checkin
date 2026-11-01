"""阿里云 ESA ``acw_sc__v2`` 挑战自愈：HttpOnly 旧值会让页面脚本写不进新值而无限重出题。"""

from __future__ import annotations

import asyncio
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from browser import waf

ARG1 = "4CCED7F54A71A957C842FB06D52EEC4DD6A7CF31"
POSITIONS = ("0xf,0x23,0x1d,0x18,0x21,0x10,0x1,0x26,0xa,0x9,0x13,0x1f,0x28,0x1b,0x16,0x17,0x19,0xd,0x6,0xb,"
             "0x27,0x12,0x14,0x8,0xe,0x15,0x20,0x1a,0x2,0x1e,0x7,0x4,0x11,0x5,0x3,0x1c,0x22,0x25,0xc,0x24")
CHALLENGE = (f"<html><script>var arg1='{ARG1}';(function(a,c){{}}());"
             f"!(function(){{for(var m=[{POSITIONS}],p=L(0x115);;)document.cookie='acw_sc__v2='+v;}}());</script></html>")


class _Context:
    def __init__(self, cookies):
        self.jar = list(cookies)
        self.added: list[dict] = []
        self.handlers: dict[str, list] = {}

    async def cookies(self, _url=None):
        return [dict(c) for c in self.jar]

    async def clear_cookies(self, *, name=None, domain=None, path=None):
        def hit(c):
            if name is not None and c["name"] != name:
                return False
            if domain is None:
                return True
            if isinstance(domain, re.Pattern):
                return bool(domain.search(c["domain"]))
            return c["domain"] == domain
        self.jar = [c for c in self.jar if not hit(c)]

    async def add_cookies(self, cookies):
        self.added.extend(cookies)
        self.jar.extend(cookies)

    def on(self, event, handler):
        self.handlers.setdefault(event, []).append(handler)


def _response(*, status=200, header="denied by http_custom", resource="document", body=CHALLENGE,
              url="https://anyrouter.top/console"):
    headers = {waf.ESA_CHALLENGE_HEADER: header} if header else {}
    return SimpleNamespace(status=status, headers=headers, url=url,
                           request=SimpleNamespace(resource_type=resource), text=AsyncMock(return_value=body))


def test_acw_sc_v2_matches_known_vector_and_validates_input():
    # 向量来自真实挑战页：浏览器执行站点脚本得到的值与此一致，且纯 HTTP 带上它即放行。
    assert waf.acw_sc_v2(ARG1) == "6ae6c02fa4c172b6dc623976afd6a5feea4e6f62"
    assert waf.acw_sc_v2(ARG1.lower()) == waf.acw_sc_v2(ARG1)
    for bad in ("", "XYZ", ARG1[:-1], "G" * 40):
        with pytest.raises(ValueError):
            waf.acw_sc_v2(bad)


def test_solve_challenge_refuses_unknown_permutation():
    assert waf.solve_acw_challenge(CHALLENGE) == waf.acw_sc_v2(ARG1)
    assert waf.solve_acw_challenge("<html>ok</html>") == ""
    changed = CHALLENGE.replace("var m=[0xf,", "var m=[0xe,")
    # 站点换了置换表就不能再按旧算法乱写 Cookie。
    assert waf.solve_acw_challenge(changed) == ""


def test_detects_only_esa_denied_200():
    assert waf.is_esa_challenge_response(_response())
    assert not waf.is_esa_challenge_response(_response(status=307))
    assert not waf.is_esa_challenge_response(_response(header=""))
    assert not waf.is_esa_challenge_response(SimpleNamespace())


def test_document_challenge_removes_stale_httponly_cookie_only():
    ctx = _Context([
        {"name": "acw_sc__v2", "value": "old", "domain": "anyrouter.top", "httpOnly": True},
        {"name": "acw_tc", "value": "tc", "domain": "anyrouter.top", "httpOnly": True},
    ])
    action = asyncio.run(waf.heal_esa_response(ctx, _response()))
    assert action == "cleared_httponly"
    assert [c["name"] for c in ctx.jar] == ["acw_tc"]
    # 文档挑战由页面脚本写新值，这里不代写。
    assert ctx.added == []


def test_document_challenge_keeps_script_written_cookie():
    ctx = _Context([{"name": "acw_sc__v2", "value": "fresh", "domain": "anyrouter.top", "httpOnly": False}])
    assert asyncio.run(waf.heal_esa_response(ctx, _response())) == ""
    assert ctx.jar[0]["value"] == "fresh"


def test_fetch_challenge_computes_non_httponly_cookie():
    ctx = _Context([{"name": "acw_sc__v2", "value": "old", "domain": "anyrouter.top", "httpOnly": True}])
    action = asyncio.run(waf.heal_esa_response(ctx, _response(resource="fetch", url="https://anyrouter.top/api/user/self")))
    assert action == "cleared_httponly+computed"
    assert len(ctx.added) == 1
    cookie = ctx.added[0]
    assert cookie["name"] == "acw_sc__v2" and cookie["domain"] == "anyrouter.top"
    assert cookie["value"] == waf.acw_sc_v2(ARG1) and cookie["httpOnly"] is False


def test_non_challenge_response_is_untouched():
    ctx = _Context([{"name": "acw_sc__v2", "value": "old", "domain": "anyrouter.top", "httpOnly": True}])
    assert asyncio.run(waf.heal_esa_response(ctx, _response(header="", resource="fetch"))) == ""
    assert len(ctx.jar) == 1 and ctx.added == []


def test_install_healer_is_idempotent_and_runs_on_challenge():
    ctx = _Context([{"name": "acw_sc__v2", "value": "old", "domain": "anyrouter.top", "httpOnly": True}])

    async def scenario():
        assert waf.install_esa_healer(ctx) is True
        assert waf.install_esa_healer(ctx) is False
        assert len(ctx.handlers["response"]) == 1
        ctx.handlers["response"][0](_response(header=""))
        ctx.handlers["response"][0](_response())
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    asyncio.run(scenario())
    assert ctx.jar == []
    assert waf.install_esa_healer(None) is False


def test_reset_waf_cookies_scoped_to_site_host_and_parents():
    ctx = _Context([
        {"name": "acw_tc", "value": "1", "domain": "anyrouter.top"},
        {"name": "acw_sc__v2", "value": "2", "domain": ".anyrouter.top"},
        {"name": "cdn_sec_tc", "value": "3", "domain": "www.anyrouter.top"},
        {"name": "acw_tc", "value": "4", "domain": "notanyrouter.top"},
        {"name": "session", "value": "5", "domain": "anyrouter.top"},
    ])
    page = SimpleNamespace(context=ctx)
    asyncio.run(waf.reset_waf_cookies(page, "https://www.anyrouter.top"))
    assert sorted((c["name"], c["domain"]) for c in ctx.jar) == [("acw_tc", "notanyrouter.top"), ("session", "anyrouter.top")]


def test_solve_waf_resets_cookies_before_retry_round(monkeypatch):
    calls: list[str] = []
    page = SimpleNamespace(context=_Context([]), content=AsyncMock(return_value=CHALLENGE))
    monkeypatch.setattr(waf, "safe_goto", AsyncMock(side_effect=lambda *a, **k: calls.append("goto")))
    monkeypatch.setattr(waf, "reset_waf_cookies", AsyncMock(side_effect=lambda *a, **k: calls.append("reset")))
    monkeypatch.setattr(waf.asyncio, "sleep", AsyncMock())

    assert asyncio.run(waf.solve_waf(page, "https://anyrouter.top", rounds=2)) is False
    # 首轮直接导航；第二轮先清 WAF Cookie 再导航，打断 HttpOnly 旧值造成的重出题循环。
    assert calls == ["goto", "reset", "goto"]
    assert page.context.handlers.get("response")
