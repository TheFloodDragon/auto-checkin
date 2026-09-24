"""引擎阶段机：登录 → 执行 → 验证 → 确认 → 渲染。

这里断言的是**跨阶段的编排语义**，不是某个站点的接口细节：
- 固定的阶段失败就失败，不许自行扩大候选；
- 真正跑通的候选被写回覆盖层，下次直接命中；
- 任务依赖未完成时判「不适用」而不是失败；
- tolerate_failure 把失败改判为无影响，而不是伪装成成功。
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from config import schema
from config.overlay import Overlay
from core.outcome import Verdict
from net import http as net_http
from runtime import engine


# ── 测试替身 ────────────────────────────────────────────────────────────────
class FakeSite:
    """按 (method, path) 回放响应的假站点。"""

    def __init__(self, routes: dict[tuple[str, str], Any]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str]] = []

    def send(self, client, method, path, **_kwargs):
        key = (method.upper(), path.split("?")[0])
        self.calls.append(key)
        if key not in self.routes:
            raise net_http.TaskError("not found", status=404, payload={"message": "404 not found"})
        value = self.routes[key]
        if isinstance(value, Exception):
            raise value
        return net_http.unwrap_data(value)


@pytest.fixture
def site(monkeypatch):
    holder: dict[str, FakeSite] = {}

    def install(routes: dict[tuple[str, str], Any]) -> FakeSite:
        fake = FakeSite(routes)
        holder["site"] = fake
        monkeypatch.setattr(
            net_http.HttpClient,
            "_send",
            lambda self, method, path, **kw: fake.send(self, method, path, **kw),
        )
        return fake

    return install


def account(**overrides: Any):
    payload = {
        "id": "demo",
        "name": "演示站",
        "base_url": "https://demo.invalid",
        "template": "newapi",
        "credentials": {"access_token": "a.b.c", "user_id": "42"},
        "login": {"method": "access_token"},
        "tasks": [{"id": "daily", "method": "http_api"}],
    }
    payload.update(overrides)
    return schema.parse_account(payload)


def run(spec, overlay):
    return asyncio.run(engine.run_account(spec, overlay=overlay))


NEWAPI_READY = {
    ("GET", "/api/user/checkin"): {"success": True, "data": {"stats": {"checked_in_today": False}}},
    ("GET", "/api/status"): {"success": True, "data": {"turnstile_check": False}},
    ("GET", "/api/user/self"): {"success": True, "data": {"quota": 1_000_000}},
}


# ── 用例 ────────────────────────────────────────────────────────────────────
def test_success_path_renders_custom_text(site, tmp_path) -> None:
    """成功路径：结论 + 自定义文本（额度）+ 附加项，一次性给全。"""
    site(
        {
            **NEWAPI_READY,
            ("POST", "/api/user/checkin"): {
                "success": True,
                "data": {"quota_awarded": 250_000, "quota": 1_250_000, "consecutive_days": 3},
            },
        }
    )
    overlay = Overlay(path=tmp_path / "o.json").load()
    result = run(account(), overlay)

    record = result.records[0]
    assert record.outcome.verdict is Verdict.SUCCESS
    view = record.rendered()
    assert view.text == "$2.50" and view.text_label == "额度"
    assert ("获得", "$0.50") in view.extras
    assert ("连续天数", "3") in view.extras


def test_already_done_is_not_a_failure(site, tmp_path) -> None:
    site(
        {
            **NEWAPI_READY,
            ("GET", "/api/user/checkin"): {
                "success": True,
                "data": {"stats": {"checked_in_today": True}},
            },
        }
    )
    result = run(account(), Overlay(path=tmp_path / "o.json").load())
    record = result.records[0]
    assert record.outcome.verdict is Verdict.ALREADY_DONE
    assert record.ok and result.ok


def test_success_message_also_reports_current_balance(site, tmp_path) -> None:
    """消息里除了「本次获得」还要有「当前额度」。

    message 是通知、CI 摘要与结果文件里唯一一定会被读到的那一行；此前它只说获得了
    多少，账上还剩多少只出现在汇总表的自定义文本列，脱离表格就看不到。
    """
    site(
        {
            **NEWAPI_READY,
            ("POST", "/api/user/checkin"): {
                "success": True,
                "data": {"quota_awarded": 250_000, "quota": 1_250_000},
            },
        }
    )
    result = run(account(), Overlay(path=tmp_path / "o.json").load())

    outcome = result.records[0].outcome
    assert outcome.verdict is Verdict.SUCCESS
    # 当前额度用模板自己的单位格式化（quota_500000：1_250_000 → $2.50），
    # 绝不能把站点原始额度值直接打成「当前额度 1250000」。
    assert "（当前额度 $2.50）" in outcome.message
    assert "1250000" not in outcome.message


def test_already_done_message_also_reports_current_balance(site, tmp_path) -> None:
    """「今日已完成」同样要报当前额度：这天最常见的结论就是它。

    已签到路径不读签到响应里的额度，而是回查 ``/api/user/self``（签到接口此时不发数值），
    所以余额要配在那里。
    """
    site(
        {
            **NEWAPI_READY,
            ("GET", "/api/user/checkin"): {
                "success": True,
                "data": {"stats": {"checked_in_today": True}},
            },
            ("GET", "/api/user/self"): {"success": True, "data": {"quota": 3_000_000}},
        }
    )
    result = run(account(), Overlay(path=tmp_path / "o.json").load())

    outcome = result.records[0].outcome
    assert outcome.verdict is Verdict.ALREADY_DONE
    assert "（当前额度 $6.00）" in outcome.message


def test_current_balance_is_never_fabricated_or_duplicated() -> None:
    """读不到余额就不加；已经写过就不追加第二遍；失败结论不动。"""
    from core.outcome import DisplaySpec, already_done, failed, success
    from runtime.engine import _with_current_balance

    defaults = DisplaySpec(text_label="额度")

    # 1) 没有 balance：什么都不加（不编数值）。
    bare = success("签到成功")
    assert _with_current_balance(bare, defaults).message == "签到成功"

    # 2) 失败结论不追加：余额对「为什么失败」没有帮助，只会挤占可操作信息。
    broken = failed("登录失效", reason="need_login").with_data(balance=1).with_display(
        DisplaySpec(text="$1.00")
    )
    assert _with_current_balance(broken, defaults).message == "登录失效"

    # 3) 正常追加，并沿用模板自定义的列名（Fengwind 这类站点是「积分」而不是「额度」）。
    points = already_done("今日已签到").with_data(balance=12).with_display(
        DisplaySpec(text="12", text_label="积分")
    )
    assert _with_current_balance(points, defaults).message == "今日已签到（当前积分 12）"

    # 4) 幂等：上游已经写过当前值时不再追加。
    once = _with_current_balance(points, defaults)
    assert _with_current_balance(once, defaults).message == once.message


def test_execution_path_is_learned_and_reused(site, tmp_path) -> None:
    """执行即学习：跑通的登录方式与任务方式写回覆盖层，下次直接命中。"""
    site({**NEWAPI_READY, ("POST", "/api/user/checkin"): {"success": True, "data": {"quota_awarded": 1}}})
    path = tmp_path / "o.json"
    run(account(), Overlay(path=path).load())

    learned = Overlay(path=path).load().entry("demo").flow_discoveries()
    assert learned["login"].value == "access_token"
    assert learned["execute"].value == "http_api"


def test_locked_login_does_not_silently_fall_back(site, tmp_path) -> None:
    """写死的登录方式失败就失败：静默降级正是「日志看不出走了哪条路」的根因。"""
    site(NEWAPI_READY)
    spec = account(
        credentials={},  # 没有任何凭据
        login={"method": "access_token"},
        flow={"login": "access_token"},
    )
    result = run(spec, Overlay(path=tmp_path / "o.json").load())

    outcome = result.records[0].outcome
    assert outcome.verdict is Verdict.FAILED
    assert outcome.reason == "need_config"
    assert "access_token" in str(outcome.data.get("login_attempts"))


def test_dependent_task_is_skipped_not_failed(site, tmp_path) -> None:
    """前置任务没成功时，后续任务判「不适用」——它没失败，只是没轮到它。"""
    site({**NEWAPI_READY, ("POST", "/api/user/checkin"): net_http.TaskError("boom", status=500)})
    spec = account(
        tasks=[
            {"id": "daily", "method": "http_api"},
            {"id": "extra", "method": "http_api", "depends_on": ["daily"]},
        ]
    )
    result = run(spec, Overlay(path=tmp_path / "o.json").load())

    by_id = {record.task_id: record.outcome for record in result.records}
    assert by_id["daily"].verdict is Verdict.FAILED
    assert by_id["extra"].verdict is Verdict.NO_EFFECT
    assert by_id["extra"].reason == "not_applicable"


def test_tolerate_failure_becomes_no_effect_not_success(site, tmp_path) -> None:
    """容错是「不计成败」，不是「假装成功」；原始结论必须留在数据里可回查。"""
    site({**NEWAPI_READY, ("POST", "/api/user/checkin"): net_http.TaskError("boom", status=500)})
    spec = account(policy={"tolerate_failure": True})
    result = run(spec, Overlay(path=tmp_path / "o.json").load())

    outcome = result.records[0].outcome
    assert outcome.verdict is Verdict.NO_EFFECT
    assert outcome.reason == "tolerated"
    assert result.ok, "容错账号不影响整体退出码"
    assert outcome.data.get("tolerated_verdict") in {"failed", None}


def test_unconfirmed_result_is_cross_checked_before_reporting_success(site, tmp_path) -> None:
    """接口回 200 但没有任何证据时，必须交叉验证，验证不到就不谎报成功。

    实测存在站点静默拒绝、或端点根本不是签到接口的情况，直接报成功会出现
    「显示成功但额度没到账」。
    """
    site(
        {
            **NEWAPI_READY,
            ("POST", "/api/user/checkin"): {"success": True, "data": {}},
        }
    )
    result = run(account(), Overlay(path=tmp_path / "o.json").load())

    outcome = result.records[0].outcome
    assert outcome.verdict is Verdict.FAILED
    assert outcome.reason == "unconfirmed"


@pytest.mark.parametrize(("message", "reason", "verdict"), [
    ("会话已失效，请重新登录后再签到", "need_login", Verdict.FAILED),
    ("今日已签到", "", Verdict.ALREADY_DONE),
    ("签到功能已关闭", "not_open", Verdict.NO_EFFECT),
    ("签到资格不足", "", Verdict.FAILED),
])
@pytest.mark.parametrize("with_data", [False, True])
def test_newapi_http_200_business_rejection_keeps_real_outcome(
    monkeypatch, tmp_path, message, reason, verdict, with_data,
) -> None:
    """保留真实 JSON 信封：旧 FakeSite.send 会先拆掉 success，掩盖这个回归。"""
    import json
    from urllib.parse import urlsplit

    calls = []
    rejected = {"success": False, "message": message}
    if with_data:
        rejected["data"] = {"quota_awarded": 500_000, "quota": 2_000_000}
    routes = {**NEWAPI_READY, ("POST", "/api/user/checkin"): rejected}

    def respond(_client, url, *, method, **_kwargs):
        key = (method, urlsplit(url).path)
        calls.append(key)
        return json.dumps(routes[key], ensure_ascii=False)

    monkeypatch.setattr(net_http.HttpClient, "_once", respond)
    result = run(account(), Overlay(path=tmp_path / "o.json").load())
    outcome = result.records[0].outcome
    assert outcome.verdict is verdict
    assert outcome.reason == reason
    assert message in outcome.message
    assert "接口返回成功但" not in outcome.message
    assert calls.count(("POST", "/api/user/checkin")) == 1
    assert calls.count(("GET", "/api/user/checkin")) == 1, "拒绝回执不能再进入成功交叉确认"


@pytest.mark.parametrize("json_rejection", [False, True])
def test_newapi_state_rejecting_session_stops_before_post(monkeypatch, tmp_path, json_rejection) -> None:
    import json

    calls = []
    message = "会话已失效，请重新登录后再签到"

    def respond(_client, url, *, method, **_kwargs):
        calls.append((method, url))
        if json_rejection:
            return json.dumps({"success": False, "message": message, "data": {}})
        raise net_http.LoginRequired(message, status=401)

    monkeypatch.setattr(net_http.HttpClient, "_once", respond)
    result = run(account(), Overlay(path=tmp_path / "o.json").load())
    outcome = result.records[0].outcome
    assert outcome.reason == "need_login"
    assert message in outcome.message
    assert len(calls) == 1 and calls[0][0] == "GET"
    assert calls[0][1].endswith("/api/user/checkin")


def test_newapi_missing_status_route_still_allows_submission(site, tmp_path) -> None:
    fake = site({
        **NEWAPI_READY,
        ("GET", "/api/user/checkin"): net_http.TaskError("not found", status=404),
        ("POST", "/api/user/checkin"): {"success": True, "data": {"quota_awarded": 500_000}},
    })
    result = run(account(), Overlay(path=tmp_path / "o.json").load())
    assert result.records[0].outcome.verdict is Verdict.SUCCESS
    assert ("POST", "/api/user/checkin") in fake.calls


def test_newapi_unwrapped_failure_cannot_become_reward_success() -> None:
    from templates.builtin import newapi

    outcome = newapi._reward_outcome(None, {
        "success": False,
        "message": "会话已失效，请重新登录后再签到",
        "quota_awarded": 500_000,
        "checked_in_today": True,
    })
    assert outcome.verdict is Verdict.FAILED
    assert outcome.reason == "need_login"


def test_newapi_block_reason_is_not_reclassified_as_verification() -> None:
    from templates.builtin import newapi

    outcome = newapi._outcome_from_error(net_http.TaskError("Cloudflare blocked", reason="blocked"))
    assert outcome.reason == "blocked"


def test_health_streak_accumulates_on_failure(site, tmp_path) -> None:
    """连续失败要被记下来：流程层据此在若干次后强制重新探测。"""
    site({**NEWAPI_READY, ("POST", "/api/user/checkin"): net_http.TaskError("boom", status=500)})
    path = tmp_path / "o.json"
    run(account(), Overlay(path=path).load())
    run(account(), Overlay(path=path).load())

    assert Overlay(path=path).load().entry("demo").failure_streak == 2


def test_fengwind_oauth_uses_template_login_and_cached_token(site, tmp_path, monkeypatch) -> None:
    """配置 oauth 时仍由站点钩子登录，有效 Token 不应触发通用 OAuth 或浏览器。"""
    from unittest.mock import AsyncMock

    from browser.service import BrowserService
    from login.oauth import OAuthLogin

    generic_oauth = AsyncMock(side_effect=AssertionError("不得走通用 OAuth"))
    start_browser = AsyncMock(side_effect=AssertionError("有效 Token 不应启动浏览器"))
    monkeypatch.setattr(OAuthLogin, "authenticate", generic_oauth)
    monkeypatch.setattr(BrowserService, "_ensure_started", start_browser)
    monkeypatch.setattr(engine.caps_module, "detect", lambda _: frozenset({"browser"}))
    fake = site(
        {
            ("GET", "/api/me"): {"code": 0, "data": {"id": 42}},
            ("GET", "/api/checkin/status"): {
                "code": 0,
                "data": {"checked_in_today": True, "today": {"amount": 5, "status": "credited"}},
            },
            ("GET", "/api/level"): {"code": 0, "data": {"checkin_eligible": True}},
            ("GET", "/api/checkin/history"): {"code": 0, "data": {"items": []}},
        }
    )
    spec = account(
        template="scripts/tasks/fengwind_welfare.py",
        login={"method": "oauth", "provider": "linuxdo"},
        tasks=[{"id": "daily", "method": "script"}],
    )
    result = asyncio.run(
        engine.run_account(
            spec,
            overlay=Overlay(path=tmp_path / "fengwind.json").load(),
            oauth_state=lambda provider, name: "test-shared-state",
        )
    )

    assert result.ok
    assert result.records[0].outcome.verdict is Verdict.ALREADY_DONE
    assert fake.calls[0] == ("GET", "/api/me")
    assert not any(method == "POST" or path == "/api/status" for method, path in fake.calls)
    generic_oauth.assert_not_awaited()
    start_browser.assert_not_awaited()
