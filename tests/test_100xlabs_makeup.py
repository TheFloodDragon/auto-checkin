"""百倍/林夕签到补签：只用免费额度补近几天，绝不使用活跃度；全部为合成响应，不请求真实站点。

FakeSite 对每个补签 POST 强制检查：同一日期刚刚得到 cost_kind=free、can_afford=true 的
preview。任何违反都抛 BaseException 子类，绕过业务代码的 ``except Exception`` 直接让用例失败。
"""
from __future__ import annotations

import asyncio
import importlib
import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from core.chain import is_final
from core.errors import LoginRequired, TaskError, TransientError
from core.outcome import Verdict, already_done, failed, success

ORIGIN = "https://makeup.test"
TODAY = "2026-11-01"
D1, D2, D3 = "2026-10-31", "2026-10-30", "2026-10-29"
CST = timezone(timedelta(hours=8))
SECRET = "synthetic-secret"


class Broken(BaseException):
    """测试替身发现的违规：不能被业务代码当作普通异常吞掉。"""


@pytest.fixture
def makeup(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts" / "tasks"))
    module = importlib.import_module("_100xlabs_makeup")
    # 默认站点时间是白天，远离日切；跨日用例自己覆盖。
    monkeypatch.setattr(module, "_site_now", lambda: datetime(2026, 11, 1, 10, 0, tzinfo=CST))
    return module


def clock(monkeypatch, makeup, *moments):
    """按调用顺序返回站点时间，最后一个值一直保持。"""
    sequence = list(moments)
    monkeypatch.setattr(makeup, "_site_now", lambda: sequence.pop(0) if len(sequence) > 1 else sequence[0])
class FakeSite:
    """按脚本顺序应答；记录调用并强制「补签 POST 前必有同日免费、可负担的 preview」。"""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []
        self.previews = {}
        self.headers = {"Authorization": "Bearer synthetic-access"}

    def request(self, method, path, *, json_body=None, via_page=False, **kwargs):
        if method == "POST" and not via_page and kwargs.get("retry_non_idempotent") is not False:
            raise Broken(f"POST 必须禁用非幂等重试：{method} {path}")
        if not self.script:
            raise Broken(f"未准备的请求：{method} {path}")
        want_method, want_path, reply = self.script.pop(0)
        parts = urlsplit(path)
        if (method, parts.path) != (want_method, want_path):
            raise Broken(f"请求顺序不符：期望 {want_method} {want_path}，实际 {method} {path}")
        query = {key: values[0] for key, values in parse_qs(parts.query).items()}
        self.calls.append((method, parts.path, query, json_body))
        if parts.path == "/api/v1/check-in/makeup":
            day = (json_body or {}).get("date")
            seen = self.previews.pop(day, None)
            if set(json_body or {}) != {"date"} or seen is None:
                raise Broken(f"补签 {day} 前没有同日 preview，或提交体含多余字段：{json_body}")
            data = seen.get("data", seen) if isinstance(seen, dict) else {}
            if data.get("cost_kind") != "free" or data.get("can_afford") is not True:
                raise Broken(f"违规提交：{day} 的 preview 不是可负担的免费补签")
        if isinstance(reply, BaseException):
            raise reply
        if parts.path == "/api/v1/check-in/makeup/preview":
            self.previews[query.get("date")] = reply
        return reply

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def posts(self, path="/api/v1/check-in/makeup"):
        return [body for method, called, _, body in self.calls if method == "POST" and called == path]

    def order(self):
        return [f"{method} {path}".strip() for method, path, _, _ in self.calls]


class FakePage:
    """浏览器传输：page.evaluate 收到的参数转给同一个 FakeSite。"""

    def __init__(self, site, url=ORIGIN + "/check-in"):
        self.site = site
        self.url = url
        self.evaluate = AsyncMock(side_effect=self._evaluate)

    async def _evaluate(self, script, args):
        if args["baseUrl"] != ORIGIN:
            raise Broken("页内请求不是账号站点同源")
        try:
            payload = self.site.request(args["method"], args["path"], json_body=args["body"], via_page=True)
        except TaskError as exc:
            if isinstance(exc, LoginRequired):
                return {"status": 401}
            return {"status": exc.status or 0, "payload": exc.payload}
        return {"status": 200, "payload": payload}
STATUS = "/api/v1/check-in/status"
CALENDAR = "/api/v1/check-in/calendar"
PREVIEW = "/api/v1/check-in/makeup/preview"
MAKEUP = "/api/v1/check-in/makeup"


def ok(data):
    return {"code": 0, "message": "success", "data": data}


def _fields(base, overrides):
    base.update(overrides)
    return {key: value for key, value in base.items() if value is not ...}


def status(**overrides):
    return ok(_fields({
        "enabled": True, "checked_in_today": False, "check_in_date": TODAY, "activity_score": 20,
        "makeup_enabled": True, "makeup_near_free_cost_usd": 10, "makeup_far_activity_cost": 1,
        "free_balance": 500, "turnstile_required": False,
    }, overrides))


def calendar(*dates, days=()):
    return ok({"dates": list(dates), "days": [{"date": day, "pool": "free"} for day in days]})


def preview(day, ago, /, **overrides):
    return ok(_fields({
        "date": day, "days_ago": ago, "cost_kind": "free", "free_cost": 10, "activity_cost": 1,
        "free_balance": 500, "activity_score": 20, "can_afford": True,
    }, overrides))


def receipt(day, /, **overrides):
    return ok(_fields({"date": day, "check_in_date": TODAY, "activity_score": 20, "free_balance": 490}, overrides))


def refused(code, http_status=None):
    """站点业务拒绝：200 + code≠0 或 4xx；message 是不该进入结果的站点原文。"""
    body = {"code": 400, "reason": code, "message": SECRET}
    if http_status is None:
        return body
    return TaskError(SECRET, status=http_status, payload=body)


def case(script, transport="http", args=None, remaining=None):
    site = FakeSite(script)
    ctx = SimpleNamespace(
        account=SimpleNamespace(id="fake", base_url=ORIGIN, task_id="daily"),
        args=dict(args or {}), log=Mock(), expired=Mock(return_value=False),
        http=site if transport == "http" else SimpleNamespace(request=Mock(side_effect=Broken("浏览器步骤不能走 HTTP"))),
    )
    if remaining is not None:
        ctx.remaining_seconds = remaining
    page = FakePage(site) if transport == "browser" else None
    return ctx, page, site


def around(makeup, ctx, page, site, checkin=None):
    """走真实钩子入口；签到替身只记录调用时机。"""
    result = checkin if checkin is not None else success("签到成功", data={"balance": 1})

    async def attempt():
        site.calls.append(("CHECKIN", "", {}, None))
        return result

    return asyncio.run(makeup.around_checkin(ctx, page, attempt))


TRANSPORTS = pytest.mark.parametrize("transport", ["http", "browser"])
# ── 正常补签 ────────────────────────────────────────────────────────────────
@TRANSPORTS
@pytest.mark.parametrize("checkin", [success("签到成功"), already_done("今日已签到")])
def test_free_makeup_runs_before_checkin_and_keeps_checkin_verdict(makeup, transport, checkin):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, receipt(D1)),
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D1, D2, D3)),
    ], transport)
    outcome = around(makeup, ctx, page, site, checkin)
    assert outcome.verdict is checkin.verdict and outcome.reason == checkin.reason
    assert outcome.message == f"{checkin.message}；补签 1 天（{D1}），扣免费额度 $10.00"
    assert site.order() == [
        f"GET {STATUS}", f"GET {CALENDAR}", f"GET {PREVIEW}", f"POST {MAKEUP}", f"GET {STATUS}", f"GET {CALENDAR}",
        "CHECKIN",
    ], "补签必须在今日签到之前完成"
    assert site.calls[1][2] == {"month": "2026-10"} and site.calls[2][2] == {"date": D1}
    assert site.posts() == [{"date": D1}]
    data = outcome.data["makeup"]
    assert data["state"] == "done" and data["made_up"] == [D1] and data["free_spent"] == 10.0
    assert data["window_days"] == 3 and data["window_source"] == "default"
    assert data["activity_before"] == data["activity_after"] == 20
    assert not is_final(outcome) and not site.script
    json.dumps(outcome.to_payload(), ensure_ascii=False)


@TRANSPORTS
def test_site_threshold_beyond_free_days_is_skipped_not_paid(makeup, transport):
    """站点真实阈值比默认窗口小：更早一天 preview 为活跃度，只补免费的两天。"""
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar()),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, receipt(D1)),
        ("GET", STATUS, status()),
        ("GET", PREVIEW, preview(D2, 2)),
        ("POST", MAKEUP, receipt(D2)),
        ("GET", STATUS, status()),
        ("GET", PREVIEW, preview(D3, 3, cost_kind="activity", can_afford=True, free_cost=0)),
        ("GET", CALENDAR, calendar(D1, D2)),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == [{"date": D1}, {"date": D2}]
    assert outcome.data["makeup"]["skipped"] == {D3: "not_free"}
    assert outcome.message == f"签到成功；补签 2 天（{D1}、{D2}），扣免费额度 $20.00；{D3} 非免费额度补签，已跳过"
    assert outcome.verdict is Verdict.SUCCESS and not site.script
# ── 绝不提交的情形 ──────────────────────────────────────────────────────────
@TRANSPORTS
@pytest.mark.parametrize("fields", [
    {"cost_kind": "activity"},
    {"cost_kind": "activity", "activity_cost": 0, "free_cost": 0},
    {"cost_kind": "activity", "free_cost": 10},
    {"cost_kind": "FREE"},
    {"cost_kind": "paid"},
    {"cost_kind": ...},
    {"cost_kind": None},
], ids=["activity", "activity-zero-cost", "activity-with-free-cost", "upper", "paid", "missing", "null"])
def test_non_free_preview_is_never_submitted(makeup, transport, fields):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, preview(D1, 1, **fields)),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == []
    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.data["makeup"]["skipped"] == {D1: "not_free"}
    assert outcome.message == f"签到成功；{D1} 非免费额度补签，已跳过"
    assert not site.script


@TRANSPORTS
@pytest.mark.parametrize("fields,reason", [
    ({"can_afford": False}, "cannot_afford"),
    ({"can_afford": "true"}, "cannot_afford"),
    ({"can_afford": 1}, "cannot_afford"),
    ({"can_afford": ...}, "cannot_afford"),
    ({"free_cost": ...}, "invalid_preview"),
    ({"free_cost": -1}, "invalid_preview"),
    ({"free_cost": "abc"}, "invalid_preview"),
    ({"free_cost": True}, "invalid_preview"),
    ({"free_cost": 10, "free_balance": 9.99}, "invalid_preview"),
    ({"date": D2}, "invalid_preview"),
    ({"date": ...}, "invalid_preview"),
    ({"days_ago": "1"}, "invalid_preview"),
    ({"days_ago": ...}, "invalid_preview"),
])
def test_unaffordable_or_inconsistent_preview_is_never_submitted(makeup, transport, fields, reason):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, preview(D1, 1, **fields)),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == []
    assert outcome.data["makeup"]["skipped"] == {D1: reason}
    assert outcome.verdict is Verdict.SUCCESS and not site.script


@TRANSPORTS
@pytest.mark.parametrize("http_status", [None, 400, 403, 409])
@pytest.mark.parametrize("code,reason,shown", [
    ("CHECK_IN_MAKEUP_ALREADY", "already", False),
    ("CHECK_IN_MAKEUP_NEED_FREE", "cannot_afford", True),
    ("CHECK_IN_MAKEUP_NEED_ACTIVITY", "not_free", True),
    ("CHECK_IN_MAKEUP_NOT_PAST", "invalid_preview", True),
    ("SOMETHING_ELSE", "refused", True),
])
def test_preview_refusal_skips_the_day_without_leaking_site_text(makeup, transport, http_status, code, reason, shown):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, refused(code, http_status)),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == []
    assert outcome.data["makeup"]["skipped"] == {D1: reason}
    assert (outcome.message != "签到成功") is shown
    assert SECRET not in json.dumps(outcome.to_payload(), ensure_ascii=False)
    assert not site.script


@TRANSPORTS
def test_preview_disabled_stops_all_makeup(makeup, transport):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D3)),
        ("GET", PREVIEW, refused("CHECK_IN_MAKEUP_DISABLED", 403)),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == [] and not site.script, "关闭后不能再 preview 其他日期"
    assert outcome.data["makeup"]["state"] == "stopped"
    assert outcome.message == "签到成功；站点已关闭补签"


@TRANSPORTS
def test_preview_days_ago_mismatch_means_site_day_changed_and_stops(makeup, transport):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar()),
        ("GET", PREVIEW, preview(D1, 2)),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == [] and not site.script
    assert outcome.data["makeup"]["state"] == "stopped"
    assert "距今天数" in outcome.message and outcome.verdict is Verdict.SUCCESS
# ── 站点日切保护 ────────────────────────────────────────────────────────────
@TRANSPORTS
@pytest.mark.parametrize("moment", [
    datetime(2026, 11, 1, 23, 50, tzinfo=CST),
    datetime(2026, 11, 1, 23, 45, tzinfo=CST),
    datetime(2026, 11, 2, 0, 1, tzinfo=CST),
    datetime(2026, 10, 31, 23, 59, tzinfo=CST),
    datetime(2026, 11, 1, 15, 50, tzinfo=timezone.utc),
], ids=["10min-left", "exactly-guard", "local-next-day", "local-behind", "utc-input-near-cst-midnight"])
def test_no_submission_near_site_rollover_or_with_mismatched_clock(monkeypatch, makeup, transport, moment):
    clock(monkeypatch, makeup, moment)
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D3)),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == [] and not site.script, "临近日切不能 preview 或提交"
    assert outcome.data["makeup"]["skipped"] == {D1: "rollover", D2: "rollover"}
    assert outcome.message == f"签到成功；{D1}、{D2} 临近站点日切，顺延到下次运行"


def test_one_second_outside_the_guard_still_makes_up(monkeypatch, makeup):
    clock(monkeypatch, makeup, datetime(2026, 11, 1, 23, 44, 59, tzinfo=CST))
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, receipt(D1)),
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D1, D2, D3)),
    ])
    assert around(makeup, ctx, page, site).data["makeup"]["made_up"] == [D1]


def test_rollover_between_preview_and_submit_blocks_the_submit(monkeypatch, makeup):
    """费用种类在提交时才确定：preview 后跨入保护窗口就不能再提交。"""
    clock(monkeypatch, makeup, datetime(2026, 11, 1, 23, 40, tzinfo=CST), datetime(2026, 11, 1, 23, 50, tzinfo=CST))
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, preview(D1, 1)),
    ])
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == [] and not site.script
    assert outcome.data["makeup"]["skipped"] == {D1: "rollover"}


# ── 活跃度保护 ──────────────────────────────────────────────────────────────
@TRANSPORTS
@pytest.mark.parametrize("bad_receipt,readback,violation", [
    (receipt(D1, activity_score=19), status(), "活跃度下降（20 → 19）"),
    (receipt(D1), status(activity_score=19), "活跃度下降（20 → 19）"),
    (receipt(D1, cost_kind="activity"), status(), "回执显示非免费补签"),
    (receipt(D1, cost_kind="free", cost_activity=1), status(), "回执显示消耗了活跃度"),
    (receipt(D1, cost_activity="x"), status(), "回执显示消耗了活跃度"),
], ids=["receipt-drop", "readback-drop", "receipt-kind", "receipt-cost", "receipt-cost-garbage"])
def test_any_sign_of_activity_spend_fails_the_task_and_stops(makeup, transport, bad_receipt, readback, violation):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar()),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, bad_receipt),
        ("GET", STATUS, readback),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert outcome.verdict is Verdict.FAILED and outcome.reason == makeup.VIOLATION_REASON
    assert is_final(outcome), "活跃度违规不能回退浏览器再补一次"
    assert outcome.data["makeup"]["violation"] == violation
    assert outcome.data["checkin"] == {"verdict": "success", "reason": ""}
    assert site.posts() == [{"date": D1}], "发现违规后不能再补其他日期"
    assert site.order()[-1] == "CHECKIN" and not site.script, "签到本身不消耗活跃度，仍照常完成"
    assert outcome.message.startswith(f"签到成功；⚠ 补签后{violation}，已停止补签")


def test_baseline_follows_latest_readback_across_days(makeup):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, receipt(D1, activity_score=23)),
        ("GET", STATUS, status(activity_score=23)),
        ("GET", PREVIEW, preview(D2, 2)),
        ("POST", MAKEUP, receipt(D2, activity_score=22)),
        ("GET", STATUS, status(activity_score=22)),
    ])
    outcome = around(makeup, ctx, page, site)
    assert outcome.reason == makeup.VIOLATION_REASON
    assert outcome.data["makeup"]["violation"] == "活跃度下降（23 → 22）"
    assert not site.script
# ── 提交被拒 / 不明确 ───────────────────────────────────────────────────────
@TRANSPORTS
@pytest.mark.parametrize("http_status", [None, 409])
@pytest.mark.parametrize("code,reason", [("CHECK_IN_MAKEUP_ALREADY", "already"), ("CHECK_IN_MAKEUP_NEED_FREE", "cannot_afford")])
def test_benign_submit_refusal_moves_on_to_next_day(makeup, transport, http_status, code, reason):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, refused(code, http_status)),
        ("GET", PREVIEW, preview(D2, 2)),
        ("POST", MAKEUP, receipt(D2)),
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert outcome.data["makeup"]["made_up"] == [D2]
    assert outcome.data["makeup"]["skipped"] == {D1: reason}
    assert outcome.verdict is Verdict.SUCCESS and not site.script


@TRANSPORTS
@pytest.mark.parametrize("code,note", [
    ("CHECK_IN_MAKEUP_NEED_ACTIVITY", f"{D1} 提交时站点改要活跃度（与预估不一致），已停止补签"),
    ("CHECK_IN_MAKEUP_DISABLED", f"{D1} 站点拒绝补签（CHECK_IN_MAKEUP_DISABLED），已停止补签"),
    ("", f"{D1} 站点拒绝补签（未知原因），已停止补签"),
])
def test_unexpected_submit_refusal_stops_without_violation(makeup, transport, code, note):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar()),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, refused(code)),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert outcome.verdict is Verdict.SUCCESS, "被拒说明没有执行，不构成活跃度违规"
    assert outcome.data["makeup"]["state"] == "stopped" and "made_up" not in outcome.data["makeup"]
    assert outcome.message == f"签到成功；{note}"
    assert SECRET not in json.dumps(outcome.to_payload(), ensure_ascii=False)
    assert not site.script


@TRANSPORTS
@pytest.mark.parametrize("reply", [
    TransientError(SECRET), TaskError(SECRET, status=502, reason="network_error"),
    "not-json", {}, ok([]), {"code": 0, "data": None},
], ids=["timeout", "502", "text", "empty", "list-data", "null-data"])
def test_ambiguous_submit_reads_back_once_and_never_resubmits(makeup, transport, reply):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, reply),
        ("GET", STATUS, status()),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == [{"date": D1}] and not site.script, "结果不明确只回读，不重发、不补下一天"
    data = outcome.data["makeup"]
    assert data["unconfirmed"] == [D1] and "made_up" not in data and data["state"] == "stopped"
    assert outcome.message == f"签到成功；{D1} 补签提交未确认，下次运行重新核对"
    assert outcome.verdict is Verdict.SUCCESS
    assert SECRET not in json.dumps(outcome.to_payload(), ensure_ascii=False)


def test_ambiguous_submit_with_activity_drop_is_a_violation(makeup):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, TransientError("timeout")),
        ("GET", STATUS, status(activity_score=19)),
    ])
    outcome = around(makeup, ctx, page, site)
    assert outcome.reason == makeup.VIOLATION_REASON and is_final(outcome)
    assert outcome.data["makeup"]["unconfirmed"] == [D1]


@TRANSPORTS
def test_submit_login_failure_stops_without_marking_unconfirmed(makeup, transport):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, LoginRequired(SECRET, status=401)),
    ], transport)
    outcome = around(makeup, ctx, page, site)
    assert "unconfirmed" not in outcome.data["makeup"] and not site.script
    assert outcome.message == "签到成功；补签时登录态失效，已停止补签"


def test_readback_failure_after_submit_stops_further_makeup(makeup):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, receipt(D1)),
        ("GET", STATUS, status(activity_score=...)),
        ("GET", CALENDAR, calendar(D1, D3)),
    ])
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == [{"date": D1}] and not site.script, "停止后只做一次只读日历核对，不补下一天"
    assert outcome.data["makeup"]["made_up"] == [D1]
    assert outcome.message.endswith("补签后未能回读活跃度，已停止补签")
# ── 补签问题不挡签到 ────────────────────────────────────────────────────────
@TRANSPORTS
@pytest.mark.parametrize("checkin", [
    success("签到成功"), already_done("今日已签到"), failed("签到未获服务端确认", reason="unconfirmed"),
])
@pytest.mark.parametrize("reply,note", [
    (LoginRequired(SECRET, status=401), "补签未执行：登录态失效"),
    (TransientError(SECRET), "补签未执行：站点不可达"),
    (status(check_in_date=...), "补签未执行：签到状态缺少站点今天日期，无法判断哪天漏签"),
    (status(check_in_date="11/01"), "补签未执行：签到状态缺少站点今天日期，无法判断哪天漏签"),
    (status(activity_score=...), "补签未执行：签到状态缺少有效活跃度，无法证明补签不动用活跃度"),
    (status(activity_score="20"), "补签未执行：签到状态缺少有效活跃度，无法证明补签不动用活跃度"),
    (status(activity_score=-1), "补签未执行：签到状态缺少有效活跃度，无法证明补签不动用活跃度"),
    (refused("SOME_REASON"), "补签未执行：站点拒绝补签请求（SOME_REASON）"),
    ({"code": 0, "data": "x"}, "补签未执行：补签接口响应缺少数据对象"),
])
def test_status_problems_never_block_or_change_the_checkin(makeup, transport, checkin, reply, note):
    ctx, page, site = case([("GET", STATUS, reply)], transport)
    outcome = around(makeup, ctx, page, site, checkin)
    assert (outcome.verdict, outcome.reason) == (checkin.verdict, checkin.reason)
    assert outcome.message == f"{checkin.message}；{note}"
    assert site.order() == [f"GET {STATUS}", "CHECKIN"] and site.posts() == []
    assert outcome.data["makeup"]["state"] == "stopped"
    assert SECRET not in json.dumps(outcome.to_payload(), ensure_ascii=False)


@TRANSPORTS
@pytest.mark.parametrize("fields", [
    {"makeup_enabled": False}, {"makeup_enabled": ...}, {"makeup_enabled": "true"}, {"makeup_enabled": 1},
    {"enabled": False},
])
def test_closed_makeup_only_reads_status(makeup, transport, fields):
    ctx, page, site = case([("GET", STATUS, status(**fields))], transport)
    outcome = around(makeup, ctx, page, site)
    assert outcome.message == "签到成功" and outcome.data["makeup"] == {"state": "not_open"}
    assert site.order() == [f"GET {STATUS}", "CHECKIN"]


@TRANSPORTS
@pytest.mark.parametrize("value", [False, "false", "0", "off", "no"])
def test_makeup_arg_off_sends_nothing(makeup, transport, value):
    ctx, page, site = case([], transport, args={"makeup": value})
    outcome = around(makeup, ctx, page, site)
    assert outcome.message == "签到成功" and outcome.data["makeup"] == {"state": "off"}
    assert site.order() == ["CHECKIN"]
    if page is not None:
        page.evaluate.assert_not_awaited()


@pytest.mark.parametrize("configured,window,source", [
    (..., 3, "default"), (None, 3, "default"), (0, 3, "default"), (-2, 3, "default"), (True, 3, "default"),
    ("5", 3, "default"), (2.0, 3, "default"), (1, 1, "site"), (5, 5, "site"), (31, 31, "site"), (99, 31, "site"),
])
def test_window_follows_site_threshold_with_default_and_cap(makeup, configured, window, source):
    days = [(datetime(2026, 11, 1) - timedelta(days=offset)).date().isoformat() for offset in range(1, 32)]
    ctx, page, site = case([
        ("GET", STATUS, status(makeup_near_max_days=configured)),
        ("GET", CALENDAR, calendar(*days)),
    ])
    outcome = around(makeup, ctx, page, site)
    data = outcome.data["makeup"]
    assert data == {"state": "none", "window_days": window, "window_source": source}
    assert site.calls[1][2] == {"month": "2026-10"} and not site.script


def test_window_scans_only_days_inside_the_threshold(makeup):
    ctx, page, site = case([
        ("GET", STATUS, status(makeup_near_max_days=1)),
        ("GET", CALENDAR, calendar(D1)),
    ])
    outcome = around(makeup, ctx, page, site)
    assert outcome.data["makeup"]["state"] == "none", "阈值外的漏签（10-30、10-29）不看、不补"
    assert site.posts() == []


def test_window_across_months_reads_both_calendars(monkeypatch, makeup):
    clock(monkeypatch, makeup, datetime(2026, 11, 2, 10, 0, tzinfo=CST))
    ctx, page, site = case([
        ("GET", STATUS, status(check_in_date="2026-11-02")),
        ("GET", CALENDAR, calendar(D1, D2)),
        ("GET", CALENDAR, calendar()),
        ("GET", PREVIEW, preview(TODAY, 1)),
        ("POST", MAKEUP, receipt(TODAY, check_in_date="2026-11-02")),
        ("GET", STATUS, status(check_in_date="2026-11-02")),
        ("GET", CALENDAR, calendar(TODAY)),
    ])
    outcome = around(makeup, ctx, page, site)
    assert [call[2] for call in site.calls if call[1] == CALENDAR] == [
        {"month": "2026-10"}, {"month": "2026-11"}, {"month": "2026-11"},
    ]
    assert outcome.data["makeup"]["made_up"] == [TODAY] and not site.script
@pytest.mark.parametrize("bad", [ok({"dates": "2026-10-31"}), ok({"days": {"date": D1}}), ok([])])
def test_malformed_calendar_never_guesses_missed_days(makeup, bad):
    ctx, page, site = case([("GET", STATUS, status()), ("GET", CALENDAR, bad)])
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == [] and not site.script
    assert outcome.data["makeup"]["state"] == "stopped" and outcome.message.startswith("签到成功；补签未执行：")


def test_submit_not_seen_in_calendar_is_reported_unconfirmed(makeup):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, receipt(D1)),
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
    ])
    outcome = around(makeup, ctx, page, site)
    data = outcome.data["makeup"]
    assert "made_up" not in data and data["unconfirmed"] == [D1]
    assert outcome.message == f"签到成功；{D1} 补签提交未确认，下次运行重新核对"


def test_confirmation_read_failure_keeps_the_confirmed_submit(makeup):
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, receipt(D1)),
        ("GET", STATUS, status()),
        ("GET", CALENDAR, TransientError("timeout")),
    ])
    assert around(makeup, ctx, page, site).data["makeup"]["made_up"] == [D1]


def test_time_budget_reserves_room_for_todays_checkin(makeup):
    """每个请求「消耗」40 秒；剩余不足 45 秒时其余日期顺延，不再核对日历。"""
    ctx, page, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, receipt(D1)),
        ("GET", STATUS, status()),
    ], remaining=lambda: 200 - 40 * len(site.calls))
    outcome = around(makeup, ctx, page, site)
    assert site.posts() == [{"date": D1}] and not site.script
    assert outcome.data["makeup"]["skipped"] == {D2: "no_time"}
    assert outcome.message == f"签到成功；补签 1 天（{D1}），扣免费额度 $10.00；{D2} 时间预算不足，顺延到下次运行"


def test_no_budget_means_no_makeup_requests(makeup):
    ctx, page, site = case([], remaining=lambda: 30)
    outcome = around(makeup, ctx, page, site)
    assert site.order() == ["CHECKIN"] and outcome.message == "签到成功；补签未执行：时间预算不足"


@pytest.mark.parametrize("url", ["https://other.test/check-in", "about:blank"])
def test_browser_never_uses_a_page_outside_the_account_site(makeup, url):
    ctx, page, site = case([], "browser")
    page.url = url
    outcome = around(makeup, ctx, page, site)
    page.evaluate.assert_not_awaited()
    assert outcome.message == "签到成功；补签未执行：登录态失效"
# ── 页内请求脚本（Node 离线执行，无真实网络）──────────────────────────────
@pytest.fixture(scope="module")
def node_executable():
    node = shutil.which("node")
    if not node:
        try:
            from playwright._impl._driver import compute_driver_executable
            node = compute_driver_executable()[0]
        except ImportError:
            pytest.skip("缺少 Node/Playwright driver，无法执行页内 JS")
    if not Path(node).exists():
        pytest.skip("本机无 JavaScript 运行时")
    return str(node)


NODE_HARNESS = r"""
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const store = {auth_token: 'synthetic-access'};
global.localStorage = {getItem: k => store[k] ?? null, setItem: (k, v) => { store[k] = String(v); }};
if (input.origin) global.location = {origin: input.origin};
const calls = [];
global.fetch = async (url, options = {}) => {
  calls.push({url, method: options.method, headers: options.headers, body: options.body ?? null,
              redirect: options.redirect, credentials: options.credentials});
  return {status: 200, ok: true, text: async () => JSON.stringify({code: 0, data: {echo: true}})};
};
(async () => {
  const result = await eval('(' + input.script + ')')(input.argument);
  process.stdout.write(JSON.stringify({result, calls}));
})().catch(error => { console.error(error); process.exitCode = 1; });
"""


def run_page_script(node, makeup, argument, origin=ORIGIN):
    execution = subprocess.run(
        [node, "-e", NODE_HARNESS],
        input=json.dumps({"script": makeup._PAGE_REQUEST_JS, "argument": argument, "origin": origin}),
        text=True, encoding="utf-8", capture_output=True, check=True, timeout=15,
    )
    return json.loads(execution.stdout)


@pytest.mark.parametrize("method,body", [("POST", {"date": D1}), ("GET", None)])
def test_page_script_sends_same_origin_bearer_request(node_executable, makeup, method, body):
    path = MAKEUP if method == "POST" else PREVIEW + "?date=" + D1
    output = run_page_script(node_executable, makeup, {
        "baseUrl": ORIGIN, "method": method, "path": path, "body": body, "timeoutMs": 5000,
    })
    assert output["result"] == {"status": 200, "payload": {"code": 0, "data": {"echo": True}}}
    (call,) = output["calls"]
    assert call["url"] == ORIGIN + path and call["method"] == method
    assert call["headers"]["Authorization"] == "Bearer synthetic-access"
    assert call["redirect"] == "error" and call["credentials"] == "include"
    assert call["body"] == (json.dumps(body, separators=(",", ":")) if body else None)


@pytest.mark.parametrize("origin", ["https://other.test", None])
def test_page_script_refuses_foreign_or_unknown_origin(node_executable, makeup, origin):
    output = run_page_script(node_executable, makeup, {
        "baseUrl": ORIGIN, "method": "POST", "path": MAKEUP, "body": {"date": D1}, "timeoutMs": 5000,
    }, origin=origin)
    assert output == {"result": {"status": -1}, "calls": []}


# ── 接入：模板与共享流程 ────────────────────────────────────────────────────
def test_template_installs_the_makeup_hook_and_toggle(makeup):
    template = importlib.import_module("scripts.tasks.100xlabs")
    assert template.makeup is makeup
    assert template.SPEC.around_checkin is makeup.around_checkin and template.SPEC.strict_checkin is True
    spec = template.MANIFEST.task_option("script").args.get("makeup")
    assert spec is not None and spec.kind == "bool" and spec.default is True


def test_http_attempt_makes_up_before_the_real_strict_checkin(makeup):
    template = importlib.import_module("scripts.tasks.100xlabs")
    ctx, _, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, receipt(D1)),
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D1, D2, D3)),
        ("GET", STATUS, status()),
        ("POST", "/api/v1/check-in", ok({"checked_in_today": True, "reward_amount": 5, "balance": 6})),
        ("GET", STATUS, status(checked_in_today=True, balance=6)),
    ])
    outcome = asyncio.run(template.flow.http_attempt(ctx, template.SPEC))
    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.message == f"签到成功；补签 1 天（{D1}），扣免费额度 $10.00"
    assert site.order().index(f"POST {MAKEUP}") < site.order().index("POST /api/v1/check-in")
    assert outcome.data["makeup"]["made_up"] == [D1] and not site.script


def test_http_handoff_keeps_the_makeup_note_and_still_falls_back(makeup):
    template = importlib.import_module("scripts.tasks.100xlabs")
    ctx, _, site = case([
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D2, D3)),
        ("GET", PREVIEW, preview(D1, 1)),
        ("POST", MAKEUP, receipt(D1)),
        ("GET", STATUS, status()),
        ("GET", CALENDAR, calendar(D1, D2, D3)),
        ("GET", STATUS, status(turnstile_required=True)),
    ])
    outcome = asyncio.run(template.flow.http_attempt(ctx, template.SPEC))
    assert outcome.verdict is Verdict.FAILED and outcome.reason == "need_verification"
    assert not is_final(outcome), "签到仍需交给浏览器步骤"
    assert outcome.message.endswith(f"；补签 1 天（{D1}），扣免费额度 $10.00")
    assert site.posts("/api/v1/check-in") == [] and not site.script


def test_http_attempt_without_credentials_skips_makeup_entirely(makeup):
    template = importlib.import_module("scripts.tasks.100xlabs")
    ctx, _, site = case([])
    site.headers = {}
    outcome = asyncio.run(template.flow.http_attempt(ctx, template.SPEC))
    assert outcome.reason == "need_login" and site.calls == []


def test_browser_flow_calls_hook_with_the_verified_page(monkeypatch, makeup):
    import sdk
    from sdk import PageHelpers

    class MutableHelpers(PageHelpers):
        """无 __slots__ 的子类：保留真实结论构造器，同时允许替换 resolve_url。"""

    flow = makeup.flow
    seen = {}

    async def hook(ctx, page, attempt):
        seen.update(ctx=ctx, page=page)
        return (await attempt()).with_data(hooked=True)

    spec = flow.SiteSpec("测试站点", "/api/v1/check-in", "t", "t", status_path=STATUS,
                         strict_checkin=True, around_checkin=hook)
    ctx = SimpleNamespace(args={}, log=Mock())
    page = SimpleNamespace(url=ORIGIN + "/check-in")
    lease = SimpleNamespace(page=page, context=object(), mark_authenticated=Mock())
    helpers = MutableHelpers(ctx, lease, page)
    helpers.resolve_url = lambda path: ORIGIN + path
    monkeypatch.setattr(sdk, "PageHelpers", lambda *_: helpers)
    for name in ("add_init_script", "navigate_and_settle", "dismiss_notice"):
        monkeypatch.setattr(flow, name, AsyncMock())
    monkeypatch.setattr(flow, "on_login_page", AsyncMock(return_value=False))
    monkeypatch.setattr(flow, "authenticated", AsyncMock(return_value=True))
    monkeypatch.setattr(flow, "query_status", AsyncMock(
        return_value=flow._strict_checkin_response(status(), state=True)))
    checkin = AsyncMock(return_value={"ok": True, "already": False, "status": 200, "balance": 1, "reward": 1})
    monkeypatch.setattr(flow, "api_checkin", checkin)
    outcome = asyncio.run(flow.run_flow(ctx, lease, spec))
    assert seen == {"ctx": ctx, "page": page}
    assert outcome.verdict is Verdict.SUCCESS and outcome.data["hooked"] is True
    checkin.assert_awaited_once()
    lease.mark_authenticated.assert_called_once()
