"""百倍/林夕签到补签：只补免费额度能补的近几天，绝不使用活跃度补签。

站点协议（两站同一前端版本，取自签到页与管理端配置）：

- ``GET /api/v1/check-in/status``：``makeup_enabled``、``check_in_date``（站点今天）、
  ``activity_score``；管理端的 ``makeup_near_max_days``（默认 3）用户端未必返回。
- ``GET /api/v1/check-in/calendar?month=YYYY-MM``：``dates`` / ``days[].date`` 是已签日期。
- ``GET /api/v1/check-in/makeup/preview?date=``：只读预估 ``days_ago``、``cost_kind``
  （free / activity）、``free_cost``、``can_afford``。
- ``POST /api/v1/check-in/makeup {"date"}``：只传日期。**扣哪一种由服务端按提交时的距今天数
  决定**：不超过近几天阈值扣免费额度，更早扣活跃度。

安全规则：

1. 只看阈值内（站点未返回时默认近 3 天）且日历没有记录的日期；
2. 每个日期先 preview，仅 ``cost_kind == "free"``、``can_afford is True`` 且距今天数与站点
   今天一致才提交；``activity`` 一律跳过，费用为 0 也不例外；
3. 费用种类在提交时才确定：临近站点日切、或本机日期与站点今天不一致时不提交，免得
   「近几天」在提交瞬间变成「更早」而改扣活跃度；
4. 每次提交后回读状态：活跃度下降或回执不是免费补签即停止补签并判失败；站点今天变化
   同样停止。提交结果不明确只回读、不重发（站点按日期去重，下次运行重新核对日历）；
5. 站点说明补签不发签到奖励、计入抽奖连续；是否接上签到连续未经验证，所以放在今日签到
   之前，让今日签到有机会接上。补签自身的问题（未开放、额度不足、接口异常）不改变签到
   结论，只附在消息与 ``data.makeup`` 里。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Awaitable, Callable
from urllib.parse import urlencode

import _sub2api_flow as flow

from sdk import REASONS, LoginRequired, Outcome, TaskError, Verdict, chain_final

STATUS_PATH = "/api/v1/check-in/status"
CALENDAR_PATH = "/api/v1/check-in/calendar"
PREVIEW_PATH = "/api/v1/check-in/makeup/preview"
MAKEUP_PATH = "/api/v1/check-in/makeup"
#: 站点未返回 ``makeup_near_max_days`` 时的窗口：管理端默认值即近 3 天免费补签。
DEFAULT_WINDOW_DAYS = 3
#: 站点阈值的安全上限，防止异常配置让一次运行扫描、提交过多日期。
MAX_WINDOW_DAYS = 31
#: 两站公开配置 server_timezone=Asia/Shanghai（+08:00），签到日按它切换。
SITE_TZ = timezone(timedelta(hours=8))
#: 距站点日切不足这么久不提交补签。CI 在 09:30 / 15:30 运行，远离日切；本机若时钟偏差
#: 超过此值，日期比对会先不一致而跳过。
ROLLOVER_GUARD_SECONDS = 15 * 60
#: 每个日期开始前至少留给今日签到的时间（秒）。补签是附带动作，不能挤掉签到本身。
CHECKIN_RESERVE_SECONDS = 45.0
REQUEST_TIMEOUT_SECONDS = 20

VIOLATION_REASON = "makeup_activity_spent"
REASONS.register(
    VIOLATION_REASON, verdict=Verdict.FAILED, label="补签动用活跃度", icon="🛑", actionable=True,
    description="补签后活跃度下降或回执不是免费补签；已停止补签，需人工到站点核对。",
)

#: 跳过原因 → 摘要文案。already 是日历与 preview 的正常差异，不进消息。
SKIP_TEXT = {
    "not_free": "非免费额度补签，已跳过",
    "cannot_afford": "免费额度不足",
    "rollover": "临近站点日切，顺延到下次运行",
    "no_time": "时间预算不足，顺延到下次运行",
    "invalid_preview": "预估数据异常，未提交",
    "refused": "站点拒绝补签",
}
#: preview 的业务拒绝 → 跳过原因（preview 只读，拒绝不会产生任何扣费）。
PREVIEW_REFUSALS = {
    "CHECK_IN_MAKEUP_ALREADY": "already",
    "CHECK_IN_MAKEUP_NEED_FREE": "cannot_afford",
    "CHECK_IN_MAKEUP_NEED_ACTIVITY": "not_free",
    "CHECK_IN_MAKEUP_NOT_PAST": "invalid_preview",
}


def _site_now() -> datetime:
    """站点时区的当前时间；测试替换它来模拟日切。"""
    return datetime.now(SITE_TZ)


class _Refused(TaskError):
    """站点明确的业务拒绝（code≠0 或 4xx 带机器可读 reason）：请求没有被执行。"""

    def __init__(self, code: str, *, status: int | None = None) -> None:
        super().__init__(f"站点拒绝补签请求（{code or '未知原因'}）", reason="unconfirmed", status=status)
        self.code = code


class _Invalid(TaskError):
    """本模块自己的一致性校验失败；message 是写给用户的完整说明。"""

    def __init__(self, message: str) -> None:
        super().__init__(message, reason="unconfirmed")


def _reason_code(payload: Any) -> str:
    """只取机器可读的 reason（如 CHECK_IN_MAKEUP_ALREADY），不回显站点原文。"""
    for part in (payload, payload.get("data") if isinstance(payload, dict) else None):
        if not isinstance(part, dict):
            continue
        for key in ("reason", "error", "code"):
            value = part.get(key)
            if isinstance(value, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", value.strip()):
                return value.strip()
    return ""


def _data(raw: Any) -> dict[str, Any]:
    """Sub2API 信封：与前端拦截器一致，只有 code 为 0 才算业务成功。"""
    if not isinstance(raw, dict) or not raw:
        raise _Invalid("补签接口未返回有效 JSON")
    code = raw.get("code", 0)
    if raw.get("success") is False or isinstance(code, bool) or code not in (0, "0"):
        raise _Refused(_reason_code(raw))
    data = raw.get("data", raw)
    if not isinstance(data, dict):
        raise _Invalid("补签接口响应缺少数据对象")
    return data


_PAGE_REQUEST_JS = "async ({baseUrl, method, path, body, timeoutMs}) => {\n" + \
    "if (typeof location === 'undefined' || location.origin !== new URL(baseUrl).origin) return {status: -1};\n" + \
    flow._PAGE_AUTH_REQUEST_HELPERS_JS + """
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await requestWithAuth(token => fetch(baseUrl + path, {
            method, redirect: 'error', credentials: 'include', signal: controller.signal,
            headers: {Authorization: `Bearer ${token}`, Accept: 'application/json',
                      'Content-Type': 'application/json'},
            body: method === 'POST' ? JSON.stringify(body) : undefined,
        }));
        if (!response) return {status: 401};
        return {status: response.status, payload: await parseBody(response)};
    } catch (_) {
        return {status: 0};
    } finally { clearTimeout(timer); }
}"""


class _Client:
    """纯 HTTP 走 ``ctx.http``（自带续期）；浏览器步骤在已登录页面里同源 fetch。"""

    def __init__(self, ctx: Any, page: Any = None) -> None:
        self.ctx = ctx
        self.page = page
        self.origin = flow.origin_of(ctx.account.base_url)

    async def get(self, path: str, query: dict[str, str] | None = None) -> dict[str, Any]:
        target = path + ("?" + urlencode(query) if query else "")
        return _data(await self._request("GET", target))

    async def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return _data(await self._request("POST", path, body))

    async def _request(self, method: str, path: str, body: Any = None) -> Any:
        if self.page is not None:
            return await self._page_request(method, path, body)
        try:
            return self.ctx.http.request(
                method, path, json_body=body, retry_non_idempotent=False, timeout=_request_timeout(self.ctx),
            )
        except TaskError as exc:
            code = _reason_code(exc.payload)
            status = exc.status or 0
            # 站点可能用 403 表达业务拒绝；带 reason 的 4xx 就是明确拒绝，不当作登录失效。
            if code and 400 <= status < 500 and status not in (401, 429):
                raise _Refused(code, status=status) from exc
            raise

    async def _page_request(self, method: str, path: str, body: Any) -> Any:
        if flow.origin_of(str(self.page.url)) != self.origin:
            raise LoginRequired("补签页面已离开账号站点，停止请求")
        try:
            result = await self.page.evaluate(_PAGE_REQUEST_JS, {
                "baseUrl": self.origin, "method": method, "path": path, "body": body,
                "timeoutMs": _request_timeout(self.ctx) * 1000,
            })
        except Exception as exc:
            raise TaskError("补签浏览器请求中断", reason="network_error") from exc
        status = result.get("status") if isinstance(result, dict) else None
        if type(status) is not int:
            raise _Invalid("补签浏览器接口缺少有效 HTTP 状态")
        if status in (-1, 401):
            raise LoginRequired("补签登录态已失效")
        payload = result.get("payload")
        if 200 <= status < 300:
            return payload
        code = _reason_code(payload)
        if code and 400 <= status < 500 and status != 429:
            raise _Refused(code, status=status)
        reason = "network_error" if status in (0, 429) or status >= 500 else "unconfirmed"
        raise TaskError("补签接口返回非成功 HTTP 状态", status=status, reason=reason)


def _remaining(ctx: Any) -> float | None:
    getter = getattr(ctx, "remaining_seconds", None)
    value = getter() if callable(getter) else None
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _no_time(ctx: Any) -> bool:
    expired = getattr(ctx, "expired", None)
    if callable(expired) and expired() is True:
        return True
    remaining = _remaining(ctx)
    return remaining is not None and remaining < CHECKIN_RESERVE_SECONDS


def _request_timeout(ctx: Any) -> int:
    remaining = _remaining(ctx)
    if remaining is None:
        return REQUEST_TIMEOUT_SECONDS
    return max(5, min(REQUEST_TIMEOUT_SECONDS, int(remaining - CHECKIN_RESERVE_SECONDS)))


def _day(value: Any) -> date | None:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value.strip()[:10]):
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def _amount(value: Any) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        return None
    return amount if amount.is_finite() and amount >= 0 else None


@dataclass(frozen=True)
class _Status:
    today: date
    activity: int
    window: int
    window_source: str


def _status(data: dict[str, Any]) -> _Status:
    today = _day(data.get("check_in_date"))
    if today is None:
        raise _Invalid("签到状态缺少站点今天日期，无法判断哪天漏签")
    activity = data.get("activity_score")
    # 没有活跃度就无法证明补签没动用它，宁可不补。
    if type(activity) is not int or activity < 0:
        raise _Invalid("签到状态缺少有效活跃度，无法证明补签不动用活跃度")
    configured = data.get("makeup_near_max_days")
    if type(configured) is int and configured > 0:
        return _Status(today, activity, min(configured, MAX_WINDOW_DAYS), "site")
    return _Status(today, activity, DEFAULT_WINDOW_DAYS, "default")


@dataclass
class _Report:
    state: str = "none"
    window: int = 0
    window_source: str = ""
    missed: list[str] = field(default_factory=list)
    made_up: dict[str, Decimal] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)
    unconfirmed: list[str] = field(default_factory=list)
    activity_before: int | None = None
    activity_after: int | None = None
    violation: str = ""
    note: str = ""

    def payload(self) -> dict[str, Any]:
        data: dict[str, Any] = {"state": self.state}
        if self.window:
            data.update(window_days=self.window, window_source=self.window_source)
        for key in ("missed", "unconfirmed"):
            if getattr(self, key):
                data[key] = list(getattr(self, key))
        if self.made_up:
            data["made_up"] = list(self.made_up)
            data["free_spent"] = float(sum(self.made_up.values(), Decimal(0)))
        if self.skipped:
            data["skipped"] = dict(self.skipped)
        if self.made_up or self.unconfirmed or self.violation:
            data.update(activity_before=self.activity_before, activity_after=self.activity_after)
        if self.violation:
            data["violation"] = self.violation
        if self.note:
            data["note"] = self.note
        return data


def _money(value: Decimal) -> str:
    return f"${value:.2f}"


def _summary(report: _Report) -> str:
    parts: list[str] = []
    if report.violation:
        parts.append(f"⚠ 补签后{report.violation}，已停止补签，请到站点核对活跃度")
    if report.made_up:
        spent = sum(report.made_up.values(), Decimal(0))
        parts.append(f"补签 {len(report.made_up)} 天（{'、'.join(report.made_up)}），扣免费额度 {_money(spent)}")
    grouped: dict[str, list[str]] = {}
    for day, reason in report.skipped.items():
        if reason in SKIP_TEXT:
            grouped.setdefault(reason, []).append(day)
    for reason, days in grouped.items():
        parts.append(f"{'、'.join(days)} {SKIP_TEXT[reason]}")
    if report.unconfirmed:
        parts.append(f"{'、'.join(report.unconfirmed)} 补签提交未确认，下次运行重新核对")
    if report.note:
        parts.append(report.note)
    return "；".join(parts)


def _merge(outcome: Outcome, report: _Report) -> Outcome:
    merged = outcome.with_data(makeup=report.payload())
    summary = _summary(report)
    if summary:
        merged = merged.with_message(f"{merged.message}；{summary}" if merged.message else summary)
    if not report.violation:
        return merged
    # 签到本身不消耗活跃度，照常完成；但活跃度补签被明确禁止，出现即判失败、不回退浏览器。
    failure = merged.as_reason(VIOLATION_REASON, verdict=Verdict.FAILED).with_data(
        checkin={"verdict": str(outcome.verdict), "reason": outcome.reason},
    )
    return chain_final(failure)


async def _recorded_days(client: _Client, days: list[date]) -> set[str]:
    """日历里已有记录（含已补签）的日期；按月读取，跨月窗口读两个月。"""
    recorded: set[str] = set()
    for month in sorted({day.strftime("%Y-%m") for day in days}):
        data = await client.get(CALENDAR_PATH, {"month": month})
        for key in ("dates", "days"):
            items = data.get(key)
            if items is None:
                continue
            if not isinstance(items, list):
                raise _Invalid("签到日历格式无效")
            for item in items:
                value = item.get("date") if isinstance(item, dict) else item
                parsed = _day(value)
                if parsed is not None:
                    recorded.add(parsed.isoformat())
    return recorded


def _check_preview(preview: dict[str, Any], day: date, today: date) -> str:
    """ok / rollover（站点今天已变化）/ not_free / cannot_afford / invalid_preview。"""
    if _day(preview.get("date")) != day:
        return "invalid_preview"
    days_ago = preview.get("days_ago")
    if type(days_ago) is not int:
        return "invalid_preview"
    if days_ago != (today - day).days:
        return "rollover"
    if preview.get("cost_kind") != "free":
        return "not_free"
    if preview.get("can_afford") is not True:
        return "cannot_afford"
    cost = _amount(preview.get("free_cost"))
    balance = _amount(preview.get("free_balance"))
    if cost is None or (balance is not None and balance < cost):
        return "invalid_preview"
    return "ok"


def _clock_safe(today: date) -> bool:
    """本机按站点时区的日期必须等于站点今天，且离下一次日切足够远。"""
    now = _site_now()
    now = now.astimezone(SITE_TZ) if now.tzinfo else now.replace(tzinfo=SITE_TZ)
    if now.date() != today:
        return False
    midnight = datetime.combine(today + timedelta(days=1), datetime.min.time(), SITE_TZ)
    return (midnight - now).total_seconds() > ROLLOVER_GUARD_SECONDS


def _receipt_violation(receipt: dict[str, Any], baseline: int) -> str:
    kind = receipt.get("cost_kind")
    if kind is not None and kind != "free":
        return "回执显示非免费补签"
    spent = receipt.get("cost_activity")
    if spent is not None and _amount(spent) != 0:
        return "回执显示消耗了活跃度"
    after = receipt.get("activity_score")
    if type(after) is int and after < baseline:
        return f"活跃度下降（{baseline} → {after}）"
    return ""


async def _readback(client: _Client, report: _Report, baseline: int) -> _Status | None:
    """只读复查当前状态；活跃度下降记为违规。读不到返回 None。"""
    try:
        after = _status(await client.get(STATUS_PATH))
    except Exception:
        return None
    report.activity_after = after.activity
    if after.activity < baseline:
        report.violation = report.violation or f"活跃度下降（{baseline} → {after.activity}）"
    return after


async def _process(ctx: Any, client: _Client, report: _Report, status: _Status, day: date) -> str:
    """补一个日期。返回 next（继续）/ rollover、no_time（顺延其余日期）/ stop。"""
    key = day.isoformat()
    if _no_time(ctx):
        return "no_time"
    if not _clock_safe(status.today):
        return "rollover"
    try:
        preview = await client.get(PREVIEW_PATH, {"date": key})
    except _Refused as exc:
        if exc.code == "CHECK_IN_MAKEUP_DISABLED":
            report.state, report.note = "stopped", "站点已关闭补签"
            return "stop"
        verdict = PREVIEW_REFUSALS.get(exc.code, "refused")
    else:
        verdict = _check_preview(preview, day, status.today)
    if verdict == "rollover":
        report.state, report.note = "stopped", "补签预估的距今天数与站点今天不一致，已停止补签"
        return "stop"
    if verdict != "ok":
        report.skipped[key] = verdict
        if verdict in SKIP_TEXT:
            _log(ctx, f"{key} {SKIP_TEXT[verdict]}")
        return "next"
    # 扣费种类由服务端在提交时决定：preview 与提交之间不能跨过站点日切。
    if not _clock_safe(status.today):
        return "rollover"
    return await _submit(ctx, client, report, status, day, _amount(preview.get("free_cost")) or Decimal(0))


async def _submit(ctx: Any, client: _Client, report: _Report, status: _Status, day: date, cost: Decimal) -> str:
    key = day.isoformat()
    baseline = report.activity_after if report.activity_after is not None else status.activity
    try:
        receipt = await client.post(MAKEUP_PATH, {"date": key})
    except _Refused as exc:
        # 业务拒绝说明请求未执行，没有扣费。
        if exc.code in ("CHECK_IN_MAKEUP_ALREADY", "CHECK_IN_MAKEUP_NEED_FREE"):
            report.skipped[key] = "already" if exc.code == "CHECK_IN_MAKEUP_ALREADY" else "cannot_afford"
            return "next"
        report.state = "stopped"
        report.note = (f"{key} 提交时站点改要活跃度（与预估不一致），已停止补签"
                       if exc.code == "CHECK_IN_MAKEUP_NEED_ACTIVITY"
                       else f"{key} 站点拒绝补签（{exc.code or '未知原因'}），已停止补签")
        return "stop"
    except LoginRequired:
        report.state, report.note = "stopped", "补签时登录态失效，已停止补签"
        return "stop"
    except Exception:
        # 已发出却没有明确回执：只回读不重发；站点按日期去重，下次运行会先核对日历。
        report.unconfirmed.append(key)
        report.state = "stopped"
        await _readback(client, report, baseline)
        return "stop"
    report.made_up[key] = cost
    _log(ctx, f"已补签 {key}（免费额度 {_money(cost)}）")
    if type(receipt.get("activity_score")) is int:
        report.activity_after = receipt["activity_score"]
    report.violation = _receipt_violation(receipt, baseline)
    after = await _readback(client, report, baseline)
    if report.violation:
        report.state = "stopped"
        return "stop"
    if after is None:
        report.state, report.note = "stopped", "补签后未能回读活跃度，已停止补签"
        return "stop"
    if after.today != status.today:
        report.state, report.note = "stopped", "补签期间站点日期变化，已停止补签"
        return "stop"
    return "next"


async def _run(ctx: Any, client: _Client, report: _Report) -> None:
    if _no_time(ctx):
        report.state, report.note = "stopped", "补签未执行：时间预算不足"
        return
    data = await client.get(STATUS_PATH)
    if data.get("enabled") is False or data.get("makeup_enabled") is not True:
        report.state = "not_open"
        return
    status = _status(data)
    report.window, report.window_source = status.window, status.window_source
    report.activity_before = status.activity
    window = [status.today - timedelta(days=offset) for offset in range(1, status.window + 1)]
    recorded = await _recorded_days(client, window)
    missed = [day for day in window if day.isoformat() not in recorded]
    report.missed = [day.isoformat() for day in missed]
    if not missed:
        report.state = "none"
        return
    source = "站点阈值" if status.window_source == "site" else "默认"
    _log(ctx, f"近 {status.window} 天（{source}）漏签 {len(missed)} 天：{'、'.join(report.missed)}")
    report.state = "done"
    for index, day in enumerate(missed):
        signal = await _process(ctx, client, report, status, day)
        if signal == "next":
            continue
        if signal in ("rollover", "no_time"):
            for rest in missed[index:]:
                report.skipped.setdefault(rest.isoformat(), signal)
        break
    if report.made_up and not report.violation and not _no_time(ctx):
        await _confirm_calendar(client, report)


async def _confirm_calendar(client: _Client, report: _Report) -> None:
    """提交成功不等于日历已记录：再读一次日历，没记上的改记为未确认。"""
    try:
        recorded = await _recorded_days(client, [date.fromisoformat(day) for day in report.made_up])
    except Exception:
        return
    for day in [day for day in report.made_up if day not in recorded]:
        report.made_up.pop(day)
        report.unconfirmed.append(day)


def _failure_note(exc: BaseException, prefix: str) -> str:
    if isinstance(exc, (_Invalid, _Refused)):
        return f"{prefix}：{exc.message}"
    if isinstance(exc, LoginRequired):
        return f"{prefix}：登录态失效"
    reason = exc.reason if isinstance(exc, TaskError) else ""
    detail = {"network_error": "站点不可达", "need_verification": "站点要求人机验证",
              "blocked": "出口 IP 被拒"}.get(reason, "接口异常")
    return f"{prefix}：{detail}"


def _enabled(ctx: Any) -> bool:
    args = getattr(ctx, "args", None) or {}
    return flow._as_bool(args.get("makeup"), True)


def _log(ctx: Any, message: str) -> None:
    log = getattr(ctx, "log", None)
    if callable(log):
        log(message)


async def run_makeup(ctx: Any, page: Any = None) -> _Report:
    """执行补签并返回报告。除取消外不抛异常：补签的任何问题都不能挡住今日签到。"""
    report = _Report()
    if not _enabled(ctx):
        report.state = "off"
        return report
    try:
        await _run(ctx, _Client(ctx, page), report)
    except Exception as exc:
        prefix = "补签中断" if report.made_up or report.unconfirmed else "补签未执行"
        report.state, report.note = "stopped", _failure_note(exc, prefix)
    return report


async def around_checkin(ctx: Any, page: Any, attempt: Callable[[], Awaitable[Outcome]]) -> Outcome:
    """``SiteSpec.around_checkin`` 钩子：先补签，再今日签到，最后把补签报告并入签到结论。"""
    report = await run_makeup(ctx, page)
    summary = _summary(report)
    if summary:
        _log(ctx, summary)
    return _merge(await attempt(), report)
