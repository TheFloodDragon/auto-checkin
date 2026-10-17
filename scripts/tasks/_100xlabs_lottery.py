"""百倍与林夕每日抽奖：赠送次数优先，只使用赠送额度，绝不使用活跃度。

只执行单抽；每次提交使用独立幂等键，认证重放沿用原请求。任何提交结果不明确
都停止，不能以浏览器回退、业务重试或本地计数代替服务端确认。
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import uuid4

import _sub2api_flow as flow

from core.chain import is_final, strip_control
from sdk import (
    LoginRequired, Outcome, PageHelpers, TaskError, Verdict, already_done, chain_final, failed, success,
)

STATUS_PATH = "/api/v1/lottery/status"
DRAW_PATH = "/api/v1/lottery"
MAX_DRAWS = 200
BROWSER_RECOVERABLE = frozenset({"need_login", "need_verification", "network_error"})


def _detail() -> dict[str, Any]:
    return {
        "source": "lottery", "attempted": False, "draws": 0, "bonus_used": 0,
        "free_used": 0, "remaining": None, "activity_spent": 0, "status_confirmed": False,
    }


def _invalid(message: str) -> TaskError:
    return TaskError(message, reason="unconfirmed")


def _integer(value: Any, *, minimum: int | None = 0) -> int:
    if type(value) is not int or (minimum is not None and value < minimum):
        raise _invalid("抽奖次数或活跃度字段无效，已停止")
    return value


def _boolean(value: Any) -> bool:
    if type(value) is not bool:
        raise _invalid("抽奖开关字段缺失或类型无效，已停止")
    return value


def _amount(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise _invalid("抽奖金额字段缺失或类型无效，已停止")
    if isinstance(value, str) and not re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", value):
        raise _invalid("抽奖金额格式无效，已停止")
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError, OverflowError) as exc:
        raise _invalid("抽奖金额格式无效，已停止") from exc
    if not amount.is_finite() or amount < 0:
        raise _invalid("抽奖金额不是有限非负数，已停止")
    return amount


def _payload(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or not raw:
        raise _invalid("抽奖接口未返回有效 JSON")
    if "success" in raw and raw["success"] is not True:
        raise _invalid("抽奖接口返回业务拒绝，未确认完成")
    code = raw.get("code")
    if isinstance(code, bool) or code not in (None, 0, 200, "0", "200"):
        raise _invalid("抽奖接口返回业务拒绝，未确认完成")
    data = raw.get("data", raw)
    if not isinstance(data, dict) or not data:
        raise _invalid("抽奖响应缺少有效数据")
    return data


@dataclass(frozen=True)
class _State:
    enabled: bool
    window_open: bool
    can_draw: bool
    limit: int
    today: int
    remaining: int
    bonus: int
    free_enabled: bool
    free_cost: Decimal
    free_balance: Decimal
    activity: int


def _state(raw: dict[str, Any]) -> _State:
    enabled = _boolean(raw.get("enabled"))
    window_open = _boolean(raw.get("window_open"))
    can_draw = _boolean(raw.get("can_draw"))
    limit = _integer(raw.get("daily_draw_limit"), minimum=None)
    today = _integer(raw.get("today_draws"))
    remaining = _integer(raw.get("today_remaining"), minimum=-1)
    bonus = _integer(raw.get("bonus_draws"))
    costs = raw.get("costs")
    if not isinstance(costs, dict):
        raise _invalid("抽奖响应缺少费用配置，已停止")
    # 付费、活跃度及助力配置完全不用；缺少这些禁用通道不影响安全赠送抽奖。
    free_enabled, free_cost = False, Decimal(0)
    if "free" in costs:
        free = costs["free"]
        if not isinstance(free, dict):
            raise _invalid("抽奖赠送额度配置无效，已停止")
        free_enabled = _boolean(free.get("enabled"))
        if free_enabled or "amount" in free:
            free_cost = _amount(free.get("amount"))
    balance = _amount(raw.get("free_balance"))
    activity = _integer(raw.get("activity_score"))
    if limit > 0 and remaining >= 0 and remaining != max(0, limit - today):
        raise _invalid("服务端每日抽奖次数互相矛盾，已停止")
    if can_draw and (not enabled or not window_open or (limit > 0 and remaining == 0)):
        raise _invalid("服务端抽奖许可与开放状态或剩余次数矛盾，已停止")
    return _State(
        enabled, window_open, can_draw, limit, today, remaining, bonus,
        free_enabled, free_cost, balance, activity,
    )


def _finite(state: _State) -> None:
    if state.limit <= 0 or state.remaining < 0:
        raise TaskError("本站未配置有限的每日抽奖次数，未消耗赠送次数或额度", reason="need_config")


def _cost_type(state: _State) -> str:
    if not state.enabled:
        raise TaskError("本站未开放抽奖，今日次数尚未用完", reason="not_open")
    if not state.window_open:
        raise TaskError("当前不在抽奖开放时间内，今日次数尚未用完", reason="not_open")
    if not state.can_draw:
        raise _invalid("服务端当前不允许抽奖，今日次数尚未用完")
    if state.bonus > 0:
        return "bonus"
    if state.free_enabled and state.free_balance >= state.free_cost:
        return "free"
    raise TaskError("赠送次数或赠送额度不足，未使用付费余额或活跃度", reason="need_config")


def _verify_draw(raw: dict[str, Any], kind: str, state: _State, seen: set[str]) -> str:
    draw = raw.get("draw")
    if not isinstance(draw, dict):
        raise _invalid("抽奖响应缺少明确抽奖记录，已停止")
    draw_id = draw.get("id")
    if type(draw_id) is int and draw_id > 0:
        identity = str(draw_id)
    elif isinstance(draw_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", draw_id):
        if draw_id.isdecimal() and int(draw_id) <= 0:
            raise _invalid("抽奖记录编号无效，已停止")
        identity = draw_id
    else:
        raise _invalid("抽奖记录编号缺失或无效，已停止")
    if identity in seen or draw.get("status") not in ("win", "miss"):
        raise _invalid("抽奖记录重复或状态不明确，已停止")
    if draw.get("cost_type") != kind:
        raise _invalid("服务端使用了非指定抽奖费用类型，已停止")
    # 必须显式证明未使用付费余额或活跃度；缺字段绝不按零处理。
    for field in ("cost_paid", "cost_activity"):
        if _amount(draw.get(field)) != 0:
            raise _invalid("服务端抽奖记录存在付费或活跃度消耗，已停止")
    if "boost_activity_cost" in draw:
        if _amount(draw["boost_activity_cost"]) != 0:
            raise _invalid("服务端抽奖记录存在助力活跃度消耗，已停止")
    else:
        # 当前两站普通单抽不返回 boost_activity_cost，而返回明确的前后活跃度。
        # 仅在两者均与提交前状态一致时接受，不能把缺失费用直接视为零。
        before = _integer(draw.get("activity_before"))
        after = _integer(draw.get("activity_after"))
        # 抽奖中奖可能奖励活跃度；只要没有下降，且响应级活跃度与回执一致，
        # 就能证明没有把活跃度用于扣费/助力。下降才表示发生了未声明消耗。
        if before != state.activity or after < before or _integer(raw.get("activity_score")) != after:
            raise _invalid("抽奖记录未证明助力活跃度无消耗，已停止")
    expected_free = state.free_cost if kind == "free" else Decimal(0)
    if _amount(draw.get("cost_free")) != expected_free:
        raise _invalid("抽奖赠送额度扣费与提交前配置不一致，已停止")
    if draw.get("boost") is True:
        raise _invalid("服务端抽奖记录启用了助力，已停止")
    return identity


class _LotteryClient:
    def __init__(self, ctx: Any, page: Any = None) -> None:
        self.ctx = ctx
        self.page = page
        self.origin = flow.origin_of(ctx.account.base_url)

    async def request(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        if self.page is None:
            try:
                raw = self.ctx.http.request(method, path, json_body=body, retry_non_idempotent=False)
            except TaskError as exc:
                # 不传播接口原文、异常 data 或 evidence，避免奖品兑换码/认证信息进入结果。
                raise TaskError(
                    "抽奖接口请求失败，未确认每日次数用完", reason=exc.reason or "unconfirmed", status=exc.status,
                ) from exc
            except (OSError, TimeoutError) as exc:
                raise TaskError("抽奖接口连接中断", reason="network_error") from exc
        else:
            if flow.origin_of(str(self.page.url)) != self.origin:
                raise LoginRequired("抽奖页面已离开账号站点，停止请求")
            script = "async ({baseUrl, method, path, body}) => {\n" + flow._PAGE_AUTH_REQUEST_HELPERS_JS + """
                if (location.origin !== new URL(baseUrl).origin) return {status: 401};
                const requestBody = method === 'POST' ? JSON.stringify(body) : undefined;
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), 20000);
                try {
                    const response = await requestWithAuth(token => fetch(baseUrl + path, {
                        method, redirect: 'error', credentials: 'include', signal: controller.signal,
                        headers: {Authorization: `Bearer ${token}`, Accept: 'application/json',
                                  'Content-Type': 'application/json'},
                        body: requestBody,
                    }));
                    if (!response) return {status: 401};
                    return {status: response.status, payload: await parseBody(response)};
                } finally { clearTimeout(timer); }
            }"""
            try:
                result = await self.page.evaluate(
                    script, {"baseUrl": self.origin, "method": method, "path": path, "body": body},
                )
            except Exception as exc:
                raise TaskError("抽奖浏览器请求中断，未重发抽奖", reason="network_error") from exc
            status = result.get("status") if isinstance(result, dict) else None
            if type(status) is not int:
                raise _invalid("抽奖浏览器接口缺少有效 HTTP 状态")
            if status == 401:
                raise LoginRequired("抽奖登录已失效")
            if not 200 <= status < 300:
                reason = "network_error" if status >= 500 or status == 429 else "unconfirmed"
                raise TaskError("抽奖接口返回非成功 HTTP 状态", status=status, reason=reason)
            raw = result.get("payload")
        return _payload(raw)

    async def state(self) -> dict[str, Any]:
        return await self.request("GET", STATUS_PATH)

    async def draw(self, kind: str) -> dict[str, Any]:
        if kind not in ("bonus", "free"):
            raise _invalid("拒绝使用非赠送方式抽奖")
        return await self.request(
            "POST", DRAW_PATH, {"cost_type": kind, "idempotency_key": str(uuid4()), "boost": False},
        )


async def run_lottery(ctx: Any, page: Any = None) -> Outcome:
    """每日有限次数全部用完才成功；任何提交后的失败都是访问链终局。"""
    detail = _detail()
    client: _LotteryClient | None = None
    initial_request = False
    readback_due = False
    state: _State | None = None
    try:
        if ctx.expired():
            raise _invalid("抽奖时间预算已耗尽，未确认每日次数用完")
        client = _LotteryClient(ctx, page)
        initial_request = True
        raw = await client.state()
        initial_request = False
        state = _state(raw)
        detail.update(status_confirmed=True, remaining=state.remaining)
        _finite(state)
        if state.remaining == 0:
            return already_done("今日抽奖次数已用完", data=detail)
        seen: set[str] = set()
        for _ in range(MAX_DRAWS):
            if ctx.expired():
                raise _invalid("抽奖时间预算已耗尽，今日次数尚未用完")
            _finite(state)
            kind = _cost_type(state)
            # 提交标记必须早于 await；取消或普通异常也不能换浏览器再抽。
            detail["attempted"] = True
            detail.pop("activity_spent", None)
            readback_due = True
            result = await client.draw(kind)
            identity = _verify_draw(result, kind, state, seen)
            detail["activity_spent"] = 0
            # 这次 GET 同时是下一抽之前的最新服务端状态；不额外信任 POST 附带的状态。
            readback_due = False
            after = _state(await client.state())
            detail["remaining"] = after.remaining
            if after.activity < state.activity:
                detail.pop("activity_spent", None)
                raise _invalid("抽奖后活跃度下降，无法确认无消耗，已停止")
            _finite(after)
            if after.limit != state.limit or after.today != state.today + 1 or after.remaining != state.remaining - 1:
                raise _invalid("抽奖后服务端每日次数未按单抽更新，已停止重复请求")
            seen.add(identity)
            detail["draws"] += 1
            detail["bonus_used" if kind == "bonus" else "free_used"] += 1
            state = after
            if state.remaining == 0:
                detail["completion_signal"] = "lottery_status"
                return success(f"每日抽奖完成，本次已抽 {detail['draws']} 次", data=detail)
        raise _invalid("抽奖达到安全单抽次数上限，今日次数尚未用完")
    except (Exception, asyncio.CancelledError) as exc:
        # 已发出 POST 却无完整响应时，只读一次；无成本证明即使次数归零也不报告成功。
        if detail["attempted"] and readback_due and client is not None and not isinstance(exc, asyncio.CancelledError):
            try:
                if not ctx.expired():
                    readback_due = False
                    observed = _state(await client.state())
                    detail["remaining"] = observed.remaining
                    if state is not None and observed.activity < state.activity:
                        detail.pop("activity_spent", None)
            except (Exception, asyncio.CancelledError):
                pass
        if isinstance(exc, TaskError):
            reason = exc.reason or "unconfirmed"
            message = exc.message
            if type(exc.status) is int:
                detail["http_status"] = exc.status
        else:
            reason = "unconfirmed"
            message = "抽奖已取消，未确认每日次数用完" if isinstance(exc, asyncio.CancelledError) else "抽奖执行中断，未确认每日次数用完"
        outcome = failed(message, reason=reason, data=detail)
        if not detail["attempted"] and initial_request and reason in BROWSER_RECOVERABLE:
            return outcome
        return chain_final(outcome)


async def run_http(ctx: Any, spec: flow.SiteSpec) -> Outcome:
    """仅首次只读 GET 的认证/网络失败可回退浏览器；业务拒绝及提交后失败均终局。"""
    outcome = await run_lottery(ctx)
    if outcome.verdict is not Verdict.FAILED:
        return outcome
    recoverable = (
        not outcome.data.get("attempted") and not outcome.data.get("status_confirmed")
        and outcome.reason in BROWSER_RECOVERABLE and not is_final(outcome)
    )
    return outcome if recoverable else chain_final(outcome)


async def run(ctx: Any, spec: flow.SiteSpec) -> Outcome:
    """独立入口：只恢复登录，不触发签到、砍树、设备绑定或屏障操作。"""
    outcome = await run_http(ctx, spec)
    if getattr(ctx, "browser_service", None) is None or outcome.verdict is not Verdict.FAILED or is_final(outcome):
        return strip_control(outcome)
    return await run_browser(ctx, spec)


async def run_browser(ctx: Any, spec: flow.SiteSpec) -> Outcome:
    """打开抽奖页面恢复认证，再直接请求同源 API；不生成或保存设备标识。"""
    detail = _detail()
    outcome: Outcome | None = None
    try:
        if ctx.expired():
            return chain_final(failed("抽奖时间预算已耗尽", reason="unconfirmed", data=detail))
        origin = flow.origin_of(ctx.account.base_url)
        async with ctx.browser.lease(reason="100xlabs-lottery") as lease:
            await lease.new_page()
            page = lease.page
            helpers = PageHelpers(ctx, lease, page)
            opts = flow.parse_options(spec, ctx.args)
            stash_key = flow.session_stash_key(spec.login_reset_sentinel)
            await flow.add_init_script(
                lease.context, flow.preflight_init_script(stash_key, preserve_refresh=True, origin=origin),
            )
            await flow.navigate_and_settle(page, helpers, "/lottery", opts)
            if flow.origin_of(str(page.url)) != origin:
                return chain_final(failed("抽奖页面已离开账号站点，未读取其他站点的登录态", reason="need_login", data=detail))
            login_detail: dict[str, Any] = {}
            initial_probe: dict[str, Any] = {}
            if not await flow._authenticated_with_probe(page, origin, initial_probe):
                if initial_probe.get("reason") not in {None, "need_login"}:
                    return chain_final(flow._authentication_failure(helpers, spec, initial_probe, detail))
                failure = await flow.login_with_password(
                    page, lease.context, helpers, spec, opts,
                    resolved_url=helpers.resolve_url("/lottery"), origin=origin, login_detail=login_detail,
                )
                if failure is not None:
                    return chain_final(failure.with_data(detail))
                await flow.navigate_and_settle(page, helpers, "/lottery", opts)
                if flow.origin_of(str(page.url)) != origin:
                    return chain_final(failed("抽奖登录后离开账号站点，停止读取登录态", reason="need_login", data=detail))
                failure = await flow.confirm_login_session(page, helpers, spec, origin, login_detail)
                if failure is not None:
                    return chain_final(failure.with_data(detail))
                await flow._record_new_tokens(page, helpers, ctx, origin)
            lease.mark_authenticated()
            outcome = await run_lottery(ctx, page)
            return chain_final(outcome) if outcome.verdict is Verdict.FAILED else outcome
    except (Exception, asyncio.CancelledError) as exc:
        if outcome is not None:
            detail = dict(outcome.data)
        reason = exc.reason if isinstance(exc, TaskError) and exc.reason else "unconfirmed"
        return chain_final(failed("抽奖浏览器流程中断，未重新提交抽奖", reason=reason, data=detail))
