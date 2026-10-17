"""100xlabs 灵台：百倍模板的独立砍树任务，不属于通用 Sub2API 功能。

仅添加 id=chop_tree 的任务才执行。只消费已有斧力，不购买、不装备、不分解；
按服务端状态逐批执行，不以请求成功代替清空确认。沿用设备标识与每批幂等键。
"""
from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urlencode
from uuid import uuid4

import _sub2api_flow as flow

from core.chain import is_final, strip_control
from sdk import (
    LoginRequired, Outcome, PageHelpers, TaskError, Verdict, already_done, chain_final, failed, need_login, success,
)

DEVICE_KEY = "lottery_barrier_device_id"
STATUS_PATH = "/api/v1/game/status"
CHOP_PATH = "/api/v1/game/chop"
#: 单次运行的安全批次上限。斧力会随时间持续恢复（实测一天可积累数千点），
#: 真正的边界是任务时间预算；这里只防服务端异常导致的死循环。
MAX_BATCHES = 3000
#: 每批提交前至少保留的剩余时间（秒）：留给最后一次请求、只读复查与结果落盘，
#: 避免被引擎硬超时打断后丢失「已消耗多少」的明细。
STOP_RESERVE_SECONDS = 20.0
#: 单次灵台请求的超时上限（秒），与 HttpConfig 默认值一致；临近预算时再收紧。
REQUEST_TIMEOUT_SECONDS = 30
#: 服务端 5xx / 传输异常后的退避重试（秒）。只有只读复查确认了当前斧力后才换新
#: batch_key 继续；斧力不会低于 0 且任务不购买任何东西，所以重发最多只是把本来
#: 就要消耗的斧力用掉。登录失效、业务拒绝等明确结论不重试。
RETRY_DELAYS: tuple[float, ...] = (2.0, 5.0, 10.0)


def _retryable(exc: TaskError) -> bool:
    status = exc.status or 0
    return exc.reason == "network_error" or status >= 500 or status == 429


def _payload(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or not raw:
        raise TaskError("灵台接口未返回有效 JSON", reason="unconfirmed")
    if raw.get("success") is False or raw.get("code") not in (None, 0, 200, "0", "200"):
        raise TaskError("灵台接口返回业务拒绝，未确认完成", reason="unconfirmed")
    data = raw.get("data", raw)
    if not isinstance(data, dict) or not data:
        raise TaskError("灵台响应缺少有效数据", reason="unconfirmed")
    return data


def _integer(value: Any, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < (1 if positive else 0):
        raise TaskError("灵台斧力或批量上限无效，停止砍树", reason="unconfirmed")
    return value


def _chop_state(state: dict[str, Any]) -> tuple[int, int]:
    chop = state.get("chop")
    if not isinstance(chop, dict):
        raise TaskError("灵台响应缺少砍树状态", reason="unconfirmed")
    if chop.get("enabled") is not True:
        raise TaskError("本站未开放砍树，请关闭 chop_tree 参数", reason="not_open")
    if chop.get("bind_blocked"):
        raise TaskError("灵台设备绑定受限，未执行砍树；请在网站确认绑定", reason="need_config")
    stamina = chop.get("stamina")
    if not isinstance(stamina, dict):
        raise TaskError("灵台响应缺少剩余斧力", reason="unconfirmed")
    remain = _integer(stamina.get("remain"))
    # 前端使用 batch_max || 10；这里不猜测未知上限，但已耗尽不需要批量参数。
    batch_max = _integer(chop.get("batch_max"), positive=True) if remain else 1
    return remain, batch_max


def _used(state: dict[str, Any]) -> int | None:
    """服务端累计已用斧力（前端 chop 后 ``used += n``）。缺失或无效时返回 None。

    斧力会随时间恢复：一批砍完后 ``remain`` 可能因恢复而不降反升，只看 remain 会把
    真实消耗误判为「未减少」。``used`` 单调递增，是更可靠的进度信号。
    """
    chop = state.get("chop")
    stamina = chop.get("stamina") if isinstance(chop, dict) else None
    value = stamina.get("used") if isinstance(stamina, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _progress(before_remain: int, before_used: int | None, after_remain: int, after_used: int | None) -> int:
    """本批确认的消耗量；优先用 used 增量，缺失时退回 remain 差值。"""
    if before_used is not None and after_used is not None and after_used >= before_used:
        delta = after_used - before_used
        if delta > 0:
            return delta
    return max(0, before_remain - after_remain)


def _remaining_seconds(ctx: Any) -> float | None:
    getter = getattr(ctx, "remaining_seconds", None)
    if not callable(getter):
        return None
    value = getter()
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _out_of_time(ctx: Any, need: float = 0.0) -> bool:
    if ctx.expired():
        return True
    remaining = _remaining_seconds(ctx)
    return remaining is not None and remaining < STOP_RESERVE_SECONDS + need


def _request_timeout(ctx: Any) -> int:
    remaining = _remaining_seconds(ctx)
    if remaining is None:
        return REQUEST_TIMEOUT_SECONDS
    return max(5, min(REQUEST_TIMEOUT_SECONDS, int(remaining - STOP_RESERVE_SECONDS / 2)))


async def _device_id(ctx: Any, page: Any = None) -> str:
    origin = flow.origin_of(ctx.account.base_url)
    key = f"chop_tree.device_id:{origin}"
    saved = ctx.store.get(key, "")
    saved = saved if isinstance(saved, str) else ""
    if page is None:
        device = saved or str(uuid4())
    else:
        # 只在本站页面使用本地设备标识；沿用前端已有值，不更换 ID 规避绑定。
        if flow.origin_of(str(page.url)) != origin:
            raise TaskError("灵台页面不在账号站点，拒绝使用登录态", reason="unconfirmed")
        device = await page.evaluate(
            """({key, saved, fresh}) => {
                const existing = localStorage.getItem(key) || '';
                if (saved && existing && saved !== existing) return null;
                const id = saved || existing || fresh;
                localStorage.setItem(key, id);
                return id;
            }""",
            {"key": DEVICE_KEY, "saved": saved, "fresh": str(uuid4())},
        )
    if not isinstance(device, str) or not device.strip() or len(device) > 200:
        raise TaskError("灵台设备标识无效", reason="need_config")
    if device != saved and not ctx.store.put(key, device):
        raise TaskError("无法保存灵台设备标识，为避免重复绑定已停止砍树", reason="need_config")
    return device


class _GameClient:
    def __init__(self, ctx: Any, device: str, page: Any = None) -> None:
        self.ctx = ctx
        self.page = page
        self.device = device
        self.origin = flow.origin_of(ctx.account.base_url)

    async def request(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        if self.page is None:
            # 砍树不是无条件幂等：传输异常不盲目重发。401 的正常续期仍由 HttpClient 负责。
            raw = self.ctx.http.request(
                method, path, json_body=body, retry_non_idempotent=False, timeout=_request_timeout(self.ctx),
            )
        else:
            if flow.origin_of(str(self.page.url)) != self.origin:
                raise LoginRequired("灵台页面已离开账号站点，停止请求")
            script = "async ({baseUrl, method, path, body}) => {\n" + flow._PAGE_AUTH_REQUEST_HELPERS_JS + """
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), 20000);
                try {
                    const response = await requestWithAuth(token => fetch(baseUrl + path, {
                        method, credentials: 'include', signal: controller.signal,
                        headers: {Authorization: `Bearer ${token}`, Accept: 'application/json',
                                  'Content-Type': 'application/json'},
                        body: method === 'POST' ? JSON.stringify(body) : undefined,
                    }));
                    if (!response) return {status: 401};
                    return {status: response.status, payload: await parseBody(response)};
                } finally { clearTimeout(timer); }
            }"""
            try:
                result = await self.page.evaluate(
                    script, {"baseUrl": self.origin, "method": method, "path": path, "body": body}
                )
            except Exception as exc:
                raise TaskError("灵台浏览器请求中断，未重发砍树请求", reason="network_error") from exc
            status = result.get("status", 0) if isinstance(result, dict) else 0
            if status == 401:
                raise LoginRequired("灵台登录已失效")
            if not 200 <= status < 300:
                raise TaskError(f"灵台接口返回 HTTP {status}", status=status, reason="unconfirmed")
            raw = result.get("payload")
        return _payload(raw)

    async def state(self) -> dict[str, Any]:
        return await self.request("GET", STATUS_PATH + "?" + urlencode({"device_id": self.device}))

    async def chop(self, count: int) -> dict[str, Any]:
        return await self.request(
            "POST", CHOP_PATH, {"count": count, "batch_key": str(uuid4()), "device_id": self.device}
        )


async def run_chop_tree(ctx: Any, page: Any = None) -> Outcome:
    """在本次时间预算内尽量清空斧力；独立返回结果，调用方不得用签到成功掩盖失败。

    斧力会随时间持续恢复，一天可积累数千点，按服务端批量上限逐批提交往往无法在一次
    任务预算内清空。因此：服务端确认清零才算「完成」；预算或安全批次上限先到、但
    已有服务端确认的消耗时，返回带 ``partial`` 标记的成功（剩余留给下次运行）；
    一点消耗都没确认时仍然失败。
    """
    detail: dict[str, Any] = {"source": "lingtai", "batches": 0, "consumed": 0}
    try:
        device = await _device_id(ctx, page)
        client = _GameClient(ctx, device, page)
        state = await client.state()
        remain, batch_max = _chop_state(state)
        used = _used(state)
        detail.update(initial_stamina=remain, remaining_stamina=remain)
        if not remain:
            return already_done("今日斧力已清空", data=detail)
        ctx.log(f"灵台剩余斧力 {remain}，每批最多 {batch_max} 次")
        errors = 0
        for _ in range(MAX_BATCHES):
            if _out_of_time(ctx):
                return _stopped_early(ctx, detail, "砍树时间预算已耗尽")
            count = min(remain, batch_max)
            after_used: int | None = None
            try:
                result = await client.chop(count)
                state = result.get("status")
                if not isinstance(state, dict):
                    raise TaskError("砍树响应缺少更新后的状态", reason="unconfirmed")
                after, next_max = _chop_state(state)
                after_used = _used(state)
            except TaskError as exc:
                detail["request_error"] = {"reason": exc.reason, "status": exc.status}
                # 请求超时可能已经扣除斧力。只读复查（GET 无副作用，传输异常可退避重试）；
                # 不换 batch_key 盲目重发 POST。
                after = None
                while True:
                    try:
                        state = await client.state()
                        # 错误后的复查也是最新状态，后续提交必须同时遵守新的斧力和批量上限。
                        after, batch_max = _chop_state(state)
                        after_used = _used(state)
                        break
                    except TaskError as read_exc:
                        if (not _retryable(read_exc) or errors >= len(RETRY_DELAYS)
                                or _out_of_time(ctx, RETRY_DELAYS[errors])):
                            break
                        delay = RETRY_DELAYS[errors]
                        errors += 1
                        detail["retries"] = errors
                        ctx.log(f"复查斧力失败（{read_exc.status or read_exc.reason}），{delay:g}s 后重试复查")
                        await asyncio.sleep(delay)
                if after is not None:
                    detail["remaining_stamina"] = after
                    detail["consumed"] += _progress(remain, used, after, after_used)
                    used = after_used
                if after == 0:
                    detail["completion_signal"] = "status_after_error"
                    return success("每日砍树完成，斧力已清空", data=detail)
                if (after is not None and _retryable(exc) and errors < len(RETRY_DELAYS)
                        and not _out_of_time(ctx, RETRY_DELAYS[errors])):
                    delay = RETRY_DELAYS[errors]
                    errors += 1
                    detail["retries"] = errors
                    ctx.log(
                        f"砍树请求失败（{exc.status or exc.reason}），服务端确认剩余斧力 {after}；"
                        f"{delay:g}s 后第 {errors} 次重试"
                    )
                    remain = after
                    await asyncio.sleep(delay)
                    continue
                return exc.to_outcome().with_message("砍树中断，未确认斧力清空").with_data(detail)
            errors = 0
            detail["batches"] += 1
            delta = _progress(remain, used, after, after_used)
            detail["remaining_stamina"] = after
            detail["consumed"] += delta
            if delta <= 0:
                return failed("砍树后斧力未减少，已停止重复请求", reason="unconfirmed", data=detail)
            remain, batch_max, used = after, next_max, after_used
            if remain == 0:
                # 不只相信 POST 的乐观响应；最后重新查询一次服务端状态。
                final_state = await client.state()
                final_remain, _ = _chop_state(final_state)
                detail["remaining_stamina"] = final_remain
                if final_remain != 0:
                    return failed("砍树结束但服务端仍有剩余斧力", reason="unconfirmed", data=detail)
                detail["completion_signal"] = "game_status"
                for key in ("balance", "free_balance", "wood"):
                    value = final_state.get(key)
                    if isinstance(value, (int, float)) and not isinstance(value, bool):
                        detail[key] = value
                ctx.log(f"灵台斧力已清空，本次消耗 {detail['consumed']} 点")
                return success(f"每日砍树完成，已消耗 {detail['consumed']} 点斧力", data=detail)
        return _stopped_early(ctx, detail, "砍树达到安全批次数上限")
    except TaskError as exc:
        return exc.to_outcome().with_data(detail)


def _stopped_early(ctx: Any, detail: dict[str, Any], why: str) -> Outcome:
    """预算/批次上限先到：有服务端确认的消耗算部分完成，否则失败。"""
    remaining = detail.get("remaining_stamina")
    if detail.get("consumed", 0) > 0:
        detail.update(partial=True, completion_signal="budget_partial")
        ctx.log(f"{why}：本次已消耗 {detail['consumed']} 点斧力，剩余 {remaining} 点留待下次运行")
        return success(
            f"{why}，本次已消耗 {detail['consumed']} 点斧力；剩余 {remaining} 点留待下次运行"
            "（斧力持续恢复，可调大 chop_tree 任务 timeout 以多砍）",
            data=detail,
        )
    return failed(f"{why}，未确认任何斧力消耗", reason="unconfirmed", data=detail)


#: 首次只读状态失败时，这些原因允许换浏览器恢复认证后重试；任何砍树提交之后都不换路径。
BROWSER_RECOVERABLE = frozenset({"need_login", "need_verification", "network_error"})


def _saved_device(ctx: Any) -> Any:
    origin = flow.origin_of(ctx.account.base_url)
    return ctx.store.get(f"chop_tree.device_id:{origin}", "")


async def run(ctx: Any, spec: flow.SiteSpec) -> Outcome:
    """独立任务入口（未配置访问链时）；登录兜底只恢复认证，绝不顺带执行签到。

    与访问链共用同两段实现：先纯 HTTP，只有「首次只读状态失败」才换浏览器。
    """
    has_browser = getattr(ctx, "browser_service", None) is not None
    outcome = await run_http(ctx, spec)
    if not has_browser or outcome.verdict is not Verdict.FAILED or is_final(outcome):
        return strip_control(outcome)
    return await run_browser(ctx, spec)


async def run_http(ctx: Any, spec: flow.SiteSpec) -> Outcome:
    """访问链 HTTP 步骤：已有设备标识（或本次没有浏览器）时纯接口砍树。

    还没有设备标识、又能开浏览器时不在这里凭空生成：交给浏览器步骤让前端先建立，
    避免同一账号绑定两个设备。已经开始砍树、或服务端明确拒绝的失败是终局，
    访问链不会再换浏览器重发。
    """
    saved = _saved_device(ctx)
    has_browser = getattr(ctx, "browser_service", None) is not None
    if not saved and has_browser:
        return failed(
            "尚无灵台设备标识，交给浏览器打开灵台页面建立", reason="need_config", data={"source": "lingtai"},
        )
    outcome = await run_chop_tree(ctx)
    if outcome.verdict is not Verdict.FAILED:
        return outcome
    recoverable = "initial_stamina" not in outcome.data and outcome.reason in BROWSER_RECOVERABLE
    return outcome if recoverable else chain_final(outcome)


async def run_browser(ctx: Any, spec: flow.SiteSpec) -> Outcome:
    """访问链浏览器步骤：打开灵台页面，必要时账密登录恢复认证，再在同一页面砍树。"""
    origin = flow.origin_of(ctx.account.base_url)
    saved = _saved_device(ctx)
    try:
        async with ctx.browser.lease(reason="100xlabs-lingtai") as lease:
            await lease.new_page()
            page = lease.page
            helpers = PageHelpers(ctx, lease, page)
            opts = flow.parse_options(spec, ctx.args)
            stash_key = flow.session_stash_key(spec.login_reset_sentinel)
            await flow.add_init_script(
                lease.context, flow.preflight_init_script(stash_key, preserve_refresh=True, origin=origin)
            )
            if isinstance(saved, str) and saved:
                # 在前端首次生成设备 ID 之前续入保存值；已有不同 ID 不覆盖，后面会拒绝冲突。
                await flow.add_init_script(lease.context, (
                    "(() => { const [origin, key, id] = "
                    + json.dumps([origin, DEVICE_KEY, saved])
                    + "; if (location.origin === origin && !localStorage.getItem(key)) "
                    + "localStorage.setItem(key, id); })();"
                ))
            await flow.navigate_and_settle(page, helpers, "/lingtai", opts)
            if flow.origin_of(str(page.url)) != origin:
                return need_login("灵台页面已离开账号站点，未读取其他站点的登录态")
            login_detail: dict[str, Any] = {}
            initial_probe: dict[str, Any] = {}
            if not await flow._authenticated_with_probe(page, origin, initial_probe):
                if initial_probe.get("reason") not in {None, "need_login"}:
                    return flow._authentication_failure(helpers, spec, initial_probe, {"source": "lingtai"})
                failure = await flow.login_with_password(
                    page, lease.context, helpers, spec, opts,
                    resolved_url=helpers.resolve_url("/lingtai"), origin=origin, login_detail=login_detail,
                )
                if failure is not None:
                    return failure.with_data(source="lingtai")
                await flow.navigate_and_settle(page, helpers, "/lingtai", opts)
                if flow.origin_of(str(page.url)) != origin:
                    return need_login("灵台登录后离开账号站点，停止读取登录态")
                failure = await flow.confirm_login_session(page, helpers, spec, origin, login_detail)
                if failure is not None:
                    return failure.with_data(source="lingtai")
                await flow._record_new_tokens(page, helpers, ctx, origin)
            lease.mark_authenticated()
            return await run_chop_tree(ctx, page)
    except TaskError as exc:
        return exc.to_outcome().with_data(source="lingtai")
