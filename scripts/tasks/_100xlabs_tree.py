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
MAX_BATCHES = 200
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
            raw = self.ctx.http.request(method, path, json_body=body, retry_non_idempotent=False)
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
    """清空本次运行可用斧力；独立返回结果，调用方不得用签到成功掩盖失败。"""
    detail: dict[str, Any] = {"source": "lingtai", "batches": 0, "consumed": 0}
    try:
        device = await _device_id(ctx, page)
        client = _GameClient(ctx, device, page)
        state = await client.state()
        remain, batch_max = _chop_state(state)
        detail.update(initial_stamina=remain, remaining_stamina=remain)
        if not remain:
            return already_done("今日斧力已清空", data=detail)
        ctx.log(f"灵台剩余斧力 {remain}，每批最多 {batch_max} 次")
        errors = 0
        for _ in range(MAX_BATCHES):
            if ctx.expired():
                return failed("砍树时间预算已耗尽，剩余斧力未清空", reason="unconfirmed", data=detail)
            count = min(remain, batch_max)
            try:
                result = await client.chop(count)
                state = result.get("status")
                if not isinstance(state, dict):
                    raise TaskError("砍树响应缺少更新后的状态", reason="unconfirmed")
                after, next_max = _chop_state(state)
            except TaskError as exc:
                detail["request_error"] = {"reason": exc.reason, "status": exc.status}
                # 请求超时可能已经扣除斧力。只读复查；不换 batch_key 盲目重发。
                try:
                    state = await client.state()
                    after, _ = _chop_state(state)
                    detail["remaining_stamina"] = after
                    detail["consumed"] += max(0, remain - after)
                except TaskError:
                    after = None
                if after == 0:
                    detail["completion_signal"] = "status_after_error"
                    return success("每日砍树完成，斧力已清空", data=detail)
                if after is not None and _retryable(exc) and errors < len(RETRY_DELAYS):
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
            detail["remaining_stamina"] = after
            detail["consumed"] += max(0, remain - after)
            if after >= remain:
                return failed("砍树后斧力未减少，已停止重复请求", reason="unconfirmed", data=detail)
            remain, batch_max = after, next_max
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
        return failed("砍树达到安全批次数上限，剩余斧力未清空", reason="unconfirmed", data=detail)
    except TaskError as exc:
        return exc.to_outcome().with_data(detail)


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
                lease.context, flow.preflight_init_script(stash_key, preserve_refresh=True)
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
            if not await flow.authenticated(page, origin):
                failure = await flow.login_with_password(
                    page, lease.context, helpers, spec, opts,
                    resolved_url=helpers.resolve_url("/lingtai"), origin=origin, login_detail={},
                )
                if failure is not None:
                    return failure.with_data(source="lingtai")
                await flow.navigate_and_settle(page, helpers, "/lingtai", opts)
                if flow.origin_of(str(page.url)) != origin:
                    return need_login("灵台登录后离开账号站点，停止读取登录态")
                if not await flow.authenticated(page, origin):
                    return need_login("灵台登录未通过服务端确认", data={"source": "lingtai"})
            lease.mark_authenticated()
            return await run_chop_tree(ctx, page)
    except TaskError as exc:
        return exc.to_outcome().with_data(source="lingtai")
