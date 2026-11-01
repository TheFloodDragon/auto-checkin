"""任务方式：OAuth 重登发放（AgentRouter 类站点）。

这类站点没有签到接口，每次通过 OAuth 登录一次就发一份额度。判定只能靠**前后数值差**：
接口不会告诉你「这次发了多少」，甚至不会告诉你「今天已经发过了」。

关键约束（旧实现踩过）：数值没涨**不能**报失败，也不该报「今日已领取」这种确定性
结论——到账可能有延迟。这里统一给 ``already_done`` + 说明文案，且不覆盖站点自己的
提示消息。

重登前余额来源：先用引擎装载的首选现成凭据；站点拒绝（如配置里的旧 token 已作废）
时按序尝试其余已存凭据（含站点快照里的 session Cookie）；仍读不到才退回上次重登后
确认的余额基线，且基线只用于证明正向增量。
"""

from __future__ import annotations

import time
from dataclasses import replace
from math import isfinite
from typing import Any

from core.errors import ConfigError, TaskError
from core.outcome import DisplaySpec, Outcome, already_done, success
from net.http import unwrap_data
from solvers.registry import CAP_BROWSER
from .base import hook_owns_execute, run_template_hook

__all__ = ["ReloginTask"]

#: 上次重登后经同一站点用户确认的余额（换算后数值 + 单位 + 时间），仅作重登前读取失败时的退路。
_BASELINE_KEY = "relogin_baseline"
#: 基线超过 3 天不再采用：间隔越长，充值/兑换等站外入账被误记为发放的机会越大。
_BASELINE_MAX_AGE = 3 * 86400


class ReloginTask:
    id = "relogin"
    requires = frozenset({CAP_BROWSER})

    async def run(self, ctx: Any, template: Any) -> Outcome:
        if hook_owns_execute(template, self.id):
            return await run_template_hook(ctx, template, what=self.id)

        manifest = template.manifest
        response = manifest.response
        user_path = str((manifest.endpoints or {}).get("user") or "").strip()
        if not user_path:
            raise ConfigError(f"模板 {manifest.id} 未声明 [endpoints].user，无法比较重登前后的数值。")

        # provider 的来源顺序：任务 args → 账号的 login.provider → linuxdo。
        # 早先只读 args 并硬编码回落 linuxdo，于是配了 login.provider="github" 的
        # 账号会去重放 linuxdo 的 OAuth（实测 AgentRouter(G) 因此拿 linuxdo 登录态
        # 撞上 Cloudflare），报错也指向错误的 provider，排查时完全看不出真因。
        provider = str(
            ctx.args.get("provider") or ctx.account.oauth_provider or "linuxdo"
        ).strip().lower()
        account_name = str(
            ctx.args.get("account") or ctx.account.oauth_account or "default"
        ).strip()
        before, before_identity = _read_before(ctx, user_path, response)

        if not await ctx.login.relogin(provider, account_name):
            raise TaskError("新 OAuth 会话未完成认证，不能确认重登或发放", reason="need_login")

        after, after_identity = _read(ctx, user_path, response)
        before_number, after_number = _finite(response.to_number(before)), _finite(response.to_number(after))
        detail = {"source": "relogin", "balance": after if after_number is not None else None}
        display = DisplaySpec(text=response.format(after) if after_number is not None else "")
        baseline_note = ""
        if (before_number is None and after_number is not None and after_identity
                and before_identity in {"", after_identity}):
            # 重登前读不到：退而与上次重登后确认的余额比较。只认同一用户、近期、
            # 同计量单位的记录；它只能证明「正向增量」，下降/持平仍不下结论。
            baseline = _load_baseline(ctx, response, after_identity)
            if baseline is not None:
                before_number, baseline_note = baseline
                before_identity = after_identity
                detail["baseline"] = "last_relogin"
        if after_number is not None and after_identity:
            _save_baseline(ctx, response, after_identity, after_number)
        same_identity = bool(before_identity and after_identity and before_identity == after_identity)
        if before_number is not None and after_number is not None and not same_identity:
            detail["identity_unconfirmed"] = True
            return already_done(
                "已完成重登，但前后余额无法确认属于同一站点用户，不能据此判断本次是否发放。",
                data=detail,
            ).with_display(display)
        if before_number is not None and after_number is not None:
            delta = after_number - before_number
            if isfinite(delta) and delta > 1e-9 and isfinite(_raw(response, delta)):
                detail["awarded"] = _raw(response, delta)
                return success(
                    f"重登发放成功，获得：{response.format(_raw(response, delta))}{baseline_note}", data=detail
                ).with_display(
                    display.merge(DisplaySpec(extras=(("获得", response.format(_raw(response, delta))),)))
                )
        # 读不到数值 ≠ 数值没变。两者都报「站点数值未变化」会让「接口读取失败」伪装成
        # 一个确定结论——实测 agentrouter-g 因缺 user_id 而 /api/user/self 全程 401，
        # 却照样显示「已完成重登；站点数值未变化」，看不出发放到底成没成。
        if before_number is None or after_number is None:
            detail["balance_unavailable"] = True
            return already_done(
                "已完成重登，但重登前后数值不完整，无法确认本次是否发放。",
                data=detail,
            ).with_display(display)
        if baseline_note:
            # 基线与本次之间可能有消费，持平/下降既不能证明「没发」，也不能证明「发了」。
            return already_done(
                f"已完成重登；与上次重登后余额相比未见正向增量，期间消费可能抵消发放，"
                f"无法确认本次是否发放{baseline_note}", data=detail,
            ).with_display(display)
        return already_done(
            "已完成重登；未观察到数值正向增量，无法确认本次是否发放（可能有到账延迟）。", data=detail
        ).with_display(display)


def _finite(number: float | None) -> float | None:
    return number if number is not None and isfinite(number) else None


def _read_before(ctx: Any, path: str, response: Any) -> tuple[Any, str]:
    """重登前余额：首选认证被站点拒绝时，按序尝试引擎给出的其余现成凭据。

    站点已接受某份认证并返回用户数据时就以它为准（哪怕缺身份/余额），不再换凭据
    「挑」一个更好看的结果；只有被拒或读取失败才回落下一份。
    """
    value, identity, accepted = _fetch(ctx, path, response, ctx.http)
    if accepted:
        return value, identity
    handle = getattr(ctx, "login_handle", None)
    for index, client in enumerate(getattr(handle, "baseline_alternates", ()) or (), start=2):
        value, identity, accepted = _fetch(ctx, path, response, client)
        if accepted:
            ctx.log(f"重登前首选凭据未被站点接受，改用第 {index} 份已存凭据读取重登前余额")
            return value, identity
    return None, ""


def _load_baseline(ctx: Any, response: Any, identity: str) -> tuple[float, str] | None:
    store = getattr(ctx, "store", None)
    if store is None:
        return None
    try:
        record = store.get(_BASELINE_KEY)
    except Exception:  # noqa: BLE001 - 读不到基线只是少一条退路
        return None
    if not isinstance(record, dict):
        return None
    value, at = record.get("balance"), record.get("at")
    if (str(record.get("identity") or "") != identity or record.get("unit") != response.unit
            or isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value)
            or isinstance(at, bool) or not isinstance(at, (int, float)) or not isfinite(at)):
        return None
    age = time.time() - at
    if age < 0 or age > _BASELINE_MAX_AGE:
        return None
    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(at))
    return float(value), f"（重登前余额读取失败，改与上次重登后确认的余额 {response.format(_raw(response, value))}（{stamp}）比较）"


def _save_baseline(ctx: Any, response: Any, identity: str, number: float) -> None:
    store = getattr(ctx, "store", None)
    if store is None:
        return
    try:
        store.put(_BASELINE_KEY, {"identity": identity, "balance": number, "unit": response.unit, "at": time.time()})
    except Exception:  # noqa: BLE001 - 基线写失败不影响本次结论
        return


def _read(ctx: Any, path: str, response: Any) -> tuple[Any, str]:
    value, identity, _accepted = _fetch(ctx, path, response, ctx.http)
    return value, identity


def _fetch(ctx: Any, path: str, response: Any, client: Any) -> tuple[Any, str, bool]:
    """返回 (余额, 站点用户, 站点是否接受了该认证并返回用户数据)。"""
    # 余额查询只读现成认证。401 不得触发续期，尤其不能另开一条 OAuth 链。
    http = client.with_auth()
    http.auth_refresher = None
    if not any(key.lower() in {"authorization", "cookie"} for key in http.headers) and not http.cookie_jar:
        return None, "", False
    remaining = ctx.remaining_seconds()
    timeout = min(10.0, max(0.0, remaining - 2.0)) if remaining is not None else 10.0
    if timeout <= 0:
        return None, "", False
    http.config = replace(http.config, max_attempts=1)
    try:
        raw = http.get(path, timeout=timeout)
    except TaskError:
        return None, "", False
    payload = unwrap_data(raw)
    data = payload if isinstance(payload, dict) else {}
    accepted = bool(data) and not (isinstance(raw, dict) and raw.get("success") is False)
    identities = {
        str(data[key]).strip() for key in ("id", "user_id")
        if isinstance(data.get(key), (str, int)) and not isinstance(data.get(key), bool) and str(data[key]).strip()
    }
    # 两种 API 字段是同一身份别名；同时给出互相冲突的值则不能猜测。
    identity = next(iter(identities)) if len(identities) == 1 else ""
    return response.pick(data, "balance"), identity, accepted


def _raw(response: Any, delta: float) -> float:
    from core.manifest import QUOTA_UNIT

    return delta * QUOTA_UNIT if response.unit == "quota_500000" else delta
