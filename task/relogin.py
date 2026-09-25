"""任务方式：OAuth 重登发放（AgentRouter 类站点）。

这类站点没有签到接口，每次通过 OAuth 登录一次就发一份额度。判定只能靠**前后数值差**：
接口不会告诉你「这次发了多少」，甚至不会告诉你「今天已经发过了」。

关键约束（旧实现踩过）：数值没涨**不能**报失败，也不该报「今日已领取」这种确定性
结论——到账可能有延迟。这里统一给 ``already_done`` + 说明文案，且不覆盖站点自己的
提示消息。
"""

from __future__ import annotations

from dataclasses import replace
from math import isfinite
from typing import Any

from core.errors import ConfigError, TaskError
from core.outcome import DisplaySpec, Outcome, already_done, success
from net.http import unwrap_data
from solvers.registry import CAP_BROWSER
from .base import hook_owns_execute, run_template_hook

__all__ = ["ReloginTask"]


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
        before, before_identity = _read(ctx, user_path, response)

        if not await ctx.login.relogin(provider, account_name):
            raise TaskError("新 OAuth 会话未完成认证，不能确认重登或发放", reason="need_login")

        after, after_identity = _read(ctx, user_path, response)
        before_number, after_number = response.to_number(before), response.to_number(after)
        if before_number is not None and not isfinite(before_number):
            before_number = None
        if after_number is not None and not isfinite(after_number):
            after_number = None
        detail = {"source": "relogin", "balance": after if after_number is not None else None}
        display = DisplaySpec(text=response.format(after) if after_number is not None else "")
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
                    f"重登发放成功，获得：{response.format(_raw(response, delta))}", data=detail
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
        return already_done(
            "已完成重登；未观察到数值正向增量，无法确认本次是否发放（可能有到账延迟）。", data=detail
        ).with_display(display)


def _read(ctx: Any, path: str, response: Any) -> tuple[Any, str]:
    # 余额查询只读现成认证。401 不得触发续期，尤其不能另开一条 OAuth 链。
    http = ctx.http.with_auth()
    http.auth_refresher = None
    if not any(key.lower() in {"authorization", "cookie"} for key in http.headers) and not http.cookie_jar:
        return None, ""
    remaining = ctx.remaining_seconds()
    timeout = min(10.0, max(0.0, remaining - 2.0)) if remaining is not None else 10.0
    if timeout <= 0:
        return None, ""
    http.config = replace(http.config, max_attempts=1)
    try:
        payload = unwrap_data(http.get(path, timeout=timeout))
    except TaskError:
        return None, ""
    data = payload if isinstance(payload, dict) else {}
    identity = ""
    for key in ("id", "user_id"):
        value = data.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip():
            identity = f"{key}:{str(value).strip()}"
            break
    return response.pick(data, "balance"), identity


def _raw(response: Any, delta: float) -> float:
    from core.manifest import QUOTA_UNIT

    return delta * QUOTA_UNIT if response.unit == "quota_500000" else delta
