"""任务方式：OAuth 重登发放（AgentRouter 类站点）。

这类站点没有签到接口，每次通过 OAuth 登录一次就发一份额度。判定只能靠**前后数值差**：
接口不会告诉你「这次发了多少」，甚至不会告诉你「今天已经发过了」。

关键约束（旧实现踩过）：数值没涨**不能**报失败，也不该报「今日已领取」这种确定性
结论——到账可能有延迟。这里统一给 ``already_done`` + 说明文案，且不覆盖站点自己的
提示消息。
"""

from __future__ import annotations

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

        provider = str(ctx.args.get("provider") or "linuxdo").strip().lower()
        before = _read(ctx, user_path, response)

        async with ctx.browser.lease(reason="relogin") as lease:
            page = await lease.new_page()
            await lease.goto("", page=page, wait_until="domcontentloaded")
            ctx.log(f"重放 {provider} OAuth 登录以触发发放…")
            link = await lease.oauth(provider, page=page)
            if not link.get("landed_back"):
                from login.oauth import _oauth_error  # noqa: PLC2701 - 同一套失败判据

                raise _oauth_error(provider, str(ctx.args.get("account") or "default"), link)
            lease.mark_authenticated()

        after = _read(ctx, user_path, response)
        detail = {"source": "relogin", "balance": after}
        display = DisplaySpec(text=response.format(after) if after is not None else "")
        if before is not None and after is not None:
            delta = response.to_number(after) - response.to_number(before)
            if delta is not None and delta > 1e-9:
                detail["awarded"] = _raw(response, delta)
                return success(
                    f"重登发放成功，获得：{response.format(_raw(response, delta))}", data=detail
                ).with_display(
                    display.merge(DisplaySpec(extras=(("获得", response.format(_raw(response, delta))),)))
                )
        return already_done(
            "已完成重登；站点数值未变化（今日可能已发放，或到账有延迟）。", data=detail
        ).with_display(display)


def _read(ctx: Any, path: str, response: Any) -> Any:
    try:
        payload = unwrap_data(ctx.http.get(path))
    except TaskError:
        return None
    return response.pick(payload if isinstance(payload, dict) else {}, "balance")


def _raw(response: Any, delta: float) -> float:
    from core.manifest import QUOTA_UNIT

    return delta * QUOTA_UNIT if response.unit == "quota_500000" else delta
