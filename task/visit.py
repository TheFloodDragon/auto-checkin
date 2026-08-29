"""任务方式：访问保活。

有些站点不发放额度，只按「最近是否登录/访问过」保留账号或额度。这类任务没有签到接口，
唯一能做的就是发一次已认证请求，并记录当天已经访问过。

与旧 ``providers/actions/visit.py`` 的差别：不再往
``.cache-checkin/login_grant_state.json`` 写一份自己的状态文件，改用 ``ctx.store``
（进覆盖层的 learning 段，跟着账号的失效规则走）。
"""

from __future__ import annotations

from typing import Any

from core.errors import ConfigError, TaskError
from core.outcome import DisplaySpec, Outcome, already_done, success
from core.timebase import business_date
from net.http import unwrap_data
from .base import run_template_hook
from .http_api import outcome_from_error

__all__ = ["VisitTask"]

STORE_KEY = "visit_baseline"


class VisitTask:
    id = "visit"
    requires: frozenset[str] = frozenset()

    async def run(self, ctx: Any, template: Any) -> Outcome:
        if template.hook("run") is not None:
            return await run_template_hook(ctx, template, what=self.id)

        manifest = template.manifest
        path = str((manifest.endpoints or {}).get("user") or "").strip()
        if not path:
            raise ConfigError(
                f"模板 {manifest.id} 未声明 [endpoints].user，访问保活不知道该请求哪个接口。"
            )
        response = manifest.response
        today = business_date()
        baseline = ctx.store.get(STORE_KEY) or {}
        try:
            payload = unwrap_data(ctx.http.get(path))
        except TaskError as exc:
            return outcome_from_error(exc)

        data = payload if isinstance(payload, dict) else {}
        balance = response.pick(data, "balance")
        text = response.format(balance)
        display = DisplaySpec(text=text)
        detail = {"source": "visit", "balance": balance}

        previous_date = str(baseline.get("date") or "")
        ctx.store.put(STORE_KEY, {"date": today, "balance": balance})
        if previous_date == today:
            return already_done("今日已访问保活。", data=detail).with_display(display)
        return success("访问保活成功。", data=detail).with_display(display)
