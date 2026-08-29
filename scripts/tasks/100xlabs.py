#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""站点模板：百倍实验室（100xLabs）。

Sub2API 系站点，登录与签到链路与极速蹬同构，共享实现在 ``_sub2api_flow``；本文件
只声明差异（端点、显示名、按钮文案、sentinel 键）。
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _sub2api_flow as flow  # noqa: E402

from sdk import (  # noqa: E402
    ArgSchema,
    ArgSpec,
    DisplayDefaults,
    LoginOption,
    Outcome,
    TaskOption,
    TemplateManifest,
)

MANIFEST = TemplateManifest(
    id="100xlabs",
    title="百倍实验室",
    description="Sub2API 系每日签到（浏览器点击 + 纯 API 兜底）",
    login=(
        LoginOption("access_token", priority=10, title="Access Token"),
        LoginOption("refresh", priority=20, title="Refresh Token 续期"),
        LoginOption(
            "password",
            priority=30,
            title="账密登录",
            args=ArgSchema(
                (
                    ArgSpec("email", env="X100LABS_EMAIL", secret=True, title="邮箱"),
                    ArgSpec("password", env="X100LABS_PASSWORD", secret=True, title="密码"),
                )
            ),
        ),
        LoginOption("browser_state", priority=40, requires=frozenset({"browser"}), title="浏览器登录态"),
        LoginOption("oauth", priority=50, requires=frozenset({"browser"}), title="OAuth 登录态"),
    ),
    task=(
        TaskOption(
            "script",
            priority=10,
            title="签到",
            # 这个流程自己查状态、自己点按钮、自己确认结果，通用探测只会制造噪声。
            # 刻意**不**声明 requires={"browser"}：token 有效时纯 HTTP 就能跑完，
            # 浏览器是兜底而不是前提。
            owns=frozenset({"detect", "confirm"}),
            args=ArgSchema(
                (
                    ArgSpec("start_path", default="/check-in", title="入口路径"),
                    ArgSpec("checkin_text", title="签到按钮文案", help="留空则用内置候选词"),
                )
            ),
        ),
    ),
    display=DisplayDefaults(text_label="额度"),
    endpoints={"prefix": "/api/v1", "submit": "/api/v1/check-in", "state": "/api/v1/check-in/status"},
)

SPEC = flow.SiteSpec(
    site_label="百倍",
    checkin_path="/api/v1/check-in",
    # 实测 GET 该端点稳定回 {"data":{"checked_in_today":true,"today_reward":5,"balance":897}}。
    status_path="/api/v1/check-in/status",
    login_reset_sentinel="__x100_login_reset",
    screenshot_prefix="100xlabs",
    default_start_path="/check-in",
    email_env="X100LABS_EMAIL",
    password_env="X100LABS_PASSWORD",
    checkin_texts=("签到", "每日签到", "立即签到", "领取", "今日领取", "Check in", "Claim", "now"),
    already_texts=("已签到", "今日已签到", "已领取", "今日已领取", "Already", "Checked", "today"),
    success_texts=("签到成功", "领取成功", "成功", "获得", "Success"),
    # 监听 POST 签到响应；百倍前端路径可能是 /check-in 或 /checkin。
    response_match=("check-in", "checkin"),
    # "today" 过于宽泛（页面标题/日期也含它），仅在按钮被禁用时才采信为已签到。
    weak_already_texts=("today",),
    success_message="签到成功",
)


async def run(ctx: Any) -> Outcome:
    """执行百倍签到。

    先试纯 HTTP（token 有效时十几秒的浏览器启动完全省掉），走不通再开浏览器点按钮；
    共享流程由 ``_sub2api_flow`` 统一维护。
    """
    outcome = await flow.http_first(ctx, SPEC)
    if outcome is not None:
        return outcome
    async with ctx.browser.lease(reason="checkin") as lease:
        await lease.new_page()
        return await flow.run_flow(ctx, lease, SPEC)
