#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""站点模板：百倍实验室（100xLabs）。

登录与签到链路与极速蹬同构，共享实现在 ``_sub2api_flow``。
灵台是百倍模板扩展，不属于通用 Sub2API 功能；独立 ``chop_tree`` 任务由
``_100xlabs_tree`` 执行，默认签到任务不会访问灵台。
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _sub2api_flow as flow  # noqa: E402
import _100xlabs_tree as tree  # noqa: E402

from sdk import (  # noqa: E402
    ArgSchema,
    ArgSpec,
    ChainStep,
    DisplayDefaults,
    LoginOption,
    Outcome,
    TaskOption,
    TemplateManifest,
)

MANIFEST = TemplateManifest(
    id="100xlabs",
    title="百倍实验室",
    description="百倍模板每日签到；可另外添加 id=chop_tree 的独立灵台砍树任务",
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
    # 默认访问链：先纯 HTTP（AT，失效用 RT 续期），失败再开浏览器登录并操作页面。
    # 本站登录接口要求 Turnstile，纯 HTTP 账密登录必然失败，因此 HTTP 步骤不列 password；
    # 浏览器步骤先恢复登录态快照，页面仍在登录页时由页面流程账密登录。
    chain=(
        ChainStep("http", "http", title="HTTP 直连", login=("access_token", "refresh")),
        ChainStep("browser", "browser", title="浏览器登录并操作", login=("browser_state", "password")),
    ),
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
    # 实测：本站登录接口要的是 turnstile_token；发 cf-turnstile-response 会被回
    # {"reason":"TURNSTILE_VERIFICATION_FAILED"}。与默认值相同，显式写出以留痕。
    turnstile_field_name="turnstile_token",
    strict_checkin=True,
)


async def run(ctx: Any) -> Outcome:
    """每日签到与灵台砍树是独立任务，各自确认结果、独立重试。

    tasks 中添加 {"id": "chop_tree", "method": "script"} 才执行灵台任务；
    其余任务保持原签到行为，不读取旧 daily.args.chop_tree 开关。
    未配置访问链的任务走这里；配置了访问链的任务由引擎分别调用下面两个步骤钩子。
    """
    if getattr(ctx.account, "task_id", "") == "chop_tree":
        return await tree.run(ctx, SPEC)
    outcome = await flow.http_first(ctx, SPEC)
    if outcome is not None:
        return outcome
    async with ctx.browser.lease(reason="checkin") as lease:
        await lease.new_page()
        return await flow.run_flow(ctx, lease, SPEC)


async def run_http(ctx: Any) -> Outcome:
    """访问链 HTTP 步骤：凭据由引擎按步骤声明取得（AT，失效时用 RT 续期）。"""
    if getattr(ctx.account, "task_id", "") == "chop_tree":
        return await tree.run_http(ctx, SPEC)
    return await flow.http_attempt(ctx, SPEC)


async def run_browser(ctx: Any) -> Outcome:
    """访问链浏览器步骤：恢复登录态或页面账密登录后，在页面上完成签到/砍树。"""
    if getattr(ctx.account, "task_id", "") == "chop_tree":
        return await tree.run_browser(ctx, SPEC)
    async with ctx.browser.lease(reason="checkin") as lease:
        await lease.new_page()
        return await flow.run_flow(ctx, lease, SPEC)
