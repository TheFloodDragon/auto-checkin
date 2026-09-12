"""LinuxDO 刷帖任务。

访问 linux.do 论坛，使用共享浏览器登录态，模拟人类化浏览帖子：
- 随机点进帖子，每篇停留随机可控时长
- 贝塞尔曲线平滑鼠标移动 + 分段随机滚动，模拟真实阅读节奏
- 每篇读完后返回首页刷新，获取新帖列表

使用方式：将本脚本路径填入账号 template 字段，并捕获 LinuxDO 浏览器登录态。
"""

from __future__ import annotations

import asyncio
import random
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent   # scripts/tasks
_REPO_ROOT = _HERE.parents[1]            # 仓库根
for _path in (_HERE, _REPO_ROOT):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from core.outcome import DisplaySpec  # noqa: E402
from sdk import (  # noqa: E402
    ArgSchema,
    ArgSpec,
    DisplayDefaults,
    LoginOption,
    Outcome,
    PageHelpers,
    TaskOption,
    TemplateManifest,
    already_done,
    failed,
    ok,
)
from core.timebase import business_date  # noqa: E402

LINUXDO_URL = "https://linux.do"
STORE_KEY = "linuxdo_browse"

MANIFEST = TemplateManifest(
    id="linuxdo_browse",
    title="LinuxDO 刷帖",
    description="访问 linux.do 论坛，模拟人类化随机浏览帖子，保持账号活跃度",
    login=(
        LoginOption(
            "browser_state",
            priority=10,
            requires=frozenset({"browser"}),
            title="浏览器登录态（LinuxDO）",
        ),
    ),
    task=(
        TaskOption(
            "browser_flow",
            priority=10,
            requires=frozenset({"browser"}),
            owns=frozenset({"detect", "confirm"}),
            title="模拟刷帖",
            args=ArgSchema(
                (
                    ArgSpec(
                        "post_count",
                        kind="int",
                        default=5,
                        minimum=1,
                        maximum=30,
                        title="浏览帖子数",
                        help="每次运行随机浏览的帖子数量，实际数量在 1~该值 之间随机",
                    ),
                    ArgSpec(
                        "min_read_seconds",
                        kind="int",
                        default=8,
                        minimum=3,
                        maximum=120,
                        title="最短阅读秒数",
                        help="每篇帖子最少停留的秒数",
                    ),
                    ArgSpec(
                        "max_read_seconds",
                        kind="int",
                        default=30,
                        minimum=5,
                        maximum=300,
                        title="最长阅读秒数",
                        help="每篇帖子最多停留的秒数",
                    ),
                    ArgSpec(
                        "once_per_day",
                        kind="bool",
                        default=False,
                        title="每日只刷一次",
                        help="启用后，当天已刷过则跳过（返回 already_done）",
                    ),
                )
            ),
        ),
    ),
    display=DisplayDefaults(text_label="浏览帖数"),
)


# ── 人类化鼠标 / 滚动辅助 ────────────────────────────────────────────────────

async def _bezier_move(
    page: Any,
    x0: float, y0: float,
    x1: float, y1: float,
    steps: int = 22,
) -> None:
    """二阶贝塞尔曲线平滑鼠标移动，模拟人类手腕弧线轨迹。

    控制点随机偏移，让每次路径略有不同；速度在中段最快、两端最慢，
    与真实鼠标加速度曲线一致。
    """
    cx = random.uniform(min(x0, x1) - 60, max(x0, x1) + 60)
    cy = random.uniform(min(y0, y1) - 60, max(y0, y1) + 60)
    for i in range(steps + 1):
        t = i / steps
        x = (1 - t) ** 2 * x0 + 2 * (1 - t) * t * cx + t**2 * x1
        y = (1 - t) ** 2 * y0 + 2 * (1 - t) * t * cy + t**2 * y1
        await page.mouse.move(x, y)
        # 两端慢（ease-in-out 曲线）：t 越靠近 0 / 1 越慢
        ease = 4 * t * (1 - t)          # 0→1→0，中间最大
        delay = random.uniform(0.006, 0.018) * (1.6 - ease)
        await asyncio.sleep(delay)


async def _human_scroll(page: Any, total_px: int) -> None:
    """分段下滑，每段随机长度并随机停顿，模拟人类阅读节奏。"""
    scrolled = 0
    while scrolled < total_px:
        chunk = random.randint(90, 320)
        chunk = min(chunk, total_px - scrolled)
        await page.mouse.wheel(0, chunk)
        scrolled += chunk
        await asyncio.sleep(random.uniform(0.25, 1.2))


async def _simulate_read(page: Any, read_seconds: float) -> None:
    """在帖子页模拟阅读行为：滚动 + 停顿 + 偶尔移动鼠标。"""
    try:
        vp = await page.evaluate(
            "() => ({ w: window.innerWidth, h: window.innerHeight })"
        )
        vw = vp.get("w", 1280)
        vh = vp.get("h", 800)
    except Exception:
        vw, vh = 1280, 800

    # 初始落点：正文区域中部偏左
    await _bezier_move(
        page,
        vw * 0.5, vh * 0.5,
        random.uniform(vw * 0.25, vw * 0.65),
        random.uniform(vh * 0.35, vh * 0.65),
    )

    elapsed = 0.0
    # 开头停顿，模拟"开始阅读"
    first_pause = random.uniform(1.0, 2.5)
    await asyncio.sleep(first_pause)
    elapsed += first_pause

    while elapsed < read_seconds:
        chunk = random.randint(110, 380)
        await page.mouse.wheel(0, chunk)
        pause = random.uniform(0.7, 2.8)
        await asyncio.sleep(pause)
        elapsed += pause + 0.08

        # 约 35% 概率微微移动鼠标（模拟视线跟随文字）
        if random.random() < 0.35:
            mx = random.uniform(vw * 0.2, vw * 0.75)
            my = random.uniform(vh * 0.25, vh * 0.75)
            await page.mouse.move(mx, my)
            micro = random.uniform(0.1, 0.45)
            await asyncio.sleep(micro)
            elapsed += micro


# ── LinuxDO Discourse 页面选择器 ─────────────────────────────────────────────

_TOPIC_SELECTORS = [
    "tr.topic-list-item a.raw-topic-link",
    "tr.topic-list-item a.title",
    ".topic-list-item .main-link a",
    ".topic-list .title a",
]
_LOADED_MARKERS = [
    "#main-outlet",
    ".topic-list",
    ".d-header",
]


async def _wait_loaded(page: Any, timeout: int = 20000) -> bool:
    """等待 Discourse 主框架加载完成，任一标记出现即返回 True。"""
    for sel in _LOADED_MARKERS:
        try:
            await page.wait_for_selector(sel, state="visible", timeout=timeout)
            return True
        except Exception:
            continue
    return False


async def _collect_topic_links(page: Any) -> list[str]:
    """从当前页面提取帖子链接，返回绝对 URL 列表。"""
    for sel in _TOPIC_SELECTORS:
        try:
            hrefs: list[str] = await page.evaluate(
                f"""() => {{
                    const els = document.querySelectorAll('{sel}');
                    return Array.from(els)
                        .map(a => a.href)
                        .filter(h => h && h.includes('/t/'));
                }}"""
            )
            if hrefs:
                return hrefs
        except Exception:
            continue
    return []


# ── 主流程 ───────────────────────────────────────────────────────────────────

async def run(ctx: Any) -> Outcome:
    """模拟人类浏览 LinuxDO 帖子：随机点进帖子、阅读、返回、刷新主页。"""
    today = business_date()

    # 每日只刷一次检测
    once = bool(ctx.args.get("once_per_day", False))
    if once:
        baseline = ctx.store.get(STORE_KEY) or {}
        if str(baseline.get("date") or "") == today:
            posts_read = int(baseline.get("posts_read") or 0)
            return already_done(
                f"今日已刷帖（共 {posts_read} 篇）",
                data={"date": today, "posts_read": posts_read},
            ).with_display(DisplaySpec(text=str(posts_read)))

    max_posts = int(ctx.args.get("post_count") or 5)
    min_secs = int(ctx.args.get("min_read_seconds") or 8)
    max_secs = int(ctx.args.get("max_read_seconds") or 30)

    # 实际浏览数：[ceil(max/2), max] 区间随机，更自然
    target_count = random.randint(max(1, (max_posts + 1) // 2), max_posts)

    ctx.log(f"目标浏览 {target_count} 篇帖子，每篇 {min_secs}~{max_secs} 秒")

    async with ctx.browser.lease(reason="linuxdo_browse") as lease:
        page = await lease.new_page()
        helpers = PageHelpers(ctx, lease, page)

        # ── 打开首页 ──
        ctx.log("打开 LinuxDO 首页…")
        try:
            await lease.goto(LINUXDO_URL, page=page, wait_until="domcontentloaded")
        except Exception:
            pass  # commit 模式吞超时，页面通常已可用

        await _wait_loaded(page, timeout=25000)
        await lease.dismiss_popups(page=page)

        # 验证登录态：检查是否有用户头像 / 菜单按钮
        logged_in = await page.evaluate(
            """() => !!document.querySelector(
                '#current-user, .header-buttons .btn-default .d-icon-user-circle, '
                + '.current-user .avatar, button.header-dropdown-toggle .avatar'
            )"""
        )
        if not logged_in:
            ctx.log("未检测到登录态，可能 browser_state 已过期")
            return helpers.need_login(
                "LinuxDO 登录态失效，请重新捕获浏览器登录态",
                detail={"url": LINUXDO_URL},
            )

        ctx.log("登录态有效，开始收集帖子链接")

        # ── 收集帖子链接 ──
        topic_links = await _collect_topic_links(page)
        if not topic_links:
            ctx.log("首页未找到帖子链接，截图留证")
            await helpers.screenshot("linuxdo_no_topics")
            return helpers.error(
                "未能从 LinuxDO 首页提取到帖子链接",
                detail={"url": LINUXDO_URL},
            )

        ctx.log(f"首页共找到 {len(topic_links)} 个帖子链接")

        # 去重 + 随机打乱，取前 target_count 个
        unique_links = list(dict.fromkeys(topic_links))
        random.shuffle(unique_links)
        to_visit = unique_links[:target_count]

        posts_read = 0

        for idx, link in enumerate(to_visit, 1):
            read_secs = random.randint(min_secs, max_secs)
            ctx.log(f"[{idx}/{len(to_visit)}] 打开帖子，计划阅读 {read_secs} 秒：{link}")

            # 找到对应链接元素，贝塞尔移动后点击（更真实）
            try:
                el = page.locator(f'a[href="{link}"], a[href*="{link.split("/t/")[-1].split("/")[0]}"]').first
                box = await el.bounding_box()
            except Exception:
                box = None

            if box:
                vp = await page.evaluate("() => ({ w: window.innerWidth, h: window.innerHeight })")
                cur_x = random.uniform(vp.get("w", 1280) * 0.4, vp.get("w", 1280) * 0.6)
                cur_y = random.uniform(vp.get("h", 800) * 0.4, vp.get("h", 800) * 0.6)
                target_x = box["x"] + random.uniform(box["width"] * 0.2, box["width"] * 0.8)
                target_y = box["y"] + random.uniform(box["height"] * 0.2, box["height"] * 0.8)
                await _bezier_move(page, cur_x, cur_y, target_x, target_y)
                await asyncio.sleep(random.uniform(0.08, 0.25))
                await page.mouse.click(target_x, target_y)
            else:
                # 后备：直接导航
                try:
                    await lease.goto(link, page=page, wait_until="domcontentloaded")
                except Exception:
                    pass

            # 等待帖子内容区域出现
            try:
                await page.wait_for_selector(
                    ".post-stream, article.post, .cooked",
                    state="visible", timeout=18000,
                )
            except Exception:
                ctx.log(f"帖子加载超时，跳过：{link}")
                try:
                    await page.go_back()
                    await _wait_loaded(page, timeout=10000)
                except Exception:
                    await lease.goto(LINUXDO_URL, page=page, wait_until="domcontentloaded")
                continue

            # 模拟阅读
            await _simulate_read(page, read_secs)
            posts_read += 1

            ctx.log(f"已阅读 {posts_read} 篇，返回首页…")

            # 返回首页并刷新
            try:
                await page.go_back()
            except Exception:
                try:
                    await lease.goto(LINUXDO_URL, page=page, wait_until="domcontentloaded")
                except Exception:
                    pass

            await _wait_loaded(page, timeout=15000)

            # 在帖子之间随机停顿 1~4 秒，再刷新主页帖子列表
            inter_pause = random.uniform(1.0, 4.0)
            await asyncio.sleep(inter_pause)

            # 若还有下一篇，刷新首页拿新帖（模拟真实用户行为）
            if idx < len(to_visit):
                try:
                    await page.reload(wait_until="domcontentloaded")
                except Exception:
                    pass
                await _wait_loaded(page, timeout=12000)
                await asyncio.sleep(random.uniform(0.5, 1.5))

                # 重新采集帖子（刷新后可能有新帖）
                fresh = await _collect_topic_links(page)
                if fresh:
                    remaining = [u for u in fresh if u not in to_visit]
                    random.shuffle(remaining)
                    # 补充剩余槽位
                    needed = len(to_visit) - idx
                    to_visit = to_visit[:idx] + (
                        (to_visit[idx:] + remaining)[:needed]
                    )

        # ── 写入今日记录 ──
        ctx.store.put(STORE_KEY, {"date": today, "posts_read": posts_read})
        msg = f"LinuxDO 刷帖完成，本次浏览 {posts_read} 篇帖子"
        ctx.log(msg)
        return ok(msg, data={"date": today, "posts_read": posts_read}).with_display(
            DisplaySpec(text=str(posts_read))
        )
