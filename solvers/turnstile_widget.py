"""Turnstile 令牌铸造：在站点 origin 下注入一个 widget，拿到令牌交给 HTTP 层提交。

与 ``solvers/web.py`` 里的 ``turnstile`` 的区别：
- ``turnstile``：页面上**已经有**站点自己的 widget（登录表单里那种），点它一下；
- ``turnstile:inject``（本模块）：页面上**没有** widget，站点只在 ``/api/status`` 里
  给了 sitekey，需要我们自己造一个来换令牌。

原理（原样迁自 ``scripts/newapi_turnstile.py``，那套参数是 A/B 实测出来的）：
1. 用路由拦截在站点 origin 下打开一个空白承载页——Turnstile 只校验
   (sitekey, hostname)，不关心页面内容，而站点首页是数 MB 的 SPA；
2. 在**主世界**注入 widget（``page.evaluate`` 的隔离上下文拿不到 ``window.turnstile``）；
3. 先看是否自动签发（managed/invisible 模式无需点击），否则用真实鼠标点击复选框
   （Cloudflare 校验 ``isTrusted``，JS click 无效）；
4. 失败后 reset 再试一次。连续两次失败通常是当前出口 IP 被风控，继续试只是空耗。

只消费 Cloudflare 正常签发的令牌，不伪造、不绕过。令牌绑定 (sitekey, hostname, 出口 IP)，
浏览器与 HTTP 层同机运行，因此 IP 一致。
"""

from __future__ import annotations

import asyncio
import json
import math
import sys
import time
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

from core.outcome import Evidence
from .registry import CAP_BROWSER, SolveResult

__all__ = ["TurnstileInjectSolver", "register"]

# widget 注入脚本。把签发的令牌写进 host 元素的 data-token 属性，供隔离上下文读取。
_WIDGET_BOOTSTRAP_JS = r"""
(() => {
  const SITEKEY = __SITEKEY_JSON__;
  const host = document.createElement('div');
  host.id = 'ck-ts-host';
  host.setAttribute('data-state', 'init');
  host.style.cssText = 'position:fixed;left:24px;top:24px;width:320px;'
    + 'z-index:2147483647;background:#fff;padding:4px';
  const slot = document.createElement('div');
  slot.id = 'ck-ts-slot';
  host.appendChild(slot);
  document.body.appendChild(host);

  let widgetId = null;

  const render = () => {
    try {
      widgetId = window.turnstile.render(slot, {
        sitekey: SITEKEY,
        retry: 'never',
        'refresh-expired': 'manual',
        'refresh-timeout': 'manual',
        'before-interactive-callback': () => host.setAttribute('data-interactive', 'true'),
        'after-interactive-callback': () => host.setAttribute('data-interactive', 'false'),
        'expired-callback': () => {
          host.removeAttribute('data-token');
          host.setAttribute('data-state', 'error');
          host.setAttribute('data-error', 'expired');
        },
        callback: (token) => {
          host.setAttribute('data-token', token);
          host.setAttribute('data-state', 'done');
        },
        'error-callback': (code) => {
          host.setAttribute('data-state', 'error');
          host.setAttribute('data-error', String(code || 'unknown'));
        },
        'timeout-callback': () => {
          host.setAttribute('data-state', 'timeout');
        },
      });
      host.setAttribute('data-state', 'rendered');
    } catch (e) {
      host.setAttribute('data-state', 'error');
      host.setAttribute('data-error', String((e && e.message) || e));
    }
  };

  // 隔离上下文（page.evaluate）拿不到页面的 window.turnstile，无法直接 reset。
  // 用 data-cmd 属性做命令通道：外部写入 reset，主世界这里执行后清回 rendered。
  // Cloudflare 文档把 600xxx 归为可重试错误，重试前必须 reset，否则 widget 会
  // 一直停在错误态，后续轮询只是空等。
  new MutationObserver(() => {
    if (host.getAttribute('data-cmd') !== 'reset') return;
    host.removeAttribute('data-cmd');
    try {
      host.removeAttribute('data-error');
      host.removeAttribute('data-token');
      host.removeAttribute('data-interactive');
      host.setAttribute('data-state', 'rendered');
      if (widgetId !== null) { window.turnstile.reset(widgetId); }
      else { render(); }
    } catch (e) {
      host.setAttribute('data-state', 'error');
      host.setAttribute('data-error', 'reset failed: ' + String((e && e.message) || e));
    }
  }).observe(host, { attributes: true, attributeFilter: ['data-cmd'] });

  if (window.turnstile && window.turnstile.render) { render(); return; }
  const s = document.createElement('script');
  s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  s.async = true;
  s.onload = () => {
    let n = 0;
    const w = setInterval(() => {
      if (window.turnstile && window.turnstile.render) { clearInterval(w); render(); }
      else if (++n > 100) { clearInterval(w); host.setAttribute('data-state', 'no-global'); }
    }, 100);
  };
  s.onerror = () => {
    host.setAttribute('data-state', 'error');
    host.setAttribute('data-error', 'api.js load failed');
  };
  document.head.appendChild(s);
})();
"""

# 令牌有两个来源，必须都读：我们注入的 callback 写的 data-token，以及 Turnstile 自己
# 在 widget 内创建的 input[name=cf-turnstile-response]。只读前者会漏掉「人工完成了
# 验证但 callback 没触发」的情况，表现为「明明点过却不算数」。
_STATE_JS = """() => {
  const host = document.getElementById('ck-ts-host');
  const slot = document.getElementById('ck-ts-slot');
  const r = slot ? slot.getBoundingClientRect() : null;
  let token = (host && host.getAttribute('data-token')) || '';
  if (!token && host) {
    for (const f of host.querySelectorAll(
      'input[name^="cf-turnstile-response"], textarea[name^="cf-turnstile-response"]'
    )) {
      const v = typeof f.value === 'string' ? f.value : String(f.textContent || '');
      if (v.trim()) { token = v.trim(); break; }
    }
  }
  return {
    state: (host && host.getAttribute('data-state')) || 'missing',
    error: (host && host.getAttribute('data-error')) || '',
    token: token,
    interactive: !!host && host.getAttribute('data-interactive') === 'true',
    slot: r ? { x: r.x, y: r.y, w: r.width, h: r.height } : null,
  };
}"""

_RESET_JS = """() => {
  const host = document.getElementById('ck-ts-host');
  if (host) host.setAttribute('data-cmd', 'reset');
}"""

#: widget 的最小有效高度（未挂载时为 0，挂载后约 65–74px）。
MIN_WIDGET_HEIGHT = 50
#: 轮询间隔（ms）。widget 挂载只需 1–2s，秒级间隔会把「已就绪」的发现推迟近一秒。
POLL_INTERVAL_MS = 200
#: 点击后等待令牌的上限（ms）。实测正常签发在 1–5s 内完成；等到 20s 一次都没见过成功。
TOKEN_WAIT_MS = 12_000
#: widget 挂载等待上限（ms）。api.js 下载 + render 通常 1–8s，Cloudflare 侧波动时会超 12s。
MOUNT_WAIT_MS = 20_000
#: widget 报错后仍继续观察的宽限期（ms）。600xxx 偶尔会先报错再自行恢复成签发。
ERROR_GRACE_MS = 1_500
#: 承载页路径。用站点前端不会接管的路径，避免 SPA 路由抢走渲染。
HOST_PATH = "/__checkin_turnstile__"
#: 整体尝试次数。连续两次失败通常是当前 IP/指纹被风控，第三次成功率很低。
MAX_ATTEMPTS = 2
RETRY_COOLDOWN_MS = 2_000


DEFAULT_BUDGET_SECONDS = 90.0
RPC_TIMEOUT_SECONDS = 5.0
PAGE_CREATE_TIMEOUT_SECONDS = 10.0
NAVIGATION_TIMEOUT_SECONDS = 20.0
CLICK_TIMEOUT_SECONDS = 8.0
SCREENSHOT_TIMEOUT_SECONDS = 2.0
CLEANUP_RESERVE_SECONDS = 5.0
AUTO_WAIT_SECONDS = 2.0


class _StageTimeout(TimeoutError):
    def __init__(self, stage: str):
        super().__init__(f"{stage}超时")
        self.stage = stage


def _consume_task(task: asyncio.Future) -> None:
    if not task.cancelled():
        task.exception()


async def _within(
    operation: Callable[[], Awaitable[Any]], deadline: float, stage: str, limit: float | None = None,
) -> Any:
    """每个 RPC 截到剩余总预算；取消挂起操作，不等可能卡死的取消清理。"""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _StageTimeout(stage)
    timeout = remaining if limit is None else min(remaining, limit)
    task = asyncio.ensure_future(operation())
    try:
        done, _pending = await asyncio.wait({task}, timeout=timeout)
        if task not in done:
            raise _StageTimeout(stage)
        try:
            return task.result()
        except TimeoutError as exc:
            raise _StageTimeout(stage) from exc
    finally:
        if not task.done():
            task.cancel()
        task.add_done_callback(_consume_task)


async def _state(page: Any, deadline: float, stage: str) -> dict[str, Any]:
    value = await _within(lambda: page.evaluate(_STATE_JS), deadline, stage, RPC_TIMEOUT_SECONDS)
    if not isinstance(value, dict):
        raise ValueError("widget 状态不是对象")
    return value


async def _pause(deadline: float, milliseconds: int | None = None) -> None:
    # 本地定时器不依赖页面/驱动，页面 JS 卡死也不影响预算推进。
    interval = POLL_INTERVAL_MS if milliseconds is None else milliseconds
    await asyncio.sleep(min(interval / 1000, max(0.0, deadline - time.monotonic())))


class TurnstileInjectSolver:
    """按 sitekey 铸造一枚 Turnstile 令牌。"""

    async def solve(
        self,
        ctx: Any,
        /,
        *,
        sitekey: str = "",
        budget: float | None = None,
        **_: Any,
    ) -> SolveResult:
        key = str(sitekey or "").strip()
        if not key:
            return SolveResult.failure("invalid", "缺少 sitekey，无法注入 Turnstile widget")
        browser = getattr(ctx, "browser_service", None) or getattr(ctx, "browser", None)
        if browser is None:
            return SolveResult.failure("unavailable", "Turnstile 铸造需要浏览器")
        seconds = DEFAULT_BUDGET_SECONDS if budget is None else float(budget)
        if not math.isfinite(seconds):
            return SolveResult.failure("invalid", "Turnstile 时间预算必须为有限值")
        if seconds <= 0:
            return SolveResult.failure("timeout", "Turnstile 剩余预算不足，未启动浏览器")

        log = getattr(ctx, "log", None) or (lambda _m: None)
        started = time.monotonic()
        deadline = started + seconds
        # 在传入的预算内预留关闭页面时间，不额外占用账号的收尾余量。
        work_deadline = deadline - min(CLEANUP_RESERVE_SECONDS, seconds / 10)
        manager = browser.lease(reason="turnstile")
        lease = page = None
        attempts = 0
        stage = "启动浏览器"
        result: SolveResult | None = None
        log(f"Turnstile 铸造总预算 {seconds:g}s（含启动、点击、截图和收尾）")
        try:
            lease = await _within(manager.__aenter__, work_deadline, stage)
            stage = "创建验证页面"
            # 空白承载页没有公告；不要让公告守卫误删验证控件或占用浏览器 RPC。
            page = await _within(
                lambda: lease.new_page(guard_origin=""), work_deadline, stage, PAGE_CREATE_TIMEOUT_SECONDS
            )
            stage = "打开最小承载页"
            await _open_widget_host(lease, page, log, work_deadline)
            stage = "注入 Turnstile widget"
            log("注入 Turnstile widget（主世界）…")
            script = _WIDGET_BOOTSTRAP_JS.replace("__SITEKEY_JSON__", json.dumps(key))
            await _within(lambda: page.add_script_tag(content=script), work_deadline, stage, RPC_TIMEOUT_SECONDS)
            reason = "剩余预算不足"
            for attempts in range(1, MAX_ATTEMPTS + 1):
                stage = "获取 Turnstile 令牌"
                token, reason = await _one_attempt(page, log, work_deadline)
                if token:
                    log(f"Turnstile 令牌已签发（{len(token)} 字符，耗时 {time.monotonic() - started:.1f}s）")
                    result = SolveResult.solved(token, attempts=attempts)
                    break
                # 未回调不代表失败。只在 widget 明确报错后 reset，不能重置正在处理/
                # 人工操作的挑战；浏览器 RPC 超时则直接结束，不在卡住的页面上继续重试。
                if attempts >= MAX_ATTEMPTS or time.monotonic() >= work_deadline or not reason.startswith("widget 错误"):
                    break
                stage = "重置错误 widget"
                log(f"第 {attempts} 次收到明确错误（{reason}），reset widget 后重试")
                await _within(lambda: page.evaluate(_RESET_JS), work_deadline, stage, RPC_TIMEOUT_SECONDS)
                await _pause(work_deadline, RETRY_COOLDOWN_MS)
            if result is None:
                result = SolveResult.failure(
                    "timeout" if "超时" in reason else "refused",
                    f"未能取得 Turnstile 令牌（{reason}）；已停止本轮验证，不重复提交签到。",
                    attempts=attempts, data={"stage": stage},
                )
        except _StageTimeout as exc:
            log(f"Turnstile {exc}，停止本轮；不会继续等待到账号硬超时")
            result = SolveResult.failure("timeout", f"Turnstile {exc}，已停止本轮验证。",
                                         attempts=attempts, data={"stage": exc.stage})
        except Exception as exc:
            # 不回显可能含完整 sitekey/令牌的驱动异常。
            log(f"Turnstile {stage}失败：{type(exc).__name__}")
            result = SolveResult.failure("error", f"Turnstile {stage}失败：{type(exc).__name__}",
                                         attempts=attempts, data={"stage": stage})
        finally:
            if lease is not None:
                if result is not None and not result.ok and page is not None and time.monotonic() < work_deadline:
                    try:
                        shot = await _within(
                            lambda: lease.screenshot("turnstile-inject-failed.png", page=page),
                            work_deadline, "采集验证截图", SCREENSHOT_TIMEOUT_SECONDS,
                        )
                        if shot:
                            result = result.with_evidence(Evidence().with_screenshot(shot))
                    except Exception:
                        pass
                exc_info = sys.exc_info()
                try:
                    await _within(lambda: manager.__aexit__(*exc_info), deadline, "关闭验证页面", CLEANUP_RESERVE_SECONDS)
                except Exception:
                    log("验证页面收尾未完成，交由浏览器服务回收；保留本次验证结果")
        return result


async def _open_widget_host(lease: Any, page: Any, log: Any, deadline: float) -> None:
    """在原站点同源下打开空白承载页；回退导航也只能使用同一份剩余预算。"""
    from browser.storage_scope import same_origin

    base_url = lease.service.base_url.rstrip("/")
    target = base_url + HOST_PATH
    try:
        await _within(
            lambda: page.route(target, lambda route: route.fulfill(
                status=200, content_type="text/html; charset=utf-8",
                body="<!doctype html><html><head><title>checkin</title></head><body></body></html>",
            )), deadline, "设置承载页路由", RPC_TIMEOUT_SECONDS,
        )
        await _within(
            lambda: lease.goto(HOST_PATH, page=page, wait_until="domcontentloaded", timeout=20000),
            deadline, "打开最小承载页", NAVIGATION_TIMEOUT_SECONDS,
        )
        origin = await _within(lambda: page.evaluate("() => location.origin"), deadline, "确认承载页同源", RPC_TIMEOUT_SECONDS)
        if same_origin(str(origin or ""), base_url):
            log(f"已在 {urlsplit(base_url).hostname} 下打开最小承载页（跳过 SPA 加载）")
            return
        log("承载页同源校验未通过，回落真实导航")
    except _StageTimeout:
        raise
    except Exception as exc:
        log(f"最小承载页不可用（{type(exc).__name__}），回落真实导航")

    await _within(lambda: lease.goto("", page=page, wait_until="domcontentloaded", timeout=20000),
                  deadline, "回退站点导航", NAVIGATION_TIMEOUT_SECONDS)
    from browser import bypass

    if not await _within(lambda: bypass.solve_cloudflare(page, log=log, wait_seconds=15),
                         deadline, "等待承载页放行", 15):
        raise RuntimeError("承载页仍被 Cloudflare 拦截")
    origin = await _within(lambda: page.evaluate("() => location.origin"), deadline, "确认承载页同源", RPC_TIMEOUT_SECONDS)
    if not same_origin(str(origin or ""), base_url):
        raise RuntimeError("承载页离开站点同源，停止注入")


async def _one_attempt(page: Any, log: Any, deadline: float) -> tuple[str, str]:
    """等挂载/自动签发，再点击一次；不在处理中重复点击或刷新。"""
    mount_deadline = min(time.monotonic() + MOUNT_WAIT_MS / 1000, deadline)
    ready_since: float | None = None
    while True:
        info = await _state(page, mount_deadline, "读取 widget 挂载状态")
        token = info.get("token")
        if isinstance(token, str) and token.strip():
            log(f"令牌已自动签发（{len(token)} 字符，无需点击）")
            return token.strip(), ""
        state = str(info.get("state") or "missing")
        if state == "missing":
            return "", "widget 容器丢失（页面可能已跳转）"
        if state == "no-global":
            return "", "Turnstile api.js 未就绪"
        if state in {"error", "timeout"}:
            return await _poll_token(page, mount_deadline, "等待 widget 错误恢复")
        slot = info.get("slot") or {}
        if float(slot.get("h", 0) or 0) >= MIN_WIDGET_HEIGHT:
            now = time.monotonic()
            if ready_since is None:
                ready_since = now
            if info.get("interactive") or now - ready_since >= AUTO_WAIT_SECONDS:
                # 自动签发可能在读取完坐标后发生；点击函数会再次读取令牌状态。
                early_token = await _click_checkbox(page, slot, log, deadline)
                if early_token:
                    return early_token, ""
                return await _poll_token(
                    page, min(time.monotonic() + TOKEN_WAIT_MS / 1000, deadline), "点击后等待令牌"
                )
        if time.monotonic() >= mount_deadline:
            return "", f"widget 挂载超时（state={state}）"
        await _pause(mount_deadline)


async def _click_checkbox(page: Any, slot: dict, log: Any, deadline: float) -> str:
    """在受控承载页中点击真实鼠标；每一步都可超时，成功后才记录点击完成。"""
    values = [float(slot.get(key, 0) or 0) for key in ("x", "y", "w", "h")]
    x, y, width, height = values
    if not all(math.isfinite(value) for value in values) or width <= 30 or height < MIN_WIDGET_HEIGHT:
        raise ValueError("widget 坐标不可用")
    cx, cy = x + 30, y + height / 2
    if cx < 0 or cy < 0:
        raise ValueError("widget 不在可点击区域")
    info = await _state(page, deadline, "点击前检查令牌")
    token = info.get("token")
    if isinstance(token, str) and token.strip():
        return token.strip()
    if info.get("state") in {"missing", "error", "timeout", "no-global"}:
        return ""  # 状态已变化，交给轮询处理；不能点错误/消失的控件。
    # 浏览器全局 humanize 已关闭；只在 CF 复选框前做有限步数的移动，不先移远再移回。
    # 步数在点击预算开始前算好，避免导入/读取偏好占用点击预算。
    from browser.turnstile import cf_move_steps

    steps = cf_move_steps(page)
    log(f"widget 已就绪，准备真实鼠标点击 @({cx:.0f},{cy:.0f})")
    click_deadline = min(deadline, time.monotonic() + CLICK_TIMEOUT_SECONDS)
    await _within(lambda: page.mouse.move(cx, cy, steps=steps), click_deadline, "移动到 CF 复选框")
    await _within(lambda: page.mouse.click(cx, cy), click_deadline, "点击 CF 复选框")
    log("真实鼠标点击已完成，开始等待令牌；不会重复点击处理中控件")
    return ""


async def _poll_token(page: Any, deadline: float, stage: str) -> tuple[str, str]:
    """轮询期间每个 evaluate 也有上限；没有 token 不能误报成功。"""
    error_deadline: float | None = None
    while time.monotonic() < deadline:
        info = await _state(page, deadline, stage)
        token = info.get("token")
        if isinstance(token, str) and token.strip():
            return token.strip(), ""
        state = str(info.get("state") or "missing")
        err = info.get("error") or ""
        now = time.monotonic()
        if state == "missing":
            return "", "widget 容器丢失（页面可能已跳转）"
        if state == "no-global":
            return "", "Turnstile api.js 未就绪"
        if state in {"error", "timeout"}:
            if error_deadline is None:
                error_deadline = now + ERROR_GRACE_MS / 1000
            elif now >= error_deadline:
                return "", f"widget 错误 {str(err or state)[:120]}"
        else:
            error_deadline = None
        await _pause(deadline)
    return "", f"{stage}超时"


def register(registry: Any) -> None:
    registry.register(
        "turnstile:inject",
        TurnstileInjectSolver,
        requires={CAP_BROWSER},
        title="Turnstile 令牌铸造",
        description="按 sitekey 注入 widget 换取令牌，供纯 HTTP 提交使用",
        default_budget=90,
    )
