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

import time
from typing import Any

from ..core.outcome import Evidence
from .registry import CAP_BROWSER, SolveResult

__all__ = ["TurnstileInjectSolver", "register"]

# widget 注入脚本。把签发的令牌写进 host 元素的 data-token 属性，供隔离上下文读取。
_WIDGET_BOOTSTRAP_JS = r"""
(() => {
  const SITEKEY = '__SITEKEY__';
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
  if (!token) {
    for (const f of document.querySelectorAll(
      'input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]'
    )) {
      const v = typeof f.value === 'string' ? f.value : String(f.textContent || '');
      if (v.trim()) { token = v.trim(); break; }
    }
  }
  return {
    state: (host && host.getAttribute('data-state')) || 'missing',
    error: (host && host.getAttribute('data-error')) || '',
    token: token,
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

        log = getattr(ctx, "log", None) or (lambda _m: None)
        deadline = time.monotonic() + float(budget or 90)
        evidence = Evidence()
        reason = ""
        async with browser.lease(reason="turnstile") as lease:
            page = await lease.new_page()
            await _open_widget_host(lease, page, log)
            log("注入 Turnstile widget（主世界）…")
            try:
                await page.add_script_tag(content=_WIDGET_BOOTSTRAP_JS.replace("__SITEKEY__", key))
            except Exception as exc:  # noqa: BLE001
                return SolveResult.failure("error", f"注入 widget 失败：{type(exc).__name__}: {exc}")

            for attempt in range(1, MAX_ATTEMPTS + 1):
                token, reason = await _one_attempt(page, log, deadline)
                if token:
                    log(f"Turnstile 令牌已签发（{len(token)} 字符）")
                    return SolveResult.solved(token, attempts=attempt)
                if attempt >= MAX_ATTEMPTS or time.monotonic() >= deadline:
                    break
                log(f"第 {attempt} 次失败（{reason}），reset widget 后重试")
                try:
                    await page.evaluate(_RESET_JS)
                    await page.wait_for_timeout(RETRY_COOLDOWN_MS)
                except Exception:
                    break
            shot = await lease.screenshot("turnstile-inject-failed.png", page=page)
            if shot:
                evidence = evidence.with_screenshot(shot)

        return SolveResult.failure(
            "timeout" if "超时" in reason else "refused",
            f"未能取得 Turnstile 令牌（{reason or '未知原因'}）；"
            "多为当前出口 IP 被 Cloudflare 风控，可配置住宅代理或等下次任务重试。",
            attempts=MAX_ATTEMPTS,
            evidence=evidence,
        )


async def _open_widget_host(lease: Any, page: Any, log: Any) -> None:
    """在站点 origin 下打开一个最小承载页。

    Turnstile 只校验 (sitekey, hostname)，不关心页面内容；而站点首页要下载数 MB
    bundle 并执行整套前端（实测 ~3s，且站点脚本可能干扰注入）。路由拦截返回空白 HTML，
    hostname 不变、令牌照样有效。拦截失败时回落真实导航，保证功能不因优化而丢失。
    """
    base_url = lease.service.base_url.rstrip("/")
    target = base_url + HOST_PATH
    try:
        await page.route(
            target,
            lambda route: route.fulfill(
                status=200,
                content_type="text/html; charset=utf-8",
                body="<!doctype html><html><head><title>checkin</title></head><body></body></html>",
            ),
        )
        await lease.goto(HOST_PATH, page=page, wait_until="domcontentloaded", timeout=20000)
        host = await page.evaluate("() => location.hostname")
        if host and str(host) in base_url:
            log(f"已在 {host} 下打开最小承载页（跳过 SPA 加载）")
            return
        log("承载页 hostname 校验未通过，回落真实导航")
    except Exception as exc:  # noqa: BLE001
        log(f"最小承载页不可用（{type(exc).__name__}: {exc}），回落真实导航")

    await lease.goto("", page=page, wait_until="domcontentloaded", timeout=45000)
    from browser import bypass

    await bypass.solve_cloudflare(page, log=log, wait_seconds=15)


async def _one_attempt(page: Any, log: Any, deadline: float) -> tuple[str, str]:
    """单次求解：等挂载 → 看是否自动签发 → 真实点击 → 轮询令牌。"""
    mount_deadline = min(time.monotonic() + MOUNT_WAIT_MS / 1000, deadline)
    slot: dict = {}
    while True:
        info = await page.evaluate(_STATE_JS)
        token = str(info.get("token") or "")
        if token:  # 极快的自动签发，连挂载轮询都没走完
            log(f"令牌已自动签发（{len(token)} 字符，无需点击）")
            return token, ""
        state = str(info.get("state") or "missing")
        if state == "missing":
            return "", "widget 容器丢失（页面可能已跳转）"
        if state == "no-global":
            return "", "Turnstile api.js 未就绪"
        slot = info.get("slot") or {}
        if float(slot.get("h", 0) or 0) >= MIN_WIDGET_HEIGHT:
            break
        if time.monotonic() >= mount_deadline:
            # 带上 widget 自报状态：Cloudflare 拒绝渲染时容器高度会一直是 0，
            # 只说「挂载超时」无法区分「还没挂上」和「已被判定为自动化」。
            err = info.get("error") or ""
            detail = f"state={state}" + (f" err={err}" if err else "")
            return "", f"widget 挂载超时（{detail}，容器高度 {slot.get('h', 0)}）"
        await page.wait_for_timeout(POLL_INTERVAL_MS)

    await _click_checkbox(page, slot, log)
    return await _poll_token(page, min(time.monotonic() + TOKEN_WAIT_MS / 1000, deadline), "等待令牌")


async def _click_checkbox(page: Any, slot: dict, log: Any) -> None:
    """用真实鼠标事件点击复选框。

    Cloudflare 校验 isTrusted，JS click 无效。Turnstile 用 closed shadow root，内部
    iframe 定位不到，容器矩形是唯一可用几何：复选框在容器左侧约 30px、垂直居中。
    steps 必须很小：Camoufox 会把每个 step 都人类化，A/B 实测 2/2 是能签发的最小值，
    更大的值会把 60px 移动拖到十几秒。
    """
    cx = float(slot["x"]) + 30
    cy = float(slot["y"]) + float(slot["h"]) / 2
    log(f"widget 已就绪，真实鼠标点击复选框 @({cx:.0f},{cy:.0f})")
    await page.mouse.move(max(cx + 60, 8.0), max(cy + 40, 8.0), steps=2)
    await page.mouse.move(cx, cy, steps=2)
    await page.mouse.click(cx, cy)


async def _poll_token(page: Any, deadline: float, stage: str) -> tuple[str, str]:
    """轮询令牌直到出现、widget 进入终态、或到达 deadline。"""
    error_deadline: float | None = None
    while True:
        info = await page.evaluate(_STATE_JS)
        token = str(info.get("token") or "")
        if token:
            return token, ""
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
                return "", f"widget 错误 {err or state}"
        elif error_deadline is not None:
            error_deadline = None  # 已自行恢复，撤销宽限计时
        if now >= deadline:
            return "", f"{stage}超时"
        await page.wait_for_timeout(POLL_INTERVAL_MS)


def register(registry: Any) -> None:
    registry.register(
        "turnstile:inject",
        TurnstileInjectSolver,
        requires={CAP_BROWSER},
        title="Turnstile 令牌铸造",
        description="按 sitekey 注入 widget 换取令牌，供纯 HTTP 提交使用",
        default_budget=90,
    )
