"""腾讯官方 SDK：只等待无感放行或人工操作，不代做验证码挑战。

仅在 BrowserService 的同源固定空白页加载 TJCaptcha.js。Camoufox 的 evaluate
可能处于隔离世界，因此用本次唯一 expose_binding 把主世界回调送进内存；票据
不写 DOM、日志、截图标签或持久化存储，只交给调用方进行站内兑换。

构造器参数依据腾讯云 Web 客户端接入文档（options 默认为可选）：
https://cloud.tencent.com/document/product/1110/36841
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
import json
import math
import re
import time
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from core.errors import TransientError
from core.outcome import Evidence
from . import registry
from .registry import SolveResult

__all__ = ["TencentCaptchaSolver"]

SDK_URL = "https://turing.captcha.qcloud.com/TJCaptcha.js"
HOST_PATH = "/__checkin_tencent__"
DEFAULT_BUDGET_SECONDS = 90.0
RPC_TIMEOUT_SECONDS = 5.0
PAGE_CREATE_TIMEOUT_SECONDS = 30.0
NAVIGATION_TIMEOUT_SECONDS = 20.0
SDK_LOAD_TIMEOUT_SECONDS = 25.0
POLL_INTERVAL_SECONDS = 0.2
SCREENSHOT_TIMEOUT_SECONDS = 1.0
CLEANUP_RESERVE_SECONDS = 5.0

_HOST_HTML = (
    '<!doctype html><html><head><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>验证码</title></head><body></body></html>'
)

# SDK 每次动态加载，不读取 getTicket()、历史全局或隐藏字段。主世界桥只保留销毁
# 方法和实例 ID；敏感值不挂 window、不进 DOM，仅通过专属绑定交付一次。
_BOOTSTRAP_JS = r"""
(() => {
  const KEY = __KEY_JSON__, ID = __ID_JSON__, APP_ID = __APP_ID_JSON__;
  const TARGET = __TARGET_JSON__, BINDING = __BINDING_JSON__;
  if (location.href !== TARGET || window[KEY] || typeof window[BINDING] !== 'function') return;
  let active = true, state = 'sdk_loading', captcha = null, script = null;
  const current = () => active && window[KEY] === bridge && location.href === TARGET;
  const secret = (value, max) => typeof value === 'string' && value.length > 0
    && value.length <= max && /^[\x21-\x7e]+$/.test(value);
  const stop = () => {
    active = false;
    if (script) { script.onload = null; script.onerror = null; }
  };
  const bridge = {
    instance: ID,
    stop,
    dispose: () => {
      stop();
      try { if (captcha && typeof captcha.destroy === 'function') captcha.destroy(); } catch (_) {}
      captcha = null;
      if (script) { script.remove(); script = null; }
      if (window[KEY] === bridge) delete window[KEY];
    },
  };
  window[KEY] = bridge;
  const emit = (next, pair = null) => {
    if (!current()) return;
    state = next;
    const payload = {state: next, instance: ID};
    if (pair) { payload.ret = 0; payload.ticket = pair.ticket; payload.randstr = pair.randstr; }
    try {
      const delivery = window[BINDING](payload);
      if (delivery && typeof delivery.catch === 'function') delivery.catch(() => {});
    } catch (_) { stop(); }
    if (!['sdk_loading', 'pending'].includes(next)) stop();
  };
  const callback = result => {
    if (!current() || !['sdk_loading', 'pending'].includes(state)) return;
    if (!result || typeof result !== 'object') { emit('invalid_result'); return; }
    for (const field of ['appid', 'CaptchaAppId', 'appId']) {
      if (result[field] !== undefined && String(result[field]) !== APP_ID) {
        emit('appid_mismatch'); return;
      }
    }
    if (result.bizState !== undefined && result.bizState !== ID) { emit('instance_mismatch'); return; }
    if (result.ret === 2) { emit('cancelled'); return; }
    if (result.ret !== 0) { emit('verification_failed'); return; }
    // 官方 SDK 的容灾分支也可能 ret=0；容灾票据不是验证通过证据。
    if ((result.errorCode !== undefined && result.errorCode !== null && result.errorCode !== 0)
        || (typeof result.ticket === 'string' && /^trerror_/i.test(result.ticket))) {
      emit('sdk_error'); return;
    }
    if (!secret(result.ticket, 8192) || !secret(result.randstr, 1024)) { emit('invalid_result'); return; }
    emit('done', {ticket: result.ticket, randstr: result.randstr});
  };
  emit('sdk_loading');
  script = document.createElement('script');
  script.src = __SDK_URL_JSON__;
  script.async = true;
  script.onload = () => {
    if (!current()) return;
    if (typeof window.TencentCaptcha !== 'function') { emit('sdk_missing'); return; }
    try {
      emit('pending');
      captcha = new window.TencentCaptcha(String(APP_ID), callback, {userLanguage: 'zh-cn', bizState: ID});
      if (current() && state === 'pending') captcha.show();
    } catch (_) { emit('sdk_error'); }
  };
  script.onerror = () => { if (current()) emit('sdk_load_error'); };
  document.head.appendChild(script);
})();
"""

# 同样通过 script tag 在主世界执行，绝不依赖隔离世界的 window 读取或 DOM 票据桥接。
_STOP_JS = r"""(() => {
  const bridge = window[__KEY_JSON__];
  if (bridge && bridge.instance === __ID_JSON__) bridge.stop();
})();"""
_DISPOSE_JS = r"""(() => {
  const bridge = window[__KEY_JSON__];
  if (bridge && bridge.instance === __ID_JSON__) bridge.dispose();
})();"""
_LOCATION_JS = "() => location.href"


class _StageTimeout(TimeoutError):
    def __init__(self, stage: str) -> None:
        super().__init__(stage)
        self.stage = stage


class _InvalidOrigin(ValueError):
    pass


def _consume(task: asyncio.Future) -> None:
    if not task.cancelled():
        task.exception()


async def _within(
    operation: Callable[[], Awaitable[Any]], deadline: float, stage: str, limit: float | None = None,
) -> Any:
    """不用 wait_for 等待驱动自己的无限取消清理；所有 RPC 共用一个总截止点。"""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _StageTimeout(stage)
    task = asyncio.ensure_future(operation())
    try:
        done, _ = await asyncio.wait({task}, timeout=min(remaining, limit) if limit is not None else remaining)
        if task not in done:
            raise _StageTimeout(stage)
        try:
            return task.result()
        except TimeoutError:
            raise _StageTimeout(stage) from None
    finally:
        if not task.done():
            task.cancel()
        task.add_done_callback(_consume)


def _origin(value: Any) -> str:
    """仅 HTTP(S) 来源；不接受 userinfo、无效端口或控制字符。"""
    if not isinstance(value, str) or not value or len(value) > 4096 or re.search(r"[\s\x00-\x1f\x7f]", value):
        raise _InvalidOrigin
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower()
        port = parsed.port
        if parsed.scheme not in {"http", "https"} or not host or parsed.username is not None:
            raise _InvalidOrigin
        if parsed.password is not None or port == 0 or "\\" in value:
            raise _InvalidOrigin
    except (ValueError, UnicodeError):
        raise _InvalidOrigin from None
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != {"http": 80, "https": 443}[parsed.scheme]:
        authority += f":{port}"
    return f"{parsed.scheme}://{authority}"


def _seconds(ctx: Any, budget: float | None) -> float:
    if isinstance(budget, bool):
        raise ValueError
    seconds = DEFAULT_BUDGET_SECONDS if budget is None else float(budget)
    if not math.isfinite(seconds):
        raise ValueError
    getter = getattr(ctx, "remaining_seconds", None)
    if callable(getter):
        remaining = getter()
        if remaining is not None:
            remaining = float(remaining)
            if not math.isfinite(remaining):
                raise ValueError
            reserve = max(0.0, float(getattr(registry, "TEARDOWN_RESERVE_SECONDS", 20.0)))
            seconds = min(seconds, max(0.0, remaining - reserve))
    return seconds


def _script(template: str, *, key: str, instance: str, target: str = "", app_id: str = "", binding: str = "") -> str:
    for name, value in (
        ("KEY", key), ("ID", instance), ("TARGET", target), ("APP_ID", app_id), ("SDK_URL", SDK_URL), ("BINDING", binding),
    ):
        template = template.replace(f"__{name}_JSON__", json.dumps(value))
    return template


def _valid_secret(value: Any, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum and bool(re.fullmatch(r"[\x21-\x7e]+", value))


def _log(ctx: Any, message: str) -> None:
    logger = getattr(ctx, "log", None)
    if callable(logger):
        try:
            logger(message)
        except Exception:
            pass


_STATE_FAILURES = {
    "sdk_load_error": ("network_error", "腾讯官方验证码 SDK 加载失败"),
    "sdk_error": ("network_error", "腾讯验证码 SDK 报错或返回容灾票据，未视为通过"),
    "sdk_missing": ("unavailable", "腾讯官方验证码 SDK 未提供构造器"),
    "cancelled": ("cancelled", "用户关闭了腾讯验证码"),
    "verification_failed": ("need_human", "腾讯验证码未通过，请在有头浏览器中人工完成验证"),
    "invalid_result": ("invalid_result", "腾讯验证码未返回有效票据和随机串"),
    "appid_mismatch": ("invalid_app_id", "腾讯验证码回调的 App ID 与本次请求不符"),
    "instance_mismatch": ("invalid_result", "腾讯验证码回调不属于本次实例"),
    "source_mismatch": ("invalid_origin", "验证码承载页离开了预期同源页面，已停止"),
}


class _CallbackState:
    """page.expose_binding 的唯一接收器；只接收主 frame 本次消息，收尾同步失效。"""

    def __init__(self, page: Any, *, instance: str, target: str, app_id: str, deadline: float) -> None:
        self.page, self.instance, self.target, self.deadline = page, instance, target, deadline
        self.app_id = app_id
        self.accepting = True
        self.info: dict[str, Any] = {"state": "sdk_loading"}

    def _record(self, state: str, **pair: Any) -> None:
        self.info = {"state": state, **pair}
        if state not in {"sdk_loading", "pending"}:
            self.accepting = False

    def receive(self, source: Any, payload: Any) -> bool:
        # 暴露绑定在所有 frame 和导航后都可能仍存在；不能相信 payload 自报的 URL。
        if not self.accepting or time.monotonic() >= self.deadline:
            return False
        try:
            if not isinstance(source, dict) or source.get("page") is not self.page:
                return False
            frame = source.get("frame")
            if frame is not getattr(self.page, "main_frame", None) or frame is None:
                return False
            if frame.url != self.target or self.page.url != self.target:
                self._record("source_mismatch")
                return False
            if not isinstance(payload, dict) or not isinstance(payload.get("state"), str):
                self._record("invalid_result")
                return False
            if payload.get("instance") != self.instance:
                self._record("instance_mismatch")
                return False
            for field in ("appid", "CaptchaAppId", "appId"):
                if field in payload and str(payload[field]) != self.app_id:
                    self._record("appid_mismatch")
                    return False
            if "bizState" in payload and payload["bizState"] != self.instance:
                self._record("instance_mismatch")
                return False
            state = payload["state"]
            if state == "done":
                ticket, randstr = payload.get("ticket"), payload.get("randstr")
                if (type(payload.get("ret")) is not int or payload["ret"] != 0
                        or not _valid_secret(ticket, 8192) or not _valid_secret(randstr, 1024)):
                    self._record("invalid_result")
                    return False
                if ticket.lower().startswith("trerror_") or payload.get("errorCode") not in (None, 0):
                    self._record("sdk_error")
                    return False
                self._record("done", ticket=ticket, randstr=randstr)
                return True
            if state not in {"sdk_loading", "pending"} and state not in _STATE_FAILURES:
                state = "invalid_result"
            self._record(state)  # 错误字段、sid、ticket/randstr 等额外字段一律丢弃。
            return True
        except Exception:
            self._record("invalid_result")
            return False  # 绑定回调本身也绝不能让原始驱动异常/票据进入日志。

    def close(self) -> None:
        self.accepting = False
        self.info = {"state": "closed"}


async def _wait_result(receiver: _CallbackState, ctx: Any, *, deadline: float) -> SolveResult:
    load_deadline = min(deadline, time.monotonic() + SDK_LOAD_TIMEOUT_SECONDS)
    pending = False
    while time.monotonic() < deadline:
        if receiver.page.url != receiver.target:
            reason, message = _STATE_FAILURES["source_mismatch"]
            return SolveResult.failure(reason, message, attempts=1)
        info = receiver.info
        state = info["state"]
        if state == "done":
            return SolveResult.solved("", attempts=1, data={"ticket": info["ticket"], "randstr": info["randstr"]})
        if state in _STATE_FAILURES:
            reason, message = _STATE_FAILURES[state]
            return SolveResult.failure(reason, message, attempts=1)
        if state == "pending" and not pending:
            pending = True
            _log(ctx, "腾讯官方验证码已展示，仅等待无感放行或人工完成；不自动拖动或识图")
        if state == "sdk_loading" and time.monotonic() >= load_deadline:
            raise _StageTimeout("加载官方 SDK")
        await asyncio.sleep(min(POLL_INTERVAL_SECONDS, max(0.0, deadline - time.monotonic())))
    if pending:
        return SolveResult.failure("need_human", "腾讯验证码尚未完成人工验证，已在预算内停止", attempts=1)
    raise _StageTimeout("等待验证回调")


async def _finish(
    ctx: Any, manager: Any, lease: Any, page: Any, result: SolveResult | None, *, receiver: _CallbackState | None,
    binding_handle: Any, key: str, instance: str, target: str, host_ready: bool, deadline: float, reserve: float,
) -> SolveResult | None:
    """接收器立即失效，再做有界截图/销毁；最后始终归还租约而不关闭共享服务。"""
    if receiver is not None:
        receiver.close()
    cancelled = False
    evidence_deadline = min(deadline, time.monotonic() + reserve / 2)
    stopped = False
    if page is not None and host_ready and page.url == target:
        try:
            await _within(
                lambda: page.add_script_tag(content=_script(_STOP_JS, key=key, instance=instance)),
                evidence_deadline, "停止验证回调", RPC_TIMEOUT_SECONDS,
            )
            stopped = True
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            pass
        if stopped and result is not None and not result.ok and result.reason != "cancelled":
            try:
                shot = await _within(
                    lambda: lease.screenshot("tencent-widget-failed.png", page=page),
                    evidence_deadline, "采集验证截图", SCREENSHOT_TIMEOUT_SECONDS,
                )
                if isinstance(shot, str) and shot:
                    result = result.with_evidence(Evidence().with_screenshot(shot))
            except asyncio.CancelledError:
                cancelled = True
            except Exception:
                pass
        try:
            await _within(
                lambda: page.add_script_tag(content=_script(_DISPOSE_JS, key=key, instance=instance)),
                evidence_deadline, "销毁验证实例", RPC_TIMEOUT_SECONDS,
            )
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            pass
    close_binding = getattr(binding_handle, "close", None)  # 新版返回句柄；旧版返回 None，随 page 关闭。
    if callable(close_binding):
        try:
            await _within(close_binding, evidence_deadline, "移除验证回调绑定", RPC_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            pass
    # __aenter__ 超时也尝试 __aexit__，仅回收本租约页面，保留共享浏览器及登录态。
    try:
        await _within(lambda: manager.__aexit__(None, None, None), deadline, "归还浏览器租约")
    except asyncio.CancelledError:
        cancelled = True
    except Exception:
        _log(ctx, "腾讯验证码页面收尾未完成，交由浏览器服务回收")
    if cancelled:
        raise asyncio.CancelledError
    return result


class TencentCaptchaSolver:
    """只消费官方 SDK 本次 callback 的有效票据；不修改账号认证状态。"""

    async def solve(
        self, ctx: Any, /, *, app_id: str, budget: float | None = None, origin: str = "", **_: Any,
    ) -> SolveResult:
        started = time.monotonic()
        if not isinstance(app_id, str) or not re.fullmatch(r"[0-9]{1,32}", app_id):
            return SolveResult.failure("invalid_app_id", "腾讯验证码 App ID 必须是非空数字字符串")
        browser = getattr(ctx, "browser_service", None) or getattr(ctx, "browser", None)
        if browser is None or not callable(getattr(browser, "lease", None)):
            return SolveResult.failure("unavailable", "腾讯验证码需要浏览器服务")
        try:
            seconds = _seconds(ctx, budget)
        except Exception:
            return SolveResult.failure("invalid", "腾讯验证码时间预算无效")
        if seconds <= 0:
            return SolveResult.failure("timeout", "腾讯验证码剩余预算不足，未启动浏览器")
        try:
            expected = _origin(getattr(browser, "base_url", ""))
            if origin and _origin(origin) != expected:
                raise _InvalidOrigin
        except _InvalidOrigin:
            return SolveResult.failure("invalid_origin", "腾讯验证码仅允许在浏览器服务的预期同源页面加载")
        target = expected + HOST_PATH
        deadline = started + seconds
        reserve = min(CLEANUP_RESERVE_SECONDS, seconds / 5)
        work_deadline = deadline - reserve
        instance = uuid4().hex
        key, binding = "__checkin_tencent_" + instance, "__checkin_tencent_callback_" + instance
        manager = lease = page = receiver = binding_handle = None
        result = None
        stage = "启动浏览器"
        attempts = 0
        host_ready = False
        _log(ctx, f"腾讯验证码总预算 {seconds:g}s（含启动、SDK、人工等待、截图和收尾）")
        try:
            manager = browser.lease(reason="tencent")
            lease = await _within(manager.__aenter__, work_deadline, stage)
            if _origin(getattr(getattr(lease, "service", None), "base_url", "")) != expected:
                raise _InvalidOrigin
            stage = "创建验证页面"
            page = await _within(lambda: lease.new_page(guard_origin=""), work_deadline, stage, PAGE_CREATE_TIMEOUT_SECONDS)
            if not callable(getattr(page, "expose_binding", None)):
                result = SolveResult.failure("unavailable", "浏览器不支持安全验证码回调绑定")
            else:
                stage = "设置承载页路由"
                await _within(
                    lambda: page.route(target, lambda route: route.fulfill(
                        status=200, content_type="text/html; charset=utf-8", body=_HOST_HTML,
                    )), work_deadline, stage, RPC_TIMEOUT_SECONDS,
                )
                stage = "打开同源承载页"
                await _within(lambda: lease.goto(
                    target, page=page, wait_until="domcontentloaded", ignore_timeout=False,
                    timeout=max(1, int(min(NAVIGATION_TIMEOUT_SECONDS, max(0.0, work_deadline - time.monotonic())) * 1000)),
                ), work_deadline, stage, NAVIGATION_TIMEOUT_SECONDS)
                stage = "确认承载页来源"
                actual = await _within(lambda: page.evaluate(_LOCATION_JS), work_deadline, stage, RPC_TIMEOUT_SECONDS)
                if actual != target:
                    raise _InvalidOrigin
                host_ready = True
                receiver = _CallbackState(page, instance=instance, target=target, app_id=app_id, deadline=work_deadline)
                stage = "建立验证码回调"
                binding_handle = await _within(
                    lambda: page.expose_binding(binding, receiver.receive), work_deadline, stage, RPC_TIMEOUT_SECONDS,
                )
                stage = "加载官方 SDK"
                script = _script(_BOOTSTRAP_JS, key=key, instance=instance, target=target, app_id=app_id, binding=binding)
                await _within(lambda: page.add_script_tag(content=script), work_deadline, stage, RPC_TIMEOUT_SECONDS)
                attempts = 1
                stage = "等待验证回调"
                result = await _wait_result(receiver, ctx, deadline=work_deadline)
        except asyncio.CancelledError:
            # 遵循引擎的任务取消语义；人工关闭弹窗的 ret=2 则返回 cancelled。
            _log(ctx, "腾讯验证码任务已取消，停止接受回调并归还租约")
            raise
        except _InvalidOrigin:
            result = SolveResult.failure("invalid_origin", "腾讯验证码承载页来源校验失败，未继续验证", attempts=attempts)
        except _StageTimeout as exc:
            result = SolveResult.failure(
                "timeout", f"腾讯验证码{exc.stage}超时，已停止本轮验证", attempts=attempts, data={"stage": exc.stage},
            )
        except Exception as exc:
            reason = "network_error" if isinstance(exc, (ConnectionError, TransientError)) else "error"
            if stage == "启动浏览器":
                reason = "unavailable"
            # 原始驱动异常可能包含回调票据；只允许输出异常类别和固定阶段。
            message = f"腾讯验证码{stage}失败：{type(exc).__name__}"
            _log(ctx, message)
            result = SolveResult.failure(reason, message, attempts=attempts, data={"stage": stage})
        finally:
            if manager is not None:
                result = await _finish(
                    ctx, manager, lease, page, result, receiver=receiver, binding_handle=binding_handle,
                    key=key, instance=instance, target=target, host_ready=host_ready, deadline=deadline, reserve=reserve,
                )
        return result if result is not None else SolveResult.failure("error", "腾讯验证码未产生结果")
