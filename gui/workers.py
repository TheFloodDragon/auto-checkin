# -*- coding: utf-8 -*-
"""后台执行层。

- TaskRunner   ：QThreadPool 统一执行 dailytask 引擎的单账号运行。
  信号定义在长寿命 runner 上，任务对象只负责计算后经 runner 转发回主线程，
  消除旧版 BatchTask.setAutoDelete(False) + 手动持引用的整套 workaround。
- BrowserWorker：QThread，仅保留需要人工交互/长时驻留的 capture��登录捕获）
  与 verify（登录态检测）；执行调用一律走 TaskRunner。

GUI 里「测试运行」与批量/CI 走的是**同一个引擎入口**（``run_account``），
只是前者在进程内、后者在子进程。旧实现这两条路各拼一份运行参数，行为常年不一致。
"""

from __future__ import annotations

import time
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, QThread, QThreadPool, Signal

from core.outcome import to_legacy_status

from . import core

TaskCallback = Callable[[dict[str, Any]], None]
StorageOperation = Callable[[], Any]
StorageCallback = Callable[[Any, BaseException | None], None]


def _task_context(action: str, params: dict[str, Any]) -> dict[str, Any]:
    return {
        "action": action,
        "site": params.get("name") or params.get("base_url"),
        "base_url": params.get("base_url", ""),
        "template": params.get("template", ""),
        "login": (params.get("login") or {}).get("method", ""),
        "tasks": [item.get("id") for item in (params.get("tasks") or [])],
    }


class _ProviderTask(QRunnable):
    """在线程池里执行一次账号运行，结果经 runner 的信号送回主线程。"""

    def __init__(self, action: str, params: dict[str, Any], callback: TaskCallback, done_signal: Signal):
        super().__init__()
        self.action = action
        self.params = params
        self.callback = callback
        self._done = done_signal

    def run(self) -> None:
        context = _task_context(self.action, self.params)
        started = time.perf_counter()
        core.bg_log("INFO", "后台任务开始", **context)
        try:
            result = _execute(self.action, self.params)
            core.bg_log(
                "INFO" if result.get("ok") else "WARN",
                "后台任务完成",
                duration=f"{time.perf_counter() - started:.2f}s",
                result=result,
                **context,
            )
        except Exception as exc:
            result = core.error_result(
                "后台任务异常", exc, duration=f"{time.perf_counter() - started:.2f}s", **context
            )
            result["query"] = self.action == "query"
        self._done.emit(self.callback, result)


def _execute(action: str, params: dict[str, Any]) -> dict[str, Any]:
    """执行一次账号运行，并把结论压成 GUI 用的扁平结果。

    ``query`` 与 ``checkin`` 现在走同一条链路：区别只是前者把 ``execute`` 阶段关掉
    （``flow.execute=off``），只做登录与状态读取。旧实现为只读查询单独维护了一套
    ``query_action``，于是「查询能过、签到失败」这类偏差长期存在。
    """
    from apps.cli import run_account_sync
    from config import schema
    from config.overlay import Overlay

    payload = dict(params)
    explicit = tuple(payload.pop("_explicit_credential_fields", ()) or ())
    oauth_states = payload.pop("_oauth_states", {}) or {}
    if action == "query":
        flow = dict(payload.get("flow") or {})
        flow["execute"] = "off"
        payload["flow"] = flow

    spec = schema.parse_account(payload)
    run = run_account_sync(
        spec,
        overlay=Overlay().load(),
        explicit=explicit,
        oauth_state=lambda provider, account: schema.oauth_state_text(oauth_states, provider, account),
        structured=False,
    )
    return _flatten(run, query=action == "query")


def _flatten(run: Any, *, query: bool) -> dict[str, Any]:
    """AccountRun → GUI 单行结果。多任务时取最严重的一条作为整体结论。"""
    records = list(run.records)
    if not records:
        return {"ok": False, "query": query, "status": "error", "message": "没有可执行的任务"}
    worst = min(records, key=lambda item: (item.ok, item.outcome.reason == ""))
    view = worst.rendered()
    return {
        "ok": all(item.ok for item in records),
        "query": query,
        # status 保留旧 8 值形态：GUI 的状态缓存与图标映射还按它索引。
        "status": to_legacy_status(worst.outcome),
        "verdict": str(worst.outcome.verdict),
        "reason": worst.outcome.reason,
        "message": "；".join(item.outcome.message for item in records if item.outcome.message),
        "text": view.text,
        "text_label": view.text_label,
        "quota_usd": core.detail_quota_usd(dict(worst.outcome.data)),
        "checked_in": worst.outcome.verdict.value in {"already_done", "success"},
        "detail": dict(worst.outcome.data),
        "results": [item.to_payload() for item in records],
    }


class TaskRunner(QObject):
    """账号运行的统一入口；回调保证在主线程执行。"""

    _done = Signal(object, dict)

    def __init__(self, parent: QObject | None = None, max_threads: int = 5):
        super().__init__(parent)
        self._pool = QThreadPool(self)
        self._pool.setMaxThreadCount(max_threads)
        self._done.connect(self._dispatch)

    def submit(self, action: str, params: dict[str, Any], callback: TaskCallback) -> None:
        self._pool.start(_ProviderTask(action, params, callback, self._done))

    def _dispatch(self, callback: object, result: dict) -> None:
        try:
            callback(result)  # type: ignore[operator]
        except Exception as exc:
            core.bg_log("ERROR", "任务回调异常", error=exc)

    def clear_pending(self) -> None:
        """清空尚未开始的排队任务；已在飞的任务无法安全中断。"""
        self._pool.clear()

    def shutdown(self, wait_ms: int = 5000) -> bool:
        """停止接收排队任务，并等待正在运行的 provider 调用收尾。"""
        self._pool.clear()
        return self._pool.waitForDone(wait_ms)


class _StorageTask(QRunnable):
    """串行存储队列中的一次文件操作。"""

    def __init__(self, operation: StorageOperation, callback: StorageCallback | None, done_signal: Signal):
        super().__init__()
        self.operation = operation
        self.callback = callback
        self._done = done_signal

    def run(self) -> None:
        try:
            result = self.operation()
            error: BaseException | None = None
        except BaseException as exc:  # noqa: BLE001 - 必须把写盘错误投递回主线程
            result = None
            error = exc
        self._done.emit(self.callback, result, error)


class StorageRunner(QObject):
    """单线程写盘队列；回调总是在 GUI 主线程执行。"""

    _done = Signal(object, object, object)

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)
        self._pool = QThreadPool(self)
        self._pool.setMaxThreadCount(1)
        self._done.connect(self._dispatch)

    def submit(self, operation: StorageOperation, callback: StorageCallback | None = None) -> None:
        self._pool.start(_StorageTask(operation, callback, self._done))

    def _dispatch(self, callback: object, result: object, error: object) -> None:
        if callback is None:
            if isinstance(error, BaseException):
                core.bg_log("ERROR", "后台写盘失败", error=error)
            return
        try:
            callback(result, error if isinstance(error, BaseException) else None)  # type: ignore[operator]
        except Exception as exc:
            core.bg_log("ERROR", "存储回调异常", error=exc)

    def shutdown(self, wait_ms: int = 5000) -> bool:
        """等待已提交写盘完成；不丢弃持久化任务。"""
        return self._pool.waitForDone(wait_ms)


class BrowserWorker(QThread):
    """在后台线程跑 Playwright 交互操作，避免阻塞 UI。

    action ∈ {"capture", "verify"}：
      - capture：有头浏览器人工登录捕获登录态，结束返回 base64 state；
      - verify ：无头检测登录态是否有效。
    通过信号把进度/结果回传主线程（Qt 信号跨线程安全）。
    """

    progress = Signal(str)
    finished_ok = Signal(dict)
    failed = Signal(str)

    def __init__(self, action: str, params: dict[str, Any], parent=None):
        super().__init__(parent)
        self.action = action
        self.params = params
        self._close_requested = False

    def request_close(self) -> None:
        """capture 模式：用户确认登录完成后置位，让 wait_for_close 返回。"""
        self._close_requested = True

    def _fail(self, message: str, exc: BaseException | None = None) -> None:
        import traceback

        from core.masking import mask_secrets

        tb = traceback.format_exc() if exc is not None else ""
        text = f"{message}：{exc}" if exc is not None else message
        core.bg_log("ERROR", text, traceback=tb, **_task_context(self.action, self.params))
        self.failed.emit(mask_secrets(text))

    def run(self) -> None:  # noqa: D401 - QThread 入口
        log = self.progress.emit
        p = self.params
        started = time.perf_counter()
        core.bg_log("INFO", "浏览器任务开始", **_task_context(self.action, self.params))

        try:
            import asyncio

            from browser import session as browser_session
        except Exception as exc:
            self._fail("加载 browser_session 失败", exc)
            return

        async def _wait_for_close_async() -> None:
            waited = 0.0
            while not self._close_requested and waited < 600.0:
                await asyncio.sleep(0.2)
                waited += 0.2

        try:
            login = p.get("login") or {}
            login_method = str(login.get("method") or p.get("auth_method") or "")
            login_args = login.get("args") or {}
            template = str(p.get("template") or p.get("site_profile") or p.get("type") or "")
            if self.action == "capture":
                if login_method == "oauth":
                    result = browser_session.run_sync(
                        browser_session.capture_oauth_state(
                            oauth_provider=login.get("provider") or p.get("oauth_provider", "linuxdo"),
                            proxy=p.get("proxy", ""),
                            log=log,
                            wait_for_close=_wait_for_close_async,
                        )
                    )
                elif template == "sub2api":
                    result = browser_session.run_sync(
                        browser_session.capture_sub2api_login(
                            base_url=p["base_url"],
                            proxy=p.get("proxy", ""),
                            log=log,
                            wait_for_close=_wait_for_close_async,
                        )
                    )
                else:
                    result = browser_session.run_sync(
                        browser_session.capture_login(
                            base_url=p["base_url"],
                            fallback_uid=login_args.get("user_id") or p.get("fallback_uid", ""),
                            proxy=p.get("proxy", ""),
                            log=log,
                            wait_for_close=_wait_for_close_async,
                        )
                    )
            elif self.action == "verify":
                if template == "sub2api":
                    # sub2api 无 /api/user/self，用 browser_state 刷新 token 检测有效性
                    token = browser_session.run_sync(
                        browser_session.capture_sub2api_token(
                            base_url=p["base_url"],
                            browser_state_text=p.get("browser_state", ""),
                            proxy=p.get("proxy", ""),
                            log=log,
                        )
                    )
                    if token:
                        result = {"ok": True, "message": f"登录态有效，已刷新 auth_token（{len(token)} 字符）"}
                    else:
                        result = {"ok": False, "message": "登录态无效或无法刷新 token，请重新捕获。"}
                else:
                    result = browser_session.run_sync(
                        browser_session.verify_state(
                            base_url=p["base_url"],
                            browser_state_text=p.get("browser_state", ""),
                            fallback_uid=p.get("fallback_uid", ""),
                            proxy=p.get("proxy", ""),
                            log=log,
                        )
                    )
            else:
                self._fail(f"未知操作：{self.action}")
                return
        except browser_session.BrowserSessionError as exc:
            self._fail("浏览器会话失败", exc)
            return
        except Exception as exc:
            self._fail("浏览器操作异常", exc)
            return

        ok = bool(result.get("ok", True)) if isinstance(result, dict) else True
        core.bg_log(
            "INFO" if ok else "WARN",
            "浏览器任务完成",
            ok=ok,
            duration=f"{time.perf_counter() - started:.2f}s",
            result=result,
            **_task_context(self.action, self.params),
        )
        self.finished_ok.emit(result)
