"""Qt 无关的单账号子进程桥：stdin 请求/控制，stdout 单个 JSON，stderr 诊断。"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from core.masking import is_sensitive_key, mask_secrets, sanitize_data

ACTIONS = frozenset({"run", "explain", "capture", "templates"})
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 16 * 1024 * 1024
MAX_LOG_LINE = 32 * 1024


class Redactor:
    """字段脱敏之外，也清除请求中的裸凭据及 Cookie 子值。"""

    def __init__(self, request: Any = None):
        self.secrets: set[str] = set()
        self._collect(request)

    def _collect(self, value: Any, sensitive: bool = False, key: str = "") -> None:
        sensitive = sensitive or is_sensitive_key(key) or key in {"oauth_states", "args"}
        if isinstance(value, dict):
            for name, item in value.items():
                self._collect(item, sensitive, str(name))
        elif isinstance(value, (tuple, list)):
            for item in value:
                self._collect(item, sensitive)
        elif isinstance(value, str) and value:
            if sensitive:
                self.secrets.add(value)
                self.secrets.add(json.dumps(value, ensure_ascii=False)[1:-1])
                self.secrets.update(part for part in value.splitlines() if part)
                if "cookie" in key.lower():
                    self.secrets.update(part.split("=", 1)[1].strip() for part in value.split(";") if "=" in part)
                if key in {"browser_state", "oauth_state", "state"}:
                    self._state_secrets(value)
            if key in {"proxy", "url", "environ_proxy", "base_url"}:
                try:
                    parsed = urlsplit(value if "://" in value else "http://" + value)
                    self.secrets.update(form for part in (parsed.username, parsed.password) if part
                                        for form in (part, unquote(part)))
                except ValueError:
                    pass

    def _state_secrets(self, value: str) -> None:
        try:
            from browser.state import decode_state

            state = decode_state(value)
            for cookie in state.get("cookies", []):
                self._collect(cookie.get("value"), True)
            for origin in state.get("origins", []):
                for item in origin.get("localStorage", []):
                    if is_sensitive_key(item.get("name", "")):
                        self._collect(item.get("value"), True)
        except Exception:
            pass

    def credentials(self, credentials) -> None:
        from core.account import CREDENTIAL_FIELDS

        self._collect({name: credentials.get(name) for name in CREDENTIAL_FIELDS})

    def text(self, value: Any) -> str:
        text = str(value)
        for secret in sorted(self.secrets, key=len, reverse=True):
            if len(secret) >= 4:
                text = text.replace(secret, "<redacted>")
            elif secret:
                text = re.sub(r"(?<!\w)" + re.escape(secret) + r"(?!\w)", "<redacted>", text)
        return mask_secrets(text)

    def data(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): self.data(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.data(item) for item in value]
        return self.text(value) if isinstance(value, str) else value


def safe_data(payload: Any) -> Any:
    """结果不记录凭据，且不把同一 payload 的凭据复述到 message/evidence。"""
    return Redactor(payload).data(sanitize_data(payload))


class _DiagnosticStream:
    """子进程内先清除文件/覆盖层读取的凭据，再写真实 stderr 管道。"""

    def __init__(self, stream, redactor: Redactor):
        self.stream, self.redactor = stream, redactor
        self.pending = ""
        self.dropping = False
        self.total = 0
        self.lock = threading.RLock()

    def write(self, text: str) -> int:
        with self.lock:
            for part in text.splitlines(keepends=True):
                if not self.dropping:
                    self.pending += part
                    if len(self.pending) > MAX_LOG_LINE:
                        self.pending = ""
                        self.dropping = True
                if part.endswith(("\n", "\r")):
                    self._line()
        return len(text)

    def _line(self) -> None:
        if self.pending and not self.dropping:
            safe = self.redactor.text(self.pending.rstrip("\r\n")) + "\n"
            self.total += len(safe.encode("utf-8"))
            if self.total <= 2 * 1024 * 1024:
                self.stream.write(safe)
                self.stream.flush()
        self.pending = ""
        self.dropping = False

    def flush(self) -> None:
        self.stream.flush()

    def finish(self) -> None:
        with self.lock:
            self._line()


class CaptureCancelled(Exception):
    pass


class _PipeInput:
    """单读者管道缓冲：不让控制线程长期阻塞在 Python/CRT 的 stdin 锁上。

    Windows 上阻塞的 stdin.readline 会卡住 NumPy 原生模块加载，并可能在解释器
    退出时触发 _enter_buffered_busy。先探测可读字节，再短读；请求和控制命令共用
    本缓冲，保留同一批写入时预读到的后续命令。stop() 可及时收束后台线程。
    """

    def __init__(self, fd: int):
        self.fd = fd
        self.pending = bytearray()
        self.eof = False
        self.stopped = threading.Event()
        if os.name == "nt":
            import ctypes
            import msvcrt
            from ctypes import wintypes

            self._handle = msvcrt.get_osfhandle(fd)
            self._peek = ctypes.WinDLL("kernel32", use_last_error=True).PeekNamedPipe
            self._peek.argtypes = [
                wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(wintypes.DWORD),
            ]
            self._peek.restype = wintypes.BOOL

    def _available(self) -> int:
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            count = wintypes.DWORD()
            if not self._peek(self._handle, None, 0, None, ctypes.byref(count), None):
                error = ctypes.get_last_error()
                if error in {109, 232, 233}:  # 管道断开/写端关闭，等价 EOF。
                    return -1
                raise ctypes.WinError(error)
            return count.value
        import select

        return 65536 if select.select([self.fd], [], [], 0)[0] else 0

    def readline(self, limit: int) -> bytes:
        while not self.stopped.is_set():
            newline = self.pending.find(b"\n", 0, limit)
            if newline >= 0 or len(self.pending) >= limit or self.eof:
                count = newline + 1 if newline >= 0 else min(len(self.pending), limit)
                result = bytes(self.pending[:count])
                del self.pending[:count]
                return result
            available = self._available()
            if available < 0:
                self.eof = True
            elif available:
                data = os.read(self.fd, min(available, 65536, limit - len(self.pending)))
                self.pending.extend(data)
                self.eof = not data
            else:
                self.stopped.wait(0.05)
        return b""

    def stop(self) -> None:
        self.stopped.set()


def _input_stream() -> Any:
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    try:
        fd = stream.fileno()
        if stat.S_ISFIFO(os.fstat(fd).st_mode):
            return _PipeInput(fd)
    except (AttributeError, OSError, ValueError):
        pass  # 内存测试流/普通重定向文件不需要管道轮询。
    return stream


class CaptureControl:
    """控制读线程只读 stdin；浏览器及关闭流程始终在同一 async loop。"""

    def __init__(self, stream: Any = None, timeout: float = 600.0):
        self.stream = stream
        self.timeout = timeout
        self.command = ""
        self._event = threading.Event()
        self._closing = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.stream is not None and self._thread is None:
            self._thread = threading.Thread(target=self._read, daemon=True, name="capture-stdin")
            self._thread.start()

    def close(self) -> None:
        self._closing.set()
        if isinstance(self.stream, _PipeInput):
            self.stream.stop()
        if self._thread is not None:
            self._thread.join(timeout=1)

    def _read(self) -> None:
        while not self._event.is_set() and not self._closing.is_set():
            try:
                line = self.stream.readline(4097)
            except (OSError, ValueError):
                line = b""
            if self._closing.is_set():
                return
            if not line or len(line) > 4096:
                self.set("cancel")
                return
            try:
                value = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if isinstance(value, dict):
                self.set(str(value.get("command", "")))

    def set(self, command: str) -> None:
        if command in {"finish", "cancel"} and not self._event.is_set():
            self.command = command
            self._event.set()

    async def wait(self) -> None:
        deadline = time.monotonic() + self.timeout
        while not self._event.is_set():
            if time.monotonic() >= deadline:
                raise TimeoutError("登录态捕获等待超时，未保存凭据")
            await asyncio.sleep(0.1)
        if self.command == "cancel":
            raise CaptureCancelled("已取消登录态捕获，未保存凭据")


def _overlay(request: dict[str, Any]):
    from apps.cli import _cache_policy
    from config.overlay import Overlay

    return Overlay(
        path=Path(request["overlay_path"]) if request.get("overlay_path") else None,
        accounts_path=Path(request["config_path"]) if request.get("config_path") else None,
        policy=_cache_policy(),
    ).load()


def _account_request(request: dict[str, Any]):
    from gui.core import account_payload, selected_task_ids, validate_payload

    raw = request.get("account")
    if not isinstance(raw, dict):
        raise ValueError("请求缺少账号草稿")
    path = Path(request["config_path"]) if request.get("config_path") else None
    selected = tuple(selected_task_ids(raw, request.get("only_tasks") or (), path=path, context=request))
    document = validate_payload(account_payload(raw, request), path=path)
    return document.accounts[0], selected


def _run(request: dict[str, Any], redactor: Redactor) -> dict[str, Any]:
    from apps import cli
    from config.schema import oauth_state_text
    from config.proxies import parse_groups
    from core.timebase import utc_now

    spec, selected = _account_request(request)
    overlay = _overlay(request)
    oauth_states = request.get("oauth_states") or {}
    environ_proxy = request.get("environ_proxy", os.environ.get("CHECKIN_PROXY", ""))
    redactor._collect({"environ_proxy": environ_proxy})
    redactor.credentials(spec.credentials)
    redactor.credentials(overlay.apply(spec, explicit=tuple(request.get("explicit") or ())).credentials)

    def raise_account_error(_spec, outcome):
        # CLI 的旧兜底会虚构 daily 记录。在独占子进程中替换此兜底，不改公共引擎。
        raise RuntimeError(outcome.message or "账号执行失败，未生成任务结果")

    original = cli._single
    cli._single = raise_account_error
    try:
        run = cli.run_account_sync(
            spec, overlay=overlay, explicit=tuple(request.get("explicit") or ()),
            only_tasks=selected,
            oauth_state=lambda provider, account: oauth_state_text(oauth_states, provider, account),
            proxy_groups=parse_groups(request.get("proxy_groups")),
            default_proxy_group=request.get("default_proxy_group", ""),
            environ_proxy=environ_proxy,
            structured=True,
        )
    finally:
        cli._single = original
    payload = run.to_payload()
    # 快速连续运行也能区分新旧返回；不要让秒精度导致界面沿用上一轮文本。
    payload["generated_at"] = utc_now().isoformat(timespec="microseconds").replace("+00:00", "Z")
    return redactor.data(safe_data(payload))


def _explain(request: dict[str, Any], redactor: Redactor) -> dict[str, Any]:
    from core.flow import FlowPlan
    from runtime import capabilities, engine
    from templates import registry

    spec, selected = _account_request(request)
    overlay = _overlay(request)
    explicit = tuple(request.get("explicit") or ())
    account = overlay.apply(spec, explicit=explicit)
    redactor.credentials(spec.credentials)
    redactor.credentials(account.credentials)
    caps = capabilities.detect(account)
    from gui.core import proxy_status

    payload = {"account_id": spec.id, "capabilities": sorted(caps),
               "network": proxy_status(request["account"].get("network"), request,
                                       environ_proxy=request.get("environ_proxy")),
               "overlay": overlay.explain(spec, explicit=explicit), "tasks": []}
    tasks = {task.id: task for task in spec.tasks}
    for task_id in selected:
        task = tasks[task_id]
        reference = spec.task_template(task)
        entry: dict[str, Any] = {"task_id": task.id, "template": reference}
        if reference.lower() == "auto":
            entry.update(flow=None, describe="auto 模板将在运行时只读探测；当前不预设执行路径", runtime_detection=True)
        else:
            try:
                template = registry.get(reference)
                plan = FlowPlan.resolve(
                    configured=engine._flow_config(spec, task),
                    template=template.manifest, learned=account.learned_flow,
                    capabilities=caps, failure_streak=int(account.health.get("failure_streak", 0) or 0),
                )
                entry.update(flow=plan.to_payload(), describe=plan.describe())
                if task.chain is not None:
                    chain = engine.explain_chain(task, template, caps, account)
                    entry.update(chain=chain, describe="访问链：" + chain["describe"])
            except Exception as exc:
                entry["error"] = str(exc)
        payload["tasks"].append(entry)
    return redactor.data(safe_data(payload))


def _arg_payload(arg) -> dict[str, Any]:
    secret = arg.secret or is_sensitive_key(arg.name)
    return {
        "name": arg.name, "type": arg.kind, "title": arg.title or arg.name,
        "help": arg.help, "secret": secret, "required": arg.required,
        "default": None if secret else safe_data(arg.default), "env": arg.env,
        "choices": [] if secret else safe_data(list(arg.choices)),
        "minimum": arg.minimum, "maximum": arg.maximum,
    }


def _option_payload(option) -> dict[str, Any]:
    return {
        "method": option.method, "title": option.title or option.method,
        "args": [_arg_payload(arg) for arg in option.args],
        "requires": sorted(option.requires), "owns": sorted(getattr(option, "owns", ())),
    }


def _chain_step_payload(step) -> dict[str, Any]:
    """模板默认访问链的一步：只含结构，步骤参数值可能敏感，一律不带。"""
    from core.chain import step_payload

    payload = step_payload(step)
    payload.pop("args", None)
    payload["title"] = step.label
    return payload


def _templates() -> dict[str, Any]:
    from templates import registry

    references = set(registry.ids())
    for path in (registry.REPO_ROOT / "scripts" / "tasks").glob("*.py"):
        if not path.name.startswith("_") and path.is_file():
            references.add(path.relative_to(registry.REPO_ROOT).as_posix())
    items = []
    for reference in sorted(references):
        item: dict[str, Any] = {"reference": reference}
        try:
            loaded = registry.get(reference)
            manifest = loaded.manifest
            login_options = [_option_payload(option) for option in manifest.login]
            task_options = [_option_payload(option) for option in manifest.task]
            item.update(
                title=manifest.title or manifest.id, description=manifest.description,
                source=loaded.source,
                login_methods=[option.method for option in manifest.login],
                task_methods=[option.method for option in manifest.task],
                args=[_arg_payload(arg) for arg in manifest.args],
                login_options=login_options, task_options=task_options,
                login_args={option["method"]: option["args"] for option in login_options},
                task_args={option["method"]: option["args"] for option in task_options},
                chain=[_chain_step_payload(step) for step in manifest.chain],
            )
        except Exception as exc:
            item["error"] = mask_secrets(str(exc))
        items.append(item)
    return {"templates": items}


async def _capture(request: dict[str, Any], control: CaptureControl) -> dict[str, Any]:
    from browser import session, storage_scope
    from browser.service import BrowserService, STATE_EXPORT_TIMEOUT, encode_state
    from runtime.events import emit

    if control.command == "cancel":
        raise CaptureCancelled("已取消登录态捕获，未保存凭据")
    redactor = Redactor(request)

    def log(message):
        emit("capture", redactor.text(message))

    from config.proxies import network_from_payload, resolve_proxy, validate_proxy_config
    from gui.core import proxy_context

    target = request.get("target")
    account = request.get("account") or {}
    network = request.get("network", {}) if target == "oauth" else account.get("network", {})
    if request.get("proxy"):
        network = {"proxy": request["proxy"]}
    groups, default = validate_proxy_config({**proxy_context(request), "accounts": [{"network": network}]})
    environ_proxy = request.get("environ_proxy", os.environ.get("CHECKIN_PROXY", ""))
    redactor._collect({"environ_proxy": environ_proxy})
    selection = resolve_proxy(network_from_payload(network), groups, default, environ_proxy=environ_proxy)
    log(selection.description)
    if target == "oauth":
        provider = str(request.get("provider") or "").strip()
        if not provider:
            raise ValueError("OAuth 捕获必须明确指定 provider")
        from browser.oauth_providers import KNOWN_OAUTH_PROVIDERS

        provider = provider.lower()
        if provider not in KNOWN_OAUTH_PROVIDERS:
            raise ValueError("不支持的 OAuth provider")
        result = await session.capture_oauth_state(
            oauth_provider=provider, proxy=selection.url,
            log=log, wait_for_close=control.wait,
        )
        if control.command == "cancel":
            raise CaptureCancelled("已取消登录态捕获，未保存凭据")
        return result
    if target != "site":
        raise ValueError("capture.target 必须是 site 或 oauth")
    account = request.get("account") or {}
    base_url = str(account.get("base_url") or "").strip()
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("站点捕获需要有效的 http(s) base_url")
    service = BrowserService(base_url=base_url, proxy=selection.url, headless=False, log=log)
    try:
        async with service.lease(reason="人工捕获，未验证登录") as lease:
            await lease.new_page()
            await lease.goto()
            log("请人工登录后点击完成捕获；捕获不等于验证，不会执行任何任务")
            await control.wait()
            state = await asyncio.wait_for(lease.context.storage_state(), timeout=STATE_EXPORT_TIMEOUT)
            # storage_state 本体保留完整浏览器态；独立 HTTP 凭据严格限定本站来源。
            credentials = {"browser_state": encode_state(state)}
            for name, value in (
                ("cookie", storage_scope.site_cookie_string(state.get("cookies", []), base_url)),
                ("access_token", storage_scope.storage_access_token(state, base_url=base_url)),
                ("refresh_token", storage_scope.storage_refresh_token(state, base_url=base_url)),
            ):
                if value:
                    credentials[name] = value
            return {"ok": True, "credentials": credentials, "message": "捕获完成（未验证），请显式纳入草稿"}
    finally:
        await service.aclose()


def execute(
    request: dict[str, Any], *, control: CaptureControl | None = None, redactor: Redactor | None = None,
) -> dict[str, Any]:
    """仅在隔离进程执行；测试可注入本地 stub。"""
    action = request.get("action")
    if action not in ACTIONS:
        raise ValueError("未知后台操作")
    redactor = redactor or Redactor(request)
    if action == "run":
        return _run(request, redactor)
    if action == "explain":
        return _explain(request, redactor)
    if action == "templates":
        return _templates()
    from browser.runtime_loop import run_sync

    return run_sync(_capture(request, control or CaptureControl()))


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    output = sys.stdout
    request: dict[str, Any] = {}
    redactor = Redactor()
    diagnostics = _DiagnosticStream(sys.stderr, redactor)
    code = 0
    control: CaptureControl | None = None
    try:
        stream = _input_stream()
        line = stream.readline(MAX_REQUEST_BYTES + 1)
        if len(line) > MAX_REQUEST_BYTES:
            raise ValueError("后台请求超过大小限制")
        request = json.loads(line)
        if not isinstance(request, dict):
            raise ValueError("后台请求必须是 JSON 对象")
        control = CaptureControl(stream)
        if request.get("action") == "capture":
            control.start()
        redactor._collect(request)
        # 重定向只发生于此独立子进程，绝不会污染 GUI 或其存储线程的 stdout。
        with contextlib.redirect_stdout(diagnostics), contextlib.redirect_stderr(diagnostics):
            result = execute(request, control=control, redactor=redactor)
        if request.get("action") != "capture":
            result = redactor.data(result)
        text = json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    except BaseException as exc:
        code = 1
        text = json.dumps({"error": redactor.text(f"{type(exc).__name__}: {exc}")}, ensure_ascii=False)
    finally:
        if control is not None:
            control.close()
        diagnostics.finish()
    if len(text.encode("utf-8")) > MAX_RESULT_BYTES:
        code = 1
        text = json.dumps({"error": "后台结果超过大小限制"}, ensure_ascii=False)
    output.write(text + "\n")
    output.flush()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
