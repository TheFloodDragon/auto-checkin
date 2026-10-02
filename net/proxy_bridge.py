"""本地 mihomo 代理桥：把 vless / anytls 等出站转换成回环地址上的带认证 HTTP 代理。

标准库 urllib 与 Camoufox 只认识 http / https / socks5。这里为一次账号执行启动一个
**只含一个出站**的 mihomo 进程：

- 只监听 127.0.0.1，随机端口 + 每次随机生成的认证，``skip-auth-prefixes`` 显式为空，
  同机其它进程不能蹭用；
- 规则只有 ``MATCH``，不加载 GeoIP / GeoSite，不开放控制器，不记忆选择；
- 配置文件含节点凭据，放在独立临时目录（权限 0600），关闭即删除；
- 校验或启动失败只给固定文案和 mihomo 的错误类别，绝不回显配置或原始日志；
- 父进程意外退出时由 Job Object（Windows）/ PR_SET_PDEATHSIG（Linux）回收子进程。
"""

from __future__ import annotations

import atexit
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import weakref
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import quote

from core.errors import ConfigError, TransientError

__all__ = [
    "ENV_BINARY",
    "NODE_NAME",
    "ProxyBridge",
    "build_bridge_config",
    "find_mihomo",
    "mihomo_status",
    "require_mihomo",
]

ENV_BINARY = "CHECKIN_MIHOMO"
NODE_NAME = "bridge-node"
LISTEN_TIMEOUT = 15.0
VALIDATE_TIMEOUT = 30.0
STOP_TIMEOUT = 3.0
START_ATTEMPTS = 3
_CANDIDATE_NAMES = ("mihomo", "verge-mihomo", "mihomo-meta", "clash-meta")
_ERROR_CATEGORY = re.compile(r"proxy \d+: ([A-Za-z][A-Za-z0-9 _.-]{2,80})")
_CREATE_NO_WINDOW = 0x08000000

LogFn = Callable[[str], None]


# ── 发现 ────────────────────────────────────────────────────────────────────
def _executable(path: Path) -> bool:
    try:
        return path.is_file() and (os.name == "nt" or os.access(path, os.X_OK))
    except OSError:
        return False


def _platform_candidates(environ: Mapping[str, str]) -> list[Path]:
    paths: list[Path] = []
    if os.name == "nt":
        for base in (environ.get("ProgramFiles"), environ.get("ProgramW6432"), environ.get("ProgramFiles(x86)")):
            if base:
                paths.append(Path(base) / "Clash Verge" / "verge-mihomo.exe")
        local = environ.get("LOCALAPPDATA")
        if local:
            paths.append(Path(local) / "Programs" / "Clash Verge" / "verge-mihomo.exe")
            paths.append(Path(local) / "Clash Verge" / "verge-mihomo.exe")
    else:
        paths.extend(Path(item) for item in (
            "/usr/local/bin/mihomo", "/usr/bin/mihomo", "/opt/homebrew/bin/mihomo",
            "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo",
        ))
    runner = environ.get("RUNNER_TEMP")
    if runner:
        paths.append(Path(runner) / "mihomo" / ("mihomo.exe" if os.name == "nt" else "mihomo"))
    return paths


def find_mihomo(environ: Mapping[str, str] | None = None) -> str | None:
    """按 CHECKIN_MIHOMO → PATH → 常见安装位置 → CI 下载位置查找；找不到返回 None。"""
    env = os.environ if environ is None else environ
    explicit = str(env.get(ENV_BINARY) or "").strip()
    if explicit:
        path = Path(explicit)
        return str(path) if _executable(path) else None
    search_path = env.get("PATH")
    for name in _CANDIDATE_NAMES:
        found = shutil.which(name, path=search_path)
        if found:
            return found
    for path in _platform_candidates(env):
        if _executable(path):
            return str(path)
    return None


def require_mihomo(environ: Mapping[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    found = find_mihomo(env)
    if found:
        return found
    if str(env.get(ENV_BINARY) or "").strip():
        raise ConfigError(f"{ENV_BINARY} 指向的 mihomo 不存在或不可执行；该节点需要本地代理桥，不会改用直连")
    raise ConfigError(f"该节点需要 mihomo 代理桥：请安装 mihomo（或 Clash Verge）或设置 {ENV_BINARY}；不会改用直连")


def mihomo_status(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """供界面展示：只给是否找到和文件名，不给完整路径之外的任何信息。"""
    found = find_mihomo(environ)
    return {"available": bool(found), "name": Path(found).name if found else ""}


# ── 配置 ────────────────────────────────────────────────────────────────────
def build_bridge_config(outbound: Mapping[str, Any], *, port: int, username: str, password: str) -> dict[str, Any]:
    """纯函数：生成单出站 mihomo 配置。outbound 应已通过 parse_bridge_outbound 校验。"""
    if not isinstance(outbound, Mapping) or not outbound.get("type") or not outbound.get("server"):
        raise ConfigError("代理桥节点配置无效")
    proxy = {key: value for key, value in json.loads(json.dumps(dict(outbound))).items() if key != "name"}
    proxy = {"name": NODE_NAME, **proxy}
    server = str(proxy.get("server") or "")
    return {
        "mixed-port": int(port),
        "bind-address": "127.0.0.1",
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        # 只有服务器本身是 IPv6 字面量时才开启；CI 出站没有 IPv6，默认开启会拖慢每次拨号。
        "ipv6": ":" in server,
        "external-controller": "",
        "find-process-mode": "off",
        "geo-auto-update": False,
        "profile": {"store-selected": False, "store-fake-ip": False},
        "authentication": [f"{username}:{password}"],
        "skip-auth-prefixes": [],
        "proxies": [proxy],
        "rules": [f"MATCH,{NODE_NAME}"],
    }


# ── 孤儿进程防护 ────────────────────────────────────────────────────────────
_JOB_LOCK = threading.Lock()
_JOB: Any = None
_PRCTL: Any = None


def _windows_job() -> Any:
    """进程级 Job Object：本进程退出时句柄关闭，系统随即结束所有桥进程。"""
    global _JOB
    with _JOB_LOCK:
        if _JOB is not None:
            return _JOB or None
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            class IoCounters(ctypes.Structure):
                _fields_ = [(name, ctypes.c_ulonglong) for name in (
                    "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                    "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

            class Basic(ctypes.Structure):
                _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                            ("PerJobUserTimeLimit", ctypes.c_longlong),
                            ("LimitFlags", wintypes.DWORD),
                            ("MinimumWorkingSetSize", ctypes.c_size_t),
                            ("MaximumWorkingSetSize", ctypes.c_size_t),
                            ("ActiveProcessLimit", wintypes.DWORD),
                            ("Affinity", ctypes.c_size_t),
                            ("PriorityClass", wintypes.DWORD),
                            ("SchedulingClass", wintypes.DWORD)]

            class Extended(ctypes.Structure):
                _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", IoCounters),
                            ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                            ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                raise OSError("CreateJobObjectW")
            info = Extended()
            info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise OSError("SetInformationJobObject")
            _JOB = (kernel32, job)
        except Exception:  # noqa: BLE001 - 尽力而为；失败时仍有 atexit 与显式关闭
            _JOB = False
        return _JOB or None


def _assign_job(process: subprocess.Popen) -> None:
    job = _windows_job()
    handle = getattr(process, "_handle", None)
    if job and handle:
        try:
            job[0].AssignProcessToJobObject(job[1], int(handle))
        except Exception:  # noqa: BLE001
            pass


def _linux_preexec() -> Callable[[], None] | None:
    global _PRCTL
    if not sys.platform.startswith("linux"):
        return None
    if _PRCTL is None:
        try:
            import ctypes

            _PRCTL = ctypes.CDLL(None, use_errno=True).prctl
        except Exception:  # noqa: BLE001
            _PRCTL = False
    if not _PRCTL:
        return None
    prctl = _PRCTL

    def preexec() -> None:
        prctl(1, 9)  # PR_SET_PDEATHSIG, SIGKILL

    return preexec


_LIVE: "weakref.WeakSet[ProxyBridge]" = weakref.WeakSet()


@atexit.register
def _close_all() -> None:  # pragma: no cover - 进程退出兜底
    for bridge in list(_LIVE):
        try:
            bridge.close()
        except Exception:  # noqa: BLE001
            pass


# ── 进程 ────────────────────────────────────────────────────────────────────
def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def _popen_kwargs() -> dict[str, Any]:
    kwargs: dict[str, Any] = {"stdin": subprocess.DEVNULL}
    if os.name == "nt":
        kwargs["creationflags"] = _CREATE_NO_WINDOW
    else:
        preexec = _linux_preexec()
        if preexec is not None:
            kwargs["preexec_fn"] = preexec
    return kwargs


def _private_write(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _error_category(output: str) -> str:
    """只取 ``proxy N: <英文错误类别>``；该类别由 mihomo 固定生成，不含字段值。"""
    match = _ERROR_CATEGORY.search(output or "")
    return match.group(1).strip() if match else ""


class ProxyBridge:
    """一次执行用的单节点桥。``start()`` 返回本地代理 URL，``close()`` 幂等。"""

    def __init__(
        self,
        outbound: Mapping[str, Any],
        *,
        binary: str | None = None,
        listen_timeout: float = LISTEN_TIMEOUT,
        log: LogFn | None = None,
    ) -> None:
        self._outbound = json.loads(json.dumps(dict(outbound)))
        self._binary = binary
        self._listen_timeout = float(listen_timeout)
        self._log = log
        self._username = "bridge-" + secrets.token_hex(4)
        self._password = secrets.token_urlsafe(18)
        self._workdir: Path | None = None
        self._process: subprocess.Popen | None = None
        self._log_handle: Any = None
        self._lock = threading.Lock()
        self.port: int | None = None
        self.url: str = ""

    def __repr__(self) -> str:
        return f"ProxyBridge(type={self._outbound.get('type')!r}, port={self.port!r})"

    @property
    def secrets(self) -> tuple[str, ...]:
        return (self._username, self._password)

    def __enter__(self) -> str:
        return self.start()

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def _emit(self, message: str) -> None:
        if self._log is not None:
            try:
                self._log(message)
            except Exception:  # noqa: BLE001
                pass

    def _config_text(self, port: int) -> str:
        config = build_bridge_config(self._outbound, port=port, username=self._username, password=self._password)
        # JSON 是 YAML 的子集，mihomo 可直接读取；避免运行时依赖 PyYAML 的序列化细节。
        return json.dumps(config, ensure_ascii=False, indent=1)

    def _validate(self, binary: str, config: Path) -> None:
        assert self._workdir is not None
        try:
            completed = subprocess.run(
                [binary, "-t", "-d", str(self._workdir), "-f", str(config)],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=VALIDATE_TIMEOUT, **_popen_kwargs(),
            )
        except subprocess.TimeoutExpired:
            raise TransientError("代理桥配置校验超时") from None
        except OSError:
            raise ConfigError("无法运行 mihomo；请检查 CHECKIN_MIHOMO 或安装位置") from None
        if completed.returncode != 0:
            category = _error_category(completed.stdout + "\n" + completed.stderr)
            detail = f"（{category}）" if category else ""
            raise ConfigError(f"代理桥配置校验未通过{detail}；请检查节点参数或升级 mihomo，不会改用直连")

    def start(self) -> str:
        with self._lock:
            if self.url:
                return self.url
            binary = self._binary or require_mihomo()
            self._workdir = Path(tempfile.mkdtemp(prefix="checkin-bridge-"))
            _LIVE.add(self)
            try:
                return self._start_locked(binary)
            except BaseException:
                self._shutdown_locked(report=False)
                raise

    def _start_locked(self, binary: str) -> str:
        assert self._workdir is not None
        config = self._workdir / "config.yaml"
        last_error = "mihomo 提前退出"
        for attempt in range(START_ATTEMPTS):
            port = _free_port()
            _private_write(config, self._config_text(port))
            if attempt == 0:
                self._validate(binary, config)
            self._log_handle = open(self._workdir / "mihomo.log", "wb")
            try:
                self._process = subprocess.Popen(
                    [binary, "-d", str(self._workdir), "-f", str(config)],
                    stdout=self._log_handle, stderr=subprocess.STDOUT, **_popen_kwargs(),
                )
            except OSError:
                raise ConfigError("无法启动 mihomo；请检查 CHECKIN_MIHOMO 或安装位置") from None
            if os.name == "nt":
                _assign_job(self._process)
            deadline = time.monotonic() + self._listen_timeout
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    break
                if _listening(port):
                    self.port = port
                    auth = quote(self._username, safe="") + ":" + quote(self._password, safe="")
                    self.url = f"http://{auth}@127.0.0.1:{port}"
                    self._emit(f"代理桥已就绪：127.0.0.1:{port}（{self._outbound.get('type')}，仅本机）")
                    return self.url
                time.sleep(0.1)
            if self._process.poll() is None:
                self._stop_process()
                raise TransientError(f"代理桥未在 {self._listen_timeout:.0f}s 内就绪；不会改用直连")
            # 进程提前退出：多半是端口在探测与绑定之间被占用，换端口重试。
            self._stop_process()
            last_error = "mihomo 在本地端口就绪前退出"
        raise TransientError(f"代理桥启动失败（{last_error}，已重试 {START_ATTEMPTS} 次）；不会改用直连")

    def _stop_process(self) -> None:
        process, self._process = self._process, None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    pass
        handle, self._log_handle = self._log_handle, None
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass

    def _dial_failures(self) -> int:
        if self._workdir is None:
            return 0
        try:
            text = (self._workdir / "mihomo.log").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return 0
        return sum(
            1 for line in text.splitlines()
            if "dial" in line.lower() and ("error" in line.lower() or "fail" in line.lower())
        )

    def _shutdown_locked(self, *, report: bool) -> None:
        self._stop_process()
        if report and self.url:
            failures = self._dial_failures()
            if failures:
                # 原始日志含目标主机与节点信息，只输出计数。
                self._emit(f"代理桥：本次运行中上游连接失败 {failures} 次（未输出 mihomo 原始日志）")
        workdir, self._workdir = self._workdir, None
        if workdir is not None:
            for _ in range(10):
                shutil.rmtree(workdir, ignore_errors=True)
                if not workdir.exists():
                    break
                time.sleep(0.2)
        self.url = ""
        self.port = None
        _LIVE.discard(self)

    def close(self) -> None:
        with self._lock:
            self._shutdown_locked(report=True)
