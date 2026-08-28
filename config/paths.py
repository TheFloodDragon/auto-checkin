"""路径与原子写：所有落盘位置的唯一来源。

锁与原子写是**并发正确性的地基**，不是工具函数：多个签到任务同时做「读整个文件 →
改一条 → 写整个文件」，没有锁就会丢更新；写到一半崩溃而没有原子替换，就会留下一个
谁也读不了的截断文件。这里的实现从旧 ``accounts_store`` 原样迁入（它已经处理了
Windows ``msvcrt.locking`` 与 POSIX ``fcntl`` 的差异、锁超时、以及同线程重入）。
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from ..core.errors import ConfigError

__all__ = [
    "ACCOUNTS_PATH",
    "CACHE_DIR",
    "EVIDENCE_DIR",
    "LEGACY_TOKEN_CACHE_PATH",
    "OVERLAY_PATH",
    "REPO_ROOT",
    "RESULT_PATH",
    "RESULTS_DIR",
    "RESULTS_DIR_NAME",
    "SHARED_STORE_DIR",
    "atomic_write_json",
    "atomic_write_text",
    "file_lock",
    "mtime_iso",
    "read_json",
]

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
RESULTS_DIR_NAME = ".cache-checkin"
CACHE_DIR: Path = REPO_ROOT / RESULTS_DIR_NAME
#: 兼容别名：旧代码里叫 RESULTS_DIR，含义与 CACHE_DIR 相同。
RESULTS_DIR: Path = CACHE_DIR

ACCOUNTS_PATH: Path = REPO_ROOT / "ACCOUNTS.json"
OVERLAY_PATH: Path = CACHE_DIR / "overlay.json"
LEGACY_TOKEN_CACHE_PATH: Path = CACHE_DIR / "token_cache.json"
RESULT_PATH: Path = CACHE_DIR / "checkin_result.json"
SHARED_STORE_DIR: Path = CACHE_DIR / "shared"
EVIDENCE_DIR: Path = CACHE_DIR / "evidence"


# ── 原子写 ──────────────────────────────────────────────────────────────────
def atomic_write_text(path: Path, text: str) -> None:
    """原子写文本（同目录临时文件 + ``os.replace``）。

    写到一半崩溃会留下一个截断且无法解析的文件，之后每一次读都失败。先写同级临时
    文件再 ``os.replace``，保证读者要么看到旧内容、要么看到完整新内容，绝不会看到
    半截。``flush + fsync`` 让字节在改名前真正落盘，断电也能得到有效内容。
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, target)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise


def atomic_write_json(path: Path, payload: Any, *, indent: int = 2) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(Path(path), json.dumps(payload, ensure_ascii=False, indent=indent))


# ── 跨进程文件锁 ────────────────────────────────────────────────────────────
class _LockState:
    """进程内的可重入锁与每线程的持锁簿记。"""

    def __init__(self) -> None:
        self.rlock = threading.RLock()
        self.local = threading.local()


_LOCK_STATE = _LockState()


def _lock_settings() -> tuple[float, int]:
    """锁参数集中在 ``config.FileLockConfig``（可用环境变量覆盖）。"""
    from config import FileLockConfig

    return float(FileLockConfig.DEFAULT_TIMEOUT), int(FileLockConfig.LOCK_SIZE)


@contextmanager
def file_lock(path: Path, *, timeout: float | None = None) -> Iterator[None]:
    """跨平台建议锁，串行化对 ``path`` 的读-改-写。

    **可重入**：同一线程可以嵌套持锁（如 update_* → save）。纯 OS 文件锁在 Windows
    上会自我死锁，因此进程内先用可重入锁串行，只在最外层真正碰 OS 锁，用每线程深度
    计数跟踪。超时拿不到锁就显式失败——绝不在无锁状态继续写，那正是丢更新的成因。
    """
    default_timeout, lock_bytes = _lock_settings()
    if timeout is None:
        timeout = default_timeout
    target = Path(path)

    _LOCK_STATE.rlock.acquire()
    try:
        depth = getattr(_LOCK_STATE.local, "depth", 0)
        _LOCK_STATE.local.depth = depth + 1
        handle = None
        locked = False
        try:
            if depth == 0:
                lock_path = target.parent / (target.name + ".lock")
                target.parent.mkdir(parents=True, exist_ok=True)
                handle = open(lock_path, "a+")  # noqa: SIM115 - 生命周期绑定到本上下文
                locked = _acquire_lock(handle, timeout=timeout, lock_bytes=lock_bytes)
                if not locked:
                    raise ConfigError(f"等待文件锁超时：{lock_path.name}")
            yield
        finally:
            _LOCK_STATE.local.depth = depth
            if depth == 0 and handle is not None:
                if locked:
                    _release_lock(handle, lock_bytes=lock_bytes)
                with contextlib.suppress(OSError):
                    handle.close()
    finally:
        _LOCK_STATE.rlock.release()


def _acquire_lock(handle: Any, *, timeout: float, lock_bytes: int) -> bool:
    """在已打开的句柄上取排他锁；成功返回 True。"""
    deadline = time.monotonic() + timeout
    try:
        import msvcrt  # Windows

        while True:
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, lock_bytes)
                return True
            except OSError:
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.1)
    except ImportError:
        pass

    try:
        import fcntl  # POSIX

        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except OSError:
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.1)
    except ImportError:
        return False


def _release_lock(handle: Any, *, lock_bytes: int) -> None:
    """释放 ``_acquire_lock`` 取得的锁（尽力而为）。"""
    try:
        import msvcrt

        with contextlib.suppress(OSError):
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, lock_bytes)
        return
    except ImportError:
        pass
    try:
        import fcntl

        with contextlib.suppress(OSError):
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except ImportError:
        pass


# ── 读取 ────────────────────────────────────────────────────────────────────
def read_json(path: Path, default: Any = None) -> Any:
    """读 JSON；缺失或损坏返回 default。

    缓存类文件永远不该因为损坏而中断任务：它们都可以重建，最坏结果是多跑一次探测或
    多开一次浏览器。配置类文件的解析失败由调用方另行抛 ConfigError。
    """
    target = Path(path)
    if not target.exists():
        return default
    try:
        return json.loads(target.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return default


def mtime_iso(path: Path) -> str:
    """文件最后修改时间的 UTC ISO 串；文件不存在返回空串。

    覆盖层用它回答「用户在缓存写入之后动过配置文件吗」——这是时间维度判定的锚点，
    旧实现完全没有这个信息，只能靠凭据摘要做二值比较。
    """
    from datetime import datetime, timezone

    try:
        stamp = Path(path).stat().st_mtime
    except OSError:
        return ""
    return (
        datetime.fromtimestamp(stamp, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def ensure_dirs() -> None:
    for directory in (CACHE_DIR, SHARED_STORE_DIR, EVIDENCE_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def relative(path: Path) -> str:
    """仓库内相对路径（正斜杠），用于写进结果与日志。"""
    try:
        return str(Path(path).resolve().relative_to(REPO_ROOT.resolve())).replace(os.sep, "/")
    except (ValueError, OSError):
        return str(path)
