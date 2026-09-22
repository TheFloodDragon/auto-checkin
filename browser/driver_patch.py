#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""修补 Playwright Firefox 驱动对缺失 pageError.location 的空指针崩溃。

问题（实测 playwright 1.61.0 + Camoufox 0.4.11，CI 与本机均可复现）：
Firefox 上报的未捕获页面错误并不总是带 location 字段（例如脚本被 CSP 阻断、
worker/module 内抛错、或错误来自已销毁的 frame）。驱动侧 coreBundle.js 直接读
``pageError.location.url``，于是在 Node 进程里抛出

    TypeError: Cannot read properties of undefined (reading 'url')
        at FFBrowserContext.<anonymous> (.../coreBundle.js:52908:39)

这是**驱动进程整体退出**，不是可捕获的 Python 异常。Python 侧只会看到后续
``Page.goto: Connection closed while reading from the driver``，浏览器流程直接
报废。实测把 AgentRouter 的 OAuth 重登打成 error。

为什么必须补驱动、而不是在 Python 侧兜住：
1. 崩溃发生在 Node 驱动进程，Python 端 try/except 无法拦；
2. 该上报路径由 Firefox 的 ``_onUncaughtError`` 主动触发，与我们是否注册
   ``pageerror`` 监听无关 —— 不监听同样崩；
3. 页面内 ``window.onerror`` 之类的吞错脚本晚于驱动上报，拦不住。

因此在启动浏览器前把 ``pageError.location.X`` 改写为 ``(pageError.location||{}).X``
的安全形式。补丁是幂等的纯文本替换，只在检测到未修补内容时写入。

**写入必须原子**（CI 实测，2026-09-21 run #52）：本项目批量签到是组间并发（最多 8
个子进程同时启动浏览器），每个进程启动前都会调用本模块。旧实现用
``Path.write_text`` 就地改写这个 3.3MB 的共享文件，而 ``write_text`` 先截断再写：

1. 进程 A 截断 coreBundle.js，正在写入 3.3MB；
2. 进程 B 同时启动浏览器，Node 加载到的是**被截断的** coreBundle.js；
3. 驱动进程立刻退出，Python 侧只看到 ``Connection closed while reading from
   the driver`` —— 与「缺 location 崩溃」表现完全一样，极易误判。

时序完全吻合：崩溃只打中一轮里最先启动浏览器的账号（补丁恰在此时首次写入），
且只在部分运行出现（竞态是概率性的）—— run #52 有 4 个账号因此失败，run #50/#49
一个都没有。

修复：写同目录临时文件后 ``os.replace`` 原子改名。读者要么看到完整的旧文件、
要么看到完整的新文件，绝不会看到半截。这是本模块的**关键不变量**；另加一把
best-effort 文件锁只为省掉重复的 3.3MB 写入，拿不到锁也能安全继续 —— 替换是
原子的，且替换内容由输入唯一决定、补丁幂等，并发补同一个文件的结果仍然正确。
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import tempfile
import time
from pathlib import Path

# 只替换这三个字段的读取；它们都在 pageError 上报路径上（tracing 与 dispatcher 各一处）。
_FIELD_DEFAULTS = {
    "url": '""',
    "lineNumber": "0",
    "columnNumber": "0",
}
_UNSAFE_RE = re.compile(r"pageError\.location\.(url|lineNumber|columnNumber)\b")

#: 补丁只是一次几 MB 的文本替换，正常在一秒内完成。锁文件存活超过这个时间，
#: 只可能是持锁进程被强杀（CI 任务超时），必须允许回收，否则后续全被挡住。
_LOCK_STALE_SECONDS = 60.0
_LOCK_TIMEOUT_SECONDS = 30.0


def driver_bundle_path() -> Path | None:
    """返回当前环境 Playwright 驱动的 coreBundle.js 路径；找不到返回 None。"""
    try:
        import playwright
    except Exception:
        return None
    root = Path(playwright.__file__).resolve().parent
    candidate = root / "driver" / "package" / "lib" / "coreBundle.js"
    return candidate if candidate.is_file() else None


class _PatchLock:
    """跨进程独占锁：``O_CREAT|O_EXCL`` 创建锁文件，失败则放弃加锁而非阻断。

    加锁只是避免多个进程重复写同一份 3.3MB 文件；正确性由原子替换保证，
    因此拿不到锁（目录只读、等待超时）时调用方照常继续。
    """

    def __init__(self, path: Path, *, timeout: float = _LOCK_TIMEOUT_SECONDS) -> None:
        self.path = path
        self.timeout = timeout
        self._fd: int | None = None

    def __enter__(self) -> bool:
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return True
            except FileExistsError:
                try:
                    if time.time() - self.path.stat().st_mtime > _LOCK_STALE_SECONDS:
                        self.path.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.05)
            except OSError:
                # 目录不可写等情况：不阻断启动，按未加锁路径继续。
                return False

    def __exit__(self, *_exc: object) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None
        with contextlib.suppress(OSError):
            self.path.unlink(missing_ok=True)


def _read_text(target: Path) -> str | None:
    try:
        return target.read_text(encoding="utf-8")
    except Exception:
        return None


def _atomic_write_text(target: Path, text: str) -> bool:
    """原子替换 ``target`` 的内容；失败时保持原文件不变并返回 False。

    绝不就地截断写入：并发启动的浏览器会加载到半截文件，让 Node 驱动直接退出。
    """
    tmp_path: Path | None = None
    try:
        handle, tmp_name = tempfile.mkstemp(
            dir=str(target.parent), prefix=f".{target.name}.", suffix=".part"
        )
        tmp_path = Path(tmp_name)
        with os.fdopen(handle, "w", encoding="utf-8") as buffer:
            buffer.write(text)
            buffer.flush()
            os.fsync(buffer.fileno())
        # mkstemp 建的是 0600；驱动文件要保持原有权限，否则换用户跑会读不到。
        with contextlib.suppress(OSError):
            shutil.copymode(str(target), str(tmp_path))
        os.replace(str(tmp_path), str(target))
        return True
    except Exception:
        if tmp_path is not None:
            with contextlib.suppress(OSError):
                tmp_path.unlink()
        return False


def _apply(source: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        field = match.group(1)
        # 包一层括号，避免 ``a||b`` 与外层表达式（如三元、逗号）结合出错。
        return f"((pageError.location||{{}}).{field}||{_FIELD_DEFAULTS[field]})"

    return _UNSAFE_RE.sub(_replace, source)


def patch_firefox_page_error(bundle: Path | None = None) -> str:
    """就地修补驱动，返回结果状态。

    返回值：
    - ``"patched"``   ：本次完成修补；
    - ``"already"``   ：此前已修补（或等锁期间被其它进程补完），无需改动；
    - ``"unavailable"``：找不到驱动文件；
    - ``"failed"``    ：读写失败（权限/只读挂载等），调用方不应因此中断流程。
    """
    target = bundle or driver_bundle_path()
    if target is None or not target.is_file():
        return "unavailable"

    # 快路径：已修补就不进临界区，避免每次启动都抢锁。
    source = _read_text(target)
    if source is None:
        return "failed"
    if not _UNSAFE_RE.search(source):
        return "already"

    with _PatchLock(target.parent / f"{target.name}.patchlock"):
        # 等锁期间可能已由其它进程补完，必须重新读取再判断。
        source = _read_text(target)
        if source is None:
            return "failed"
        if not _UNSAFE_RE.search(source):
            return "already"
        return "patched" if _atomic_write_text(target, _apply(source)) else "failed"


__all__ = ["driver_bundle_path", "patch_firefox_page_error"]
