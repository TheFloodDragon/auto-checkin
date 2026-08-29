"""脚本缓存与学习数据。

取代旧实现里各脚本自己往 ``.cache-checkin/`` 写散落文件的做法
（``play_quiz_unknown.json``、``login_grant_state.json`` …各写各的读写与错误处理）。

两个作用域：

- **账号级**（默认）：进覆盖层的 ``learning`` 段，跟着账号走，随账号一起被
  「配置改了就失效」的规则管理；
- **共享级**（``ctx.store.shared()``）：跨账号复用的知识，如每日答题题库、
  验证码方言——它们与具体账号无关，存 ``.cache-checkin/shared/<命名空间>.json``。

统一保证：原子写 + 文件锁、体积上限、写入前脱敏、损坏文件按空处理不阻断任务。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from config import paths
from config.overlay import LEARNING_VALUE_MAX_BYTES, Overlay

__all__ = ["Store", "SharedStore"]

_SAFE_NAME = re.compile(r"[^\w.\-]+")


class SharedStore:
    """跨账号共享的键值存储，按命名空间分文件。"""

    __slots__ = ("namespace", "_path", "_log")

    def __init__(self, namespace: str, *, log: Any = None) -> None:
        self.namespace = _SAFE_NAME.sub("_", str(namespace or "shared")).strip("._") or "shared"
        self._path = paths.SHARED_STORE_DIR / f"{self.namespace}.json"
        self._log = log

    def get(self, key: str, default: Any = None) -> Any:
        document = paths.read_json(self._path, default={}) or {}
        value = document.get(str(key)) if isinstance(document, dict) else None
        return default if value is None else value

    def put(self, key: str, value: Any) -> bool:
        try:
            encoded = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            self._warn(f"共享缓存 {self.namespace}.{key} 的值无法序列化，已跳过")
            return False
        if len(encoded.encode("utf-8")) > LEARNING_VALUE_MAX_BYTES:
            self._warn(
                f"共享缓存 {self.namespace}.{key} 超过 {LEARNING_VALUE_MAX_BYTES // 1024} KiB 上限，已拒绝写入"
                "（静默截断会让下次读到半截数据，比拿不到更糟）"
            )
            return False
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with paths.file_lock(self._path):
                document = paths.read_json(self._path, default={}) or {}
                if not isinstance(document, dict):
                    document = {}
                document[str(key)] = json.loads(encoded)
                paths.atomic_write_json(self._path, document)
        except Exception:
            return False
        return True

    def _warn(self, message: str) -> None:
        if callable(self._log):
            self._log(message)


class Store:
    """账号级键值存储；``shared()`` 切到跨账号命名空间。"""

    __slots__ = ("account_id", "namespace", "_overlay", "_log")

    def __init__(
        self,
        account_id: str,
        *,
        overlay: Overlay,
        namespace: str = "",
        log: Any = None,
    ) -> None:
        self.account_id = str(account_id)
        self.namespace = str(namespace or "")
        self._overlay = overlay
        self._log = log

    def _key(self, key: str) -> str:
        return f"{self.namespace}.{key}" if self.namespace else str(key)

    def get(self, key: str, default: Any = None) -> Any:
        return self._overlay.get_learning(self.account_id, self._key(key), default)

    def put(self, key: str, value: Any) -> bool:
        ok = self._overlay.put_learning(self.account_id, self._key(key), value)
        if not ok and callable(self._log):
            self._log(
                f"学习数据 {self._key(key)} 写入失败（多半是超过 "
                f"{LEARNING_VALUE_MAX_BYTES // 1024} KiB 上限或无法序列化）"
            )
        return ok

    def shared(self, namespace: str = "") -> SharedStore:
        return SharedStore(namespace or self.namespace or "shared", log=self._log)

    def scoped(self, namespace: str) -> "Store":
        return Store(self.account_id, overlay=self._overlay, namespace=namespace, log=self._log)

    def evidence_dir(self) -> Path:
        directory = paths.EVIDENCE_DIR / (_SAFE_NAME.sub("_", self.account_id) or "account")
        directory.mkdir(parents=True, exist_ok=True)
        return directory
