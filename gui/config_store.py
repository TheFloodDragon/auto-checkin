"""GUI 原始 v3 配置：事务式加载、冻结保存、磁盘版本冲突检测。"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from config import paths, store
from core.errors import ConfigError

from . import core

__all__ = ["LoadedConfiguration", "SaveRequest", "build_save_request", "load_configuration"]


@dataclass(frozen=True)
class LoadedConfiguration:
    """完整加载成功后才替换表单；payload 是独立、可编辑的原始草稿。"""

    payload: dict = field(repr=False)
    path: Path
    revision: str | None
    notes: tuple[str, ...] = ()


def _read_bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError:
        raise ConfigError("配置文件读取失败，请检查路径及文件访问权限") from None


def _revision(content: bytes | None) -> str | None:
    return hashlib.sha256(content).hexdigest() if content is not None else None


def _decode(content: bytes) -> dict | list:
    try:
        return core._decode_json(content.decode("utf-8-sig"))
    except UnicodeError:
        raise ConfigError("配置文件不是有效的 UTF-8 文本") from None


def load_configuration(path: Path | None = None) -> LoadedConfiguration:
    """缺失允许空白 onboarding；损坏、迁移/备份失败一律报错，不覆盖原文件。"""
    target = Path(path or paths.ACCOUNTS_PATH).resolve()
    try:
        with paths.file_lock(target):
            content = _read_bytes(target)
            if content is None:
                return LoadedConfiguration({"version": 3, "accounts": [], "oauth_states": {}}, target, None)
            payload, notes, migrated = core._prepare_document(_decode(content))
            core.validate_payload(payload, path=target)
            if migrated:
                # 必须先完整校验，再备份/写盘；现有迁移器不能静默跳过坏账号。
                if _read_bytes(target) != content:
                    raise ConfigError("配置已被外部修改，请重新加载后再迁移")
                if store.backup(target) is None:
                    raise ConfigError("旧配置备份失败，迁移已取消，原文件未覆盖")
                store.save_payload(payload, target)
                written = _read_bytes(target)
                if written is None or core.fingerprint(_decode(written)) != core.fingerprint(payload):
                    raise ConfigError("迁移期间配置已被外部修改，请重新加载")
                content = written
            return LoadedConfiguration(payload, target, _revision(content), notes)
    except OSError:
        raise ConfigError("配置加载或迁移失败，请检查文件权限；当前表单未变更") from None


@dataclass(frozen=True, slots=True)
class SaveRequest:
    """真正冻结的保存请求：仅保存不可变 JSON 文本，repr 不包含凭据。

    payload 每次返回独立副本；修改副本不会改变排队中或正在执行的保存请求。
    snapshot 是摘要，可用于表单脏状态比较。
    """

    _json: str = field(repr=False)
    path: Path
    expected_revision: str | None
    snapshot: str

    @property
    def payload(self) -> dict:
        return json.loads(self._json)

    def persist(self) -> LoadedConfiguration:
        """锁内比较实际磁盘字节版本；冲突时绝不覆盖，也不清理运行期缓存。"""
        payload = self.payload
        try:
            with paths.file_lock(self.path):
                if _revision(_read_bytes(self.path)) != self.expected_revision:
                    raise ConfigError("配置已被外部修改（或创建/删除），请重新加载并合并后再保存")
                # 公共接口仍做 schema 校验，使用同一可重入文件锁和原子写机制。
                try:
                    store.save_payload(payload, self.path)
                except ConfigError:
                    raise ConfigError("配置保存校验失败，请检查 credentials.cookie_file 及配置字段") from None
                written = _read_bytes(self.path)
                if written is None:
                    raise ConfigError("保存后配置文件已被外部删除，请重新加载")
                saved = _decode(written)
                if core.fingerprint(saved) != self.snapshot:
                    raise ConfigError("保存期间配置已被外部修改，请重新加载确认")
                return LoadedConfiguration(saved, self.path, _revision(written))
        except OSError:
            raise ConfigError("配置原子保存失败，请检查文件权限或磁盘空间") from None


def build_save_request(
    payload: dict, *, path: Path | None = None, expected_revision: str | None,
) -> SaveRequest:
    """主线程冻结全部 JSON 后再验证；保存线程永远不读取表单中的可变对象。"""
    target = Path(path or paths.ACCOUNTS_PATH).resolve()
    # 先检查 JSON 类型，避免 dumps 把非字符串键/tuple 悄悄转换为另一份配置。
    core.fingerprint(payload)
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    frozen = json.loads(encoded)
    core.validate_payload(frozen, path=target)
    return SaveRequest(encoded, target, expected_revision, core.fingerprint(frozen))
