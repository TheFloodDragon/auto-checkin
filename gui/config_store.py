"""GUI 原始 v3 配置：事务式加载、冻结保存、磁盘版本冲突检测。"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from config import paths, settings, store
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
    needs_save: bool = False
    settings_revision: str | None = None


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


def _settings_revision(path: Path) -> str | None:
    """settings 单独保留原始字节摘要，不改变旧账号 revision 的含义。"""
    return _revision(_read_bytes(settings.settings_path())) if store.uses_settings(path) else None


def _settings_snapshot(path: Path) -> tuple[dict, bytes | None]:
    """直接解析同一份字节快照，避免旧节点草稿配上新 settings 版本。"""
    if not store.uses_settings(path):
        return {}, None
    content = _read_bytes(settings.settings_path())
    if content is None:
        raise ConfigError("settings 在加载或保存期间被外部删除，请重新加载")
    try:
        values = settings._parse_payload(content.decode("utf-8-sig"), "settings 配置文件")
    except UnicodeError:
        raise ConfigError("settings 配置文件不是有效的 UTF-8 文本") from None
    return {**settings.default_payload(), **values}, content


def _check_settings_snapshot(path: Path, content: bytes | None) -> None:
    if store.uses_settings(path) and _read_bytes(settings.settings_path()) != content:
        raise ConfigError("settings 在加载或保存期间已被外部修改，请重新加载")


def _effective_payload(
    content: bytes,
    path: Path,
    values: dict,
    *,
    proxy_fields: tuple[str, ...] = (),
) -> dict | list:
    payload = _decode(content)
    if store.uses_settings(path) and isinstance(payload, dict):
        payload = store.merge_settings(payload, values)
        # 显式空节点字段转存后，仍保留在本次保存的完整草稿中。
        for key in proxy_fields:
            payload.setdefault(key, values[key])
    return payload


def load_configuration(path: Path | None = None) -> LoadedConfiguration:
    """加载账号与 settings；草稿与两个 revision 都绑定到同一次字节快照。"""
    target = Path(path or paths.ACCOUNTS_PATH).resolve()
    try:
        if not store.uses_settings(target):
            settings.load()
        with paths.file_lock(store.configuration_lock_path(target)):
            content = _read_bytes(target)
            if content is None:
                source = {"version": 3, "accounts": [], "oauth_states": {}}
                store.load_settings(source, target)
                values, settings_content = _settings_snapshot(target)
                payload = store.merge_settings(source, values)
                core.validate_payload(payload, path=target)
                _check_settings_snapshot(target, settings_content)
                return LoadedConfiguration(
                    payload,
                    target,
                    None,
                    needs_save=True,
                    settings_revision=_revision(settings_content),
                )
            source, notes, migrated = core._prepare_document(_decode(content))
            # 启动初始化之后，以原始字节重新读取，不能给旧值配上更新后的摘要。
            store.load_settings(source, target)
            values, settings_content = _settings_snapshot(target)
            payload = store.merge_settings(source, values)
            core.validate_payload(payload, path=target)
            revision = _revision(content)
            proxy_fields = tuple(key for key in ("proxy_groups", "default_proxy_group") if key in payload)
            if migrated:
                if _revision(_read_bytes(target)) != revision:
                    raise ConfigError("配置已被外部修改，请重新加载后再迁移")
                _check_settings_snapshot(target, settings_content)
                if store.backup(target) is None:
                    raise ConfigError("旧配置备份失败，迁移已取消，原文件未覆盖")
                store.save_configuration(payload, target)
                written = _read_bytes(target)
                if written is None:
                    raise ConfigError("迁移期间配置已被外部删除，请重新加载")
                values, settings_content = _settings_snapshot(target)
                saved = _effective_payload(written, target, values, proxy_fields=proxy_fields)
                if core.fingerprint(saved) != core.fingerprint(payload):
                    raise ConfigError("迁移期间配置已被外部修改，请重新加载")
                content = written
            original = _effective_payload(content, target, values, proxy_fields=proxy_fields)
            needs_save = core.fingerprint(original) != core.fingerprint(payload)
            if _read_bytes(target) != content:
                raise ConfigError("配置在加载期间已被外部修改，请重新加载")
            _check_settings_snapshot(target, settings_content)
            return LoadedConfiguration(
                payload,
                target,
                _revision(content),
                notes,
                needs_save=needs_save,
                settings_revision=_revision(settings_content),
            )
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
    expected_settings_revision: str | None = None

    @property
    def payload(self) -> dict:
        return json.loads(self._json)

    def persist(self) -> LoadedConfiguration:
        """锁内比较两份配置的实际字节版本；冲突时不覆盖，也不清理运行期缓存。"""
        payload = self.payload
        try:
            with paths.file_lock(store.configuration_lock_path(self.path)):
                if (
                    _revision(_read_bytes(self.path)) != self.expected_revision
                    or _settings_revision(self.path) != self.expected_settings_revision
                ):
                    raise ConfigError("配置已被外部修改（或创建/删除），请重新加载并合并后再保存")
                try:
                    store.save_configuration(payload, self.path)
                except ConfigError:
                    raise ConfigError("配置保存校验失败，请检查 credentials.cookie_file 及配置字段") from None
                written = _read_bytes(self.path)
                if written is None:
                    raise ConfigError("保存后配置文件已被外部删除，请重新加载")
                values, settings_content = _settings_snapshot(self.path)
                proxy_fields = tuple(key for key in ("proxy_groups", "default_proxy_group") if key in payload)
                saved = _effective_payload(written, self.path, values, proxy_fields=proxy_fields)
                if core.fingerprint(saved) != self.snapshot or _read_bytes(self.path) != written:
                    raise ConfigError("保存期间配置已被外部修改，请重新加载确认")
                _check_settings_snapshot(self.path, settings_content)
                return LoadedConfiguration(
                    saved,
                    self.path,
                    _revision(written),
                    settings_revision=_revision(settings_content),
                )
        except OSError:
            raise ConfigError("配置原子保存失败，请检查文件权限或磁盘空间") from None


def build_save_request(
    payload: dict,
    *,
    path: Path | None = None,
    expected_revision: str | None,
    expected_settings_revision: str | None = None,
) -> SaveRequest:
    """主线程冻结全部 JSON 后再验证；旧调用者未传 settings 版本时在此捕获。"""
    target = Path(path or paths.ACCOUNTS_PATH).resolve()
    # 先检查 JSON 类型，避免 dumps 把非字符串键/tuple 转换为另一份配置。
    core.fingerprint(payload)
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    frozen = json.loads(encoded)
    core.validate_payload(frozen, path=target)
    settings_revision = _settings_revision(target) if expected_settings_revision is None else expected_settings_revision
    return SaveRequest(encoded, target, expected_revision, core.fingerprint(frozen), settings_revision)
