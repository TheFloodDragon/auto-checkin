"""ACCOUNTS.json 的读写。

**运行期只读**是本模块的核心约束：整条执行链路只调用 ``load()``，任何运行中产生的
东西（刷新到的 token、浏览器登录态、探测到的流程、脚本学到的数据）都进覆盖层
（``config/overlay.py``），绝不回写用户维护的配置文件。

理由是旧实现里踩过的：一旦运行链路能写配置，用户的文件就会被后台任务反复改写，
导出的 GitHub Secret 里也会带上很快失效的短期值；而且「用户配的」和「程序回填的」
混在同一个文件里之后，就再也分不清一个值到底是谁写的。

写入只发生在两个地方：GUI 的显式保存，和 CLI 的管理子命令。两者都走 ``save()``。
例外是一次性格式迁移（v1/v2 → v3、旧版本转存到 settings 的代理节点迁回账号配置），
写前先备份原文件。代理组与节点只保存在账号配置中，不写入 settings。
"""

from __future__ import annotations

import contextlib
import json
import time
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from core.errors import ConfigError
from . import migrate as migrate_module
from . import paths, settings
from .secret_codec import decode_secret
from .schema import CONFIG_VERSION, Document, parse_document

__all__ = [
    "backup",
    "delete_oauth_state",
    "is_default_path",
    "load",
    "prepare_settings",
    "readonly",
    "retire_legacy_proxies",
    "save",
    "save_payload",
    "save_oauth_state",
    "with_legacy_proxies",
]

LEGACY_PROXY_MOVED = "旧版保存在 settings 的代理节点已迁回账号配置（已备份原文件）"


def is_default_path(path: Path | None = None) -> bool:
    """只有默认账号配置可能有旧版本转存到 settings 的节点；其他配置文件始终自包含。"""
    return Path(path or paths.ACCOUNTS_PATH).resolve() == paths.ACCOUNTS_PATH.resolve()


def prepare_settings(path: Path | None = None) -> None:
    """启动边界：补齐 settings 与默认模板；不能让全局参数写进账号配置文件。"""
    target = Path(path or paths.ACCOUNTS_PATH)
    if settings.settings_path().resolve() == target.resolve():
        raise ConfigError("settings 配置文件不能与账号配置使用同一路径")
    settings.load()


def with_legacy_proxies(payload: Mapping[str, Any], path: Path | None = None) -> dict[str, Any]:
    """纯合并：账号配置的显式节点（包括空值）优先；缺失时补上旧版本留在 settings 的节点。"""
    merged = deepcopy(dict(payload))
    if "proxy_groups" in payload or not is_default_path(path):
        return merged
    legacy = settings.legacy_proxies()
    if legacy.get("proxy_groups"):
        merged["proxy_groups"] = deepcopy(legacy["proxy_groups"])
        if "default_proxy_group" not in payload and legacy.get("default_proxy_group"):
            merged["default_proxy_group"] = legacy["default_proxy_group"]
    return merged


def retire_legacy_proxies(path: Path | None = None) -> str | None:
    """节点已保存在账号配置后，备份并删除 settings 中的旧节点字段；返回需要提示的说明。"""
    if not is_default_path(path):
        return None
    try:
        backup_path = settings.discard_legacy_proxies()
    except ConfigError:
        return "旧版 settings 中的代理节点字段未能清理，请手动删除 proxy_groups/default_proxy_group"
    if backup_path is None:
        return None
    return f"已从 settings 删除旧版代理节点字段（备份：{backup_path.name}）"


def load(path: Path | None = None, *, auto_migrate: bool = True, overlay: Any = None) -> Document:
    """读取账号配置；必要时迁移到 v3、把旧版留在 settings 的节点迁回账号配置，并重挂旧覆盖层缓存键。"""
    target = Path(path or paths.ACCOUNTS_PATH)
    default = is_default_path(target)
    prepare_settings(target)
    with paths.file_lock(target) if default else contextlib.nullcontext():
        if not target.exists():
            raise ConfigError(f"未找到配置文件：{target}（可从 ACCOUNTS.example.json 复制一份）")
        try:
            text = decode_secret(target.read_text(encoding="utf-8-sig"))
        except OSError as exc:
            raise ConfigError(f"配置文件读取失败：{exc}") from exc
        except ValueError as exc:
            raise ConfigError(f"配置 Secret 解码失败：{exc}") from exc
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            # 损坏配置必须报错，不能悄悄执行一轮空账号。
            raise ConfigError(f"配置不是合法 JSON（{target}）：{exc}") from exc

        notes: list[str] = []
        if auto_migrate and migrate_module.needs_migration(raw):
            result = migrate_module.migrate_document(raw)
            backup(target)
            _write(target, result.payload)
            if overlay is not None and result.cache_keys:
                moved = overlay.migrate_keys(result.cache_keys)
                if moved:
                    result.notes.append(f"运行期缓存已重挂到新账号 id：{moved} 条")
            raw = result.payload
            notes.extend(result.notes)

        if default and isinstance(raw, Mapping):
            merged = with_legacy_proxies(raw, target)
            document = parse_document(merged, path=target)
            if merged != raw:
                if auto_migrate:
                    # 先完整校验再写：没有备份不改写账号配置；写不成功时 settings 中的节点保留，
                    # 本次按内存合并运行，下次启动再迁。
                    failed = "旧版 settings 中的代理节点未能写回账号配置；本次按内存合并运行"
                    if backup(target, label="proxies") is None:
                        notes.append(failed + "（账号配置备份失败）")
                    else:
                        try:
                            _write(target, merged)
                        except OSError:
                            notes.append(failed)
                        else:
                            notes.append(LEGACY_PROXY_MOVED)
                            notes.extend(note for note in (retire_legacy_proxies(target),) if note)
            elif auto_migrate:
                notes.extend(note for note in (retire_legacy_proxies(target),) if note)
        else:
            document = parse_document(raw, path=target)
        return replace(document, path=target, notes=tuple(notes))


def readonly(path: Path | None = None, *, overlay: Any = None) -> Document:
    """运行链路的入口别名。语义与 ``load`` 相同，命名上强调只读。"""
    return load(path, overlay=overlay)


def save(document: Document, path: Path | None = None) -> Path:
    """显式保存（GUI / CLI 管理命令）。原子写 + 文件锁，节点与账号一起保存。"""
    target = Path(path or document.path or paths.ACCOUNTS_PATH)
    payload = document.to_payload()
    if is_default_path(target):
        # to_payload 为最小化导出省略空值；默认配置显式写出，旧 settings 节点不能再被补回。
        payload["proxy_groups"] = [group.to_payload() for group in document.proxy_groups]
        payload["default_proxy_group"] = document.default_proxy_group
    with paths.file_lock(target):
        _write(target, payload)
    return target


def save_payload(payload: dict[str, Any], path: Path | None = None) -> Path:
    """显式保存原始 JSON 文档；校验但不经过 Document.to_payload 投影。

    JSON 序列化形成独立快照，随后在文件锁内校验并原子写入；未知嵌套键、
    显式空值和 cookie_file 引用均原样保留。不读写运行期覆盖层，也不读写 settings：
    文档必须自带它引用的代理组。
    """
    target = Path(path or paths.ACCOUNTS_PATH)
    encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False)
    snapshot = json.loads(encoded)
    validation = json.loads(encoded)
    # schema 的默认相对目录是仓库根；显式指定配置路径时，相对凭据文件应跟随配置。
    # 只改验证副本，写盘仍使用用户原始引用，不展开凭据，也不改写绝对路径。
    accounts = validation.get("accounts") if isinstance(validation, dict) else None
    for account in accounts if isinstance(accounts, list) else ():
        if not isinstance(account, dict):
            continue
        for section in (account, account.get("credentials", {})):
            if not isinstance(section, dict):
                continue
            reference = section.get("cookie_file")
            if isinstance(reference, str) and reference.strip() and not Path(reference.strip()).is_absolute():
                section["cookie_file"] = str(target.resolve().parent / reference.strip())
    with paths.file_lock(target):
        parse_document(validation, path=target)
        _write(target, snapshot)
    return target


def backup(path: Path, *, label: str = "v2") -> Path | None:
    """迁移前备份。失败不阻断迁移，但会少一层保险，所以要留痕。"""
    target = Path(path)
    if not target.exists():
        return None
    stamp = time.strftime("%Y%m%d%H%M%S")
    destination = target.with_suffix(target.suffix + f".bak-{label}-{stamp}")
    try:
        destination.write_bytes(target.read_bytes())
    except OSError:
        return None
    return destination


def save_oauth_state(
    document: Document,
    provider: str,
    account: str,
    state: str,
    *,
    username: str = "",
    path: Path | None = None,
) -> Document:
    """写入共享 OAuth 登录态（GUI 的「捕获登录态」）。"""
    from core.timebase import utc_iso

    states = {key: {"accounts": dict(value.get("accounts", {}))} for key, value in document.oauth_states.items()}
    entry = states.setdefault(str(provider).strip().lower(), {"accounts": {}})
    entry["accounts"][str(account).strip() or "default"] = {
        "state": str(state or ""),
        "username": str(username or ""),
        "updated_at": utc_iso(),
    }
    updated = replace(document, oauth_states=states, version=CONFIG_VERSION)
    save(updated, path)
    return updated


def delete_oauth_state(document: Document, provider: str, account: str, *, path: Path | None = None) -> Document:
    states = {key: {"accounts": dict(value.get("accounts", {}))} for key, value in document.oauth_states.items()}
    entry = states.get(str(provider).strip().lower())
    if entry is not None:
        entry["accounts"].pop(str(account).strip() or "default", None)
        if not entry["accounts"]:
            states.pop(str(provider).strip().lower(), None)
    updated = replace(document, oauth_states=states, version=CONFIG_VERSION)
    save(updated, path)
    return updated


def _write(target: Path, payload: dict[str, Any]) -> None:
    paths.atomic_write_text(Path(target), json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
