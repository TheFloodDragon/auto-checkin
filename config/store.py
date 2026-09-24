"""ACCOUNTS.json 的读写。

**运行期只读**是本模块的核心约束：整条执行链路只调用 ``load()``，任何运行中产生的
东西（刷新到的 token、浏览器登录态、探测到的流程、脚本学到的数据）都进覆盖层
（``config/overlay.py``），绝不回写用户维护的配置文件。

理由是旧实现里踩过的：一旦运行链路能写配置，用户的文件就会被后台任务反复改写，
导出的 GitHub Secret 里也会带上很快失效的短期值；而且「用户配的」和「程序回填的」
混在同一个文件里之后，就再也分不清一个值到底是谁写的。

写入只发生在两个地方：GUI 的显式保存，和 CLI 的管理子命令。两者都走 ``save()``。
"""

from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from core.errors import ConfigError
from . import migrate as migrate_module
from . import paths
from .schema import CONFIG_VERSION, Document, parse_document

__all__ = [
    "backup",
    "delete_oauth_state",
    "load",
    "readonly",
    "save",
    "save_payload",
    "save_oauth_state",
]


def load(path: Path | None = None, *, auto_migrate: bool = True, overlay: Any = None) -> Document:
    """读取配置；必要时先迁移到 v3。

    ``overlay`` 传入时，迁移会顺带把运行期缓存的旧键（``base_url|name``）重挂到新的
    账号 id 上——否则一次迁移就等于清空所有已缓存的 token 与登录态。
    """
    target = Path(path or paths.ACCOUNTS_PATH)
    if not target.exists():
        raise ConfigError(f"未找到配置文件：{target}（可从 ACCOUNTS.example.json 复制一份）")
    try:
        raw = json.loads(target.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise ConfigError(f"配置文件读取失败：{exc}") from exc
    except json.JSONDecodeError as exc:
        # 配置损坏必须报错而不是回落默认值：静默跑一轮「没有任何账号」的签到，
        # 比直接失败更难发现。
        raise ConfigError(f"配置不是合法 JSON（{target}）：{exc}") from exc

    notes: tuple[str, ...] = ()
    if auto_migrate and migrate_module.needs_migration(raw):
        result = migrate_module.migrate_document(raw)
        backup(target)
        _write(target, result.payload)
        if overlay is not None and result.cache_keys:
            moved = overlay.migrate_keys(result.cache_keys)
            if moved:
                result.notes.append(f"运行期缓存已重挂到新账号 id：{moved} 条")
        raw = result.payload
        notes = tuple(result.notes)

    document = parse_document(raw, path=target)
    return replace(document, path=target, notes=notes)


def readonly(path: Path | None = None, *, overlay: Any = None) -> Document:
    """运行链路的入口别名。语义与 ``load`` 相同，命名上强调只读。"""
    return load(path, overlay=overlay)


def save(document: Document, path: Path | None = None) -> Path:
    """显式保存（GUI / CLI 管理命令）。原子写 + 文件锁。"""
    target = Path(path or document.path or paths.ACCOUNTS_PATH)
    with paths.file_lock(target):
        _write(target, document.to_payload())
    return target


def save_payload(payload: dict[str, Any], path: Path | None = None) -> Path:
    """显式保存原始 JSON 文档；校验但不经过 Document.to_payload 投影。

    JSON 序列化形成独立快照，随后在统一文件锁内校验并原子写入；未知嵌套键、
    显式空值和 cookie_file 引用均原样保留。不读写运行期覆盖层。
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


def backup(path: Path) -> Path | None:
    """迁移前备份。失败不阻断迁移，但会少一层保险，所以要留痕。"""
    target = Path(path)
    if not target.exists():
        return None
    stamp = time.strftime("%Y%m%d%H%M%S")
    destination = target.with_suffix(target.suffix + f".bak-v2-{stamp}")
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


def delete_oauth_state(
    document: Document, provider: str, account: str, *, path: Path | None = None
) -> Document:
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
    paths.atomic_write_text(
        Path(target), json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    )
