"""可信存储线程读取的只读凭据快照；绝不迁移缓存或展开外部凭据文件。"""
from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from config import paths
from config.overlay import CachePolicy, FieldEntry, Overlay, OverlayEntry
from config.schema import parse_account
from core.account import CREDENTIAL_FIELDS
from core.errors import ConfigError


@dataclass(frozen=True, repr=False)
class OverlaySnapshot:
    config_path: str
    account_id: str
    base_url: str = field(repr=False)
    accounts_mtime: str = ""
    fields: Mapping[str, FieldEntry] = field(default_factory=lambda: MappingProxyType({}), repr=False)
    updated_at: str = ""
    entry_accounts_mtime: str = ""
    configured: tuple[tuple[str, str], ...] = field(default=(), repr=False)

    def __repr__(self) -> str:
        return "<OverlaySnapshot: sensitive, read-only>"


@dataclass(frozen=True, repr=False)
class OverlayFieldPreview:
    value: str = ""
    source: str = "runtime"
    updated_at: str = ""
    expired: bool = False
    effective: bool | None = None
    mismatch: bool | None = None
    reason: str = "无法判定"

    def __repr__(self) -> str:
        return "<OverlayFieldPreview: sensitive>"


def _spec(raw: dict):
    # schema 的 cookie_file 支持读盘；预览只能解析内联字段。
    clean = deepcopy(raw)
    clean.pop("cookie_file", None)
    credentials = clean.get("credentials")
    if isinstance(credentials, dict):
        credentials.pop("cookie_file", None)
    return parse_account(clean)


def load_overlay_snapshot(config_path: str | Path, overlay_path: str | Path,
                          account_id: str) -> OverlaySnapshot | None:
    """仅从指定两文件读取。账号尚未保存时返回 None；异常不含源文件内容。"""
    try:
        config_path = Path(config_path).resolve()
        raw = json.loads(config_path.read_text(encoding="utf-8-sig"))
        accounts = raw.get("accounts", [])
        matches = [item for item in accounts if isinstance(item, dict) and item.get("id") == account_id]
        if not matches:
            return None
        if len(matches) != 1:
            raise ValueError("duplicate identity")
        spec = _spec(matches[0])
        overlay_path = Path(overlay_path)
        try:
            payload = json.loads(overlay_path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            payload = {"entries": {}}
        entries = payload.get("entries", {})
        if not isinstance(entries, dict):
            raise ValueError("invalid overlay")
        entry = OverlayEntry.from_payload(entries.get(account_id))
        return OverlaySnapshot(
            str(config_path), account_id, spec.base_url, paths.mtime_iso(config_path),
            MappingProxyType(dict(entry.fields)), entry.updated_at, entry.accounts_mtime,
            tuple((key, spec.credentials.get(key)) for key in CREDENTIAL_FIELDS),
        )
    except Exception:
        raise ConfigError("无法读取 overlay 对照；请检查配置和缓存文件。") from None


def _overlay(snapshot: OverlaySnapshot, *, policy: str, fresh: bool = False) -> Overlay:
    # 不调用构造器/load：两者均可能读盘，load 甚至可能迁移写盘。
    result = object.__new__(Overlay)
    result.path = Path(snapshot.config_path)
    result.policy = policy
    result._accounts_mtime = snapshot.accounts_mtime
    fields = {key: replace(value, ttl=0) if fresh else value for key, value in snapshot.fields.items()}
    result._entries = {snapshot.account_id: OverlayEntry(
        fields=MappingProxyType(fields), updated_at=snapshot.updated_at,
        accounts_mtime=snapshot.entry_accounts_mtime,
    )}
    result._loaded = True
    return result


def evaluate_overlay(snapshot: OverlaySnapshot, draft: dict | None, *,
                     policy: str = CachePolicy.READONLY, now_iso: str = "") -> dict[str, OverlayFieldPreview]:
    """纯内存计算；沿用 Overlay.apply 五条规则，修改/清空字段视为显式草稿。"""
    if draft is not None and draft.get("id") != snapshot.account_id:
        return {}
    spec = None
    try:
        if draft is not None:
            spec = _spec(draft)
    except Exception:
        pass
    resolved = compatible = None
    explicit = set()
    if spec is not None:
        baseline = dict(snapshot.configured)
        explicit = {key for key in CREDENTIAL_FIELDS if spec.credentials.get(key) != baseline.get(key, "")}
        resolved = _overlay(snapshot, policy=policy).apply(spec, explicit=explicit, now_iso=now_iso)
        compatible = _overlay(snapshot, policy=CachePolicy.READONLY, fresh=True).apply(spec, now_iso=now_iso)
    result = {}
    for key in CREDENTIAL_FIELDS:
        cached = snapshot.fields.get(key)
        if cached is None:
            result[key] = OverlayFieldPreview(reason="无缓存值", effective=False, mismatch=False)
            continue
        expired = cached.expired(now_iso=now_iso)
        mismatch = effective = None
        reason = "当前草稿无效，无法判定"
        if spec is not None:
            mismatch = spec.base_url != snapshot.base_url or not compatible.origins[key].startswith("overlay:")
            effective = not mismatch and resolved.origins[key].startswith("overlay:")
            reason = ("已生效" if effective else "未生效：配置不匹配" if mismatch else
                      "未生效：显式草稿值" if key in explicit else "未生效：已过期" if expired else "未生效")
            credentials = draft.get("credentials") or {}
            if (draft.get("cookie_file") or credentials.get("cookie_file")) and key not in credentials:
                effective = None
                reason = "外部凭据引用未读取，无法判定"
        if policy == CachePolicy.IGNORE:
            effective = False
            reason = "未生效：运行时忽略缓存（CHECKIN_CACHE_POLICY=ignore）"
        # 元数据也不允许携带任意缓存文本到可见标签。
        source = cached.origin if cached.origin in {"runtime", "refresh", "password", "browser", "oauth", "legacy"} else "runtime"
        stamp = cached.updated_at
        from datetime import datetime
        try:
            datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            stamp = "未知"
        result[key] = OverlayFieldPreview(cached.value, source, stamp or "未知", expired, effective, mismatch, reason)
    return result
