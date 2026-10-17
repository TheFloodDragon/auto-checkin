"""可信存储线程读取的只读凭据快照；绝不迁移缓存或展开外部凭据文件。"""
from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from config import paths
from config.overlay import CachePolicy, FieldEntry, Overlay, OverlayEntry
from config.schema import oauth_state_basis, parse_account
from core.account import CREDENTIAL_FIELDS
from core.errors import ConfigError

#: 覆写层可以接管的共享 OAuth 提供商。与 ``config.overlay._OAUTH_PROVIDERS`` 必须一致，
#: 由 tests/test_gui_overlay.py 直接断言，避免两处判定漂移。
OAUTH_PROVIDERS = frozenset({"linuxdo", "github"})


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


# ── 共享 OAuth 登录态：只读覆写预览 ─────────────────────────────────────────
# 只读同一份 overlay 文件；绝不调用 Overlay.load()（它会迁移旧缓存写盘），
# 也绝不展开 cookie_file 之类的外部凭据引用。
@dataclass(frozen=True, repr=False)
class OAuthOverlaySnapshot:
    """共享登录态的覆写层原始条目；只带标签需要的元数据。"""

    config_path: str
    provider: str
    account: str
    configured: str = field(repr=False)
    username: str = field(default="", repr=False)
    configured_updated_at: str = field(default="", repr=False)
    accounts_mtime: str = ""
    saved_value: str = field(default="", repr=False)
    saved_origin: str = "runtime"
    saved_updated_at: str = ""
    saved_ttl: int = 0
    saved_basis: str = field(default="", repr=False)

    def __repr__(self) -> str:
        return "<OAuthOverlaySnapshot: sensitive, read-only>"


@dataclass(frozen=True, repr=False)
class OAuthOverlayPreview:
    value: str = field(default="", repr=False)
    source: str = "runtime"
    updated_at: str = "未知"
    expired: bool = False
    effective: bool | None = None
    mismatch: bool | None = None
    reason: str = "无覆写值"

    def __repr__(self) -> str:
        return "<OAuthOverlayPreview: sensitive>"


def _oauth_config(document: Mapping[str, Any], provider: str, account: str) -> tuple[str, str, str]:
    """返回 (state, username, updated_at)。容器形状非 map 视为损坏；条目缺失给空串。"""
    states = document.get("oauth_states")
    if states is None:
        return ("", "", "")
    if not isinstance(states, Mapping):
        raise ValueError("oauth_states container is corrupted")
    bucket = states.get(provider)
    if bucket is None:
        return ("", "", "")
    if not isinstance(bucket, Mapping):
        raise ValueError("oauth provider container is corrupted")
    accounts = bucket.get("accounts")
    if accounts is None:
        return ("", "", "")
    if not isinstance(accounts, Mapping):
        raise ValueError("oauth accounts container is corrupted")
    entry = accounts.get(account)
    if entry is None:
        return ("", "", "")
    if not isinstance(entry, Mapping):
        raise ValueError("oauth state entry is corrupted")
    return (str(entry.get("state") or ""), str(entry.get("username") or ""), str(entry.get("updated_at") or ""))


def _oauth_document(config_path: str | Path) -> dict[str, Any]:
    """直接读取配置字节，不经 LoadedConfiguration；不迁移、不写盘、不解密。"""
    target = Path(config_path)
    raw = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, Mapping):
        raise ValueError("configuration root is not an object")
    return dict(raw)


def _oauth_basis(provider: str, account: str, state: str, username: str = "", updated_at: str = "") -> str:
    """与运行期 OAuthStateReader.basis 同一算法：登录态条目三个字段的确定性摘要。"""
    states = {provider: {"accounts": {account: {
        "state": state, "username": username, "updated_at": updated_at,
    }}}}
    return oauth_state_basis(states, provider, account)[1]


def load_oauth_overlay_snapshot(config_path: str | Path, overlay_path: str | Path,
                                provider: str, account: str) -> OAuthOverlaySnapshot | None:
    """仅从指定两文件读取共享登录态的覆写对照；配置里没有该条目时返回 None。

    异常一律换成固定文案：源文件内容（含登录态）绝不能进入可见标签或日志。
    """
    try:
        provider = str(provider or "").strip().lower()
        account = str(account or "").strip()
        if not provider or not account:
            return None
        config_path = Path(config_path).resolve()
        state, username, updated_at = _oauth_config(_oauth_document(config_path), provider, account)
        if not state:
            return None
        overlay_path = Path(overlay_path)
        try:
            payload = json.loads(overlay_path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            payload = {"oauth_states": {}}
        cached = _oauth_cached(payload, provider, account)
        return OAuthOverlaySnapshot(
            str(config_path), provider, account, state, username, updated_at, paths.mtime_iso(config_path),
            "" if cached is None else cached.value,
            "runtime" if cached is None else cached.origin,
            "" if cached is None else cached.updated_at,
            0 if cached is None else cached.ttl,
            "" if cached is None else cached.config_hash,
        )
    except Exception:
        raise ConfigError("无法读取共享登录态的覆写对照；请检查配置和缓存文件。") from None


def _oauth_cached(payload: Any, provider: str, account: str) -> FieldEntry | None:
    """从只读 overlay 文档里取共享态的缓存条目；容器形状异常视为损坏。"""
    if not isinstance(payload, Mapping):
        raise ValueError("invalid overlay")
    states = payload.get("oauth_states") or {}
    if not isinstance(states, Mapping):
        raise ValueError("invalid overlay")
    bucket = states.get(provider) or {}
    if not isinstance(bucket, Mapping):
        raise ValueError("invalid overlay")
    accounts = bucket.get("accounts") or {}
    if not isinstance(accounts, Mapping):
        raise ValueError("invalid overlay")
    raw = accounts.get(account)
    return FieldEntry.from_payload(raw) if isinstance(raw, Mapping) else None


def _oauth_reason(snapshot: OAuthOverlaySnapshot, *, expired: bool, mismatch: bool, adopted: bool) -> str:
    if not snapshot.saved_value:
        return "无覆写值"
    # 与账号凭据区同一优先级：先说不匹配（配置改过），再说过期。
    if mismatch:
        return "未生效：配置不匹配"
    if expired:
        return "未生效：已过期"
    return "已生效" if adopted else "未生效"


def evaluate_oauth_overlay(snapshot: OAuthOverlaySnapshot, configured: str = "", *,
                           policy: str = CachePolicy.READONLY, now_iso: str = "") -> OAuthOverlayPreview:
    """纯内存判定：逐条复刻 Overlay.resolve_oauth_state 的采用条件。

    采用与否只取决于「配置里保存的条目」和缓存条目，与当前草稿是否被改过无关：
    草稿改动只影响提示文案，不会让覆盖层凭空生效或失效。
    """
    configured = configured if isinstance(configured, str) else ""
    # 运行期 basis 永远由「配置里的条目原文」算出；这里用同一算法复算，才能正确
    # 判断缓存写入之后配置有没有被改过（改过就不采用）。
    expected = _oauth_basis(
        snapshot.provider, snapshot.account, snapshot.configured,
        snapshot.username, snapshot.configured_updated_at,
    )
    mismatch = bool(snapshot.saved_value) and snapshot.saved_basis != expected
    expired = False
    if snapshot.saved_value:
        expired = FieldEntry(
            value=snapshot.saved_value, updated_at=snapshot.saved_updated_at, ttl=snapshot.saved_ttl,
            origin=snapshot.saved_origin, config_hash=snapshot.saved_basis,
        ).expired(now_iso=now_iso)
    adopted = bool(
        policy in (CachePolicy.COMPATIBLE, CachePolicy.READONLY)
        and snapshot.provider in OAUTH_PROVIDERS
        and snapshot.saved_ttl > 0
        and snapshot.saved_value
        and not expired
        and not mismatch
    )
    if not snapshot.saved_value:
        return OAuthOverlayPreview(reason="无覆写值", effective=False, mismatch=False)
    # 元数据也不允许携带任意缓存文本到可见标签。
    source = snapshot.saved_origin if snapshot.saved_origin in {"runtime", "refresh", "password", "browser", "oauth", "legacy"} else "runtime"
    from datetime import datetime
    stamp = snapshot.saved_updated_at
    try:
        datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        stamp = "未知"
    if policy == CachePolicy.IGNORE:
        return OAuthOverlayPreview(snapshot.saved_value, source, stamp or "未知", expired, False, mismatch,
                                   "未生效：运行时忽略缓存（CHECKIN_CACHE_POLICY=ignore）")
    if not configured.strip():
        # 配置里没有可参与判定的原值：既不采用也不断言过期/不匹配。
        return OAuthOverlayPreview(snapshot.saved_value, source, stamp or "未知", expired, None, mismatch, "无法判定")
    if configured.strip() == snapshot.saved_value:
        # 草稿已被覆写成同一个值：运行期结果与它一致，不存在冲突。
        return OAuthOverlayPreview(snapshot.saved_value, source, stamp or "未知", expired, True, mismatch,
                                   "已应用到草稿")
    if snapshot.configured and configured != snapshot.configured:
        return OAuthOverlayPreview(snapshot.saved_value, source, stamp or "未知", expired, False, mismatch,
                                   "未生效：显式草稿值")
    return OAuthOverlayPreview(snapshot.saved_value, source, stamp or "未知", expired, adopted, mismatch,
                               _oauth_reason(snapshot, expired=expired, mismatch=mismatch, adopted=adopted))
