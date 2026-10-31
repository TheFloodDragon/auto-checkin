"""运行期覆盖层：把运行中产生的凭据、流程结论与学习数据叠加到配置上。

取代 ``providers/token_cache.py``。三点核心变化：

1. **时间成为第一判据**。旧实现只有「凭据摘要一致」这个二值判据，外加一个
   ``*_invalidated_at`` 补丁标记；用户改了 Secret 又改回来、或只是改个站点名，
   判定结果就会跳变。现在每个字段都带 ``updated_at`` + ``ttl``，条目带
   ``accounts_mtime``，配置与缓存谁更新一目了然（见 ``FieldDecision``）。

2. **覆盖对象是配置，不是文件**。``apply()`` 产出独立的 ``ResolvedAccount``，
   ``ACCOUNTS.json`` 在整个运行期只读。旧实现是 ``setattr(site, field, value)``
   就地改配置对象，于是「用户配的」与「缓存回填的」在同一个对象里无法区分。

3. **不只是凭据**。流程探测结论（``flow``）、脚本学习数据（``learning``）、
   健康度（``health``）都在这里，脚本不再各自往 ``.cache-checkin/`` 写散落文件。

**永不删除**：判定为「不可用」的条目只是不被采用，值继续留在文件里；用户把凭据
改回去就能重新命中。这条规则从旧实现继承而来（当时用注释解释了三遍），现在由
``apply()`` 的结构保证——它根本没有删除路径。
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping

from core.account import (
    CREDENTIAL_FIELDS,
    CREDENTIAL_GROUPS,
    AccountSpec,
    CredentialSet,
    ResolvedAccount,
    authentication_scope,
)
from core.flow import Discovery
from core.timebase import age_seconds, newer_than, utc_iso
from net.lifetime import credential_ttl
from . import paths

__all__ = [
    "CachePolicy",
    "FieldDecision",
    "FieldEntry",
    "OAuthStateResolution",
    "Overlay",
    "OverlayEntry",
    "TTL_DEFAULTS",
    "load",
]

OVERLAY_VERSION = 3

#: 各凭据字段的默认有效期（秒）。到期后不再采用，但值仍保留。
#: 依据：access_token 多为数小时的 JWT；refresh_token 通常 30 天；
#: 浏览器登录态经验上两周内可用；站点 session cookie 一天。
TTL_DEFAULTS: Mapping[str, int] = MappingProxyType(
    {
        "access_token": 6 * 3600,
        "refresh_token": 30 * 86400,
        "cookie": 14 * 86400,
        "session_cookie": 86400,
        "browser_state": 14 * 86400,
    }
)

#: 单个学习数据键的体积上限。脚本题库这类东西容易无节制增长，最终把整个
#: overlay.json 撑到读写都慢，且每次写入都要全量序列化。
LEARNING_VALUE_MAX_BYTES = 256 * 1024


class CachePolicy:
    """覆盖层的应用策略。"""

    #: 正常：按时间与指纹规则叠加。
    COMPATIBLE = "compatible"
    #: 完全不读：父进程已解析完凭据后派生的 worker 子进程用这个，
    #: 避免同一任务经过两套优先级判断（旧实现的 CHECKIN_CACHE_POLICY=ignore）。
    IGNORE = "ignore"
    #: 只读不写：诊断与 dry-run。
    READONLY = "readonly"


# ── 数据结构 ────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class FieldEntry:
    """覆盖层里的一个字段值。"""

    value: str
    updated_at: str = ""
    ttl: int = 0
    origin: str = "runtime"       # refresh / password / browser / oauth / runtime
    config_hash: str = ""         # 写入时配置里该字段的摘要，用于判断配置是否变过
    revision_nonce: str = ""      # 每次凭据写入都换代，区分同一秒同值重写与 ABA
    tombstone: bool = False       # 只有显式 clear 才产生，空值也参与覆盖且永不过期
    auth_scope: str = ""          # 不改变凭据 schema；独立绑定规范站点、主体与认证契约

    def expired(self, *, now_iso: str = "") -> bool:
        if self.tombstone or self.ttl <= 0:
            return False
        age = age_seconds(self.updated_at, now_iso=now_iso)
        if age is None:
            return True          # 无时间戳 = 无法证明还新鲜
        if age < 0:
            return True          # 未来时间戳（时钟回拨/手工改过）不可信
        return age > self.ttl

    def to_payload(self) -> dict[str, Any]:
        payload = {
            "value": self.value,
            "updated_at": self.updated_at,
            "ttl": int(self.ttl),
            "origin": self.origin,
            "config_hash": self.config_hash,
        }
        if self.revision_nonce:
            payload["revision_nonce"] = self.revision_nonce
        if self.tombstone:
            payload["tombstone"] = True
        if self.auth_scope:
            payload["auth_scope"] = self.auth_scope
        return payload

    @classmethod
    def from_payload(cls, payload: Any) -> "FieldEntry | None":
        if isinstance(payload, str):
            # 旧 token_cache.json 的形态：字段直接是字符串，没有任何元数据。
            return cls(value=payload) if payload.strip() else None
        if not isinstance(payload, Mapping):
            return None
        value = str(payload.get("value") or "").strip()
        tombstone = (
            payload.get("tombstone") is True
            and isinstance(payload.get("value"), str)
            and not value
            and isinstance(payload.get("config_hash"), str)
            and bool(payload["config_hash"].strip())
        )
        if not value and not tombstone:
            return None
        try:
            ttl = int(payload.get("ttl", 0))
        except (TypeError, ValueError):
            ttl = 0
        return cls(
            value=value,
            updated_at=str(payload.get("updated_at") or ""),
            ttl=0 if tombstone else ttl,
            origin=str(payload.get("origin") or "runtime"),
            config_hash=str(payload.get("config_hash") or ""),
            revision_nonce=str(payload.get("revision_nonce") or ""),
            tombstone=tombstone,
            auth_scope=str(payload.get("auth_scope") or ""),
        )


@dataclass(frozen=True, slots=True)
class OAuthStateResolution:
    """共享 OAuth 登录态的一次解析快照；敏感值不参与诊断输出。

    ``revision`` 对原始条目（包括未知元数据）取摘要，即使条目未被采用也保留版本，
    供写回时进行 compare-and-swap。此层不验证浏览器 cookie。
    """

    provider: str
    account: str
    state: str = field(repr=False)
    configured: str = field(repr=False)
    config_hash: str = field(repr=False)
    revision: str = field(repr=False)
    from_overlay: bool = False


@dataclass(frozen=True, slots=True)
class FieldDecision:
    """一次字段级覆盖判定的结果与理由。

    理由要能进日志：「为什么这次没用缓存的 token」是排查里最常问的问题，
    旧实现只能靠读代码推断。
    """

    field: str
    winner: str                   # "config" | "overlay"
    value: str
    rule: str                     # 命中的规则编号与说明
    origin: str = ""

    @property
    def from_overlay(self) -> bool:
        return self.winner == "overlay"


@dataclass(frozen=True, slots=True)
class OverlayEntry:
    """一个账号在覆盖层里的完整条目。"""

    fields: Mapping[str, FieldEntry] = field(default_factory=lambda: MappingProxyType({}))
    flow: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    learning: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    health: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    accounts_mtime: str = ""      # 写入时 ACCOUNTS.json 的最后修改时间
    updated_at: str = ""
    identity: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    identity_scope: str = ""
    identity_revision_nonce: str = ""
    scoped_flow: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def to_payload(self) -> dict[str, Any]:
        return {
            "fields": {name: entry.to_payload() for name, entry in self.fields.items()},
            "flow": dict(self.flow),
            "scoped_flow": dict(self.scoped_flow),
            "identity": dict(self.identity),
            "identity_scope": self.identity_scope,
            "identity_revision_nonce": self.identity_revision_nonce,
            "learning": dict(self.learning),
            "health": dict(self.health),
            "accounts_mtime": self.accounts_mtime,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_payload(cls, payload: Any) -> "OverlayEntry":
        if not isinstance(payload, Mapping):
            return cls()
        raw_fields = payload.get("fields")
        fields_map: dict[str, FieldEntry] = {}
        if isinstance(raw_fields, Mapping):
            for name, item in raw_fields.items():
                entry = FieldEntry.from_payload(item)
                if entry is not None and name in CREDENTIAL_FIELDS:
                    fields_map[str(name)] = entry
        return cls(
            fields=MappingProxyType(fields_map),
            flow=MappingProxyType(dict(_as_map(payload.get("flow")))),
            learning=MappingProxyType(dict(_as_map(payload.get("learning")))),
            health=MappingProxyType(dict(_as_map(payload.get("health")))),
            accounts_mtime=str(payload.get("accounts_mtime") or ""),
            updated_at=str(payload.get("updated_at") or ""),
            identity=MappingProxyType(_safe_identity(_as_map(payload.get("identity")))),
            identity_scope=str(payload.get("identity_scope") or ""),
            identity_revision_nonce=str(payload.get("identity_revision_nonce") or ""),
            scoped_flow=MappingProxyType(dict(_as_map(payload.get("scoped_flow")))),
        )

    def flow_discoveries(self) -> dict[str, Discovery]:
        out: dict[str, Discovery] = {}
        for stage, item in self.flow.items():
            discovery = Discovery.from_payload(str(stage), item)
            if discovery is not None:
                out[str(stage)] = discovery
        return out

    @property
    def failure_streak(self) -> int:
        try:
            return max(0, int(self.health.get("failure_streak", 0)))
        except (TypeError, ValueError):
            return 0


# ── 覆盖层 ──────────────────────────────────────────────────────────────────
class Overlay:
    """``.cache-checkin/overlay.json`` 的读写与判定。

    所有写入都走 ``文件锁 + 读-改-原子写``；任何写入失败都只记一个布尔返回值，
    绝不抛给调用方——缓存写不进去最多是下次多开一次浏览器，不该影响本次结论。
    """

    __slots__ = ("path", "policy", "_entries", "_accounts_mtime", "_loaded")

    def __init__(
        self,
        path: Path | None = None,
        *,
        policy: str = CachePolicy.COMPATIBLE,
        accounts_path: Path | None = None,
    ) -> None:
        self.path = Path(path or paths.OVERLAY_PATH)
        self.policy = str(policy or CachePolicy.COMPATIBLE).strip().lower()
        self._entries: dict[str, OverlayEntry] = {}
        self._accounts_mtime = paths.mtime_iso(accounts_path or paths.ACCOUNTS_PATH)
        self._loaded = False

    # -- 加载 --
    def load(self) -> "Overlay":
        if self._loaded:
            return self
        document = paths.read_json(self.path, default=None)
        if document is None and not self.path.exists():
            document = self._migrate_legacy()
        entries = document.get("entries") if isinstance(document, Mapping) else None
        if isinstance(entries, Mapping):
            self._entries = {
                str(key): OverlayEntry.from_payload(value) for key, value in entries.items()
            }
        self._loaded = True
        return self

    def entry(self, account_id: str) -> OverlayEntry:
        self.load()
        return self._entries.get(str(account_id)) or OverlayEntry()

    def credential_revisions(
        self, account_id: str, *, fields: Iterable[str] = CREDENTIAL_FIELDS, include_group: bool = False,
    ) -> Mapping[str, str]:
        """只读原始版本；可将身份/绑定元数据与全部凭据加入整组 CAS。"""
        names = tuple(dict.fromkeys(name for name in fields if name in CREDENTIAL_FIELDS))
        try:
            document = _read_overlay_document(self.path)
            revisions = {name: _credential_revision(_credential_raw_entry(document, str(account_id), name))
                         for name in names}
            if include_group:
                revisions["__group__"] = _credential_group_revision(document, str(account_id))
        except Exception:
            revisions = {name: "unreadable" for name in names}
            if include_group:
                revisions["__group__"] = "unreadable"
        return MappingProxyType(revisions)

    def credential_snapshot(
        self, spec: AccountSpec, *, explicit: Iterable[str] = (), include_group: bool = False,
        auth_scope: str | None = None,
    ) -> tuple[ResolvedAccount, Mapping[str, str], OverlayEntry]:
        """一次严格只读得到一致视图、原始凭据/元数据版本；损坏不能伪装成缺失。"""
        key = str(spec.id)
        document = _read_overlay_document(self.path)
        revisions: dict[str, str] = {}
        for name in CREDENTIAL_FIELDS:
            raw = _credential_raw_entry(document, key, name)
            if raw is not _CREDENTIAL_MISSING and FieldEntry.from_payload(raw) is None:
                raise ValueError("overlay credential field is corrupted")
            revisions[name] = _credential_revision(raw)
        if include_group:
            revisions["__group__"] = _credential_group_revision(document, key)
        entries = document.get("entries")
        parsed = OverlayEntry.from_payload(entries.get(key) if isinstance(entries, Mapping) else None)
        view = Overlay(self.path, policy=self.policy)
        view._accounts_mtime = self._accounts_mtime
        view._entries = {key: parsed}
        view._loaded = True
        resolved = view.apply(spec, explicit=explicit, auth_scope=auth_scope)
        return resolved, MappingProxyType(revisions), parsed

    # -- 共享 OAuth：独立于站点账号的命名空间 --
    def resolve_oauth_state(
        self,
        provider: str,
        account: str,
        configured: str,
        *,
        config_hash: str = "",
        now_iso: str = "",
    ) -> OAuthStateResolution:
        """每次重新读盘；配置清空后绝不复活缓存，摘要优先于文件修改时间。"""
        provider = str(provider or "").strip().lower()
        account = str(account or "").strip()
        configured = configured.strip() if isinstance(configured, str) else ""
        basis = str(config_hash or "").strip() or _hash(configured)
        raw = _OAUTH_MISSING
        revision = ""
        if self.policy != CachePolicy.IGNORE:
            try:
                document = _read_overlay_document(self.path)
                raw = _oauth_raw_entry(document, provider, account)
                revision = _oauth_revision(raw)
            except Exception:
                # 损坏/不可读的文件不能伪装成空缓存；写回也会再次严格检查。
                pass
        cached = _oauth_field_entry(raw)
        adopted = bool(
            self.policy in (CachePolicy.COMPATIBLE, CachePolicy.READONLY)
            and provider in _OAUTH_PROVIDERS
            and account
            and configured
            and cached is not None
            and cached.config_hash == basis
            and cached.ttl > 0
            and not cached.expired(now_iso=now_iso)
        )
        return OAuthStateResolution(
            provider=provider,
            account=account,
            state=cached.value if adopted and cached is not None else configured,
            configured=configured,
            config_hash=basis,
            revision=revision,
            from_overlay=adopted,
        )

    def record_oauth_state(
        self,
        resolution: OAuthStateResolution,
        state: str,
        *,
        current_config: Callable[[], tuple[str, str]] | None = None,
        ttl: int = 14 * 86400,
        now_iso: str = "",
    ) -> bool:
        """锁内重读并比较原始条目版本与当前配置；写缓存，不写配置文件。"""
        if (
            self.policy != CachePolicy.COMPATIBLE
            or not isinstance(resolution, OAuthStateResolution)
            or resolution.provider not in _OAUTH_PROVIDERS
            or not resolution.account.strip()
            or not resolution.configured.strip()
            or not isinstance(state, str)
            or not state.strip()
            or type(ttl) is not int
            or ttl <= 0
        ):
            return False
        try:
            stamp = now_iso or utc_iso()
            if age_seconds(stamp, now_iso=stamp) is None:
                return False
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with paths.file_lock(self.path):
                document = _read_overlay_document(self.path)
                raw = _oauth_raw_entry(document, resolution.provider, resolution.account)
                if _oauth_revision(raw) != resolution.revision:
                    return False
                if raw is not _OAUTH_MISSING and _oauth_field_entry(raw) is None:
                    return False
                if current_config is not None:
                    configured, basis = current_config()
                    if not isinstance(configured, str) or not isinstance(basis, str):
                        return False
                    configured = configured.strip()
                    basis = basis.strip() or _hash(configured)
                    if (
                        not configured
                        or configured != resolution.configured
                        or basis != resolution.config_hash
                    ):
                        return False
                states = dict(_as_map(document.get("oauth_states")))
                bucket = dict(_as_map(states.get(resolution.provider)))
                accounts = dict(_as_map(bucket.get("accounts")))
                payload = dict(raw) if isinstance(raw, Mapping) else {}
                payload.update(
                    FieldEntry(
                        value=state.strip(),
                        updated_at=stamp,
                        ttl=ttl,
                        origin="oauth",
                        config_hash=resolution.config_hash,
                    ).to_payload()
                )
                payload["revision_nonce"] = uuid.uuid4().hex
                accounts[resolution.account] = payload
                bucket["accounts"] = accounts
                states[resolution.provider] = bucket
                document["version"] = OVERLAY_VERSION
                document["oauth_states"] = states
                paths.atomic_write_json(self.path, document)
        except Exception:
            return False
        return True

    def apply(
        self, spec: AccountSpec, *, explicit: Iterable[str] = (), now_iso: str = "", auth_scope: str | None = None,
    ) -> ResolvedAccount:
        """显式配置/TTL/摘要优先；只有可证明归属的缓存凭据才参与覆盖。"""
        explicit_fields = {str(item) for item in explicit if str(item) in CREDENTIAL_FIELDS}
        scope = auth_scope or authentication_scope(spec)
        entry = OverlayEntry() if self.policy == CachePolicy.IGNORE else self.entry(spec.id)
        ignore_all = self.policy == CachePolicy.IGNORE
        decisions = {
            name: _decide(
                name, configured=spec.credentials.get(name), cached=entry.fields.get(name),
                explicit=name in explicit_fields, ignore_all=ignore_all,
                entry_updated_at=entry.updated_at, accounts_mtime=self._accounts_mtime,
                entry_accounts_mtime=entry.accounts_mtime, now_iso=now_iso, auth_scope=scope,
            )
            for name in CREDENTIAL_FIELDS
        }
        origins = {
            name: (f"overlay:{decision.origin or 'runtime'}" if decision.from_overlay
                   else ("explicit" if name in explicit_fields else "config"))
            for name, decision in decisions.items()
        }
        identity = {}
        identity_fields = frozenset()
        if not ignore_all and entry.identity_scope == scope:
            identity_fields = frozenset(
                name for name, cached in entry.fields.items()
                if cached.auth_scope == scope and cached.value and decisions[name].value == cached.value
            )
            if identity_fields:
                identity = dict(entry.identity)
        return ResolvedAccount(
            spec=spec, credentials=CredentialSet(**{name: decision.value for name, decision in decisions.items()}),
            origins=MappingProxyType(origins), learned_flow=MappingProxyType({}),
            health=MappingProxyType({} if ignore_all else dict(entry.health)), auth_scope=scope,
            identity=MappingProxyType(identity), identity_fields=identity_fields,
        )


    def explain(self, spec: AccountSpec, *, explicit: Iterable[str] = ()) -> list[str]:
        """把本次覆盖判定渲染成可读行，供 ``--verbose`` 与诊断使用。"""
        explicit_fields = {str(item) for item in explicit if str(item) in CREDENTIAL_FIELDS}
        entry = self.entry(spec.id)
        lines: list[str] = []
        for name in CREDENTIAL_FIELDS:
            configured = spec.credentials.get(name)
            cached = entry.fields.get(name)
            if not configured and cached is None:
                continue
            decision = _decide(
                name,
                configured=configured,
                cached=cached,
                explicit=name in explicit_fields,
                ignore_all=self.policy == CachePolicy.IGNORE,
                entry_updated_at=entry.updated_at,
                accounts_mtime=self._accounts_mtime,
                entry_accounts_mtime=entry.accounts_mtime,
                auth_scope=authentication_scope(spec),
            )
            state = "空" if not decision.value else f"{len(decision.value)} 字符"
            lines.append(f"{name}: 采用{decision.winner}（{state}）— {decision.rule}")
        return lines

    def record_credentials(
        self,
        spec: AccountSpec,
        *,
        origin: str = "runtime",
        ttl: Mapping[str, int] | None = None,
        clear: Iterable[str] = (),
        expected_revisions: Mapping[str, str] | None = None,
        written_revisions: dict[str, str] | None = None,
        group_receipt: dict[str, str] | None = None,
        auth_scope: str | None = None,
        identity: Mapping[str, Any] | None = None,
        **fields: str,
    ) -> bool:
        """凭据、独立身份元数据在同一锁内 CAS；清空写永不过期 tombstone。"""
        clean = {key: str(value or "").strip() for key, value in fields.items()
                 if key in CREDENTIAL_FIELDS and str(value or "").strip()}
        cleared = {name for name in clear if name in CREDENTIAL_FIELDS}
        clean.update(dict.fromkeys(cleared, ""))
        if (not clean and identity is None) or self.policy == CachePolicy.READONLY:
            return False
        scope = auth_scope or authentication_scope(spec)
        expected = dict(expected_revisions) if expected_revisions is not None else None
        if expected is not None and any(
            name not in (*CREDENTIAL_FIELDS, "__group__") or not isinstance(revision, str)
            for name, revision in expected.items()
        ):
            return False
        ttl_map = dict(TTL_DEFAULTS)
        for key, value in clean.items():
            if key in ("access_token", "refresh_token") and value:
                ttl_map[key] = credential_ttl(key, value, default=ttl_map[key])
        ttl_map.update({key: int(value) for key, value in (ttl or {}).items() if key in CREDENTIAL_FIELDS})

        def mutate(entry: OverlayEntry) -> OverlayEntry:
            merged = dict(entry.fields)
            stamp = utc_iso()
            for key, value in clean.items():
                merged[key] = FieldEntry(
                    value=value, updated_at=stamp, ttl=0 if key in cleared else ttl_map.get(key, 0),
                    origin=origin, config_hash=_hash(spec.credentials.get(key)),
                    revision_nonce=uuid.uuid4().hex, tombstone=key in cleared, auth_scope=scope,
                )
            verified_identity = dict(entry.identity) if entry.identity_scope == scope else {}
            if identity is not None:
                verified_identity = _safe_identity(identity)
            return replace(entry, fields=MappingProxyType(merged),
                           identity=MappingProxyType(verified_identity), identity_scope=scope,
                       identity_revision_nonce=uuid.uuid4().hex)

        return self._update(spec.id, mutate, expected_revisions=expected, written_revisions=written_revisions,
                            group_receipt=group_receipt)

    def record_flow(
        self, account_id: str, discoveries: Iterable[Discovery], *, login_scope: str = "", task_scope: str = "",
    ) -> bool:
        """登录结论绑定认证契约；执行结论按 task+模板+配置独立保存。

        无作用域的旧写入仅保留兼容文档，不进入生产学习读取。
        """
        items = [item for item in discoveries if item and item.value]
        if not items or self.policy == CachePolicy.READONLY:
            return False

        def mutate(entry: OverlayEntry) -> OverlayEntry:
            legacy = dict(entry.flow)
            scoped = {key: dict(_as_map(value)) for key, value in entry.scoped_flow.items()}
            for discovery in items:
                payload = discovery.to_payload()
                if not payload.get("probed_at"):
                    payload["probed_at"] = utc_iso()
                key = login_scope if discovery.stage == "login" else task_scope
                target = scoped.setdefault(key, {}) if key else legacy
                target[discovery.stage] = payload
            return replace(entry, flow=MappingProxyType(legacy), scoped_flow=MappingProxyType(scoped))

        return self._update(account_id, mutate)


    def learned_for(self, account_id: str, *, login_scope: str, task_scope: str) -> Mapping[str, Any]:
        """只读当前作用域的结论；无作用域/旧全局学习保留但不参与执行。"""
        if self.policy == CachePolicy.IGNORE:
            return MappingProxyType({})
        entry = self.entry(account_id)
        login = _as_map(entry.scoped_flow.get(login_scope))
        task = _as_map(entry.scoped_flow.get(task_scope))
        values = {key: value for key, value in task.items() if key != "login"}
        if "login" in login:
            values["login"] = login["login"]
        return MappingProxyType(values)

    def record_health(self, account_id: str, *, ok: bool, verdict: str = "", reason: str = "") -> bool:
        """更新健康度。连续失败达阈值后，流程层会强制重新探测。"""
        if self.policy == CachePolicy.READONLY:
            return False

        def mutate(entry: OverlayEntry) -> OverlayEntry:
            streak = 0 if ok else entry.failure_streak + 1
            return replace(
                entry,
                health=MappingProxyType(
                    {
                        "failure_streak": streak,
                        "last_verdict": str(verdict or ("success" if ok else "failed")),
                        "last_reason": str(reason or ""),
                        "last_run": utc_iso(),
                    }
                ),
            )

        return self._update(account_id, mutate)

    def get_learning(self, account_id: str, key: str, default: Any = None) -> Any:
        value = self.entry(account_id).learning.get(str(key))
        return default if value is None else value

    def put_learning(self, account_id: str, key: str, value: Any) -> bool:
        """写脚本学习数据（题库、验证码方言、端点方言……）。

        超过体积上限直接拒绝并返回 False：静默截断会让脚本读到半截数据，
        比拿不到还糟。调用方（``ctx.store``）会记一行日志。
        """
        if self.policy == CachePolicy.READONLY:
            return False
        try:
            encoded = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return False
        if len(encoded.encode("utf-8")) > LEARNING_VALUE_MAX_BYTES:
            return False

        def mutate(entry: OverlayEntry) -> OverlayEntry:
            merged = dict(entry.learning)
            merged[str(key)] = json.loads(encoded)
            return replace(entry, learning=MappingProxyType(merged))

        return self._update(account_id, mutate)

    # -- 内部 --
    def _update(
        self,
        account_id: str,
        mutate: Any,
        *,
        expected_revisions: Mapping[str, str] | None = None,
        written_revisions: dict[str, str] | None = None,
        group_receipt: dict[str, str] | None = None,
    ) -> bool:
        key = str(account_id)
        if not key:
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with paths.file_lock(self.path):
                # 锁内重新读盘：比较所有预期字段，而不只比较本次写入的字段。
                document = _read_overlay_document(self.path)
                for name, revision in (expected_revisions or {}).items():
                    if name == "__group__":
                        if _credential_group_revision(document, key) != revision:
                            return False
                        continue
                    raw = _credential_raw_entry(document, key, name)
                    if _credential_revision(raw) != revision:
                        return False
                    if raw is not _CREDENTIAL_MISSING and FieldEntry.from_payload(raw) is None:
                        return False
                # 整组写前版本必须在同一把锁内、修改之前取得，回执才对应这一次提交。
                group_before = _group_revision_or_empty(document, key) if group_receipt is not None else ""
                raw_entries = document.get("entries")
                entries = dict(raw_entries) if isinstance(raw_entries, Mapping) else {}
                entry = OverlayEntry.from_payload(entries.get(key))
                updated = mutate(entry)
                updated = replace(
                    updated,
                    updated_at=utc_iso(),
                    accounts_mtime=self._accounts_mtime or updated.accounts_mtime,
                )
                payload = _merge_entry_payload(entries.get(key), entry, updated)
                entries[key] = payload
                document["version"] = OVERLAY_VERSION
                document["entries"] = entries
                # 从本次确切 payload 生成回执，绝不在成功后读盘误认别人的版本。
                receipt = {
                    name: _credential_revision(payload["fields"][name])
                    for name, value in updated.fields.items()
                    if value != entry.fields.get(name)
                } if written_revisions is not None else {}
                # 整组回执单独返回写前/写后版本：调用方只有在写前版本仍等于自己的基线时
                # 才能推进，不能把期间别处的写入（例如只改身份元数据）认作自己的来源。
                group = {
                    "before": group_before, "after": _group_revision_or_empty(document, key),
                } if group_receipt is not None else {}
                paths.atomic_write_json(self.path, document)
                self._entries[key] = updated
                self._loaded = True
        except Exception:
            return False
        if written_revisions is not None:
            written_revisions.update(receipt)
        if group_receipt is not None:
            group_receipt.update(group)
        return True

    def _migrate_legacy(self) -> dict[str, Any]:
        """把旧 ``token_cache.json`` 迁移成 v3 文档（一次性，保留原文件）。

        迁移只在 compatible 策略下落盘，并且必须在锁内重新检查目标文件；这样不会
        抹掉另一个进程刚创建的、尤其是共享 ``oauth_states`` 命名空间。
        """
        def build_document() -> dict[str, Any]:
            legacy = paths.read_json(paths.LEGACY_TOKEN_CACHE_PATH, default=None)
            if not isinstance(legacy, Mapping):
                return {"version": OVERLAY_VERSION, "entries": {}}
            tokens = legacy.get("tokens")
            if not isinstance(tokens, Mapping):
                return {"version": OVERLAY_VERSION, "entries": {}}
            entries: dict[str, Any] = {}
            for key, value in tokens.items():
                if not isinstance(value, Mapping):
                    continue
                fields: dict[str, Any] = {}
                stamp = str(value.get("updated_at") or "")
                for name in ("access_token", "refresh_token", "browser_state"):
                    text = str(value.get(name) or "").strip()
                    if text:
                        fields[name] = {
                            "value": text,
                            "updated_at": stamp,
                            "ttl": TTL_DEFAULTS.get(name, 0),
                            "origin": "legacy",
                            "config_hash": "",
                        }
                if fields:
                    entries[f"legacy:{key}"] = {
                        "fields": fields,
                        "flow": {},
                        "learning": {},
                        "health": {},
                        "accounts_mtime": "",
                        "updated_at": stamp,
                    }
            return {"version": OVERLAY_VERSION, "entries": entries}

        candidate = build_document()
        if self.policy != CachePolicy.COMPATIBLE:
            return candidate
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with paths.file_lock(self.path):
                if self.path.exists():
                    try:
                        return _read_overlay_document(self.path)
                    except Exception:
                        return {"version": OVERLAY_VERSION, "entries": {}}
                if candidate.get("entries"):
                    paths.atomic_write_json(self.path, candidate)
        except Exception:
            return candidate
        return candidate

    def migrate_keys(self, mapping: Mapping[str, str]) -> int:
        """把 ``legacy:<base_url|name>`` 条目改挂到账号 id 上。

        ``mapping`` 由配置加载器提供：``{"<base_url>|<name>": "<account_id>"}``。
        已存在同 id 的新条目时不覆盖——新数据永远优先于迁移来的旧数据。
        """
        self.load()
        moved = 0
        try:
            with paths.file_lock(self.path):
                document = _read_overlay_document(self.path)
                raw_entries = document.get("entries")
                entries = dict(raw_entries) if isinstance(raw_entries, Mapping) else {}
                for legacy_key, account_id in mapping.items():
                    source = f"legacy:{legacy_key}"
                    if source not in entries or str(account_id) in entries:
                        continue
                    entries[str(account_id)] = entries.pop(source)
                    moved += 1
                if moved:
                    document["version"] = OVERLAY_VERSION
                    document["entries"] = entries
                    paths.atomic_write_json(self.path, document)
                    self._entries = {
                        str(key): OverlayEntry.from_payload(value) for key, value in entries.items()
                    }
                    self._loaded = True
        except Exception:
            return 0
        return moved


def load(
    *,
    policy: str = CachePolicy.COMPATIBLE,
    path: Path | None = None,
    accounts_path: Path | None = None,
) -> Overlay:
    return Overlay(path, policy=policy, accounts_path=accounts_path).load()


# ── 判定实现 ────────────────────────────────────────────────────────────────
def _decide(
    name: str,
    *,
    configured: str,
    cached: FieldEntry | None,
    explicit: bool,
    ignore_all: bool,
    entry_updated_at: str,
    accounts_mtime: str,
    entry_accounts_mtime: str,
    now_iso: str = "",
    auth_scope: str = "",
) -> FieldDecision:
    group = CREDENTIAL_GROUPS.get(name, name)

    if ignore_all:
        return FieldDecision(name, "config", configured, "规则1：cache_policy=ignore，不叠加覆盖层")
    if explicit:
        return FieldDecision(name, "config", configured, "规则2：调用方显式提供（含显式清空）")
    if cached is None or (not cached.value and not cached.tombstone):
        return FieldDecision(name, "config", configured, "规则5：覆盖层无该字段")
    if auth_scope and not cached.auth_scope:
        return FieldDecision(name, "config", configured, "规则作用域：旧缓存无法证明站点与登录主体归属，保留但不采用")
    if auth_scope and cached.auth_scope != auth_scope:
        return FieldDecision(name, "config", configured, "规则作用域：站点、登录主体或认证契约已变，保留但不采用")
    if cached.expired(now_iso=now_iso):
        return FieldDecision(
            name, "config", configured, f"规则3：覆盖层值已过期（ttl={cached.ttl}s，写于 {cached.updated_at or '未知'}）"
        )

    if cached.config_hash:
        if cached.config_hash != _hash(configured):
            return FieldDecision(
                name, "config", configured,
                f"规则4a：{group} 组配置在缓存写入后被改动（摘要不一致）",
            )
    else:
        # 无记录摘要（旧缓存迁移而来）：只能靠时间。配置文件在缓存写入之后被动过、
        # 且配置里该字段非空时，认为用户提供了更新的值。
        # 比较基准优先取**字段级** updated_at（最精确），条目级与迁移时间只是兜底。
        written_at = cached.updated_at or entry_updated_at or entry_accounts_mtime
        if configured and newer_than(accounts_mtime, written_at):
            return FieldDecision(
                name, "config", configured,
                f"规则4b：配置文件（{accounts_mtime}）晚于缓存（{written_at or '未知'}），采用配置值",
            )

    return FieldDecision(
        name, "overlay", cached.value,
        f"规则5：采用覆盖层值（来源 {cached.origin}，写于 {cached.updated_at or '未知'}）",
        origin=cached.origin,
    )


_CREDENTIAL_MISSING = object()
_OAUTH_PROVIDERS = frozenset({"linuxdo", "github"})
_OAUTH_MISSING = object()
_OAUTH_CORRUPT = object()


def _read_overlay_document(path: Path) -> dict[str, Any]:
    target = Path(path)
    if not target.exists():
        return {"version": OVERLAY_VERSION, "entries": {}}
    try:
        document = json.loads(target.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        raise ValueError("overlay cache is corrupted") from None
    if not isinstance(document, Mapping):
        raise ValueError("overlay cache is corrupted")
    return dict(document)


def _credential_raw_entry(document: Mapping[str, Any], account_id: str, name: str) -> Any:
    if "entries" not in document:
        return _CREDENTIAL_MISSING
    entries = document["entries"]
    if not isinstance(entries, Mapping):
        raise ValueError("overlay entries container is corrupted")
    if account_id not in entries:
        return _CREDENTIAL_MISSING
    entry = entries[account_id]
    if not isinstance(entry, Mapping):
        raise ValueError("overlay account container is corrupted")
    if "fields" not in entry:
        return _CREDENTIAL_MISSING
    fields = entry["fields"]
    if not isinstance(fields, Mapping):
        raise ValueError("overlay fields container is corrupted")
    return fields.get(name, _CREDENTIAL_MISSING)


def _credential_revision(raw: Any) -> str:
    if raw is _CREDENTIAL_MISSING:
        return "missing"
    encoded = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _merge_entry_payload(raw: Any, before: OverlayEntry, after: OverlayEntry) -> dict[str, Any]:
    """只替换实际改动的字段；无关写入不得归一化原始凭据或丢失扩展元数据。"""
    payload = dict(_as_map(raw))
    if "fields" not in payload or before.fields != after.fields:
        fields = dict(_as_map(payload.get("fields")))
        for name in before.fields.keys() - after.fields.keys():
            fields.pop(name, None)
        for name, value in after.fields.items():
            if value == before.fields.get(name):
                continue
            item = dict(_as_map(fields.get(name)))
            item.update(value.to_payload())
            if not value.tombstone:
                item.pop("tombstone", None)
            fields[name] = item
        payload["fields"] = fields
    for name in ("flow", "learning", "health", "identity", "scoped_flow"):
        if name not in payload or getattr(before, name) != getattr(after, name):
            payload[name] = dict(getattr(after, name))
    for name in ("identity_scope", "identity_revision_nonce"):
        if name not in payload or getattr(before, name) != getattr(after, name):
            payload[name] = getattr(after, name)
    payload["accounts_mtime"] = after.accounts_mtime
    payload["updated_at"] = after.updated_at
    return payload


def _oauth_states(document: Mapping[str, Any]) -> dict[str, Any]:
    states = document.get("oauth_states")
    if states is None:
        return {}
    if not isinstance(states, Mapping):
        raise ValueError("oauth_states container is corrupted")
    return dict(states)


def _oauth_raw_entry(document: Mapping[str, Any], provider: str, account: str) -> Any:
    states = _oauth_states(document)
    if provider not in states:
        return _OAUTH_MISSING
    bucket = states[provider]
    if not isinstance(bucket, Mapping):
        raise ValueError("oauth provider container is corrupted")
    if "accounts" not in bucket:
        return _OAUTH_MISSING
    accounts = bucket["accounts"]
    if not isinstance(accounts, Mapping):
        raise ValueError("oauth accounts container is corrupted")
    return accounts.get(account, _OAUTH_MISSING)


def _oauth_field_entry(raw: Any) -> FieldEntry | None:
    if raw is _OAUTH_MISSING or not isinstance(raw, Mapping):
        return None
    value = raw.get("value") or raw.get("state")
    ttl = raw.get("ttl")
    stamp = raw.get("updated_at")
    basis = raw.get("config_hash")
    if (
        not isinstance(value, str)
        or not value.strip()
        or type(ttl) is not int
        or ttl <= 0
        or not isinstance(stamp, str)
        or age_seconds(stamp, now_iso=stamp) is None
        or not isinstance(basis, str)
        or not basis.strip()
    ):
        return None
    payload = dict(raw)
    payload["value"] = str(value).strip()
    return FieldEntry.from_payload(payload)


def _oauth_revision(raw: Any) -> str:
    if raw is _OAUTH_MISSING:
        return ""
    try:
        encoded = json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        encoded = repr(raw)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _hash(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "sha256:empty"
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _as_map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _safe_identity(value: Mapping[str, Any]) -> dict[str, str]:
    """站点身份元数据严格白名单；token/URL/任意脚本内容不能混入。"""
    identity = {}
    user_id = value.get("user_id")
    if not isinstance(user_id, bool) and isinstance(user_id, (str, int)):
        text = str(user_id).strip()
        if len(text) <= 32 and text.isdecimal() and int(text) > 0:
            identity["user_id"] = str(int(text))
    return identity


def _credential_group_revision(document: Mapping[str, Any], account_id: str) -> str:
    raw_fields = {name: _credential_raw_entry(document, account_id, name) for name in CREDENTIAL_FIELDS}
    entries = document.get("entries")
    entry = entries.get(account_id) if isinstance(entries, Mapping) else None
    raw = _as_map(entry)
    if ("identity" in raw and not isinstance(raw["identity"], Mapping)) or (
        "identity_scope" in raw and not isinstance(raw["identity_scope"], str)
    ):
        raise ValueError("overlay authentication metadata is corrupted")
    payload = {
        "fields": {name: (None if value is _CREDENTIAL_MISSING else value) for name, value in raw_fields.items()},
        "identity": raw.get("identity"), "identity_scope": raw.get("identity_scope"),
        "identity_revision_nonce": raw.get("identity_revision_nonce"),
    }
    return _hash(payload)


def _group_revision_or_empty(document: Mapping[str, Any], account_id: str) -> str:
    """整组回执用：元数据损坏时返回空串（未知），调用方据此不推进基线，也不让写入失败。"""
    try:
        return _credential_group_revision(document, account_id)
    except Exception:
        return ""
