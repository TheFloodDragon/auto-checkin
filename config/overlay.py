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
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from core.account import (
    CREDENTIAL_FIELDS,
    CREDENTIAL_GROUPS,
    AccountSpec,
    CredentialSet,
    ResolvedAccount,
)
from core.flow import Discovery
from core.timebase import age_seconds, newer_than, utc_iso
from . import paths

__all__ = [
    "CachePolicy",
    "FieldDecision",
    "FieldEntry",
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

    def expired(self, *, now_iso: str = "") -> bool:
        if self.ttl <= 0:
            return False
        age = age_seconds(self.updated_at, now_iso=now_iso)
        if age is None:
            return True          # 无时间戳 = 无法证明还新鲜
        if age < 0:
            return True          # 未来时间戳（时钟回拨/手工改过）不可信
        return age > self.ttl

    def to_payload(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "updated_at": self.updated_at,
            "ttl": int(self.ttl),
            "origin": self.origin,
            "config_hash": self.config_hash,
        }

    @classmethod
    def from_payload(cls, payload: Any) -> "FieldEntry | None":
        if isinstance(payload, str):
            # 旧 token_cache.json 的形态：字段直接是字符串，没有任何元数据。
            return cls(value=payload) if payload.strip() else None
        if not isinstance(payload, Mapping):
            return None
        value = str(payload.get("value") or "").strip()
        if not value:
            return None
        try:
            ttl = int(payload.get("ttl", 0))
        except (TypeError, ValueError):
            ttl = 0
        return cls(
            value=value,
            updated_at=str(payload.get("updated_at") or ""),
            ttl=ttl,
            origin=str(payload.get("origin") or "runtime"),
            config_hash=str(payload.get("config_hash") or ""),
        )


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

    def to_payload(self) -> dict[str, Any]:
        return {
            "fields": {name: entry.to_payload() for name, entry in self.fields.items()},
            "flow": dict(self.flow),
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
        if document is None:
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

    # -- 核心：叠加到配置 --
    def apply(
        self,
        spec: AccountSpec,
        *,
        explicit: Iterable[str] = (),
        now_iso: str = "",
    ) -> ResolvedAccount:
        """按五条规则逐字段判定，产出可执行的账号视图。

        规则（顺序求值，先命中先生效）：

        1. ``policy=ignore``                     → 完全不叠加。
        2. 调用方**显式**提供该字段（含显式空串）→ 配置胜。
        3. 缓存值已过 TTL                        → 配置胜（缓存保留不删）。
        4. 配置值在缓存写入之后被改动过           → 配置胜。
           判据一：配置值摘要 ≠ 写缓存时记录的摘要（值确实变了）；
           判据二：无记录摘要（旧缓存迁移而来）时退回时间比较——
                   ACCOUNTS.json 的 mtime 晚于缓存 ``updated_at`` 且配置值非空。
        5. 其余                                  → 缓存胜。
        """
        explicit_fields = {str(item) for item in explicit if str(item) in CREDENTIAL_FIELDS}
        decisions: dict[str, FieldDecision] = {}
        values: dict[str, str] = {}

        entry = OverlayEntry() if self.policy == CachePolicy.IGNORE else self.entry(spec.id)
        ignore_all = self.policy == CachePolicy.IGNORE

        for name in CREDENTIAL_FIELDS:
            configured = spec.credentials.get(name)
            cached = entry.fields.get(name)
            decision = _decide(
                name,
                configured=configured,
                cached=cached,
                explicit=name in explicit_fields,
                ignore_all=ignore_all,
                entry_updated_at=entry.updated_at,
                accounts_mtime=self._accounts_mtime,
                entry_accounts_mtime=entry.accounts_mtime,
                now_iso=now_iso,
            )
            decisions[name] = decision
            values[name] = decision.value

        origins = {
            name: (f"overlay:{d.origin or 'runtime'}" if d.from_overlay else ("explicit" if name in explicit_fields else "config"))
            for name, d in decisions.items()
        }
        return ResolvedAccount(
            spec=spec,
            credentials=CredentialSet(**values),
            origins=MappingProxyType(origins),
            learned_flow=MappingProxyType({} if ignore_all else dict(entry.flow)),
            health=MappingProxyType({} if ignore_all else dict(entry.health)),
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
            )
            state = "空" if not decision.value else f"{len(decision.value)} 字符"
            lines.append(f"{name}: 采用{decision.winner}（{state}）— {decision.rule}")
        return lines

    # -- 写入 --
    def record_credentials(
        self,
        spec: AccountSpec,
        *,
        origin: str = "runtime",
        ttl: Mapping[str, int] | None = None,
        **fields: str,
    ) -> bool:
        """写回运行中刷新到的凭据。只写传入的非空字段。

        ``config_hash`` 记录**当前配置**里该字段的摘要，这是规则 4 判据一的锚点：
        下次读取时若配置摘要与它不同，就说明用户在这之后改过配置。
        """
        clean = {
            key: str(value or "").strip()
            for key, value in fields.items()
            if key in CREDENTIAL_FIELDS and str(value or "").strip()
        }
        if not clean or self.policy == CachePolicy.READONLY:
            return False
        ttl_map = dict(TTL_DEFAULTS)
        ttl_map.update({k: int(v) for k, v in (ttl or {}).items() if k in CREDENTIAL_FIELDS})
        stamp = utc_iso()

        def mutate(entry: OverlayEntry) -> OverlayEntry:
            merged = dict(entry.fields)
            for key, value in clean.items():
                merged[key] = FieldEntry(
                    value=value,
                    updated_at=stamp,
                    ttl=ttl_map.get(key, 0),
                    origin=origin,
                    config_hash=_hash(spec.credentials.get(key)),
                )
            return replace(entry, fields=MappingProxyType(merged))

        return self._update(spec.id, mutate)

    def record_flow(self, account_id: str, discoveries: Iterable[Discovery]) -> bool:
        """写回探测得出的流程结论，供下次 ``auto`` 直接复用。"""
        items = [d for d in discoveries if d and d.value]
        if not items or self.policy == CachePolicy.READONLY:
            return False

        def mutate(entry: OverlayEntry) -> OverlayEntry:
            merged = dict(entry.flow)
            for discovery in items:
                payload = discovery.to_payload()
                payload.setdefault("probed_at", utc_iso())
                if not payload.get("probed_at"):
                    payload["probed_at"] = utc_iso()
                merged[discovery.stage] = payload
            return replace(entry, flow=MappingProxyType(merged))

        return self._update(account_id, mutate)

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
    def _update(self, account_id: str, mutate: Any) -> bool:
        key = str(account_id)
        if not key:
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with paths.file_lock(self.path):
                # 锁内重新读盘：并发任务各自持有内存快照，直接写会互相覆盖。
                document = paths.read_json(self.path, default=None) or {"entries": {}}
                raw_entries = document.get("entries")
                entries = dict(raw_entries) if isinstance(raw_entries, Mapping) else {}
                entry = OverlayEntry.from_payload(entries.get(key))
                updated = mutate(entry)
                updated = replace(
                    updated,
                    updated_at=utc_iso(),
                    accounts_mtime=self._accounts_mtime or updated.accounts_mtime,
                )
                entries[key] = updated.to_payload()
                paths.atomic_write_json(
                    self.path, {"version": OVERLAY_VERSION, "entries": entries}
                )
                self._entries[key] = updated
                self._loaded = True
        except Exception:
            return False
        return True

    def _migrate_legacy(self) -> dict[str, Any]:
        """把旧 ``token_cache.json`` 迁移成 v3 文档（一次性，保留原文件）。

        旧键是 ``base_url|name`` 拼接串，新键是账号 id。这里只做形态迁移并把旧键
        原样保留在 ``legacy_key`` 里；键的重映射由 ``migrate_keys()`` 在拿到账号
        清单后完成——覆盖层自己不认识账号身份，硬猜只会错配。
        """
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
                        # 刻意留空 config_hash：迁移条目走规则 4 的判据二（时间比较），
                        # 这正是旧数据唯一能提供的信息。
                        "config_hash": "",
                    }
            if not fields:
                continue
            entries[f"legacy:{key}"] = {
                "fields": fields,
                "flow": {},
                "learning": {},
                "health": {},
                "accounts_mtime": "",
                "updated_at": stamp,
            }
        document = {"version": OVERLAY_VERSION, "entries": entries}
        if entries:
            try:
                paths.atomic_write_json(self.path, document)
            except Exception:
                pass
        return document

    def migrate_keys(self, mapping: Mapping[str, str]) -> int:
        """把 ``legacy:<base_url|name>`` 条目改挂到账号 id 上。

        ``mapping`` 由配置加载器提供：``{"<base_url>|<name>": "<account_id>"}``。
        已存在同 id 的新条目时不覆盖——新数据永远优先于迁移来的旧数据。
        """
        self.load()
        moved = 0
        for legacy_key, account_id in mapping.items():
            source = f"legacy:{legacy_key}"
            if source not in self._entries or account_id in self._entries:
                continue
            entry = self._entries.pop(source)
            self._entries[account_id] = entry
            moved += 1
        if moved:
            try:
                with paths.file_lock(self.path):
                    paths.atomic_write_json(
                        self.path,
                        {
                            "version": OVERLAY_VERSION,
                            "entries": {k: v.to_payload() for k, v in self._entries.items()},
                        },
                    )
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
) -> FieldDecision:
    group = CREDENTIAL_GROUPS.get(name, name)

    if ignore_all:
        return FieldDecision(name, "config", configured, "规则1：cache_policy=ignore，不叠加覆盖层")
    if explicit:
        return FieldDecision(name, "config", configured, "规则2：调用方显式提供（含显式清空）")
    if cached is None or not cached.value:
        return FieldDecision(name, "config", configured, "规则5：覆盖层无该字段")
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


def _hash(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "sha256:empty"
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _as_map(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}
