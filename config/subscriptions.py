"""Clash/节点订阅的受限解析与代理组原子合并。

http / https / socks5 节点写成 ``url``，HTTP 客户端与浏览器直接使用；vless / anytls / vmess /
trojan / ss / hysteria2 / tuic 节点写成 ``clash`` 出站映射，运行时由本地 mihomo 桥接。
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from core.account import slugify
from core.errors import ConfigError
from core.masking import mask_secrets
from core.timebase import utc_iso
from net.subscriptions import read_source

from .proxies import (
    BRIDGED_TYPES,
    BridgedProxy,
    bridge_secrets,
    canonical_outbound,
    parse_bridge_outbound,
    parse_node_endpoint,
    parse_proxy_url,
)

try:  # PyYAML 是运行依赖；保留友好错误，便于未安装时启动 GUI。
    import yaml
except ImportError:  # pragma: no cover - 由依赖安装决定
    yaml = None

__all__ = [
    "BRIDGED_SCHEMES",
    "NATIVE_SCHEMES",
    "SUPPORTED_FORMATS",
    "SUPPORTED_SCHEMES",
    "SourceSpec",
    "ProxyCandidate",
    "SubscriptionImport",
    "SubscriptionImporter",
    "merge_proxy_import",
    "parse_node_link",
    "parse_subscription_text",
    "source_id_for",
    "subscription_update_summary",
    "select_policy_nodes",
]

SUPPORTED_FORMATS = ("auto", "clash_yaml", "base64", "uri")
NATIVE_SCHEMES = frozenset({"http", "https", "socks5"})
#: 分享链接 scheme → mihomo 出站类型。
BRIDGED_SCHEMES = frozenset({"vless", "anytls", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic"})
SUPPORTED_SCHEMES = NATIVE_SCHEMES | BRIDGED_SCHEMES
_ACCEPTED_STATUSES = frozenset({"accepted", "browser_only", "bridged"})
_POLICY_TYPES = frozenset({"select", "url-test", "fallback", "load-balance", "relay", "direct", "reject"})
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/_=-]+$")
_TOKEN_RE = re.compile(r"^[a-z0-9-]{1,16}$")
_MAX_TEXT_BYTES = 8 * 1024 * 1024
_USERINFO_KEYS = ("upload", "download", "total", "expire")


@dataclass(frozen=True, slots=True)
class SourceSpec:
    """受限来源描述；单个节点 URL 不经过网络读取。"""

    kind: str
    format: str
    source: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProxyCandidate:
    """一个候选节点；URL / 出站映射只用于最终配置，不进入 repr 或展示字段。"""

    name: str
    protocol: str
    display: str
    status: str
    reason: str = ""
    capabilities: tuple[str, ...] = ()
    source_key: str = ""
    source_id: str = ""
    node_id: str = ""
    url: str = field(default="", repr=False)
    clash: Mapping[str, Any] | None = field(default=None, repr=False)
    insecure: bool = False

    @property
    def importable(self) -> bool:
        return self.status in _ACCEPTED_STATUSES and (bool(self.url) or self.clash is not None)

    @property
    def bridged(self) -> bool:
        return self.clash is not None

    @property
    def identity(self) -> str:
        """连接内容身份；去重时必须同时比较名称，不能丢弃别名。"""
        if self.clash is not None:
            return "clash:" + canonical_outbound(self.clash)
        return "url:" + self.url

    @property
    def secrets(self) -> tuple[str, ...]:
        if self.clash is not None:
            return bridge_secrets(self.clash)
        if self.url:
            try:
                return parse_proxy_url(self.url).secrets
            except ConfigError:
                return ()
        return ()

    def to_payload(self) -> dict[str, Any]:
        if not self.importable:
            raise ConfigError("当前候选节点不可导入")
        payload: dict[str, Any] = {"id": self.node_id, "name": self.name}
        if self.clash is not None:
            payload["clash"] = deepcopy(dict(self.clash))
        else:
            payload["url"] = self.url
        payload.update(
            enabled=True,
            source_id=self.source_id,
            source_key=self.source_key,
            capabilities=list(self.capabilities),
        )
        return payload


@dataclass(frozen=True, slots=True)
class SubscriptionImport:
    """导入预览；正文仅存于隐藏的内存字段，合并配置不持久化原文。"""

    source_id: str
    source_label: str
    group_id: str
    group_name: str
    format: str
    candidates: tuple[ProxyCandidate, ...] = ()
    nodes: tuple[dict[str, Any], ...] = field(default=(), repr=False)
    notices: tuple[str, ...] = ()
    title: str = ""
    userinfo: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    content_hash: str = ""
    content: str = field(default="", repr=False)
    policy_groups: tuple[Mapping[str, Any], ...] = ()
    providers: tuple[Mapping[str, Any], ...] = ()
    #: 目标组当前节点来自本订阅，且在新内容中找不到对应节点（更新后将变为未选择）。
    selection_lost: bool = False
    #: 文本来源不可绑定订阅；content 只供内存中的预览编辑。
    source_kind: str = ""
    #: 离线解析未展开远端 provider 时为 False；合并必须拒绝部分覆盖。
    providers_complete: bool = True

    @property
    def importable_count(self) -> int:
        return len(self.nodes)

    @property
    def accepted_count(self) -> int:
        return sum(item.status == "accepted" for item in self.candidates)

    @property
    def browser_only_count(self) -> int:
        return sum(item.status == "browser_only" for item in self.candidates)

    @property
    def bridged_count(self) -> int:
        return sum(item.status == "bridged" for item in self.candidates)

    @property
    def duplicate_count(self) -> int:
        return sum(item.status == "duplicate" for item in self.candidates)

    @property
    def skipped_count(self) -> int:
        return sum(item.status in {"unsupported", "invalid", "conflict"} for item in self.candidates)


class SubscriptionImporter:
    """组合受限来源读取与离线解析；正文仅交给内存预览，不记录或持久化。"""

    def import_source(
        self,
        spec: SourceSpec,
        *,
        existing_group: Mapping[str, Any] | None = None,
        source_id: str | None = None,
    ) -> SubscriptionImport:
        kind = str(spec.kind or "").strip().lower()
        format = str(spec.format or "auto").strip().lower()
        source = str(spec.source or "")
        if kind != "text":
            source = source.strip()
        title = ""
        userinfo: Mapping[str, int] = {}
        fetched = None
        if kind in {"node", "text"}:
            fetched_text = source
            source_label = "粘贴内容" if kind == "text" else _safe_source_label(source)
        elif kind in {"url", "file"}:
            fetched = read_source(source, kind=kind)
            fetched_text = fetched.text
            source_label = fetched.label
            title = str(getattr(fetched, "title", "") or "")
            userinfo = getattr(fetched, "userinfo", None) or {}
        else:
            raise ConfigError("订阅来源必须是链接、单个节点链接、粘贴文本或文件")
        _checked_text_size(fetched_text)
        group = existing_group if isinstance(existing_group, Mapping) else {}
        default_source_id = (
            "source-" + hashlib.sha256(fetched_text.encode("utf-8")).hexdigest()[:16]
            if kind == "text" else source_id_for(source)
        )
        result = parse_subscription_text(
            fetched_text,
            source_id=str(source_id or "").strip() or default_source_id,
            source_label=source_label,
            group_name=str(group.get("name") or ""),
            group_id=str(group.get("id") or ""),
            format="uri" if kind == "node" else format,
            existing_group=group,
            title=title,
            userinfo=userinfo,
            content_hash=str(getattr(fetched, "content_hash", "") or "") if kind in {"url", "file"} else "",
        )
        if not result.providers_complete:
            expanded = _expand_http_providers(_yaml_text_for_metadata(fetched_text, format))
            result = parse_subscription_text(
                expanded,
                source_id=result.source_id,
                source_label=result.source_label,
                group_name=result.group_name,
                group_id=result.group_id,
                format="clash_yaml",
                existing_group=group,
                title=title,
                userinfo=userinfo,
                content_hash=result.content_hash,
            )
            if not result.providers_complete:
                raise ConfigError("provider 未完整展开，未导入任何节点")
        return replace(result, source_kind=kind, content=fetched_text)


class _YamlUnavailable(ConfigError):
    pass


class _UriInvalid(ValueError):
    """分享链接内容有误；``reason`` 是不含字段值的固定文案。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _UriUnsupported(_UriInvalid):
    pass


def source_id_for(reference: str) -> str:
    """只返回哈希来源 ID；订阅 URL/文件路径永不写入节点字段。"""
    text = str(reference or "").strip()
    if not text:
        text = "manual-source"
    return "source-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def parse_node_link(value: str) -> ProxyCandidate:
    """解析单条节点链接（GUI 节点对话框用）；不访问网络。"""
    text = str(value or "").strip()
    if not text or any(char.isspace() or ord(char) < 32 for char in text):
        return _invalid_candidate("节点", "节点链接格式无效")
    return _candidate_from_uri(text)


def parse_subscription_text(
    text: str,
    *,
    source_id: str,
    source_label: str,
    group_name: str = "",
    group_id: str = "",
    format: str = "auto",
    existing_group: Mapping[str, Any] | None = None,
    title: str = "",
    userinfo: Mapping[str, Any] | None = None,
    content_hash: str = "",
) -> SubscriptionImport:
    """解析 Clash YAML、Base64 URI 列表或逐行节点 URI。

    ``existing_group`` 只用于预览去重：同一来源的旧节点会被视为可更新，手工节点和
    其它来源节点仍然参与重复检查。
    """
    _checked_text_size(text)
    mode = str(format or "auto").strip().lower()
    if mode not in SUPPORTED_FORMATS:
        raise ConfigError("导入格式必须是自动识别、Clash YAML、Base64 或节点链接")
    source_id = str(source_id or "").strip() or source_id_for("manual-source")
    source_label = _safe_source_label(source_label)
    title = _safe_title(title)
    content_hash = str(content_hash or "").strip() or hashlib.sha256(text.encode("utf-8")).hexdigest()
    group_name = str(group_name or "").strip() or title or source_label or "导入节点"
    group_id = str(group_id or "").strip() or (
        "imported-" + source_id.removeprefix("source-")[:12]
        if source_id.startswith("source-") else slugify(group_name, fallback="imported")
    )

    parsed_format, raw_candidates, parse_notices = _parse_candidates(text, mode)
    policy_groups: tuple[Mapping[str, Any], ...] = ()
    providers: tuple[Mapping[str, Any], ...] = ()
    if parsed_format == "clash_yaml":
        policy_groups, providers = _clash_metadata(_yaml_text_for_metadata(text, mode))
    existing = existing_group if isinstance(existing_group, Mapping) else {}
    existing_nodes = existing.get("proxies", [])
    existing_nodes = list(existing_nodes) if isinstance(existing_nodes, list) else []
    preserved_nodes = [
        item for item in existing_nodes
        if isinstance(item, Mapping) and str(item.get("source_id") or "") != source_id
    ]
    existing_keys = _existing_identities(preserved_nodes)
    existing_ids = {
        str(item.get("id") or "").strip()
        for item in preserved_nodes
        if str(item.get("id") or "").strip()
    }
    # 旧来源的 ID 也预留，避免新别名占用已删除节点的 ID；精确匹配时复用旧 ID。
    old_by_content: dict[tuple[str, str], list[str]] = {}
    used_ids = set(existing_ids)
    for item in existing_nodes:
        if not isinstance(item, Mapping) or str(item.get("source_id") or "") != source_id:
            continue
        old_id = str(item.get("id") or "").strip()
        if old_id:
            used_ids.add(old_id)
            old_by_content.setdefault(_node_content(item), []).append(old_id)
    assigned_ids = set(existing_ids)
    seen_keys: set[tuple[str, str]] = set()
    candidates: list[ProxyCandidate] = []
    nodes: list[dict[str, Any]] = []
    for candidate in raw_candidates:
        candidate = replace(candidate, source_id=source_id)
        if not candidate.importable:
            candidates.append(candidate)
            continue
        key = (candidate.name, candidate.identity)
        if key in seen_keys or key in existing_keys:
            candidates.append(replace(candidate, status="duplicate", reason="同名且连接内容重复", node_id=""))
            continue
        seen_keys.add(key)
        old_id = next((value for value in old_by_content.get(key, ()) if value not in assigned_ids), "")
        base_id = _node_id(candidate, set())
        if not old_id and base_id in existing_ids:
            candidates.append(replace(candidate, status="conflict", reason="节点 ID 与现有节点内容冲突", node_id=""))
            continue
        node_id = old_id or _node_id(candidate, used_ids)
        assigned_ids.add(node_id)
        used_ids.add(node_id)
        accepted = replace(candidate, node_id=node_id)
        candidates.append(accepted)
        nodes.append(accepted.to_payload())

    selection_lost = False
    selected = str(existing.get("selected") or "")
    if selected:
        _, selection_lost = _carry_selection(existing_nodes, selected, source_id, nodes)

    notices: list[str] = list(parse_notices)
    if not candidates:
        notices.append("没有识别到节点；请检查来源内容或导入格式。")
    if any(item.status == "bridged" for item in candidates):
        notices.append("VLESS / AnyTLS 等节点需要本地 mihomo 桥接：运行时自动在 127.0.0.1 启动；"
                       "找不到 mihomo 时报告配置错误，不会改用直连。")
    if any(item.insecure and item.importable for item in candidates):
        notices.append("部分节点自身配置了跳过证书校验，已按原样保留；请确认信任该订阅来源。")
    if any(item.status == "unsupported" for item in candidates):
        notices.append("部分节点协议或选项当前不能使用（如 SSR、WireGuard、策略组），已跳过；不会改写成其它协议。")
    if any(item.status == "browser_only" for item in candidates):
        notices.append("SOCKS5 节点仅供浏览器流程使用，HTTP 任务选择后会报告配置不兼容。")
    if policy_groups:
        notices.append("Clash 策略组已识别；当前只支持手动选择可导入成员，不会自动测速、轮换或分流。")
    providers_complete = all(item.get("resolved", False) for item in providers)
    if providers:
        notices.append("proxy-providers 仅在显式导入时读取，不会让 mihomo 在后台同步。")
    if not providers_complete:
        notices.append("provider 尚未完整展开；离线结果不能合并，以免部分覆盖旧节点。请显式重新导入来源。")
    if any(item.status == "duplicate" for item in candidates):
        notices.append("重复节点未再次写入；同一来源的旧节点会在确认更新时替换。")
    if any(item.status == "conflict" for item in candidates):
        notices.append("节点 ID 与现有不同内容冲突，已拒绝覆盖；请修改名称或先处理现有节点。")
    if selection_lost:
        notices.append("当前节点在新订阅中已不存在：更新后该组将变为未选择，引用账号需重新选择节点，不会自动切换。")
    return SubscriptionImport(
        source_id=source_id,
        source_label=source_label,
        group_id=group_id,
        group_name=group_name,
        format=parsed_format,
        candidates=tuple(candidates),
        nodes=tuple(nodes),
        notices=tuple(dict.fromkeys(notices)),
        title=title,
        userinfo=MappingProxyType(_safe_userinfo(userinfo)),
        content_hash=content_hash,
        content=text,
        policy_groups=tuple(MappingProxyType(dict(item)) for item in policy_groups),
        providers=tuple(MappingProxyType(dict(item)) for item in providers),
        selection_lost=selection_lost,
        providers_complete=providers_complete,
    )


def merge_proxy_import(
    payload: Mapping[str, Any],
    result: SubscriptionImport,
    *,
    target_group_id: str | None = None,
    target_group_name: str | None = None,
    subscription: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """将导入节点合并进草稿；只替换同来源节点，手工节点保持不动。

    ``subscription``（含 ``url`` / ``format``）表示把该订阅绑定到目标组，后续可一键更新。
    一个订阅只能绑定一个组，一个组也只能绑定一个订阅；冲突时整体拒绝。
    """
    if not result.providers_complete:
        raise ConfigError("provider 未完整展开，不能部分覆盖现有节点；请重新导入来源")
    if result.source_kind == "text" and subscription is not None:
        raise ConfigError("粘贴内容不能绑定为订阅链接，未改变草稿")
    if not result.nodes:
        if any(candidate.status == "conflict" for candidate in result.candidates):
            raise ConfigError("节点 ID 与现有节点内容冲突，未覆盖现有节点")
        raise ConfigError("没有可导入节点，未改变草稿")
    updated = deepcopy(dict(payload))
    groups = updated.setdefault("proxy_groups", [])
    if not isinstance(groups, list):
        raise ConfigError("代理组配置无效，未改变草稿")
    group_id = str(target_group_id or result.group_id).strip() or result.group_id
    group = next((item for item in groups if isinstance(item, dict) and item.get("id") == group_id), None)
    if group is None:
        old_nodes: list[Any] = []
        selected = ""
    else:
        if not isinstance(group.get("proxies", []), list):
            raise ConfigError("目标代理组节点列表无效，未改变草稿")
        old_nodes = list(group.get("proxies", []))
        selected = str(group.get("selected") or "")

    if subscription is not None:
        for other in groups:
            if not isinstance(other, dict) or other is group:
                continue
            if _bound_source(other) == result.source_id:
                name = mask_secrets(str(other.get("name") or other.get("id") or ""))[:80]
                raise ConfigError(f"该订阅已绑定到代理组「{name}」；请在代理页对该组使用“从订阅更新”")
        if group is not None and _bound_source(group) not in ("", result.source_id):
            raise ConfigError("目标代理组已绑定其它订阅；请先在组设置中解除绑定，或新建代理组")
        meta = _subscription_meta(subscription, result, group)
    else:
        meta = None

    incoming_ids: set[str] = set()
    existing_by_id = {
        str(node.get("id")): node
        for node in old_nodes
        if isinstance(node, Mapping)
        and str(node.get("source_id") or "") != result.source_id
        and str(node.get("id") or "")
    }
    for node in result.nodes:
        if not isinstance(node, Mapping) or not str(node.get("id") or "").strip():
            raise ConfigError("导入节点缺少有效 ID，未改变草稿")
        node_id = str(node["id"])
        if node_id in incoming_ids:
            raise ConfigError("导入结果包含重复节点 ID，未改变草稿")
        incoming_ids.add(node_id)
        existing = existing_by_id.get(node_id)
        if existing is not None:
            if _node_content(existing) != _node_content(node):
                raise ConfigError("节点 ID 与现有节点内容冲突，未覆盖现有节点")
            raise ConfigError("节点 ID 已存在，未重复写入现有节点")

    if group is None:
        group = {
            "id": group_id,
            "name": str(target_group_name or result.group_name).strip() or result.group_name,
            "enabled": True,
            "selected": "",
            "proxies": [],
        }
        groups.append(group)
    new_nodes = deepcopy(list(result.nodes))
    new_selected, _lost = _carry_selection(old_nodes, selected, result.source_id, new_nodes)
    kept = [
        node for node in old_nodes
        if not isinstance(node, Mapping) or str(node.get("source_id") or "") != result.source_id
    ]
    group["proxies"] = kept + new_nodes
    group["selected"] = new_selected
    if meta is not None:
        group["subscription"] = meta
    elif _bound_source(group) == result.source_id:
        group["subscription"] = _subscription_meta(group["subscription"], result, group)
    return updated


# ── 选择保留与订阅元数据 ────────────────────────────────────────────────────
def _carry_selection(
    old_nodes: list[Any], selected: str, source_id: str, new_nodes: list[Mapping[str, Any]],
) -> tuple[str, bool]:
    """返回 (更新后的当前节点 ID, 是否因更新丢失)。

    先按同名同连接匹配（兼容旧版仅连接哈希的 source_key），再按唯一同名节点匹配。
    别名共享旧 source_key 也绝不跨名称切换；非本来源的当前节点原样保留。
    """
    if not selected:
        return "", False
    old = next((node for node in old_nodes if isinstance(node, Mapping) and node.get("id") == selected), None)
    if old is None:
        return "", False
    if str(old.get("source_id") or "") != source_id:
        return selected, False
    name = str(old.get("name") or "")
    same = [node for node in new_nodes if name and str(node.get("name") or "") == name]
    exact = [node for node in same if _node_content(node) == _node_content(old)]
    if len(exact) == 1:
        return str(exact[0].get("id") or ""), False
    old_same = [
        node for node in old_nodes
        if isinstance(node, Mapping) and str(node.get("source_id") or "") == source_id
        and str(node.get("name") or "") == name
    ]
    if len(same) == 1 and len(old_same) == 1:
        return str(same[0].get("id") or ""), False
    return "", True


def _bound_source(group: Mapping[str, Any]) -> str:
    bound = group.get("subscription")
    if isinstance(bound, Mapping):
        return str(bound.get("source_id") or "")
    return ""


def _subscription_meta(
    subscription: Mapping[str, Any], result: SubscriptionImport, group: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(subscription, Mapping):
        raise ConfigError("订阅绑定信息无效，未改变草稿")
    url = str(subscription.get("url") or "").strip()
    if not url:
        raise ConfigError("绑定订阅需要填写订阅链接，未改变草稿")
    previous = group.get("subscription") if isinstance(group, Mapping) else None
    meta = deepcopy(dict(previous)) if isinstance(previous, Mapping) and _bound_source(group) == result.source_id else {}
    fmt = str(subscription.get("format") or meta.get("format") or "auto").strip().lower()
    meta.update(
        url=url,
        format=fmt if fmt in SUPPORTED_FORMATS else "auto",
        source_id=result.source_id,
        updated_at=utc_iso(),
    )
    if result.title:
        meta["title"] = result.title
    if result.userinfo:
        meta["userinfo"] = dict(result.userinfo)
    if result.content_hash:
        meta["content_hash"] = result.content_hash
    meta["node_count"] = result.importable_count
    meta["policy_group_count"] = len(result.policy_groups)
    meta["provider_count"] = len(result.providers)
    return meta


def _node_content(node: Mapping[str, Any]) -> tuple[str, str]:
    name = str(node.get("name") or "")
    try:
        endpoint = parse_node_endpoint(node)
    except ConfigError:
        clash = node.get("clash")
        if isinstance(clash, Mapping):
            return name, "clash:" + canonical_outbound(clash)
        return name, "url:" + str(node.get("url") or "")
    if isinstance(endpoint, BridgedProxy):
        return name, "clash:" + canonical_outbound(endpoint.outbound)
    return name, "url:" + endpoint.url


# ── 格式识别 ────────────────────────────────────────────────────────────────
def _parse_candidates(text: str, mode: str) -> tuple[str, list[ProxyCandidate], list[str]]:
    stripped = text.lstrip("\ufeff").strip()
    if not stripped:
        raise ConfigError("订阅内容为空")
    if mode == "uri":
        return "uri", _parse_uri_lines(stripped), []
    if mode == "base64":
        decoded = _decode_base64(stripped)
        return _parse_decoded(decoded)
    if mode == "clash_yaml":
        return ("clash_yaml", *_parse_yaml(stripped))

    if _looks_like_uri_lines(stripped):
        return "uri", _parse_uri_lines(stripped), []
    if _looks_like_yaml(stripped):
        return ("clash_yaml", *_parse_yaml(stripped))
    try:
        decoded = _decode_base64(stripped)
    except ConfigError:
        decoded = None
    if decoded is not None:
        return _parse_decoded(decoded)
    return ("clash_yaml", *_parse_yaml(stripped))


def _parse_decoded(decoded: str) -> tuple[str, list[ProxyCandidate], list[str]]:
    if _looks_like_yaml(decoded):
        return ("clash_yaml", *_parse_yaml(decoded))
    return "base64", _parse_uri_lines(decoded), []


def _checked_text_size(text: str) -> int:
    if not isinstance(text, str):
        raise ConfigError("订阅内容必须是文本")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError:
        raise ConfigError("订阅内容字符编码无效，必须是 UTF-8 文本") from None
    if size > _MAX_TEXT_BYTES:
        raise ConfigError("订阅内容过大，不能超过 8 MiB")
    return size


def _load_yaml(text: str) -> Any:
    if yaml is None:
        raise _YamlUnavailable("Clash YAML 导入需要 PyYAML，请先执行 uv sync")
    try:
        return yaml.safe_load(text)
    except Exception:
        raise ConfigError("Clash YAML 格式无效，请检查 proxies 节点字段") from None


def _provider_definitions(raw: Any) -> Mapping[str, Any]:
    providers = raw.get("proxy-providers", {}) if isinstance(raw, Mapping) else {}
    if not isinstance(providers, Mapping):
        raise ConfigError("proxy-providers 必须是对象映射")
    if len(providers) > 16:
        raise ConfigError("provider 数量过多，单次最多导入 16 个")
    for item in providers.values():
        if not isinstance(item, Mapping):
            raise ConfigError("provider 配置必须是对象")
        if "payload" in item and not isinstance(item["payload"], list):
            raise ConfigError("provider payload 必须是节点数组")
        if any(item.get(key) for key in ("override", "filter", "exclude-filter", "exclude-type", "header", "proxy")):
            raise ConfigError("暂不支持 provider 的 override/filter/header/proxy 等改写或请求选项，未进行部分导入")
        provider_type = str(item.get("type") or ("inline" if "payload" in item else "http")).strip().lower()
        if provider_type not in {"inline", "http", "file"}:
            raise ConfigError("不支持该 provider 类型，未进行部分导入")
        if provider_type == "inline" and "payload" not in item:
            raise ConfigError("inline provider 缺少 payload 节点数组")
    return providers


def _yaml_items(raw: Any) -> list[Any]:
    if isinstance(raw, Mapping) and "proxies" in raw:
        items = raw.get("proxies")
        if items is None:
            items = []
    elif isinstance(raw, list):
        items = raw
    elif isinstance(raw, Mapping) and {"name", "type", "server"}.issubset(raw):
        items = [raw]
    elif isinstance(raw, Mapping) and raw.get("proxy-providers"):
        items = []
    else:
        raise ConfigError("Clash 内容未包含可导入的 proxies 节点数组")
    if not isinstance(items, list):
        raise ConfigError("Clash proxies 必须是对象数组")
    return items


def _parse_yaml(text: str) -> tuple[list[ProxyCandidate], list[str]]:
    raw = _load_yaml(text)
    items = list(_yaml_items(raw))
    for item in _provider_definitions(raw).values():
        items.extend(item.get("payload", []))
    return [_candidate_from_clash(item) for item in items], []


def _expand_http_providers(text: str) -> str:
    """只由显式 importer 调用：每个 HTTP URL 最多一次，禁止子 provider 和本地 path。"""
    total = _checked_text_size(text)
    raw = _load_yaml(text)
    providers = _provider_definitions(raw)
    cache: dict[str, list[Any]] = {}
    for provider in providers.values():
        if "payload" in provider:
            continue
        if str(provider.get("type") or "http").strip().lower() != "http":
            raise ConfigError("仅支持 HTTP 或 inline provider；不会读取订阅中的本地 path，未导入任何节点")
        url = str(provider.get("url") or "").strip()
        if url not in cache:
            try:
                fetched = read_source(url, kind="url")
                total += _checked_text_size(fetched.text)
                if total > _MAX_TEXT_BYTES:
                    raise ConfigError("订阅与 provider 总内容不能超过 8 MiB")
                child = _load_yaml(fetched.text)
                if isinstance(child, Mapping) and child.get("proxy-providers"):
                    raise ConfigError("provider 不允许继续引用子 provider")
                cache[url] = _yaml_items(child)
            except ConfigError:
                raise ConfigError("HTTP provider 读取失败、格式无效或超出限制，未导入任何节点") from None
        # path、health-check 等不会交给 mihomo；payload 仅作为本次离线快照使用。
        provider["payload"] = cache[url]
    try:
        expanded = yaml.safe_dump(raw, allow_unicode=True, sort_keys=False)
    except Exception:
        raise ConfigError("provider 内容无法安全展开，未导入任何节点") from None
    _checked_text_size(expanded)
    return expanded


def _parse_uri_lines(text: str) -> list[ProxyCandidate]:
    candidates: list[ProxyCandidate] = []
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        candidates.append(_candidate_from_uri(value))
    if not candidates:
        raise ConfigError("节点内容为空，请提供至少一个节点链接")
    return candidates


# ── 单个节点 ────────────────────────────────────────────────────────────────
def _candidate_from_uri(value: str) -> ProxyCandidate:
    scheme = value.split("://", 1)[0].strip().lower() if "://" in value else ""
    if scheme in BRIDGED_SCHEMES:
        return _bridged_from_uri(value, scheme)
    try:
        parts = urlsplit(value)
    except ValueError:
        return _invalid_candidate("节点", "节点链接格式无效")
    scheme = (parts.scheme or "").lower()
    name = unquote(parts.fragment or "").strip()
    display = _display_endpoint(parts, _safe_token(scheme) or "节点")
    if scheme not in NATIVE_SCHEMES:
        label = _safe_token(scheme) or "未知"
        return ProxyCandidate(
            name=(name or display)[:160],
            protocol=label if scheme else "unknown",
            display=display,
            status="unsupported",
            reason=f"当前不支持 {label} 节点",
            source_key=_hash_key(value),
        )
    raw = urlunsplit((scheme, parts.netloc, parts.path, parts.query, ""))
    try:
        parsed = parse_proxy_url(raw)
    except ConfigError:
        return _invalid_candidate(name or display, "代理 URL 无效")
    if not name:
        name = parsed.host
    capabilities = ("browser",) if parsed.scheme == "socks5" else ("http", "browser")
    status = "browser_only" if parsed.scheme == "socks5" else "accepted"
    return ProxyCandidate(
        name=name[:160],
        protocol=parsed.scheme,
        display=parsed.display,
        status=status,
        capabilities=capabilities,
        source_key=_hash_key(parsed.url),
        url=parsed.url,
    )


def _bridged_from_uri(value: str, scheme: str) -> ProxyCandidate:
    body, _, fragment = value.partition("#")
    name = unquote(fragment).strip()
    protocol = "hysteria2" if scheme == "hy2" else scheme
    try:
        parts = urlsplit(body)
    except ValueError:
        parts = None
    display = _display_endpoint(parts, protocol) if parts is not None and scheme not in {"vmess", "ss"} else protocol
    try:
        converter = _URI_CONVERTERS[protocol]
        outbound, fallback = converter(body, parts)
    except _UriUnsupported as exc:
        return ProxyCandidate(
            name=(name or display)[:160], protocol=protocol, display=display, status="unsupported",
            reason=exc.reason, source_key=_hash_key(value),
        )
    except _UriInvalid as exc:
        return _invalid_candidate(name or display, exc.reason, protocol=protocol)
    except (ValueError, TypeError, KeyError, UnicodeError):
        return _invalid_candidate(name or display, "节点链接格式无效", protocol=protocol)
    return _bridged_candidate(outbound, name or fallback, display)


def _candidate_from_clash(raw: Any) -> ProxyCandidate:
    if not isinstance(raw, Mapping):
        return _invalid_candidate("节点", "节点必须是对象")
    name = str(raw.get("name") or "").strip()[:160]
    kind = str(raw.get("type") or "").strip().lower()
    server = str(raw.get("server") or "").strip()
    port_value = raw.get("port")
    display = _display_host(_safe_token(kind) or "节点", server, port_value)
    if kind in BRIDGED_TYPES:
        return _bridged_candidate({key: value for key, value in raw.items() if key != "name"}, name, display)
    if kind not in NATIVE_SCHEMES:
        label = _safe_token(kind) or "未知"
        reason = "Clash 策略节点不可直接作为出口" if kind in _POLICY_TYPES else f"当前不支持 {label} 节点"
        return ProxyCandidate(
            name=name or display,
            protocol=label if kind else "unknown",
            display=display,
            status="unsupported",
            reason=reason,
            source_key=_hash_key(f"{kind}|{name}|{display}"),
        )
    if any(key in raw and not isinstance(raw[key], bool) for key in ("tls", "skip-cert-verify", "udp")):
        return _invalid_candidate(name or display, "节点 TLS/证书/UDP 选项必须是布尔值")
    native_keys = {"name", "type", "server", "port", "username", "password", "tls", "skip-cert-verify", "udp"}
    if set(raw) - native_keys or raw.get("udp") is True:
        return ProxyCandidate(
            name=name or display, protocol=kind, display=display, status="unsupported",
            reason="原生代理包含无法保留的选项（如 SNI、headers、拨号链或 UDP），未简化导入",
            source_key=_hash_key(f"{kind}|{name}|{display}"),
        )
    if not server or isinstance(port_value, bool):
        return _invalid_candidate(name or display, "节点缺少有效服务器或端口")
    try:
        port = int(port_value)
    except (TypeError, ValueError):
        return _invalid_candidate(name or display, "节点端口无效")
    if not 1 <= port <= 65535:
        return _invalid_candidate(name or display, "节点端口无效")
    if kind == "socks5" and raw.get("tls") is True:
        return ProxyCandidate(
            name=name or display,
            protocol=kind,
            display=display,
            status="unsupported",
            reason="带 TLS 的 SOCKS5 节点无法由当前执行器表示",
            source_key=_hash_key(f"{kind}|{name}|{display}"),
        )
    if raw.get("skip-cert-verify") is True and kind in {"http", "https"}:
        return ProxyCandidate(
            name=name or display,
            protocol=kind,
            display=display,
            status="unsupported",
            reason="节点的跳过证书校验选项无法安全保留",
            source_key=_hash_key(f"{kind}|{name}|{display}"),
        )
    username = raw.get("username", "")
    password = raw.get("password", "")
    if username not in (None, "") and not isinstance(username, str):
        return _invalid_candidate(name or display, "节点用户名无效")
    if password not in (None, "") and not isinstance(password, str):
        return _invalid_candidate(name or display, "节点密码无效")
    username = str(username or "")
    password = str(password or "")
    if password and not username:
        return _invalid_candidate(name or display, "节点填写密码时必须同时填写用户名")
    scheme = "https" if kind == "http" and raw.get("tls") is True else kind
    host = server.strip("[]")
    if ":" in host:
        host = f"[{host}]"
    auth = quote(username, safe="") if username else ""
    if username:
        auth += ":" + quote(password, safe="") if password else ""
        auth += "@"
    url = f"{scheme}://{auth}{host}:{port}"
    candidate = _candidate_from_uri(url + ("#" + quote(name, safe="") if name else ""))
    return replace(candidate, name=name or candidate.name, protocol=scheme)


def _bridged_candidate(outbound: Mapping[str, Any], name: str, display: str) -> ProxyCandidate:
    try:
        parsed = parse_bridge_outbound(outbound)
    except ConfigError as exc:
        protocol = str(outbound.get("type") or "") if isinstance(outbound, Mapping) else ""
        return _invalid_candidate(name or display, _brief_reason(exc.message), protocol=_safe_token(protocol.lower()))
    return _accepted_bridge(parsed, name)


def _accepted_bridge(parsed: BridgedProxy, name: str) -> ProxyCandidate:
    clash = parsed.to_payload()
    return ProxyCandidate(
        name=(str(name or "").strip() or parsed.host)[:160],
        protocol=parsed.protocol,
        display=parsed.display,
        status="bridged",
        reason="节点自身配置了跳过证书校验" if parsed.insecure else "",
        capabilities=("http", "browser"),
        source_key=_hash_key("clash:" + canonical_outbound(clash)),
        clash=MappingProxyType(clash),
        insecure=parsed.insecure,
    )


def _invalid_candidate(name: str, reason: str, *, protocol: str = "") -> ProxyCandidate:
    return ProxyCandidate(
        name=str(name or "节点")[:160],
        protocol=protocol or "unknown",
        display="—",
        status="invalid",
        reason=reason,
        source_key=_hash_key(str(name) + "|" + reason),
    )


# ── 分享链接 → mihomo 出站 ──────────────────────────────────────────────────
def _query_text(text: str) -> dict[str, str]:
    """不把 ``+`` 当空格：密码、混淆参数里的 ``+`` 必须原样保留。"""
    result: dict[str, str] = {}
    for item in str(text or "").split("&"):
        if not item:
            continue
        key, _, value = item.partition("=")
        key = unquote(key).strip()
        if key:
            result[key] = unquote(value).strip()
    return result


def _query(parts: Any) -> dict[str, str]:
    return _query_text(parts.query) if parts is not None else {}


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _endpoint(parts: Any, *, default_port: int | None = None) -> tuple[str, int]:
    if parts is None:
        raise _UriInvalid("节点链接格式无效")
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise _UriInvalid("节点端口无效（暂不支持端口跳跃）") from None
    if not host:
        raise _UriInvalid("节点缺少服务器地址")
    if port is None:
        if default_port is None:
            raise _UriInvalid("节点缺少端口")
        port = default_port
    if not 1 <= port <= 65535:
        raise _UriInvalid("节点端口无效")
    return host, port


def _userinfo(parts: Any) -> str:
    netloc = parts.netloc if parts is not None else ""
    if "@" not in netloc:
        return ""
    return unquote(netloc.rsplit("@", 1)[0], errors="strict")


def _tls_common(out: dict[str, Any], q: Mapping[str, str], *, sni_key: str) -> None:
    sni = q.get("sni") or q.get("peer") or q.get("servername")
    if sni:
        out[sni_key] = sni
    if q.get("fp"):
        out["client-fingerprint"] = q["fp"]
    if q.get("alpn"):
        alpn = [item.strip() for item in q["alpn"].split(",") if item.strip()]
        if alpn:
            out["alpn"] = alpn
    if any(_truthy(q.get(key)) for key in ("allowInsecure", "insecure", "allow_insecure", "skip-cert-verify")):
        out["skip-cert-verify"] = True


def _reality(out: dict[str, Any], q: Mapping[str, str]) -> None:
    public_key = q.get("pbk") or q.get("publicKey") or q.get("public-key")
    if not public_key:
        raise _UriInvalid("REALITY 节点缺少公钥")
    opts = {"public-key": public_key}
    short_id = q.get("sid") or q.get("shortId")
    if short_id:
        opts["short-id"] = short_id
    out["tls"] = True
    out["reality-opts"] = opts


def _hosts(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _transport(out: dict[str, Any], network: str, q: Mapping[str, str], allowed: frozenset[str]) -> None:
    net = str(network or "tcp").strip().lower()
    path = q.get("path", "")
    host = q.get("host", "")
    if net in {"", "tcp", "raw", "none"}:
        if str(q.get("headerType") or "").lower() == "http":
            if "http" not in allowed:
                raise _UriUnsupported("该协议不支持 HTTP 伪装传输")
            opts: dict[str, Any] = {"method": "GET", "path": [path or "/"]}
            if _hosts(host):
                opts["headers"] = {"Host": _hosts(host)}
            out["network"] = "http"
            out["http-opts"] = opts
        return
    if net in {"h2", "http"}:
        net = "h2"
    elif net == "splithttp":
        net = "xhttp"
    if net not in allowed:
        label = net if _TOKEN_RE.fullmatch(net) else "未知"
        raise _UriUnsupported(f"不支持 {label} 传输方式")
    if net in {"ws", "httpupgrade"}:
        opts = {}
        if path:
            base, _, query = path.partition("?")
            early = _query_text(query).get("ed", "")
            if early.isdigit():
                opts["max-early-data"] = int(early)
                opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
                path = base
            opts["path"] = path
        if host:
            opts["headers"] = {"Host": host}
        if net == "httpupgrade":
            opts["v2ray-http-upgrade"] = True
        out["network"] = "ws"
        out["ws-opts"] = opts
    elif net == "grpc":
        out["network"] = "grpc"
        out["grpc-opts"] = {"grpc-service-name": q.get("serviceName") or path or ""}
    elif net == "h2":
        opts = {"path": path or "/"}
        if _hosts(host):
            opts["host"] = _hosts(host)
        out["network"] = "h2"
        out["h2-opts"] = opts
    elif net == "xhttp":
        opts = {"path": path or "/"}
        if host:
            opts["host"] = host
        if q.get("mode"):
            opts["mode"] = q["mode"]
        out["network"] = "xhttp"
        out["xhttp-opts"] = opts


_VLESS_NETWORKS = frozenset({"ws", "httpupgrade", "grpc", "h2", "http", "xhttp"})
_VMESS_NETWORKS = frozenset({"ws", "httpupgrade", "grpc", "h2", "http"})
_TROJAN_NETWORKS = frozenset({"ws", "httpupgrade", "grpc"})


def _security(out: dict[str, Any], q: Mapping[str, str], *, sni_key: str, default: str = "none") -> None:
    security = str(q.get("security") or default).strip().lower()
    if security in {"tls", "xtls"}:
        out["tls"] = True
    elif security == "reality":
        _reality(out, q)
    elif security not in {"", "none"}:
        raise _UriUnsupported("不支持该传输层安全方式")
    _tls_common(out, q, sni_key=sni_key)


def _vless_uri(body: str, parts: Any) -> tuple[dict[str, Any], str]:
    host, port = _endpoint(parts)
    uuid = _userinfo(parts)
    if not uuid:
        raise _UriInvalid("VLESS 节点缺少 UUID")
    q = _query(parts)
    out: dict[str, Any] = {"type": "vless", "server": host, "port": port, "uuid": uuid, "udp": True}
    _security(out, q, sni_key="servername")
    if q.get("flow"):
        out["flow"] = q["flow"]
    encryption = q.get("encryption", "")
    if encryption and encryption != "none":
        out["encryption"] = encryption
    packet = q.get("packetEncoding") or q.get("packet-encoding")
    if packet:
        out["packet-encoding"] = packet
    _transport(out, q.get("type", "tcp"), q, _VLESS_NETWORKS)
    return out, ""


def _trojan_uri(body: str, parts: Any) -> tuple[dict[str, Any], str]:
    host, port = _endpoint(parts, default_port=443)
    password = _userinfo(parts)
    if not password:
        raise _UriInvalid("Trojan 节点缺少密码")
    q = _query(parts)
    out: dict[str, Any] = {"type": "trojan", "server": host, "port": port, "password": password, "udp": True}
    security = str(q.get("security") or "tls").strip().lower()
    if security == "reality":
        _reality(out, q)
    elif security not in {"", "tls", "none"}:
        raise _UriUnsupported("不支持该传输层安全方式")
    _tls_common(out, q, sni_key="sni")
    _transport(out, q.get("type", "tcp"), q, _TROJAN_NETWORKS)
    return out, ""


def _anytls_uri(body: str, parts: Any) -> tuple[dict[str, Any], str]:
    host, port = _endpoint(parts, default_port=443)
    password = _userinfo(parts)
    if not password:
        raise _UriInvalid("AnyTLS 节点缺少密码")
    q = _query(parts)
    out: dict[str, Any] = {"type": "anytls", "server": host, "port": port, "password": password, "udp": True}
    _tls_common(out, q, sni_key="sni")
    return out, ""


def _hysteria2_uri(body: str, parts: Any) -> tuple[dict[str, Any], str]:
    host, port = _endpoint(parts, default_port=443)
    password = _userinfo(parts)
    if not password:
        raise _UriInvalid("Hysteria2 节点缺少密码")
    q = _query(parts)
    out: dict[str, Any] = {"type": "hysteria2", "server": host, "port": port, "password": password, "udp": True}
    _tls_common(out, q, sni_key="sni")
    obfs = q.get("obfs", "")
    if obfs and obfs != "none":
        out["obfs"] = obfs
        if q.get("obfs-password"):
            out["obfs-password"] = q["obfs-password"]
    return out, ""


def _tuic_uri(body: str, parts: Any) -> tuple[dict[str, Any], str]:
    host, port = _endpoint(parts)
    netloc = parts.netloc if parts is not None else ""
    userinfo = netloc.rsplit("@", 1)[0] if "@" in netloc else ""
    uuid, _, password = userinfo.partition(":")
    uuid, password = unquote(uuid, errors="strict"), unquote(password, errors="strict")
    if not uuid or not password:
        raise _UriInvalid("TUIC 节点缺少 UUID 或密码")
    q = _query(parts)
    out: dict[str, Any] = {"type": "tuic", "server": host, "port": port, "uuid": uuid,
                           "password": password, "udp": True}
    _tls_common(out, q, sni_key="sni")
    congestion = q.get("congestion_control") or q.get("congestion")
    if congestion:
        out["congestion-controller"] = congestion
    if q.get("udp_relay_mode"):
        out["udp-relay-mode"] = q["udp_relay_mode"]
    if _truthy(q.get("disable_sni")):
        out["disable-sni"] = True
    return out, ""


def _vmess_uri(body: str, parts: Any) -> tuple[dict[str, Any], str]:
    data = _b64_json(body.split("://", 1)[1])
    if data is None:
        # 少数客户端使用标准 URI 形式：vmess://uuid@host:port?...
        host, port = _endpoint(parts)
        uuid = _userinfo(parts)
        if not uuid:
            raise _UriInvalid("VMess 节点缺少 UUID")
        q = _query(parts)
        out: dict[str, Any] = {"type": "vmess", "server": host, "port": port, "uuid": uuid,
                               "alterId": 0, "cipher": q.get("encryption") or "auto", "udp": True}
        _security(out, q, sni_key="servername")
        _transport(out, q.get("type", "tcp"), q, _VMESS_NETWORKS)
        return out, ""
    host = str(data.get("add") or "").strip()
    if not host:
        raise _UriInvalid("VMess 节点缺少服务器地址")
    try:
        port = int(str(data.get("port") or "").strip())
        alter_id = int(str(data.get("aid") or "0").strip() or "0")
    except ValueError:
        raise _UriInvalid("VMess 节点端口或 alterId 无效") from None
    uuid = str(data.get("id") or "").strip()
    if not uuid:
        raise _UriInvalid("VMess 节点缺少 UUID")
    out = {"type": "vmess", "server": host, "port": port, "uuid": uuid, "alterId": alter_id,
           "cipher": str(data.get("scy") or "auto").strip() or "auto", "udp": True}
    if str(data.get("tls") or "").strip().lower() == "tls":
        out["tls"] = True
    tls = {key: str(data.get(key) or "").strip() for key in ("sni", "alpn", "fp")}
    if _truthy(data.get("allowInsecure")) or _truthy(data.get("skip-cert-verify")):
        tls["allowInsecure"] = "1"
    _tls_common(out, tls, sni_key="servername")
    path = str(data.get("path") or "").strip()
    q = {"path": path, "host": str(data.get("host") or "").strip(), "serviceName": path,
         "headerType": str(data.get("type") or "").strip()}
    _transport(out, str(data.get("net") or "tcp"), q, _VMESS_NETWORKS)
    return out, str(data.get("ps") or "").strip()


def _ss_uri(body: str, parts: Any) -> tuple[dict[str, Any], str]:
    rest = body.split("://", 1)[1]
    main, _, query = rest.partition("?")
    main = main.rstrip("/")
    if "@" in main:
        userinfo, hostport = main.rsplit("@", 1)
        userinfo = unquote(userinfo, errors="strict")
        if ":" not in userinfo:  # SIP002：base64url(method:password)
            decoded = _b64_text(userinfo)
            if decoded is None:
                raise _UriInvalid("Shadowsocks 认证信息无效")
            userinfo = decoded
    else:  # 旧式：整体 base64(method:password@host:port)
        decoded = _b64_text(main)
        if decoded is None or "@" not in decoded:
            raise _UriInvalid("Shadowsocks 节点链接无效")
        userinfo, hostport = decoded.rsplit("@", 1)
    method, sep, password = userinfo.partition(":")
    if not sep or not method.strip() or not password:
        raise _UriInvalid("Shadowsocks 节点缺少加密方式或密码")
    try:
        host, port = _endpoint(urlsplit("ss://" + hostport.strip()))
    except ValueError:
        raise _UriInvalid("Shadowsocks 服务器地址无效") from None
    out: dict[str, Any] = {"type": "ss", "server": host, "port": port, "cipher": method.strip(),
                           "password": password, "udp": True}
    plugin = _query_text(query).get("plugin", "")
    if plugin:
        _ss_plugin(out, plugin)
    return out, ""


def _ss_plugin(out: dict[str, Any], text: str) -> None:
    items = text.split(";")
    name = items[0].strip().lower()
    opts: dict[str, str] = {}
    for item in items[1:]:
        key, sep, value = item.partition("=")
        if key.strip():
            opts[key.strip()] = value.strip() if sep else "true"
    if name in {"obfs-local", "simple-obfs", "obfs"}:
        plugin_opts: dict[str, Any] = {"mode": opts.get("obfs") or "http"}
        if opts.get("obfs-host"):
            plugin_opts["host"] = opts["obfs-host"]
        out["plugin"] = "obfs"
    elif name == "v2ray-plugin":
        plugin_opts = {"mode": "websocket"}
        if opts.get("host"):
            plugin_opts["host"] = opts["host"]
        if opts.get("path"):
            plugin_opts["path"] = opts["path"]
        if "tls" in opts:
            plugin_opts["tls"] = True
        out["plugin"] = "v2ray-plugin"
    elif name == "shadow-tls":
        try:
            version = int(opts.get("version") or 3)
        except ValueError:
            raise _UriInvalid("shadow-tls 插件版本无效") from None
        plugin_opts = {"host": opts.get("host", ""), "password": opts.get("password", ""), "version": version}
        out["plugin"] = "shadow-tls"
    else:
        raise _UriUnsupported("Shadowsocks 插件不受支持（仅支持 obfs / v2ray-plugin / shadow-tls）")
    out["plugin-opts"] = plugin_opts


_URI_CONVERTERS = {
    "vless": _vless_uri,
    "vmess": _vmess_uri,
    "trojan": _trojan_uri,
    "anytls": _anytls_uri,
    "ss": _ss_uri,
    "hysteria2": _hysteria2_uri,
    "tuic": _tuic_uri,
}


def _b64_text(value: str) -> str | None:
    compact = "".join(str(value or "").split())
    if not compact or not _BASE64_RE.fullmatch(compact) or len(compact) % 4 == 1:
        return None
    compact = compact.rstrip("=")
    compact += "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact.replace("-", "+").replace("_", "/"), validate=True).decode("utf-8")
    except (ValueError, UnicodeError):
        return None


def _b64_json(value: str) -> dict[str, Any] | None:
    text = _b64_text(value)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


# ── 去重与小工具 ────────────────────────────────────────────────────────────
def _node_id(candidate: ProxyCandidate, used: set[str]) -> str:
    # 哈希包含完整名称与连接，避免中文别名、长名称截断及排序造成 ID 碰撞。
    name = slugify(candidate.name, fallback="node")[:24]
    key = _hash_key(json.dumps([candidate.name, candidate.identity], ensure_ascii=False))
    base = f"{name}-{key}"
    value = base
    suffix = 2
    while value in used:
        value = f"{base}-{suffix}"
        suffix += 1
    return value


def _existing_identities(nodes: list[Any]) -> set[tuple[str, str]]:
    return {_node_content(node) for node in nodes if isinstance(node, Mapping)}


def _decode_base64(text: str) -> str:
    compact = "".join(line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    if not compact or not _BASE64_RE.fullmatch(compact) or len(compact) % 4 == 1:
        raise ConfigError("内容不是有效的 Base64 节点订阅")
    compact += "=" * (-len(compact) % 4)
    try:
        data = base64.b64decode(compact, altchars=b"-_", validate=True)
        if len(data) > _MAX_TEXT_BYTES:
            raise ConfigError("Base64 解码后的订阅内容过大")
        return data.decode("utf-8-sig")
    except ConfigError:
        raise
    except (ValueError, UnicodeError):
        raise ConfigError("Base64 节点订阅无效或不是 UTF-8 文本") from None


def _looks_like_uri_lines(text: str) -> bool:
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    return bool(lines) and all("://" in line for line in lines[: min(8, len(lines))])


def _looks_like_yaml(text: str) -> bool:
    lowered = text.lower()
    return (
        "proxies:" in lowered
        or "proxy-providers:" in lowered
        or lowered.startswith("proxy:")
        or lowered.startswith("port:")
        or lowered.startswith("mixed-port:")
        or text.lstrip().startswith(("{", "["))
    )


def _hash_key(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:20]


def _brief_reason(message: str) -> str:
    text = str(message or "")
    return (text.split(": ", 1)[1] if ": " in text else text)[:200] or "节点配置无效"


def _safe_token(value: str) -> str:
    text = str(value or "").strip().lower()
    return text if _TOKEN_RE.fullmatch(text) else ""


def _safe_title(value: str) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", "", str(value or "")).strip()
    return mask_secrets(text[:80]) if text else ""


def _safe_userinfo(value: Mapping[str, Any] | None) -> dict[str, int]:
    result: dict[str, int] = {}
    if not isinstance(value, Mapping):
        return result
    for key in _USERINFO_KEYS:
        item = value.get(key)
        if isinstance(item, int) and not isinstance(item, bool) and item >= 0:
            result[key] = item
    return result


def _safe_source_label(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "导入节点"
    try:
        parts = urlsplit(text)
        if parts.scheme and parts.hostname:
            host = parts.hostname
            port = f":{parts.port}" if parts.port else ""
            return mask_secrets((host + port)[:120]) or "导入节点"
    except ValueError:
        pass
    if "://" in text:
        return "单个节点"
    return mask_secrets(text.replace("\\", "/").rsplit("/", 1)[-1][:120]) or "导入节点"


def _display_endpoint(parts: Any, fallback: str) -> str:
    try:
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        host, port = "", None
    scheme = _safe_token(str(getattr(parts, "scheme", "") or "")) or fallback
    return _display_host(scheme, host, port)


def _display_host(protocol: str, host: str, port: Any) -> str:
    clean = str(host or "").strip().strip("[]")
    if "@" in clean:
        clean = clean.rsplit("@", 1)[-1]
    if not clean:
        return str(protocol or "节点")
    if ":" in clean:
        clean = f"[{clean}]"
    suffix = ""
    try:
        if port not in (None, ""):
            suffix = f":{int(port)}"
    except (TypeError, ValueError):
        suffix = ""
    return f"{protocol or '节点'}://{clean}{suffix}"



def _yaml_text_for_metadata(text: str, mode: str) -> str:
    if mode == "base64":
        try:
            return _decode_base64(text.lstrip("\ufeff").strip())
        except ConfigError:
            return text
    if mode == "auto" and not _looks_like_yaml(text):
        try:
            decoded = _decode_base64(text.lstrip("\ufeff").strip())
        except ConfigError:
            return text
        return decoded if _looks_like_yaml(decoded) else text
    return text


def _clash_metadata(text: str) -> tuple[tuple[Mapping[str, Any], ...], tuple[Mapping[str, Any], ...]]:
    """只保留成员名称/内容哈希等摘要，不保留 provider URL、path 或连接凭据。"""
    raw = _load_yaml(text)
    if not isinstance(raw, Mapping):
        return (), ()
    direct_keys = tuple(
        _named_content_key((candidate.name, candidate.identity))
        for candidate in (_candidate_from_clash(node) for node in _yaml_items(raw))
        if candidate.importable
    )
    groups: list[Mapping[str, Any]] = []
    for item in raw.get("proxy-groups", []) if isinstance(raw.get("proxy-groups"), list) else []:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("name") or "").strip()[:160]
        kind = _safe_token(str(item.get("type") or "").lower())
        members = item.get("proxies")
        safe_members = tuple(str(member).strip()[:160] for member in members if isinstance(member, str)) if isinstance(members, list) else ()
        use = item.get("use")
        if name and kind:
            groups.append(MappingProxyType({
                "name": name,
                "type": kind,
                "member_count": len(safe_members),
                "members": safe_members,
                "manual": kind == "select",
                "use": tuple(str(value).strip()[:160] for value in use if isinstance(value, str)) if isinstance(use, list) else (),
                "include_all": item.get("include-all") is True,
                "include_all_proxies": item.get("include-all-proxies") is True,
                "direct_node_keys": direct_keys if item.get("include-all-proxies") is True else (),
                "include_all_providers": item.get("include-all-providers") is True,
                "filtered": any(item.get(key) for key in ("filter", "exclude-filter", "exclude-type")),
            }))
    providers: list[Mapping[str, Any]] = []
    for name, item in _provider_definitions(raw).items():
        candidates = [_candidate_from_clash(node) for node in item.get("payload", [])]
        kind = str(item.get("type") or ("inline" if "payload" in item else "http")).strip().lower()
        providers.append(MappingProxyType({
            "name": str(name).strip()[:160],
            "type": _safe_token(kind) or "unknown",
            "resolved": "payload" in item,
            "members": tuple(candidate.name for candidate in candidates if candidate.importable),
            "node_keys": tuple(_named_content_key((candidate.name, candidate.identity)) for candidate in candidates if candidate.importable),
        }))
    return tuple(groups), tuple(providers)


def _named_content_key(content: tuple[str, str]) -> str:
    return _hash_key(json.dumps(content, ensure_ascii=False))


def subscription_update_summary(
    existing_group: Mapping[str, Any] | None, result: SubscriptionImport,
) -> dict[str, Any]:
    """返回订阅刷新摘要；只使用节点身份和安全元数据，不回显正文。"""
    group = existing_group if isinstance(existing_group, Mapping) else {}
    old_nodes = [
        item for item in group.get("proxies", [])
        if isinstance(item, Mapping) and str(item.get("source_id") or "") == result.source_id
    ]
    old_by_key = Counter(_node_content(item) for item in old_nodes)
    new_by_key = Counter(_node_content(item) for item in result.nodes)
    unchanged = sum((old_by_key & new_by_key).values())
    old_missing = old_by_key - new_by_key
    new_missing = new_by_key - old_by_key
    old_names: Counter[str] = Counter()
    new_names: Counter[str] = Counter()
    for (name, _), count in old_missing.items():
        old_names[name] += count
    for (name, _), count in new_missing.items():
        new_names[name] += count
    replaced = sum((old_names & new_names).values())
    removed = sum(old_missing.values()) - replaced
    added = sum(new_missing.values()) - replaced
    selected = str(group.get("selected") or "")
    selected_node = next((item for item in old_nodes if str(item.get("id") or "") == selected), None)
    _, selection_lost = _carry_selection(list(group.get("proxies", [])), selected, result.source_id, list(result.nodes))
    return {
        "source_id": result.source_id,
        "format": result.format,
        "content_hash": result.content_hash,
        "title": result.title,
        "old_count": len(old_nodes),
        "new_count": len(result.nodes),
        "added": added,
        "replaced": replaced,
        "removed": removed,
        "unchanged": unchanged,
        "selection_lost": selection_lost,
        "selected_name": str(selected_node.get("name") or "") if selected_node else "",
        "policy_group_count": len(result.policy_groups),
        "provider_count": len(result.providers),
        "notices": tuple(result.notices),
    }



def select_policy_nodes(result: SubscriptionImport, group_name: str) -> tuple[dict[str, Any], ...]:
    """迭代展开 select 引用的节点/策略组/provider，只供手动选出口，不运行策略。"""
    wanted = str(group_name or "").strip()
    groups = {str(item.get("name") or ""): item for item in result.policy_groups}
    policy = groups.get(wanted)
    if policy is None or policy.get("type") != "select":
        raise ConfigError("未找到可手动选择的 Clash select 策略组")
    if not result.providers_complete:
        raise ConfigError("provider 尚未完整展开，不能导入部分策略组成员")
    providers = {str(item.get("name") or ""): item for item in result.providers}
    members: set[str] = set()
    keys: set[str] = set()
    visited: set[str] = set()
    pending = [wanted]
    include_all = False
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        group = groups.get(name)
        if group is None:
            if name.upper() not in {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}:
                members.add(name)
            continue
        kind = str(group.get("type") or "")
        if kind == "relay":
            raise ConfigError("relay 串联策略不能安全展开成独立出口，未简化导入")
        if kind not in {"select", "url-test", "fallback", "load-balance"}:
            continue
        if group.get("filtered"):
            raise ConfigError("暂不支持带 filter/exclude 规则的策略组，未简化导入")
        pending.extend(str(member) for member in group.get("members", ()))
        include_all = include_all or bool(group.get("include_all"))
        if group.get("include_all_proxies"):
            keys.update(group.get("direct_node_keys", ()))
        used = providers.values() if group.get("include_all_providers") else (
            providers[provider] for provider in group.get("use", ()) if provider in providers
        )
        for provider in used:
            keys.update(provider.get("node_keys", ()))
    nodes = tuple(
        deepcopy(node) for node in result.nodes
        if include_all or str(node.get("name") or "") in members or _named_content_key(_node_content(node)) in keys
    )
    if not nodes:
        raise ConfigError("该 select 策略组没有可导入的节点（已跳过环、未知成员和 DIRECT 等内置出口）")
    return nodes
