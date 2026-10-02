"""Clash/节点订阅的受限解析与代理组原子合并。

http / https / socks5 节点写成 ``url``，HTTP 客户端与浏览器直接使用；vless / anytls / vmess /
trojan / ss / hysteria2 / tuic 节点写成 ``clash`` 出站映射，运行时由本地 mihomo 桥接。
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
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
    source: str


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
        """内容身份：同一出口不论名称如何都视为重复。"""
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
    """解析后的导入结果，不包含原始订阅正文或来源明文。"""

    source_id: str
    source_label: str
    group_id: str
    group_name: str
    format: str
    candidates: tuple[ProxyCandidate, ...] = ()
    nodes: tuple[dict[str, Any], ...] = ()
    notices: tuple[str, ...] = ()
    title: str = ""
    userinfo: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    #: 目标组当前节点来自本订阅，且在新内容中找不到对应节点（更新后将变为未选择）。
    selection_lost: bool = False

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
    """组合受限来源读取和离线解析；不保留原始正文。"""

    def import_source(
        self,
        spec: SourceSpec,
        *,
        existing_group: Mapping[str, Any] | None = None,
        source_id: str | None = None,
    ) -> SubscriptionImport:
        kind = str(spec.kind or "").strip().lower()
        format = str(spec.format or "auto").strip().lower()
        source = str(spec.source or "").strip()
        title = ""
        userinfo: Mapping[str, int] = {}
        if kind == "node":
            fetched_text = source
            source_label = _safe_source_label(source)
        elif kind in {"url", "file"}:
            fetched = read_source(source, kind=kind)
            fetched_text = fetched.text
            source_label = fetched.label
            title = str(getattr(fetched, "title", "") or "")
            userinfo = getattr(fetched, "userinfo", None) or {}
        else:
            raise ConfigError("订阅来源必须是链接、单个节点链接或文件")
        group = existing_group if isinstance(existing_group, Mapping) else {}
        return parse_subscription_text(
            fetched_text,
            source_id=str(source_id or "").strip() or source_id_for(source),
            source_label=source_label,
            group_name=str(group.get("name") or ""),
            group_id=str(group.get("id") or ""),
            format="uri" if kind == "node" else format,
            existing_group=group,
            title=title,
            userinfo=userinfo,
        )


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
) -> SubscriptionImport:
    """解析 Clash YAML、Base64 URI 列表或逐行节点 URI。

    ``existing_group`` 只用于预览去重：同一来源的旧节点会被视为可更新，手工节点和
    其它来源节点仍然参与重复检查。
    """
    if not isinstance(text, str):
        raise ConfigError("订阅内容必须是文本")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError:
        raise ConfigError("订阅内容字符编码无效，必须是 UTF-8 文本") from None
    if size > _MAX_TEXT_BYTES:
        raise ConfigError("订阅内容过大，不能超过 8 MiB")
    mode = str(format or "auto").strip().lower()
    if mode not in SUPPORTED_FORMATS:
        raise ConfigError("导入格式必须是自动识别、Clash YAML、Base64 或节点链接")
    source_id = str(source_id or "").strip() or source_id_for("manual-source")
    source_label = _safe_source_label(source_label)
    title = _safe_title(title)
    group_name = str(group_name or "").strip() or title or source_label or "导入节点"
    group_id = str(group_id or "").strip() or (
        "imported-" + source_id.removeprefix("source-")[:12]
        if source_id.startswith("source-") else slugify(group_name, fallback="imported")
    )

    parsed_format, raw_candidates, parse_notices = _parse_candidates(text, mode)
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
    used_ids = set(existing_ids)
    seen_keys: set[str] = set()
    candidates: list[ProxyCandidate] = []
    nodes: list[dict[str, Any]] = []
    for candidate in raw_candidates:
        candidate = replace(candidate, source_id=source_id)
        if not candidate.importable:
            candidates.append(candidate)
            continue
        if candidate.source_key in seen_keys or candidate.identity in existing_keys:
            candidates.append(replace(candidate, status="duplicate", reason="与现有节点重复", node_id=""))
            continue
        seen_keys.add(candidate.source_key)
        base_id = _node_id(candidate, set())
        if base_id in existing_ids:
            candidates.append(replace(candidate, status="conflict", reason="节点 ID 与现有节点内容冲突", node_id=""))
            continue
        node_id = _node_id(candidate, used_ids)
        used_ids.add(node_id)
        accepted = replace(candidate, node_id=node_id)
        candidates.append(accepted)
        nodes.append(accepted.to_payload())

    selection_lost = False
    selected = str(existing.get("selected") or "")
    if selected and nodes:
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
        selection_lost=selection_lost,
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

    先按 source_key（内容未变）匹配；机场轮换凭据时内容变化，再按唯一同名节点匹配；
    都找不到时置空，绝不顺延到别的节点。非本来源的当前节点原样保留。
    """
    if not selected:
        return "", False
    old = next((node for node in old_nodes if isinstance(node, Mapping) and node.get("id") == selected), None)
    if old is None:
        return "", False
    if str(old.get("source_id") or "") != source_id:
        return selected, False
    key = str(old.get("source_key") or "")
    if key:
        match = next((node for node in new_nodes if str(node.get("source_key") or "") == key), None)
        if match is not None:
            return str(match.get("id") or ""), False
    name = str(old.get("name") or "")
    same = [node for node in new_nodes if name and str(node.get("name") or "") == name]
    if len(same) == 1:
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
    return meta


def _node_content(node: Mapping[str, Any]) -> tuple[str, str]:
    clash = node.get("clash")
    if isinstance(clash, Mapping):
        return str(node.get("name") or ""), "clash:" + canonical_outbound(clash)
    return str(node.get("name") or ""), "url:" + str(node.get("url") or "")


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


def _parse_yaml(text: str) -> tuple[list[ProxyCandidate], list[str]]:
    if yaml is None:
        raise _YamlUnavailable("Clash YAML 导入需要 PyYAML，请先执行 uv sync")
    try:
        raw = yaml.safe_load(text)
    except Exception:
        raise ConfigError("Clash YAML 格式无效，请检查 proxies 节点字段") from None
    notices: list[str] = []
    if isinstance(raw, Mapping) and raw.get("proxy-providers"):
        notices.append("订阅包含 proxy-providers：远程 provider 未展开，仅导入 proxies 中直接列出的节点。")
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
    return [_candidate_from_clash(item) for item in items], notices


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
    seed = f"{candidate.name}-{candidate.source_key[:8]}"
    base = slugify(seed, fallback="node")
    value = base
    suffix = 2
    while value in used:
        value = f"{base}-{suffix}"
        suffix += 1
    return value


def _existing_identities(nodes: list[Any]) -> set[str]:
    result: set[str] = set()
    for node in nodes:
        if not isinstance(node, Mapping):
            continue
        try:
            endpoint = parse_node_endpoint(node)
        except ConfigError:
            value = str(node.get("url") or "").strip()
            if value:
                result.add("url:" + value)
            continue
        if isinstance(endpoint, BridgedProxy):
            result.add("clash:" + canonical_outbound(endpoint.outbound))
        else:
            result.add("url:" + endpoint.url)
    return result


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
