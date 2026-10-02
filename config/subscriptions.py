"""Clash/节点订阅的受限解析与代理组原子合并。"""

from __future__ import annotations

import base64
import hashlib
import re
from copy import deepcopy
from dataclasses import dataclass, field, replace
from collections.abc import Mapping
from typing import Any

from net.subscriptions import read_source
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from core.account import slugify
from core.errors import ConfigError
from core.masking import mask_secrets

from .proxies import parse_proxy_url

try:  # PyYAML 是运行依赖；保留友好错误，便于未安装时启动 GUI。
    import yaml
except ImportError:  # pragma: no cover - 由依赖安装决定
    yaml = None

__all__ = [
    "SUPPORTED_FORMATS",
    "SUPPORTED_SCHEMES",
    "SourceSpec",
    "ProxyCandidate",
    "SubscriptionImport",
    "SubscriptionImporter",
    "merge_proxy_import",
    "parse_subscription_text",
    "source_id_for",
]

SUPPORTED_FORMATS = ("auto", "clash_yaml", "base64", "uri")
SUPPORTED_SCHEMES = frozenset({"http", "https", "socks5"})
_ACCEPTED_STATUSES = frozenset({"accepted", "browser_only"})
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/_=-]+$")
_MAX_TEXT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class SourceSpec:
    """受限来源描述；单个节点 URL 不经过网络读取。"""

    kind: str
    format: str
    source: str


@dataclass(frozen=True, slots=True)
class ProxyCandidate:
    """一个候选节点；URL 只用于最终配置，不进入 repr 或展示字段。"""

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

    @property
    def importable(self) -> bool:
        return self.status in _ACCEPTED_STATUSES and bool(self.url)

    def to_payload(self) -> dict[str, Any]:
        if not self.importable:
            raise ConfigError("当前候选节点不可导入")
        return {
            "id": self.node_id,
            "name": self.name,
            "url": self.url,
            "enabled": True,
            "source_id": self.source_id,
            "source_key": self.source_key,
            "capabilities": list(self.capabilities),
        }


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
    ) -> SubscriptionImport:
        kind = str(spec.kind or "").strip().lower()
        format = str(spec.format or "auto").strip().lower()
        source = str(spec.source or "").strip()
        if kind == "node":
            fetched_text = source
            source_label = _safe_source_label(source)
        elif kind in {"url", "file"}:
            fetched = read_source(source, kind=kind)
            fetched_text = fetched.text
            source_label = fetched.label
        else:
            raise ConfigError("订阅来源必须是链接、单个节点链接或文件")
        group = existing_group if isinstance(existing_group, Mapping) else {}
        return parse_subscription_text(
            fetched_text,
            source_id=source_id_for(source),
            source_label=source_label,
            group_name=str(group.get("name") or ""),
            group_id=str(group.get("id") or ""),
            format="uri" if kind == "node" else format,
            existing_group=group,
        )


class _YamlUnavailable(ConfigError):
    pass


def source_id_for(reference: str) -> str:
    """只返回哈希来源 ID；订阅 URL/文件路径永不写入节点字段。"""
    text = str(reference or "").strip()
    if not text:
        text = "manual-source"
    return "source-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def parse_subscription_text(
    text: str,
    *,
    source_id: str,
    source_label: str,
    group_name: str = "",
    group_id: str = "",
    format: str = "auto",
    existing_group: Mapping[str, Any] | None = None,
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
    group_name = str(group_name or "").strip() or source_label or "导入节点"
    group_id = str(group_id or "").strip() or (
        "imported-" + source_id.removeprefix("source-")[:12]
        if source_id.startswith("source-") else slugify(group_name, fallback="imported")
    )

    parsed_format, raw_candidates = _parse_candidates(text, mode)
    existing_nodes = list((existing_group or {}).get("proxies", []))
    preserved_nodes = [
        item for item in existing_nodes
        if isinstance(item, Mapping) and str(item.get("source_id") or "") != source_id
    ]
    existing_urls = _existing_urls(preserved_nodes)
    existing_ids = {
        str(item.get("id") or "").strip()
        for item in preserved_nodes
        if isinstance(item, Mapping) and str(item.get("id") or "").strip()
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
        if candidate.source_key in seen_keys or candidate.url in existing_urls:
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

    notices: list[str] = []
    if not candidates:
        notices.append("没有识别到节点；请检查来源内容或导入格式。")
    if any(item.status == "unsupported" for item in candidates):
        notices.append("部分 Clash 协议当前不能直接交给执行器，已跳过；不会改写成其它协议。")
    if any(item.status == "browser_only" for item in candidates):
        notices.append("SOCKS5 节点仅供浏览器流程使用，HTTP 任务选择后会报告配置不兼容。")
    if any(item.status == "duplicate" for item in candidates):
        notices.append("重复节点未再次写入；同一来源的旧节点会在确认更新时替换。")
    if any(item.status == "conflict" for item in candidates):
        notices.append("节点 ID 与现有不同内容冲突，已拒绝覆盖；请修改名称或先处理现有节点。")
    return SubscriptionImport(
        source_id=source_id,
        source_label=source_label,
        group_id=group_id,
        group_name=group_name,
        format=parsed_format,
        candidates=tuple(candidates),
        nodes=tuple(nodes),
        notices=tuple(dict.fromkeys(notices)),
    )


def merge_proxy_import(
    payload: Mapping[str, Any],
    result: SubscriptionImport,
    *,
    target_group_id: str | None = None,
    target_group_name: str | None = None,
) -> dict[str, Any]:
    """将导入节点合并进草稿；只替换同来源节点，手工节点保持不动。"""
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
            if (str(existing.get("name") or ""), str(existing.get("url") or "")) != (
                str(node.get("name") or ""), str(node.get("url") or "")
            ):
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
    selected_source_key = ""
    for node in old_nodes:
        if isinstance(node, Mapping) and node.get("id") == selected:
            if str(node.get("source_id") or "") == result.source_id:
                selected_source_key = str(node.get("source_key") or "")
            break
    kept = [
        node for node in old_nodes
        if not isinstance(node, Mapping) or str(node.get("source_id") or "") != result.source_id
    ]
    group["proxies"] = kept + deepcopy(list(result.nodes))
    if selected_source_key:
        replacement = next(
            (node for node in result.nodes if node.get("source_key") == selected_source_key),
            None,
        )
        group["selected"] = replacement.get("id", "") if replacement else ""
    elif selected and any(isinstance(node, Mapping) and node.get("id") == selected for node in kept):
        group["selected"] = selected
    else:
        group["selected"] = ""
    return updated


def _parse_candidates(text: str, mode: str) -> tuple[str, list[ProxyCandidate]]:
    stripped = text.lstrip("\ufeff").strip()
    if not stripped:
        raise ConfigError("订阅内容为空")
    if mode == "uri":
        return "uri", _parse_uri_lines(stripped)
    if mode == "base64":
        decoded = _decode_base64(stripped)
        return _parse_decoded(decoded)
    if mode == "clash_yaml":
        return "clash_yaml", _parse_yaml(stripped)

    if _looks_like_uri_lines(stripped):
        return "uri", _parse_uri_lines(stripped)
    if _looks_like_yaml(stripped):
        return "clash_yaml", _parse_yaml(stripped)
    try:
        decoded = _decode_base64(stripped)
    except ConfigError:
        decoded = None
    if decoded is not None:
        return _parse_decoded(decoded)
    return "clash_yaml", _parse_yaml(stripped)


def _parse_decoded(decoded: str) -> tuple[str, list[ProxyCandidate]]:
    if _looks_like_yaml(decoded):
        return "clash_yaml", _parse_yaml(decoded)
    return "base64", _parse_uri_lines(decoded)


def _parse_yaml(text: str) -> list[ProxyCandidate]:
    if yaml is None:
        raise _YamlUnavailable("Clash YAML 导入需要 PyYAML，请先执行 uv sync")
    try:
        raw = yaml.safe_load(text)
    except Exception:
        raise ConfigError("Clash YAML 格式无效，请检查 proxies 节点字段") from None
    if isinstance(raw, Mapping) and "proxies" in raw:
        items = raw.get("proxies")
    elif isinstance(raw, list):
        items = raw
    elif isinstance(raw, Mapping) and {"name", "type", "server"}.issubset(raw):
        items = [raw]
    else:
        raise ConfigError("Clash 内容未包含可导入的 proxies 节点数组")
    if not isinstance(items, list):
        raise ConfigError("Clash proxies 必须是对象数组")
    return [_candidate_from_clash(item) for item in items]


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


def _candidate_from_uri(value: str) -> ProxyCandidate:
    try:
        parts = urlsplit(value)
    except ValueError:
        return _invalid_candidate("节点", "节点链接格式无效")
    scheme = (parts.scheme or "").lower()
    name = unquote(parts.fragment or "").strip()
    display = _display_endpoint(parts, scheme or "节点")
    if scheme not in SUPPORTED_SCHEMES:
        return ProxyCandidate(
            name=name or display,
            protocol=scheme or "unknown",
            display=display,
            status="unsupported",
            reason=f"当前执行器不支持 {scheme or '未知'} 节点",
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


def _candidate_from_clash(raw: Any) -> ProxyCandidate:
    if not isinstance(raw, Mapping):
        return _invalid_candidate("节点", "节点必须是对象")
    name = str(raw.get("name") or "").strip()[:160]
    kind = str(raw.get("type") or "").strip().lower()
    server = str(raw.get("server") or "").strip()
    port_value = raw.get("port")
    display = _display_host(kind or "节点", server, port_value)
    if kind not in SUPPORTED_SCHEMES:
        reason = "Clash 策略节点不可直接作为出口" if kind in {"select", "url-test", "fallback", "load-balance", "direct", "reject"} else f"当前执行器不支持 {kind or '未知'} 节点"
        return ProxyCandidate(
            name=name or display,
            protocol=kind or "unknown",
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


def _invalid_candidate(name: str, reason: str) -> ProxyCandidate:
    return ProxyCandidate(
        name=str(name or "节点")[:160],
        protocol="unknown",
        display="—",
        status="invalid",
        reason=reason,
        source_key=_hash_key(name + "|" + reason),
    )


def _node_id(candidate: ProxyCandidate, used: set[str]) -> str:
    seed = f"{candidate.name}-{candidate.source_key[:8]}"
    base = slugify(seed, fallback="node")
    value = base
    suffix = 2
    while value in used:
        value = f"{base}-{suffix}"
        suffix += 1
    return value


def _existing_urls(nodes: list[Any]) -> set[str]:
    result: set[str] = set()
    for node in nodes:
        if not isinstance(node, Mapping):
            continue
        value = str(node.get("url") or "").strip()
        if not value:
            continue
        try:
            result.add(parse_proxy_url(value).url)
        except ConfigError:
            result.add(value)
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
        or lowered.startswith("proxy:")
        or lowered.startswith("port:")
        or lowered.startswith("mixed-port:")
        or text.lstrip().startswith(("{", "["))
    )


def _hash_key(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:20]


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
    return mask_secrets(text.replace("\\", "/").rsplit("/", 1)[-1][:120]) or "导入节点"


def _display_endpoint(parts: Any, fallback: str) -> str:
    try:
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        host, port = "", None
    return _display_host(str(getattr(parts, "scheme", "") or fallback), host, port)


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
