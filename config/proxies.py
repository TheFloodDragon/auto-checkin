"""代理配置与确定性选路。只解析显式输入，不访问网络、环境变量或磁盘。

节点有两种互斥形态：

- ``url``：http / https / socks5，HTTP 客户端与浏览器直接使用；
- ``clash``：一份 mihomo 出站映射（vless / anytls / vmess / trojan / ss / hysteria2 / tuic），
  运行时由 ``net.proxy_bridge`` 在本机回环地址上桥接成带随机认证的 HTTP 代理。
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import quote, unquote, urlsplit

from core.account import NetworkSpec
from core.errors import ConfigError
from core.masking import is_sensitive_key, mask_secrets

MODES = ("inherit", "direct", "custom", "group")
SCHEMES = ("http", "https", "socks5")
#: 需要本地 mihomo 桥接的出站类型；与 mihomo 的 ``type`` 字段一一对应。
BRIDGED_TYPES = ("vless", "anytls", "vmess", "trojan", "ss", "hysteria2", "tuic")
_BRIDGE_REQUIRED: Mapping[str, tuple[tuple[str, ...], ...]] = MappingProxyType({
    "vless": (("uuid",),),
    "vmess": (("uuid",),),
    "anytls": (("password",),),
    "trojan": (("password",),),
    "hysteria2": (("password",),),
    "ss": (("cipher", "password"),),
    # TUIC v5 用 uuid + password，v4 用 token；任一组齐全即可。
    "tuic": (("uuid", "password"), ("token",)),
})
#: 与本机运行环境耦合、在桥接进程里没有意义甚至会改变出口的键。
_BRIDGE_FORBIDDEN = frozenset({"dialer-proxy", "interface-name", "routing-mark"})
#: 出站映射里除 is_sensitive_key 之外也必须脱敏的值。
_BRIDGE_SECRET_KEYS = frozenset({"uuid", "short-id", "public-key", "token", "psk"})
_BRIDGE_MAX_BYTES = 16 * 1024
_BRIDGE_MAX_DEPTH = 5
_HOST_BAD = re.compile(r"[\s\x00-\x1f\x7f@/?#\\]")


def _error(path: str, message: str) -> None:
    raise ConfigError(f"{path}: {message}")


def _text(raw: Mapping, key: str, path: str, *, required: bool = False, default: str = "") -> str:
    value = raw.get(key, default)
    if not isinstance(value, str) or (required and not value.strip()):
        _error(f"{path}.{key}", "必须是非空字符串" if required else "必须是字符串")
    return value.strip()


def _enabled(raw: Mapping, path: str) -> bool:
    value = raw.get("enabled", True)
    if type(value) is not bool:
        _error(f"{path}.enabled", "必须是布尔值")
    return value


def _extras(raw: Mapping, known: set[str]) -> Mapping[str, Any]:
    return MappingProxyType(deepcopy({key: value for key, value in raw.items() if key not in known}))


@dataclass(frozen=True, slots=True)
class ParsedProxy:
    url: str = field(repr=False)
    scheme: str
    host: str
    port: int | None
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)

    @property
    def server(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}" + (f":{self.port}" if self.port is not None else "")

    @property
    def display(self) -> str:
        return self.server

    @property
    def protocol(self) -> str:
        return self.scheme

    @property
    def bridged(self) -> bool:
        return False

    @property
    def has_auth(self) -> bool:
        return bool(self.username or self.password)

    @property
    def secrets(self) -> tuple[str, ...]:
        return tuple(item for item in (self.username, self.password) if item)

    def browser_proxy(self) -> dict[str, str]:
        result = {"server": self.server}
        if self.username:
            result["username"] = self.username
        if self.password:
            result["password"] = self.password
        return result


def parse_proxy_url(value: str, *, allow_bare: bool = False) -> ParsedProxy:
    """URL 错误永不复述输入；原始配置文本由调用方单独保留。"""
    message = "代理 URL 无效：请使用 http://、https:// 或 socks5://主机[:端口]，认证中的特殊字符需 URL 编码"
    if not isinstance(value, str):
        raise ConfigError(message)
    raw = value.strip()
    if not raw or re.search(r"[\s\x00-\x1f\x7f\\]", raw):
        raise ConfigError(message)
    if allow_bare and "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        host, port = parts.hostname, parts.port
        if (parts.scheme not in SCHEMES or not host or parts.path not in {"", "/"}
                or parts.query or parts.fragment or port == 0
                or parts.netloc.rsplit("@", 1)[-1].endswith(":")):
            raise ValueError
        if any(char in host for char in "@/?#"):
            raise ValueError
        userinfo = parts.netloc.rsplit("@", 1)[0] if "@" in parts.netloc else ""
        if re.search(r"%(?![0-9a-fA-F]{2})", userinfo):
            raise ValueError
        username = unquote(parts.username or "", errors="strict")
        password = unquote(parts.password or "", errors="strict")
        if re.search(r"[\x00-\x1f\x7f]", username + password):
            raise ValueError
        parsed = ParsedProxy("", parts.scheme, host, port, username, password)
        auth = ""
        if parts.username is not None:
            auth = quote(username, safe="")
            if parts.password is not None:
                auth += ":" + quote(password, safe="")
            auth += "@"
        url = parsed.server.replace("://", "://" + auth, 1)
        return ParsedProxy(url, parts.scheme, host, port, username, password)
    except (ValueError, UnicodeError):
        raise ConfigError(message) from None


# ── 桥接节点 ────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class BridgedProxy:
    """经本地 mihomo 桥接的出站；``outbound`` 不含 name，凭据不进入 repr。"""

    protocol: str
    host: str
    port: int
    outbound: Mapping[str, Any] = field(repr=False)

    @property
    def bridged(self) -> bool:
        return True

    @property
    def display(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.protocol}://{host}:{self.port}"

    @property
    def has_auth(self) -> bool:
        return True

    @property
    def insecure(self) -> bool:
        return self.outbound.get("skip-cert-verify") is True

    @property
    def transport(self) -> str:
        network = self.outbound.get("network")
        return str(network) if isinstance(network, str) and network else "tcp"

    @property
    def security(self) -> str:
        if isinstance(self.outbound.get("reality-opts"), Mapping):
            return "reality"
        if self.protocol in {"anytls", "trojan", "hysteria2", "tuic"} or self.outbound.get("tls") is True:
            return "tls"
        return "none"

    @property
    def secrets(self) -> tuple[str, ...]:
        return bridge_secrets(self.outbound)

    def to_payload(self) -> dict[str, Any]:
        return deepcopy(dict(self.outbound))


def _check_value(value: Any, path: str, depth: int) -> Any:
    if depth > _BRIDGE_MAX_DEPTH:
        _error(path, "嵌套层级过深")
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                _error(path, "字段名必须是非空字符串")
            result[key] = _check_value(item, path, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_check_value(item, path, depth + 1) for item in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    _error(path, "只能包含字符串、数字、布尔值、列表与对象")
    return None  # pragma: no cover - _error 总会抛出


def _bridge_port(value: Any, path: str) -> int:
    if isinstance(value, bool):
        _error(path + ".port", "端口无效")
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if not isinstance(value, int) or not 1 <= value <= 65535:
        _error(path + ".port", "端口无效")
    return value


def parse_bridge_outbound(raw: Any, *, path: str = "clash") -> BridgedProxy:
    """校验一份 mihomo 出站映射。错误只说明哪一类字段有问题，绝不复述字段值。"""
    if not isinstance(raw, Mapping):
        _error(path, "必须是对象")
    outbound = _check_value(raw, path, 1)
    outbound.pop("name", None)
    kind = outbound.get("type")
    if not isinstance(kind, str) or kind.strip().lower() not in BRIDGED_TYPES:
        _error(path + ".type", "必须是 " + " / ".join(BRIDGED_TYPES) + " 之一")
    kind = kind.strip().lower()
    outbound["type"] = kind
    server = outbound.get("server")
    if not isinstance(server, str) or not server.strip():
        _error(path + ".server", "必须是非空字符串")
    host = server.strip().strip("[]")
    if not host or _HOST_BAD.search(host):
        _error(path + ".server", "服务器地址无效")
    outbound["server"] = host
    outbound["port"] = _bridge_port(outbound.get("port"), path)
    forbidden = sorted(_BRIDGE_FORBIDDEN.intersection(outbound))
    if forbidden:
        _error(path, "包含依赖本机运行环境的字段（" + "、".join(forbidden) + "），无法桥接")
    for key in {name for group in _BRIDGE_REQUIRED[kind] for name in group}:
        value = outbound.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            outbound[key] = str(value)
    if not any(
        all(isinstance(outbound.get(key), str) and outbound[key].strip() for key in group)
        for group in _BRIDGE_REQUIRED[kind]
    ):
        names = " 或 ".join("+".join(group) for group in _BRIDGE_REQUIRED[kind])
        _error(path, f"{kind} 节点缺少必填凭据（{names}）")
    if len(canonical_outbound(outbound).encode("utf-8")) > _BRIDGE_MAX_BYTES:
        _error(path, "节点配置过大")
    return BridgedProxy(kind, host, outbound["port"], MappingProxyType(deepcopy(outbound)))


def canonical_outbound(outbound: Mapping[str, Any]) -> str:
    """去掉 name 后的规范化 JSON；用于去重键，不用于展示。"""
    data = {key: value for key, value in dict(outbound).items() if key != "name"}
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def bridge_secrets(outbound: Any, key: str = "") -> tuple[str, ...]:
    """收集出站映射里所有凭据类字符串，供展示前替换。"""
    found: list[str] = []
    if isinstance(outbound, Mapping):
        for name, item in outbound.items():
            found.extend(bridge_secrets(item, str(name)))
    elif isinstance(outbound, (list, tuple)):
        for item in outbound:
            found.extend(bridge_secrets(item, key))
    elif isinstance(outbound, str) and outbound and (key in _BRIDGE_SECRET_KEYS or is_sensitive_key(key)):
        found.append(outbound)
    return tuple(dict.fromkeys(found))


def parse_node_endpoint(node: Mapping[str, Any], *, path: str = "节点") -> ParsedProxy | BridgedProxy:
    """节点必须且只能填写 ``url`` 或 ``clash`` 之一；GUI、选路与去重共用此入口。"""
    if not isinstance(node, Mapping):
        _error(path, "必须是对象")
    has_url, has_clash = "url" in node, "clash" in node
    if has_url and has_clash:
        _error(path, "url 与 clash 只能填写其一")
    if has_clash:
        return parse_bridge_outbound(node.get("clash"), path=path + ".clash")
    if not has_url:
        _error(path + ".url", "必须填写代理 URL 或 clash 节点配置")
    url = _text(node, "url", path, required=True)
    try:
        return parse_proxy_url(url)
    except ConfigError as exc:
        _error(path + ".url", exc.message)
    raise AssertionError("unreachable")  # pragma: no cover


@dataclass(frozen=True, slots=True)
class ProxyNode:
    id: str
    name: str
    url: str = field(default="", repr=False)
    enabled: bool = True
    extras: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}), repr=False)
    clash: Mapping[str, Any] | None = field(default=None, repr=False)

    @property
    def endpoint(self) -> ParsedProxy | BridgedProxy:
        if self.clash is not None:
            return parse_bridge_outbound(self.clash)
        return parse_proxy_url(self.url)

    def to_payload(self) -> dict[str, Any]:
        result = {**deepcopy(dict(self.extras)), "id": self.id, "name": self.name}
        if self.clash is not None:
            result["clash"] = deepcopy(dict(self.clash))
        else:
            result["url"] = self.url
        result["enabled"] = self.enabled
        return result


@dataclass(frozen=True, slots=True)
class ProxyGroup:
    id: str
    name: str
    proxies: tuple[ProxyNode, ...] = ()
    selected: str = ""
    enabled: bool = True
    extras: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}), repr=False)

    def to_payload(self) -> dict[str, Any]:
        return {**deepcopy(dict(self.extras)), "id": self.id, "name": self.name,
                "proxies": [node.to_payload() for node in self.proxies],
                "selected": self.selected, "enabled": self.enabled}


def parse_groups(raw: Any) -> tuple[ProxyGroup, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        _error("$.proxy_groups", "必须是对象数组")
    groups: list[ProxyGroup] = []
    ids: set[str] = set()
    for index, item in enumerate(raw):
        path = f"$.proxy_groups[{index}]"
        if not isinstance(item, Mapping):
            _error(path, "必须是对象")
        group_id = _text(item, "id", path, required=True)
        if group_id in ids:
            _error(path + ".id", "代理组 ID 重复")
        ids.add(group_id)
        name = _text(item, "name", path, required=True)
        selected = _text(item, "selected", path)
        nodes_raw = item.get("proxies", [])
        if not isinstance(nodes_raw, list):
            _error(path + ".proxies", "必须是对象数组")
        nodes: list[ProxyNode] = []
        node_ids: set[str] = set()
        for node_index, node in enumerate(nodes_raw):
            node_path = f"{path}.proxies[{node_index}]"
            if not isinstance(node, Mapping):
                _error(node_path, "必须是对象")
            node_id = _text(node, "id", node_path, required=True)
            if node_id in node_ids:
                _error(node_path + ".id", "节点 ID 重复")
            node_ids.add(node_id)
            node_name = _text(node, "name", node_path, required=True)
            endpoint = parse_node_endpoint(node, path=node_path)
            extras = _extras(node, {"id", "name", "url", "enabled", "clash"})
            if isinstance(endpoint, BridgedProxy):
                nodes.append(ProxyNode(node_id, node_name, "", _enabled(node, node_path), extras,
                                       MappingProxyType(deepcopy(dict(node["clash"])))))
            else:
                nodes.append(ProxyNode(node_id, node_name, _text(node, "url", node_path, required=True),
                                       _enabled(node, node_path), extras))
        if selected and selected not in node_ids:
            _error(path + ".selected", "当前节点不存在")
        groups.append(ProxyGroup(group_id, name, tuple(nodes), selected, _enabled(item, path),
                                 _extras(item, {"id", "name", "proxies", "selected", "enabled"})))
    return tuple(groups)


def network_from_payload(raw: Any) -> NetworkSpec:
    """只取代理选择字段，其他网络属性由 schema 原有逻辑处理。"""
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        _error("network", "必须是对象")
    for name in ("proxy_mode", "proxy_group"):
        if name in raw and not isinstance(raw[name], str):
            _error("network." + name, "必须是字符串")
    return NetworkSpec(proxy=str(raw.get("proxy") or "").strip(),
                       proxy_mode=str(raw.get("proxy_mode") or "").strip(),
                       proxy_group=str(raw.get("proxy_group") or "").strip())


def network_mode(network: NetworkSpec) -> str:
    mode = network.proxy_mode
    proxy, group = network.proxy, network.proxy_group
    if mode and mode not in MODES:
        _error("network.proxy_mode", "必须是 inherit / direct / custom / group")
    if proxy and group:
        _error("network", "proxy 和 proxy_group 不能同时设置")
    if not mode:
        mode = "custom" if proxy else "group" if group else "inherit"
    if mode in {"inherit", "direct"} and (proxy or group):
        _error("network", "继承或直连模式不能同时指定 proxy / proxy_group")
    if mode == "custom" and (not proxy or group):
        _error("network.proxy", "自定义代理模式必须填写代理 URL，且不能指定代理组")
    if mode == "group" and (not group or proxy):
        _error("network.proxy_group", "代理组模式必须指定组 ID，且不能指定自定义代理")
    return mode


def validate_proxy_config(payload: Mapping[str, Any]) -> tuple[tuple[ProxyGroup, ...], str]:
    if "proxy_groups" in payload and not isinstance(payload["proxy_groups"], list):
        _error("$.proxy_groups", "必须是对象数组")
    groups = parse_groups(payload.get("proxy_groups"))
    default = _text(payload, "default_proxy_group", "$")
    ids = {group.id for group in groups}
    if default and default not in ids:
        _error("$.default_proxy_group", "引用的代理组不存在")
    accounts = payload.get("accounts", [])
    if isinstance(accounts, (list, tuple)):
        for index, account in enumerate(accounts):
            if not isinstance(account, Mapping):
                continue
            try:
                network = network_from_payload(account.get("network"))
                mode = network_mode(network)
                if mode == "group" and network.proxy_group not in ids:
                    _error("network.proxy_group", "引用的代理组不存在；独立账号 JSON 请通过 --config 提供共享配置")
            except ConfigError as exc:
                _error(f"$.accounts[{index}]", exc.message)
    return groups, default


def _safe_label(value: str, secrets: Iterable[str] = ()) -> str:
    result = str(value)
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        result = result.replace(secret, "<redacted>").replace(quote(secret, safe=""), "<redacted>")
    return mask_secrets(result)


@dataclass(frozen=True, slots=True)
class ProxyResolution:
    url: str = field(default="", repr=False)
    source: str = "direct"
    group_id: str = ""
    group_name: str = ""
    node_id: str = ""
    node_name: str = ""
    protocol: str = ""
    endpoint_display: str = ""
    #: 需要本地 mihomo 桥接时为出站映射；此时 ``url`` 为空，由执行方启动桥后得到本地 URL。
    bridge: Mapping[str, Any] | None = field(default=None, repr=False)

    @property
    def requires_bridge(self) -> bool:
        return self.bridge is not None

    @property
    def endpoint(self) -> str:
        if self.bridge is not None:
            return self.endpoint_display
        return parse_proxy_url(self.url).display if self.url else ""

    @property
    def description(self) -> str:
        if not self.url and self.bridge is None:
            return "直连"
        endpoint = self.endpoint
        if self.source in {"group", "default_group"}:
            origin = "默认组" if self.source == "default_group" else "代理组"
            text = f"{origin} {self.group_name} → {self.node_name} · {endpoint}"
        else:
            origin = "环境代理 CHECKIN_PROXY" if self.source == "environment" else "自定义代理"
            text = f"{origin} · {endpoint}"
        if self.bridge is not None:
            text += "（经本地 mihomo 桥接）"
        elif self.url.startswith("socks5:"):
            text += "（仅浏览器；HTTP 步骤不支持 SOCKS）"
        return text

    def to_payload(self) -> dict[str, Any]:
        return {"source": self.source, "group_id": self.group_id, "group_name": self.group_name,
                "node_id": self.node_id, "node_name": self.node_name,
                "protocol": self.protocol, "bridged": self.bridge is not None,
                "endpoint": self.endpoint, "description": self.description}


def resolve_proxy(
    network: NetworkSpec, groups: Sequence[ProxyGroup] = (), default_group: str = "", *, environ_proxy: str = "",
) -> ProxyResolution:
    mode = network_mode(network)
    if mode == "direct":
        return ProxyResolution()
    if mode == "custom":
        proxy = parse_proxy_url(network.proxy, allow_bare=True)
        return ProxyResolution(proxy.url, "custom", protocol=proxy.scheme)
    group_id = network.proxy_group if mode == "group" else default_group
    if group_id:
        group = next((item for item in groups if item.id == group_id), None)
        path = "network.proxy_group" if mode == "group" else "default_proxy_group"
        if group is None:
            _error(path, "代理组不存在，无法执行；不会改用直连")
        if not group.enabled:
            _error(path, "代理组已停用，无法执行；请启用或改绑")
        if not group.proxies:
            _error(path, "代理组为空，请先添加节点")
        if not group.selected:
            _error(path, "代理组未选择当前节点")
        node = next((item for item in group.proxies if item.id == group.selected), None)
        if node is None or not node.enabled:
            _error(path, "当前节点不存在或已停用，请明确选择启用节点")
        endpoint = node.endpoint
        secrets = endpoint.secrets
        labels = dict(group_id=_safe_label(group.id, secrets), group_name=_safe_label(group.name, secrets),
                      node_id=_safe_label(node.id, secrets), node_name=_safe_label(node.name, secrets))
        source = "group" if mode == "group" else "default_group"
        if isinstance(endpoint, BridgedProxy):
            return ProxyResolution("", source, protocol=endpoint.protocol, endpoint_display=endpoint.display,
                                   bridge=MappingProxyType(deepcopy(dict(endpoint.outbound))), **labels)
        return ProxyResolution(endpoint.url, source, protocol=endpoint.scheme, **labels)
    if environ_proxy.strip():
        proxy = parse_proxy_url(environ_proxy, allow_bare=True)
        return ProxyResolution(proxy.url, "environment", protocol=proxy.scheme)
    return ProxyResolution()
