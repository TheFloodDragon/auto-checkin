"""代理配置与确定性选路。只解析显式输入，不访问网络、环境变量或磁盘。"""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Sequence
from urllib.parse import quote, unquote, urlsplit

from core.account import NetworkSpec
from core.errors import ConfigError
from core.masking import mask_secrets

MODES = ("inherit", "direct", "custom", "group")
SCHEMES = ("http", "https", "socks5")


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


@dataclass(frozen=True, slots=True)
class ProxyNode:
    id: str
    name: str
    url: str = field(repr=False)
    enabled: bool = True
    extras: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}), repr=False)

    def to_payload(self) -> dict[str, Any]:
        return {**deepcopy(dict(self.extras)), "id": self.id, "name": self.name,
                "url": self.url, "enabled": self.enabled}


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
            url = _text(node, "url", node_path, required=True)
            try:
                parse_proxy_url(url)
            except ConfigError as exc:
                _error(node_path + ".url", exc.message)
            nodes.append(ProxyNode(node_id, node_name, url, _enabled(node, node_path),
                                   _extras(node, {"id", "name", "url", "enabled"})))
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


def _safe_label(value: str, proxy: ParsedProxy | None) -> str:
    result = str(value)
    if proxy:
        for secret in (proxy.username, proxy.password):
            if secret:
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

    @property
    def description(self) -> str:
        if not self.url:
            return "直连"
        endpoint = parse_proxy_url(self.url).display
        if self.source in {"group", "default_group"}:
            origin = "默认组" if self.source == "default_group" else "代理组"
            text = f"{origin} {self.group_name} → {self.node_name} · {endpoint}"
        else:
            origin = "环境代理 CHECKIN_PROXY" if self.source == "environment" else "自定义代理"
            text = f"{origin} · {endpoint}"
        if self.url.startswith("socks5:"):
            text += "（仅浏览器；HTTP 步骤不支持 SOCKS）"
        return text

    def to_payload(self) -> dict[str, Any]:
        return {"source": self.source, "group_id": self.group_id, "group_name": self.group_name,
                "node_id": self.node_id, "node_name": self.node_name,
                "endpoint": parse_proxy_url(self.url).display if self.url else "",
                "description": self.description}


def resolve_proxy(
    network: NetworkSpec, groups: Sequence[ProxyGroup] = (), default_group: str = "", *, environ_proxy: str = "",
) -> ProxyResolution:
    mode = network_mode(network)
    if mode == "direct":
        return ProxyResolution()
    if mode == "custom":
        return ProxyResolution(parse_proxy_url(network.proxy, allow_bare=True).url, "custom")
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
        proxy = parse_proxy_url(node.url)
        return ProxyResolution(proxy.url, "group" if mode == "group" else "default_group",
                               _safe_label(group.id, proxy), _safe_label(group.name, proxy),
                               _safe_label(node.id, proxy), _safe_label(node.name, proxy))
    if environ_proxy.strip():
        return ProxyResolution(parse_proxy_url(environ_proxy, allow_bare=True).url, "environment")
    return ProxyResolution()
