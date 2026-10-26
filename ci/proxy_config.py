"""把完整 Clash 配置转换为 CI 的本地显式代理；不改变出口和 TLS 策略。"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
from typing import Sequence

import yaml

MAX_CONFIG_BYTES = 8 * 1024 * 1024


class ProxyConfigError(ValueError):
    """错误消息均为固定文案，不包含 YAML、节点、路径或凭据。"""


def apply_domain_split(config: dict, *, domains: Sequence[str], group: str) -> None:
    """把「这些域名走指定代理组」的规则插到现有规则最前面。

    现实约束：同一账号要访问两个互相不可达的目标。实测 agentrouter.org 走默认路由
    正常、东京节点 TLS 直接断；linux.do 反之，默认路由过不了 Cloudflare。订阅里的
    规则按顺序匹配，插到最前面才能盖过既有 MATCH 兜底。
    """
    names = [str(item).strip().lower().lstrip(".") for item in domains if str(item).strip()]
    target = str(group or "").strip()
    if not names or not target:
        return
    rules = config.get("rules")
    if rules is None:
        rules = []
    if not isinstance(rules, list):
        raise ProxyConfigError("CLASH_CONFIG rules 必须是数组")
    injected = [f"DOMAIN-SUFFIX,{name},{target}" for name in names]
    config["rules"] = injected + [rule for rule in rules if rule not in injected]


def prepare_config(
    text: str, *, dns_mode: str = "system", split_domains: Sequence[str] = (), split_group: str = "",
) -> dict:
    if dns_mode not in {"system", "config"}:
        raise ProxyConfigError("CLASH_DNS_MODE 必须为 system 或 config")
    try:
        if not isinstance(text, str) or not text.strip():
            raise ProxyConfigError("CLASH_CONFIG 为空")
        if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
            raise ProxyConfigError("CLASH_CONFIG 不能超过 8 MiB")
        config = yaml.safe_load(text)
    except (yaml.YAMLError, UnicodeError, RecursionError):
        raise ProxyConfigError("CLASH_CONFIG YAML 格式无效") from None
    if not isinstance(config, dict) or not all(isinstance(key, str) for key in config):
        raise ProxyConfigError("CLASH_CONFIG 顶层必须为配置对象")
    # 只处理顶层运行环境。保留 proxies/provider、认证、传输、安全与路由配置。
    for key in (
        "port", "socks-port", "redir-port", "tproxy-port",
        "external-controller-tls", "external-controller-unix", "external-controller-pipe",
        "interface-name", "routing-mark",
    ):
        config.pop(key, None)
    config.update({
        "mixed-port": 7897,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "external-controller": "",
        "ipv6": False,
        "tun": {"enable": False},
        "listeners": [],
    })
    if dns_mode == "system":
        # Mihomo 的 dns.enable=false 使用系统解析器，不能只禁用顶层 ipv6：
        # 导出的 dns 仍可能指向本机监听、局域网、不可达 DoH 或经未建立的代理自举。
        config["dns"] = {"enable": False, "ipv6": False}
    else:
        dns = config.get("dns")
        if dns is None:
            dns = {}
        if not isinstance(dns, dict):
            raise ProxyConfigError("CLASH_CONFIG dns 必须为配置对象")
        config["dns"] = {**dns, "ipv6": False}
    apply_domain_split(config, domains=split_domains, group=split_group)
    return config


def write_config(path: Path, config: dict) -> None:
    """先序列化再原子替换，写失败时不损坏既有配置。"""
    try:
        content = yaml.safe_dump(config, allow_unicode=True, sort_keys=False)
    except (yaml.YAMLError, RecursionError):
        raise ProxyConfigError("CLASH_CONFIG 无法安全序列化") from None
    fd, filename = tempfile.mkstemp(prefix=".proxy-config-", suffix=".yaml", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(filename, 0o600)
        os.replace(filename, path)
    finally:
        Path(filename).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("[setup_proxy] 配置转换需要一个输出文件参数")
        return 1
    dns_mode = os.environ.get("CLASH_DNS_MODE", "system").strip().lower()
    raw_domains = os.environ.get("CLASH_SPLIT_DOMAINS", "")
    split_domains = [item for item in raw_domains.replace(" ", ",").split(",") if item]
    split_group = os.environ.get("CLASH_SPLIT_GROUP", "").strip()
    try:
        config = prepare_config(
            os.environ.get("CLASH_CONFIG", ""), dns_mode=dns_mode,
            split_domains=split_domains, split_group=split_group,
        )
        write_config(Path(args[0]), config)
    except ProxyConfigError as exc:
        print(f"[setup_proxy] {exc}")
        return 1
    except (OSError, ValueError, TypeError, RecursionError):
        print("[setup_proxy] 无法安全写入 CI 代理配置；请检查格式与文件权限")
        return 1
    if dns_mode == "system":
        print("[setup_proxy] CI 使用系统 DNS，禁用桌面 DNS/TUN/顶层网卡绑定（CLASH_DNS_MODE=config 可保留自定义 DNS）")
    else:
        print("[setup_proxy] CI 保留自定义 DNS，禁用 IPv6/TUN/顶层网卡绑定")
    if split_domains and split_group:
        print(f"[setup_proxy] 已按域名分流：{','.join(split_domains)} → {split_group}")
    else:
        print("[setup_proxy] 节点、策略组、路由规则和 TLS 校验保持不变；未自动切换出口")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
