"""mihomo 代理桥纯函数回归；不启动真实 mihomo。"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.errors import ConfigError
from net import proxy_bridge


def outbound() -> dict:
    return {
        "type": "vless",
        "server": "edge.example.invalid",
        "port": 443,
        "uuid": "11111111-1111-1111-1111-111111111111",
        "tls": True,
        "servername": "edge.example.invalid",
    }


def test_build_bridge_config_is_loopback_and_single_outbound() -> None:
    raw = outbound()
    config = proxy_bridge.build_bridge_config(raw, port=18080, username="bridge", password="secret")

    assert raw["type"] == "vless"
    assert config["mixed-port"] == 18080
    assert config["bind-address"] == "127.0.0.1"
    assert config["allow-lan"] is False
    assert config["authentication"] == ["bridge:secret"]
    assert config["proxies"] == [{"name": "bridge-node", **raw}]
    assert config["rules"] == ["MATCH,bridge-node"]
    assert config["external-controller"] == ""


def test_require_mihomo_rejects_missing_explicit_binary_without_leaking_path() -> None:
    with pytest.raises(ConfigError, match="不会改用直连") as caught:
        proxy_bridge.require_mihomo({proxy_bridge.ENV_BINARY: "/private/secret/mihomo"})
    assert "/private/secret/mihomo" not in str(caught.value)


def test_find_mihomo_accepts_explicit_executable(tmp_path: Path) -> None:
    binary = tmp_path / "mihomo"
    binary.write_text("stub", encoding="utf-8")
    if proxy_bridge.os.name != "nt":
        binary.chmod(0o700)
    found = proxy_bridge.find_mihomo({proxy_bridge.ENV_BINARY: str(binary)})
    assert found == str(binary)


def test_error_category_only_extracts_fixed_mihomo_prefix() -> None:
    assert proxy_bridge._error_category("proxy 0: invalid uuid") == "invalid uuid"
    assert proxy_bridge._error_category("secret uuid=private-value") == ""
