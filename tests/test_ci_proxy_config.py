"""CI 配置转换必须隔离桌面网络设置，保留真实出口及认证，不触网。"""
from __future__ import annotations

from copy import deepcopy
import os

import pytest
import yaml

from ci.proxy_config import MAX_CONFIG_BYTES, ProxyConfigError, main, prepare_config, write_config


DESKTOP = """
mode: rule
mixed-port: 8888
port: 8080
socks-port: 1080
redir-port: 8081
tproxy-port: 8082
allow-lan: true
bind-address: '*'
ipv6: true
interface-name: WLAN
routing-mark: 6666
external-controller: 0.0.0.0:9090
external-controller-tls: 0.0.0.0:9091
external-controller-unix: /tmp/clash.sock
external-controller-pipe: original-pipe
authentication: [private-user:private-password]
tun:
  enable: true
  auto-route: true
  auto-detect-interface: true
listeners:
  - {name: private-listener, type: socks, port: 7899, listen: 0.0.0.0}
dns:
  enable: true
  ipv6: true
  listen: 127.0.0.1:53
  enhanced-mode: fake-ip
  nameserver: [https://private-dns.invalid/dns-query#RULES]
  proxy-server-nameserver: [127.0.0.1:1053]
  respect-rules: true
proxies:
  - name: private-node
    type: trojan
    server: private-server.invalid
    port: 443
    password: private-password
    sni: private-sni.invalid
    skip-cert-verify: false
proxy-groups:
  - name: private-group
    type: select
    proxies: [private-node]
proxy-providers:
  private-provider:
    type: http
    url: https://provider.invalid/sub?token=private-token
    path: ./proxies/provider.yaml
rules: ['MATCH,private-group']
"""


def test_desktop_config_uses_ci_system_dns_without_changing_egress():
    original = yaml.safe_load(DESKTOP)
    config = prepare_config(DESKTOP)
    assert config["dns"] == {"enable": False, "ipv6": False}
    assert config["tun"] == {"enable": False} and config["listeners"] == []
    assert config["mixed-port"] == 7897 and config["bind-address"] == "127.0.0.1"
    assert not config["allow-lan"] and not config["ipv6"]
    assert config["external-controller"] == ""
    for key in ("port", "socks-port", "redir-port", "tproxy-port", "interface-name", "routing-mark",
                "external-controller-tls", "external-controller-unix", "external-controller-pipe"):
        assert key not in config
    for key in ("proxies", "proxy-groups", "proxy-providers", "rules", "mode", "authentication"):
        assert config[key] == original[key]


def test_explicit_custom_dns_keeps_resolvers_but_disables_ipv6():
    original = yaml.safe_load(DESKTOP)
    config = prepare_config(DESKTOP, dns_mode="config")
    assert config["dns"] == {**original["dns"], "ipv6": False}
    assert config["proxies"] == original["proxies"]


@pytest.mark.parametrize("source", [
    '"mixed-port": 9999\n"ipv6": true\nproxies: []\n',
    '{mixed-port: 9999, ipv6: true, proxies: []}',
    'defaults: &defaults {mixed-port: 9999, ipv6: true, dns: {enable: true, ipv6: true}}\n<<: *defaults\n',
    '\ufeff  mixed-port: 9999\n  ipv6: true\n  proxies: []\n',
    'bind-address: >\n  0.0.0.0\nproxies: []\n',
])
def test_quoted_flow_merged_and_multiline_yaml_does_not_keep_desktop_overrides(source):
    config = prepare_config(source)
    rendered = yaml.safe_dump(config)
    reparsed = yaml.safe_load(rendered)
    assert reparsed["mixed-port"] == 7897
    assert reparsed["ipv6"] is False
    assert reparsed["bind-address"] == "127.0.0.1"
    assert reparsed["dns"] == {"enable": False, "ipv6": False}
    assert len([line for line in rendered.splitlines() if line.startswith("mixed-port:")]) == 1


@pytest.mark.parametrize("source", ["", "[]", "null", "secret-token", "dns: [", "? [invalid, key]\n: value"])
def test_invalid_yaml_has_fixed_private_errors(source):
    with pytest.raises(ProxyConfigError) as caught:
        prepare_config(source)
    assert source not in str(caught.value) or source == ""
    assert "secret-token" not in str(caught.value)


def test_config_limits_and_invalid_dns_mode():
    with pytest.raises(ProxyConfigError, match="8 MiB"):
        prepare_config("#" * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(ProxyConfigError, match="CLASH_DNS_MODE"):
        prepare_config(DESKTOP, dns_mode="private-token")
    with pytest.raises(ProxyConfigError, match="dns"):
        prepare_config("dns: []", dns_mode="config")


def test_write_config_is_private_and_roundtrips_without_mutating(tmp_path):
    config = prepare_config(DESKTOP)
    before = deepcopy(config)
    target = tmp_path / "config.yaml"
    write_config(target, config)
    assert yaml.safe_load(target.read_text(encoding="utf-8")) == config == before
    assert not list(tmp_path.glob(".proxy-config-*"))
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600


def test_failed_write_preserves_existing_file_and_cleans_up(tmp_path, monkeypatch):
    target = tmp_path / "config.yaml"
    target.write_text("old", encoding="utf-8")

    def fail(*args):
        raise OSError("private-path")

    monkeypatch.setattr("ci.proxy_config.os.replace", fail)
    with pytest.raises(OSError):
        write_config(target, prepare_config(DESKTOP))
    assert target.read_text(encoding="utf-8") == "old"
    assert not list(tmp_path.glob(".proxy-config-*"))


@pytest.mark.parametrize("mode", ["system", "config", "private-mode"])
def test_main_emits_only_safe_summaries(tmp_path, monkeypatch, capsys, mode):
    monkeypatch.setenv("CLASH_CONFIG", DESKTOP)
    monkeypatch.setenv("CLASH_DNS_MODE", mode)
    target = tmp_path / "private-config.yaml"
    code = main([str(target)])
    assert code == (1 if mode == "private-mode" else 0)
    output = capsys.readouterr()
    assert "private" not in output.out + output.err
    if code == 0:
        assert "未自动切换出口" in output.out


def test_real_mihomo_uses_system_dns_and_forwards_to_local_upstream(tmp_path):
    """安装内核时离线验证真实链路；只监听随机回环端口，不使用真实账号/出口。"""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import socket
    import subprocess
    import threading
    import time

    from net.proxy_bridge import find_mihomo

    binary = find_mihomo()
    if not binary:
        pytest.skip("本机未安装 mihomo，跳过真实内核离线转发测试")

    class Upstream(BaseHTTPRequestHandler):
        def do_CONNECT(self):
            self.send_response(200)
            self.end_headers()
            self.close_connection = False

        def do_GET(self):
            body = b"synthetic-proxy-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        config = prepare_config(yaml.safe_dump({
            "dns": {"enable": True, "nameserver": ["127.0.0.1:1"], "respect-rules": True},
            "interface-name": "nonexistent-desktop-interface",
            "tun": {"enable": True, "auto-route": True},
            "proxies": [{"name": "upstream", "type": "http", "server": "localhost", "port": upstream.server_port}],
            "rules": ["MATCH,upstream"],
        }))
        config["mixed-port"] = port  # 不占用用户正在使用的固定端口。
        path = tmp_path / "config.yaml"
        write_config(path, config)
        process = subprocess.Popen([binary, "-d", str(tmp_path), "-f", str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while True:
            assert process.poll() is None, "合成 CI 配置未能启动内核"
            try:
                connection = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                assert time.monotonic() < deadline, "合成代理未按时监听"
                time.sleep(0.05)
        with connection:
            connection.settimeout(5)
            connection.sendall(b"GET http://127.0.0.1:1/probe HTTP/1.1\r\nHost: 127.0.0.1:1\r\nConnection: close\r\n\r\n")
            response = bytearray()
            while chunk := connection.recv(4096):
                response.extend(chunk)
                assert len(response) < 8192
        assert b"200 OK" in response and b"synthetic-proxy-ok" in response
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)


def test_main_bad_yaml_does_not_print_parser_diagnostics(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CLASH_CONFIG", "proxies: [private-password")
    assert main([str(tmp_path / "config.yaml")]) == 1
    assert "private-password" not in capsys.readouterr().out
    assert not (tmp_path / "config.yaml").exists()
