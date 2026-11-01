"""mihomo 代理桥纯函数回归；不启动真实 mihomo。"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys

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


def test_build_bridge_config_splits_domains_to_a_second_node() -> None:
    """同一账号可能同时访问两个互相不可达的目标，只能按域名分流。

    实测：agentrouter.org 走默认路由正常、东京节点 TLS 直接断；linux.do 反之，
    默认路由过不了 Cloudflare。单出口必然有一边失败。
    """
    raw = outbound()
    other = {**raw, "server": "split.example"}
    config = proxy_bridge.build_bridge_config(
        raw, port=18080, username="bridge", password="secret",
        split={"domains": ["linux.do", "connect.linux.do"], "outbound": other},
    )

    assert len(config["proxies"]) == 2
    assert any(proxy["server"] == "split.example" for proxy in config["proxies"])
    rules = config["rules"]
    assert "DOMAIN-SUFFIX,linux.do,bridge-node-split" in rules
    assert "DOMAIN-SUFFIX,connect.linux.do,bridge-node-split" in rules
    assert rules[-1] == "MATCH,bridge-node", "兜底规则必须留在最后"


def test_build_bridge_config_ignores_split_without_usable_outbound() -> None:
    raw = outbound()
    config = proxy_bridge.build_bridge_config(
        raw, port=18080, username="bridge", password="secret", split={"domains": ["linux.do"]},
    )

    assert config["proxies"] == [{"name": "bridge-node", **raw}]
    assert config["rules"] == ["MATCH,bridge-node"]


@pytest.mark.parametrize("url,expected", [
    ("http://127.0.0.1:7897", {"type": "http", "server": "127.0.0.1", "port": 7897}),
    ("127.0.0.1:7897", {"type": "http", "server": "127.0.0.1", "port": 7897}),
    ("socks5://u:p%40ss@10.0.0.2:1080",
     {"type": "socks5", "server": "10.0.0.2", "port": 1080, "username": "u", "password": "p@ss"}),
    ("https://proxy.example.invalid", {"type": "http", "server": "proxy.example.invalid", "port": 443, "tls": True}),
])
def test_plain_proxy_url_becomes_bridge_outbound(url, expected) -> None:
    from config.proxies import plain_outbound

    assert plain_outbound(url) == expected


def _split_engine_case(monkeypatch, network: dict):
    import asyncio
    from config.overlay import Overlay
    from config.proxies import parse_groups
    from config.schema import parse_account
    from runtime import engine

    groups = parse_groups([{
        "id": "jp", "name": "JP", "selected": "n1",
        "proxies": [{"id": "n1", "name": "n1", "clash": outbound()}],
    }])
    spec = parse_account({
        "id": "ar", "name": "AR", "base_url": "https://agentrouter.org", "template": "newapi",
        "network": network, "tasks": [{"id": "daily", "method": "http_api"}],
    })
    created = []

    class FakeBridge:
        def __init__(self, outbound, *, log=None, split=None):
            created.append({"outbound": outbound, "split": split})

        def start(self):
            return "http://bridge:secret@127.0.0.1:18080"

        def close(self):
            pass

    seen = {}

    async def fake_run(spec, account, proxy_url, **_kwargs):
        seen["proxy"] = proxy_url
        return engine.AccountRun(spec.id, spec.name, spec.base_url, ())

    monkeypatch.setattr(engine, "_bridge_factory", FakeBridge)
    monkeypatch.setattr(engine, "_run_tasks", fake_run)
    monkeypatch.setattr(engine, "_keepalive_shared", lambda *a, **k: asyncio.sleep(0))
    asyncio.run(engine.run_account(spec, overlay=Overlay(), proxy_groups=groups, structured=False, environ_proxy=""))
    return created, seen


def test_plain_proxy_with_domain_split_starts_bridge(monkeypatch) -> None:
    """AgentRouter 用本机代理，linux.do / github.com 的 OAuth 走另一个节点。"""
    created, seen = _split_engine_case(monkeypatch, {
        "proxy": "http://127.0.0.1:7897",
        "proxy_split": {"domains": ["linux.do", "github.com"], "proxy_group": "jp"},
    })
    assert len(created) == 1
    assert created[0]["outbound"] == {"type": "http", "server": "127.0.0.1", "port": 7897}
    assert created[0]["split"]["domains"] == ["linux.do", "github.com"]
    assert created[0]["split"]["outbound"]["server"] == "edge.example.invalid"
    assert seen["proxy"] == "http://bridge:secret@127.0.0.1:18080"
    # 真实桥会 JSON 序列化出站与分流配置；只读 mappingproxy 曾在这里抛 TypeError。
    import json

    json.dumps(created[0])
    proxy_bridge.ProxyBridge(created[0]["outbound"], split=created[0]["split"])._config_text(18080)


def test_group_bridge_outbound_is_json_serializable(monkeypatch) -> None:
    import json

    created, _seen = _split_engine_case(monkeypatch, {"proxy_group": "jp", "proxy_mode": "group"})
    assert len(created) == 1
    json.dumps(created[0]["outbound"])


def test_plain_proxy_without_split_stays_unbridged(monkeypatch) -> None:
    created, seen = _split_engine_case(monkeypatch, {"proxy": "http://127.0.0.1:7897"})
    assert created == []
    assert seen["proxy"] == "http://127.0.0.1:7897"


# ── 组内故障转移 ────────────────────────────────────────────────────────────
def _failover(*servers: str, url: str = "https://linux.do/", interval: int = 120) -> dict:
    return {"outbounds": [{**outbound(), "server": server} for server in servers],
            "names": [f"n-{server}" for server in servers], "url": url, "interval": interval}


def test_failover_builds_fallback_group_with_primary_first() -> None:
    """美国 runner 到台湾家宽经常连不上：当前节点失效时由 mihomo fallback 组换下一个。"""
    config = proxy_bridge.build_bridge_config(
        outbound(), port=18080, username="bridge", password="secret",
        failover=_failover("b1.example", "b2.example"),
    )
    names = [proxy["name"] for proxy in config["proxies"]]
    assert names == ["bridge-node", "bridge-node-backup1", "bridge-node-backup2"]
    assert [proxy["server"] for proxy in config["proxies"]] == ["edge.example.invalid", "b1.example", "b2.example"]
    (group,) = config["proxy-groups"]
    assert group["type"] == "fallback", "fallback 只在当前节点失效时换出口；url-test 会按延迟抖动换 IP"
    assert group["proxies"] == names, "当前选择的节点必须排第一，健康时始终用它"
    assert group["url"] == "https://linux.do/" and group["interval"] == 120
    assert group["lazy"] is False and group["timeout"] > 0 and group["max-failed-times"] >= 1
    assert config["rules"] == [f"MATCH,{group['name']}"]
    assert config["external-controller"] == "" and config["bind-address"] == "127.0.0.1"


def test_failover_without_usable_backups_keeps_single_node_config() -> None:
    plain = proxy_bridge.build_bridge_config(outbound(), port=18080, username="bridge", password="secret")
    for empty in (None, {}, {"outbounds": []}, {"outbounds": [{"type": "vless"}]}):
        config = proxy_bridge.build_bridge_config(
            outbound(), port=18080, username="bridge", password="secret", failover=empty,
        )
        assert config == plain
        assert "proxy-groups" not in config


def test_split_failover_routes_split_domains_to_their_own_fallback_group() -> None:
    """agentrouter-l / anyrounter：主出口是普通代理，linux.do 分流到带备用节点的组。"""
    main = {"type": "http", "server": "127.0.0.1", "port": 7897}
    config = proxy_bridge.build_bridge_config(
        main, port=18080, username="bridge", password="secret",
        split={"domains": ["linux.do"], "outbound": {**outbound(), "server": "tw.example"},
               "failover": _failover("jp.example")},
    )
    (group,) = config["proxy-groups"]
    assert group["name"] == "bridge-node-split-auto"
    assert group["proxies"] == ["bridge-node-split", "bridge-node-split-backup1"]
    assert config["rules"] == ["DOMAIN-SUFFIX,linux.do,bridge-node-split-auto", "MATCH,bridge-node"]
    assert config["proxies"][0] == {"name": "bridge-node", **main}


def test_failover_config_passes_real_mihomo_validation(tmp_path: Path) -> None:
    """生成的 fallback 组字段必须被真实 mihomo 接受（本机/CI 有 mihomo 时才运行）。"""
    import json
    import subprocess

    binary = proxy_bridge.find_mihomo()
    if not binary:
        pytest.skip("未安装 mihomo")
    anytls = {"type": "anytls", "server": "a.example.invalid", "port": 443, "password": "p", "sni": "s.invalid",
              "skip-cert-verify": True, "udp": True}
    config = proxy_bridge.build_bridge_config(
        anytls, port=18080, username="bridge", password="secret",
        failover={"outbounds": [{**anytls, "server": "b.example.invalid"}], "url": "https://linux.do/",
                  "interval": 60},
        split={"domains": ["linux.do"], "outbound": {**anytls, "server": "c.example.invalid"},
               "failover": {"outbounds": [{**anytls, "server": "d.example.invalid"}]}},
    )
    path = tmp_path / "config.yaml"
    path.write_text(json.dumps(config), encoding="utf-8")
    completed = subprocess.run([binary, "-t", "-d", str(tmp_path), "-f", str(path)],
                               capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    assert completed.returncode == 0, proxy_bridge._error_category(completed.stdout + completed.stderr)


@pytest.mark.parametrize("split,failover,expected", [
    (None, None, []),
    (None, _failover("b.example", url="https://cp.cloudflare.com/generate_204"),
     ["https://cp.cloudflare.com/generate_204"]),
    # 分流出口的探测必须命中分流域名，否则请求会走主出口，测不到分流节点。
    ({"domains": ["linux.do"], "outbound": outbound(), "failover": _failover("b.example", url="https://linux.do/")},
     None, ["https://linux.do/"]),
    ({"domains": ["linux.do"], "outbound": outbound(),
      "failover": _failover("b.example", url="https://cp.cloudflare.com/generate_204")}, None, ["https://linux.do/"]),
    # 主出口的探测 URL 被分流规则截走时改用默认地址。
    ({"domains": ["linux.do"], "outbound": outbound()}, _failover("b.example", url="https://connect.linux.do/"),
     ["https://cp.cloudflare.com/generate_204"]),
    ({"domains": ["linux.do"], "outbound": outbound()}, None, []),
])
def test_warmup_targets_follow_routing(split, failover, expected) -> None:
    assert proxy_bridge.warmup_targets(split, failover) == expected


class _AliveProcess:
    def poll(self):
        return None


def _bridge_for_warmup(monkeypatch, results, *, budget=5.0, failover=None, split=None):
    calls = []

    def probe(url, target, timeout):
        calls.append(target)
        return results.pop(0) if results else False

    monkeypatch.setattr(proxy_bridge, "_probe_through", probe)
    monkeypatch.setattr(proxy_bridge, "WARMUP_RETRY_INTERVAL", 0.0)
    logs: list[str] = []
    bridge = proxy_bridge.ProxyBridge(outbound(), log=logs.append, split=split,
                                      failover=failover, warmup_budget=budget)
    bridge.url = "http://bridge:secret@127.0.0.1:18080"
    bridge._process = _AliveProcess()
    return bridge, calls, logs


def test_warmup_retries_until_failover_group_connects(monkeypatch) -> None:
    bridge, calls, logs = _bridge_for_warmup(monkeypatch, [False, False, True], failover=_failover("b.example"))
    bridge._warm_up()
    assert calls == ["https://linux.do/"] * 3
    assert logs == ["代理桥预热：经故障转移组连通 linux.do（第 3 次）"]


def test_warmup_budget_exhaustion_is_logged_not_raised(monkeypatch) -> None:
    bridge, calls, logs = _bridge_for_warmup(monkeypatch, [], budget=0.2, failover=_failover("b.example"))
    bridge._warm_up()
    assert calls, "预算内至少探测一次"
    assert len(logs) == 1 and "未连通 linux.do" in logs[0] and "继续执行" in logs[0]


def test_warmup_skipped_without_failover(monkeypatch) -> None:
    bridge, calls, logs = _bridge_for_warmup(monkeypatch, [True])
    bridge._warm_up()
    assert calls == [] and logs == []


def test_failover_credentials_stay_out_of_bridge_repr_and_logs(monkeypatch) -> None:
    secret_backup = {**outbound(), "server": "b.example", "uuid": "22222222-2222-2222-2222-222222222222"}
    bridge, _calls, logs = _bridge_for_warmup(
        monkeypatch, [True], failover={"outbounds": [secret_backup], "url": "https://linux.do/"},
    )
    bridge._warm_up()
    text = repr(bridge) + "\n".join(logs)
    assert secret_backup["uuid"] not in text and "b.example" not in text
    assert secret_backup["uuid"] in bridge._config_text(18080), "凭据只进入私有配置文件"


def _failover_engine_case(monkeypatch, network: dict):
    import asyncio
    from config.overlay import Overlay
    from config.proxies import parse_groups
    from config.schema import parse_account
    from runtime import engine

    groups = parse_groups([{
        "id": "pool", "name": "Pool", "selected": "tw",
        "failover": {"nodes": ["jp", "新加坡"], "url": "https://linux.do/", "interval": 60},
        "proxies": [
            {"id": "tw", "name": "台湾", "clash": {**outbound(), "server": "tw.example"}},
            {"id": "jp", "name": "日本", "clash": {**outbound(), "server": "jp.example"}},
            {"id": "sg", "name": "新加坡", "clash": {**outbound(), "server": "sg.example"}},
        ],
    }])
    spec = parse_account({
        "id": "ld", "name": "LD", "base_url": "https://linux.do", "template": "newapi",
        "network": network, "tasks": [{"id": "daily", "method": "http_api"}],
    })
    created = []

    class FakeBridge:
        def __init__(self, outbound, *, log=None, split=None, failover=None):
            created.append({"outbound": outbound, "split": split, "failover": failover})

        def start(self):
            return "http://bridge:secret@127.0.0.1:18080"

        def close(self):
            pass

    async def fake_run(spec, account, proxy_url, **_kwargs):
        return engine.AccountRun(spec.id, spec.name, spec.base_url, ())

    monkeypatch.setattr(engine, "_bridge_factory", FakeBridge)
    monkeypatch.setattr(engine, "_run_tasks", fake_run)
    monkeypatch.setattr(engine, "_keepalive_shared", lambda *a, **k: asyncio.sleep(0))
    asyncio.run(engine.run_account(spec, overlay=Overlay(), proxy_groups=groups, structured=False, environ_proxy=""))
    return created


def test_engine_passes_group_failover_to_bridge(monkeypatch) -> None:
    import json

    created = _failover_engine_case(monkeypatch, {"proxy_group": "pool", "proxy_mode": "group"})
    (call,) = created
    assert call["outbound"]["server"] == "tw.example"
    assert [item["server"] for item in call["failover"]["outbounds"]] == ["jp.example", "sg.example"]
    assert call["failover"]["names"] == ["日本", "新加坡"]
    assert call["failover"]["url"] == "https://linux.do/" and call["failover"]["interval"] == 60
    json.dumps(call)
    proxy_bridge.ProxyBridge(call["outbound"], failover=call["failover"])._config_text(18080)


def test_engine_split_inherits_target_group_failover(monkeypatch) -> None:
    created = _failover_engine_case(monkeypatch, {
        "proxy": "http://127.0.0.1:7897",
        "proxy_split": {"domains": ["linux.do"], "proxy_group": "pool"},
    })
    (call,) = created
    assert call["outbound"] == {"type": "http", "server": "127.0.0.1", "port": 7897}
    assert call["failover"] is None, "主出口是自定义代理，没有组内备用节点"
    assert call["split"]["outbound"]["server"] == "tw.example"
    assert [item["server"] for item in call["split"]["failover"]["outbounds"]] == ["jp.example", "sg.example"]
    config = proxy_bridge.ProxyBridge(call["outbound"], split=call["split"])._config_text(18080)
    assert "bridge-node-split-auto" in config


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


@pytest.fixture
def isolated_discovery(monkeypatch):
    # 不受运行测试的机器的 PATH、安装目录或注册表影响。
    monkeypatch.setattr(proxy_bridge.shutil, "which", lambda *args, **kwargs: None)
    monkeypatch.setattr(proxy_bridge, "_platform_candidates", lambda env: [])
    monkeypatch.setattr(proxy_bridge, "_windows_verge_roots", lambda: [])
    monkeypatch.setattr(proxy_bridge.platform, "machine", lambda: "AMD64")


@pytest.mark.parametrize("variable,folder", [
    ("ProgramFiles", "Clash Verge"),
    ("ProgramW6432", "Clash Verge Rev"),
    ("ProgramFiles(x86)", "Clash Verge"),
    ("LOCALAPPDATA", "Programs/Clash Verge"),
    ("LOCALAPPDATA", "Clash Verge Rev"),
    ("USERPROFILE", "AppData/Local/Programs/Clash Verge"),
])
@pytest.mark.parametrize("filename", [
    "verge-mihomo.exe", "mihomo.exe", "verge-mihomo-x86_64-pc-windows-msvc.exe",
    "mihomo-windows-amd64.exe", "verge-mihomo-alpha.exe",
])
def test_windows_verge_default_installs(isolated_discovery, monkeypatch, tmp_path, variable, folder, filename):
    monkeypatch.setattr(proxy_bridge.sys, "platform", "win32")
    binary = tmp_path / folder / filename
    binary.parent.mkdir(parents=True)
    binary.write_text("stub")
    binary.chmod(0o700)
    assert proxy_bridge.find_mihomo({variable: str(tmp_path), "PATH": ""}) == str(binary)


@pytest.mark.parametrize("system,root,filename,machine", [
    ("darwin", "/Applications/Clash Verge.app/Contents/MacOS", "verge-mihomo", "x86_64"),
    ("darwin", "/Applications/Clash Verge Rev.app/Contents/Resources/binaries", "mihomo-aarch64-apple-darwin", "arm64"),
    ("darwin", "/home/test/Applications/Clash Verge.app/Contents/MacOS", "verge-mihomo", "arm64"),
    ("linux", "/usr/lib/clash-verge", "verge-mihomo", "x86_64"),
    ("linux", "/opt/clash-verge-rev/resources", "mihomo", "x86_64"),
    ("linux", "/usr/lib/clash-verge/resources/binaries", "verge-mihomo-x86_64-unknown-linux-gnu", "x86_64"),
    ("linux", "/usr/bin", "verge-mihomo", "x86_64"),
])
def test_unix_verge_locations(isolated_discovery, monkeypatch, system, root, filename, machine):
    monkeypatch.setattr(proxy_bridge.sys, "platform", system)
    monkeypatch.setattr(proxy_bridge.platform, "machine", lambda: machine)
    binary = Path(root) / filename
    monkeypatch.setattr(proxy_bridge, "_executable", lambda path: path == binary)
    assert Path(proxy_bridge.find_mihomo({"PATH": "", "HOME": "/home/test"})) == binary


def test_existing_discovery_priority(isolated_discovery, monkeypatch):
    legacy, verge, explicit = map(Path, ("legacy/mihomo", "verge/mihomo", "explicit/mihomo"))
    monkeypatch.setattr(proxy_bridge, "_platform_candidates", lambda env: [legacy])
    monkeypatch.setattr(proxy_bridge, "_verge_candidates", lambda env: [verge])
    monkeypatch.setattr(proxy_bridge, "_executable", lambda path: True)
    assert proxy_bridge.find_mihomo({"PATH": ""}) == str(legacy)
    monkeypatch.setattr(proxy_bridge.shutil, "which", lambda *args, **kwargs: "path/mihomo")
    assert proxy_bridge.find_mihomo({"PATH": ""}) == "path/mihomo"
    assert proxy_bridge.find_mihomo({proxy_bridge.ENV_BINARY: str(explicit)}) == str(explicit)
    monkeypatch.setattr(proxy_bridge, "_executable", lambda path: path != explicit)
    assert proxy_bridge.find_mihomo({proxy_bridge.ENV_BINARY: str(explicit)}) is None


def test_gui_only_and_invalid_paths_are_not_kernels(isolated_discovery, monkeypatch, tmp_path):
    monkeypatch.setattr(proxy_bridge.sys, "platform", "win32")
    root = tmp_path / "Clash Verge"
    root.mkdir()
    for filename in ("Clash Verge.exe", "clash-verge.exe", "verge-mihomo.exe.bak"):
        (root / filename).write_text("GUI")
    (root / "mihomo.exe").mkdir()  # 同名目录不是内核
    assert proxy_bridge.mihomo_status({"ProgramFiles": str(tmp_path), "PATH": ""}) == {
        "available": False, "name": "",
    }
    assert proxy_bridge.find_mihomo({"ProgramFiles": "bad\x00path", "PATH": ""}) is None
    assert proxy_bridge.find_mihomo({proxy_bridge.ENV_BINARY: "bad\x00path"}) is None
    with pytest.raises(ConfigError, match="不会改用直连"):
        proxy_bridge.require_mihomo({"PATH": ""})


def test_unix_kernel_requires_execute_permission(monkeypatch, tmp_path):
    binary = tmp_path / "mihomo"
    binary.write_text("stub")
    monkeypatch.setattr(proxy_bridge.os, "access", lambda *args: False)
    # 单独模拟 os，避免修改共享 os.name 导致 pathlib/pytest 切换平台。
    monkeypatch.setattr(proxy_bridge, "os", SimpleNamespace(name="posix", access=lambda *args: False, X_OK=1))
    assert not proxy_bridge._executable(binary)


def test_windows_registry_custom_install(monkeypatch, tmp_path):
    root = tmp_path / "custom install"
    class Key:
        def __init__(self, name):
            self.name = name
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
    entries = {
        "verge": {"DisplayName": "Clash Verge", "InstallLocation": str(root)},
        "rev": {"DisplayName": "Clash Verge Rev", "DisplayIcon": f'"{root / "Clash Verge.exe"}",0'},
        "other": {"DisplayName": "Other App", "InstallLocation": str(tmp_path / "other")},
        "bad": {"DisplayName": "Clash Verge", "InstallLocation": "relative/path", "DisplayIcon": "bad\x00path"},
    }
    def query(key, name):
        if name not in entries[key.name]:
            raise OSError("missing")
        return entries[key.name][name], 1
    def open_key(parent, name, *args):
        return Key(name if isinstance(parent, Key) else "uninstall")
    fake = SimpleNamespace(HKEY_CURRENT_USER=1, HKEY_LOCAL_MACHINE=2,
                           KEY_WOW64_64KEY=256, KEY_WOW64_32KEY=512, KEY_READ=1,
                           OpenKey=open_key, QueryInfoKey=lambda key: (len(entries), 0, 0),
                           EnumKey=lambda key, index: list(entries)[index], QueryValueEx=query)
    # 不让 platform.machine() 的首次系统探测误用这个只实现卸载注册表的替身。
    monkeypatch.setattr(proxy_bridge.platform, "machine", lambda: "AMD64")
    monkeypatch.setitem(sys.modules, "winreg", fake)
    assert proxy_bridge._windows_verge_roots() == [root]
    monkeypatch.setattr(proxy_bridge.sys, "platform", "win32")
    monkeypatch.setattr(proxy_bridge.shutil, "which", lambda *args, **kwargs: None)
    monkeypatch.setattr(proxy_bridge, "_platform_candidates", lambda env: [])
    binary = root / "resources" / "verge-mihomo.exe"
    binary.parent.mkdir(parents=True)
    binary.write_text("stub")
    binary.chmod(0o700)
    assert proxy_bridge.require_mihomo({"PATH": ""}) == str(binary)
    assert proxy_bridge.mihomo_status({"PATH": ""}) == {"available": True, "name": binary.name}
    def denied(*args):
        raise PermissionError("denied")
    fake.OpenKey = denied
    assert proxy_bridge._windows_verge_roots() == []
    assert proxy_bridge.find_mihomo({"PATH": ""}) is None


def test_error_category_only_extracts_fixed_mihomo_prefix() -> None:
    assert proxy_bridge._error_category("proxy 0: invalid uuid") == "invalid uuid"
    assert proxy_bridge._error_category("secret uuid=private-value") == ""
