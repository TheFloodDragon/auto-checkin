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
