"""settings.yml 与纯内置默认模板；所有配置和节点都是临时合成数据。"""

from __future__ import annotations

import ast
import builtins
import importlib
import json
import os
import subprocess
import sys
import traceback
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    from config import paths, settings

    for name in list(os.environ):
        if name == "SETTINGS" or name.startswith("CHECKIN_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(paths, "SETTINGS_PATH", tmp_path / "settings.yml")
    monkeypatch.setattr(paths, "SETTINGS_DEFAULT_PATH", tmp_path / "settings.default.yml")
    module = importlib.reload(settings)
    yield module
    # 即使测试故意损坏文件/预设，退出时也恢复到安全的无覆盖类常量。
    with monkeypatch.context() as restore:
        for name in list(os.environ):
            if name == "SETTINGS" or name.startswith("CHECKIN_"):
                restore.delenv(name, raising=False)
        restore.setattr(paths, "SETTINGS_PATH", tmp_path / "restore-settings.yml")
        importlib.reload(settings)


def _read_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _groups():
    return [{
        "id": "office", "name": "办公代理", "current": "first",
        "proxies": [
            {
                "id": "first", "name": "节点一", "url": "socks5://test-user:test-pass@127.0.0.1:1080",
                "subscription_id": "subscription-one", "extension": {"weight": 2, "tags": ["test"]},
            },
            {
                "id": "second", "name": "节点二",
                "clash": {"type": "trojan", "server": "node.invalid", "port": 443, "password": "fake-secret"},
                "subscription": {"source": "subscription-one", "raw_name": "原始节点"},
            },
        ],
        "subscriptions": [{
            "id": "subscription-one", "url": "https://subscription.invalid/synthetic-token",
            "headers": {"Authorization": "Bearer synthetic-token"}, "refresh_interval": 3600,
            "extra": {"updated_at": "2025-01-01T00:00:00Z", "enabled": False},
        }],
        "extension": {"region": "test", "feature": None},
    }]


def test_import_is_read_only_and_does_not_import_proxy_schema(cfg, monkeypatch):
    from config import paths

    def unexpected(*args, **kwargs):
        raise AssertionError("模块导入不能加锁或写文件")

    original_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "proxies" or name == "config.proxies":
            raise AssertionError("初始配置读取不能导入代理 schema")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(paths, "file_lock", unexpected)
    monkeypatch.setattr(paths, "atomic_write_text", unexpected)
    monkeypatch.setattr(builtins, "__import__", guarded_import)
    importlib.reload(cfg)
    assert not paths.SETTINGS_PATH.exists()
    assert not paths.SETTINGS_DEFAULT_PATH.exists()
    assert not paths.SETTINGS_PATH.with_suffix(".yml.lock").exists()


def test_stdlib_import_skips_all_sources_but_real_load_save_require_pyyaml(cfg, tmp_path):
    target = tmp_path / "stdlib" / "settings.yml"
    target.parent.mkdir()
    raw = "HTTP_REQUEST: 51\nnode: [synthetic-token\n"
    target.write_text(raw, encoding="utf-8")
    code = """
import importlib
import os
import sys
from pathlib import Path

target = Path(sys.argv[1])
assert target.exists()
def unexpected_read(*args, **kwargs):
    raise AssertionError("stdlib settings initialization cannot read any configuration source")
Path.read_text = unexpected_read
from config import paths, settings
from core.errors import ConfigError

assert settings.Timeouts.HTTP_REQUEST == 7
assert settings.Timeouts.BROWSER_TASK == 420.0
assert settings.FileLockConfig.DEFAULT_TIMEOUT == 2.5
assert settings.default_payload()["HTTP_REQUEST"] == 30
paths.SETTINGS_PATH = target
paths.SETTINGS_DEFAULT_PATH = target.with_name("settings.default.yml")
os.environ.pop("SETTINGS", None)
settings = importlib.reload(settings)
assert settings.Timeouts.HTTP_REQUEST == 7
for operation in (lambda: settings.load(), lambda: settings.save({"HTTP_REQUEST": 41})):
    try:
        operation()
    except ConfigError as exc:
        assert "PyYAML" in str(exc)
    else:
        raise AssertionError("real settings IO must not silently proceed without PyYAML")
assert not paths.SETTINGS_DEFAULT_PATH.exists()
"""
    env = {**os.environ, "PYTHONPATH": str(Path(cfg.__file__).resolve().parents[1]), "PYTHONIOENCODING": "utf-8",
           "SETTINGS": "node: [synthetic-token", "CHECKIN_HTTP_REQUEST": "7",
           "CHECKIN_BROWSER_TASK": "nan", "CHECKIN_FILE_LOCK_TIMEOUT": "2.5"}
    completed = subprocess.run(
        [sys.executable, "-B", "-S", "-c", code, str(target)], cwd=tmp_path, env=env,
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert "CHECKIN_BROWSER_TASK" in completed.stderr
    assert "synthetic-token" not in completed.stderr
    assert target.read_text(encoding="utf-8") == raw


def test_first_load_creates_persistent_config_and_pure_template(cfg):
    from config import paths

    expected = cfg.default_payload()
    assert cfg.load() == expected
    assert _read_yaml(paths.SETTINGS_PATH) == expected
    assert _read_yaml(paths.SETTINGS_DEFAULT_PATH) == expected
    assert cfg.settings_path() == paths.SETTINGS_PATH


def test_template_includes_every_registered_builtin_parameter(cfg):
    from config import paths

    source = ast.parse(Path(cfg.__file__).read_text(encoding="utf-8"))
    getters = {"_env_int", "_env_float", "_env_flag", "_env_int_set"}
    names = {
        node.args[0].value
        for node in ast.walk(source)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id in getters and isinstance(node.args[0], ast.Constant)
    }
    cfg.load()
    template = _read_yaml(paths.SETTINGS_DEFAULT_PATH)
    assert set(template) == names | {"proxy_groups", "default_proxy_group"}
    assert len(names) == 18
    assert template == cfg.default_payload()
    assert template["RETRY_STATUS_CODES"] == [429, 500, 502, 503, 504]
    assert template["proxy_groups"] == [] and template["default_proxy_group"] == ""
    assert "LOCK_SIZE" not in template
    assert cfg.FileLockConfig.LOCK_SIZE == 1


def test_default_payload_is_an_independent_copy(cfg):
    first = cfg.default_payload()
    first["proxy_groups"].append({"id": "not-a-real-node"})
    first["RETRY_STATUS_CODES"].clear()
    second = cfg.default_payload()
    assert second["proxy_groups"] == []
    assert second["RETRY_STATUS_CODES"] == [429, 500, 502, 503, 504]


def test_environment_changes_runtime_but_neither_persistent_config_nor_template(cfg, monkeypatch):
    from config import paths

    default = cfg.default_payload()
    preset = {"HTTP_REQUEST": 41, "BROWSER_TASK": 700.0, "LOG_HTTP_BODY": False,
              "RETRY_STATUS_CODES": [418], "proxy_groups": _groups(), "default_proxy_group": "office"}
    monkeypatch.setenv("SETTINGS", yaml.safe_dump(preset))
    monkeypatch.setenv("CHECKIN_HTTP_REQUEST", "9")
    monkeypatch.setenv("CHECKIN_BROWSER_TASK", "500")
    monkeypatch.setenv("CHECKIN_LOG_HTTP_BODY", "true")
    monkeypatch.setenv("CHECKIN_RETRY_STATUS_CODES", "429,503")
    monkeypatch.setenv("CHECKIN_LOCK_SIZE", "10")
    cfg = importlib.reload(cfg)
    assert cfg.Timeouts.HTTP_REQUEST == 9
    assert cfg.Timeouts.BROWSER_TASK == 500.0
    assert cfg.LogConfig.HTTP_BODY is True
    assert cfg.RetryConfig.STATUS_CODES == frozenset({429, 503})
    assert cfg.FileLockConfig.LOCK_SIZE == 1
    loaded = cfg.load()
    assert {key: loaded[key] for key in preset} == preset
    assert _read_yaml(paths.SETTINGS_PATH) == loaded
    assert _read_yaml(paths.SETTINGS_DEFAULT_PATH) == default
    loaded["HTTP_REQUEST"] = 43
    assert cfg.save(loaded) == paths.SETTINGS_PATH
    assert _read_yaml(paths.SETTINGS_PATH)["HTTP_REQUEST"] == 43
    assert _read_yaml(paths.SETTINGS_DEFAULT_PATH) == default
    template_text = paths.SETTINGS_DEFAULT_PATH.read_text(encoding="utf-8")
    assert "synthetic-token" not in template_text and "test-pass" not in template_text


@pytest.mark.parametrize("format", ["yaml", "json", "dtg1"])
def test_settings_supports_yaml_json_and_compressed_json_presets(cfg, monkeypatch, format):
    from config import paths
    from config.secret_codec import encode_secret

    preset = {"HTTP_REQUEST": 42, "extension": {"ratio": 1e-12, "tags": [None, False, "测试"]}}
    raw = yaml.safe_dump(preset) if format == "yaml" else json.dumps(preset, ensure_ascii=False)
    if format == "dtg1":
        raw = encode_secret(raw, limit=1).text
        assert raw.startswith("DTG1:")
    monkeypatch.setenv("SETTINGS", raw)
    cfg = importlib.reload(cfg)
    assert cfg.Timeouts.HTTP_REQUEST == 42
    assert cfg.load()["extension"] == preset["extension"]
    assert _read_yaml(paths.SETTINGS_PATH)["HTTP_REQUEST"] == 42
    assert _read_yaml(paths.SETTINGS_DEFAULT_PATH)["HTTP_REQUEST"] == 30


@pytest.mark.parametrize("suffix", [".yml", ".yaml", ".json"])
def test_settings_file_path_selects_mounted_file_and_sibling_template(cfg, monkeypatch, tmp_path, suffix):
    from config import paths

    mounted = tmp_path / "mounted"
    mounted.mkdir()
    target = mounted / ("custom" + suffix)
    target.write_text(json.dumps({"HTTP_REQUEST": 55, "extension": [1, 2]}), encoding="utf-8")
    monkeypatch.setenv("SETTINGS", str(target))
    cfg = importlib.reload(cfg)
    assert cfg.settings_path() == target
    assert cfg.Timeouts.HTTP_REQUEST == 55
    assert cfg.load()["extension"] == [1, 2]
    assert _read_yaml(mounted / "settings.default.yml")["HTTP_REQUEST"] == 30
    assert not paths.SETTINGS_PATH.exists() and not paths.SETTINGS_DEFAULT_PATH.exists()
    if suffix == ".json":
        assert json.loads(target.read_text(encoding="utf-8"))["HTTP_REQUEST"] == 55
    assert cfg.save({"HTTP_REQUEST": 56}) == target
    assert cfg.Timeouts.HTTP_REQUEST == 55, "显式保存的参数下次启动才生效"


def test_missing_settings_file_path_is_created_only_by_load(cfg, monkeypatch, tmp_path):
    target = tmp_path / "docker-mounted" / "settings.yaml"
    monkeypatch.setenv("SETTINGS", str(target))
    cfg = importlib.reload(cfg)
    assert not target.exists() and not target.parent.exists()
    assert cfg.load() == cfg.default_payload()
    assert target.exists()
    assert (target.parent / "settings.default.yml").exists()


def test_explicit_path_has_priority_over_settings_file_path(cfg, monkeypatch, tmp_path):
    mounted = tmp_path / "mounted.yml"
    mounted.write_text("HTTP_REQUEST: 49\n", encoding="utf-8")
    explicit = tmp_path / "explicit" / "custom.yml"
    explicit.parent.mkdir()
    explicit.write_text("HTTP_REQUEST: 57\n", encoding="utf-8")
    monkeypatch.setenv("SETTINGS", str(mounted))
    cfg = importlib.reload(cfg)
    assert cfg.settings_path(explicit) == explicit
    assert cfg.load(explicit)["HTTP_REQUEST"] == 57
    assert cfg.save({"HTTP_REQUEST": 58}, explicit) == explicit
    assert _read_yaml(explicit)["HTTP_REQUEST"] == 58
    assert _read_yaml(mounted) == {"HTTP_REQUEST": 49}
    assert cfg.Timeouts.HTTP_REQUEST == 49
    assert (explicit.parent / "settings.default.yml").exists()


def test_relative_settings_file_paths_are_repo_relative(cfg, monkeypatch, tmp_path):
    from config import paths

    monkeypatch.setattr(paths, "REPO_ROOT", tmp_path)
    monkeypatch.setenv("SETTINGS", "mounted/custom.yml")
    assert cfg.settings_path() == tmp_path / "mounted" / "custom.yml"
    cfg.load()
    assert (tmp_path / "mounted" / "custom.yml").exists()


def test_inline_yaml_ending_in_file_url_is_not_mistaken_for_a_path(cfg, monkeypatch):
    from config import paths

    monkeypatch.setenv("SETTINGS", "extension: https://subscription.invalid/synthetic-token.yml")
    assert cfg.settings_path() == paths.SETTINGS_PATH
    assert cfg.load()["extension"] == "https://subscription.invalid/synthetic-token.yml"


def test_existing_local_values_and_explicit_empty_values_override_presets(cfg, monkeypatch):
    from config import paths

    local = {"HTTP_REQUEST": 40, "LOG_HTTP_BODY": False, "RETRY_STATUS_CODES": [],
             "proxy_groups": [], "default_proxy_group": "", "extension": "", "nullable": None}
    paths.SETTINGS_PATH.write_text(yaml.safe_dump(local), encoding="utf-8")
    preset = {"HTTP_REQUEST": 12, "BROWSER_TASK": 555.0, "LOG_HTTP_BODY": True,
              "RETRY_STATUS_CODES": [503], "proxy_groups": _groups(), "default_proxy_group": "office",
              "extension": "preset", "nullable": "preset"}
    monkeypatch.setenv("SETTINGS", yaml.safe_dump(preset))
    cfg = importlib.reload(cfg)
    assert cfg.Timeouts.HTTP_REQUEST == 40
    assert cfg.RetryConfig.STATUS_CODES == frozenset()
    assert cfg.LogConfig.HTTP_BODY is False
    loaded = cfg.load()
    assert {key: loaded[key] for key in local} == local
    assert loaded["BROWSER_TASK"] == 555.0
    preset.update(HTTP_REQUEST=15, BROWSER_TASK=666.0, extension="changed preset")
    monkeypatch.setenv("SETTINGS", yaml.safe_dump(preset))
    assert cfg.load() == loaded
    cfg = importlib.reload(cfg)
    assert cfg.Timeouts.HTTP_REQUEST == 40 and cfg.Timeouts.BROWSER_TASK == 555.0


def test_missing_top_level_keys_are_filled_without_changing_local_unknown_keys(cfg):
    from config import paths

    local = {"HTTP_REQUEST": 37, "extension": {"feature": [False, None, 3]}}
    paths.SETTINGS_PATH.write_text(yaml.safe_dump(local), encoding="utf-8")
    loaded = cfg.load()
    assert loaded == {**cfg.default_payload(), **local}
    assert _read_yaml(paths.SETTINGS_PATH) == loaded


def test_nodes_subscriptions_and_unknown_fields_round_trip_without_filling_node_defaults(cfg):
    from config import paths

    raw = {"proxy_groups": _groups(), "default_proxy_group": "office",
           "root_extension": {"features": [None, False, 1.25]}, "HTTP_REQUEST": 38}
    original = deepcopy(raw)
    assert cfg.save(raw) == paths.SETTINGS_PATH
    assert raw == original, "保存不能修改调用者或 GUI 的原始草稿"
    loaded = cfg.load()
    assert loaded["proxy_groups"] == original["proxy_groups"]
    assert loaded["default_proxy_group"] == "office"
    assert loaded["root_extension"] == original["root_extension"]
    assert "enabled" not in loaded["proxy_groups"][0]
    assert "selected" not in loaded["proxy_groups"][0]
    assert "enabled" not in loaded["proxy_groups"][0]["proxies"][0]
    cfg.save(loaded)
    assert _read_yaml(paths.SETTINGS_PATH) == loaded
    assert _read_yaml(paths.SETTINGS_DEFAULT_PATH) == cfg.default_payload()


def test_repeated_load_preserves_both_mtimes_and_does_not_write(cfg, monkeypatch):
    from config import paths

    loaded = cfg.load()
    settings_mtime = paths.SETTINGS_PATH.stat().st_mtime_ns
    template_mtime = paths.SETTINGS_DEFAULT_PATH.stat().st_mtime_ns

    def unexpected(*args, **kwargs):
        raise AssertionError("完整配置与内置模板未改变时不能重复写盘")

    monkeypatch.setattr(paths, "atomic_write_text", unexpected)
    assert cfg.load() == loaded
    assert cfg.load() == loaded
    assert cfg.save(loaded) == paths.SETTINGS_PATH
    assert paths.SETTINGS_PATH.stat().st_mtime_ns == settings_mtime
    assert paths.SETTINGS_DEFAULT_PATH.stat().st_mtime_ns == template_mtime


def test_manually_changed_template_is_replaced_by_pure_defaults_only(cfg):
    from config import paths

    cfg.load()
    settings_mtime = paths.SETTINGS_PATH.stat().st_mtime_ns
    paths.SETTINGS_DEFAULT_PATH.write_text(yaml.safe_dump({"proxy_groups": _groups()}), encoding="utf-8")
    cfg.load()
    assert _read_yaml(paths.SETTINGS_DEFAULT_PATH) == cfg.default_payload()
    assert "synthetic-token" not in paths.SETTINGS_DEFAULT_PATH.read_text(encoding="utf-8")
    assert paths.SETTINGS_PATH.stat().st_mtime_ns == settings_mtime


def test_load_and_save_use_shared_lock_and_atomic_writer(cfg, monkeypatch):
    from config import paths

    original_lock, original_write = paths.file_lock, paths.atomic_write_text
    locked, written = [], []

    @contextmanager
    def tracking_lock(path, **kwargs):
        locked.append(path)
        with original_lock(path, **kwargs):
            yield

    def tracking_write(path, text):
        written.append(path)
        original_write(path, text)

    monkeypatch.setattr(paths, "file_lock", tracking_lock)
    monkeypatch.setattr(paths, "atomic_write_text", tracking_write)
    cfg.load()
    cfg.save({"HTTP_REQUEST": 39})
    assert locked == [paths.SETTINGS_PATH, paths.SETTINGS_PATH]
    assert set(written) == {paths.SETTINGS_PATH, paths.SETTINGS_DEFAULT_PATH}


def test_save_defaults_to_settings_path_and_does_not_refresh_runtime_constants(cfg, monkeypatch):
    from config import paths

    monkeypatch.setattr(cfg.Timeouts, "HTTP_REQUEST", 87)
    assert cfg.save({"HTTP_REQUEST": 39}) == paths.SETTINGS_PATH
    assert cfg.load()["HTTP_REQUEST"] == 39
    assert cfg.Timeouts.HTTP_REQUEST == 87, "不能打断运行中任务或重置消费者的 monkeypatch"
    cfg = importlib.reload(cfg)
    assert cfg.Timeouts.HTTP_REQUEST == 39


@pytest.mark.parametrize("raw", [
    "HTTP_REQUEST: [https://subscription.invalid/synthetic-token",
    "[https://subscription.invalid/synthetic-token]",
    "https://subscription.invalid/synthetic-token",
    "root: &loop [*loop]\nnote: synthetic-token",
    "date: 2025-01-01\nnote: synthetic-token",
    "binary: !!binary c3ludGhldGljLXRva2Vu",
    "value: !!set {synthetic-token: null}",
    "1: synthetic-token",
    "value: !!python/object:synthetic-token {}",
    "value: .nan\nnote: synthetic-token",
    "null # synthetic-token",
    "DTG1:synthetic-token",
    "proxy_groups: []\nproxy_groups: []\nnote: synthetic-token",
    '{"proxy_groups": [], "proxy_groups": [], "note": "synthetic-token"}',
    "extension:\n  token: synthetic-token\n  token: replacement",
])
def test_invalid_presets_raise_without_leaking_source_text(cfg, monkeypatch, raw):
    from core.errors import ConfigError

    monkeypatch.setenv("SETTINGS", raw)
    with pytest.raises(ConfigError) as caught:
        cfg.load()
    rendered = "".join(traceback.format_exception(caught.value))
    assert "SETTINGS" in str(caught.value)
    assert "synthetic-token" not in rendered
    assert "subscription.invalid" not in rendered
    assert raw not in str(caught.value)
    assert not cfg.settings_path().exists()


@pytest.mark.parametrize("raw", [
    "proxy_groups: [https://node.invalid/synthetic-token",
    "root: &loop {child: *loop}\nnote: synthetic-token",
    "[https://node.invalid/synthetic-token]",
    "value: .inf\nnote: synthetic-token",
    "proxy_groups: []\nproxy_groups: []\nnote: synthetic-token",
    '{"proxy_groups": [], "proxy_groups": [], "note": "synthetic-token"}',
])
def test_corrupt_files_raise_without_overwriting_or_leaking_node_text(cfg, raw):
    from config import paths
    from core.errors import ConfigError

    paths.SETTINGS_PATH.write_text(raw, encoding="utf-8")
    with pytest.raises(ConfigError) as caught:
        cfg.load()
    rendered = "".join(traceback.format_exception(caught.value))
    assert "配置文件" in str(caught.value)
    assert "synthetic-token" not in rendered and "node.invalid" not in rendered
    assert paths.SETTINGS_PATH.read_text(encoding="utf-8") == raw
    assert not paths.SETTINGS_DEFAULT_PATH.exists()


@pytest.mark.parametrize("changes", [
    {"proxy_groups": None}, {"proxy_groups": {}},
    {"proxy_groups": [{"id": "broken", "name": "组", "proxies": [{
        "id": "first", "name": "节点", "url": "ftp://test-user:synthetic-token@node.invalid:80",
    }]}]},
    {"default_proxy_group": "unknown"}, {"default_proxy_group": False},
])
def test_invalid_proxy_payloads_fail_without_leaking_credentials(cfg, changes):
    from config import paths
    from core.errors import ConfigError

    with pytest.raises(ConfigError) as caught:
        cfg.save(changes)
    rendered = "".join(traceback.format_exception(caught.value))
    assert "synthetic-token" not in rendered and "test-user" not in rendered
    assert not paths.SETTINGS_PATH.exists() and not paths.SETTINGS_DEFAULT_PATH.exists()


def test_invalid_file_numbers_fall_back_but_raw_values_remain_for_correction(cfg, capsys):
    from config import paths

    local = {"HTTP_REQUEST": 0, "BROWSER_TASK": "nan", "MAX_OUTPUT_SCAN": 999999999,
             "LOG_HTTP_BODY": "https://node.invalid/synthetic-token", "RETRY_STATUS_CODES": [429, "bad"]}
    paths.SETTINGS_PATH.write_text(yaml.safe_dump(local), encoding="utf-8")
    cfg = importlib.reload(cfg)
    assert cfg.Timeouts.HTTP_REQUEST == 30
    assert cfg.Timeouts.BROWSER_TASK == 420.0
    assert cfg.OutputConfig.MAX_OUTPUT_SCAN == 4096
    assert cfg.LogConfig.HTTP_BODY is True
    assert cfg.RetryConfig.STATUS_CODES == frozenset({429, 500, 502, 503, 504})
    loaded = cfg.load()
    assert {name: loaded[name] for name in local} == local
    assert {name: _read_yaml(paths.SETTINGS_PATH)[name] for name in local} == local
    warnings = capsys.readouterr().err
    assert all(name in warnings for name in local)
    assert "synthetic-token" not in warnings and "node.invalid" not in warnings


def test_invalid_environment_override_uses_existing_local_value(cfg, monkeypatch, capsys):
    from config import paths

    paths.SETTINGS_PATH.write_text("HTTP_REQUEST: 37\n", encoding="utf-8")
    monkeypatch.setenv("CHECKIN_HTTP_REQUEST", "not-a-number")
    cfg = importlib.reload(cfg)
    assert cfg.Timeouts.HTTP_REQUEST == 37
    assert cfg.load()["HTTP_REQUEST"] == 37
    assert "CHECKIN_HTTP_REQUEST" in capsys.readouterr().err


def test_non_json_compatible_save_payloads_are_rejected_before_writing(cfg):
    from config import paths
    from core.errors import ConfigError

    recursive = {}
    recursive["child"] = recursive
    for raw in (None, [], {1: "value"}, {"value": {1, 2}}, {"value": float("inf")}, recursive):
        with pytest.raises(ConfigError):
            cfg.save(raw)
    assert not paths.SETTINGS_PATH.exists() and not paths.SETTINGS_DEFAULT_PATH.exists()


def test_invalid_utf8_file_raises_config_error_without_replacing_it(cfg):
    from config import paths
    from core.errors import ConfigError

    paths.SETTINGS_PATH.write_bytes(b"\xffsynthetic-token")
    with pytest.raises(ConfigError, match="读取失败"):
        cfg.load()
    assert paths.SETTINGS_PATH.read_bytes() == b"\xffsynthetic-token"


def test_yaml_merge_and_non_recursive_aliases_are_supported(cfg, monkeypatch):
    monkeypatch.setenv("SETTINGS", "extension: &base {tag: first}\ncopy: {<<: *base, tag: changed}")
    loaded = cfg.load()
    assert loaded["extension"] == {"tag": "first"}
    assert loaded["copy"] == {"tag": "changed"}


def test_invalid_explicit_path_raises_config_error(cfg):
    from core.errors import ConfigError

    with pytest.raises(ConfigError, match="路径无效"):
        cfg.load(Path("invalid\x00settings.yml"))


def test_default_template_cannot_be_selected_as_real_config(cfg):
    from config import paths
    from core.errors import ConfigError

    with pytest.raises(ConfigError, match="默认模板"):
        cfg.load(paths.SETTINGS_DEFAULT_PATH)
    with pytest.raises(ConfigError, match="默认模板"):
        cfg.save({"HTTP_REQUEST": 37}, paths.SETTINGS_DEFAULT_PATH)
    assert not paths.SETTINGS_DEFAULT_PATH.exists()
