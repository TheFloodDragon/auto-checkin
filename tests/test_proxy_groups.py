"""代理组配置、选路与保存回归；不连接真实代理。"""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from config import schema, secrets, store
from config.proxies import (
    network_mode, parse_groups, parse_proxy_url, resolve_proxy, validate_proxy_config,
)
from core.account import NetworkSpec
from core.errors import ConfigError
from core.masking import mask_secrets
from gui import core
from gui.worker import Redactor


def group(group_id="office", *, url="http://user:password@127.0.0.1:7897"):
    return {"id": group_id, "name": "办公代理", "selected": "first", "enabled": True,
            "proxies": [{"id": "first", "name": "节点一", "url": url, "enabled": True}]}


def document(network=None):
    return {"version": 3, "accounts": [{"id": "site", "base_url": "https://site.invalid",
                                        "network": network or {}}], "proxy_groups": [group()]}


@pytest.mark.parametrize("network,mode", [
    (NetworkSpec(), "inherit"), (NetworkSpec(proxy="http://host:80"), "custom"),
    (NetworkSpec(proxy_group="office"), "group"), (NetworkSpec(proxy_mode="direct"), "direct"),
])
def test_legacy_mode_inference(network, mode):
    assert network_mode(network) == mode


@pytest.mark.parametrize("network", [
    NetworkSpec(proxy="http://host", proxy_group="office"),
    NetworkSpec(proxy="http://host", proxy_mode="direct"),
    NetworkSpec(proxy="http://host", proxy_mode="inherit"),
    NetworkSpec(proxy_group="office", proxy_mode="custom"),
    NetworkSpec(proxy_mode="group"), NetworkSpec(proxy_mode="custom"), NetworkSpec(proxy_mode="random"),
])
def test_conflicting_modes_fail(network):
    with pytest.raises(ConfigError, match="network"):
        network_mode(network)


def test_precedence_and_direct_ignore_environment():
    groups = parse_groups([group()])
    env = "http://env.invalid:8080"
    assert resolve_proxy(NetworkSpec(), environ_proxy=env).source == "environment"
    assert resolve_proxy(NetworkSpec(), groups, "office", environ_proxy=env).source == "default_group"
    assert resolve_proxy(NetworkSpec(proxy_mode="direct"), groups, "office", environ_proxy=env).url == ""
    assert resolve_proxy(NetworkSpec(proxy=env), groups, "office").source == "custom"
    assert resolve_proxy(NetworkSpec(proxy_group="office"), groups, environ_proxy=env).source == "group"
    assert resolve_proxy(NetworkSpec()).description == "直连"


@pytest.mark.parametrize("mutation", [
    {"enabled": False}, {"selected": ""}, {"selected": "", "proxies": []},
    {"proxies": [{"id": "first", "name": "节点一", "url": "http://host:80", "enabled": False}]},
])
def test_unavailable_group_is_saveable_but_never_falls_back(mutation):
    raw = document({"proxy_group": "office"})
    raw["proxy_groups"][0].update(mutation)
    parsed = schema.parse_document(raw)
    with pytest.raises(ConfigError):
        resolve_proxy(parsed.accounts[0].network, parsed.proxy_groups, environ_proxy="http://env.invalid")


@pytest.mark.parametrize("url", [
    "ftp://host:80", "http://host:0", "http://host:65536", "http://host:bad", "http://host:",
    "http://", "socks4://host:1080", "http://host/path", "http://host?password=hidden", "http://host#part",
    "http://us%ZZer:password@host", "http://user:pa%0Ass@host", "http://bad host", "http://[::1",
])
def test_bad_url_error_does_not_leak_input(url):
    with pytest.raises(ConfigError) as caught:
        parse_proxy_url(url)
    # 公共协议名可以出现在修正提示中，不属于用户凭据。
    if url != "http://":
        assert url not in str(caught.value)
    assert "hidden" not in str(caught.value)


def test_ipv6_and_encoded_authentication_are_shared_with_browser():
    from browser.bypass import _normalize_proxy

    url = "http://u%40ser:pa%3Ass%2Fword@[::1]:8080"
    parsed = parse_proxy_url(url)
    assert parsed.server == "http://[::1]:8080"
    assert parsed.username == "u@ser" and parsed.password == "pa:ss/word"
    assert _normalize_proxy(url) == {"server": "http://[::1]:8080", "username": "u@ser", "password": "pa:ss/word"}
    assert _normalize_proxy("localhost:7897") == {"server": "http://localhost:7897"}
    assert "pa:ss" not in repr(parsed) and "u@ser" not in repr(parsed)
    assert parse_proxy_url(parsed.url) == parsed


def test_proxy_summary_redactor_and_username_only_url():
    raw = group(url="socks5://unique-user:unique-pass@host:1080")
    resolution = resolve_proxy(NetworkSpec(proxy_group="office"), parse_groups([raw]))
    text = json.dumps(resolution.to_payload(), ensure_ascii=False)
    assert "unique-user" not in text and "unique-pass" not in text
    assert "SOCKS" in text and "host:1080" in text
    assert "private-user" not in mask_secrets("http://private-user@host")
    redactor = Redactor({"proxy_groups": [raw], "environ_proxy": "http://encoded%40user:p%40ss@env"})
    assert "unique-pass" not in redactor.text("unique-user unique-pass")
    assert "encoded@user" not in redactor.text("encoded@user encoded%40user p@ss p%40ss")


@pytest.mark.parametrize("update", [
    {"proxy_groups": None}, {"proxy_groups": {}}, {"proxy_groups": [group(), group()]},
    {"default_proxy_group": "missing"}, {"default_proxy_group": False},
    {"proxy_groups": [{**group(), "selected": "missing"}]},
    {"proxy_groups": [{**group(), "proxies": [group()["proxies"][0]] * 2}]},
    {"proxy_groups": [{**group(), "enabled": "true"}]},
])
def test_invalid_group_shapes_rejected(update):
    raw = document()
    raw.update(update)
    with pytest.raises(ConfigError):
        validate_proxy_config(raw)


def test_unknown_fields_round_trip_and_oauth_save_preserves_groups(tmp_path):
    raw = document({"proxy_group": "office", "verify_ssl": False, "referer_path": "/custom", "extension": [1]})
    raw["root_extension"] = {"note": [1, 2]}
    raw["proxy_groups"][0]["extension"] = {"nested": [3]}
    raw["proxy_groups"][0]["proxies"][0]["extension"] = [4]
    raw["default_proxy_group"] = "office"
    parsed = schema.parse_document(raw)
    dumped = parsed.to_payload()
    assert dumped["proxy_groups"] == raw["proxy_groups"]
    assert dumped["root_extension"] == raw["root_extension"]
    assert dumped["accounts"][0]["network"] == raw["accounts"][0]["network"]
    target = tmp_path / "ACCOUNTS.json"
    store.save(parsed, target)
    loaded = store.load(target)
    changed = store.save_oauth_state(loaded, "github", "default", "state")
    store.delete_oauth_state(changed, "github", "default")
    final = json.loads(target.read_text(encoding="utf-8"))
    assert final["proxy_groups"] == raw["proxy_groups"]
    assert final["default_proxy_group"] == "office"
    assert final["root_extension"] == raw["root_extension"]


def test_effective_network_does_not_change_config_or_credential_updates():
    from config.overlay import Overlay

    spec = schema.parse_document(document({"proxy_group": "office"})).accounts[0]
    account = Overlay().apply(spec)
    account = replace(account, effective_network=NetworkSpec(proxy="http://chosen:80", proxy_mode="custom"))
    updated = account.with_credentials(access_token="new")
    assert updated.network.proxy == "http://chosen:80"
    assert schema.dump_account(updated.spec)["network"] == {"proxy_group": "office"}


def test_secret_exports_only_referenced_groups_and_default(monkeypatch):
    monkeypatch.setenv("CHECKIN_PROXY", "http://env-secret:password@host")
    raw = document({"proxy_group": "office"})
    raw["proxy_groups"].extend([group("default"), group("unused")])
    raw["default_proxy_group"] = "default"
    raw["accounts"].append({"id": "inherited", "base_url": "https://b.invalid"})
    raw["accounts"].append({"id": "disabled", "base_url": "https://c.invalid", "enabled": False,
                            "network": {"proxy_group": "unused"}})
    exported = secrets.build_secret_payload(schema.parse_document(raw))
    assert {item["id"] for item in exported["proxy_groups"]} == {"office", "default"}
    assert exported["default_proxy_group"] == "default"
    assert "env-secret" not in json.dumps(exported)
    raw["accounts"][1]["network"] = {"proxy_mode": "direct"}
    exported = secrets.build_secret_payload(schema.parse_document(raw))
    assert "default_proxy_group" not in exported
    assert [item["id"] for item in exported["proxy_groups"]] == ["office"]


@pytest.mark.parametrize("main_network", [{"proxy": "http://127.0.0.1:7897"}, {"proxy_group": "office"}])
def test_secret_preserves_split_only_group_and_its_failover(main_network):
    split = group("oauth")
    split["proxies"].append({"id": "backup", "name": "备用节点", "url": "http://backup.invalid:8080"})
    split["failover"] = {"nodes": ["backup"], "url": "https://linux.do/", "interval": 60}
    split["subscription"] = {"url": "https://subscription.invalid/private-token"}
    raw = document({**main_network, "proxy_split": {"domains": ["linux.do"], "proxy_group": "oauth"}})
    raw["proxy_groups"].extend([split, group("unused")])
    exported = secrets.build_secret_payload(schema.parse_document(raw))
    output = next(item for item in exported["proxy_groups"] if item["id"] == "oauth")
    assert output["failover"] == split["failover"]
    assert {node["id"] for node in output["proxies"]} == {"first", "backup"}
    assert "unused" not in {item["id"] for item in exported["proxy_groups"]}
    assert "subscription" not in output
    restored = schema.parse_document(json.loads(secrets.decode_secret(secrets.encode_payload(exported).text)))
    assert restored.accounts[0].network.extras["proxy_split"]["proxy_group"] == "oauth"
    assert any(item.id == "oauth" for item in restored.proxy_groups)


def test_secret_does_not_export_split_group_referenced_only_by_disabled_account():
    raw = document({"proxy_mode": "direct"})
    raw["proxy_groups"].append(group("oauth"))
    raw["accounts"].append({"id": "off", "base_url": "https://off.invalid", "enabled": False,
                            "network": {"proxy": "http://127.0.0.1:7897", "proxy_split": {
                                "domains": ["linux.do"], "proxy_group": "oauth"}}})
    assert "proxy_groups" not in secrets.build_secret_payload(schema.parse_document(raw))


def test_import_merges_distinct_groups_and_rejects_collision_atomically():
    original = document({"proxy_group": "office"})
    incoming = document({"proxy_group": "other"})
    incoming["proxy_groups"] = [group("other")]
    before = deepcopy(original)
    result = core.import_accounts(original, json.dumps(incoming))
    assert len(result["proxy_groups"]) == 2
    assert original == before
    incoming["proxy_groups"] = [{**group(), "name": "changed"}]
    incoming["accounts"][0]["network"]["proxy_group"] = "office"
    with pytest.raises(ConfigError, match="冲突"):
        core.import_accounts(original, json.dumps(incoming))
    assert original == before


def test_gui_context_is_independent_and_status_is_not_connectivity(monkeypatch):
    monkeypatch.delenv("CHECKIN_PROXY", raising=False)
    raw = document({"proxy_group": "office"})
    snapshot = core.account_payload(raw["accounts"][0], raw)
    initial = core.proxy_fingerprint(raw["accounts"][0], raw)
    raw["proxy_groups"][0]["name"] = "renamed"
    assert snapshot["proxy_groups"][0]["name"] == "办公代理"
    assert core.proxy_fingerprint(raw["accounts"][0], raw) != initial
    status = core.proxy_status(snapshot["accounts"][0]["network"], snapshot)
    assert status["valid"] is True and status["tested"] is False
    assert "user" not in status["description"] and "password" not in status["description"]
    assert core.selected_task_ids(snapshot["accounts"][0], context=snapshot) == ("daily",)


# ── 组内故障转移声明 ────────────────────────────────────────────────────────
def _clash(server, secret="11111111-1111-1111-1111-111111111111"):
    return {"type": "vless", "server": server, "port": 443, "uuid": secret}


def pool(failover=None, **changes):
    raw = {"id": "pool", "name": "订阅", "selected": "tw", "enabled": True, "proxies": [
        {"id": "tw", "name": "🇨🇳 台湾家宽", "clash": _clash("tw.example")},
        {"id": "jp-new-id", "name": "🇯🇵 日本原生", "clash": _clash("jp.example")},
        {"id": "sg", "name": "🇸🇬 新加坡原生", "clash": _clash("sg.example")},
        {"id": "off", "name": "停用", "clash": _clash("off.example"), "enabled": False},
        {"id": "dup", "name": "与当前节点同配置", "clash": _clash("tw.example")},
        {"id": "http", "name": "普通代理", "url": "http://u:pw@10.0.0.9:8080"},
    ]}
    if failover is not None:
        raw["failover"] = failover
    raw.update(changes)
    return raw


def test_group_without_failover_resolves_single_node():
    resolution = resolve_proxy(NetworkSpec(proxy_group="pool"), parse_groups([pool()]))
    assert not resolution.failover
    assert resolution.to_payload()["failover"] == []
    assert "故障转移" not in resolution.description


def test_failover_matches_id_or_name_and_skips_unusable_entries():
    """订阅更新可能重算节点 id，名称通常不变：两种引用都接受；失效引用直接跳过。"""
    raw = pool({"nodes": ["🇯🇵 日本原生", "sg", "off", "missing", "dup", "tw", "http"], "url": "https://linux.do/",
                "interval": 60})
    resolution = resolve_proxy(NetworkSpec(proxy_group="pool"), parse_groups([raw]))
    failover = resolution.failover
    assert resolution.node_id == "tw", "当前节点仍是 selected，备用不改变首选"
    assert failover.names == ("🇯🇵 日本原生", "🇸🇬 新加坡原生", "普通代理")
    assert [item["server"] for item in failover.outbounds] == ["jp.example", "sg.example", "10.0.0.9"]
    assert failover.outbounds[2] == {"type": "http", "server": "10.0.0.9", "port": 8080,
                                     "username": "u", "password": "pw"}
    assert failover.url == "https://linux.do/" and failover.interval == 60
    bridge = failover.to_bridge()
    json.dumps(bridge)
    assert bridge["names"] == list(failover.names)
    assert "故障转移备用 3 个" in resolution.description


def test_failover_details_never_leak_credentials():
    raw = pool({"nodes": ["sg"]})
    raw["proxies"][2]["clash"] = _clash("sg.example", secret="33333333-3333-3333-3333-333333333333")
    resolution = resolve_proxy(NetworkSpec(proxy_group="pool"), parse_groups([raw]))
    text = repr(resolution) + json.dumps(resolution.to_payload(), ensure_ascii=False) + resolution.description
    assert "33333333" not in text and "sg.example" not in text
    assert "33333333-3333-3333-3333-333333333333" in resolution.failover.secrets


def test_failover_defaults_and_survives_payload_round_trip():
    parsed = parse_groups([pool({"nodes": ["sg"]})])
    resolution = resolve_proxy(NetworkSpec(proxy_group="pool"), parsed)
    assert resolution.failover.url == "https://cp.cloudflare.com/generate_204"
    assert resolution.failover.interval == 120
    assert parsed[0].to_payload()["failover"] == {"nodes": ["sg"]}
    assert parse_groups([parsed[0].to_payload()]) == parsed


@pytest.mark.parametrize("failover", [
    [], "sg", {"nodes": "sg"}, {"nodes": [""]}, {"nodes": [1]}, {"nodes": ["sg"], "mode": "url-test"},
    {"nodes": ["sg"], "url": "ftp://x"}, {"nodes": ["sg"], "url": "https://user:pw@host/"},
    {"nodes": ["sg"], "url": ""}, {"nodes": ["sg"], "interval": 5}, {"nodes": ["sg"], "interval": "60"},
    {"nodes": ["sg"], "interval": True}, {"nodes": [f"n{index}" for index in range(9)]},
])
def test_invalid_failover_declaration_rejected(failover):
    with pytest.raises(ConfigError, match="failover") as caught:
        parse_groups([pool(failover)])
    assert "pw" not in str(caught.value)


def test_split_target_group_failover_is_resolved_like_main_route():
    from runtime import engine

    raw = pool({"nodes": ["🇯🇵 日本原生"]})
    spec = schema.parse_account({
        "id": "ar", "base_url": "https://agentrouter.org",
        "network": {"proxy": "http://127.0.0.1:7897", "proxy_split": {"domains": ["linux.do"], "proxy_group": "pool"}},
    })
    split = engine._proxy_split(spec, parse_groups([raw]), "")
    assert split["outbound"]["server"] == "tw.example"
    assert [item["server"] for item in split["failover"]["outbounds"]] == ["jp.example"]
    json.dumps(split)
