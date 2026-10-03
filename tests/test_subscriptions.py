"""订阅/节点导入的离线回归测试；不发起网络请求、不依赖 GUI。"""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import urllib.error
import urllib.request
from copy import deepcopy
from dataclasses import replace

import pytest

from config import subscriptions
from config.subscriptions import (
    SourceSpec,
    SubscriptionImporter,
    merge_proxy_import,
    parse_subscription_text,
    select_policy_nodes,
    subscription_update_summary,
)
from core.errors import ConfigError
from net.subscriptions import read_source, write_text_file


def test_uri_import_accepts_supported_nodes_and_skips_unsupported() -> None:
    result = parse_subscription_text(
        "\n".join(
            [
                "http://alice:secret@example.invalid:8080#Office",
                "https://bob:other@example.invalid:8443#Secure",
                "socks5://carol:third@example.invalid:1080#Browser",
                "ssr://b3BhcXVl#Unsupported",
            ]
        ),
        source_id="source-uri",
        source_label="https://sub.example.invalid/download?token=private-token",
        format="uri",
    )

    assert result.importable_count == 3
    assert {node["url"].split(":", 1)[0] for node in result.nodes} == {"http", "https", "socks5"}
    assert result.source_label == "sub.example.invalid"
    assert all("secret" not in candidate.display for candidate in result.candidates)
    assert any(candidate.status == "unsupported" for candidate in result.candidates)
    assert "private-token" not in result.source_label


def test_base64_import_is_decoded_offline() -> None:
    text = "http://user:password@example.invalid:8080#Encoded"
    encoded = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")

    result = parse_subscription_text(encoded, source_id="source-base64", source_label="订阅", format="base64")

    assert result.format == "base64"
    assert len(result.nodes) == 1
    assert result.nodes[0]["name"] == "Encoded"
    assert result.nodes[0]["url"].startswith("http://user:password@")


def test_file_import_uses_bounded_reader_without_network(tmp_path) -> None:
    source = tmp_path / "nodes.txt"
    source.write_text("socks5://user:password@example.invalid:1080#Local\n", encoding="utf-8")

    result = SubscriptionImporter().import_source(SourceSpec("file", "auto", str(source)))

    assert result.source_label == "nodes.txt"
    assert result.importable_count == 1
    assert result.nodes[0]["capabilities"] == ["browser"]


def test_clash_yaml_only_imports_directly_supported_protocols() -> None:
    if subscriptions.yaml is None:
        pytest.skip("PyYAML 未安装；项目依赖安装后运行该回归用例")

    text = """
proxies:
  - name: HTTP
    type: http
    server: http.example.invalid
    port: 8080
    username: alice
    password: secret
  - name: HTTPS
    type: http
    server: https.example.invalid
    port: 443
    tls: true
  - name: SOCKS
    type: socks5
    server: socks.example.invalid
    port: 1080
  - name: WireGuard
    type: wireguard
    server: "alice:secret@wg.example.invalid"
    port: 443
"""

    result = parse_subscription_text(text, source_id="source-clash", source_label="clash.yaml", format="clash_yaml")

    assert result.format == "clash_yaml"
    assert result.importable_count == 3
    assert any(candidate.status == "unsupported" and candidate.protocol == "wireguard" for candidate in result.candidates)
    assert all("alice" not in candidate.display and "secret" not in candidate.display for candidate in result.candidates)


def test_merge_replaces_only_same_source_and_preserves_manual_selection() -> None:
    payload = {
        "version": 3,
        "accounts": [],
        "proxy_groups": [
            {
                "id": "office",
                "name": "Office",
                "enabled": True,
                "selected": "manual",
                "proxies": [
                    {"id": "manual", "name": "手工", "url": "http://manual.invalid:8080", "enabled": True},
                    {
                        "id": "old-import",
                        "name": "旧订阅",
                        "url": "http://old.invalid:8080",
                        "enabled": True,
                        "source_id": "source-uri",
                        "source_key": "old",
                    },
                ],
            }
        ],
    }
    result = parse_subscription_text(
        "http://new.invalid:8080#新订阅",
        source_id="source-uri",
        source_label="sub.example.invalid",
        group_id="office",
        group_name="Office",
        format="uri",
        existing_group=payload["proxy_groups"][0],
    )

    merged = merge_proxy_import(payload, result, target_group_id="office")
    group = merged["proxy_groups"][0]

    assert [node["id"] for node in group["proxies"]] == ["manual", result.nodes[0]["id"]]
    assert group["proxies"][0]["url"] == "http://manual.invalid:8080"
    assert group["selected"] == "manual"
    assert payload["proxy_groups"][0]["proxies"][1]["id"] == "old-import"


def test_existing_different_content_id_is_rejected_atomically() -> None:
    first = parse_subscription_text(
        "http://same.invalid:8080#SameName",
        source_id="source-first",
        source_label="first",
        format="uri",
    )
    conflicting_group = {
        "id": "office",
        "name": "Office",
        "selected": "",
        "proxies": [
            {
                "id": first.nodes[0]["id"],
                "name": "Different",
                "url": "http://different.invalid:8080",
                "enabled": True,
                "source_id": "manual",
            }
        ],
    }
    result = parse_subscription_text(
        "http://same.invalid:8080#SameName",
        source_id="source-second",
        source_label="second",
        group_id="office",
        existing_group=conflicting_group,
        format="uri",
    )
    assert result.nodes == ()
    assert result.candidates[0].status == "conflict"

    payload = {"version": 3, "accounts": [], "proxy_groups": [deepcopy(conflicting_group)]}
    before = deepcopy(payload)
    with pytest.raises(ConfigError, match="冲突"):
        merge_proxy_import(payload, result, target_group_id="office")
    assert payload == before


def test_bridged_uri_import_keeps_credentials_out_of_display() -> None:
    result = parse_subscription_text(
        "vless://11111111-1111-1111-1111-111111111111@edge.example.invalid:443?security=tls&sni=edge.example.invalid#Reality",
        source_id="source-vless",
        source_label="订阅",
        format="uri",
    )

    assert result.importable_count == 1
    assert result.bridged_count == 1
    candidate = result.candidates[0]
    assert candidate.status == "bridged"
    assert candidate.clash["type"] == "vless"
    assert "11111111" not in candidate.display
    assert any("mihomo" in notice for notice in result.notices)


def test_subscription_binding_metadata_is_saved_and_updated() -> None:
    result = parse_subscription_text(
        "http://proxy.example.invalid:8080#节点",
        source_id="source-feed",
        source_label="feed.example.invalid",
        group_id="office",
        format="uri",
        title="我的订阅",
        userinfo={"upload": 1, "download": 2, "total": 3, "expire": 4},
    )
    payload = {"version": 3, "accounts": [], "proxy_groups": []}
    merged = merge_proxy_import(
        payload,
        result,
        target_group_id="office",
        subscription={"url": "https://feed.example.invalid/sub?token=private", "format": "uri"},
    )
    bound = merged["proxy_groups"][0]["subscription"]
    assert bound["source_id"] == "source-feed"
    assert bound["url"].startswith("https://feed.example.invalid/")
    assert bound["title"] == "我的订阅"
    assert bound["userinfo"]["total"] == 3
    assert bound["node_count"] == 1 and bound["content_hash"] == result.content_hash
    assert bound["policy_group_count"] == 0 and bound["provider_count"] == 0

    updated_result = parse_subscription_text(
        "http://new.example.invalid:8080#新节点",
        source_id="source-feed",
        source_label="feed.example.invalid",
        group_id="office",
        format="uri",
        existing_group=merged["proxy_groups"][0],
    )
    updated = merge_proxy_import(merged, updated_result, target_group_id="office")
    assert updated["proxy_groups"][0]["subscription"]["url"] == bound["url"]
    assert updated["proxy_groups"][0]["proxies"][0]["url"] == "http://new.example.invalid:8080"


def test_subscription_url_rejects_embedded_credentials_without_fetching() -> None:
    with pytest.raises(ConfigError, match="不能内嵌账号密码"):
        read_source("https://alice:secret@example.invalid/subscription", kind="url")



def test_subscription_update_summary_reports_changes_without_content() -> None:
    old = {
        "selected": "old",
        "proxies": [
            {"id": "old", "name": "保留", "url": "http://keep.invalid:80", "source_id": "source-feed", "source_key": "keep"},
            {"id": "gone", "name": "移除", "url": "http://gone.invalid:80", "source_id": "source-feed", "source_key": "gone"},
            {"id": "manual", "name": "手工", "url": "http://manual.invalid:80", "source_id": "manual"},
        ],
    }
    result = parse_subscription_text(
        "http://keep.invalid:80#保留\nhttp://new.invalid:80#新增",
        source_id="source-feed", source_label="feed", format="uri", existing_group=old,
    )
    summary = subscription_update_summary(old, result)
    assert summary["old_count"] == 2 and summary["new_count"] == 2
    assert summary["unchanged"] == 1 and summary["added"] == 1 and summary["removed"] == 1
    assert summary["selected_name"] == "保留"
    assert "http://keep.invalid" not in repr(summary)
    assert summary["content_hash"]


def test_clash_metadata_identifies_select_groups_and_providers() -> None:
    result = parse_subscription_text(
        """
proxies:
  - {name: A, type: http, server: a.example.invalid, port: 80}
proxy-groups:
  - {name: 手动出口, type: select, proxies: [A, DIRECT]}
  - {name: 自动出口, type: url-test, proxies: [A]}
proxy-providers:
  feed:
    type: http
    url: https://feed.example.invalid/sub?token=secret
""",
        source_id="source-clash", source_label="clash.yaml", format="clash_yaml",
    )
    assert {item["name"] for item in result.policy_groups} == {"手动出口", "自动出口"}
    assert result.providers == ({"name": "feed", "type": "http", "resolved": False, "members": (), "node_keys": ()},)
    assert not result.providers_complete
    assert any("策略组" in notice for notice in result.notices)
    assert "secret" not in repr(result.providers)


def test_write_text_file_is_atomic_and_utf8(tmp_path) -> None:
    target = tmp_path / "edited.yaml"
    assert write_text_file(str(target), "proxies:\n- name: 节点\n") == str(target)
    assert target.read_text(encoding="utf-8") == "proxies:\n- name: 节点\n"
    with pytest.raises(ConfigError, match="目录"):
        write_text_file(str(tmp_path), "text")


def test_base64_clash_metadata_is_detected() -> None:
    text = """
proxies:
  - {name: A, type: http, server: a.example.invalid, port: 80}
proxy-groups:
  - {name: 手动, type: select, proxies: [A]}
"""
    encoded = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
    result = parse_subscription_text(encoded, source_id="source-b64-clash", source_label="feed", format="base64")
    assert result.policy_groups[0]["type"] == "select"


def test_select_policy_nodes_expands_only_direct_members() -> None:
    result = parse_subscription_text(
        """
proxies:
  - {name: 香港, type: http, server: hk.example.invalid, port: 80}
  - {name: 美国, type: http, server: us.example.invalid, port: 80}
proxy-groups:
  - {name: 手动出口, type: select, proxies: [香港, DIRECT]}
""",
        source_id="source-select", source_label="clash.yaml", format="clash_yaml",
    )
    nodes = select_policy_nodes(result, "手动出口")
    assert [item["name"] for item in nodes] == ["香港"]
    assert "example.invalid" not in repr(result.policy_groups)


def _parse(text: str, **kwargs):
    return parse_subscription_text(text, source_id="source-test", source_label="订阅", **kwargs)


def _yaml(data) -> str:
    return subscriptions.yaml.safe_dump(data, allow_unicode=True, sort_keys=False)


def _http_node(name: str, host: str = "proxy.invalid") -> dict:
    return {"name": name, "type": "http", "server": host, "port": 80}


def _fake_http(monkeypatch, documents: dict):
    calls = []

    class Response(io.BytesIO):
        def __init__(self, body):
            super().__init__(body.encode() if isinstance(body, str) else body)
            self.headers = {}

    class Opener:
        def open(self, request, timeout):
            calls.append(request.full_url)
            value = documents[request.full_url]
            if isinstance(value, Exception):
                raise value
            return Response(value)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    return calls


@pytest.mark.parametrize("format", ["auto", "clash_yaml"])
def test_text_source_is_offline_hashed_and_not_persisted(monkeypatch, caplog, format) -> None:
    def unexpected_read(*args, **kwargs):
        pytest.fail("纯文本不得读取网络或文件")

    monkeypatch.setattr(subscriptions, "read_source", unexpected_read)
    text = "# private-raw-marker\n" + _yaml({"proxies": [_http_node("节点")]})
    spec = SourceSpec("text", format, text)
    result = SubscriptionImporter().import_source(spec)
    assert result.content == text  # 仅在内存中编辑；不是最终配置字段。
    assert result.source_kind == "text"
    assert result.source_label == "粘贴内容"
    assert result.source_id == "source-" + hashlib.sha256(text.encode()).hexdigest()[:16]
    assert "private-raw-marker" not in repr(spec) + repr(result) + caplog.text
    merged = merge_proxy_import({"proxy_groups": []}, result)
    assert "private-raw-marker" not in json.dumps(merged, ensure_ascii=False)
    assert "subscription" not in merged["proxy_groups"][0]
    with pytest.raises(ConfigError, match="粘贴内容不能绑定"):
        merge_proxy_import({"proxy_groups": []}, result, subscription={"url": text})


def test_text_source_limit_counts_utf8_bytes() -> None:
    prefix = "http://proxy.invalid:80#A\n#"
    exact = prefix + "x" * (subscriptions._MAX_TEXT_BYTES - len(prefix))
    assert SubscriptionImporter().import_source(SourceSpec("text", "uri", exact)).importable_count == 1
    with pytest.raises(ConfigError, match="8 MiB"):
        SubscriptionImporter().import_source(SourceSpec("text", "uri", exact + "中"))
    with pytest.raises(ConfigError, match="UTF-8"):
        SubscriptionImporter().import_source(SourceSpec("text", "auto", "\ud800"))


@pytest.mark.parametrize("connection", [
    "http://user:secret@proxy.invalid:80",
    "vless://11111111-1111-1111-1111-111111111111@proxy.invalid:443?security=tls",
])
def test_duplicate_requires_same_name_and_content_with_stable_ids(connection) -> None:
    links = [connection + "#香港", connection + "#美国", connection + "#香港"]
    result = _parse("\n".join(links), format="uri")
    assert [node["name"] for node in result.nodes] == ["香港", "美国"]
    assert result.duplicate_count == 1
    assert len({node["id"] for node in result.nodes}) == 2
    reordered = _parse("\n".join(reversed(links)), format="uri")
    assert {node["name"]: node["id"] for node in result.nodes} == {node["name"]: node["id"] for node in reordered.nodes}
    # 保留旧连接哈希 source_key 以兼容历史来源；绝不再单独用它去重。
    assert result.nodes[0]["source_key"] == result.nodes[1]["source_key"]
    assert "user:secret" not in repr(result)


def test_same_name_different_connections_and_long_names_keep_distinct_ids() -> None:
    long_name = "A" * 160
    links = [f"http://{host}.invalid:80#{long_name}" for host in ("one", "two")]
    result = _parse("\n".join(links), format="uri")
    assert result.importable_count == 2 and result.duplicate_count == 0
    assert len({node["id"] for node in result.nodes}) == 2
    assert all(len(node["id"]) <= 48 for node in result.nodes)
    reordered = _parse("\n".join(reversed(links)), format="uri")
    assert {node["url"]: node["id"] for node in result.nodes} == {node["url"]: node["id"] for node in reordered.nodes}


def test_existing_alias_does_not_suppress_new_name() -> None:
    existing = {"proxies": [{"id": "manual", "name": "原名", "url": "http://proxy.invalid:80"}]}
    result = _parse("http://proxy.invalid:80#原名\nhttp://proxy.invalid:80#别名", format="uri", existing_group=existing)
    assert [node["name"] for node in result.nodes] == ["别名"]
    assert result.duplicate_count == 1


def test_many_nodes_merge_without_truncation_or_default_selection() -> None:
    result = _parse("\n".join(f"http://proxy.invalid:80#节点{i}" for i in range(300)), format="uri")
    merged = merge_proxy_import({"proxy_groups": []}, result)
    group = merged["proxy_groups"][0]
    assert len(group["proxies"]) == 300
    assert len({node["id"] for node in group["proxies"]}) == 300
    assert group["selected"] == ""


def test_legacy_ids_and_source_keys_are_kept_without_cross_alias_selection() -> None:
    old = {"id": "group", "selected": "legacy-id", "proxies": [{
        "id": "legacy-id", "name": "香港", "url": "http://proxy.invalid:80", "source_id": "source-test",
        "source_key": subscriptions._hash_key("http://proxy.invalid:80"),
    }]}
    text = "http://proxy.invalid:80#美国\nhttp://proxy.invalid:80#香港"
    result = _parse(text, format="uri", existing_group=old)
    assert next(node for node in result.nodes if node["name"] == "香港")["id"] == "legacy-id"
    payload = {"proxy_groups": [old]}
    merged = merge_proxy_import(payload, result, target_group_id="group")
    assert merged["proxy_groups"][0]["selected"] == "legacy-id"
    assert not result.selection_lost
    renamed = _parse("http://proxy.invalid:80#美国", format="uri", existing_group=old)
    assert renamed.selection_lost
    assert merge_proxy_import(payload, renamed, target_group_id="group")["proxy_groups"][0]["selected"] == ""
    assert payload["proxy_groups"][0]["selected"] == "legacy-id"


def test_selection_prefers_exact_connection_before_unique_name_fallback() -> None:
    old = {"selected": "legacy", "proxies": [{"id": "legacy", "name": "香港", "url": "http://two.invalid:80", "source_id": "source-test"}]}
    result = _parse("http://one.invalid:80#香港\nhttp://two.invalid:80#香港", format="uri", existing_group=old)
    assert not result.selection_lost
    assert next(node for node in result.nodes if node["url"] == "http://two.invalid:80")["id"] == "legacy"
    rotated = _parse("http://three.invalid:80#香港", format="uri", existing_group=old)
    assert not rotated.selection_lost
    summary = subscription_update_summary(old, rotated)
    assert summary["replaced"] == 1 and summary["added"] == summary["removed"] == 0
    ambiguous = _parse("http://one.invalid:80#香港\nhttp://three.invalid:80#香港", format="uri", existing_group=old)
    assert ambiguous.selection_lost
    filtered = replace(result, nodes=())
    assert subscription_update_summary(old, filtered)["selection_lost"]


def test_summary_counts_aliases_individually_with_legacy_content_keys() -> None:
    original = _parse("http://proxy.invalid:80#A\nhttp://proxy.invalid:80#B", format="uri")
    old = {"proxies": list(original.nodes)}
    updated = _parse("http://proxy.invalid:80#A\nhttp://proxy.invalid:80#C", format="uri", existing_group=old)
    summary = subscription_update_summary(old, updated)
    assert (summary["unchanged"], summary["added"], summary["removed"]) == (1, 1, 1)


def test_policy_groups_expand_nested_nodes_cycles_and_builtins() -> None:
    result = _parse(_yaml({
        "proxies": [_http_node(name) for name in ("A", "B", "C", "outside")],
        "proxy-groups": [
            {"name": "手动", "type": "select", "proxies": ["测速", "DIRECT", "missing"]},
            {"name": "测速", "type": "url-test", "proxies": ["A", "后备", "手动"]},
            {"name": "后备", "type": "fallback", "proxies": ["B", "轮换", "REJECT"]},
            {"name": "轮换", "type": "load-balance", "proxies": ["C", "A", "COMPATIBLE"]},
        ],
    }))
    nodes = select_policy_nodes(result, "手动")
    assert [node["name"] for node in nodes] == ["A", "B", "C"]
    assert all("type" not in node for node in nodes)
    assert merge_proxy_import({"proxy_groups": []}, replace(result, nodes=nodes))["proxy_groups"][0]["selected"] == ""
    with pytest.raises(ConfigError, match="select"):
        select_policy_nodes(result, "测速")


def test_policy_expansion_handles_deep_chains_without_python_recursion() -> None:
    groups = [{"name": str(index), "type": "select", "proxies": [str(index + 1)]} for index in range(1100)]
    groups[-1]["proxies"] = ["A"]
    result = _parse(_yaml({"proxies": [_http_node("A")], "proxy-groups": groups}))
    assert [node["name"] for node in select_policy_nodes(result, "0")] == ["A"]


def test_empty_cycle_has_no_exit_and_relay_is_not_simplified() -> None:
    result = _parse(_yaml({"proxies": [_http_node("A")], "proxy-groups": [
        {"name": "空组", "type": "select", "proxies": ["空组", "DIRECT", "UNKNOWN"]},
        {"name": "手动", "type": "select", "proxies": ["链"]},
        {"name": "链", "type": "relay", "proxies": ["A"]},
    ]}))
    with pytest.raises(ConfigError, match="没有可导入"):
        select_policy_nodes(result, "空组")
    with pytest.raises(ConfigError, match="relay"):
        select_policy_nodes(result, "手动")


def test_inline_provider_expands_and_use_matches_exact_node_content(monkeypatch) -> None:
    monkeypatch.setattr(subscriptions, "read_source", lambda *args, **kwargs: pytest.fail("inline 不得读取来源"))
    text = _yaml({
        "proxies": [_http_node("相同名称", "direct.invalid")],
        "proxy-providers": {"inline": {"type": "inline", "payload": [_http_node("相同名称", "provided.invalid"), _http_node("别名", "provided.invalid")]}},
        "proxy-groups": [{"name": "手动", "type": "select", "use": ["inline"]}],
    })
    result = SubscriptionImporter().import_source(SourceSpec("text", "auto", text))
    assert result.importable_count == 3 and result.providers_complete
    nodes = select_policy_nodes(result, "手动")
    assert len(nodes) == 2 and all(node["url"] == "http://provided.invalid:80" for node in nodes)
    assert "provided.invalid" not in repr(result.providers)


@pytest.mark.parametrize("flag,expected", [
    ("include-all", ["direct", "provided"]),
    ("include-all-proxies", ["direct"]),
    ("include-all-providers", ["provided"]),
])
def test_policy_include_flags_expand_finite_members(flag, expected) -> None:
    result = _parse(_yaml({
        "proxies": [_http_node("direct")],
        "proxy-providers": {"inline": {"type": "inline", "payload": [_http_node("provided")]}},
        "proxy-groups": [{"name": "手动", "type": "select", flag: True}],
    }))
    assert [node["name"] for node in select_policy_nodes(result, "手动")] == expected


def test_offline_remote_provider_cannot_partially_replace_existing_nodes(monkeypatch) -> None:
    monkeypatch.setattr(subscriptions, "read_source", lambda *args, **kwargs: pytest.fail("离线解析不得请求"))
    text = _yaml({"proxies": [_http_node("direct")], "proxy-providers": {"remote": {"type": "http", "url": "https://feed.invalid/provider?token=secret"}}})
    result = _parse(text)
    assert result.importable_count == 1 and not result.providers_complete
    assert any("不能合并" in notice for notice in result.notices)
    payload = {"proxy_groups": [{"id": "group", "proxies": [{"id": "old", "source_id": "source-test"}]}]}
    before = deepcopy(payload)
    with pytest.raises(ConfigError, match="完整展开"):
        merge_proxy_import(payload, result, target_group_id="group")
    assert payload == before
    assert "token=secret" not in repr(result)


@pytest.mark.parametrize("kind", ["text", "url", "file"])
def test_explicit_import_fetches_http_provider_once_and_retains_original_text(monkeypatch, tmp_path, kind) -> None:
    url = "https://feed.invalid/provider?token=secret"
    text = _yaml({
        "proxies": [_http_node("direct")],
        "proxy-providers": {name: {"type": "http", "url": url, "path": "never-read.yaml", "health-check": {"enable": True}} for name in ("one", "two")},
        "proxy-groups": [{"name": "手动", "type": "select", "use": ["one"]}],
    })
    source_url = "https://feed.invalid/subscription"
    calls = _fake_http(monkeypatch, {source_url: text, url: _yaml({"proxies": [_http_node("A"), _http_node("B")]})})
    if kind == "file":
        source = tmp_path / "source.yaml"
        source.write_text(text, encoding="utf-8", newline="")
        reference = str(source)
    else:
        reference = text if kind == "text" else source_url
    result = SubscriptionImporter().import_source(SourceSpec(kind, "auto", reference))
    assert calls == ([source_url, url] if kind == "url" else [url])
    assert result.providers_complete and result.importable_count == 3
    assert result.content == text
    assert all(provider["resolved"] and provider["type"] == "http" for provider in result.providers)
    assert [node["name"] for node in select_policy_nodes(result, "手动")] == ["A", "B"]
    assert "token=secret" not in repr(result.providers)


@pytest.mark.parametrize("bad_body", [
    "not-a-node-array",
    "proxy-providers: {nested: {type: http, url: 'https://other.invalid/sub'}}",
    urllib.error.URLError("secret-url-must-not-leak"),
])
def test_failed_or_recursive_provider_rejects_whole_explicit_import(monkeypatch, bad_body) -> None:
    url = "https://feed.invalid/provider"
    text = _yaml({"proxies": [_http_node("direct")], "proxy-providers": {"remote": {"type": "http", "url": url}}})
    calls = _fake_http(monkeypatch, {url: bad_body})
    old = {"selected": "old", "proxies": [{"id": "old", "source_id": "source-test", "url": "http://old.invalid:80"}]}
    before = deepcopy(old)
    with pytest.raises(ConfigError, match="provider") as error:
        SubscriptionImporter().import_source(SourceSpec("text", "auto", text), existing_group=old, source_id="source-test")
    assert "secret-url" not in str(error.value)
    assert calls == [url] and old == before


def test_file_provider_never_reads_arbitrary_local_path(monkeypatch) -> None:
    monkeypatch.setattr(subscriptions, "read_source", lambda *args, **kwargs: pytest.fail("禁止读取订阅中的 path"))
    text = _yaml({"proxies": [_http_node("direct")], "proxy-providers": {"local": {"type": "file", "path": "C:/private/credentials.yaml"}}})
    assert not _parse(text).providers_complete
    with pytest.raises(ConfigError, match="本地 path"):
        SubscriptionImporter().import_source(SourceSpec("text", "auto", text))


@pytest.mark.parametrize("url", ["file:///secret", "https://user:password@feed.invalid/sub", "https://feed.invalid/sub#fragment"])
def test_provider_uses_network_url_validation_before_request(monkeypatch, url) -> None:
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: pytest.fail("无效 URL 不应发起读取"))
    text = _yaml({"proxy-providers": {"remote": {"type": "http", "url": url}}})
    with pytest.raises(ConfigError, match="provider"):
        SubscriptionImporter().import_source(SourceSpec("text", "auto", text))


def test_provider_body_and_aggregate_limits(monkeypatch) -> None:
    from net import subscriptions as network

    url = "https://feed.invalid/provider"
    text = _yaml({"proxy-providers": {"remote": {"type": "http", "url": url}}})
    calls = _fake_http(monkeypatch, {url: "#" + "x" * 1024})
    monkeypatch.setattr(network, "MAX_RAW_BYTES", 512)
    with pytest.raises(ConfigError, match="provider"):
        SubscriptionImporter().import_source(SourceSpec("text", "auto", text))
    assert calls == [url]
    monkeypatch.setattr(network, "MAX_RAW_BYTES", 4096)
    monkeypatch.setattr(subscriptions, "_MAX_TEXT_BYTES", 512)
    provider_prefix = _yaml({"proxies": [_http_node("provided")]}) + "#"
    provider = provider_prefix + "x" * (512 - len(provider_prefix) - len(text) // 2)
    assert len(provider.encode()) < 512 < len(provider.encode()) + len(text.encode())
    calls = _fake_http(monkeypatch, {url: provider})
    with pytest.raises(ConfigError, match="provider"):
        SubscriptionImporter().import_source(SourceSpec("text", "auto", text))
    assert calls == [url]


def test_provider_count_limit_before_fetch(monkeypatch) -> None:
    monkeypatch.setattr(subscriptions, "read_source", lambda *args, **kwargs: pytest.fail("超量 provider 不应读取"))
    text = _yaml({"proxy-providers": {str(index): {"type": "http", "url": "https://feed.invalid/sub"} for index in range(17)}})
    with pytest.raises(ConfigError, match="16"):
        SubscriptionImporter().import_source(SourceSpec("text", "auto", text))


@pytest.mark.parametrize("provider", [
    {"type": "inline", "payload": "not-an-array"},
    {"type": "inline"},
    {"type": "inline", "payload": [], "override": {"skip-cert-verify": True}},
])
def test_invalid_or_semantically_modified_provider_is_not_silently_ignored(provider) -> None:
    with pytest.raises(ConfigError, match="provider"):
        _parse(_yaml({"proxies": [_http_node("direct")], "proxy-providers": {"bad": provider}}))


def test_provider_unsupported_nodes_and_critical_options_are_reported() -> None:
    result = _parse(_yaml({"proxy-providers": {"inline": {"type": "inline", "payload": [
        _http_node("good"),
        {"name": "unknown", "type": "wireguard", "server": "wg.invalid", "port": 80},
        dict(_http_node("custom-sni"), sni="different.invalid", tls=True),
        dict(_http_node("headers"), headers={"Host": "different.invalid"}),
    ]}}}))
    assert result.importable_count == 1 and result.skipped_count == 3
    assert all(candidate.reason for candidate in result.candidates if not candidate.importable)
    assert any("不能使用" in notice for notice in result.notices)


def test_removed_same_name_node_does_not_select_another_old_connection() -> None:
    previous = _parse("http://one.invalid:80#香港\nhttp://two.invalid:80#香港", format="uri")
    old = {"proxies": list(previous.nodes), "selected": previous.nodes[1]["id"]}
    result = _parse("http://one.invalid:80#香港", format="uri", existing_group=old)
    assert result.selection_lost
    assert subscription_update_summary(old, result)["selection_lost"]


@pytest.mark.parametrize("redirect", ["file:///private.yaml", "https://user:password@feed.invalid/sub", "loop"])
def test_provider_redirect_validation_and_limit_are_enforced(monkeypatch, redirect) -> None:
    from net import subscriptions as network

    url = "https://feed.invalid/provider"
    calls = []

    class Opener:
        def __init__(self, handler):
            self.handler = handler

        def open(self, request, timeout):
            calls.append(request.full_url)
            if redirect == "loop":
                for _ in range(network.MAX_REDIRECTS + 1):
                    self.handler.redirect_request(request, None, 302, "", {}, url)
            else:
                self.handler.redirect_request(request, None, 302, "", {}, redirect)
            pytest.fail("受限重定向不应到达读取正文")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: Opener(next(handler for handler in handlers if isinstance(handler, network._SafeRedirectHandler))))
    text = _yaml({"proxy-providers": {"remote": {"type": "http", "url": url}}})
    with pytest.raises(ConfigError, match="provider"):
        SubscriptionImporter().import_source(SourceSpec("text", "auto", text))
    assert calls == [url]


def test_provider_gzip_decoding_limit_is_enforced(monkeypatch) -> None:
    from net import subscriptions as network

    class Response(io.BytesIO):
        headers = {"Content-Encoding": "gzip"}

    class Opener:
        def open(self, request, timeout):
            return Response(gzip.compress(b"x" * 1024))

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    monkeypatch.setattr(network, "MAX_TEXT_BYTES", 512)
    text = _yaml({"proxy-providers": {"remote": {"type": "http", "url": "https://feed.invalid/provider"}}})
    with pytest.raises(ConfigError, match="provider"):
        SubscriptionImporter().import_source(SourceSpec("text", "auto", text))


@pytest.mark.parametrize("option", ["tls", "skip-cert-verify", "udp"])
def test_native_boolean_options_are_not_silently_dropped(option) -> None:
    node = _http_node("invalid")
    node[option] = "true"
    result = _parse(_yaml({"proxies": [node]}))
    assert result.importable_count == 0 and result.candidates[0].status == "invalid"
