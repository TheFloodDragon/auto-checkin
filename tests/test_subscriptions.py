"""订阅/节点导入的离线回归测试；不发起网络请求、不依赖 GUI。"""
from __future__ import annotations

import base64
from copy import deepcopy

import pytest

from config import subscriptions
from config.subscriptions import (
    SourceSpec,
    SubscriptionImporter,
    merge_proxy_import,
    parse_subscription_text,
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
                source_id="source-feed",
                source_label="feed",
                format="uri",
                existing_group=old,
            )
            summary = subscription_update_summary(old, result)
            assert summary["old_count"] == 2 and summary["new_count"] == 2
            assert summary["unchanged"] == 1 and summary["added"] == 1 and summary["removed"] == 1
            assert summary["selected_name"] == "保留"
            assert "http://keep.invalid" not in repr(summary)
            assert summary["content_hash"]


        def test_clash_metadata_identifies_select_groups_and_providers() -> None:
            if subscriptions.yaml is None:
                pytest.skip("PyYAML 未安装")
            result = parse_subscription_text(
                """
        proxies:
          - name: A
            type: http
            server: a.example.invalid
            port: 80
        proxy-groups:
          - name: 手动出口
            type: select
            proxies: [A, DIRECT]
          - name: 自动出口
            type: url-test
            proxies: [A]
        proxy-providers:
          feed:
            type: http
            url: https://feed.example.invalid/sub?token=secret
        """,
                source_id="source-clash",
                source_label="clash.yaml",
                format="clash_yaml",
            )
            assert {item["name"] for item in result.policy_groups} == {"手动出口", "自动出口"}
            assert result.providers == ({"name": "feed", "type": "http"},)
            assert any("策略组" in notice for notice in result.notices)
            assert "secret" not in repr(result.providers)


        def test_write_text_file_is_atomic_and_utf8(tmp_path) -> None:
            target = tmp_path / "edited.yaml"
            assert write_text_file(str(target), "proxies:\n- name: 节点\n") == str(target)
            assert target.read_text(encoding="utf-8") == "proxies:\n- name: 节点\n"
            with pytest.raises(ConfigError, match="目录"):
                write_text_file(str(tmp_path), "text")



                def test_base64_clash_metadata_is_detected() -> None:
                    if subscriptions.yaml is None:
                        pytest.skip("PyYAML 未安装")
                    text = """
                proxies:
                  - name: A
                    type: http
                    server: a.example.invalid
                    port: 80
                proxy-groups:
                  - name: 手动
                    type: select
                    proxies: [A]
                """
                    encoded = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
                    result = parse_subscription_text(encoded, source_id="source-b64-clash", source_label="feed", format="base64")
                    assert result.policy_groups[0]["type"] == "select"
