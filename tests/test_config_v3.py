"""配置层：v2 → v3 迁移、未知键保全、Secret 导出。

这三件事共享一条不变量：**用户写进配置的东西，不能因为程序读过一遍就消失。**
旧实现在这里丢过 cookie_file、referer_path，也丢过整份运行期缓存（迁移换了缓存键）。
"""

from __future__ import annotations

import json

from config import migrate, schema, secrets, store
from config.overlay import Overlay

LEGACY = {
    "accounts": [
        {
            "name": "极速蹬",
            "base_url": "https://jsd.invalid/",
            "site_profile": "sub2api",
            "auth_method": "oauth",
            "checkin_action": "browser_script",
            "script": "scripts/checkin/jisudeng.py",
            "script_args": {"start_path": "/play/checkin", "email": "a@b.c", "password": "pw"},
            "script_timeout": 300,
            "oauth_provider": "linuxdo",
            "oauth_fallback_provider": "github",
            "access_token": "tok",
            "refresh_token": "rt",
            "tolerate_failure": True,
            "verification_mode": "turnstile",
            "login_selector": "#legacy",
        },
        {
            "name": "New API 站",
            "base_url": "https://api.invalid",
            "site_profile": "newapi",
            "auth_method": "cookie",
            "checkin_action": "api",
            "cookie": "s=1",
            "user_id": "42",
            "api_variant": "auto",
        },
    ],
    "oauth_states": {"linuxdo": {"accounts": {"default": {"state": "STATE"}}}},
}


def test_migration_maps_every_dimension() -> None:
    result = migrate.migrate_document(LEGACY)
    jsd, api = result.payload["accounts"]

    assert jsd["template"] == "scripts/tasks/jisudeng.py", "脚本目录已改名"
    assert jsd["tasks"][0]["method"] == "script"
    assert jsd["tasks"][0]["timeout"] == 300
    assert jsd["login"]["method"] == "oauth"
    assert jsd["flow"] == {"verification": "turnstile"}
    assert jsd["policy"] == {"tolerate_failure": True}
    assert {item["method"] for item in jsd["login"]["fallback"]} == {"oauth", "password"}

    assert api["template"] == "newapi"
    assert api["tasks"][0]["method"] == "http_api"
    # 旧 auto 的语义是「challenge 优先」，不是新模型的默认值 legacy。
    assert api["tasks"][0]["args"]["variant"] == "challenge"
    assert api["credentials"]["user_id"] == "42"


def test_migration_moves_script_credentials_out_of_task_args() -> None:
    """账密从 script_args 搬到登录方式的参数上：凭据不该混在任务参数里。"""
    result = migrate.migrate_document(LEGACY)
    jsd = result.payload["accounts"][0]
    password = next(item for item in jsd["login"]["fallback"] if item["method"] == "password")
    assert password["args"] == {"email": "a@b.c", "password": "pw"}


def test_migration_explains_every_change() -> None:
    """每条改动都要留言：静默迁移会让用户对着一份自己没写过的配置发懵。"""
    notes = "\n".join(migrate.migrate_document(LEGACY).notes)
    assert "site_profile" in notes
    assert "auth_method" in notes
    assert "tolerate_failure" in notes
    assert "login_selector" in notes, "被丢弃的废弃字段同样要说明"


def test_migration_maps_legacy_cache_keys() -> None:
    """旧缓存键 base_url|name → 新账号 id，否则一次迁移等于清空全部运行期凭据。"""
    keys = migrate.migrate_document(LEGACY).cache_keys
    assert keys["https://jsd.invalid|极速蹬"] == "jsd-invalid"


def test_migration_is_idempotent() -> None:
    once = migrate.migrate_document(LEGACY).payload
    assert migrate.needs_migration(LEGACY) is True
    assert migrate.needs_migration(once) is False


def test_unknown_keys_survive_a_full_round_trip() -> None:
    """解析器不认识的键必须原样写回：GUI 保存一次不该抹掉用户手写的东西。"""
    raw = {
        "id": "s",
        "name": "s",
        "base_url": "https://s.invalid",
        "template": "newapi",
        "tasks": [{"id": "daily"}],
        "credentials": {"my_field": "keep"},
        "my_note": "也要留着",
    }
    dumped = schema.dump_account(schema.parse_account(raw))
    assert dumped["my_note"] == "也要留着"
    assert dumped["credentials"]["my_field"] == "keep"


def test_load_migrates_and_rehomes_the_overlay(tmp_path) -> None:
    """加载旧配置时自动迁移，并把运行期缓存重挂到新 id 上。"""
    config = tmp_path / "ACCOUNTS.json"
    config.write_text(json.dumps(LEGACY, ensure_ascii=False), encoding="utf-8")

    overlay = Overlay(path=tmp_path / "overlay.json").load()
    overlay._entries["https://jsd.invalid|极速蹬"] = overlay.entry("https://jsd.invalid|极速蹬")
    document = store.load(config, overlay=overlay)

    assert document.version == schema.CONFIG_VERSION
    assert [spec.id for spec in document.accounts] == ["jsd-invalid", "new-api"]
    assert any("已迁移" in note for note in document.notes)
    assert list(tmp_path.glob("ACCOUNTS.json.bak-v2-*")), "迁移前必须留一份备份"


def test_secret_export_keeps_credentials_but_drops_disabled_accounts() -> None:
    """Secret 只带 CI 真正要用的东西：启用账号 + 它们引用到的共享登录态。"""
    document = schema.parse_document(migrate.migrate_document(LEGACY).payload)
    payload = secrets.build_secret_payload(document)

    exported = {item["id"] for item in payload["accounts"]}
    assert exported == {"jsd-invalid", "new-api"}

    jsd = next(item for item in payload["accounts"] if item["id"] == "jsd-invalid")
    # 凭据与登录方式无关：只要有就导出。旧实现按 auth_method 过滤，导致 OAuth 账号的
    # token 没进 Secret，CI 里纯 API 那一级直接被跳过，只能拉浏览器（而 CI 过不去）。
    assert jsd["credentials"]["access_token"] == "tok"
    assert jsd["credentials"]["refresh_token"] == "rt"
    assert payload["oauth_states"]["linuxdo"]["accounts"]["default"]["state"] == "STATE"


def test_secret_size_check_is_actionable() -> None:
    assert secrets.check_size("x" * 10) == ""
    warning = secrets.check_size("x" * (secrets.SECRET_SIZE_LIMIT + 1))
    assert "KiB" in warning and "登录态" in warning


def test_cookie_file_is_not_expanded_into_plaintext(tmp_path) -> None:
    """用户把凭据放在单独文件里，就是不想让它们进配置。"""
    creds = tmp_path / "creds.txt"
    creds.write_text("sess=1\n42\ntok\n", encoding="utf-8")

    spec = schema.parse_account(
        {
            "id": "s",
            "name": "s",
            "base_url": "https://s.invalid",
            "tasks": [{"id": "daily"}],
            "credentials": {"cookie_file": str(creds)},
        }
    )
    assert spec.credentials.cookie == "sess=1", "运行期确实读到了值"

    dumped = schema.dump_account(spec)
    assert dumped["credentials"] == {"cookie_file": str(creds)}
    assert "cookie" not in dumped["credentials"]
