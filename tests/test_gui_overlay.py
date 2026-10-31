"""overlay 预览仅使用临时配置、假凭据；不访问真实账号或网络。"""
import copy
import hashlib
import json

import pytest

from config.overlay import CachePolicy
from config.schema import parse_account
from core.account import authentication_scope
from gui.overlay_preview import evaluate_overlay, load_overlay_snapshot


def fake_files(tmp_path, *, ttl=0, config_hash=None):
    raw = {"id": "fake", "base_url": "https://fake.invalid", "credentials": {"access_token": "CONFIG_FAKE"}}
    config = tmp_path / "accounts.json"
    overlay = tmp_path / "overlay.json"
    config.write_text(json.dumps({"version": 3, "accounts": [raw]}), encoding="utf-8")
    field = {"value": "CACHE_FAKE", "updated_at": "2020-01-01T00:00:00Z", "ttl": ttl,
             "origin": "refresh", "config_hash": config_hash or "sha256:" + hashlib.sha256(b"CONFIG_FAKE").hexdigest(),
             # 运行期写入的缓存都绑定账号作用域；无作用域的旧缓存保留但不采用，不是这里要测的规则。
             "auth_scope": authentication_scope(parse_account(copy.deepcopy(raw)))}
    overlay.write_text(json.dumps({"version": 3, "entries": {"fake": {"fields": {"access_token": field}}}}), encoding="utf-8")
    return raw, config, overlay


def test_preview_rules_and_repr(tmp_path):
    raw, config, overlay = fake_files(tmp_path)
    before = (config.read_bytes(), overlay.read_bytes())
    snapshot = load_overlay_snapshot(config, overlay, "fake")
    preview = evaluate_overlay(snapshot, raw)["access_token"]
    assert preview.effective and not preview.mismatch and not preview.expired
    assert preview.value == "CACHE_FAKE"
    assert "FAKE" not in repr(snapshot) + repr(preview)
    assert not evaluate_overlay(snapshot, raw, policy=CachePolicy.IGNORE)["access_token"].effective
    draft = copy.deepcopy(raw)
    draft["credentials"]["access_token"] = ""
    assert not evaluate_overlay(snapshot, draft)["access_token"].effective
    assert evaluate_overlay(snapshot, draft)["access_token"].mismatch
    assert evaluate_overlay(snapshot, {**raw, "base_url": ""})["access_token"].effective is None
    assert evaluate_overlay(snapshot, {**raw, "id": "other"}) == {}
    assert load_overlay_snapshot(config, overlay, "new") is None
    assert before == (config.read_bytes(), overlay.read_bytes())


def test_expiry_and_config_mismatch(tmp_path):
    raw, config, overlay = fake_files(tmp_path, ttl=1)
    snapshot = load_overlay_snapshot(config, overlay, "fake")
    preview = evaluate_overlay(snapshot, raw, now_iso="2020-01-02T00:00:00Z")["access_token"]
    assert preview.expired and not preview.effective and not preview.mismatch
    raw, config, overlay = fake_files(tmp_path, config_hash="sha256:other")
    preview = evaluate_overlay(load_overlay_snapshot(config, overlay, "fake"), raw)["access_token"]
    assert preview.mismatch and not preview.effective


def test_legacy_time_fallback_and_no_external_reads(tmp_path, monkeypatch):
    from config import schema
    raw, config, overlay = fake_files(tmp_path)
    payload = json.loads(overlay.read_text())
    payload["entries"]["fake"]["fields"]["access_token"].pop("config_hash")
    overlay.write_text(json.dumps(payload))
    raw["credentials"]["cookie_file"] = "DO_NOT_READ"
    config.write_text(json.dumps({"accounts": [raw]}))
    monkeypatch.setattr(schema, "_read_cookie_file", lambda *a, **k: pytest.fail("external read"))
    snapshot = load_overlay_snapshot(config, overlay, "fake")
    assert evaluate_overlay(snapshot, raw)["access_token"].mismatch
    overlay.unlink()
    assert not load_overlay_snapshot(config, overlay, "fake").fields
    assert not overlay.exists()  # 未触发 Overlay.load 的旧缓存迁移写盘。


def test_load_error_does_not_echo_secret(tmp_path):
    config = tmp_path / "bad.json"
    config.write_text("SECRET_BROKEN")
    with pytest.raises(Exception) as error:
        load_overlay_snapshot(config, tmp_path / "overlay.json", "fake")
    assert "SECRET" not in str(error.value)


def oauth_files(tmp_path, *, provider="linuxdo", account="default", ttl=0, basis=None, state="CONFIG_STATE"):
    """共享登录态的配置 + overlay 缓存；默认 TTL=0，即缓存存在但未生效。"""
    from config.schema import oauth_state_basis

    config = tmp_path / "accounts.json"
    overlay = tmp_path / "overlay.json"
    entry = {"state": state, "username": "config-user", "updated_at": "2020-01-01T00:00:00Z"}
    config.write_text(json.dumps({"version": 3, "accounts": [], "oauth_states": {provider: {"accounts": {account: entry}}}}),
                      encoding="utf-8")
    digest = oauth_state_basis({provider: {"accounts": {account: entry}}}, provider, account)[1]
    field = {"value": "CACHE_OAUTH_FAKE", "updated_at": "2020-01-01T00:00:00Z", "ttl": ttl,
             "origin": "oauth", "config_hash": digest if basis is None else basis}
    overlay.write_text(json.dumps({"version": 3, "oauth_states": {provider: {"accounts": {account: field}}}}), encoding="utf-8")
    return config, overlay


def test_oauth_overlay_rules_and_repr(tmp_path):
    from gui.overlay_preview import evaluate_oauth_overlay, load_oauth_overlay_snapshot

    config, overlay = oauth_files(tmp_path, ttl=86400)
    before = (config.read_bytes(), overlay.read_bytes())
    snapshot = load_oauth_overlay_snapshot(config, overlay, "linuxdo", "default")
    # 缓存写入时间固定在 2020，用同一时刻判定，避免测试随真实时钟腐化。
    now = "2020-01-01T01:00:00Z"
    preview = evaluate_oauth_overlay(snapshot, "CONFIG_STATE", now_iso=now)
    assert preview.effective and not preview.expired and not preview.mismatch
    assert preview.value == "CACHE_OAUTH_FAKE" and preview.reason == "已生效"
    assert preview.source == "oauth" and preview.updated_at == "2020-01-01T00:00:00Z"
    assert "FAKE" not in repr(snapshot) + repr(preview)
    # 草稿被覆写成同一个值：运行期结果一致，视为已应用。
    assert evaluate_oauth_overlay(snapshot, "CACHE_OAUTH_FAKE", now_iso=now).reason == "已应用到草稿"
    # 草稿改成别的值：缓存不再生效，但配置并未变过，所以不算 mismatch。
    assert not evaluate_oauth_overlay(snapshot, "OTHER", now_iso=now).effective
    assert before == (config.read_bytes(), overlay.read_bytes())


def test_oauth_overlay_draft_does_not_change_adoption(tmp_path):
    from gui.overlay_preview import evaluate_oauth_overlay, load_oauth_overlay_snapshot

    config, overlay = oauth_files(tmp_path, ttl=86400)
    snapshot = load_oauth_overlay_snapshot(config, overlay, "linuxdo", "default")
    for draft in ("", "CONFIG_STATE", "CACHE_OAUTH_FAKE", "OTHER"):
        preview = evaluate_oauth_overlay(snapshot, draft, now_iso="2020-01-01T01:00:00Z")
        if not draft.strip():
            assert preview.effective is None and preview.reason == "无法判定"
        else:
            assert preview.value == "CACHE_OAUTH_FAKE" and preview.mismatch is False


def test_oauth_overlay_ttl_expiry_mismatch_and_policy(tmp_path):
    from config.overlay import CachePolicy
    from gui.overlay_preview import evaluate_oauth_overlay, load_oauth_overlay_snapshot

    # ttl=0：缓存存在但未生效，且不谎报过期。
    config, overlay = oauth_files(tmp_path)
    preview = evaluate_oauth_overlay(load_oauth_overlay_snapshot(config, overlay, "linuxdo", "default"), "CONFIG_STATE")
    assert not preview.effective and not preview.expired and preview.reason == "未生效"
    # 有 TTL 但已过期。
    config, overlay = oauth_files(tmp_path, ttl=1)
    preview = evaluate_oauth_overlay(load_oauth_overlay_snapshot(config, overlay, "linuxdo", "default"), "CONFIG_STATE",
                                     now_iso="2020-01-02T00:00:00Z")
    assert preview.expired and not preview.effective and preview.reason == "未生效：已过期"
    # 写入缓存之后配置条目被改过：摘要不匹配，且优先于过期报告。
    config, overlay = oauth_files(tmp_path, ttl=1, basis="sha256:other")
    preview = evaluate_oauth_overlay(load_oauth_overlay_snapshot(config, overlay, "linuxdo", "default"), "CONFIG_STATE")
    assert preview.mismatch and preview.reason == "未生效：配置不匹配"
    # ignore 策略：运行期完全不叠加。
    config, overlay = oauth_files(tmp_path, ttl=86400)
    preview = evaluate_oauth_overlay(load_oauth_overlay_snapshot(config, overlay, "linuxdo", "default"), "CONFIG_STATE",
                                     policy=CachePolicy.IGNORE)
    assert not preview.effective and preview.reason.startswith("未生效：运行时忽略缓存")


def test_oauth_overlay_missing_entries_and_corruption(tmp_path):
    from gui.overlay_preview import evaluate_oauth_overlay, load_oauth_overlay_snapshot

    config, overlay = oauth_files(tmp_path, ttl=86400)
    # 配置里没有该条目 → 无可对照（不虚构缓存值）。
    assert load_oauth_overlay_snapshot(config, overlay, "linuxdo", "other") is None
    assert load_oauth_overlay_snapshot(config, overlay, "github", "default") is None
    assert load_oauth_overlay_snapshot(config, overlay, "", "default") is None
    # 配置里的条目无 state：同样不产生对照。
    empty = {"version": 3, "accounts": [], "oauth_states": {"linuxdo": {"accounts": {"default": {"state": ""}}}}}
    config.write_text(json.dumps(empty), encoding="utf-8")
    assert load_oauth_overlay_snapshot(config, overlay, "linuxdo", "default") is None
    # overlay 缺失：视为无缓存值，且绝不写盘。
    config, overlay = oauth_files(tmp_path, ttl=86400)
    overlay.unlink()
    snapshot = load_oauth_overlay_snapshot(config, overlay, "linuxdo", "default")
    preview = evaluate_oauth_overlay(snapshot)
    assert preview.value == "" and preview.reason == "无覆写值" and not preview.effective
    assert not overlay.exists()
    # 损坏的 overlay：固定文案，且不泄露文件内容。
    overlay.write_text("SECRET_BROKEN", encoding="utf-8")
    with pytest.raises(Exception) as error:
        load_oauth_overlay_snapshot(config, overlay, "linuxdo", "default")
    assert "SECRET" not in str(error.value)


def test_oauth_overlay_reads_are_read_only_for_legacy_cache(tmp_path, monkeypatch):
    from config import schema
    from gui.overlay_preview import load_oauth_overlay_snapshot

    config, overlay = oauth_files(tmp_path, ttl=86400)
    payload = json.loads(config.read_text(encoding="utf-8"))
    payload["accounts"] = [{"id": "fake", "base_url": "https://fake.invalid", "credentials": {"cookie_file": "DO_NOT_READ"}}]
    config.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(schema, "_read_cookie_file", lambda *a, **k: pytest.fail("external read"))
    before = (config.read_bytes(), overlay.read_bytes())
    snapshot = load_oauth_overlay_snapshot(config, overlay, "linuxdo", "default")
    assert snapshot.saved_value == "CACHE_OAUTH_FAKE"
    assert before == (config.read_bytes(), overlay.read_bytes())
