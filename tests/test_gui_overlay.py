"""overlay 预览仅使用临时配置、假凭据；不访问真实账号或网络。"""
import copy
import hashlib
import json

import pytest

from config.overlay import CachePolicy
from gui.overlay_preview import evaluate_overlay, load_overlay_snapshot


def fake_files(tmp_path, *, ttl=0, config_hash=None):
    raw = {"id": "fake", "base_url": "https://fake.invalid", "credentials": {"access_token": "CONFIG_FAKE"}}
    config = tmp_path / "accounts.json"
    overlay = tmp_path / "overlay.json"
    config.write_text(json.dumps({"version": 3, "accounts": [raw]}), encoding="utf-8")
    field = {"value": "CACHE_FAKE", "updated_at": "2020-01-01T00:00:00Z", "ttl": ttl,
             "origin": "refresh", "config_hash": config_hash or "sha256:" + hashlib.sha256(b"CONFIG_FAKE").hexdigest()}
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
