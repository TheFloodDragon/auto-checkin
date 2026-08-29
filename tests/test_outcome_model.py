"""结论模型：四基准 + 自由子结果 + 三级展示优先级。"""

from __future__ import annotations

import pytest

from core.outcome import (
    REASONS,
    DisplaySpec,
    Evidence,
    Outcome,
    Verdict,
    already_done,
    failed,
    from_legacy_status,
    no_effect,
    success,
    to_legacy_status,
)


# ── 基准判定 ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("outcome", "expected_ok"),
    [
        (success("s"), True),
        (already_done("d"), True),
        (no_effect("n"), True),      # 未开放不计失败，也不影响退出码
        (failed("f"), False),
    ],
)
def test_ok_only_excludes_failed(outcome, expected_ok):
    assert outcome.ok is expected_ok


def test_reason_carries_actionability_and_retryability():
    assert failed("x", reason="need_login").actionable is True
    assert failed("x", reason="network_error").retryable is True
    assert failed("x", reason="need_config").retryable is False
    assert success("x").actionable is False


# ── 自由子结果 ──────────────────────────────────────────────────────────────
def test_unregistered_reason_is_preserved_not_rejected():
    """脚本报一个自定义结论，不该先去改内核。"""
    outcome = failed("等级不足").as_reason("level_gate")
    assert outcome.reason == "level_gate"
    assert "level_gate" in outcome.label     # 未注册时至少让人看见
    assert outcome.to_payload()["reason"] == "level_gate"


def test_registered_reason_supplies_label_and_verdict():
    REASONS.register(
        "lottery_miss", verdict=Verdict.SUCCESS, label="已抽奖（未中）", icon="🎲",
        replace_existing=True,
    )
    outcome = failed("抽了但没中").as_reason("lottery_miss")
    # 注册时声明了基准结果，改判会一并生效
    assert outcome.verdict is Verdict.SUCCESS
    assert outcome.ok is True
    assert outcome.label == "已抽奖（未中）"


def test_reason_cannot_be_silently_rebound_to_another_verdict():
    REASONS.register("stable_slug", verdict=Verdict.FAILED, label="A", replace_existing=True)
    with pytest.raises(ValueError):
        REASONS.register("stable_slug", verdict=Verdict.SUCCESS, label="B")


def test_reason_slug_is_normalized():
    assert failed("x").as_reason("Need-Login").reason == "need_login"


# ── 展示优先级：内置默认 → 模板默认 → 结论覆写 ──────────────────────────────
def test_display_precedence():
    outcome = failed("x", reason="need_login").with_display(label="账号被封")
    view = outcome.rendered(defaults=DisplaySpec(label="登录问题", icon="🔑", text_label="额度"))
    assert view.label == "账号被封"    # 结论覆写最高
    assert view.icon == "🔐"           # 内置子结果图标（模板未覆写图标时保留）
    assert view.text_label == "额度"   # 模板默认生效


def test_empty_fields_mean_use_default_not_show_blank():
    view = success("s").rendered(defaults=DisplaySpec(text="$1.00", text_label="额度"))
    assert view.label == "成功"
    assert view.text == "$1.00"


def test_extras_are_appended_and_deduped():
    outcome = success("s", extras=[("连续天数", 3)]).with_display(
        DisplaySpec(extras=(("连续天数", "99"), ("累计", "10")))
    )
    extras = dict(outcome.rendered().extras)
    assert extras["连续天数"] == "3"   # 先到的赢，不被后续默认值顶掉
    assert extras["累计"] == "10"


# ── 自定义文本列 ────────────────────────────────────────────────────────────
def test_custom_text_is_optional():
    """不支持自定义文本的任务，该列就是空的——不再被迫编一个额度。"""
    payload = success("抽奖完成").to_payload()
    assert "text" not in payload


def test_custom_text_is_not_quota_specific():
    payload = success("答对 3 题", text="3/5", text_label="答题").to_payload()
    assert payload["text"] == "3/5"
    assert payload["text_label"] == "答题"


# ── tolerate_failure ────────────────────────────────────────────────────────
def test_tolerated_rewrites_verdict_and_keeps_origin():
    outcome = failed("站点长期不可用", reason="network_error").tolerated()
    assert outcome.verdict is Verdict.NO_EFFECT
    assert outcome.ok is True
    assert outcome.reason == "tolerated"
    assert outcome.data["tolerated_from"] == {"verdict": "failed", "reason": "network_error"}


def test_tolerated_is_noop_for_successful_outcome():
    outcome = success("s")
    assert outcome.tolerated() is outcome


# ── 不可变性 ────────────────────────────────────────────────────────────────
def test_outcome_is_immutable_and_transforms_return_new():
    base = success("s")
    changed = base.with_data(a=1).with_message("t")
    assert base.message == "s" and not base.data
    assert changed.message == "t" and changed.data["a"] == 1


def test_with_data_merges_maps_and_kwargs():
    outcome = success("s").with_data({"a": 1}, {"b": 2}, c=3)
    assert dict(outcome.data) == {"a": 1, "b": 2, "c": 3}


# ── 证据 ────────────────────────────────────────────────────────────────────
def test_evidence_merges_without_duplicates():
    left = Evidence().with_screenshot("a.png").with_stage("s1")
    right = Evidence().with_screenshot("a.png").with_screenshot("b.png").with_stage("s2")
    merged = left.merge(right)
    assert merged.screenshots == ("a.png", "b.png")
    assert merged.stages == ("s1", "s2")


def test_evidence_enters_payload_only_when_present():
    assert "evidence" not in success("s").to_payload()
    assert "evidence" in success("s").with_evidence(Evidence().with_screenshot("x")).to_payload()


# ── 与旧 8 值 status 的双向映射 ─────────────────────────────────────────────
@pytest.mark.parametrize(
    "legacy",
    ["success", "already_done", "not_open", "need_login", "need_verification",
     "need_config", "network_error", "error"],
)
def test_legacy_status_roundtrip(legacy):
    verdict, reason = from_legacy_status(legacy)
    assert to_legacy_status(Outcome(verdict=verdict, reason=reason)) == legacy


def test_unknown_legacy_status_is_failure():
    assert from_legacy_status("wat") == (Verdict.FAILED, "")


def test_custom_reason_maps_to_nearest_legacy_status():
    assert to_legacy_status(failed("x").as_reason("level_gate")) == "error"
    assert to_legacy_status(no_effect("x", reason="not_applicable")) == "not_open"


# ── 序列化 ──────────────────────────────────────────────────────────────────
def test_payload_roundtrip_preserves_display_and_data():
    outcome = success("完成", text="$1.00", text_label="额度", data={"k": "v"})
    restored = Outcome.from_payload(outcome.to_payload())
    assert restored.verdict is Verdict.SUCCESS
    assert restored.rendered().text == "$1.00"
    assert restored.data["k"] == "v"


def test_from_payload_reads_v1_result_rows():
    restored = Outcome.from_payload(
        {"status": "need_verification", "message": "需验证", "detail": {"a": 1}}
    )
    assert restored.verdict is Verdict.FAILED
    assert restored.reason == "need_verification"
    assert restored.data["a"] == 1
