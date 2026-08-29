# -*- coding: utf-8 -*-
"""gui.core 纯逻辑层测试（不依赖 PySide6）。"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from core import timebase as time_utils

from config import schema
from gui import config_store, core


def _mk_states(provider: str = "linuxdo", account: str = "default", state: str = "abc123") -> dict:
    return {provider: {"accounts": {account: {"state": state, "username": "u"}}}}


# ── effective_auth / can_optional_oauth ──────────────────────────────────────
def test_effective_auth_only_forces_oauth_for_relogin() -> None:
    """任务方式不该替用户改登录方式，除了 relogin。

    ``relogin`` 的语义就是「重放一次 OAuth 登录触发发放」，用别的登录方式没有意义。
    其余任务方式（脚本、浏览器流程）在新模型里可以配任意登录方式：脚本自己决定
    要不要开浏览器，框架不该提前替它选。
    """
    assert core.effective_auth("relogin", "cookie") == "oauth"
    assert core.effective_auth("script", "browser_state") == "browser_state"
    assert core.effective_auth("script", "access_token") == "access_token"
    assert core.effective_auth("http_api", "cookie") == "cookie"
    assert core.effective_auth("http_api", "") == "", "留空表示交给引擎按模板优先序决定"


def test_optional_login_fallback_is_open_to_every_method() -> None:
    """备选登录方式不再是 OAuth 专属特例。

    旧模型只有 ``oauth_fallback_provider`` 一个单点，于是「token 失效后试账密」这种
    再普通不过的降级都表达不了��新模型是 ``login.fallback`` 链，对任何方式都成立。
    """
    assert core.can_optional_oauth("newapi", "http_api", "access_token")
    assert core.can_optional_oauth("sub2api", "script", "refresh")


def test_row_from_account_flattens_first_task_and_login() -> None:
    """账号 → 表单行：摊平第一个任务与主登录方式，地址归一化。"""
    spec = schema.parse_account(
        {
            "id": "s",
            "name": "s",
            "base_url": "https://Example.com/",
            "template": "newapi",
            "login": {"method": "oauth", "provider": "linuxdo"},
            "tasks": [{"id": "daily", "method": "relogin", "timeout": 120}],
        }
    )
    row = core.row_from_account(spec)
    assert row.auth_method == "oauth"
    assert row.checkin_action == "relogin"
    assert row.script_timeout == 120
    assert row.base_url == "https://example.com", "归一化会小写主机名并去尾斜杠"
    assert row.account_id == "s"


def test_row_to_account_preserves_everything_the_form_does_not_show() -> None:
    """表单只覆盖它认识的字段，其余原样保留。

    这是「GUI 保存一次就把手写配置抹掉」这一整类问题的防线：多任务、任务依赖、
    policy、以及解析器都不认识的自定义键，都必须在往返后原样还在。
    """
    spec = schema.parse_account(
        {
            "id": "multi",
            "name": "多任务站",
            "base_url": "https://a.com",
            "template": "sub2api",
            "tasks": [
                {"id": "daily", "method": "http_api"},
                {"id": "quiz", "method": "script", "depends_on": ["daily"]},
            ],
            "policy": {"tolerate_failure": True},
            "my_own_note": "别删我",
        }
    )
    row = core.row_from_account(spec)
    row.name = "改个名字"
    restored = core.row_to_account(row)

    assert [task.id for task in restored.tasks] == ["daily", "quiz"]
    assert restored.tasks[1].depends_on == ("daily",)
    assert restored.policy.tolerate_failure is True
    assert dict(restored.extras)["my_own_note"] == "别删我"
    assert restored.name == "改个名字"


def test_verification_mode_round_trips_through_flow() -> None:
    """验证机制现在住在 flow 里；auto 不写进配置，避免制造噪声键。"""
    spec = schema.parse_account(
        {
            "id": "s",
            "name": "s",
            "base_url": "https://a.com",
            "template": "newapi",
            "flow": {"verification": "click_shape"},
            "tasks": [{"id": "daily"}],
        }
    )
    row = core.row_from_account(spec)
    assert row.verification_mode == "click_shape"

    row.verification_mode = "auto"
    assert "verification" not in dict(core.row_to_account(row).flow)


def test_row_from_account_script_args_text() -> None:
    spec = schema.parse_account(
        {
            "id": "s",
            "name": "s",
            "base_url": "https://a.com",
            "template": "scripts/tasks/100xlabs.py",
            "tasks": [{"id": "daily", "method": "script", "args": {"k": "v"}}],
        }
    )
    row = core.row_from_account(spec)
    assert row.script_args == {"k": "v"}
    assert json.loads(row.script_args_text) == {"k": "v"}
    assert row.script == "scripts/tasks/100xlabs.py", "路径型模板同时填进脚本框"

    empty = core.row_from_account(
        schema.parse_account({"id": "e", "name": "e", "base_url": "https://a.com", "tasks": [{"id": "daily"}]})
    )
    assert empty.script_args_text == "{}"


def test_task_params_produces_a_valid_v3_account() -> None:
    """GUI 的「立即执行」载荷必须与批量子进程读到的账号完全同构。

    旧实现在 GUI、CLI、批量三处各手写一份运行参数 dict，字段增删必然漏改一处
    （实测：GUI 能用、批量静默丢脚本参数）。这里断言载荷能被同一个解析器接受。
    """
    row = core.SiteRow(
        name="s", base_url="https://a.com", checkin_action="relogin", auth_method="cookie"
    )
    params = core.task_params(row, _mk_states(state="STATE-X"))

    assert params["login"]["method"] == "oauth", "relogin 必须矫正为 OAuth 登录"
    assert params["tasks"][0]["method"] == "relogin"
    assert params["_oauth_states"]["linuxdo"]["accounts"]["default"]["state"] == "STATE-X"

    spec = schema.parse_account({k: v for k, v in params.items() if not k.startswith("_")})
    assert spec.login.method == "oauth"
    assert spec.network.verify_ssl is True


def test_task_params_carries_credentials_and_fallback() -> None:
    row = core.SiteRow(
        name="s",
        base_url="https://a.com",
        type="sub2api",
        auth_method="access_token",
        checkin_action="http_api",
        browser_state="row-state",
        oauth_fallback_provider="linuxdo",
        oauth_fallback_account="default",
        verify_ssl=False,
    )
    params = core.task_params(row, {})
    assert params["credentials"]["browser_state"] == "row-state"
    assert params["login"]["fallback"][0] == {"method": "oauth", "provider": "linuxdo"}
    assert params["network"]["verify_ssl"] is False


def test_form_plan_relogin() -> None:
    row = core.SiteRow(name="s", base_url="https://a.com", checkin_action="relogin", auth_method="oauth")
    plan = core.build_form_plan(row, _mk_states())
    assert plan.show_oauth and plan.show_browser_ops and plan.show_delete_oauth
    assert not plan.creds_enabled
    assert plan.capture_text == "捕获 OAuth 登录态"
    assert "已保存" in plan.oauth_status


def test_form_plan_sub2api_token_fallback() -> None:
    row = core.SiteRow(
        name="s", base_url="https://a.com", type="sub2api", auth_method="access_token",
        checkin_action="http_api", oauth_fallback_provider="linuxdo",
    )
    plan = core.build_form_plan(row, {})
    assert plan.show_fallback and plan.creds_enabled and plan.show_state_box
    assert not plan.show_browser_ops and not plan.state_editable
    assert "未保存登录态" in plan.oauth_status


def test_form_plan_hides_state_box_without_a_reason_to_show_it() -> None:
    """没配备选 OAuth、也不用浏览器登录时，不该多出一个用不上的登录态输入框。"""
    row = core.SiteRow(
        name="s", base_url="https://a.com", type="sub2api", auth_method="access_token",
        checkin_action="http_api",
    )
    plan = core.build_form_plan(row, {})
    assert plan.show_fallback, "备选链对所有登录方式开放"
    assert not plan.show_state_box


def test_form_plan_script_task_with_browser_login() -> None:
    row = core.SiteRow(
        name="s", base_url="https://a.com", auth_method="browser_state", checkin_action="script",
        oauth_fallback_provider="linuxdo", oauth_fallback_account="default",
    )
    plan = core.build_form_plan(row, _mk_states())
    assert plan.show_script and plan.show_fallback and plan.state_editable
    assert plan.oauth_status.startswith("可选 OAuth：")


def test_form_plan_newapi_api_controls_visible() -> None:
    row = core.SiteRow(name="s", base_url="https://a.com", type="newapi", checkin_action="http_api")
    plan = core.build_form_plan(row, {})
    assert plan.show_variant
    assert plan.show_verification
    assert not plan.show_state_box


def test_validate_rows_errors() -> None:
    assert core.validate_rows([core.SiteRow(name="", base_url="https://a.com")]) is not None
    assert core.validate_rows([core.SiteRow(name="a", base_url="")]) is not None
    dup = [core.SiteRow(name="a", base_url="https://a.com"), core.SiteRow(name="a", base_url="https://b.com")]
    assert "重复" in (core.validate_rows(dup) or "")
    # 任务参数不是 JSON：模板路径必须是真实存在的文件，否则先撞上路径校验。
    bad_args = core.SiteRow(
        name="a", base_url="https://a.com", checkin_action="script", auth_method="browser_state",
        script="scripts/tasks/jisudeng.py", script_args_text="not json",
    )
    assert "JSON" in (core.validate_rows([bad_args]) or "")
    ok = core.SiteRow(name="a", base_url="https://a.com", type="newapi")
    assert core.validate_rows([ok]) is None


def test_validate_rows_checks_script_path_exists() -> None:
    """路径写错要在保存时就拦住：签到跑在后台，隔很久才会被看到。"""
    missing = core.SiteRow(
        name="a", base_url="https://a.com", checkin_action="browser_script", auth_method="browser",
        script="scripts/checkin/nope.py",
    )
    assert "不存在" in (core.validate_rows([missing]) or "")

    escaping = core.SiteRow(
        name="a", base_url="https://a.com", checkin_action="browser_script", auth_method="browser",
        script="/etc/passwd",
    )
    assert core.validate_rows([escaping]) is not None


def test_template_path_is_optional_but_validated() -> None:
    """内置模板不需要脚本路径；写了就必须指向真实存在的模板文件。"""
    blank = core.SiteRow(name="a", base_url="https://a.com", type="newapi", checkin_action="http_api")
    assert core.validate_rows([blank]) is None

    missing = core.SiteRow(
        name="a", base_url="https://a.com", checkin_action="script", script="scripts/tasks/nope.py"
    )
    assert core.validate_rows([missing]) is not None


def test_form_plan_always_offers_template_and_args() -> None:
    """模板路径与任务参数对所有任务方式都开放。

    旧模型里 ``script_args`` 只传给浏览器脚本，纯 HTTP 钩子拿不到，于是「每日口令」
    这类参数无处安放。新模型里参数由模板的 ArgSchema 声明，跟任务方式无关。
    """
    plan = core.build_form_plan(
        core.SiteRow(name="s", base_url="https://a.com", type="newapi", checkin_action="http_api"), {}
    )
    assert plan.show_script and plan.show_script_args and plan.show_script_timeout
    assert plan.script_hint == core.SCRIPT_HINT_API


def test_persist_accounts_shapes() -> None:
    """表单行 → v3 账号：模板、任务、凭据、网络各归各位。"""
    rows = [
        core.SiteRow(
            name="script-site",
            base_url="https://a.com",
            auth_method="browser_state",
            checkin_action="script",
            script="scripts/tasks/100xlabs.py",
            script_args_text='{"a": 1}',
            browser_state="ST",
            verify_ssl=False,
        ),
        core.SiteRow(
            name="api-site",
            base_url="https://b.com",
            type="newapi",
            checkin_action="http_api",
            verification_mode="string_captcha",
        ),
        core.SiteRow(
            name="relogin-site", base_url="https://c.com", checkin_action="relogin", auth_method="cookie"
        ),
    ]
    script_site, api_site, relogin = core.persist_accounts(rows)

    assert script_site["template"] == "scripts/tasks/100xlabs.py"
    assert script_site["tasks"][0]["args"] == {"a": 1}
    assert script_site["credentials"]["browser_state"] == "ST"
    assert script_site["network"]["verify_ssl"] is False

    assert api_site["template"] == "newapi"
    assert api_site["flow"] == {"verification": "string_captcha"}

    assert relogin["login"]["method"] == "oauth", "relogin 的登录方式被矫正"
    assert relogin["tasks"][0]["method"] == "relogin"
    assert "flow" not in relogin, "auto 的验证机制不写进配置，避免噪声键"


def test_config_snapshot_stable_and_sensitive_to_changes() -> None:
    rows = [core.SiteRow(name="a", base_url="https://a.com")]
    snap1 = core.config_snapshot(rows, {})
    snap2 = core.config_snapshot([r.copy() for r in rows], {})
    assert snap1 == snap2
    rows[0].cookie = "changed"
    assert core.config_snapshot(rows, {}) != snap1


# ── 剪贴板 / 格式化 ──────────────────────────────────────────────────────────
def test_parse_clipboard_site_variants() -> None:
    data, err = core.parse_clipboard_site('{"name": "x", "base_url": "https://a.com"}')
    assert err == "" and data["name"] == "x"
    data, err = core.parse_clipboard_site('[{"name": "x"}]')
    assert err == "" and data["name"] == "x"
    data, err = core.parse_clipboard_site('{"wrapped": {"cookie": "c"}}')
    assert err == "" and data["name"] == "wrapped" and data["cookie"] == "c"
    _, err = core.parse_clipboard_site("not json")
    assert err
    _, err = core.parse_clipboard_site("")
    assert err


def test_parse_clipboard_extracts_tokens_from_localstorage_json() -> None:
    payload = {
        "channel-status-auto-refresh": '{"enabled":true}',
        "auth_token": "eyJ.test.\n signature",
        "refresh_token": "rt_keep",
        "auth_user": '{"id":19653}',
    }

    data, err = core.parse_clipboard_site(json.dumps(payload))

    assert err == ""
    assert data["access_token"] == "eyJ.test.signature"
    assert data["refresh_token"] == "rt_keep"


def test_parse_clipboard_recursively_extracts_aliases_from_nested_json_strings() -> None:
    nested = json.dumps({"AUTH-TOKEN": " access.value ", "rtToken": "rt_nested"})
    payload = {"storage": [{"localStorage": nested}]}

    data, err = core.parse_clipboard_site(json.dumps(payload))

    assert err == ""
    assert data["access_token"] == "access.value"
    assert data["refresh_token"] == "rt_nested"


def test_parse_clipboard_keeps_explicit_standard_tokens_over_aliases() -> None:
    payload = {
        "access_token": "explicit_access",
        "refresh_token": "explicit_refresh",
        "nested": {"auth_token": "fallback_access", "rt_token": "fallback_refresh"},
    }

    data, err = core.parse_clipboard_site(json.dumps(payload))

    assert err == ""
    assert data["access_token"] == "explicit_access"
    assert data["refresh_token"] == "explicit_refresh"


def test_parse_clipboard_extracts_tokens_when_json_root_is_encoded_string() -> None:
    text = json.dumps(json.dumps({"authToken": "access", "rt_token": "refresh"}))

    data, err = core.parse_clipboard_site(text)

    assert err == ""
    assert data == {"access_token": "access", "refresh_token": "refresh"}


def test_merge_clipboard_site_translates_legacy_vocabulary() -> None:
    """collector.js 仍在用旧词表，粘贴时必须翻译成新模型。

    用户不该为了粘一份凭据先去升级浏览器书签里的采集脚本。
    """
    original = core.SiteRow(
        name="old",
        base_url="https://old.invalid",
        type="newapi",
        auth_method="cookie",
        checkin_action="http_api",
        runtime_id="stable-row",
        referer_path="/custom",
    )
    collector_data = {
        "name": "Sub2 channel",
        "base_url": "https://sub.invalid/",
        "site_profile": "sub2api",
        "auth_method": "browser",
        "checkin_action": "browser_script",
        "oauth_provider": "github",
        "oauth_account": "work",
        "script": "scripts/checkin/100xlabs.py",
        "access_token": "a.b.c",
        "refresh_token": "refresh",
        "enabled": False,
    }

    merged = core.merge_clipboard_site(original, collector_data)

    assert merged.runtime_id == "stable-row", "GUI 身份不随粘贴改变"
    assert merged.auth_method == "browser_state", "browser → browser_state"
    assert merged.checkin_action == "script", "browser_script → script"
    assert merged.script == "scripts/tasks/100xlabs.py", "脚本目录已改名"
    assert merged.oauth_provider == "github" and merged.oauth_account == "work"
    assert merged.access_token == "a.b.c" and merged.refresh_token == "refresh"
    assert merged.enabled is False
    assert merged.referer_path == "/custom", "未导入的字段保持原值"


def test_merge_clipboard_site_accepts_legacy_type_field() -> None:
    original = core.SiteRow(name="old", base_url="https://old.invalid")

    merged = core.merge_clipboard_site(original, {"type": "sub2api", "access_token": "a.b.c"})

    assert merged.type == "sub2api"
    assert merged.access_token == "a.b.c"


def test_format_usd_and_detail_quota() -> None:
    assert core.format_usd(246.1) == "$246.10"
    assert core.format_usd(0.004) == "$0.0040"
    assert core.detail_quota_usd({"current_quota": 500000}) == 1.0
    assert core.detail_quota_usd({"current_quota": 2.5, "quota_is_usd": True}) == 2.5
    assert core.detail_quota_usd({"current_quota": "n/a"}) is None
    assert core.detail_quota_usd(None) is None


# ── StatusStore ──────────────────────────────────────────────────────────────
def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_status_store_merges_by_saved_at(tmp_path: Path) -> None:
    today = time_utils.business_date()
    _write(
        tmp_path / "checkin_result.json",
        {
            "generated_at": time_utils.utc_iso(),
            "business_date": today,
            "results": [
                {"site": "a", "base_url": "https://a.com", "status": "success", "current_quota": "$5.0"},
                {"site": "b", "base_url": "https://b.com", "status": "need_login", "current_quota": "$9.9"},
            ],
        },
    )
    now = time_utils.utc_now()
    _write(
        tmp_path / "gui_status_cache.json",
        {
            "entries": {
                # 更新的手动查询应覆盖批量结果
                "https://a.com|a": {
                    "quota_usd": 7.5, "checked_in": False, "ok": True, "status": "success",
                    "message": "",
                    "saved_at": time_utils.utc_iso(now + timedelta(minutes=5)),
                    "business_date": today,
                },
                # 更旧的条目不应覆盖
                "https://b.com|b": {
                    "quota_usd": 1.0, "checked_in": True, "ok": True, "status": "success",
                    "message": "",
                    "saved_at": time_utils.utc_iso(now - timedelta(minutes=5)),
                    "business_date": today,
                },
            }
        },
    )
    store = core.StatusStore(results_dir=tmp_path)
    store.load()
    a = store.get("https://a.com|a")
    assert a["quota_usd"] == 7.5 and a["checked_in"] is False
    b = store.get("https://b.com|b")
    assert b["status"] == "need_login" and b["quota_usd"] is None and b["last_quota_usd"] == 9.9


def test_status_store_merge_compares_across_timezones(tmp_path: Path) -> None:
    """CI 写 +08:00、GUI 写 UTC 时，字符串比较会得出错误的先后顺序。"""
    today = time_utils.business_date()
    _write(
        tmp_path / "checkin_result.json",
        {
            # UTC 02:00 == 北京 10:00，比下面的 09:00+08:00 更新
            "generated_at": f"{today}T02:00:00Z",
            "business_date": today,
            "results": [
                {"site": "a", "base_url": "https://a.com", "status": "success", "current_quota": "$5.0"},
            ],
        },
    )
    _write(
        tmp_path / "gui_status_cache.json",
        {
            "entries": {
                "https://a.com|a": {
                    "quota_usd": 7.5, "checked_in": False, "ok": True, "status": "success",
                    "message": "", "saved_at": f"{today}T09:00:00+08:00", "business_date": today,
                }
            }
        },
    )
    store = core.StatusStore(results_dir=tmp_path)
    store.load()
    # GUI 条目其实更旧，字符串比较会误判成更新
    assert store.get("https://a.com|a")["quota_usd"] == 5.0


def test_status_store_expires_yesterday_entries(tmp_path: Path) -> None:
    """昨日的「今日已签到」不得继续作为今日状态显示。"""
    yesterday = (time_utils.utc_now() - timedelta(days=1)).isoformat(timespec="seconds")
    _write(
        tmp_path / "checkin_result.json",
        {
            "generated_at": yesterday,
            "results": [
                {"site": "a", "base_url": "https://a.com", "status": "success", "current_quota": "$5.0"},
            ],
        },
    )
    _write(
        tmp_path / "gui_status_cache.json",
        {
            "entries": {
                "https://b.com|b": {
                    "quota_usd": 3.0, "checked_in": True, "ok": True, "status": "already_done",
                    "message": "", "saved_at": yesterday,
                }
            }
        },
    )
    store = core.StatusStore(results_dir=tmp_path)
    store.load()
    assert store.get("https://a.com|a") is None
    assert store.get("https://b.com|b") is None


def test_status_store_drops_unparsable_timestamps(tmp_path: Path) -> None:
    _write(
        tmp_path / "gui_status_cache.json",
        {
            "entries": {
                "https://a.com|a": {
                    "quota_usd": 3.0, "checked_in": True, "ok": True, "status": "success",
                    "message": "", "saved_at": "not-a-timestamp",
                }
            }
        },
    )
    store = core.StatusStore(results_dir=tmp_path)
    store.load()
    assert store.get("https://a.com|a") is None


def test_status_store_prunes_expired_entries_on_save(tmp_path: Path) -> None:
    store = core.StatusStore(results_dir=tmp_path)
    store.apply_query("fresh", {"ok": True, "quota_usd": 1.0, "status": "success", "message": "m"})
    store.entries["stale"] = {
        "quota_usd": 9.0,
        "last_quota_usd": 9.0,
        "checked_in": True,
        "ok": True,
        "status": "already_done",
        "message": "",
        "saved_at": (time_utils.utc_now() - timedelta(days=2)).isoformat(timespec="seconds"),
    }
    store.save()

    payload = json.loads((tmp_path / "gui_status_cache.json").read_text(encoding="utf-8"))
    assert "fresh" in payload["entries"]
    assert "stale" not in payload["entries"]


def test_status_store_apply_query_keeps_last_quota_on_failure(tmp_path: Path) -> None:
    store = core.StatusStore(results_dir=tmp_path)
    store.apply_query("k", {"ok": True, "quota_usd": 3.0, "checked_in": True, "status": "success", "message": "m"})
    entry = store.apply_query("k", {"ok": False, "status": "need_login", "message": "expired"})
    assert entry["quota_usd"] is None
    assert entry["last_quota_usd"] == 3.0
    # 落盘 + 重载后仍可读回
    store2 = core.StatusStore(results_dir=tmp_path)
    store2.load()
    assert store2.get("k")["last_quota_usd"] == 3.0


def test_status_store_apply_checkin_extracts_detail_quota(tmp_path: Path) -> None:
    store = core.StatusStore(results_dir=tmp_path)
    entry = store.apply_checkin("k", {"status": "success", "detail": {"current_quota": 1000000}})
    assert entry["quota_usd"] == 2.0 and entry["checked_in"] is True
    entry = store.apply_checkin("k", {"status": "need_verification", "message": "ts"})
    assert entry["checked_in"] is None and entry["last_quota_usd"] == 2.0


def test_status_store_can_defer_writes_for_gui_queue(tmp_path: Path) -> None:
    store = core.StatusStore(results_dir=tmp_path, autosave=False)

    store.apply_query("k", {"ok": True, "quota_usd": 3.0, "status": "success"})

    path = tmp_path / "gui_status_cache.json"
    assert not path.exists()
    core.StatusStore.write_payload(tmp_path, store.snapshot_payload())
    assert json.loads(path.read_text(encoding="utf-8"))["entries"]["k"]["quota_usd"] == 3.0


def test_status_store_merges_concurrent_gui_snapshots(tmp_path: Path) -> None:
    today = time_utils.business_date()
    now = time_utils.utc_now()

    def entry(quota: float, minutes: int) -> dict:
        return {
            "quota_usd": quota,
            "last_quota_usd": quota,
            "checked_in": True,
            "ok": True,
            "status": "success",
            "message": "",
            "saved_at": time_utils.utc_iso(now + timedelta(minutes=minutes)),
            "business_date": today,
        }

    core.StatusStore.write_payload(
        tmp_path,
        {"business_date": today, "entries": {"shared": entry(9.0, 5), "first": entry(1.0, 0)}},
    )
    # 第二个 GUI 带着陈旧 shared 快照写盘时，不得覆盖第一个 GUI 的更新。
    core.StatusStore.write_payload(
        tmp_path,
        {"business_date": today, "entries": {"shared": entry(2.0, -5), "second": entry(2.0, 1)}},
    )

    entries = json.loads((tmp_path / "gui_status_cache.json").read_text(encoding="utf-8"))["entries"]
    assert entries["shared"]["quota_usd"] == 9.0
    assert {"first", "second"} <= entries.keys()


def test_status_store_rolls_over_while_gui_stays_open(tmp_path: Path, monkeypatch) -> None:
    day = {"value": "2099-01-01"}
    monkeypatch.setattr(time_utils, "business_date", lambda: day["value"])
    store = core.StatusStore(results_dir=tmp_path, autosave=False)
    store.apply_query("old", {"ok": True, "quota_usd": 1.0, "status": "success"})

    day["value"] = "2099-01-02"

    assert store.get("old") is None
    assert store.today == "2099-01-02"


def test_config_save_request_freezes_mutable_gui_state() -> None:
    """保存请求必须是快照：提交后再改表单，不能影响已排队的那次写盘。"""
    row = core.SiteRow(
        account_id="s", name="before", base_url="https://site.invalid", access_token="old-token"
    )
    oauth_states = _mk_states(state="old-state")
    previous = core.credential_snapshots([row])
    request = config_store.build_save_request([row], oauth_states, previous)

    row.name = "after"
    row.access_token = "new-token"
    oauth_states["linuxdo"]["accounts"]["default"]["state"] = "new-state"

    assert request.accounts[0]["name"] == "before"
    assert request.accounts[0]["credentials"]["access_token"] == "old-token"
    assert request.oauth_states["linuxdo"]["accounts"]["default"]["state"] == "old-state"


def test_summarize(tmp_path: Path) -> None:
    store = core.StatusStore(results_dir=tmp_path)
    rows = [
        core.SiteRow(name="a", base_url="https://a.com"),
        core.SiteRow(name="b", base_url="https://b.com", enabled=False),
    ]
    store.apply_query(core.StatusStore.status_key(rows[0]), {"ok": True, "quota_usd": 4.0, "checked_in": True})
    store.apply_query(core.StatusStore.status_key(rows[1]), {"ok": False, "status": "need_login"})
    stats = core.summarize(rows, store)
    assert stats.total == 2 and stats.enabled == 1
    assert stats.done == 1 and stats.failed == 1
    assert stats.quota_sum == 4.0 and stats.quota_known == 1


# ── 脱敏日志 ─────────────────────────────────────────────────────────────────
def test_safe_log_value_redacts_sensitive_keys() -> None:
    assert "redacted" in core._safe_log_value("secret-token-value", "access_token")
    nested = core._safe_log_value({"cookie": "abc", "plain": "ok"}, "result")
    assert "abc" not in nested and "ok" in nested


def test_log_sink_receives_lines() -> None:
    lines: list[str] = []
    core.add_log_sink(lines.append)
    try:
        core.bg_log("INFO", "hello", site="x")
    finally:
        core.remove_log_sink(lines.append)
    assert lines and "hello" in lines[0] and "site=x" in lines[0]


# ── 接口凭据可编辑性 / token 健康度 ──────────────────────────────────────────
def test_sub2api_token_inputs_editable_under_browser_auth() -> None:
    """sub2api 即使用 browser 登录态，签到仍先走纯 API，故 token 框必须可编辑。

    回归：此前 token 框跟随 creds_enabled（只在 access_token/cookie 时启用），
    导致 auth_method=browser 的 sub2api 站点无法手填 token，表现为「填了仍显示没有」。
    """
    row = core.SiteRow(
        name="s", base_url="https://s.invalid", type="sub2api",
        auth_method="browser", checkin_action="browser_script", script="x.js",
    )
    plan = core.build_form_plan(row, {})
    assert plan.creds_enabled is False          # cookie/uid 仍按登录方式灰掉
    assert plan.token_enabled is True           # 但接口凭据必须可填
    assert plan.show_refresh_input is True


def test_newapi_cookie_auth_keeps_token_enabled() -> None:
    row = core.SiteRow(name="n", base_url="https://n.invalid", type="newapi", auth_method="cookie")
    plan = core.build_form_plan(row, {})
    assert plan.token_enabled is True
    assert plan.show_refresh_input is False     # refresh_token 只对 sub2api 有意义


def test_newapi_browser_auth_disables_token() -> None:
    row = core.SiteRow(name="n", base_url="https://n.invalid", type="newapi", auth_method="browser")
    plan = core.build_form_plan(row, {})
    assert plan.token_enabled is False


def test_token_defect_flags_non_ascii_ellipsis() -> None:
    """从截断显示里复制的 token 带 U+2026，运行时被静默判为空，必须提示。"""
    msg = core.token_defect("eyJhbGciOi\u2026Q1NH0.xCpdND.sig")
    assert "U+2026" in msg


def test_token_defect_flags_placeholder_and_shape() -> None:
    assert "占位" in core.token_defect("<在站点后台采集的 access_token>")
    assert "JWT" in core.token_defect("abcdef")


def test_token_defect_accepts_valid_jwt_with_prefix() -> None:
    assert core.token_defect("Bearer aaa.bbb.ccc") == ""
    assert core.token_defect("aaa.bbb.ccc") == ""
    assert core.token_defect("") == ""
    assert core.token_defect("   ") == ""


def test_refresh_status_surfaces_defect_before_refresh_hint() -> None:
    row = core.SiteRow(
        name="s", base_url="https://s.invalid", type="sub2api",
        access_token="aa\u2026bb.cc.dd", refresh_token="rt_x",
    )
    plan = core.build_form_plan(row, {})
    assert plan.refresh_status.startswith("\u26a0")
    assert "已保存 refresh_token" in plan.refresh_status


def test_cred_json_roundtrip_includes_refresh_token() -> None:
    """复制凭据 → 剪贴板导入必须往返一致，漏掉 refresh_token 会丢长期凭据。"""
    row = core.SiteRow(
        name="s", base_url="https://s.invalid", type="sub2api",
        access_token="aa.bb.cc", refresh_token="rt_keep",
    )
    data, err = core.parse_clipboard_site(core.cred_json(row))
    assert err == ""
    assert data["access_token"] == "aa.bb.cc"
    assert data["refresh_token"] == "rt_keep"


# ── 配置字段往返（GUI 保存不得丢字段）────────────────────────────────────────
def test_non_default_fields_survive_roundtrip() -> None:
    """用户改过的每一项都必须能从 GUI 往返落盘。

    旧实现漏掉了 cookie_file / referer_path 这类 GUI 不展示的字段，保存一次就静默
    抹掉用户手写的值。新模型用 ``extras`` 兜住所有解析器不认识的键。
    """
    original = {
        "id": "s",
        "name": "s",
        "base_url": "https://s.invalid",
        "template": "newapi",
        "login": {"method": "cookie"},
        "tasks": [{"id": "daily", "method": "http_api", "timeout": 90}],
        "network": {"referer_path": "/console", "proxy": "http://p.invalid:8080", "verify_ssl": False},
        "policy": {"tolerate_failure": True},
        "credentials": {"cookie": "c=1"},
    }
    row = core.row_from_account(schema.parse_account(original))
    saved = core.persist_accounts([row])[0]

    assert saved["network"]["referer_path"] == "/console"
    assert saved["network"]["proxy"] == "http://p.invalid:8080"
    assert saved["network"]["verify_ssl"] is False
    assert saved["policy"]["tolerate_failure"] is True
    assert saved["tasks"][0]["timeout"] == 90
    assert saved["credentials"]["cookie"] == "c=1"


def test_default_values_do_not_add_noise_keys() -> None:
    """等于默认值时不落盘，避免给每个账号塞进一堆冗余键。"""
    row = core.row_from_account(
        schema.parse_account(
            {"id": "s", "name": "s", "base_url": "https://s.invalid", "template": "newapi",
             "login": {"method": "cookie"}, "tasks": [{"id": "daily"}]}
        )
    )
    saved = core.persist_accounts([row])[0]
    assert "network" not in saved, "默认网络参数不写盘"
    assert "policy" not in saved
    assert "flow" not in saved
    assert saved["tasks"][0] == {"id": "daily"}, "任务默认值同样不该产生噪声键"


def test_task_params_matches_what_the_batch_worker_reads() -> None:
    """GUI 内单站执行必须与批量/CI 读到同一份账号。"""
    original = {
        "id": "s",
        "name": "s",
        "base_url": "https://s.invalid",
        "template": "newapi",
        "login": {"method": "cookie", "args": {"user_id": "42"}},
        "tasks": [{"id": "daily", "method": "http_api"}],
        "network": {"referer_path": "/console"},
    }
    row = core.row_from_account(schema.parse_account(original))
    params = core.task_params(row, {})

    assert params["network"]["referer_path"] == "/console"
    assert params["login"]["args"]["user_id"] == "42"

    spec = schema.parse_account({k: v for k, v in params.items() if not k.startswith("_")})
    assert spec.network.referer_path == "/console"
    assert dict(spec.login.args)["user_id"] == "42"


def test_task_params_marks_only_changed_credentials_explicit() -> None:
    row = core.SiteRow(
        name="s",
        base_url="https://s.invalid",
        access_token="NEW",
        refresh_token="RT",
        browser_state="STATE",
    )
    saved = {
        "name": "s",
        "base_url": "https://s.invalid",
        "access_token": "OLD",
        "refresh_token": "RT",
        "browser_state": "STATE",
    }

    changed = core.changed_credential_fields(row, saved)
    params = core.task_params(row, {}, explicit_credential_fields=changed)

    assert changed == {"access_token"}
    assert params["_explicit_credential_fields"] == ["access_token"]


def test_changed_credentials_detects_explicit_clear() -> None:
    row = core.SiteRow(name="s", base_url="https://s.invalid", browser_state="")
    saved = {
        "name": "s",
        "base_url": "https://s.invalid",
        "access_token": "",
        "refresh_token": "",
        "browser_state": "OLD-STATE",
    }
    assert core.changed_credential_fields(row, saved) == {"browser_state"}


def test_unrelated_save_does_not_touch_the_overlay(tmp_path: Path, monkeypatch) -> None:
    """只改了名字/顺序时，运行期凭据不该被标记为「配置已变」。

    标记会让下次运行不再使用缓存的 token 与登录态，等于白跑一次 Turnstile / OAuth。
    """
    from config.overlay import Overlay

    overlay = Overlay(path=tmp_path / "overlay.json").load()
    row = core.SiteRow(
        account_id="s", name="s", base_url="https://s.invalid", access_token="tok"
    )
    saved = core.credential_snapshots([row])
    row.name = "改了名字"

    monkeypatch.setattr("gui.core._Overlay", lambda *a, **k: overlay)
    assert core.apply_credential_cache_changes([row], saved) == 0


def test_credential_edit_is_reported_without_touching_the_cache(tmp_path: Path) -> None:
    """改凭据只在提示里报个数，不删也不改运行期缓存。

    删除不可逆：用户改错又改回来、或只是重排，本来仍然有效的运行期 token 与登录态
    就被永久丢掉，下次运行必须重跑一遍 Turnstile / OAuth。「配置变了要不要用缓存」
    由覆盖层在读取时按配置摘要判断（见 config/overlay.py 规则 4），不需要事件式标记。
    """
    from config.overlay import Overlay

    path = tmp_path / "overlay.json"
    overlay = Overlay(path=path).load()
    overlay.record_credentials(
        _spec_for("s", "https://s.invalid", access_token="tok"), access_token="runtime-token"
    )

    row = core.SiteRow(account_id="s", name="s", base_url="https://s.invalid", access_token="tok")
    saved = core.credential_snapshots([row])
    row.access_token = "new-token"

    assert core.apply_credential_cache_changes([row], saved) == 1
    kept = Overlay(path=path).load().entry("s")
    assert kept.fields, "缓存值必须还在：判定发生在读取侧，不靠删除"


def _spec_for(account_id: str, base_url: str, **credentials):
    return schema.parse_account(
        {
            "id": account_id,
            "name": account_id,
            "base_url": base_url,
            "credentials": dict(credentials),
            "tasks": [{"id": "daily"}],
        }
    )


def _spec_for(account_id: str, base_url: str, **credentials):
    return schema.parse_account(
        {
            "id": account_id,
            "name": account_id,
            "base_url": base_url,
            "credentials": dict(credentials),
            "tasks": [{"id": "daily"}],
        }
    )


def test_changed_token_is_not_applied_although_cache_kept(tmp_path: Path) -> None:
    """留着缓存不等于会被用上：配置摘要对不上时读取侧必须拒绝应用。"""
    from config.overlay import Overlay

    path = tmp_path / "overlay.json"
    Overlay(path=path).load().record_credentials(
        _spec_for("s", "https://s.invalid", access_token="tok"), access_token="runtime-token"
    )

    # 用户换了配置里的 token：运行期缓存仍在文件里，但不该再被应用。
    new_spec = _spec_for("s", "https://s.invalid", access_token="brand-new")
    resolved = Overlay(path=path).load().apply(new_spec)
    assert resolved.credentials.access_token == "brand-new"


