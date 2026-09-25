"""访问链：配置解析与校验、失败回退执行、模板步骤拆分、兼容旧入口。

全部离线：HTTP 走回放替身，浏览器是不启动任何进程的假服务，模板是临时注册的假模板
或把页面流程打桩后的真实模板。断言的是编排语义：

- 某一步成功（含今日已完成 / 未开放）即止，只有失败才回退；
- 终局失败（已向服务端提交过）不回退，避免重复提交；
- HTTP 步骤只在自己列出的凭据来源里续期（AT 失效 → RT 刷新），续期写进步骤明细；
- 浏览器不可用时报告前一步的真实失败，而不是一句「缺浏览器」；
- 没配置 chain 的任务行为不变，未知键原样往返。
"""

from __future__ import annotations

import asyncio
import importlib
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from config import schema
from config.overlay import Overlay
from core import chain as chain_module
from core.chain import ChainStep, parse_chain
from core.errors import ConfigError, LoginRequired, TaskError
from core.manifest import LoginOption, TaskOption, TemplateManifest
from core.outcome import Verdict, already_done, failed, no_effect, success
from gui import core as gui_core
from net import http as net_http
from runtime import engine
from templates import registry as templates


# ── 测试替身 ────────────────────────────────────────────────────────────────
class ReplaySite:
    """按 (method, path) 回放；值可以是可调用对象，用来按请求头给出不同回执。"""

    def __init__(self, routes: dict[tuple[str, str], Any]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str, str]] = []

    def send(self, client, method, path, **_kwargs):
        key = (method.upper(), path.split("?")[0])
        self.calls.append((*key, str(client.headers.get("Authorization") or "")))
        value = self.routes.get(key)
        if callable(value):
            value = value(client)
        if value is None:
            raise net_http.TaskError("not found", status=404, payload={"message": "404 not found"})
        if isinstance(value, BaseException):
            raise value
        return net_http.unwrap_data(value)


@pytest.fixture
def site(monkeypatch):
    def install(routes: dict[tuple[str, str], Any]) -> ReplaySite:
        fake = ReplaySite(routes)
        monkeypatch.setattr(net_http.HttpClient, "_send", lambda self, method, path, **kw: fake.send(self, method, path, **kw))
        return fake

    return install


class FakeLease:
    def __init__(self) -> None:
        self.page = SimpleNamespace(url="about:blank")
        self.context = SimpleNamespace()
        self.new_page = AsyncMock(return_value=self.page)
        self.mark_authenticated = Mock()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


class FakeBrowser:
    """不启动任何进程的浏览器服务：只记录租约。"""

    def __init__(self) -> None:
        self.leases: list[str] = []
        self.started = False

    def lease(self, *, reason: str = "", state_text: str = ""):
        self.leases.append(reason)
        return FakeLease()

    def note_outcome(self, _outcome) -> None:
        return None

    async def aclose(self) -> None:
        return None


@pytest.fixture
def browser(monkeypatch):
    """让引擎认为浏览器可用，并换成假服务。"""
    fake = FakeBrowser()
    monkeypatch.setattr(engine.caps_module, "detect", lambda account=None: frozenset({"browser"}) if (
        getattr(getattr(account, "policy", None), "allow_browser", True)) else frozenset())
    monkeypatch.setattr(engine, "_make_browser", lambda *args, **kwargs: fake)
    return fake


@pytest.fixture
def no_browser(monkeypatch):
    monkeypatch.setattr(engine.caps_module, "detect", lambda account=None: frozenset())


def fake_template(monkeypatch, *, http=None, browser=None, run=None, chain=None, login=None):
    """注册一个临时模板；步骤钩子返回给定结论（或按调用次数取序列）。"""
    calls: dict[str, int] = {"run_http": 0, "run_browser": 0, "run": 0}

    def hook(name, value):
        async def _hook(ctx):
            calls[name] += 1
            result = value(ctx) if callable(value) else value
            if isinstance(result, BaseException):
                raise result
            return result

        return _hook

    manifest = TemplateManifest(
        id="fake-chain",
        title="假模板",
        login=tuple(login or (LoginOption("access_token", priority=10), LoginOption("refresh", priority=20))),
        task=(TaskOption("script", priority=10),),
        endpoints={"refresh": "/api/v1/auth/refresh", "user": "/api/v1/user/profile"},
        chain=tuple(chain if chain is not None else (
            ChainStep("http", "http", title="HTTP", login=("access_token", "refresh")),
            ChainStep("browser", "browser", title="浏览器", login=("browser_state", "password")),
        )),
    )
    hooks = {"run": hook("run", run if run is not None else success("原流程"))}
    if http is not None:
        hooks["run_http"] = hook("run_http", http)
    if browser is not None:
        hooks["run_browser"] = hook("run_browser", browser)
    loaded = templates.LoadedTemplate(manifest=manifest, source="test", hooks=MappingProxyType(hooks))
    # 注册表带 __slots__，不能替换实例方法；走公开的 register()，测试结束时撤掉。
    templates.REGISTRY.register(loaded, replace_existing=True)
    _REGISTERED.append(loaded.id)
    return calls


_REGISTERED: list[str] = []


@pytest.fixture(autouse=True)
def _unregister_fake_templates():
    yield
    while _REGISTERED:
        templates.REGISTRY._cache.pop(_REGISTERED.pop(), None)


def account(*, chain: Any = ..., credentials=None, policy=None, **extra):
    task: dict[str, Any] = {"id": "daily", "method": "script"}
    if chain is not ...:
        task["chain"] = chain
    payload = {
        "id": "demo",
        "name": "演示站",
        "base_url": "https://demo.invalid",
        "template": "fake-chain",
        "credentials": credentials if credentials is not None else {"access_token": "a.b.c"},
        "tasks": [task],
        **extra,
    }
    if policy is not None:
        payload["policy"] = policy
    return schema.parse_account(payload)


def run(spec, tmp_path):
    return asyncio.run(engine.run_account(spec, overlay=Overlay(path=tmp_path / "o.json").load(), structured=False))


def steps(record) -> list[dict]:
    return list(record.outcome.data["chain"]["steps"])


# ── 解析与校验 ───────────────────────────────────────────────────────────────
def test_missing_chain_keeps_legacy_flow() -> None:
    assert parse_chain(None, label="t") is None
    assert account().tasks[0].chain is None


def test_template_chain_and_custom_chain_parse_with_implicit_order() -> None:
    template = parse_chain({"use": "template"}, label="t")
    assert template.use == "template" and template.steps == ()

    custom = parse_chain({"steps": [
        {"id": "http", "kind": "HTTP", "login": ["Access_Token", "refresh"]},
        {"id": "browser", "kind": "browser", "timeout": 90, "args": {"start_path": "/x"}},
    ]}, label="t")
    assert custom.use == "custom", "只写 steps 时就是自定义链"
    resolved = chain_module.resolve(custom, TemplateManifest(id="x"))
    assert [step.id for step in resolved.order()] == ["http", "browser"]
    assert resolved.step("http").login == ("access_token", "refresh")
    assert resolved.step("browser").timeout == 90


@pytest.mark.parametrize(("raw", "fragment"), [
    ([], "必须是对象"),
    ({"use": "sometimes"}, "只能是 template 或 custom"),
    ({"use": "template", "steps": [{"id": "a", "kind": "http"}]}, "不能同时写 steps"),
    ({"use": "custom"}, "非空数组"),
    ({"steps": [{"id": "a", "kind": "ftp"}]}, "kind 只能是"),
    ({"steps": [{"id": "", "kind": "http"}]}, ".id 必须"),
    ({"steps": [{"id": "a", "kind": "http"}, {"id": "a", "kind": "browser"}]}, "重复的步骤 id"),
    ({"steps": [{"id": "a", "kind": "http", "on_failure": "zz"}]}, "不存在的步骤"),
    ({"steps": [{"id": "a", "kind": "http", "on_failure": "a"}]}, "不能回退到自己"),
    ({"steps": [{"id": "a", "kind": "http", "on_failure": "b"},
                {"id": "b", "kind": "browser", "on_failure": "a"}]}, "形成循环"),
    ({"entry": "zz", "steps": [{"id": "a", "kind": "http"}]}, "入口步骤 zz 不存在"),
    ({"steps": [{"id": "a", "kind": "http", "timeout": 0}]}, "timeout"),
    ({"steps": [{"id": "a", "kind": "http", "timeout": True}]}, "timeout"),
    ({"steps": [{"id": "a", "kind": "http", "login": ["x y"]}]}, "login"),
    ({"steps": [{"id": "a", "kind": "http", "login": ["refresh", "refresh"]}]}, "重复项"),
    ({"steps": [{"id": "a", "kind": "http", "args": []}]}, "args 必须是对象"),
    ({"steps": [{"id": "a", "kind": "http"}], "layout": []}, "layout 必须是对象"),
])
def test_invalid_chain_is_rejected_with_a_field_path(raw, fragment) -> None:
    with pytest.raises(ConfigError, match=fragment):
        parse_chain(raw, label="任务 t")


def test_explicit_fallback_targets_define_order_and_unreachable_steps() -> None:
    spec = parse_chain({"entry": "b", "steps": [
        {"id": "a", "kind": "http", "on_failure": ""},
        {"id": "b", "kind": "http", "on_failure": "c"},
        {"id": "c", "kind": "browser", "on_failure": None},
        {"id": "d", "kind": "browser"},
    ]}, label="t")
    resolved = chain_module.resolve(spec, TemplateManifest(id="x"))
    assert [step.id for step in resolved.order()] == ["b", "c"], "null 与空字符串都表示失败即结束"
    assert resolved.unreachable() == ("a", "d")


def test_chain_roundtrips_unknown_keys_and_layout() -> None:
    raw = {"use": "custom", "future": {"keep": 1}, "layout": {"http": [10, 20]},
           "steps": [{"id": "http", "kind": "http", "note": "自定义备注"}]}
    spec = account(chain=raw)
    dumped = schema.dump_account(spec)["tasks"][0]["chain"]
    assert dumped == raw
    assert schema.parse_account(schema.dump_account(spec)).tasks[0].chain.to_payload() == raw


def test_template_chain_without_declaration_is_a_clear_config_error() -> None:
    with pytest.raises(ConfigError, match="没有声明默认访问链"):
        chain_module.resolve(parse_chain({"use": "template"}, label="t"), TemplateManifest(id="bare"))


def test_gui_validator_reports_chain_errors_at_the_task_path() -> None:
    payload = {"version": 3, "accounts": [{"id": "a", "base_url": "https://a.invalid",
                                           "tasks": [{"id": "daily", "chain": {"use": "nope"}}]}]}
    with pytest.raises(ConfigError, match=r"tasks\[0\]\.chain"):
        gui_core.validate_payload(payload)
    payload["accounts"][0]["tasks"][0]["chain"] = {"use": "template"}
    gui_core.validate_payload(payload)


def test_chain_summary_for_task_list() -> None:
    assert "未使用" in gui_core.chain_summary(None)
    template = [{"id": "http", "kind": "http", "title": "HTTP 签到"}, {"id": "b", "kind": "browser", "title": "浏览器"}]
    assert gui_core.chain_summary({"use": "template"}, template) == "模板默认（HTTP 签到 → 浏览器）"
    assert "未声明默认访问链" in gui_core.chain_summary({"use": "template"}, [])
    custom = {"steps": [{"id": "a", "kind": "http", "on_failure": ""}, {"id": "b", "kind": "browser"}]}
    assert gui_core.chain_summary(custom) == "自定义（HTTP）；1 个步骤不会执行"
    assert gui_core.chain_summary({"use": 3}).startswith("配置有误")


# ── 回退判定 ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(("outcome", "expected"), [
    (success("ok"), False),
    (already_done("done"), False),
    (no_effect("未开放", reason="not_open"), False),
    (failed("x", reason="need_login"), True),
    (failed("x", reason="network_error"), True),
    (failed("x"), True),
    (chain_module.final(failed("x", reason="unconfirmed")), False),
])
def test_should_fallback_only_on_non_final_failure(outcome, expected) -> None:
    step = ChainStep("http", "http")
    assert chain_module.should_fallback(step, outcome) is expected


def test_stop_on_blocks_listed_reasons() -> None:
    step = ChainStep("http", "http", stop_on=("need_config",))
    assert not chain_module.should_fallback(step, failed("缺口令", reason="need_config"))
    assert chain_module.should_fallback(step, failed("失效", reason="need_login"))


def test_strip_control_removes_final_flag_only() -> None:
    marked = chain_module.final(failed("x", data={"k": 1}))
    assert chain_module.is_final(marked)
    clean = chain_module.strip_control(marked)
    assert dict(clean.data) == {"k": 1}


# ── 引擎执行 ────────────────────────────────────────────────────────────────
def test_first_step_success_stops_the_chain(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    calls = fake_template(monkeypatch, http=success("HTTP 签到成功"), browser=success("不应执行"))
    record = run(account(chain={"use": "template"}), tmp_path).records[0]

    assert record.outcome.verdict is Verdict.SUCCESS
    assert calls["run_http"] == 1 and calls["run_browser"] == 0 and calls["run"] == 0
    assert record.outcome.data["chain"]["hit"] == "http"
    assert [item["status"] for item in steps(record)] == ["success", "not_run"]
    assert dict(record.flow) == {"chain": "http=成功"}
    assert browser.leases == [], "HTTP 成功时不启动浏览器"


@pytest.mark.parametrize("first", [already_done("今日已签到"), no_effect("未开放", reason="not_open")])
def test_already_done_and_not_open_also_stop(monkeypatch, tmp_path, browser, site, first) -> None:
    site({})
    calls = fake_template(monkeypatch, http=first, browser=success("不应执行"))
    record = run(account(chain={"use": "template"}), tmp_path).records[0]
    assert record.outcome.verdict is first.verdict
    assert calls["run_browser"] == 0


def test_failure_falls_back_to_browser_and_records_every_step(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    calls = fake_template(
        monkeypatch,
        http=failed("纯 HTTP 签到未完成", reason="need_verification"),
        browser=success("浏览器签到成功"),
    )
    record = run(account(chain={"use": "template"}), tmp_path).records[0]

    assert record.outcome.verdict is Verdict.SUCCESS
    assert calls["run_http"] == 1 and calls["run_browser"] == 1
    first, second = steps(record)
    assert (first["status"], first["reason"]) == ("failed", "need_verification")
    assert second["status"] == "success"
    assert record.outcome.data["chain"]["hit"] == "browser"
    assert record.outcome.data["chain"]["summary"] == "http=失败(need_verification) → browser=成功"


def test_final_failure_never_falls_back(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    calls = fake_template(
        monkeypatch,
        http=chain_module.final(failed("签到未获服务端确认", reason="unconfirmed", data={"checked": 1})),
        browser=success("不应执行"),
    )
    record = run(account(chain={"use": "template"}), tmp_path).records[0]

    assert record.outcome.verdict is Verdict.FAILED and record.outcome.reason == "unconfirmed"
    assert calls["run_browser"] == 0, "已提交过的失败换浏览器只会重复提交"
    assert chain_module.FINAL_FLAG not in record.outcome.data, "控制键不进结果文件"
    assert record.outcome.data["checked"] == 1


def test_all_steps_fail_reports_the_last_failure(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    fake_template(
        monkeypatch,
        http=failed("HTTP 失败", reason="network_error"),
        browser=failed("浏览器登录失败", reason="need_login"),
    )
    record = run(account(chain={"use": "template"}), tmp_path).records[0]
    assert record.outcome.reason == "need_login"
    assert [item["status"] for item in steps(record)] == ["failed", "failed"]
    assert not record.ok


def test_browser_unavailable_reports_the_http_failure(monkeypatch, tmp_path, no_browser, site) -> None:
    site({})
    calls = fake_template(monkeypatch, http=failed("登录失效", reason="need_login"), browser=success("不应执行"))
    record = run(account(chain={"use": "template"}), tmp_path).records[0]

    assert record.outcome.verdict is Verdict.FAILED
    assert record.outcome.reason == "need_login", "用户要处理的是 HTTP 那一步的失败"
    assert "不可用" in record.outcome.message
    assert calls["run_browser"] == 0
    assert [item["status"] for item in steps(record)] == ["failed", "unavailable"]


def test_allow_browser_false_marks_browser_step_unavailable(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    calls = fake_template(monkeypatch, http=failed("x", reason="need_login"), browser=success("不应执行"))
    record = run(account(chain={"use": "template"}, policy={"allow_browser": False}), tmp_path).records[0]
    assert calls["run_browser"] == 0
    assert steps(record)[1]["status"] == "unavailable"


def test_missing_browser_hook_is_unavailable_not_a_crash(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    fake_template(monkeypatch, http=failed("x", reason="need_login"))
    record = run(account(chain={"use": "template"}), tmp_path).records[0]
    assert steps(record)[1]["status"] == "unavailable"
    assert "run_browser" in steps(record)[1]["message"]


def test_step_exception_becomes_that_steps_outcome(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    calls = fake_template(monkeypatch, http=RuntimeError("boom"), browser=success("浏览器兜底"))
    record = run(account(chain={"use": "template"}), tmp_path).records[0]
    assert record.outcome.verdict is Verdict.SUCCESS
    assert "执行异常" in steps(record)[0]["message"]
    assert calls["run_browser"] == 1


def test_custom_chain_order_and_explicit_stop(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    calls = fake_template(monkeypatch, http=success("不应执行"), browser=failed("浏览器失败", reason="need_login"))
    chain = {"entry": "b", "steps": [
        {"id": "h", "kind": "http"},
        {"id": "b", "kind": "browser", "on_failure": ""},
    ]}
    record = run(account(chain=chain), tmp_path).records[0]
    assert calls["run_browser"] == 1 and calls["run_http"] == 0
    assert record.outcome.reason == "need_login"
    assert [item["id"] for item in steps(record)] == ["b", "h"]
    assert steps(record)[1]["status"] == "not_run"


def test_legacy_task_without_chain_is_untouched(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    calls = fake_template(monkeypatch, http=failed("不应执行"), browser=failed("不应执行"), run=success("原流程成功"))
    record = run(account(), tmp_path).records[0]
    assert record.outcome.verdict is Verdict.SUCCESS
    assert calls == {"run_http": 0, "run_browser": 0, "run": 1}
    assert "chain" not in record.outcome.data
    assert "chain" not in dict(record.flow)


def test_step_args_override_task_args(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    seen: dict[str, Any] = {}

    def browser_step(ctx):
        seen.update(dict(ctx.args))
        return success("ok")

    # 假模板没有声明需要浏览器的登录方式：浏览器步骤不写 login 时没有要准备的会话，直接进页面流程。
    fake_template(monkeypatch, http=failed("x", reason="need_login"), browser=browser_step)
    spec = schema.parse_account({
        "id": "demo", "name": "演示站", "base_url": "https://demo.invalid", "template": "fake-chain",
        "credentials": {"access_token": "a.b.c"},
        "tasks": [{"id": "daily", "args": {"start_path": "/task", "keep": 1}, "chain": {"steps": [
            {"id": "h", "kind": "http"},
            {"id": "b", "kind": "browser", "args": {"start_path": "/step"}},
        ]}}],
    })
    run(spec, tmp_path)
    assert seen["start_path"] == "/step" and seen["keep"] == 1
    assert seen["login_fallback"] is False, "登录来源里没有 password：页面流程不自行账密登录"


def test_browser_step_without_snapshot_or_page_login_fails_before_opening_page(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    calls = fake_template(monkeypatch, http=failed("x", reason="need_login"), browser=success("不应执行"))
    chain = {"steps": [{"id": "h", "kind": "http"}, {"id": "b", "kind": "browser", "login": ["browser_state"]}]}
    record = run(account(chain=chain), tmp_path).records[0]
    assert calls["run_browser"] == 0
    assert steps(record)[1]["reason"] == "need_config"
    assert "browser_state" in steps(record)[1]["message"]


def test_step_login_defaults_split_by_step_kind() -> None:
    manifest = templates.get("scripts/tasks/100xlabs.py").manifest
    assert engine._step_login(manifest, ChainStep("h", "http")) == ("access_token", "refresh", "password")
    assert engine._step_login(manifest, ChainStep("b", "browser")) == ("browser_state", "oauth")
    assert engine._step_login(manifest, ChainStep("b", "browser", login=("browser_state", "password"))) == (
        "browser_state",
    ), "password 由页面流程完成，不交给登录方式注册表"


def test_browser_step_with_password_enables_page_login(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    seen: dict[str, Any] = {}

    def browser_step(ctx):
        seen.update(dict(ctx.args))
        return success("ok")

    fake_template(monkeypatch, http=failed("x", reason="need_login"), browser=browser_step)
    record = run(account(chain={"use": "template"}), tmp_path).records[0]
    assert seen["login_fallback"] is True
    assert any("页面流程" in item for item in steps(record)[1]["login"])


def test_http_step_renews_with_refresh_token_and_records_it(monkeypatch, tmp_path, browser, site) -> None:
    """AT 失效 → 本步骤来源内用 RT 续期并重放；续期写进步骤明细，不开浏览器。"""

    def profile(client):
        if client.headers.get("Authorization") == "Bearer fresh.tok.en":
            return {"code": 0, "data": {"id": 1}}
        return LoginRequired("token expired", status=401)

    fake = site({
        ("GET", "/api/v1/user/profile"): profile,
        ("POST", "/api/v1/auth/refresh"): {"code": 0, "data": {"access_token": "fresh.tok.en", "refresh_token": "rt2"}},
    })

    def http_step(ctx):
        ctx.http.get("/api/v1/user/profile")
        return success("接口签到成功")

    calls = fake_template(monkeypatch, http=http_step, browser=success("不应执行"))
    record = run(account(chain={"use": "template"}, credentials={"access_token": "old.tok.en", "refresh_token": "rt1"}),
                 tmp_path).records[0]

    assert record.outcome.verdict is Verdict.SUCCESS
    assert calls["run_browser"] == 0 and browser.leases == []
    assert steps(record)[0]["login"] == ["access_token=成功", "续期：refresh=成功"]
    assert [call[:2] for call in fake.calls] == [
        ("GET", "/api/v1/user/profile"), ("POST", "/api/v1/auth/refresh"), ("GET", "/api/v1/user/profile"),
    ]
    assert fake.calls[-1][2] == "Bearer fresh.tok.en"


def test_http_step_never_renews_outside_its_sources(monkeypatch, tmp_path, browser, site) -> None:
    """HTTP 步骤只列 access_token：AT 失效不会偷偷用 RT 或账密续期，而是失败回退。"""
    fake = site({("GET", "/api/v1/user/profile"): LoginRequired("token expired", status=401),
                 ("POST", "/api/v1/auth/refresh"): {"code": 0, "data": {"access_token": "x.y.z"}}})

    def http_step(ctx):
        ctx.http.get("/api/v1/user/profile")
        return success("不应成功")

    calls = fake_template(
        monkeypatch, http=http_step, browser=success("浏览器兜底"),
        chain=(ChainStep("http", "http", login=("access_token",)), ChainStep("browser", "browser", login=("password",))),
    )
    record = run(account(chain={"use": "template"}, credentials={"access_token": "old.tok.en", "refresh_token": "rt1"}),
                 tmp_path).records[0]

    assert ("POST", "/api/v1/auth/refresh") not in [call[:2] for call in fake.calls]
    assert steps(record)[0]["reason"] == "need_login"
    assert calls["run_browser"] == 1 and record.outcome.verdict is Verdict.SUCCESS


def test_http_step_without_credentials_fails_and_falls_back(monkeypatch, tmp_path, browser, site) -> None:
    site({})
    calls = fake_template(monkeypatch, http=success("不应执行"), browser=success("浏览器登录并签到"))
    record = run(account(chain={"use": "template"}, credentials={}), tmp_path).records[0]
    assert calls["run_http"] == 0, "凭据一个都没有时不调用 HTTP 钩子"
    assert steps(record)[0]["reason"] == "need_config"
    assert record.outcome.verdict is Verdict.SUCCESS and calls["run_browser"] == 1


def test_blocked_login_is_final(monkeypatch, tmp_path, browser, site) -> None:
    from login.broker import LoginResult

    site({})
    calls = fake_template(monkeypatch, http=success("x"), browser=success("不应执行"))
    blocked = failed("出口 IP 被拒", reason="blocked")
    real = engine.LOGINS

    class BlockedBroker:
        """登录注册表带 __slots__，不能打桩实例方法；换掉引擎引用的整个对象。"""

        def get(self, method_id):
            return real.get(method_id)

        async def establish(self, *_args, **_kwargs):
            return LoginResult(outcome=blocked)

    monkeypatch.setattr(engine, "LOGINS", BlockedBroker())
    record = run(account(chain={"use": "template"}), tmp_path).records[0]
    assert record.outcome.reason == "blocked"
    assert calls["run_browser"] == 0 and calls["run_http"] == 0


def test_step_timeout_is_capped_by_task_remaining_time() -> None:
    from runtime.budget import Deadline

    clock = Deadline(30)
    assert engine._step_clock(clock, ChainStep("h", "http", timeout=600)).total <= 30
    assert engine._step_clock(clock, ChainStep("h", "http", timeout=10)).total == 10
    assert engine._step_clock(Deadline(None), ChainStep("h", "http")).total is None


def test_explain_chain_lists_order_sources_and_notes(monkeypatch) -> None:
    fake_template(monkeypatch, http=success("x"))
    template = templates.get("fake-chain")
    task = account(chain={"use": "template"}).tasks[0]
    explained = engine.explain_chain(task, template, frozenset())
    assert explained["describe"] == "HTTP →(失败)→ 浏览器"
    first, second = explained["steps"]
    assert first["login"] == ["access_token", "refresh"] and first["on_failure_next"] == "browser"
    assert second["login"] == ["browser_state", "password"]
    assert any("不能启动浏览器" in note for note in second["notes"])
    assert any("run_browser" in note for note in second["notes"])


# ── 真实模板：步骤拆分 ──────────────────────────────────────────────────────
SUB2API_FAMILY = (
    "sub2api", "scripts/tasks/100xlabs.py", "scripts/tasks/jisudeng.py", "scripts/tasks/vcnovb_lottery.py",
)


@pytest.mark.parametrize("reference", SUB2API_FAMILY)
def test_sub2api_family_declares_http_then_browser(reference) -> None:
    loaded = templates.get(reference)
    chain = loaded.manifest.chain
    assert [(step.id, step.kind) for step in chain] == [("http", "http"), ("browser", "browser")]
    assert chain[0].login[:2] == ("access_token", "refresh"), "HTTP 步骤先用 AT，失效再用 RT 续期"
    assert loaded.hook("run_http") is not None and loaded.hook("run_browser") is not None
    assert loaded.hook("run") is not None, "未配置访问链的任务仍走原入口"
    for step in chain:
        registered = {"browser_state", "oauth", "password", "access_token", "refresh", "cookie"}
        assert set(step.login) <= registered


def test_newapi_has_no_default_chain_yet() -> None:
    assert templates.get("newapi").manifest.chain == ()


@pytest.fixture
def flow_module():
    return importlib.import_module("scripts.tasks._sub2api_flow")


STRICT = None


def _strict_spec(flow):
    return flow.SiteSpec(
        site_label="测试站点", checkin_path="/api/v1/check-in", status_path="/api/v1/check-in/status",
        login_reset_sentinel="t", screenshot_prefix="t", strict_checkin=True,
    )


def _http_ctx(*, get, request=None, authorized=True):
    return SimpleNamespace(
        http=SimpleNamespace(
            headers={"Authorization": "Bearer x"} if authorized else {},
            get=Mock(side_effect=get),
            request=Mock(side_effect=request) if request is not None else Mock(),
        ),
        log=Mock(),
    )


def _state(checked=False, required=False):
    return {"code": 0, "data": {"checked_in_today": checked, "turnstile_required": required,
                                "enabled": True, "balance": 0}}


def test_http_attempt_handoffs_are_plain_failures_and_legacy_returns_none(flow_module) -> None:
    spec = _strict_spec(flow_module)
    for ctx, reason in (
        (_http_ctx(get=[], authorized=False), "need_login"),
        (_http_ctx(get=[_state(required=True)]), "need_verification"),
        (_http_ctx(get=[TaskError("超时", reason="network_error")]), "network_error"),
    ):
        outcome = asyncio.run(flow_module.http_attempt(ctx, spec))
        assert outcome.verdict is Verdict.FAILED and outcome.reason == reason
        assert not chain_module.is_final(outcome), "这类失败应交给浏览器步骤"
        ctx.http.get.reset_mock(side_effect=True)
    assert asyncio.run(flow_module.http_first(_http_ctx(get=[], authorized=False), spec)) is None


def test_http_attempt_after_submission_is_final_and_legacy_returns_it(flow_module) -> None:
    spec = _strict_spec(flow_module)
    reply = {"code": 0, "data": {"checked_in": False}}
    ctx = _http_ctx(get=[_state(), _state()], request=[reply])
    outcome = asyncio.run(flow_module.http_attempt(ctx, spec))
    assert outcome.verdict is Verdict.FAILED and chain_module.is_final(outcome)
    ctx = _http_ctx(get=[_state(), _state()], request=[reply])
    legacy = asyncio.run(flow_module.http_first(ctx, spec))
    assert legacy is not None and legacy.verdict is Verdict.FAILED
    assert chain_module.FINAL_FLAG not in legacy.data, "旧入口的结论不带访问链控制键"


def test_http_attempt_success_is_unchanged(flow_module) -> None:
    spec = _strict_spec(flow_module)
    ctx = _http_ctx(get=[_state(), _state(checked=True)], request=[{"code": 0, "data": {"checked_in": True}}])
    outcome = asyncio.run(flow_module.http_attempt(ctx, spec))
    assert outcome.verdict is Verdict.SUCCESS


@pytest.fixture
def baibei(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts" / "tasks"))
    return importlib.import_module("scripts.tasks.100xlabs")


def _task_ctx(task_id="daily", *, browser_service=None):
    return SimpleNamespace(
        account=SimpleNamespace(id="x", base_url="https://x.invalid", task_id=task_id),
        args={}, http=SimpleNamespace(headers={}), store=SimpleNamespace(get=Mock(return_value="")),
        browser_service=browser_service, log=Mock(), expired=Mock(return_value=False),
    )


def test_baibei_steps_dispatch_checkin_and_tree_separately(monkeypatch, baibei) -> None:
    attempt = AsyncMock(return_value=success("HTTP"))
    flow_run = AsyncMock(return_value=success("浏览器"))
    tree_http = AsyncMock(return_value=success("砍树 HTTP"))
    tree_browser = AsyncMock(return_value=success("砍树浏览器"))
    monkeypatch.setattr(baibei.flow, "http_attempt", attempt)
    monkeypatch.setattr(baibei.flow, "run_flow", flow_run)
    monkeypatch.setattr(baibei.tree, "run_http", tree_http)
    monkeypatch.setattr(baibei.tree, "run_browser", tree_browser)

    ctx = _task_ctx()
    ctx.browser = SimpleNamespace(lease=Mock(return_value=FakeLease()))
    assert asyncio.run(baibei.run_http(ctx)).message == "HTTP"
    assert asyncio.run(baibei.run_browser(ctx)).message == "浏览器"
    ctx.browser.lease.assert_called_once_with(reason="checkin")

    tree_ctx = _task_ctx("chop_tree")
    assert asyncio.run(baibei.run_http(tree_ctx)).message == "砍树 HTTP"
    assert asyncio.run(baibei.run_browser(tree_ctx)).message == "砍树浏览器"
    attempt.assert_awaited_once()
    flow_run.assert_awaited_once()


def test_tree_http_step_defers_first_device_binding_to_browser(baibei) -> None:
    ctx = _task_ctx("chop_tree", browser_service=object())
    outcome = asyncio.run(baibei.tree.run_http(ctx, baibei.SPEC))
    assert outcome.verdict is Verdict.FAILED and outcome.reason == "need_config"
    assert not chain_module.is_final(outcome), "没有设备标识时交给浏览器建立，而不是凭空生成"


def test_tree_http_failure_after_chop_is_final(monkeypatch, baibei) -> None:
    ctx = _task_ctx("chop_tree", browser_service=object())
    ctx.store = SimpleNamespace(get=Mock(return_value="saved-device"))
    chopped = failed("砍树中断", reason="network_error", data={"initial_stamina": 4})
    monkeypatch.setattr(baibei.tree, "run_chop_tree", AsyncMock(return_value=chopped))
    assert chain_module.is_final(asyncio.run(baibei.tree.run_http(ctx, baibei.SPEC)))

    before_post = failed("状态读取失败", reason="need_login")
    monkeypatch.setattr(baibei.tree, "run_chop_tree", AsyncMock(return_value=before_post))
    assert not chain_module.is_final(asyncio.run(baibei.tree.run_http(ctx, baibei.SPEC)))


@pytest.fixture
def jisudeng(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts" / "tasks"))
    return importlib.import_module("scripts.tasks.jisudeng")


def test_jisudeng_http_step_quizzes_only_after_checkin(monkeypatch, jisudeng) -> None:
    ctx = _task_ctx()
    ctx.store = SimpleNamespace(shared=Mock(return_value=SimpleNamespace()))
    ctx.args = {"quiz": True}
    quiz = Mock(return_value={"outcome": "submitted", "message": "答题完成"})
    monkeypatch.setattr(jisudeng, "run_play_quiz_http", quiz)

    monkeypatch.setattr(jisudeng.common, "http_attempt", AsyncMock(return_value=failed("x", reason="need_login")))
    assert asyncio.run(jisudeng.run_http(ctx)).reason == "need_login"
    quiz.assert_not_called()

    monkeypatch.setattr(jisudeng.common, "http_attempt", AsyncMock(return_value=success("签到成功")))
    outcome = asyncio.run(jisudeng.run_http(ctx))
    assert outcome.ok and outcome.data["quiz"]["outcome"] == "submitted"


@pytest.fixture
def lottery(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts" / "tasks"))
    return importlib.import_module("scripts.tasks.vcnovb_lottery")


def _pool(remaining=1, active=True):
    return {"code": 0, "data": {"pools": [{"pool": {"key": "normal", "enabled": True}, "active": active,
                                           "base_remaining": remaining, "extra_remaining": 0, "period_key": "d:2026-01-01"}]}}


def test_lottery_rejected_draw_is_final_and_legacy_still_raises_nothing(lottery) -> None:
    ctx = SimpleNamespace(
        http=SimpleNamespace(headers={"Authorization": "Bearer x"}, get=Mock(return_value=_pool()),
                             request=Mock(side_effect=TaskError("抽取被拒", status=400, payload={"reason": "X"}))),
        account=SimpleNamespace(id="acc", base_url="https://v.invalid"),
        log=Mock(),
    )
    outcome = asyncio.run(lottery.http_attempt(ctx))
    assert outcome.verdict is Verdict.FAILED and chain_module.is_final(outcome)
    legacy = asyncio.run(lottery.http_draw(ctx))
    assert legacy is not None and chain_module.FINAL_FLAG not in legacy.data


def test_lottery_unreadable_state_hands_off_to_browser(lottery) -> None:
    ctx = SimpleNamespace(
        http=SimpleNamespace(headers={"Authorization": "Bearer x"}, get=Mock(side_effect=TaskError("超时", reason="network_error"))),
        log=Mock(),
    )
    outcome = asyncio.run(lottery.http_attempt(ctx))
    assert outcome.reason == "network_error" and not chain_module.is_final(outcome)
    assert asyncio.run(lottery.http_draw(ctx)) is None
