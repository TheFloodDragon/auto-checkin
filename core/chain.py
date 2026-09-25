"""访问链：一个任务内按「前一步失败才执行下一步」串起的若干访问步骤。

旧实现把「先纯 HTTP、走不通再开浏览器」写死在每个脚本的 ``run()`` 里（百倍、极速蹬、
轮盘各写一遍），用户既看不到本次走了哪一步，也无法调整顺序或去掉某一步。访问链把
这条降级路径变成配置：

    HTTP（取 AT，AT 失效时用 RT 续期，然后签到）──失败时──▶ 浏览器（登录并操作页面）

约定只有三条：

1. **每一步都是一次完整的任务尝试**。取凭据属于步骤内部，不是单独的节点；某一步
   成功（含「今日已完成」「活动未开放」这类无需处置的结论）即结束整条链。
2. **只有失败才回退**。回退目标由 ``on_failure`` 指定；省略时回退到列表中的下一步，
   写空字符串或 null 表示失败即结束。步骤的 ``stop_on`` 可列出「不回退」的子结果；
   模板也可以把某个失败标记为终局（见 ``final``），例如已经提交过、重做会重复扣次数。
3. **不学习、不扩大**。访问链是用户看得见的执行顺序：不按上次成功的方式重排，也
   不会尝试链外的方式。没有配置 ``chain`` 的任务仍走原来的流程，行为不变。

配置形态（任务级 ``chain``）：

    {"use": "template"}                        使用模板声明的默认访问链
    {"use": "custom", "entry": "http",         自定义步骤
     "steps": [{"id": "http", "kind": "http", "login": ["access_token", "refresh"],
                "on_failure": "browser"},
               {"id": "browser", "kind": "browser", "login": ["browser_state", "password"]}],
     "layout": {...}}                           编辑器坐标，执行时忽略

``chain`` 对象及其步骤里不认识的键会原样保留并写回。
"""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from .errors import ConfigError
from .outcome import Outcome, Verdict

__all__ = [
    "BROWSER_PAGE_LOGIN",
    "ChainSpec",
    "ChainStep",
    "FINAL_FLAG",
    "KIND_TITLES",
    "ResolvedChain",
    "STATUS_TEXT",
    "STEP_HOOKS",
    "STEP_KINDS",
    "USE_CUSTOM",
    "USE_TEMPLATE",
    "final",
    "is_final",
    "parse_chain",
    "parse_steps",
    "resolve",
    "should_fallback",
    "step_payload",
    "strip_control",
    "summarize",
    "validate_steps",
]

#: 步骤类型。http = 纯接口访问；browser = 启动浏览器、登录后在页面里完成。
STEP_KINDS: tuple[str, ...] = ("http", "browser")
KIND_TITLES: Mapping[str, str] = MappingProxyType({"http": "HTTP", "browser": "浏览器"})
#: 每种步骤调用的模板钩子。
STEP_HOOKS: Mapping[str, str] = MappingProxyType({"http": "run_http", "browser": "run_browser"})
#: 浏览器步骤的登录来源里，这一项表示「由页面流程在登录页用账密完成登录」，
#: 不经过登录方式注册表。
BROWSER_PAGE_LOGIN = "password"

USE_TEMPLATE = "template"
USE_CUSTOM = "custom"

#: 模板把某个失败标成「终局、不要回退」时写进 ``Outcome.data`` 的控制键。
#: 引擎在落盘前会剥掉它，结果文件里看不到。
FINAL_FLAG = "_chain_final"

_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
_METHOD_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,39}$")
_TIMEOUT_RANGE = (1, 7200)


# ── 模型 ────────────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class ChainStep:
    """访问链的一个步骤。模板用它声明默认链，配置解析也产出它。"""

    id: str
    kind: str
    title: str = ""
    #: http 步骤：按顺序尝试的凭据来源（登录方式 id），只在列表内逐个降级。
    #: browser 步骤：进入页面前准备会话的来源；``password`` 表示页面流程可自行账密登录。
    login: tuple[str, ...] = ()
    #: 本步骤的时间预算（秒）。None = 与任务剩余时间一致。
    timeout: int | None = None
    #: 只作用于本步骤的参数，覆盖任务级 args 的同名键。
    args: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    #: 失败后回退到的步骤 id；None = 列表中的下一步；"" = 失败即结束。
    on_failure: str | None = None
    #: 失败子结果命中这些值时不回退。默认为空：任何失败都回退。
    stop_on: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return self.title or KIND_TITLES.get(self.kind, self.kind)

    @property
    def hook(self) -> str:
        return STEP_HOOKS.get(self.kind, "")

    @property
    def page_login(self) -> bool:
        """浏览器步骤是否允许页面流程自行完成账密登录。"""
        return self.kind == "browser" and BROWSER_PAGE_LOGIN in self.login

    @property
    def session_sources(self) -> tuple[str, ...]:
        """浏览器步骤里由引擎（登录方式注册表）准备会话的来源。"""
        return tuple(item for item in self.login if item != BROWSER_PAGE_LOGIN)


def step_payload(step: ChainStep) -> dict[str, Any]:
    """ChainStep → 配置 JSON（供预览、目录与编辑器使用）。"""
    payload: dict[str, Any] = {"id": step.id, "kind": step.kind}
    if step.title:
        payload["title"] = step.title
    if step.login:
        payload["login"] = list(step.login)
    if step.timeout is not None:
        payload["timeout"] = step.timeout
    if step.args:
        payload["args"] = deepcopy(dict(step.args))
    if step.on_failure is not None:
        payload["on_failure"] = step.on_failure
    if step.stop_on:
        payload["stop_on"] = list(step.stop_on)
    return payload


@dataclass(frozen=True, slots=True)
class ChainSpec:
    """任务上的 ``chain`` 配置。``raw`` 是原始 JSON 的深拷贝，导出时原样写回。"""

    use: str = USE_TEMPLATE
    steps: tuple[ChainStep, ...] = ()
    entry: str = ""
    raw: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}), repr=False, compare=False)

    def to_payload(self) -> dict[str, Any]:
        if self.raw:
            return deepcopy(dict(self.raw))
        if self.use == USE_TEMPLATE:
            return {"use": USE_TEMPLATE}
        payload: dict[str, Any] = {"use": USE_CUSTOM, "steps": [step_payload(item) for item in self.steps]}
        if self.entry:
            payload["entry"] = self.entry
        return payload


@dataclass(frozen=True, slots=True)
class ResolvedChain:
    """本次要执行的访问链：来源 + 全部步骤 + 入口。"""

    source: str
    steps: tuple[ChainStep, ...]
    entry: str = ""

    def step(self, step_id: str) -> ChainStep | None:
        return next((item for item in self.steps if item.id == step_id), None)

    def next_of(self, step: ChainStep) -> ChainStep | None:
        """``step`` 失败后回退到的步骤；None 表示链到此结束。"""
        return _next_of(self.steps, step)

    def order(self) -> tuple[ChainStep, ...]:
        """从入口沿失败回退走出的执行顺序（已校验无环）。"""
        return _path(self.steps, self.entry)

    def unreachable(self) -> tuple[str, ...]:
        reachable = {item.id for item in self.order()}
        return tuple(item.id for item in self.steps if item.id not in reachable)

    def describe(self) -> str:
        return " →(失败)→ ".join(item.label for item in self.order()) or "<空>"


# ── 解析与校验 ───────────────────────────────────────────────────────────────
def parse_chain(raw: Any, *, label: str) -> ChainSpec | None:
    """解析任务的 ``chain`` 配置。``None`` 表示未配置（沿用原流程）。"""
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ConfigError(f"{label} 的 chain 必须是对象，例如 {{\"use\": \"template\"}}")
    use_raw = raw.get("use")
    if use_raw is not None and not isinstance(use_raw, str):
        raise ConfigError(f"{label} 的 chain.use 必须是字符串 template 或 custom")
    use = str(use_raw or "").strip().lower()
    steps_raw = raw.get("steps")
    if not use:
        use = USE_CUSTOM if steps_raw is not None else USE_TEMPLATE
    if use not in (USE_TEMPLATE, USE_CUSTOM):
        raise ConfigError(f"{label} 的 chain.use 只能是 template 或 custom，收到 {use_raw!r}")
    layout = raw.get("layout")
    if layout is not None and not isinstance(layout, Mapping):
        raise ConfigError(f"{label} 的 chain.layout 必须是对象")
    entry_raw = raw.get("entry")
    if entry_raw is not None and not isinstance(entry_raw, str):
        raise ConfigError(f"{label} 的 chain.entry 必须是步骤 id 字符串")
    entry = str(entry_raw or "").strip()
    frozen = MappingProxyType(deepcopy(dict(raw)))

    if use == USE_TEMPLATE:
        if steps_raw not in (None, []):
            raise ConfigError(
                f"{label} 的 chain.use=template 时不能同时写 steps；要自定义步骤请把 use 改为 custom"
            )
        if entry:
            raise ConfigError(f"{label} 的 chain.use=template 时不能指定 entry")
        return ChainSpec(use=USE_TEMPLATE, raw=frozen)

    steps = parse_steps(steps_raw, label=label)
    validate_steps(steps, entry, label=f"{label} 的 chain")
    return ChainSpec(use=USE_CUSTOM, steps=steps, entry=entry, raw=frozen)


def parse_steps(items: Any, *, label: str) -> tuple[ChainStep, ...]:
    if not isinstance(items, list) or not items:
        raise ConfigError(f"{label} 的 chain.steps 必须是非空数组（use=custom）")
    steps: list[ChainStep] = []
    for index, item in enumerate(items):
        where = f"{label} 的 chain.steps[{index}]"
        if not isinstance(item, Mapping):
            raise ConfigError(f"{where} 必须是对象")
        step_id = item.get("id")
        if not isinstance(step_id, str) or not _ID_PATTERN.match(step_id.strip()):
            raise ConfigError(f"{where}.id 必须是 1-40 位字母、数字、下划线、点或连字符")
        kind = item.get("kind")
        if not isinstance(kind, str) or kind.strip().lower() not in STEP_KINDS:
            raise ConfigError(f"{where}.kind 只能是 {' / '.join(STEP_KINDS)}")
        title = item.get("title", "")
        if not isinstance(title, str):
            raise ConfigError(f"{where}.title 必须是字符串")
        login = _string_list(item.get("login"), where=f"{where}.login", pattern=_METHOD_PATTERN)
        if "login" in item and not login:
            raise ConfigError(f"{where}.login 不能为空；省略 login 才表示使用模板的默认来源")
        timeout = item.get("timeout")
        if timeout is not None:
            if type(timeout) is not int or not _TIMEOUT_RANGE[0] <= timeout <= _TIMEOUT_RANGE[1]:
                raise ConfigError(f"{where}.timeout 必须是 {_TIMEOUT_RANGE[0]}-{_TIMEOUT_RANGE[1]} 的整数秒")
        args = item.get("args")
        if args is not None and not isinstance(args, Mapping):
            raise ConfigError(f"{where}.args 必须是对象")
        on_failure: str | None
        if "on_failure" not in item:
            on_failure = None
        elif item.get("on_failure") is None:
            on_failure = ""
        elif isinstance(item.get("on_failure"), str):
            on_failure = item["on_failure"].strip()
        else:
            raise ConfigError(f"{where}.on_failure 必须是步骤 id、空字符串或 null")
        stop_on = _string_list(item.get("stop_on"), where=f"{where}.stop_on", pattern=_METHOD_PATTERN)
        steps.append(
            ChainStep(
                id=step_id.strip(),
                kind=kind.strip().lower(),
                title=title.strip(),
                login=login,
                timeout=timeout,
                args=MappingProxyType(deepcopy(dict(args or {}))),
                on_failure=on_failure,
                stop_on=stop_on,
            )
        )
    return tuple(steps)


def _string_list(value: Any, *, where: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ConfigError(f"{where} 必须是字符串数组")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not pattern.match(item.strip().lower()):
            raise ConfigError(f"{where} 只能包含小写字母、数字、下划线、点或连字符组成的名称")
        name = item.strip().lower()
        if name in out:
            raise ConfigError(f"{where} 含重复项 {name}")
        out.append(name)
    return tuple(out)


def validate_steps(steps: Sequence[ChainStep], entry: str = "", *, label: str) -> None:
    """步骤 id 唯一、入口与回退目标存在、回退不成环。"""
    if not steps:
        raise ConfigError(f"{label} 没有任何步骤")
    ids: list[str] = []
    for step in steps:
        if not isinstance(step, ChainStep):
            raise ConfigError(f"{label} 的每个步骤必须是 ChainStep")
        if not isinstance(step.id, str) or not _ID_PATTERN.fullmatch(step.id):
            raise ConfigError(f"{label} 的步骤 id 格式无效")
        if step.kind not in STEP_KINDS:
            raise ConfigError(f"{label} 的步骤 {step.id} 类型未知：{step.kind}")
        if not isinstance(step.title, str) or not isinstance(step.args, Mapping):
            raise ConfigError(f"{label} 的步骤 {step.id} 的 title 必须是字符串，args 必须是对象")
        if step.timeout is not None and (
            type(step.timeout) is not int or not _TIMEOUT_RANGE[0] <= step.timeout <= _TIMEOUT_RANGE[1]
        ):
            raise ConfigError(f"{label} 的步骤 {step.id} 的 timeout 必须是 1-7200 的整数秒")
        for name, items in (("login", step.login), ("stop_on", step.stop_on)):
            where = f"{label} 的步骤 {step.id} 的 {name}"
            if not isinstance(items, (tuple, list)):
                raise ConfigError(f"{where} 必须是名称数组")
            normalized = _string_list(list(items), where=where, pattern=_METHOD_PATTERN)
            if normalized != tuple(items):
                raise ConfigError(f"{where} 的名称必须小写且不含首尾空白")
        if step.on_failure is not None and not isinstance(step.on_failure, str):
            raise ConfigError(f"{label} 的步骤 {step.id} 的 on_failure 必须是步骤 id 或空字符串")
        if step.id in ids:
            raise ConfigError(f"{label} 有重复的步骤 id：{step.id}")
        ids.append(step.id)
    if entry and entry not in ids:
        raise ConfigError(f"{label} 的入口步骤 {entry} 不存在")
    for step in steps:
        if step.on_failure and step.on_failure not in ids:
            raise ConfigError(f"{label} 的步骤 {step.id} 回退到不存在的步骤 {step.on_failure}")
        if step.on_failure == step.id:
            raise ConfigError(f"{label} 的步骤 {step.id} 不能回退到自己")
    for step in steps:
        trail = [step.id]
        current = _next_of(steps, step)
        while current is not None:
            if current.id in trail:
                raise ConfigError(f"{label} 的失败回退形成循环：{' → '.join((*trail, current.id))}")
            trail.append(current.id)
            current = _next_of(steps, current)


def _next_of(steps: Sequence[ChainStep], step: ChainStep) -> ChainStep | None:
    if step.on_failure == "":
        return None
    if step.on_failure is not None:
        return next((item for item in steps if item.id == step.on_failure), None)
    for index, item in enumerate(steps):
        if item.id == step.id:
            return steps[index + 1] if index + 1 < len(steps) else None
    return None


def _path(steps: Sequence[ChainStep], entry: str) -> tuple[ChainStep, ...]:
    if not steps:
        return ()
    current = next((item for item in steps if item.id == entry), None) if entry else steps[0]
    out: list[ChainStep] = []
    seen: set[str] = set()
    while current is not None and current.id not in seen:
        out.append(current)
        seen.add(current.id)
        current = _next_of(steps, current)
    return tuple(out)


def resolve(spec: ChainSpec, manifest: Any) -> ResolvedChain:
    """把任务的 chain 配置解析成要执行的链；模板默认链在这里取出并校验。"""
    if spec.use == USE_TEMPLATE:
        steps = tuple(getattr(manifest, "chain", ()) or ())
        template_id = str(getattr(manifest, "id", "") or "?")
        if not steps:
            raise ConfigError(
                f"模板 {template_id} 没有声明默认访问链；请把 chain.use 改为 custom 并写出步骤，"
                "或删除 chain 沿用原流程"
            )
        validate_steps(steps, label=f"模板 {template_id} 的默认访问链")
        return ResolvedChain(source=USE_TEMPLATE, steps=steps)
    if spec.use != USE_CUSTOM:
        raise ConfigError(f"chain.use 只能是 template 或 custom，收到 {spec.use!r}")
    validate_steps(spec.steps, spec.entry, label="自定义访问链")
    return ResolvedChain(source=USE_CUSTOM, steps=spec.steps, entry=spec.entry)


# ── 回退判定 ────────────────────────────────────────────────────────────────
def should_fallback(step: ChainStep, outcome: Outcome) -> bool:
    """这一步的结论是否允许回退到下一步。"""
    if outcome.verdict is not Verdict.FAILED:
        return False
    if is_final(outcome):
        return False
    return not (outcome.reason and outcome.reason in step.stop_on)


def final(outcome: Outcome) -> Outcome:
    """把一个失败标记为终局：访问链不再回退到后续步骤。"""
    return outcome.with_data({FINAL_FLAG: True})


def is_final(outcome: Outcome) -> bool:
    return bool(outcome.data.get(FINAL_FLAG))


def strip_control(outcome: Outcome) -> Outcome:
    """剥掉访问链的控制键，结果文件里只留业务数据。"""
    if FINAL_FLAG not in outcome.data:
        return outcome
    from dataclasses import replace

    data = {key: value for key, value in outcome.data.items() if key != FINAL_FLAG}
    return replace(outcome, data=MappingProxyType(data))


def summarize(entries: Iterable[Mapping[str, Any]]) -> str:
    """步骤明细 → 一行摘要，进结果文件的 ``flow.chain`` 与日志。"""
    parts: list[str] = []
    for item in entries:
        status = str(item.get("status") or "")
        if status == "not_run":
            continue
        text = f"{item.get('id')}={STATUS_TEXT.get(status, status)}"
        reason = str(item.get("reason") or "")
        if status in {"failed", "unavailable"} and reason:
            text += f"({reason})"
        parts.append(text)
    return " → ".join(parts)


#: 步骤状态的中文说明（结果文件、日志与界面共用）。
STATUS_TEXT: Mapping[str, str] = MappingProxyType(
    {
        "success": "成功",
        "already_done": "今日已完成",
        "no_effect": "无影响",
        "failed": "失败",
        "unavailable": "不可用",
        "not_run": "未执行",
    }
)
