"""模板 / 任务清单契约与参数 schema。

两件事在这里定死：

1. **参数不再是自由 dict**。旧实现里 ``script_args`` 是任意 JSON，每个脚本自己写
   ``str(args.get("email") or "").strip()`` 这类解析，GUI 只能给一个自由文本框，
   写错键名要等到运行时才发现（而且多半表现为一句无关的失败）。``ArgSchema``
   声明字段类型、默认值、是否必填、环境变量回退与敏感标记，加载时统一校验，
   GUI 据此自动生成表单。
2. **能力与自管阶段是显式声明**。``requires`` 让引擎在启动前就知道要不要准备
   浏览器/视觉模型；``owns`` 取代旧的 ``OWNS_HTTP_FLOW`` 布尔，可以按阶段细分
   （只自管 detect、或同时自管 confirm）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .chain import ChainStep
from .errors import ConfigError

__all__ = [
    "ArgSchema",
    "ArgSpec",
    "ChainStep",
    "DisplayDefaults",
    "EMPTY_SCHEMA",
    "LoginOption",
    "ResponseMap",
    "STAGES",
    "TaskOption",
    "TemplateManifest",
]

#: 引擎的阶段名。``owns`` / ``flow`` 配置只接受这些值。
STAGES: tuple[str, ...] = (
    "login",
    "prepare",
    "detect",
    "execute",
    "verification",
    "confirm",
    "render",
)

_TRUE = {"1", "true", "yes", "y", "on"}
_FALSE = {"0", "false", "no", "n", "off"}


# ── 参数 schema ─────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class ArgSpec:
    """一个任务参数的声明。

    ``env`` 是环境变量回退：账密这类凭据不该写进 ACCOUNTS.json，旧实现让每个脚本
    自己实现 ``email_env`` / ``password_env`` 的二段查找（``providers/actions/
    browser_script.py:_script_credentials``），现在下沉为通用能力。
    """

    name: str
    kind: str = "str"          # str | int | float | bool | json
    default: Any = None
    required: bool = False
    secret: bool = False       # 真时不进日志、不进结果文件、GUI 用密码框
    env: str = ""              # 值为空时回退读该环境变量
    choices: tuple[Any, ...] = ()
    title: str = ""            # GUI 标签；缺省用 name
    help: str = ""
    minimum: float | None = None
    maximum: float | None = None

    def coerce(self, value: Any) -> Any:
        """把外部值转成声明类型；无法转换时抛 ConfigError（带字段名）。"""
        if value is None or value == "":
            return None
        try:
            if self.kind == "bool":
                return _to_bool(value)
            if self.kind == "int":
                return _bounded(int(value), self)
            if self.kind == "float":
                return _bounded(float(value), self)
            if self.kind == "json":
                return value if isinstance(value, (dict, list)) else _load_json(value)
            return str(value)
        except ConfigError:
            raise
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"参数 {self.name} 期望 {self.kind}，收到 {value!r}：{exc}") from exc


class ArgSchema:
    """有序参数集合。不可变；``resolve()`` 产出校验后的只读映射。"""

    __slots__ = ("_specs", "_allow_extra")

    def __init__(self, specs: Iterable[ArgSpec] = (), *, allow_extra: bool = True) -> None:
        ordered: dict[str, ArgSpec] = {}
        for spec in specs:
            ordered[spec.name] = spec
        self._specs = MappingProxyType(ordered)
        # 默认允许未声明的键透传：站点脚本迭代快，强制先改 schema 再传参会拖慢排查。
        # 未声明键不会被类型转换，也不会出现在 GUI 表单里。
        self._allow_extra = allow_extra

    def __iter__(self):
        return iter(self._specs.values())

    def __contains__(self, name: object) -> bool:
        return str(name) in self._specs

    def __len__(self) -> int:
        return len(self._specs)

    def get(self, name: str) -> ArgSpec | None:
        return self._specs.get(name)

    def merge(self, other: "ArgSchema | None") -> "ArgSchema":
        """模板继承时叠加：``other`` 同名字段覆盖自身。"""
        if other is None or not len(other):
            return self
        merged = dict(self._specs)
        for spec in other:
            merged[spec.name] = spec
        return ArgSchema(merged.values(), allow_extra=self._allow_extra and other._allow_extra)

    def secret_names(self) -> frozenset[str]:
        return frozenset(spec.name for spec in self._specs.values() if spec.secret)

    def resolve(self, values: Mapping[str, Any] | None, *, label: str = "任务") -> Mapping[str, Any]:
        """校验并补默认值 / 环境变量回退，返回只读映射。

        失败一次性列出所有问题：逐个报错会让用户改一个跑一次，配置多的站点很折磨。
        """
        raw = dict(values or {})
        out: dict[str, Any] = {}
        problems: list[str] = []

        for spec in self._specs.values():
            value = raw.pop(spec.name, None)
            if (value is None or value == "") and spec.env:
                value = os.environ.get(spec.env, "") or None
            if value is None or value == "":
                if spec.required:
                    hint = f"（可用环境变量 {spec.env}）" if spec.env else ""
                    problems.append(f"缺少必填参数 {spec.name}{hint}")
                    continue
                if spec.default is not None:
                    out[spec.name] = spec.default
                continue
            try:
                coerced = spec.coerce(value)
            except ConfigError as exc:
                problems.append(exc.message)
                continue
            if spec.choices and coerced not in spec.choices:
                problems.append(
                    f"参数 {spec.name} 只能是 {', '.join(str(c) for c in spec.choices)}，收到 {coerced!r}"
                )
                continue
            out[spec.name] = coerced

        if raw and not self._allow_extra:
            problems.append(f"存在未声明的参数：{', '.join(sorted(raw))}")
        elif raw:
            out.update(raw)

        if problems:
            raise ConfigError(f"{label}参数无效：" + "；".join(problems))
        return MappingProxyType(out)


EMPTY_SCHEMA = ArgSchema()


# ── 选项与清单 ──────────────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class LoginOption:
    """一种登录方式（原 auth_method 的一个取值）在本模板下的可用性声明。"""

    method: str
    priority: int = 50                              # auto 探测顺序，小的先试
    args: ArgSchema = EMPTY_SCHEMA
    requires: frozenset[str] = frozenset()          # {"browser"} / {"node"} ...
    title: str = ""

    @property
    def label(self) -> str:
        return self.title or self.method


@dataclass(frozen=True, slots=True)
class TaskOption:
    """一种任务方式（原 checkin_action 的一个取值）在本模板下的可用性声明。"""

    method: str
    priority: int = 50
    args: ArgSchema = EMPTY_SCHEMA
    requires: frozenset[str] = frozenset()
    #: 由模板/脚本自管、引擎不再介入的阶段。取代旧的 OWNS_HTTP_FLOW 布尔。
    owns: frozenset[str] = frozenset()
    title: str = ""

    @property
    def label(self) -> str:
        return self.title or self.method

    def __post_init__(self) -> None:
        unknown = set(self.owns) - set(STAGES)
        if unknown:
            raise ValueError(f"TaskOption.owns 含未知阶段：{sorted(unknown)}")


@dataclass(frozen=True, slots=True)
class DisplayDefaults:
    """模板级展示默认值。结论未覆写时用它填充。"""

    text_label: str = ""
    label: str = ""
    icon: str = ""


# ── 响应字段映射 ────────────────────────────────────────────────────────────
#: 数值单位。``quota_500000`` 是 New API 的内部额度单位（除以 50 万得美元）。
UNITS: tuple[str, ...] = ("raw", "usd", "quota_500000")

QUOTA_UNIT = 500_000


@dataclass(frozen=True, slots=True)
class ResponseMap:
    """把站点响应里的字段名映射到框架认识的语义。

    存在的理由：没有它，「不写 Python 就能加一个站点」这句话不成立——声明式模板
    只能改端点，却读不懂响应，通用驱动无从判断「今日已完成」还是「刚刚签到成功」。

    每个语义字段是一串**候选路径**，按顺序取第一个非空值：
    - 含 ``.`` 的按点分路径逐层取（``data.stats.checked_in_today``）；
    - 不含 ``.`` 的在整个响应里按键名广度优先搜索（各 fork 的嵌套层级并不一致，
      写死层级会让一次改版就失效）。
    """

    checked_in: tuple[str, ...] = ()
    already: tuple[str, ...] = ()     # 「今日已签到」的显式标记字段
    awarded: tuple[str, ...] = ()     # 本次获得
    balance: tuple[str, ...] = ()     # 当前余额 / 当前数值
    streak: tuple[str, ...] = ()      # 连续天数
    total: tuple[str, ...] = ()       # 累计次数
    message: tuple[str, ...] = ()     # 站点自带的结论文案
    unit: str = "raw"

    def pick(self, payload: Any, field: str) -> Any:
        return pick_path(payload, getattr(self, field, ()) or ())

    def to_number(self, value: Any) -> float | None:
        """按 ``unit`` 换算为可展示数值；非数字（含 bool）或非有限值返回 None。

        NaN / Infinity 必须挡在这里：json 会把它们写成裸 NaN（非标准 JSON），
        且 NaN 参与任何比较都为 False，会让「数值是否增长」的交叉验证静默失效。
        """
        import math

        if value is None or isinstance(value, bool):
            return None
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(number):
            return None
        return number / QUOTA_UNIT if self.unit == "quota_500000" else number

    def format(self, value: Any) -> str:
        """展示文本。货币单位给 ``$x.xx``，raw 单位原样给数字字符串。"""
        number = self.to_number(value)
        if number is None:
            return ""
        if self.unit == "raw":
            return str(int(number)) if float(number).is_integer() else f"{number:g}"
        return f"${number:.2f}" if abs(number) >= 0.01 else f"${number:.4f}"

    def has_amount(self, value: Any) -> bool:
        """是否有「值得展示的获得数值」。

        0 一律视为「站点没回具体数值」而不是「获得 0」：站点签到成功但不带金额时
        常回 0，展示成「获得额度：$0.0000」既不是事实，也让用户以为签到出了问题。
        """
        number = self.to_number(value)
        return number is not None and abs(number) > 0

    def is_empty(self) -> bool:
        return not any(
            getattr(self, name)
            for name in ("checked_in", "already", "awarded", "balance", "streak", "total", "message")
        )

    def merge(self, other: "ResponseMap | None") -> "ResponseMap":
        """模板继承：``other`` 的非空字段覆盖自身。"""
        if other is None or other.is_empty():
            return replace(self, unit=other.unit if other and other.unit != "raw" else self.unit)
        return ResponseMap(
            checked_in=other.checked_in or self.checked_in,
            already=other.already or self.already,
            awarded=other.awarded or self.awarded,
            balance=other.balance or self.balance,
            streak=other.streak or self.streak,
            total=other.total or self.total,
            message=other.message or self.message,
            unit=other.unit if other.unit != "raw" else self.unit,
        )


EMPTY_RESPONSE_MAP = ResponseMap()


def pick_path(payload: Any, candidates: Iterable[str]) -> Any:
    """按候选路径取第一个非空值。含 ``.`` 走点分路径，否则按键名 BFS。"""
    for candidate in candidates:
        path = str(candidate or "").strip()
        if not path:
            continue
        value = _dotted(payload, path) if "." in path else _bfs(payload, path)
        if value not in (None, ""):
            return value
    return None


def _dotted(payload: Any, path: str) -> Any:
    current = payload
    for part in path.split("."):
        if isinstance(current, Mapping):
            current = current.get(part)
        elif isinstance(current, (list, tuple)) and part.isdigit():
            index = int(part)
            current = current[index] if 0 <= index < len(current) else None
        else:
            return None
        if current is None:
            return None
    return current


def _bfs(payload: Any, key: str) -> Any:
    """按键名广度优先查找（不区分大小写）；带环保护。"""
    from collections import deque

    wanted = key.lower()
    queue: deque[Any] = deque([payload])
    seen: set[int] = set()
    while queue:
        item = queue.popleft()
        if item is None:
            continue
        marker = id(item)
        if marker in seen:
            continue
        seen.add(marker)
        if isinstance(item, Mapping):
            for name, value in item.items():
                if str(name).lower() == wanted and value not in (None, ""):
                    return value
            queue.extend(item.values())
        elif isinstance(item, (list, tuple)):
            queue.extend(item)
    return None


@dataclass(frozen=True, slots=True)
class DetectSpec:
    """站点指纹：``template="auto"`` 时用来判断这是哪一族站点。

    只做**只读**探测：``paths`` 逐个 GET，命中 ``markers`` 中任一片段即加分。
    真正的打分逻辑在 ``runtime.probe``，这里只是声明式数据。
    """

    paths: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()
    json_keys: tuple[str, ...] = ()
    weight: float = 1.0


@dataclass(frozen=True, slots=True)
class TemplateManifest:
    """模板清单。内置模板与用户模板、自定义脚本共用同一结构。"""

    id: str
    title: str = ""
    extends: str = ""
    sdk: int = 1
    detect: DetectSpec | None = None
    login: tuple[LoginOption, ...] = ()
    task: tuple[TaskOption, ...] = ()
    display: DisplayDefaults = DisplayDefaults()
    capabilities: frozenset[str] = frozenset()
    args: ArgSchema = EMPTY_SCHEMA
    endpoints: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    #: 该站点族要求的额外请求头。值里可用 ``{user_id}`` / ``{base_url}`` /
    #: ``{referer_path}`` 占位；渲染后为空的头会被丢弃。
    #: 例：New API 需要 ``New-Api-User``，写死在客户端类里就意味着换个站点族要改内核。
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    #: 响应字段映射。声明式（TOML）模板靠它被通用驱动执行；写了 ``run()`` 的
    #: Python 模板可以不填。
    response: ResponseMap = EMPTY_RESPONSE_MAP
    description: str = ""
    #: 默认访问链：任务配置 ``chain: {"use": "template"}`` 时执行的步骤。
    #: 为空表示本模板没有默认访问链，任务只能沿用原流程或写自定义链。
    chain: tuple[ChainStep, ...] = ()
    def login_option(self, method: str) -> LoginOption | None:
        key = str(method or "").strip().lower()
        for option in self.login:
            if option.method == key:
                return option
        return None

    def task_option(self, method: str) -> TaskOption | None:
        key = str(method or "").strip().lower()
        for option in self.task:
            if option.method == key:
                return option
        return None

    def login_order(self) -> tuple[str, ...]:
        return tuple(o.method for o in sorted(self.login, key=lambda o: (o.priority, o.method)))

    def task_order(self) -> tuple[str, ...]:
        return tuple(o.method for o in sorted(self.task, key=lambda o: (o.priority, o.method)))

    def inherit(self, parent: "TemplateManifest") -> "TemplateManifest":
        """按 ``extends`` 合并父模板：本模板显式给出的字段优先。

        login/task 按 method 归并（子覆盖父），endpoints 逐键覆盖，
        capabilities 取并集——子模板不该因为没重复声明就丢掉父模板的能力。
        """
        login = {o.method: o for o in parent.login}
        login.update({o.method: o for o in self.login})
        task = {o.method: o for o in parent.task}
        task.update({o.method: o for o in self.task})
        endpoints = dict(parent.endpoints)
        endpoints.update(dict(self.endpoints))
        headers = dict(parent.headers)
        headers.update(dict(self.headers))
        return TemplateManifest(
            id=self.id,
            title=self.title or parent.title,
            extends="",
            sdk=max(self.sdk, parent.sdk),
            detect=self.detect or parent.detect,
            login=tuple(sorted(login.values(), key=lambda o: (o.priority, o.method))),
            task=tuple(sorted(task.values(), key=lambda o: (o.priority, o.method))),
            display=DisplayDefaults(
                text_label=self.display.text_label or parent.display.text_label,
                label=self.display.label or parent.display.label,
                icon=self.display.icon or parent.display.icon,
            ),
            capabilities=frozenset(self.capabilities | parent.capabilities),
            args=parent.args.merge(self.args),
            endpoints=MappingProxyType(endpoints),
            headers=MappingProxyType(headers),
            response=parent.response.merge(self.response),
            description=self.description or parent.description,
            chain=self.chain or parent.chain,
        )


# ── 小工具 ──────────────────────────────────────────────────────────────────
def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ValueError(f"不是布尔值：{value!r}")


def _load_json(value: Any) -> Any:
    import json

    return json.loads(str(value))


def _bounded(value: float | int, spec: ArgSpec) -> float | int:
    if spec.minimum is not None and value < spec.minimum:
        raise ConfigError(f"参数 {spec.name} 小于下限 {spec.minimum}")
    if spec.maximum is not None and value > spec.maximum:
        raise ConfigError(f"参数 {spec.name} 超过上限 {spec.maximum}")
    return value
