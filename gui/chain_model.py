"""访问链可视化编辑器的纯 JSON 草稿模型；坐标与执行连接相互独立。

不执行模板、不加载凭据。未知字段和未编辑的原始写法原样往返。结构编辑会把隐式
列表顺序物化为 on_failure，防止删除/移动节点意外改变运行顺序。
"""
from __future__ import annotations

import math
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from core.chain import KIND_TITLES, ResolvedChain, parse_chain
from core.errors import ConfigError

#: 画布坐标的绝对值上限。越界坐标一律拒绝，避免把节点写到用户再也找不到的位置。
_MAX_COORDINATE = 100_000


@dataclass(frozen=True)
class ChainIssue:
    severity: str
    message: str
    node: str = ""


class ChainDocument:
    def __init__(self, value: dict | None, template_steps: list[dict] | None = None):
        self.raw = deepcopy(value)
        self.template_steps = deepcopy(template_steps or [])

    @property
    def source(self) -> str:
        if self.raw is None:
            return "legacy"
        if not isinstance(self.raw, dict):
            return "invalid"
        use = self.raw.get("use")
        return use.strip().lower() if isinstance(use, str) and use.strip() else (
            "invalid" if use is not None and not isinstance(use, str) else "custom" if "steps" in self.raw else "template"
        )

    def _object(self) -> dict:
        return self.raw if isinstance(self.raw, dict) else {}

    def payload(self) -> dict | None:
        return deepcopy(self.raw)

    def steps(self) -> list[dict]:
        values = self.template_steps if self.source == "template" else self._object().get("steps", [])
        return deepcopy([item for item in values if isinstance(item, dict) and isinstance(item.get("id"), str)]) if isinstance(values, list) else []

    def step(self, key: str) -> dict | None:
        return next((item for item in self.steps() if item.get("id") == key), None)

    def entry(self) -> str:
        return str(self._object().get("entry") or (self.steps()[0].get("id", "") if self.steps() else ""))

    def links(self) -> list[tuple[str, str]]:
        steps = self.steps()
        result = []
        for i, item in enumerate(steps):
            target = item.get("on_failure") if "on_failure" in item else (
                steps[i + 1].get("id", "") if i + 1 < len(steps) else ""
            )
            if isinstance(target, str) and target:
                result.append((str(item.get("id", "")), target))
        return result

    def order(self) -> list[str]:
        links = dict(self.links())
        ids = {step.get("id") for step in self.steps()}
        result = []
        key = self.entry()
        while key and key in ids and key not in result:
            result.append(key)
            key = links.get(key, "")
        return result

    def positions(self) -> dict[str, list[float]]:
        raw = self._object().get("layout", {})
        if not isinstance(raw, dict):
            return {}
        values = {}
        for key, point in raw.items():
            if isinstance(point, (list, tuple)) and len(point) == 2 and all(
                type(v) in (int, float) and math.isfinite(v) and abs(v) <= _MAX_COORDINATE for v in point
            ):
                values[key] = [float(point[0]), float(point[1])]
        return values

    def select_source(self, source: str) -> None:
        if source == "legacy":
            self.raw = None
        elif source == "template":
            layout = deepcopy(self._object().get("layout"))
            self.raw = {"use": "template"}
            if layout:
                self.raw["layout"] = layout
        elif source == "custom":
            if self.source != "custom":
                steps = self.steps()
                self.raw = {**self._object(), "use": "custom", "steps": steps}
                if steps:
                    self.raw["entry"] = steps[0]["id"]
        else:
            raise ConfigError("请选择原流程、模板默认或自定义访问链")

    def _editable(self) -> list[dict]:
        """确认可编辑，并返回可原地修改的 steps 列表。

        ``{"use": "custom"}`` 省略 steps 是合法 JSON（校验会报「必须是非空数组」），
        编辑器仍要能在它上面添加第一个步骤，因此这里补齐容器而不是抛 KeyError。
        """
        if self.source != "custom":
            raise ConfigError("模板默认链不会被直接修改，请先选择「自定义」")
        steps = self.raw.get("steps")
        if not isinstance(steps, list):
            steps = []
            self.raw["steps"] = steps
        return steps

    def _explicit(self) -> list[dict]:
        """把隐式的列表顺序物化成 on_failure，之后的增删移不会改变既有顺序。"""
        steps = self._editable()
        links = dict(self.links())
        self.raw.setdefault("entry", self.entry())
        for item in steps:
            # 缺 id 的条目由 parse_chain 报错，这里不能因它崩掉整个编辑操作。
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                item["on_failure"] = links.get(item["id"], "")
        return steps

    def _unique_id(self, seed: str) -> str:
        ids = {item.get("id") for item in self.steps()}
        if seed not in ids:
            return seed
        n = 2
        while f"{seed[:34]}_{n}" in ids:
            n += 1
        return f"{seed[:34]}_{n}"

    def add(self, kind: str, *, after: str = "", position: list[float] | None = None) -> str:
        steps = self._explicit()
        if kind not in KIND_TITLES:
            raise ConfigError("只能添加 HTTP 或浏览器步骤")
        key = self._unique_id(kind)
        same_kind = next((item for item in self.template_steps if item.get("kind") == kind), {})
        logins = same_kind.get("login", ["access_token"] if kind == "http" else ["browser_state", "password"])
        node = {"id": key, "kind": kind, "title": KIND_TITLES[kind], "login": deepcopy(logins), "on_failure": ""}
        if after:
            parent = next((item for item in steps if item.get("id") == after), None)
            if parent is None:
                raise ConfigError("插入位置已不存在")
            node["on_failure"] = parent.get("on_failure", "")
            parent["on_failure"] = key
        steps.append(node)
        if len(steps) == 1:
            self.raw["entry"] = key
        if position is not None:
            self.set_positions({key: position})
        return key

    def duplicate(self, key: str) -> str:
        steps = self._explicit()
        value = self.step(key)
        if value is None:
            raise ConfigError("步骤已不存在")
        new_id = self._unique_id(str(value.get("kind") or "http"))
        value.update(id=new_id, title=str(value.get("title") or key) + " 副本", on_failure="")
        steps.append(value)
        point = self.positions().get(key, [0, 0])
        self.set_positions({new_id: [point[0] + 40, point[1] + 170]})
        return new_id

    def update(self, key: str, patch: dict, remove: tuple[str, ...] = ()) -> None:
        steps = self._editable()
        item = next((item for item in steps if item.get("id") == key), None)
        if item is None:
            raise ConfigError("步骤已不存在")
        if "id" in patch or "on_failure" in patch:
            raise ConfigError("标识和连线请使用专门的编辑操作")
        for field in remove:
            item.pop(field, None)
        item.update(deepcopy(patch))

    def connect(self, source: str, target: str) -> None:
        self._editable()
        if source == target:
            raise ConfigError("步骤不能回退到自己")
        ids = {step.get("id") for step in self.steps()}
        if source not in ids or (target and target not in ids):
            raise ConfigError("连线端点不存在")
        backup = self.payload()
        steps = self._explicit()
        for item in steps:
            if isinstance(item, dict) and item.get("id") == source:
                item["on_failure"] = target
        try:
            parse_chain(self.raw, label="访问链")
        except ConfigError:
            self.raw = backup
            raise

    def set_entry(self, key: str) -> None:
        self._editable()
        if self.step(key) is None:
            raise ConfigError("入口步骤不存在")
        self.raw["entry"] = key

    def delete(self, keys: list[str]) -> None:
        steps = self._explicit()
        doomed = set(keys)
        kept = [step for step in steps if step.get("id") not in doomed]
        self.raw["steps"] = kept
        for item in kept:
            if item.get("on_failure") in doomed:
                item["on_failure"] = ""
        # 入口被删除时保留缺失引用，让用户明确选择新入口，而非偷偷换执行起点。
        layout = self.raw.get("layout")
        if isinstance(layout, dict):
            for key in doomed:
                layout.pop(key, None)

    def move_in_order(self, key: str, direction: int) -> None:
        order = self.order()
        if key not in order:
            raise ConfigError("该步骤尚未连接到入口，请先建立回退连线")
        index = order.index(key)
        dest = index + direction
        if not 0 <= dest < len(order):
            return
        steps = self._explicit()
        order[index], order[dest] = order[dest], order[index]
        self.raw["entry"] = order[0]
        nexts = dict(zip(order, order[1:] + [""]))
        for item in steps:
            if item.get("id") in nexts:
                item["on_failure"] = nexts[item["id"]]

    def set_positions(self, values: dict[str, list[float]]) -> None:
        """只接受有限数值坐标。

        NaN / Infinity 不是合法 JSON：让它们进草稿，用户要到最终保存时才撞上一句
        路径晦涩的失败，而那时已经看不出是哪次拖动写坏的。
        """
        if self.raw is None:
            return
        cleaned: dict[str, list[float]] = {}
        for key, point in values.items():
            if not isinstance(point, (list, tuple)) or len(point) != 2:
                raise ConfigError("节点坐标必须是两个数字")
            numbers = []
            for value in point:
                if type(value) is bool or not isinstance(value, (int, float)) or not math.isfinite(value):
                    raise ConfigError("节点坐标必须是有限数字")
                if abs(value) > _MAX_COORDINATE:
                    raise ConfigError("节点坐标超出画布范围")
                numbers.append(round(float(value), 1))
            cleaned[str(key)] = numbers
        current = deepcopy(self.raw.get("layout", {}))
        if not isinstance(current, dict):
            current = {}
        current.update(cleaned)
        self.raw["layout"] = current

    def auto_layout(self) -> None:
        order = self.order()
        rest = [item["id"] for item in self.steps() if item.get("id") not in order]
        positions = {key: [i * 320, 0] for i, key in enumerate(order)}
        positions.update({key: [i * 320, 210] for i, key in enumerate(rest)})
        self.set_positions(positions)

    def issues(self) -> list[ChainIssue]:
        if self.raw is None:
            return []
        result = []
        try:
            parsed = parse_chain(self.raw, label="访问链")
            if parsed.use == "template":
                if not self.template_steps:
                    return [ChainIssue("error", "模板未声明默认访问链；请选择自定义或保留原流程。")]
                parsed = parse_chain({"use": "custom", "steps": self.template_steps}, label="模板默认链")
            resolved = ResolvedChain(parsed.use, parsed.steps, parsed.entry)
            for key in resolved.unreachable():
                result.append(ChainIssue("warning", f"步骤 {key} 未连接到入口，本次不会执行。", key))
        except (ConfigError, TypeError, KeyError, AttributeError) as exc:
            node = next((str(item.get("id")) for item in self.steps() if str(item.get("id")) in str(exc)), "")
            result.append(ChainIssue("error", str(exc), node))
        return result
