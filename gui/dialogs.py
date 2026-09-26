"""原始 JSON 和任务编辑弹窗；只有实际编辑的字段才写回草稿。"""

from __future__ import annotations

import json
import math
from copy import deepcopy
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QPlainTextEdit, QPushButton, QScrollArea, QSizePolicy, QVBoxLayout, QWidget,
)

from core.errors import ConfigError
from core.masking import is_sensitive_key

from . import core
from .ui import FlowLayout, SectionCard, configure_form, fit_dialog


def label(text: str, name: str = "hint") -> QLabel:
    result = QLabel(text)
    result.setTextFormat(Qt.TextFormat.PlainText)
    result.setWordWrap(True)
    result.setObjectName(name)
    return result


def button(text: str, callback, kind: str = "") -> QPushButton:
    result = QPushButton(text)
    result.setCursor(Qt.CursorShape.PointingHandCursor)
    if kind:
        result.setProperty("kind", kind)
    result.clicked.connect(lambda _checked=False: callback())
    return result


class OpenCombo(QComboBox):
    """开放词表：模板路径及未发现的方法不会回落到已知选项。"""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setEditable(True)
        self.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.setMinimumContentsLength(18)

    def choices(self, values: list[str]) -> None:
        text = self.currentText()
        blocked = self.blockSignals(True)
        self.clear()
        self.addItems(list(dict.fromkeys(values)))
        self.setEditText(text)
        self.blockSignals(blocked)

    def wheelEvent(self, event) -> None:  # noqa: N802
        event.ignore()


class SecretEdit(QWidget):
    """不把凭据放进 tooltip/repr；明文可见性必须由用户主动切换。"""

    textChanged = Signal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setInputMethodHints(Qt.InputMethodHint.ImhHiddenText | Qt.InputMethodHint.ImhNoPredictiveText)
        self.toggle = QPushButton("显示")
        self.toggle.setCheckable(True)
        self.toggle.setMinimumWidth(58)
        self.toggle.setProperty("kind", "quiet")
        self.toggle.setAccessibleName("显示敏感内容")
        self.toggle.setToolTip("显示或隐藏敏感内容")
        row.setSpacing(6)
        self.toggle.toggled.connect(self._visible)
        self.edit.textChanged.connect(self.textChanged)
        row.addWidget(self.edit, 1)
        row.addWidget(self.toggle)

    def _visible(self, visible: bool) -> None:
        self.edit.setEchoMode(QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password)
        self.toggle.setText("隐藏" if visible else "显示")
        self.toggle.setAccessibleName("隐藏敏感内容" if visible else "显示敏感内容")

    def setText(self, text: str) -> None:  # noqa: N802
        self.edit.setText(text)

    def text(self) -> str:
        return self.edit.text()

    def setPlaceholderText(self, text: str) -> None:  # noqa: N802
        self.edit.setPlaceholderText(text)

    def conceal(self) -> None:
        self.toggle.setChecked(False)


class JsonDialog(QDialog):
    def __init__(self, title: str, value: Any, parent: QWidget | None = None, expected_type=dict):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.expected_type = expected_type
        self._initial = deepcopy(value)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)
        layout.addWidget(label(title, "pageTitle"))
        layout.addWidget(label("只在确认后应用修改。内容可能包含凭据，请勿截图或公开分享原文。"))
        self.editor = QPlainTextEdit()
        self.editor.setObjectName("jsonEditor")
        self.editor.setAccessibleName("JSON 内容")
        self.editor.setTabStopDistance(self.editor.fontMetrics().horizontalAdvance(" ") * 2)
        self.editor.setPlainText(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False))
        layout.addWidget(self.editor, 1)
        self.error_label = label("", "error")
        self.error_label.hide()
        layout.addWidget(self.error_label)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("确认")
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("kind", "primary")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        fit_dialog(self, 820, 660, (480, 360))

    def value(self) -> Any:
        value = core._decode_json(self.editor.toPlainText())
        core._json_value(value)
        if self.expected_type is not None and not isinstance(value, self.expected_type):
            expected = {dict: "JSON 对象", list: "JSON 数组"}.get(self.expected_type, "指定的 JSON 类型")
            raise ConfigError(f"请输入{expected}，当前根容器类型不正确")
        return deepcopy(value)

    def has_changes(self) -> bool:
        return core.fingerprint({"value": self.value()}) != core.fingerprint({"value": self._initial})

    def accept(self) -> None:
        try:
            self.value()
        except (ConfigError, ValueError, TypeError, RecursionError):
            # 不使用异常正文；JSONDecodeError 等可能带有整段凭据。
            self.error_label.setText("JSON 格式或根容器类型不正确；请检查括号、字段重复和数值类型。")
            self.error_label.show()
            return
        self.error_label.hide()
        super().accept()


def catalog_entry(catalog: list[dict], reference: str) -> dict:
    return next((item for item in catalog if item.get("reference") == reference), {})


def argument_specs(entry: dict, group: str, method: str) -> list[dict]:
    specs = list(entry.get("args") or []) if group == "task" else []
    groups = entry.get(group + "_args") or {}
    if isinstance(groups, dict):
        specs.extend(groups.get(method) or [])
    for option in entry.get(group + "_options") or []:
        if isinstance(option, dict) and option.get("method") == method:
            specs.extend(option.get("args") or [])
    by_name: dict[str, dict] = {}
    for spec in specs:
        if isinstance(spec, dict) and isinstance(spec.get("name"), str) and spec["name"]:
            by_name[spec["name"]] = deepcopy(spec)
    return list(by_name.values())


class ArgsEditor(QWidget):
    """Manifest 参数表单；default/env 只提示，未知 args 和未编辑值原样保留。"""

    changed = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._base: dict = {}
        self._specs: list[dict] = []
        self._edited: set[str] = set()
        self._removed: set[str] = set()
        self._json_values: dict[str, Any] = {}
        self.fields: dict[str, QWidget] = {}
        self._loading = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        self.hint = label("模板尚无参数声明；可通过 JSON 编辑任意参数。默认值和环境变量只作提示，不写回。")
        layout.addWidget(self.hint)
        self.form = configure_form(QFormLayout())
        layout.addLayout(self.form)
        self.json_button = button("编辑完整 args JSON", self.edit_json, "quiet")
        layout.addWidget(self.json_button, 0, Qt.AlignmentFlag.AlignLeft)

    def set_value(self, value: Any, specs: list[dict] | None = None) -> None:
        self._base = deepcopy(value) if isinstance(value, dict) else {}
        self._specs = deepcopy(specs or [])
        self._edited.clear()
        self._removed.clear()
        self._json_values.clear()
        self._render()

    def set_specs(self, specs: list[dict]) -> None:
        # 无效的数字输入仍留在原控件中，不能因后台 catalog 到达而丢失。
        try:
            current = self.value()
        except ConfigError:
            return
        dirty = self.has_pending_changes()
        self.set_value(current, specs)
        if dirty:
            self._edited.add("\0json")

    def has_pending_changes(self) -> bool:
        return bool(self._edited or self._removed)

    def _render(self) -> None:
        self._loading = True
        while self.form.rowCount():
            self.form.removeRow(0)
        self.fields = {}
        try:
            for spec in self._specs:
                name = spec["name"]
                kind = spec.get("type", spec.get("kind", "str"))
                secret = bool(spec.get("secret")) or is_sensitive_key(name)
                present = name in self._base
                value = self._base.get(name)
                row = QWidget()
                column = QVBoxLayout(row)
                column.setContentsMargins(0, 0, 0, 0)
                column.setSpacing(5)
                line = QHBoxLayout()
                if kind == "json":
                    field = button("编辑 JSON" if present else "未设置 · 编辑 JSON", lambda key=name: self._edit_json_arg(key))
                elif kind == "bool" and not secret:
                    field = QComboBox()
                    field.addItems(["未设置（使用默认值/环境变量）", "true", "false"])
                    field.setCurrentIndex(1 if value is True else 2 if value is False else 0)
                    field.currentIndexChanged.connect(lambda _index, key=name: self._touch(key))
                else:
                    field = SecretEdit() if secret else OpenCombo() if spec.get("choices") else QLineEdit()
                    text = str(value) if value is not None else ""
                    if isinstance(field, OpenCombo):
                        field.choices([str(choice) for choice in spec["choices"]])
                        field.setEditText(text if present else "")
                        field.currentTextChanged.connect(lambda _text, key=name: self._touch(key))
                    else:
                        field.setText(text if present else "")
                        field.setPlaceholderText("未设置：保留默认值/环境变量")
                        field.textChanged.connect(lambda _text, key=name: self._touch(key))
                field.setObjectName("arg_" + name)
                self.fields[name] = field
                line.addWidget(field, 1)
                clear = button("恢复默认", lambda key=name: self.remove_argument(key), "quiet")
                clear.setToolTip("删除这个参数键，恢复默认值或环境变量回退")
                line.addWidget(clear)
                column.addLayout(line)
                hints = []
                if spec.get("required"):
                    hints.append("必需")
                if spec.get("env"):
                    hints.append("环境变量：" + str(spec["env"]))
                if "default" in spec and spec["default"] is not None and not secret:
                    hints.append("默认值：" + json.dumps(spec["default"], ensure_ascii=False))
                if spec.get("minimum") is not None or spec.get("maximum") is not None:
                    hints.append(f"范围：{spec.get('minimum', '不限')} 至 {spec.get('maximum', '不限')}")
                if spec.get("help"):
                    hints.append(str(spec["help"]))
                if hints:
                    column.addWidget(label("；".join(hints)))
                self.form.addRow(label(str(spec.get("title") or name), ""), row)
            self.hint.setText("未设置的值不会写回；默认值/环境变量仅提示。未知参数通过完整 JSON 保留。")
        finally:
            self._loading = False

    def _touch(self, name: str) -> None:
        if self._loading:
            return
        self._edited.add(name)
        self._removed.discard(name)
        self.changed.emit()

    def remove_argument(self, name: str) -> None:
        self._removed.add(name)
        self._edited.discard(name)
        # 清空显示但不触发 textChanged 覆盖删除意图。
        self._loading = True
        field = self.fields.get(name)
        if isinstance(field, QComboBox):
            if isinstance(field, OpenCombo):
                field.setEditText("")
            else:
                field.setCurrentIndex(0)
        elif isinstance(field, (QLineEdit, SecretEdit)):
            field.setText("")
        elif isinstance(field, QPushButton):
            field.setText("未设置 · 编辑 JSON")
        self._loading = False
        self.changed.emit()

    def _edit_json_arg(self, name: str) -> None:
        value = self._json_values.get(name, self._base.get(name))
        dialog = JsonDialog("参数 JSON（可能含凭据）", value, self, expected_type=None)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.has_changes():
            self._json_values[name] = dialog.value()
            self.fields[name].setText("编辑 JSON")
            self._touch(name)

    def edit_json(self) -> None:
        try:
            value = self.value()
        except ConfigError:
            self.hint.setText("请先修复当前参数的数字或类型输入，再打开完整 JSON。")
            return
        dialog = JsonDialog("完整 args JSON（可能含凭据）", value, self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.has_changes():
            self.set_value(dialog.value(), self._specs)
            self._edited.add("\0json")
            self.changed.emit()

    def value(self) -> dict:
        result = deepcopy(self._base)
        for spec in self._specs:
            name = spec["name"]
            if name not in self._edited:
                continue
            kind = spec.get("type", spec.get("kind", "str"))
            field = self.fields[name]
            if kind == "json":
                result[name] = deepcopy(self._json_values.get(name))
                continue
            if isinstance(field, QComboBox) and not isinstance(field, OpenCombo):
                index = field.currentIndex()
                if index == 0:
                    result.pop(name, None)
                    continue
                value: Any = index == 1
            else:
                text = field.currentText() if isinstance(field, OpenCombo) else field.text()
                value = text
                if kind in {"int", "float", "bool"}:
                    try:
                        if kind == "int":
                            value = int(text)
                        elif kind == "float":
                            value = float(text)
                            if not math.isfinite(value):
                                raise ValueError
                        else:
                            if text not in {"true", "false"}:
                                raise ValueError
                            value = text == "true"
                    except ValueError:
                        raise ConfigError("参数类型错误：请输入有效的整数、有限小数或 true/false") from None
            if type(value) in (int, float):
                low, high = spec.get("minimum"), spec.get("maximum")
                if low is not None and value < low or high is not None and value > high:
                    raise ConfigError("参数数值超出模板声明的范围")
            if spec.get("choices") and value not in spec["choices"]:
                raise ConfigError("参数值不在模板声明的可选项中")
            result[name] = value
        for name in self._removed:
            result.pop(name, None)
        return result


#: 任务访问链的三种形态（下拉框顺序即索引）。
CHAIN_MODES = ("不使用访问链（沿用登录方式与任务方式）", "使用模板默认访问链", "自定义访问链")


def _chain_mode_index(chain: Any) -> int:
    if chain is None:
        return 0
    if isinstance(chain, dict) and (
        str(chain.get("use") or "").strip().lower() == "custom"
        or (not chain.get("use") and chain.get("steps") is not None)
    ):
        return 2
    return 1


class TaskDialog(QDialog):
    """完整任务编辑，ID 只读，policy 继承与整组替代明确区分。"""

    def __init__(
        self, task: dict, parent: QWidget | None = None, *, account: dict | None = None,
        catalog: list[dict] | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("编辑任务")
        self._task = deepcopy(task)
        self._account = deepcopy(account or {})
        self._catalog = deepcopy(catalog or [])
        self._dirty: set[str] = set()
        self._loading = True
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(14)
        layout.addWidget(label("编辑任务", "pageTitle"))
        layout.addWidget(label("设置执行方式、任务参数与依赖。应用后返回账号草稿，保存配置后生效。"))
        area = QScrollArea()
        self.scroll_area = area
        area.setWidgetResizable(True)
        area.setFrameShape(QScrollArea.Shape.NoFrame)
        content = QWidget()
        column = QVBoxLayout(content)
        column.setContentsMargins(0, 0, 6, 4)
        column.setSpacing(16)
        basic = SectionCard("基本信息", "稳定任务 ID 用于关联历史结果，不随标题变化。留空的覆盖项使用账号或引擎默认设置。")
        form = configure_form(QFormLayout())
        self.fields: dict[str, QWidget] = {}
        for key, title in (("id", "稳定任务 ID"), ("title", "任务标题"), ("template", "任务模板覆盖"),
                           ("method", "任务方式"), ("text_label", "结果列标题"), ("timeout", "超时（秒）")):
            field = OpenCombo() if key in {"template", "method"} else QLineEdit()
            field.setObjectName("task_" + key)
            field.setAccessibleName(title)
            value = task.get(key)
            text = "" if value is None else str(value)
            if isinstance(field, OpenCombo):
                field.setEditText(text)
                field.currentTextChanged.connect(lambda _text, name=key: self._touch(name))
            else:
                field.setText(text)
                field.textChanged.connect(lambda _text, name=key: self._touch(name))
            if key == "id":
                field.setReadOnly(True)
            if key == "timeout":
                field.setPlaceholderText("默认超时；可设置 1–7200 秒")
            self.fields[key] = field
            form.addRow(title, field)
        self.enabled = QCheckBox("启用此任务")
        self.enabled.setChecked(task.get("enabled", True) is not False)
        self.enabled.toggled.connect(lambda _value: self._touch("enabled"))
        form.addRow("运行状态", self.enabled)
        basic.body.addLayout(form)
        column.addWidget(basic)
        dependencies = SectionCard("执行依赖", "前置任务必须存在且不能成环。单独运行时会自动包含前置依赖。")
        self.depends_on = QLineEdit()
        self.depends_on.setObjectName("task_depends_on")
        self.depends_on.setAccessibleName("前置任务 ID 数组")
        self.depends_on.setText(json.dumps(task.get("depends_on", []), ensure_ascii=False))
        self.depends_on.setPlaceholderText('["daily"]，无依赖时使用 []')
        self.depends_on.textChanged.connect(lambda _text: self._touch("depends_on"))
        dependencies.body.addWidget(self.depends_on)
        column.addWidget(dependencies)
        arguments = SectionCard("任务参数")
        self.args_editor = ArgsEditor()
        self.args_editor.set_value(task.get("args"))
        self.args_editor.changed.connect(lambda: self._touch("args"))
        arguments.body.addWidget(self.args_editor)
        column.addWidget(arguments)
        advanced = SectionCard("策略与流程", "任务独立策略会整体替代账号策略；省略或 null 才表示继承。Flow 按阶段覆盖。")
        self.policy_mode = QComboBox()
        self.policy_mode.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.policy_mode.setMinimumContentsLength(16)
        self.policy_mode.setAccessibleName("任务策略继承方式")
        self.policy_mode.addItems(["继承账号策略（省略 policy）", "继承账号策略（显式 null）", "任务独立策略（整体替代）"])
        self.policy_mode.setCurrentIndex(0 if "policy" not in task else 1 if task["policy"] is None else 2)
        self.policy_mode.currentIndexChanged.connect(self._policy_changed)
        advanced.body.addWidget(self.policy_mode)
        actions = FlowLayout()
        self.policy_button = button("编辑独立策略", lambda: self._edit_section("policy"))
        self.policy_button.setEnabled(self.policy_mode.currentIndex() == 2)
        actions.addWidget(self.policy_button)
        actions.addWidget(button("编辑任务 flow", lambda: self._edit_section("flow"), "quiet"))
        advanced.body.addLayout(actions)
        column.addWidget(advanced)
        chain = SectionCard("访问链", "失败时尝试下一步，任一步成功即结束。与“前置任务成功后执行”的任务依赖不同。")
        self.chain_mode = QComboBox()
        self.chain_mode.setObjectName("task_chain_mode")
        self.chain_mode.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.chain_mode.setMinimumContentsLength(16)
        self.chain_mode.addItems(list(CHAIN_MODES))
        self.chain_mode.setCurrentIndex(_chain_mode_index(task.get("chain")))
        self.chain_mode.currentIndexChanged.connect(self._chain_changed)
        chain.body.addWidget(self.chain_mode)
        self.chain_summary = label("")
        self.chain_summary.setObjectName("task_chain_summary")
        self.chain_summary.setWordWrap(True)
        chain.body.addWidget(self.chain_summary)
        self.chain_button = button("打开可视化编辑器", self._edit_chain, "primary")
        self.chain_button.setEnabled(True)
        chain.body.addWidget(self.chain_button, 0, Qt.AlignmentFlag.AlignLeft)
        chain.body.addWidget(label("配置访问链后，由它决定凭据来源与 HTTP / 浏览器方式。任务方式、账号登录方式及 flow 的 login / execute 对本任务不再生效。"))
        column.addWidget(chain)
        column.addStretch(1)
        area.setWidget(content)
        layout.addWidget(area, 1)
        self.error_label = label("", "error")
        self.error_label.hide()
        layout.addWidget(self.error_label)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("应用任务")
        buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("kind", "primary")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._loading = False
        self._refresh_catalog()
        fit_dialog(self, 820, 780, (500, 420))

    def _touch(self, name: str) -> None:
        if self._loading or name == "id":
            return
        self._dirty.add(name)
        if name in {"method", "template"}:
            self._refresh_catalog()

    def _refresh_catalog(self) -> None:
        reference = self.fields["template"].currentText() or str(self._account.get("template") or "auto")
        entry = catalog_entry(self._catalog, reference)
        self.fields["template"].choices([str(item["reference"]) for item in self._catalog if item.get("reference")])
        self.fields["method"].choices([str(method) for method in entry.get("task_methods", [])])
        self.args_editor.set_specs(argument_specs(entry, "task", self.fields["method"].currentText()))
        self._refresh_chain_summary()

    def _template_chain(self) -> list[dict]:
        reference = self.fields["template"].currentText() or str(self._account.get("template") or "auto")
        chain = catalog_entry(self._catalog, reference).get("chain")
        return [deepcopy(item) for item in chain if isinstance(item, dict)] if isinstance(chain, list) else []

    def _refresh_chain_summary(self) -> None:
        if hasattr(self, "chain_summary"):
            self.chain_summary.setText("当前：" + core.chain_summary(self._task.get("chain"), self._template_chain()))

    def _chain_changed(self, index: int) -> None:
        if self._loading:
            return
        current = self._task.get("chain")
        if index == 0:
            self._task.pop("chain", None)
        elif index == 1:
            self._task["chain"] = {"use": "template"}
        elif not (isinstance(current, dict) and current.get("steps") is not None):
            # 从模板默认链起步（没有就给最常见的 HTTP → 浏览器两步），再按需修改。
            steps = self._template_chain() or [
                {"id": "http", "kind": "http", "title": "HTTP"},
                {"id": "browser", "kind": "browser", "title": "浏览器"},
            ]
            self._task["chain"] = {"use": "custom", "steps": steps}
        self.chain_button.setEnabled(True)
        self._dirty.add("chain")
        self._refresh_chain_summary()

    def _edit_chain(self) -> None:
        from .chain_editor import ChainEditorDialog

        try:
            current_task = self.value()
        except (ConfigError, ValueError):
            self.error_label.setText("请先修复任务属性中的错误，再打开访问链编辑器。")
            self.error_label.show()
            return
        dialog = ChainEditorDialog(
            self._task.get("chain"), self._template_chain(), self,
            account=self._account, task=current_task,
        )
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.has_changes():
            value = dialog.value()
            if value is None:
                self._task.pop("chain", None)
            else:
                self._task["chain"] = value
            self._dirty.add("chain")
            self.chain_mode.blockSignals(True)
            self.chain_mode.setCurrentIndex(_chain_mode_index(value))
            self.chain_mode.blockSignals(False)
            self._refresh_chain_summary()

    def _policy_changed(self, index: int) -> None:
        if self._loading:
            return
        if index == 0:
            self._task.pop("policy", None)
        elif index == 1:
            self._task["policy"] = None
        elif not isinstance(self._task.get("policy"), dict):
            self._task["policy"] = {}
        self.policy_button.setEnabled(index == 2)
        self._dirty.add("policy")

    def _edit_section(self, key: str) -> None:
        current = deepcopy(self._task.get(key, {}))
        dialog = JsonDialog("任务 " + key + " JSON", current, self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.has_changes():
            self._task[key] = dialog.value()
            self._dirty.add(key)

    def value(self) -> dict:
        result = deepcopy(self._task)
        for key in self._dirty & {"template", "method", "title", "text_label"}:
            field = self.fields[key]
            result[key] = field.currentText() if isinstance(field, OpenCombo) else field.text()
        if "enabled" in self._dirty:
            result["enabled"] = self.enabled.isChecked()
        if "timeout" in self._dirty:
            text = self.fields["timeout"].text().strip()
            if not text:
                result.pop("timeout", None)
            else:
                try:
                    number = int(text)
                except ValueError:
                    raise ConfigError("任务 timeout 必须为整数") from None
                if not 1 <= number <= 7200:
                    raise ConfigError("任务 timeout 必须在 1 到 7200 秒之间")
                result["timeout"] = number
        if "depends_on" in self._dirty:
            deps = core._decode_json(self.depends_on.text())
            if not isinstance(deps, list) or any(not isinstance(dep, str) or not dep.strip() for dep in deps):
                raise ConfigError("任务 depends_on 必须是非空任务 ID 的 JSON 数组")
            result["depends_on"] = deps
        if self.args_editor.has_pending_changes():
            result["args"] = self.args_editor.value()
        return result

    def accept(self) -> None:
        try:
            result = self.value()
            tasks = deepcopy(self._account.get("tasks") or [])
            found = next((index for index, task in enumerate(tasks) if task.get("id") == result.get("id")), None)
            if found is None:
                tasks.append(result)
            else:
                tasks[found] = result
            # 未编辑的历史 null 值原样保留；校验副本仅把可省略字段的 null 视作未设置。
            # 不读取账号 URL/凭据文件，也不阻止临时空白账号编辑。
            validation = deepcopy(tasks)
            optional = {"template", "method", "title", "text_label", "timeout", "enabled", "args", "depends_on", "flow"}
            for task in validation:
                for key in optional:
                    if task.get(key, False) is None:
                        task.pop(key)
            core._account({"base_url": "https://validation.invalid", "tasks": validation}, "$.account")
        except (ConfigError, ValueError, TypeError) as exc:
            message = str(exc) if isinstance(exc, ConfigError) else "任务字段类型不正确"
            self.error_label.setText(message)
            self.error_label.show()
            return
        self.error_label.hide()
        super().accept()
