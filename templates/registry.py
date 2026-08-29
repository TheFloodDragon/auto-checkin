"""模板注册表：内置模板、用户模板与自定义脚本走同一条加载路径。

这是重构诉求 3 的落点——删除封闭的 ``site_profile`` 枚举后，``newapi`` 与
``sub2api`` 只是两个**预置模板**，和用户自己写的模板、站点脚本没有等级差别：

- 同一注册表、同一路径沙箱、同一清单契约、同一继承机制；
- 三种来源：``builtin/*.py``（内置）、``templates/user/*.py|*.toml``（用户）、
  以及配置里直接指向的仓库内脚本路径（``scripts/tasks/xxx.py``）；
- ``extends`` 支持派生：私改站点只要写 ``extends = "newapi"`` + 几个端点覆盖，
  不需要复制整份实现，更不需要改内核。

路径沙箱沿用旧 ``browser/script_loader`` 的四条校验（禁 URL、禁绝对路径、禁 ``..``、
解析后复核仍在仓库内）——这部分实现是正确的，原样迁移。
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from core.errors import TemplateError
from core.manifest import (
    UNITS,
    ArgSchema,
    ArgSpec,
    DetectSpec,
    DisplayDefaults,
    LoginOption,
    ResponseMap,
    TaskOption,
    TemplateManifest,
)

__all__ = [
    "REGISTRY",
    "LoadedTemplate",
    "TemplateRegistry",
    "get",
    "ids",
    "resolve_repo_path",
]

#: 模板路径沙箱的根 = 本文件的上两级（templates/registry.py → templates/ → 根）。
REPO_ROOT = Path(__file__).resolve().parents[1]
USER_DIR = Path(__file__).resolve().parent / "user"
BUILTIN_DIR = Path(__file__).resolve().parent / "builtin"

#: 模板模块可提供的钩子名。全部可选；缺失即由引擎的通用实现兜底。
HOOK_NAMES = ("detect", "login", "fetch_state", "run", "verify", "confirm", "render", "extras")


@dataclass(frozen=True, slots=True)
class LoadedTemplate:
    """解析完继承、绑定好钩子的模板。"""

    manifest: TemplateManifest
    module: ModuleType | None = None
    source: str = "builtin"          # builtin | user | script
    path: str = ""
    hooks: Mapping[str, Callable[..., Any]] = field(default_factory=lambda: MappingProxyType({}))

    @property
    def id(self) -> str:
        return self.manifest.id

    def hook(self, name: str) -> Callable[..., Any] | None:
        return self.hooks.get(name)

    def owns(self, stage: str) -> bool:
        """任一任务方式声明自管该阶段即为真（引擎据此跳过通用探测）。"""
        return any(stage in option.owns for option in self.manifest.task)

    def describe(self) -> str:
        return f"{self.manifest.title or self.id}（{self.source}{f':{self.path}' if self.path else ''}）"


class TemplateRegistry:
    __slots__ = ("_cache", "_builtin_loaders")

    def __init__(self) -> None:
        self._cache: dict[str, LoadedTemplate] = {}
        self._builtin_loaders: dict[str, LoadedTemplate] = {}

    # -- 注册 --
    def register_builtin(self, module: ModuleType) -> LoadedTemplate:
        """登记内置模板模块。与用户模板走同一套清单/钩子解析。"""
        template = _from_module(module, source="builtin", path="")
        self._builtin_loaders[template.id] = template
        return template

    def register(self, template: LoadedTemplate, *, replace_existing: bool = False) -> LoadedTemplate:
        key = template.id
        if key in self._cache and not replace_existing:
            raise TemplateError(f"模板 {key!r} 已注册")
        self._cache[key] = template
        return template

    # -- 查询 --
    def ids(self) -> tuple[str, ...]:
        found = set(self._builtin_loaders) | set(self._cache)
        found |= {path.stem for path in _user_files()}
        return tuple(sorted(found))

    def get(self, reference: str, *, _seen: tuple[str, ...] = ()) -> LoadedTemplate:
        """按 id 或仓库内脚本路径解析模板，并完成 ``extends`` 继承。"""
        key = str(reference or "").strip()
        if not key:
            raise TemplateError("未指定模板")
        cache_key = key.lower()
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        if cache_key in _seen:
            raise TemplateError(f"模板继承出现环：{' → '.join((*_seen, cache_key))}")

        loaded = self._load(key)
        if loaded.manifest.extends:
            parent = self.get(loaded.manifest.extends, _seen=(*_seen, cache_key))
            merged = loaded.manifest.inherit(parent.manifest)
            hooks = dict(parent.hooks)
            hooks.update(dict(loaded.hooks))
            loaded = LoadedTemplate(
                manifest=merged,
                module=loaded.module or parent.module,
                source=loaded.source,
                path=loaded.path,
                hooks=MappingProxyType(hooks),
            )
        _validate_sdk(loaded.manifest)
        self._cache[cache_key] = loaded
        if loaded.id != cache_key:
            self._cache[loaded.id] = loaded
        return loaded

    def clear(self) -> None:
        self._cache.clear()

    # -- 加载 --
    def _load(self, reference: str) -> LoadedTemplate:
        key = reference.strip().lower()

        builtin = self._builtin_loaders.get(key)
        if builtin is not None:
            return builtin

        # 看起来像路径就按脚本加载（scripts/tasks/xxx.py）
        if reference.endswith(".py") or "/" in reference or "\\" in reference:
            path = resolve_repo_path(reference)
            return _load_python(path, source="script")

        for candidate in _user_files():
            if candidate.stem.lower() != key:
                continue
            if candidate.suffix.lower() == ".toml":
                return _load_toml(candidate)
            return _load_python(candidate, source="user")

        known = "、".join(self.ids()) or "（空）"
        raise TemplateError(f"未知模板 {reference!r}；已知模板：{known}")


# ── 路径沙箱 ────────────────────────────────────────────────────────────────
def resolve_repo_path(reference: str) -> Path:
    """校验并解析仓库内相对路径。拒绝 URL / 绝对路径 / ``..`` / 越界。"""
    raw = str(reference or "").strip().replace("\\", "/")
    if not raw:
        raise TemplateError("未配置模板路径")
    parsed = urlparse(raw)
    if parsed.scheme or raw.startswith("//"):
        raise TemplateError("模板路径必须是仓库内相对路径，不能是 URL 或绝对路径")
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        raise TemplateError("模板路径必须是仓库内相对路径，不能使用绝对路径或 ..")
    resolved = (REPO_ROOT / path).resolve()
    try:
        resolved.relative_to(REPO_ROOT.resolve())
    except ValueError as exc:
        raise TemplateError("模板路径超出仓库目录") from exc
    if not resolved.is_file():
        raise TemplateError(f"模板文件不存在：{raw}")
    if resolved.suffix.lower() not in {".py", ".toml"}:
        raise TemplateError("模板只支持 .py 或 .toml")
    return resolved


def _user_files() -> tuple[Path, ...]:
    if not USER_DIR.is_dir():
        return ()
    return tuple(
        sorted(
            path
            for path in USER_DIR.iterdir()
            if path.is_file() and path.suffix.lower() in {".py", ".toml"} and not path.name.startswith("_")
        )
    )


def _load_python(path: Path, *, source: str) -> LoadedTemplate:
    """加载 Python 模板/脚本。

    每次都重新执行、不复用 ``sys.modules``：脚本在两次运行之间可能被修改，
    命中旧缓存会静默执行过期代码（旧实现踩过这个坑并加了注释，这里保留）。
    """
    module_name = f"dailytask_template_{abs(hash(str(path)))}"
    sys.modules.pop(module_name, None)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise TemplateError(f"无法加载模板：{path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException as exc:
        sys.modules.pop(module_name, None)
        raise TemplateError(f"模板 {path.name} 执行失败：{type(exc).__name__}: {exc}") from exc

    return _from_module(module, source=source, path=_relative(path), label=path.name)


def _from_module(module: ModuleType, *, source: str, path: str, label: str = "") -> LoadedTemplate:
    """从模块提取清单与钩子。内置模板与用户脚本共用这一段。"""
    name = label or getattr(module, "__name__", "模板")
    manifest = getattr(module, "MANIFEST", None)
    if not isinstance(manifest, TemplateManifest):
        raise TemplateError(
            f"模板 {name} 必须定义 MANIFEST = TemplateManifest(...)（当前为 {type(manifest).__name__}）"
        )
    hooks = {
        hook: getattr(module, hook)
        for hook in HOOK_NAMES
        if callable(getattr(module, hook, None))
    }
    if "run" not in hooks and not manifest.task:
        raise TemplateError(f"模板 {manifest.id} 既没有 run() 也没有声明任何 task 方式")
    return LoadedTemplate(
        manifest=manifest,
        module=module,
        source=source,
        path=path,
        hooks=MappingProxyType(hooks),
    )


def _load_toml(path: Path) -> LoadedTemplate:
    """加载声明式模板。改私改站点端点不必写一行 Python。"""
    import tomllib

    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise TemplateError(f"模板 {path.name} 解析失败：{exc}") from exc
    return LoadedTemplate(
        manifest=manifest_from_mapping(raw, default_id=path.stem),
        source="user",
        path=_relative(path),
    )


def manifest_from_mapping(raw: Mapping[str, Any], *, default_id: str = "") -> TemplateManifest:
    """从 TOML/JSON 映射构造清单。也供测试与 GUI 预览使用。"""
    template_id = str(raw.get("id") or default_id).strip().lower()
    if not template_id:
        raise TemplateError("模板缺少 id")

    display = raw.get("display") if isinstance(raw.get("display"), Mapping) else {}
    detect_raw = raw.get("detect") if isinstance(raw.get("detect"), Mapping) else None
    return TemplateManifest(
        id=template_id,
        title=str(raw.get("title") or template_id),
        extends=str(raw.get("extends") or "").strip().lower(),
        sdk=int(raw.get("sdk") or 1),
        detect=(
            DetectSpec(
                paths=_tuple(detect_raw.get("paths")),
                markers=_tuple(detect_raw.get("markers")),
                json_keys=_tuple(detect_raw.get("json_keys")),
                weight=float(detect_raw.get("weight") or 1.0),
            )
            if detect_raw
            else None
        ),
        login=tuple(_login_option(item) for item in _list(raw.get("login"))),
        task=tuple(_task_option(item) for item in _list(raw.get("task"))),
        display=DisplayDefaults(
            text_label=str(display.get("text_label") or ""),
            label=str(display.get("label") or ""),
            icon=str(display.get("icon") or ""),
        ),
        capabilities=frozenset(_tuple(raw.get("capabilities"))),
        args=_arg_schema(raw.get("args")),
        endpoints=MappingProxyType(
            {str(k): str(v) for k, v in (raw.get("endpoints") or {}).items()}
        ),
        headers=MappingProxyType(
            {str(k): str(v) for k, v in (raw.get("headers") or {}).items()}
        ),
        response=_response_map(raw.get("response")),
        description=str(raw.get("description") or ""),
    )


def _response_map(raw: Any) -> ResponseMap:
    """解析 ``[response]`` 段：每个语义字段接受字符串或字符串列表。"""
    if not isinstance(raw, Mapping) or not raw:
        return ResponseMap()
    unit = str(raw.get("unit") or "raw").strip().lower()
    if unit not in UNITS:
        raise TemplateError(f"[response].unit 只能是 {'、'.join(UNITS)}，收到 {unit!r}")
    return ResponseMap(
        checked_in=_tuple(raw.get("checked_in")),
        already=_tuple(raw.get("already")),
        awarded=_tuple(raw.get("awarded")),
        balance=_tuple(raw.get("balance")),
        streak=_tuple(raw.get("streak")),
        total=_tuple(raw.get("total")),
        message=_tuple(raw.get("message")),
        unit=unit,
    )


def _login_option(item: Mapping[str, Any]) -> LoginOption:
    return LoginOption(
        method=str(item.get("method") or "").strip().lower(),
        priority=int(item.get("priority") or 50),
        args=_arg_schema(item.get("args")),
        requires=frozenset(_tuple(item.get("requires"))),
        title=str(item.get("title") or ""),
    )


def _task_option(item: Mapping[str, Any]) -> TaskOption:
    return TaskOption(
        method=str(item.get("method") or "").strip().lower(),
        priority=int(item.get("priority") or 50),
        args=_arg_schema(item.get("args")),
        requires=frozenset(_tuple(item.get("requires"))),
        owns=frozenset(_tuple(item.get("owns"))),
        title=str(item.get("title") or ""),
    )


def _arg_schema(raw: Any) -> ArgSchema:
    if not isinstance(raw, Mapping) or not raw:
        return ArgSchema()
    specs: list[ArgSpec] = []
    for name, item in raw.items():
        if not isinstance(item, Mapping):
            # 简写形态：``args = { start_path = "/checkin" }`` 视为带默认值的字符串。
            specs.append(ArgSpec(name=str(name), default=item))
            continue
        specs.append(
            ArgSpec(
                name=str(name),
                kind=str(item.get("kind") or "str"),
                default=item.get("default"),
                required=bool(item.get("required")),
                secret=bool(item.get("secret")),
                env=str(item.get("env") or ""),
                choices=tuple(item.get("choices") or ()),
                title=str(item.get("title") or ""),
                help=str(item.get("help") or ""),
                minimum=item.get("minimum"),
                maximum=item.get("maximum"),
            )
        )
    return ArgSchema(specs)


def _validate_sdk(manifest: TemplateManifest) -> None:
    from sdk import SDK_VERSION

    if manifest.sdk > SDK_VERSION:
        raise TemplateError(
            f"模板 {manifest.id} 需要 SDK v{manifest.sdk}，当前框架只提供 v{SDK_VERSION}，请升级本工具"
        )


def _tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(str(item) for item in value if str(item))
    return (str(value),)


def _list(value: Any) -> tuple[Mapping[str, Any], ...]:
    if isinstance(value, Mapping):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(item for item in value if isinstance(item, Mapping))
    return ()


def _relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)


REGISTRY = TemplateRegistry()


def _bootstrap() -> None:
    from .builtin import newapi, sub2api

    REGISTRY.register_builtin(newapi)
    REGISTRY.register_builtin(sub2api)


_bootstrap()


def get(reference: str) -> LoadedTemplate:
    return REGISTRY.get(reference)


def ids() -> tuple[str, ...]:
    return REGISTRY.ids()
