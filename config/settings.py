#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全局参数与 settings.yml 持久配置。

优先级为内置默认值 < SETTINGS 预设 < 本地配置 < CHECKIN_* 临时覆盖。
SETTINGS 支持 YAML、JSON、DTG1 压缩 JSON 或配置文件路径；预设只在首次生成和
补齐缺项时使用，显式保存的本地值不会在重启时被覆盖。CHECKIN_* 只作用于参数类，
不进入持久配置或纯内置的 settings.default.yml 模板。

代理组与节点保存在账号配置（ACCOUNTS.json），不属于 settings。旧版本曾把默认账号
配置的节点写在这里：这些字段只作为迁回账号配置的来源（legacy_proxies），迁回后
由 discard_legacy_proxies 备份并删除，load/save 不会新增它们。

导入只读取配置来初始化参数类，不创建文件、不导入代理 schema；启动边界调用
load 才进行校验、补齐与原子写。非法数值告警并回落，损坏的完整配置则明确报错，
避免丢失尚未迁回的旧节点。LOCK_SIZE 固定为 1，不开放覆盖。
无 PyYAML 的纯标准库诊断模式仅初始化内置值和 CHECKIN_*；实际 load/save 仍明确报错。
"""

from __future__ import annotations

import importlib.util
import json
import math
import os
import sys
import time
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.errors import ConfigError
from config import paths
from config.secret_codec import decode_secret

_ENV_PREFIX = "CHECKIN_"
_FILE_SUFFIXES = {".yml", ".yaml", ".json"}


@dataclass(frozen=True)
class _Parameter:
    """默认值与边界在现有 _env_* 调用处登记，不维护第二份默认列表。"""

    kind: str
    default: int | float | bool | frozenset[int]
    minimum: int | float | None = None
    maximum: int | float | None = None


_PARAMETERS: dict[str, _Parameter] = {}


def _has_yaml() -> bool:
    """诊断报告以 -S/纯标准库运行时，不能在导入期读取任何配置源。"""
    try:
        return importlib.util.find_spec("yaml") is not None
    except (ImportError, ValueError):
        return False


def _yaml_module() -> Any:
    """实际配置读写仍要求 PyYAML，不能把诊断模式的默认值当成应用配置。"""
    try:
        import yaml
    except ImportError:
        raise ConfigError("settings 配置：缺少 PyYAML 依赖，请安装项目依赖后再读写配置") from None
    return yaml


def _settings_file(raw: str) -> Path | None:
    """只有独立文件路径才改变落盘目标，不能把 YAML 中的 URL 当成路径。"""
    if (
        not raw
        or "\n" in raw
        or "\r" in raw
        or raw.startswith(("{", "[", "DTG1:"))
        or "://" in raw
        or ": " in raw
        or ":\t" in raw
    ):
        return None
    try:
        target = Path(raw).expanduser()
        if target.suffix.lower() not in _FILE_SUFFIXES:
            return None
    except (OSError, ValueError, RuntimeError):
        raise ConfigError("SETTINGS 配置文件：路径无效") from None
    return target if target.is_absolute() else paths.REPO_ROOT / target


def settings_path(path: Path | None = None) -> Path:
    """显式路径优先，其次 SETTINGS 文件路径，最后是 paths.SETTINGS_PATH。"""
    if path is not None:
        try:
            return Path(path).expanduser()
        except (TypeError, OSError, ValueError, RuntimeError):
            raise ConfigError("指定配置文件：路径无效") from None
    return _settings_file(os.environ.get("SETTINGS", "").strip()) or Path(paths.SETTINGS_PATH)


def _json_payload(payload: Any, source: str) -> dict[str, Any]:
    """拒绝 YAML 特有类型、非有限数值与循环引用；错误不带原文或用户键名。"""
    if not isinstance(payload, dict):
        raise ConfigError(f"{source}：必须是 YAML/JSON 对象")
    active: set[int] = set()
    checked: set[int] = set()

    def check(value: Any, depth: int = 0) -> None:
        if depth > 100:
            raise ConfigError(f"{source}：嵌套层级超过安全上限")
        kind = type(value)
        if value is None or kind in (bool, int):
            return
        if kind is str:
            try:
                value.encode("utf-8")
            except UnicodeError:
                raise ConfigError(f"{source}：包含不兼容 UTF-8 的文本") from None
            return
        if kind is float:
            if not math.isfinite(value):
                raise ConfigError(f"{source}：包含不兼容 JSON 的非有限数值")
            return
        if kind not in (dict, list):
            raise ConfigError(f"{source}：包含不兼容 JSON 的值类型")
        identity = id(value)
        if identity in active:
            raise ConfigError(f"{source}：不允许递归引用")
        if identity in checked:
            return
        active.add(identity)
        if kind is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise ConfigError(f"{source}：对象键必须是字符串")
                check(key, depth + 1)
                check(item, depth + 1)
        else:
            for item in value:
                check(item, depth + 1)
        active.remove(identity)
        checked.add(identity)

    try:
        check(payload)
        return deepcopy(payload)
    except RecursionError:
        raise ConfigError(f"{source}：嵌套层级超过安全上限") from None


def _check_yaml_keys(node: Any, source: str, checked: set[int] | None = None) -> None:
    """显式重复键会静默吞掉旧节点；正常 YAML merge 的显式覆盖仍允许。"""
    yaml = _yaml_module()
    if checked is None:
        checked = set()
    if node is None or id(node) in checked:
        return
    checked.add(id(node))
    if isinstance(node, yaml.MappingNode):
        names: set[str] = set()
        for key, value in node.value:
            if isinstance(key, yaml.ScalarNode) and key.tag == "tag:yaml.org,2002:str":
                if key.value in names:
                    raise ConfigError(f"{source}：对象包含重复键")
                names.add(key.value)
            _check_yaml_keys(key, source, checked)
            _check_yaml_keys(value, source, checked)
    elif isinstance(node, yaml.SequenceNode):
        for value in node.value:
            _check_yaml_keys(value, source, checked)


def _parse_payload(text: str, source: str) -> dict[str, Any]:
    yaml = _yaml_module()

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name, value in pairs:
            if name in result:
                raise ConfigError(f"{source}：对象包含重复键")
            result[name] = value
        return result

    try:
        decoded = decode_secret(text)
    except ValueError:
        raise ConfigError(f"{source}：压缩 JSON 内容无效") from None
    try:
        # JSON 优先保持科学计数法等值的类型；普通 YAML 使用安全加载器。
        try:
            payload = json.loads(decoded, object_pairs_hook=unique_object)
        except json.JSONDecodeError:
            payload = yaml.safe_load(decoded)
            _check_yaml_keys(yaml.compose(decoded, Loader=yaml.SafeLoader), source)
    except (yaml.YAMLError, ValueError, TypeError, RecursionError, UnicodeError):
        raise ConfigError(f"{source}：YAML/JSON 语法无效") from None
    return _json_payload(payload, source)


def _preset_payload() -> dict[str, Any]:
    raw = os.environ.get("SETTINGS", "").strip()
    if not raw or _settings_file(raw) is not None:
        return {}
    return _parse_payload(raw, "SETTINGS 预设")


def _read_payload(target: Path) -> dict[str, Any] | None:
    try:
        text = target.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, ValueError):
        raise ConfigError("settings 配置文件：读取失败") from None
    return _parse_payload(text, "settings 配置文件")


def _read_sources(target: Path) -> tuple[dict[str, Any], dict[str, Any] | None]:
    preset = _preset_payload()
    current = _read_payload(target)
    # 只补顶层缺项；空值也是用户明确保存的值，不用真值判断覆盖。
    return {**preset, **(current if current is not None else {})}, current


# 不持锁、不写盘，也不导入 config.proxies，避免导入环与测试收集期落盘。
# 无 PyYAML 时报告只需内置参数与 CHECKIN_*；即使文件存在或 SETTINGS 损坏也不读源。
_INITIAL_PAYLOAD, _ = _read_sources(settings_path()) if _has_yaml() else ({}, None)


def _warn(name: str, raw: str, reason: str) -> None:
    """非法覆盖留痕：静默回落会让用户以为覆盖已生效。"""
    print(
        f"[WARN] 环境变量 {_ENV_PREFIX}{name}={raw!r} {reason}，已忽略并沿用默认值。",
        file=sys.stderr,
    )


def _warn_parameter(name: str, reason: str) -> None:
    # 配置值可能误填为节点 URL 或认证字段，告警只输出已知参数名与原因。
    print(
        f"[WARN] settings/SETTINGS 参数 {name} {reason}，运行时沿用内置默认值；原值保留供修正。",
        file=sys.stderr,
    )


def _coerce(parameter: _Parameter, raw: Any) -> Any:
    kind = parameter.kind
    if kind == "flag":
        if type(raw) is bool:
            return raw
        value = str(raw).strip().lower() if type(raw) in (str, int) else ""
        if value in {"1", "true", "yes", "y", "on"}:
            return True
        if value in {"0", "false", "no", "n", "off"}:
            return False
        raise ValueError("不是布尔值")
    if kind == "int_set":
        if type(raw) is str:
            parts = [part.strip() for part in raw.split(",") if part.strip()]
            if not parts:
                raise ValueError("不是有效整数集合")
        elif type(raw) is list:
            parts = raw
        else:
            raise ValueError("不是整数数组或逗号分隔的整数集合")
        if any(type(part) not in (int, str) for part in parts):
            raise ValueError("集合中包含非法整数")
        try:
            return frozenset(int(part) for part in parts)
        except (ValueError, OverflowError):
            raise ValueError("集合中包含非法整数") from None
    if kind == "int":
        if type(raw) not in (int, str):
            raise ValueError("不是合法整数")
        try:
            value = int(raw)
        except (ValueError, OverflowError):
            raise ValueError("不是合法整数") from None
        if parameter.minimum is not None and value < parameter.minimum:
            raise ValueError(f"小于下限 {parameter.minimum}")
    else:
        if type(raw) not in (int, float, str):
            raise ValueError("不是合法浮点数")
        try:
            value = float(raw)
        except (ValueError, OverflowError):
            raise ValueError("不是合法浮点数") from None
        if not math.isfinite(value):
            raise ValueError("不是有限数值（inf/nan）")
        if parameter.minimum is not None and value <= parameter.minimum:
            raise ValueError(f"不大于下限 {parameter.minimum}")
    if parameter.maximum is not None and value > parameter.maximum:
        raise ValueError(f"超过上限 {parameter.maximum}")
    return value


def _effective_value(name: str) -> Any:
    parameter = _PARAMETERS[name]
    value = parameter.default
    if name in _INITIAL_PAYLOAD:
        try:
            value = _coerce(parameter, _INITIAL_PAYLOAD[name])
        except ValueError as exc:
            _warn_parameter(name, str(exc))
    raw = os.environ.get(_ENV_PREFIX + name, "").strip()
    if raw:
        try:
            return _coerce(parameter, raw)
        except ValueError as exc:
            _warn(name, raw, str(exc))
    return value


def _env_int(name: str, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    """登记整数默认值并读取配置与临时环境覆盖。"""
    _PARAMETERS[name] = _Parameter("int", default, minimum, maximum)
    return _effective_value(name)


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float = 0.0,
    maximum: float | None = None,
) -> float:
    """登记浮点默认值与有限数值边界，读取配置与临时环境覆盖。"""
    _PARAMETERS[name] = _Parameter("float", default, minimum, maximum)
    return _effective_value(name)


def _env_flag(name: str, default: bool) -> bool:
    """登记布尔默认值并读取配置与临时环境覆盖。"""
    _PARAMETERS[name] = _Parameter("flag", default)
    return _effective_value(name)


def _env_int_set(name: str, default: frozenset[int]) -> frozenset[int]:
    """登记集合默认值并读取整数数组或逗号分隔的临时环境覆盖。"""
    _PARAMETERS[name] = _Parameter("int_set", default)
    return _effective_value(name)


class Timeouts:
    """超时配置（单位：秒）。"""

    # 单次 HTTP 请求（urllib opener.open timeout）
    HTTP_REQUEST: int = _env_int("HTTP_REQUEST", 30, maximum=300)

    # HTTP 签到任务总超时（无浏览器路径）
    HTTP_TASK: float = _env_float("HTTP_TASK", 120.0, maximum=1800.0)

    # 浏览器签到任务总超时（browser/oauth/relogin）
    BROWSER_TASK: float = _env_float("BROWSER_TASK", 420.0, maximum=7200.0)

    # 浏览器启动 + 清理的额外开销（browser_script 任务 = 脚本超时 + 此值）
    BROWSER_STARTUP_OVERHEAD: float = _env_float(
        "BROWSER_STARTUP_OVERHEAD", 120.0, maximum=1800.0
    )

    # browser_script 默认脚本超时
    BROWSER_SCRIPT_DEFAULT: int = _env_int("BROWSER_SCRIPT_DEFAULT", 240, maximum=7200)

    # browser_script 最大脚本超时上限（防止配置错误导致任务永久挂起）
    BROWSER_SCRIPT_MAX: int = _env_int("BROWSER_SCRIPT_MAX", 3600, maximum=7200)

    # Node.js WASM PoW 辅助脚本超时（checkin_challenge.js）
    NODE_CHALLENGE: int = _env_int("NODE_CHALLENGE", 60, maximum=600)

    # OAuth 回调等待时间（等待浏览器授权后跳转回站点换 token）。
    # 慢出口的 GitHub/linux.do 回跳可能超过 45s；只放宽阶段上限，不延长调用方总预算。
    # 正常回跳提前完成，CHECKIN_OAUTH_WAIT 仍可覆盖。
    OAUTH_WAIT: int = _env_int("OAUTH_WAIT", 90, maximum=300)


class RetryConfig:
    """HTTP 请求重试配置。"""

    # 含首次在内的总尝试次数
    MAX_ATTEMPTS: int = _env_int("RETRY_MAX_ATTEMPTS", 3, maximum=10)

    # 指数退避基数（秒）：第 n 次失败后等待约 base * 2**n
    BACKOFF_BASE: float = _env_float("RETRY_BACKOFF_BASE", 0.8, maximum=60.0)

    # 单次退避上限（秒）
    BACKOFF_CAP: float = _env_float("RETRY_BACKOFF_CAP", 8.0, maximum=120.0)

    # 可触发重试的 HTTP 状态码（瞬时性错误）。
    # 可用 CHECKIN_RETRY_STATUS_CODES=429,503 覆盖（逗号分隔）。
    STATUS_CODES: frozenset[int] = _env_int_set(
        "RETRY_STATUS_CODES", frozenset({429, 500, 502, 503, 504})
    )


class WAFConfig:
    """WAF 绕过配置。"""

    # 单站点 WAF 求解重试次数（每次轮询一种 bypass 策略）
    RETRY_ATTEMPTS: int = _env_int("WAF_RETRY_ATTEMPTS", 4, maximum=20)

    # 连续多少次「整轮」WAF 求解失败后判定出口 IP 被持续风控（熔断）
    # 触发熔断后跳过后续求解，快速失败，避免在被风控的 IP 上空耗数分钟
    BLOCK_THRESHOLD: int = _env_int("WAF_BLOCK_THRESHOLD", 2, maximum=20)


class FileLockConfig:
    """文件锁配置（accounts_store 的跨进程读-改-写互斥）。"""

    # 默认锁获取超时（秒）。并发签到任务多时可适当放大。
    DEFAULT_TIMEOUT: float = _env_float("FILE_LOCK_TIMEOUT", 30.0, maximum=300.0)

    # Windows msvcrt.locking 锁定字节数。msvcrt 语义要求固定值，不开放覆盖。
    LOCK_SIZE: int = 1


class OutputConfig:
    """输出 / 结果配置。"""

    # worker stdout JSON 扫描上限（字节）；worker 输出通常很短，超出部分舍弃
    MAX_OUTPUT_SCAN: int = _env_int("MAX_OUTPUT_SCAN", 4096, minimum=512, maximum=1024 * 1024)


class LogConfig:
    """诊断日志配置。

    站点原始返回值是排查「签到到底被拒在哪一步」的第一手依据：光有一句
    「签到失败」时，既看不出是业务码拒绝、验证码不通过还是被 WAF 换了页面。
    默认打开，但必须限长——个别接口会回整页 HTML，原样刷进 CI 日志既没法看，
    也把真正有用的行顶掉了。
    """

    # 是否输出每次 HTTP 请求的站点原始返回值（经脱敏）
    HTTP_BODY: bool = _env_flag("LOG_HTTP_BODY", True)

    # 单条原始返回值的字符上限，超出部分截断并标注
    HTTP_BODY_MAX: int = _env_int("LOG_HTTP_BODY_MAX", 600, minimum=80, maximum=20000)


#: 旧版本曾把默认账号配置的节点放进 settings；现在只作为迁回账号配置的来源，不再写入。
LEGACY_PROXY_KEYS = ("proxy_groups", "default_proxy_group")


def default_payload() -> dict[str, Any]:
    """返回纯内置默认值的独立副本，不读取环境；代理节点保存在账号配置中。"""
    return {
        name: sorted(parameter.default) if isinstance(parameter.default, frozenset) else parameter.default
        for name, parameter in _PARAMETERS.items()
    }


def _validate_payload(payload: dict[str, Any]) -> None:
    # 参数类只在模块导入/reload 时初始化；这里仅检查，不打断运行中的任务预算。
    for name, parameter in _PARAMETERS.items():
        try:
            _coerce(parameter, payload[name])
        except ValueError as exc:
            _warn_parameter(name, str(exc))


def _split_legacy(source: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """拆出旧版节点字段：它们不属于全局参数，只保留到迁回账号配置为止。"""
    legacy = {key: source[key] for key in LEGACY_PROXY_KEYS if key in source}
    return {key: value for key, value in source.items() if key not in LEGACY_PROXY_KEYS}, legacy


def _validate_legacy(legacy: dict[str, Any]) -> None:
    # 延迟导入，core/schema 的初始化路径可能反向依赖本模块的参数类。
    from config.proxies import parse_groups

    groups = legacy.get("proxy_groups", [])
    if not isinstance(groups, list):
        raise ConfigError("settings 配置：旧版 proxy_groups 必须是对象数组")
    try:
        parsed = parse_groups(groups)
    except ConfigError:
        raise ConfigError("settings 配置：旧版代理组或节点字段无效") from None
    default = legacy.get("default_proxy_group", "")
    if not isinstance(default, str):
        raise ConfigError("settings 配置：旧版 default_proxy_group 必须是字符串")
    if default.strip() and default.strip() not in {group.id for group in parsed}:
        raise ConfigError("settings 配置：旧版 default_proxy_group 引用的代理组不存在")


def _template_path(target: Path) -> Path:
    try:
        if "\x00" in str(target):
            raise ValueError("invalid path")
        resolved = target.resolve()
        template = (
            Path(paths.SETTINGS_DEFAULT_PATH)
            if resolved == Path(paths.SETTINGS_PATH).resolve()
            else target.parent / "settings.default.yml"
        )
        same_file = resolved == template.resolve()
    except (OSError, ValueError, RuntimeError):
        raise ConfigError("settings 配置文件：路径无效") from None
    if same_file:
        raise ConfigError("settings 配置文件：不能把内置默认模板用作实际配置")
    return template


def _dump_payload(payload: dict[str, Any], target: Path) -> str:
    yaml = _yaml_module()
    try:
        if target.suffix.lower() == ".json":
            return json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        return yaml.safe_dump(payload, allow_unicode=True, sort_keys=False, default_flow_style=False)
    except (yaml.YAMLError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise ConfigError("settings 配置：无法序列化为 YAML/JSON") from None


def _sync_defaults(template: Path) -> None:
    text = (
        "# 纯内置默认设置：自动同步，不包含环境覆盖、SETTINGS 预设或用户节点。\n"
        "# LOCK_SIZE 固定为 1，不开放配置。\n"
        + _dump_payload(default_payload(), template)
    )
    try:
        current = template.read_text(encoding="utf-8")
    except (FileNotFoundError, UnicodeError):
        current = None
    if current != text:
        paths.atomic_write_text(template, text)


def load(path: Path | None = None) -> dict[str, Any]:
    """创建/补齐持久配置并同步纯内置模板，返回不含 CHECKIN_* 覆盖的全局参数。

    参数类保持导入时的值；显式保存的全局参数在下次启动生效。未知字段原样保留，
    已有本地键（包括空值）始终优先于 SETTINGS。节点不属于 settings：本地文件里尚未
    迁回的旧节点字段原样保留在文件中，但既不返回，也不会从 SETTINGS 预设写入本地。
    """
    _yaml_module()
    target = settings_path(path)
    template = _template_path(target)
    try:
        with paths.file_lock(target):
            source, current = _read_sources(target)
            payload = {**default_payload(), **_split_legacy(source)[0]}
            _validate_payload(payload)
            _sync_defaults(template)
            stored = {**payload, **_split_legacy(current or {})[1]}
            if current != stored:
                paths.atomic_write_text(target, _dump_payload(stored, target))
    except (OSError, UnicodeError, ValueError):
        raise ConfigError("settings 配置文件：读取或写入失败") from None
    return payload


def legacy_proxies(path: Path | None = None) -> dict[str, Any]:
    """旧版本留在 settings 中的节点字段（本地文件优先于 SETTINGS 预设），仅用于迁回账号配置。

    格式无效时明确报错，不能把损坏的旧节点当成「没有节点」。
    """
    _yaml_module()
    target = settings_path(path)
    try:
        with paths.file_lock(target):
            source, _current = _read_sources(target)
    except (OSError, UnicodeError, ValueError):
        raise ConfigError("settings 配置文件：读取失败") from None
    legacy = _split_legacy(source)[1]
    _validate_legacy(legacy)
    return legacy


def discard_legacy_proxies(path: Path | None = None) -> Path | None:
    """节点已保存到账号配置后，删除本地 settings 中的旧节点字段；返回备份路径。

    删除前先备份原文件（只有空的默认值时无需备份）；备份失败则不删除。SETTINGS 预设
    （如 CI Secret）无法在此修改，需要用户自行移除其中的节点字段。
    """
    _yaml_module()
    target = settings_path(path)
    try:
        with paths.file_lock(target):
            current = _read_payload(target)
            if current is None:
                return None
            remaining, legacy = _split_legacy(current)
            if not legacy:
                return None
            backup = None
            if any(legacy.values()):
                backup = target.with_name(target.name + f".bak-proxies-{time.strftime('%Y%m%d%H%M%S')}")
                backup.write_bytes(target.read_bytes())
            paths.atomic_write_text(target, _dump_payload(remaining, target))
    except (OSError, UnicodeError, ValueError):
        raise ConfigError("settings 配置文件：清理旧节点字段失败") from None
    return backup


def save(payload: dict[str, Any], path: Path | None = None) -> Path:
    """按目标路径保存全局参数，补齐缺省值但不引入 CHECKIN_* 临时覆盖。

    代理组与节点保存在账号配置中，传入节点字段会被拒绝；文件中尚未迁回的旧节点字段原样保留。
    """
    _yaml_module()
    target = settings_path(path)
    template = _template_path(target)
    provided = _json_payload(payload, "待保存的 settings 配置")
    if any(key in provided for key in LEGACY_PROXY_KEYS):
        raise ConfigError("settings 配置：代理组与节点保存在账号配置（ACCOUNTS.json）中，不能写入 settings")
    completed = {**default_payload(), **_split_legacy(_preset_payload())[0], **provided}
    _validate_payload(completed)
    try:
        with paths.file_lock(target):
            current = _read_payload(target)
            _sync_defaults(template)
            stored = {**completed, **_split_legacy(current or {})[1]}
            if current != stored:
                paths.atomic_write_text(target, _dump_payload(stored, target))
    except (OSError, UnicodeError, ValueError):
        raise ConfigError("settings 配置文件：读取或写入失败") from None
    return target


def _validate() -> None:
    """交叉约束校验：单个值合法但组合矛盾时同样会让任务必然失败。

    只告警不抛异常：这里失败会让所有入口无法导入 config，而这些组合问题
    通常仍能跑完（只是行为不符合预期），留痕比中断更合适。
    """
    if Timeouts.BROWSER_SCRIPT_DEFAULT > Timeouts.BROWSER_SCRIPT_MAX:
        print(
            f"[WARN] BROWSER_SCRIPT_DEFAULT={Timeouts.BROWSER_SCRIPT_DEFAULT} "
            f"大于 BROWSER_SCRIPT_MAX={Timeouts.BROWSER_SCRIPT_MAX}，"
            "缺省脚本超时会突破上限。",
            file=sys.stderr,
        )
    if Timeouts.HTTP_REQUEST >= Timeouts.HTTP_TASK:
        print(
            f"[WARN] HTTP_REQUEST={Timeouts.HTTP_REQUEST} 不小于 "
            f"HTTP_TASK={Timeouts.HTTP_TASK}，单次请求可能吃满整个任务预算。",
            file=sys.stderr,
        )
    if RetryConfig.BACKOFF_BASE > RetryConfig.BACKOFF_CAP:
        print(
            f"[WARN] RETRY_BACKOFF_BASE={RetryConfig.BACKOFF_BASE} 大于 "
            f"RETRY_BACKOFF_CAP={RetryConfig.BACKOFF_CAP}，退避上限失效。",
            file=sys.stderr,
        )


_validate()
