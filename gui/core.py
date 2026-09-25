"""不依赖 Qt 的 v3 原始 JSON 草稿操作；schema 只用于校验和执行。"""

from __future__ import annotations

import hashlib
import json
import math
import os
from collections.abc import Iterable, Sequence
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from config import migrate, schema
from config.proxies import network_from_payload, network_mode, parse_groups, resolve_proxy, validate_proxy_config
from core.account import CREDENTIAL_FIELDS, slug_seed, slugify
from core.chain import parse_chain
from core.errors import ConfigError
from core.manifest import STAGES

__all__ = [
    "chain_summary", "credential_changes", "fingerprint", "import_accounts", "selected_task_ids",
    "unique_id", "validate_payload",
]


def _fail(path: str, reason: str) -> None:
    # 路径只使用代码里的已知字段和数组下标，不回显名称、未知键或凭据正文。
    raise ConfigError(f"配置 {path}：{reason}")


def _json_value(value: Any, path: str = "$", active: set[int] | None = None) -> None:
    active = set() if active is None else active
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            _fail(path, "数字必须是有限值")
        return
    if not isinstance(value, (dict, list)):
        _fail(path, "必须使用 JSON 对象、数组或基本值")
    if id(value) in active:
        _fail(path, "JSON 容器不能循环引用")
    active.add(id(value))
    try:
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    _fail(path, "对象的键必须是字符串")
                _json_value(item, path + ".<字段>", active)
        else:
            for index, item in enumerate(value):
                _json_value(item, f"{path}[{index}]", active)
    finally:
        active.remove(id(value))


def fingerprint(payload: dict) -> str:
    """规范 JSON 的 SHA256；脏状态、日志只应记录摘要，不记录原文。"""
    try:
        _object(payload, "$")
        _json_value(payload)
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    except (RecursionError, UnicodeError):
        raise ConfigError("配置 JSON 嵌套过深或字符编码无效") from None


def unique_id(seed: str, taken: Iterable[str]) -> str:
    """稳定、可读的 ID；冲突时顺序添加 -2、-3。"""
    base = slugify(seed)
    used = set(taken)
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def _object(value: Any, path: str) -> dict:
    if not isinstance(value, dict):
        _fail(path, "必须是 JSON 对象")
    return value


def _array(value: Any, path: str) -> list:
    if not isinstance(value, list):
        _fail(path, "必须是 JSON 数组")
    return value


def _string(value: Any, path: str, *, nonempty: bool = False) -> None:
    if not isinstance(value, str):
        _fail(path, "必须是字符串")
    if nonempty and not value.strip():
        _fail(path, "不能为空")


def _strings(section: dict, names: Iterable[str], path: str) -> None:
    for name in names:
        if name in section:
            _string(section[name], f"{path}.{name}")


def _boolean(section: dict, name: str, path: str, *, nullable: bool = False) -> None:
    if name in section and not (nullable and section[name] is None) and type(section[name]) is not bool:
        _fail(f"{path}.{name}", "必须是布尔值 true/false")


def _integer(section: dict, name: str, path: str, minimum: int, maximum: int) -> None:
    if name in section:
        value = section[name]
        if type(value) is not int or not minimum <= value <= maximum:
            _fail(f"{path}.{name}", f"必须是 {minimum} 到 {maximum} 之间的整数")


def _flow(raw: Any, path: str) -> None:
    for stage, value in _object(raw, path).items():
        if stage.strip().lower() not in STAGES:
            _fail(path, "只支持七个阶段：" + "、".join(STAGES))
        stage_path = f"{path}.{stage.strip().lower()}"
        if isinstance(value, str):
            continue
        for item in _array(value, stage_path):
            _string(item, stage_path + "[]")


def _policy(raw: Any, path: str) -> None:
    section = _object(raw, path)
    for name in ("tolerate_failure", "allow_browser", "humanize"):
        _boolean(section, name, path)
    _boolean(section, "headless", path, nullable=True)
    _integer(section, "retry", path, 0, 10)


def _login(raw: Any, path: str) -> None:
    section = _object(raw, path)
    _strings(section, ("method", "provider", "account"), path)
    if "args" in section:
        _object(section["args"], path + ".args")
    if "fallback" in section:
        for index, item in enumerate(_array(section["fallback"], path + ".fallback")):
            _login(item, f"{path}.fallback[{index}]")


def _url(value: Any, path: str) -> None:
    _string(value, path, nonempty=True)
    try:
        parts = urlsplit(value.strip())
        valid = parts.scheme.lower() in {"http", "https"} and bool(parts.hostname)
        valid = valid and parts.username is None and parts.password is None
        valid = valid and not any(char.isspace() or ord(char) < 32 for char in value.strip())
        valid = valid and "\\" not in value and parts.port != 0
    except ValueError:
        valid = False
    if not valid:
        _fail(path, "必须是有效的 http(s) 地址，且不能内嵌账号密码")


def _account(raw: Any, path: str) -> None:
    section = _object(raw, path)
    _strings(section, ("id", "name", "base_url", "url", "template", "cookie_file"), path)
    if "id" in section:
        _string(section["id"], path + ".id", nonempty=True)
    for key in ("base_url", "url"):
        if key in section and section[key]:
            _url(section[key], path + "." + key)
    if not section.get("base_url") and not section.get("url"):
        _fail(path + ".base_url", "缺少站点地址")
    _boolean(section, "enabled", path)
    if "login" in section:
        _login(section["login"], path + ".login")
    if "credentials" in section:
        credentials = _object(section["credentials"], path + ".credentials")
        _strings(credentials, (*CREDENTIAL_FIELDS, "cookie_file"), path + ".credentials")
        if "user_id" in credentials and type(credentials["user_id"]) not in (str, int):
            _fail(path + ".credentials.user_id", "必须是字符串或整数")
    if "user_id" in section and type(section["user_id"]) not in (str, int):
        _fail(path + ".user_id", "必须是字符串或整数")
    if "network" in section:
        network = _object(section["network"], path + ".network")
        _strings(network, ("proxy", "proxy_mode", "proxy_group", "referer_path"), path + ".network")
        _boolean(network, "verify_ssl", path + ".network")
    if "policy" in section:
        _policy(section["policy"], path + ".policy")
    if "flow" in section:
        _flow(section["flow"], path + ".flow")
    if "display" in section:
        _object(section["display"], path + ".display")
    if "tasks" not in section:
        return
    tasks = _array(section["tasks"], path + ".tasks")
    if not tasks:
        _fail(path + ".tasks", "显式任务数组不能为空；请添加任务或禁用账号")
    seen: set[str] = set()
    dependencies: dict[str, list[str]] = {}
    for index, item in enumerate(tasks):
        task_path = f"{path}.tasks[{index}]"
        task = _object(item, task_path)
        _strings(task, ("id", "template", "method", "title", "text_label"), task_path)
        if "id" in task:
            _string(task["id"], task_path + ".id", nonempty=True)
        task_id = task.get("id", f"task{index + 1}").strip()
        if task_id in seen:
            _fail(task_path + ".id", "任务 ID 重复")
        seen.add(task_id)
        _boolean(task, "enabled", task_path)
        _integer(task, "timeout", task_path, 1, 7200)
        if "args" in task:
            _object(task["args"], task_path + ".args")
        if "flow" in task:
            _flow(task["flow"], task_path + ".flow")
        # null 表示继承账号策略；对象（含 {}）是整体替代，不逐字段继承。
        if "policy" in task and task["policy"] is not None:
            _policy(task["policy"], task_path + ".policy")
        if task.get("chain") is not None:
            try:
                parse_chain(task["chain"], label="该任务")
            except ConfigError as exc:
                _fail(task_path + ".chain", exc.message)
        deps = _array(task.get("depends_on", []), task_path + ".depends_on")
        for dep in deps:
            _string(dep, task_path + ".depends_on[]", nonempty=True)
        dependencies[task_id] = [dep.strip() for dep in deps]
    _dependency_order(dependencies, tuple(dependencies), path + ".tasks")


def _dependency_order(graph: dict[str, list[str]], roots: Sequence[str], path: str) -> tuple[str, ...]:
    visited: set[str] = set()
    active: set[str] = set()
    ordered: list[str] = []

    def visit(task_id: str) -> None:
        if task_id not in graph:
            _fail(path + ".depends_on", "前置依赖任务不存在")
        if task_id in active:
            _fail(path + ".depends_on", "任务依赖存在循环")
        if task_id in visited:
            return
        active.add(task_id)
        for dep in graph[task_id]:
            visit(dep)
        active.remove(task_id)
        visited.add(task_id)
        ordered.append(task_id)

    for root in roots:
        visit(root)
    return tuple(ordered)


def _oauth(raw: Any) -> None:
    states = _object(raw, "$.oauth_states")
    normalized: set[str] = set()
    for index, (provider, entry) in enumerate(states.items()):
        path = f"$.oauth_states.<提供商{index + 1}>"
        if not provider.strip() or provider.strip().lower() in normalized:
            _fail(path, "提供商名称为空或规范化后重复")
        normalized.add(provider.strip().lower())
        section = _object(entry, path)
        if "accounts" not in section:
            continue
        accounts = _object(section["accounts"], path + ".accounts")
        for account_index, (name, account) in enumerate(accounts.items()):
            account_path = f"{path}.accounts.<账号{account_index + 1}>"
            if not name.strip():
                _fail(account_path, "共享账号名称不能为空")
            _strings(_object(account, account_path), ("state", "username", "updated_at"), account_path)


def validate_payload(payload: dict, *, path: Path | None = None) -> schema.Document:
    """严格校验但不改草稿；返回 schema 的执行模型，不用它重新生成 JSON。"""
    try:
        _object(payload, "$")
        _json_value(payload)
        if "version" in payload and (type(payload["version"]) is not int or payload["version"] != 3):
            _fail("$.version", "只支持整数版本 3")
        accounts = _array(payload.get("accounts"), "$.accounts")
        ids: set[str] = set()
        for index, account in enumerate(accounts):
            account_path = f"$.accounts[{index}]"
            _account(account, account_path)
            if account.get("id"):
                account_id = account["id"].strip()
                if account_id in ids:
                    _fail(account_path + ".id", "账号 ID 重复")
                ids.add(account_id)
        if "oauth_states" in payload:
            _oauth(payload["oauth_states"])
        # 代理错误只包含安全字段路径，直接呈现可行动的原因。
        validate_proxy_config(payload)
        try:
            # schema 内部部分容器只浅冻结；独立拷贝防止 Document 意外反向修改草稿。
            execution = deepcopy(payload)
            if path is not None:
                for account in execution["accounts"]:
                    for section in (account, account.get("credentials", {})):
                        reference = section.get("cookie_file")
                        if reference and reference.strip() and not Path(reference.strip()).is_absolute():
                            section["cookie_file"] = str(Path(path).resolve().parent / reference.strip())
            document = schema.parse_document(execution, path=path)
        except Exception:
            # schema 的错误可能包含账号名、cookie_file 路径或异常中的凭据正文。
            raise ConfigError("配置 schema 校验失败，请检查字段及 credentials.cookie_file 是否可读取") from None
        parsed_ids = [account.id for account in document.accounts]
        if len(set(parsed_ids)) != len(parsed_ids):
            _fail("$.accounts[].id", "自动生成的账号 ID 与现有 ID 冲突，请显式指定唯一 ID")
        return document
    except (RecursionError, UnicodeError):
        raise ConfigError("配置 JSON 嵌套过深或字符编码无效") from None


def credential_changes(account: dict, baseline: dict | None) -> tuple[str, ...]:
    """只比较五项凭据的存在性和值；显式新增空串、删除字段也算改变。"""
    current = _object(account.get("credentials", {}), "$.credentials")
    previous = _object((baseline or {}).get("credentials", {}), "$.baseline.credentials")
    missing = object()
    return tuple(name for name in CREDENTIAL_FIELDS if current.get(name, missing) != previous.get(name, missing))


def chain_summary(chain: Any, template_chain: Sequence[Any] | None = None) -> str:
    """任务 ``chain`` 配置的一行说明（界面展示用；不含步骤参数）。

    ``template_chain`` 是模板目录里该模板的默认访问链（步骤对象列表，带 title）。
    """
    if chain is None:
        return "未使用（沿用登录方式与任务方式）"
    try:
        spec = parse_chain(chain, label="该任务")
    except ConfigError as exc:
        return f"配置有误：{exc.message}"
    if spec is None:
        return "未使用（沿用登录方式与任务方式）"
    if spec.use == "template":
        titles = [
            str(item.get("title") or item.get("kind") or "?")
            for item in (template_chain or ()) if isinstance(item, dict)
        ]
        if not titles:
            return "模板默认（该模板未声明默认访问链，运行时会报错）"
        return "模板默认（" + " → ".join(titles) + "）"
    from core.chain import ResolvedChain

    resolved = ResolvedChain(source="custom", steps=spec.steps, entry=spec.entry)
    text = "自定义（" + " → ".join(step.label for step in resolved.order()) + "）"
    unreachable = resolved.unreachable()
    if unreachable:
        text += f"；{len(unreachable)} 个步骤不会执行"
    return text


def selected_task_ids(
    account: dict, only_tasks: Sequence[str] = (), *, path: Path | None = None, context: dict | None = None,
) -> tuple[str, ...]:
    """返回任务闭包；共享代理配置来自调用方快照而非磁盘。"""
    spec = validate_payload(account_payload(account, context), path=path).accounts[0]
    if not spec.enabled:
        _fail("$.accounts[].enabled", "账号已禁用，不能运行")
    if isinstance(only_tasks, (str, bytes)) or not all(isinstance(key, str) for key in only_tasks):
        _fail("$.only_tasks", "必须是任务 ID 数组")
    tasks = {task.id: task for task in spec.tasks}
    roots = tuple(only_tasks) or tuple(task.id for task in spec.tasks if task.enabled)
    if not roots:
        _fail("$.accounts[].tasks", "没有启用的任务，不能运行")
    ordered = _dependency_order({key: list(task.depends_on) for key, task in tasks.items()}, roots, "$.accounts[].tasks")
    if any(not tasks[key].enabled for key in ordered):
        _fail("$.accounts[].tasks.enabled", "所选任务或它的前置依赖已禁用")
    return ordered


_LEGACY_MARKERS = frozenset({
    "site_profile", "type", "provider", "auth_method", "checkin_action", "checkin_mode", "mode", "script",
    "script_args", "script_timeout", "api_variant", "verification_mode", "oauth_provider", "oauth_account",
    "oauth_fallback_provider", "oauth_fallback_account", "access_token", "refresh_token", "cookie", "browser_state",
    "token_file", "proxy", "verify_ssl", "referer_path", "tolerate_failure",
})
_MODERN_MARKERS = frozenset({"login", "tasks", "credentials", "network", "policy", "flow", "template"})


def _decode_json(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise ConfigError("JSON 对象存在重复字段，请先修复，避免数据丢失")
            result[key] = value
        return result

    def invalid_number(_value: str) -> None:
        raise ConfigError("JSON 数字必须是有限值")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_number)
    except (ValueError, UnicodeError, RecursionError):
        raise ConfigError("内容不是合法的 UTF-8 JSON，请修复后重试") from None


def _prepare_document(raw: Any, *, allow_single: bool = False) -> tuple[dict, tuple[str, ...], bool]:
    """加载/导入共用：严格识别容器，迁移旧词表，固定缺失 ID。"""
    _json_value(raw)
    source = deepcopy(raw)
    if isinstance(source, list):
        source = {"accounts": source}
    elif allow_single and isinstance(source, dict) and "accounts" not in source and "sites" not in source:
        if "base_url" in source or "url" in source:
            source = {"accounts": [source]}
        elif len(source) == 1 and isinstance(next(iter(source.values())), dict):
            name, item = next(iter(source.items()))
            item.setdefault("name", name)
            source = {"accounts": [item]}
    source = _object(source, "$")
    version = source.get("version")
    if version is not None and (type(version) is not int or version not in (1, 2, 3)):
        _fail("$.version", "仅能导入/加载 v1、v2 或 v3 配置")
    legacy = version in (1, 2) or "sites" in source and "accounts" not in source
    if "accounts" not in source and "sites" in source:
        source["accounts"] = source.pop("sites")
    accounts = _array(source.get("accounts"), "$.accounts")
    notes: list[str] = []
    migrated = legacy
    migrated_ids: set[str] = {
        item["id"].strip() for item in accounts
        if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"].strip()
    }
    for index, item in enumerate(accounts):
        _object(item, f"$.accounts[{index}]")
        is_legacy = version != 3 and not (_MODERN_MARKERS & item.keys()) and (
            legacy or bool(_LEGACY_MARKERS & item.keys())
        )
        if is_legacy:
            if "script_args" in item:
                _object(item["script_args"], f"$.accounts[{index}].script_args")
            try:
                converted, _ = migrate.migrate_account(item, taken=migrated_ids)
                migrated_ids.add(converted["id"])
            except Exception:
                raise ConfigError(f"配置 accounts[{index}] 的旧格式迁移失败，请检查字段类型") from None
            # 迁移器处理已知旧字段；它未识别的扩展不应丢失。
            extras = {key: value for key, value in item.items() if key not in _LEGACY_MARKERS}
            accounts[index] = {**extras, **converted}
            notes.append(f"accounts[{index}] 已从旧版字段迁移至 v3")
            migrated = True
    source["version"] = 3
    # 先预留所有显式 ID，自动 ID 不会抢占后面的显式 ID。
    used = {item["id"].strip() for item in accounts if isinstance(item.get("id"), str) and item["id"].strip()}
    for index, account in enumerate(accounts):
        if "id" not in account:
            try:
                seed = slug_seed(account.get("name"), account.get("base_url") or account.get("url"))
            except (ValueError, TypeError):
                _fail(f"$.accounts[{index}].base_url", "站点地址无效")
            account["id"] = unique_id(seed, used)
            used.add(account["id"])
            notes.append(f"accounts[{index}].id 已在草稿中生成稳定 ID")
        if "tasks" not in account:
            account["tasks"] = [{"id": "daily"}]
            notes.append(f"accounts[{index}].tasks 已在草稿中补足默认 daily 任务")
        if isinstance(account["tasks"], list):
            task_ids = {task["id"].strip() for task in account["tasks"]
                        if isinstance(task, dict) and isinstance(task.get("id"), str) and task["id"].strip()}
            for task_index, task in enumerate(account["tasks"]):
                if isinstance(task, dict) and "id" not in task:
                    task["id"] = unique_id(f"task{task_index + 1}", task_ids)
                    task_ids.add(task["id"])
                    notes.append(f"accounts[{index}].tasks[{task_index}].id 已在草稿中生成稳定 ID")
    if notes and not migrated:
        notes.append("草稿补足的 ID / 默认任务尚未写入文件，请显式保存配置以固定身份")
    return source, tuple(notes), migrated


def _merge_metadata(target: dict, incoming: dict, path: str) -> None:
    for key, value in incoming.items():
        if key not in target:
            target[key] = deepcopy(value)
        elif isinstance(target[key], dict) and isinstance(value, dict):
            _merge_metadata(target[key], value, path)
        elif fingerprint({"value": target[key]}) != fingerprint({"value": value}):
            _fail(path, "导入的共享数据与现有配置冲突，未覆盖任何内容")


def import_accounts(payload: dict, text: str, *, path: Path | None = None) -> dict:
    """原子追加导入；组按 ID 合并，冲突拒绝，不悄悄改变现有账号的路由。"""
    existing = validate_payload(payload, path=path)
    incoming, _, _ = _prepare_document(_decode_json(text), allow_single=True)
    result = deepcopy(payload)
    used = {account.id for account in existing.accounts}
    for account in incoming["accounts"]:
        account_id = account.get("id")
        _string(account_id, "$.accounts[].id", nonempty=True)
        if account_id.strip() in used:
            account["id"] = unique_id(account_id, used)
        used.add(account["id"].strip())
        result["accounts"].append(deepcopy(account))
    if "proxy_groups" in incoming:
        parse_groups(_array(incoming["proxy_groups"], "$.proxy_groups"))
        groups = result.setdefault("proxy_groups", [])
        by_id = {group["id"].strip(): group for group in groups}
        for group in incoming["proxy_groups"]:
            previous = by_id.get(group["id"].strip())
            if previous is not None:
                if fingerprint(previous) != fingerprint(group):
                    _fail("$.proxy_groups", "同 ID 代理组内容冲突，未导入任何内容")
            else:
                groups.append(deepcopy(group))
                by_id[group["id"].strip()] = group
    extras = {key: value for key, value in incoming.items() if key not in {"version", "accounts", "proxy_groups"}}
    _merge_metadata(result, extras, "$.oauth_states / 默认代理组 / 顶层扩展")
    validate_payload(result, path=path)
    return result


def proxy_context(payload: dict | None) -> dict:
    """与账号一起冻结的共享代理字段；不把环境值保存到配置。"""
    source = payload or {}
    return {key: deepcopy(source[key]) for key in ("proxy_groups", "default_proxy_group") if key in source}


def account_payload(account: dict, context: dict | None = None) -> dict:
    return {"version": 3, "accounts": [deepcopy(account)], **proxy_context(context)}


def proxy_status(network: dict | None, payload: dict, *, environ_proxy: str | None = None) -> dict:
    """用于 UI/预览的安全配置状态；有效不代表网络已检测。"""
    try:
        groups, default = validate_proxy_config({**proxy_context(payload), "accounts": [{"network": network or {}}]})
        selection = resolve_proxy(network_from_payload(network), groups, default,
                                  environ_proxy=os.environ.get("CHECKIN_PROXY", "") if environ_proxy is None else environ_proxy)
        return {**selection.to_payload(), "valid": True, "tested": False}
    except ConfigError as exc:
        return {"valid": False, "tested": False, "description": "代理配置不可用：" + exc.message}


def proxy_fingerprint(account: dict, payload: dict) -> str:
    """预览只对影响该账号的组和环境变化失效；摘要不包含可读凭据。"""
    try:
        network = network_from_payload(account.get("network"))
        mode = network_mode(network)
    except ConfigError:
        return fingerprint({"account": account, **proxy_context(payload)})
    group_id = network.proxy_group if mode == "group" else payload.get("default_proxy_group", "") if mode == "inherit" else ""
    if group_id:
        selected = [group for group in payload.get("proxy_groups", []) if group.get("id", "").strip() == group_id]
        return fingerprint({"account": account, "proxy_groups": selected, "group": group_id})
    environ = os.environ.get("CHECKIN_PROXY", "") if mode == "inherit" else ""
    return fingerprint({"account": account, "environment": environ}) if environ else fingerprint(account)
