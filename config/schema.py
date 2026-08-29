"""配置 v3 的内存模型与读写。

与旧 ``accounts_store`` 的差别不只是字段改名：

- **分组而非平铺**。旧 ``SiteConfig`` 27 个平铺字段，新增一项就要同步改 CLI 参数、
  worker 环境变量、GUI 行、Secret 导出四处。现在按 ``login`` / ``tasks`` /
  ``credentials`` / ``network`` / ``policy`` / ``flow`` 分组整体传递。
- **一个账号可以有多个任务**。旧结构里附加任务只能挂在「纯 HTTP 签到成功」这一条
  分支上（``providers/actions/browser_script.py:268``），走浏览器分支就整天不执行。
- **稳定 id**。旧代码用 ``base_url|name`` 拼接串做缓存键与状态键，改个站点名就丢掉
  全部运行期缓存与历史状态。

解析永远**宽进**：未知字段原样保留在 ``extras`` 里（不丢用户手写的东西），非法值给出
带字段名的 ConfigError（而不是静默回落到默认值——那会让用户以为配置生效了）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from core.account import (
    AccountSpec,
    CredentialSet,
    LoginSpec,
    NetworkSpec,
    PolicySpec,
    TaskSpec,
    normalize_base_url,
    slug_seed,
)
from core.errors import ConfigError

__all__ = [
    "CONFIG_VERSION",
    "Document",
    "dump_account",
    "oauth_state_text",
    "parse_account",
    "parse_document",
]

CONFIG_VERSION = 3

DEFAULT_OAUTH_ACCOUNT = "default"
#: 解析器认识的顶层键。其余键原样进 ``AccountSpec.extras``，导出时写回——
#: 没有这一步，任何一次 GUI 保存都会静默抹掉用户手写的字段。
KNOWN_ACCOUNT_KEYS = frozenset(
    {
        "id", "name", "base_url", "url", "template", "enabled",
        "flow", "login", "tasks", "credentials", "network", "policy", "display",
        # 兼容位：这两个在 v3 里搬进了 credentials/login.args，解析时会读走。
        "user_id", "cookie_file",
    }
)
#: ``credentials`` 段里解析器认识的键。
KNOWN_CREDENTIAL_KEYS = frozenset(
    {"access_token", "refresh_token", "cookie", "browser_state", "session_cookie",
     "user_id", "cookie_file"}
)

#: 凭据文件的历史格式：第一行 Cookie，第二行用户 ID，第三行 Access token。
COOKIE_FILE_FIELDS = ("cookie", "user_id", "access_token")


@dataclass(frozen=True, slots=True)
class Document:
    """一份完整配置。运行期只读。"""

    accounts: tuple[AccountSpec, ...] = ()
    oauth_states: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    version: int = CONFIG_VERSION
    path: Path | None = None
    #: 迁移或解析过程中产生的提示，由调用方决定要不要打印。
    notes: tuple[str, ...] = ()

    def account(self, account_id: str) -> AccountSpec | None:
        key = str(account_id or "").strip()
        return next((item for item in self.accounts if item.id == key), None)

    def enabled(self) -> tuple[AccountSpec, ...]:
        return tuple(item for item in self.accounts if item.enabled)

    def oauth_state(self, provider: str, account: str = DEFAULT_OAUTH_ACCOUNT) -> str:
        return oauth_state_text(self.oauth_states, provider, account)

    def to_payload(self) -> dict[str, Any]:
        return {
            "version": CONFIG_VERSION,
            "accounts": [dump_account(item) for item in self.accounts],
            "oauth_states": _dump_oauth_states(self.oauth_states),
        }


def oauth_state_text(states: Any, provider: str, account: str = DEFAULT_OAUTH_ACCOUNT) -> str:
    """取共享 OAuth 登录态文本；缺失返回空串。"""
    if not isinstance(states, Mapping):
        return ""
    entry = states.get(str(provider or "").strip().lower())
    if not isinstance(entry, Mapping):
        return ""
    accounts = entry.get("accounts")
    if not isinstance(accounts, Mapping):
        return ""
    item = accounts.get(str(account or DEFAULT_OAUTH_ACCOUNT).strip())
    if not isinstance(item, Mapping):
        return ""
    return str(item.get("state") or "").strip()


# ── 解析 ────────────────────────────────────────────────────────────────────
def parse_document(raw: Any, *, path: Path | None = None) -> Document:
    if not isinstance(raw, Mapping):
        raise ConfigError("配置文件必须是一个 JSON 对象")
    version = _int(raw.get("version"), CONFIG_VERSION)
    accounts_raw = raw.get("accounts")
    if not isinstance(accounts_raw, list):
        raise ConfigError("配置缺少 accounts 数组")
    accounts: list[AccountSpec] = []
    seen: set[str] = set()
    for index, item in enumerate(accounts_raw):
        if not isinstance(item, Mapping):
            raise ConfigError(f"accounts[{index}] 必须是对象")
        spec = parse_account(item, index=index, taken=seen)
        seen.add(spec.id)
        accounts.append(spec)
    return Document(
        accounts=tuple(accounts),
        oauth_states=MappingProxyType(_parse_oauth_states(raw.get("oauth_states"))),
        version=version,
        path=path,
    )


def parse_account(raw: Mapping[str, Any], *, index: int = 0, taken: Iterable[str] = ()) -> AccountSpec:
    base_url = normalize_base_url(raw.get("base_url") or raw.get("url"))
    name = str(raw.get("name") or "").strip() or base_url
    if not base_url:
        raise ConfigError(f"账号 {name or index} 缺少 base_url")
    account_id = _account_id(raw, name=name, base_url=base_url, taken=set(taken))

    credentials, login_args = _parse_credentials(raw, name=name)
    login = _parse_login(raw.get("login"), extra_args=login_args)
    tasks = _parse_tasks(raw, name=name)
    extras = _collect_extras(raw)

    return AccountSpec(
        id=account_id,
        name=name,
        base_url=base_url,
        template=str(raw.get("template") or "auto").strip() or "auto",
        enabled=_bool(raw.get("enabled"), True),
        login=login,
        tasks=tasks,
        credentials=credentials,
        network=_parse_network(raw.get("network")),
        policy=_parse_policy(raw.get("policy")),
        flow=MappingProxyType(_parse_flow(raw.get("flow"), label=name)),
        display=MappingProxyType(
            {str(k): str(v) for k, v in (raw.get("display") or {}).items() if v not in (None, "")}
        ),
        extras=MappingProxyType(extras),
    )


def _collect_extras(raw: Mapping[str, Any]) -> dict[str, Any]:
    """收集解析器不认识的键，供导出时原样写回。"""
    extras = {
        str(key): value for key, value in raw.items() if str(key) not in KNOWN_ACCOUNT_KEYS
    }
    section = raw.get("credentials")
    if isinstance(section, Mapping):
        unknown = {
            str(key): value
            for key, value in section.items()
            if str(key) not in KNOWN_CREDENTIAL_KEYS
        }
        if unknown:
            extras["credentials"] = unknown
    # cookie_file 被解析成了 cookie/user_id/access_token，但它是**用户写的输入源**，
    # 必须原样留下：否则保存一次就变成了展开后的明文凭据。
    for key in ("cookie_file", "user_id"):
        value = raw.get(key) if raw.get(key) not in (None, "") else (
            section.get(key) if isinstance(section, Mapping) else None
        )
        if value not in (None, ""):
            extras.setdefault("credentials", {})
            if isinstance(extras["credentials"], dict):
                extras["credentials"].setdefault(key, value)
    return extras


def _account_id(raw: Mapping[str, Any], *, name: str, base_url: str, taken: set[str]) -> str:
    explicit = str(raw.get("id") or "").strip()
    if explicit:
        return explicit
    # 没有显式 id 时按名字生成并去重。id 是缓存与历史结果的锚点，必须稳定：
    # 同名账号加数字后缀，而不是靠顺序——顺序会随配置增删而漂移。
    base = slug_seed(name, base_url)
    candidate = base
    suffix = 2
    while candidate in taken:
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def _parse_credentials(raw: Mapping[str, Any], *, name: str) -> tuple[CredentialSet, dict[str, Any]]:
    section = raw.get("credentials")
    values = dict(section) if isinstance(section, Mapping) else {}
    extra_args: dict[str, Any] = {}
    user_id = str(values.pop("user_id", "") or raw.get("user_id") or "").strip()
    if user_id:
        extra_args["user_id"] = user_id

    cookie_file = str(values.pop("cookie_file", "") or raw.get("cookie_file") or "").strip()
    if cookie_file:
        loaded = _read_cookie_file(cookie_file, label=name)
        for key, value in loaded.items():
            if key == "user_id":
                extra_args.setdefault("user_id", value)
            else:
                values.setdefault(key, value)

    known = {
        key: str(values.get(key) or "").strip()
        for key in ("access_token", "refresh_token", "cookie", "browser_state", "session_cookie")
    }
    return CredentialSet(**known), extra_args


def _read_cookie_file(reference: str, *, label: str) -> dict[str, str]:
    """读历史格式的凭据文件。只读不写回。

    旧实现会把去重后的 Cookie 写回该文件（``auto_refresh_cookie``）。运行期改写用户
    的文件是个坏默认：它让「配置」与「运行产物」再次混在一起，而运行产物现在有专门
    的去处（覆盖层）。
    """
    path = Path(reference)
    if not path.is_absolute():
        from . import paths as paths_module

        path = Path(paths_module.REPO_ROOT) / path
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise ConfigError(f"账号 {label} 的凭据文件读取失败（{reference}）：{exc}") from exc
    return {
        field_name: lines[position].strip()
        for position, field_name in enumerate(COOKIE_FILE_FIELDS)
        if position < len(lines) and lines[position].strip()
    }


def _parse_login(raw: Any, *, extra_args: Mapping[str, Any] | None = None) -> LoginSpec:
    if not isinstance(raw, Mapping):
        raw = {}
    args = dict(raw.get("args") or {})
    args.update({k: v for k, v in (extra_args or {}).items() if k not in args})
    fallback: list[LoginSpec] = []
    for item in raw.get("fallback") or ():
        if isinstance(item, Mapping):
            fallback.append(_parse_login(item))
    return LoginSpec(
        method=str(raw.get("method") or "").strip().lower(),
        provider=str(raw.get("provider") or "").strip().lower(),
        account=str(raw.get("account") or DEFAULT_OAUTH_ACCOUNT).strip() or DEFAULT_OAUTH_ACCOUNT,
        args=MappingProxyType(args),
        fallback=tuple(fallback),
    )


def _parse_tasks(raw: Mapping[str, Any], *, name: str) -> tuple[TaskSpec, ...]:
    items = raw.get("tasks")
    if not isinstance(items, list) or not items:
        return (TaskSpec(id="daily", timeout=_default_timeout()),)
    tasks: list[TaskSpec] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise ConfigError(f"账号 {name} 的 tasks[{index}] 必须是对象")
        task_id = str(item.get("id") or f"task{index + 1}").strip()
        if task_id in seen:
            raise ConfigError(f"账号 {name} 有重复的任务 id：{task_id}")
        seen.add(task_id)
        policy = _parse_policy(item.get("policy")) if isinstance(item.get("policy"), Mapping) else None
        tasks.append(
            TaskSpec(
                id=task_id,
                template=str(item.get("template") or "").strip(),
                method=str(item.get("method") or "").strip().lower(),
                title=str(item.get("title") or "").strip(),
                enabled=_bool(item.get("enabled"), True),
                timeout=_int(item.get("timeout"), _default_timeout(), minimum=1, maximum=7200),
                args=MappingProxyType(dict(item.get("args") or {})),
                depends_on=tuple(
                    str(dep).strip() for dep in (item.get("depends_on") or ()) if str(dep).strip()
                ),
                policy=policy,
                text_label=str(item.get("text_label") or "").strip(),
                flow=MappingProxyType(_parse_flow(item.get("flow"), label=f"{name}/{task_id}")),
            )
        )
    return tuple(tasks)


def _parse_network(raw: Any) -> NetworkSpec:
    if not isinstance(raw, Mapping):
        return NetworkSpec()
    return NetworkSpec(
        proxy=str(raw.get("proxy") or "").strip(),
        verify_ssl=_bool(raw.get("verify_ssl"), True),
        referer_path=str(raw.get("referer_path") or "/profile").strip() or "/profile",
    )


def _parse_policy(raw: Any) -> PolicySpec:
    if not isinstance(raw, Mapping):
        return PolicySpec()
    headless = raw.get("headless")
    return PolicySpec(
        tolerate_failure=_bool(raw.get("tolerate_failure"), False),
        retry=_int(raw.get("retry"), 1, minimum=0, maximum=10),
        allow_browser=_bool(raw.get("allow_browser"), True),
        headless=None if headless is None else _bool(headless, True),
        humanize=_bool(raw.get("humanize"), True),
    )


def _parse_flow(raw: Any, *, label: str) -> dict[str, Any]:
    if raw in (None, ""):
        return {}
    if not isinstance(raw, Mapping):
        raise ConfigError(f"{label} 的 flow 必须是对象，例如 {{'login': 'auto'}}")
    from core.manifest import STAGES

    out: dict[str, Any] = {}
    for key, value in raw.items():
        stage = str(key).strip().lower()
        if stage not in STAGES:
            raise ConfigError(
                f"{label} 的 flow 含未知阶段 {key!r}；可用阶段：{'、'.join(STAGES)}"
            )
        if isinstance(value, str):
            out[stage] = value.strip().lower()
        elif isinstance(value, (list, tuple)):
            out[stage] = [str(item).strip().lower() for item in value if str(item).strip()]
        else:
            raise ConfigError(f"{label} 的 flow.{stage} 必须是字符串或字符串数组")
    return out


def _parse_oauth_states(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        return {}
    out: dict[str, Any] = {}
    for provider, entry in raw.items():
        if not isinstance(entry, Mapping):
            continue
        accounts = entry.get("accounts")
        if not isinstance(accounts, Mapping):
            continue
        cleaned = {
            str(name): {
                "state": str(item.get("state") or ""),
                "username": str(item.get("username") or ""),
                "updated_at": str(item.get("updated_at") or ""),
            }
            for name, item in accounts.items()
            if isinstance(item, Mapping)
        }
        if cleaned:
            out[str(provider).strip().lower()] = {"accounts": cleaned}
    return out


# ── 导出 ────────────────────────────────────────────────────────────────────
def _merge_extras(payload: dict[str, Any], extras: Mapping[str, Any]) -> dict[str, Any]:
    """把保留下来的未知键并回导出结果；已知键始终以当前模型为准。"""
    for key, value in (extras or {}).items():
        if key == "credentials" and isinstance(value, Mapping):
            section = dict(value)
            section.update(payload.get("credentials") or {})
            if section.get("cookie_file"):
                # 用户把凭据放在单独文件里就是不想让它们进配置。解析时展开的值
                # 不能在这里被写回去——那等于替用户做了一次明文外泄。
                for loaded in COOKIE_FILE_FIELDS:
                    section.pop(loaded, None)
            payload["credentials"] = section
        else:
            payload.setdefault(str(key), value)
    return payload


def dump_account(spec: AccountSpec) -> dict[str, Any]:
    """AccountSpec → v3 JSON 对象。**唯一**的序列化实现。

    旧代码在 CLI、批量、GUI 三处各手写一份「站点 → 运行参数」的 dict，字段增删必然
    漏改一处（已实测：GUI 保存会静默抹掉用户手写的 cookie_file / referer_path）。
    """
    payload: dict[str, Any] = {
        "id": spec.id,
        "name": spec.name,
        "base_url": spec.base_url,
        "template": spec.template,
        "enabled": spec.enabled,
    }
    if spec.flow:
        payload["flow"] = dict(spec.flow)
    login = _dump_login(spec.login)
    if login:
        payload["login"] = login
    payload["tasks"] = [_dump_task(item) for item in spec.tasks]
    credentials = {
        key: value
        for key, value in (
            ("access_token", spec.credentials.access_token),
            ("refresh_token", spec.credentials.refresh_token),
            ("cookie", spec.credentials.cookie),
            ("browser_state", spec.credentials.browser_state),
            ("session_cookie", spec.credentials.session_cookie),
        )
        if value
    }
    if credentials:
        payload["credentials"] = credentials
    network = _dump_network(spec.network)
    if network:
        payload["network"] = network
    policy = _dump_policy(spec.policy)
    if policy:
        payload["policy"] = policy
    if spec.display:
        payload["display"] = dict(spec.display)
    return _merge_extras(payload, spec.extras)


def _dump_login(login: LoginSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if login.method:
        payload["method"] = login.method
    if login.provider:
        payload["provider"] = login.provider
    if login.account and login.account != DEFAULT_OAUTH_ACCOUNT:
        payload["account"] = login.account
    if login.args:
        payload["args"] = dict(login.args)
    if login.fallback:
        payload["fallback"] = [_dump_login(item) for item in login.fallback]
    return payload


def _dump_task(task: TaskSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {"id": task.id}
    for key, value, default in (
        ("template", task.template, ""),
        ("method", task.method, ""),
        ("title", task.title, ""),
        ("text_label", task.text_label, ""),
    ):
        if value != default:
            payload[key] = value
    if not task.enabled:
        payload["enabled"] = False
    if task.timeout != _default_timeout():
        payload["timeout"] = task.timeout
    if task.args:
        payload["args"] = dict(task.args)
    if task.depends_on:
        payload["depends_on"] = list(task.depends_on)
    if task.flow:
        payload["flow"] = dict(task.flow)
    if task.policy is not None:
        payload["policy"] = _dump_policy(task.policy)
    return payload


def _dump_network(network: NetworkSpec) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if network.proxy:
        payload["proxy"] = network.proxy
    if not network.verify_ssl:
        payload["verify_ssl"] = False
    if network.referer_path != "/profile":
        payload["referer_path"] = network.referer_path
    return payload


def _dump_policy(policy: PolicySpec) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if policy.tolerate_failure:
        payload["tolerate_failure"] = True
    if policy.retry != 1:
        payload["retry"] = policy.retry
    if not policy.allow_browser:
        payload["allow_browser"] = False
    if policy.headless is not None:
        payload["headless"] = policy.headless
    if not policy.humanize:
        payload["humanize"] = False
    return payload


def _dump_oauth_states(states: Mapping[str, Any]) -> dict[str, Any]:
    return {
        provider: {"accounts": {name: dict(item) for name, item in entry.get("accounts", {}).items()}}
        for provider, entry in (states or {}).items()
        if isinstance(entry, Mapping)
    }


# ── 小工具 ──────────────────────────────────────────────────────────────────
def _bool(value: Any, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _int(value: Any, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None and number < minimum:
        return default
    if maximum is not None and number > maximum:
        return default
    return number


def _default_timeout() -> int:
    from config.settings import Timeouts

    return int(Timeouts.BROWSER_SCRIPT_DEFAULT)


def loads(text: str, *, path: Path | None = None) -> Document:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"配置不是合法 JSON：{exc}") from exc
    return parse_document(raw, path=path)
