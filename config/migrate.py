"""配置迁移：v1 / v2 → v3。

一次性、纯函数、可测试。三条原则：

1. **先备份**：写 ``.bak-v2-<时间戳>``，迁移出错时用户还能回退（旧实现的
   ``_backup_before_migration`` 已经这么做，保留）。
2. **每条改动都留言**：迁移日志逐条说明「哪个字段搬到哪」，包括被丢弃的废弃字段。
   静默迁移会让用户在下次排查时对着一份自己没写过的配置发懵。
3. **不丢运行期缓存**：旧缓存键是 ``base_url|name``，新键是账号 id；迁移器产出这份
   映射交给覆盖层重挂（``overlay.migrate_keys``），改名/换 id 不会丢 token 与登录态。
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from ..core.account import normalize_base_url, slug_seed
from .schema import CONFIG_VERSION, DEFAULT_OAUTH_ACCOUNT

__all__ = [
    "MigrationResult",
    "legacy_cache_keys",
    "migrate_account",
    "migrate_document",
    "needs_migration",
]

#: 旧配置里已废弃、迁移时直接丢弃的字段（各留一行日志）。
DROPPED_FIELDS: Mapping[str, str] = {
    "login_selector": "OAuth 入口选择器（relogin 早已改用 oauth_provider 拼授权 URL）",
    "browser_profile": "浏览器持久化目录前缀（当前 Camoufox 启动不使用该参数）",
    "auto_refresh_cookie": "Cookie 回写开关（运行期产物已统一进覆盖层，不再改写用户文件）",
    "fallback_uid": "GUI 内部字段",
}

#: 旧站点脚本目录 → 新目录。
SCRIPT_DIR_MAP = (("scripts/checkin/", "scripts/tasks/"),)

#: 这些内置脚本在 v3 里已成为模板自带能力，不再需要在配置里指定。
BUILTIN_SCRIPTS = {
    "scripts/newapi_verification.py": "New API 验证机制路由（已内置于 newapi 模板）",
    "scripts/newapi_captcha.py": "New API 图形验证码（已内置于 newapi 模板）",
    "scripts/newapi_turnstile.py": "New API Turnstile（已内置于 newapi 模板）",
}

#: 旧 api_variant → 新 task.args.variant。
_API_VARIANTS = {"auto": "challenge", "legacy": "legacy", "challenge": "challenge"}

_ACTION_TO_METHOD = {
    "api": "http_api",
    "browser_script": "script",
    "relogin": "relogin",
    "visit": "visit",
}


class MigrationResult:
    """迁移产物：新文档 + 逐条说明 + 旧缓存键映射。"""

    __slots__ = ("payload", "notes", "cache_keys")

    def __init__(self, payload: dict[str, Any], notes: list[str], cache_keys: dict[str, str]) -> None:
        self.payload = payload
        self.notes = notes
        self.cache_keys = cache_keys

    def __bool__(self) -> bool:
        return bool(self.payload)


def needs_migration(raw: Any) -> bool:
    """是否是 v3 之前的配置。"""
    if isinstance(raw, list):
        return True
    if not isinstance(raw, Mapping):
        return False
    if int(raw.get("version") or 0) >= CONFIG_VERSION:
        return False
    accounts = raw.get("accounts")
    if not isinstance(accounts, list):
        return True
    # 没有 version 但已经是新形态（有 tasks）时不重复迁移。
    return not all(isinstance(item, Mapping) and "tasks" in item for item in accounts)


def migrate_document(raw: Any) -> MigrationResult:
    notes: list[str] = []
    accounts_raw, oauth_states = _split(raw)
    accounts: list[dict[str, Any]] = []
    cache_keys: dict[str, str] = {}
    taken: set[str] = set()

    for index, item in enumerate(accounts_raw):
        if not isinstance(item, Mapping):
            notes.append(f"accounts[{index}] 不是对象，已跳过")
            continue
        account, account_notes = migrate_account(item, taken=taken)
        taken.add(account["id"])
        accounts.append(account)
        notes.extend(f"[{account['id']}] {line}" for line in account_notes)
        legacy_key = _legacy_key(item)
        if legacy_key:
            cache_keys[legacy_key] = account["id"]

    payload = {
        "version": CONFIG_VERSION,
        "accounts": accounts,
        "oauth_states": oauth_states,
    }
    notes.insert(0, f"配置已迁移到 v{CONFIG_VERSION}：{len(accounts)} 个账号")
    return MigrationResult(payload, notes, cache_keys)


def migrate_account(raw: Mapping[str, Any], *, taken: Iterable[str] = ()) -> tuple[dict[str, Any], list[str]]:
    notes: list[str] = []
    base_url = normalize_base_url(raw.get("base_url") or raw.get("url"))
    name = str(raw.get("name") or "").strip() or base_url
    account_id = _unique_id(name, base_url, set(taken))

    action = str(raw.get("checkin_action") or "").strip().lower()
    if not action:
        # v1：只有 type + checkin_mode。browser_oauth 对应「浏览器重登发放」。
        legacy_mode = str(raw.get("checkin_mode") or raw.get("mode") or "").strip().lower()
        action = "relogin" if legacy_mode == "browser_oauth" else "api"
        notes.append(f"checkin_mode={legacy_mode or '（空）'} → task.method={_ACTION_TO_METHOD[action]}")
    method = _ACTION_TO_METHOD.get(action, "http_api")

    profile = str(raw.get("site_profile") or raw.get("type") or raw.get("provider") or "newapi").strip().lower()
    script = str(raw.get("script") or "").strip()
    template = profile
    if script:
        mapped, script_note = _map_script(script)
        if mapped is None:
            notes.append(script_note)
        else:
            template = mapped
            notes.append(script_note)
    if template != profile:
        notes.append(f"site_profile={profile} + script → template={template}")
    else:
        notes.append(f"site_profile={profile} → template={template}")

    task: dict[str, Any] = {"id": "daily", "method": method}
    timeout = _int(raw.get("script_timeout"))
    if timeout:
        task["timeout"] = timeout
    args = dict(raw.get("script_args") or {})
    # 旧 api_variant 的取值语义与新 variant 不同名：旧 "auto" 表示「challenge 优先」，
    # 旧 "legacy" 表示「旧接口优先」（也是新模型的默认值）。直接搬名字会把
    # 「challenge 优先」变成「默认 legacy」，站点升级过协议的账号会静默退回旧接口。
    variant = _API_VARIANTS.get(str(raw.get("api_variant") or "").strip().lower())
    if variant and variant != "legacy":
        args.setdefault("variant", variant)
        notes.append(f"api_variant={raw.get('api_variant')} → task.args.variant={variant}")
    if args:
        task["args"] = args

    flow: dict[str, Any] = {}
    verification = str(raw.get("verification_mode") or "").strip().lower()
    if verification and verification != "auto":
        flow["verification"] = verification
        notes.append(f"verification_mode={verification} → flow.verification")

    login = _migrate_login(raw, action=action, notes=notes)
    credentials = {
        key: str(raw.get(key) or "").strip()
        for key in ("access_token", "refresh_token", "cookie", "browser_state")
        if str(raw.get(key) or "").strip()
    }
    cookie_file = str(raw.get("cookie_file") or raw.get("token_file") or "").strip()
    if cookie_file:
        credentials["cookie_file"] = cookie_file
    user_id = str(raw.get("user_id") or "").strip()
    if user_id:
        credentials["user_id"] = user_id
        notes.append("user_id → credentials.user_id（作为 login.args.user_id 传给站点模板）")

    network = {
        key: value
        for key, value in (
            ("proxy", str(raw.get("proxy") or "").strip()),
            ("referer_path", str(raw.get("referer_path") or "").strip()),
        )
        if value
    }
    if raw.get("verify_ssl") is False:
        network["verify_ssl"] = False
    policy = {}
    if _bool(raw.get("tolerate_failure")):
        policy["tolerate_failure"] = True
        notes.append("tolerate_failure → policy.tolerate_failure")

    for field_name, why in DROPPED_FIELDS.items():
        value = raw.get(field_name)
        if value not in (None, "", True) or (field_name == "auto_refresh_cookie" and value is False):
            notes.append(f"丢弃已废弃字段 {field_name}：{why}")

    account: dict[str, Any] = {
        "id": account_id,
        "name": name,
        "base_url": base_url,
        "template": template,
        "enabled": _bool(raw.get("enabled"), True),
        "tasks": [task],
    }
    if flow:
        account["flow"] = flow
    if login:
        account["login"] = login
    if credentials:
        account["credentials"] = credentials
    if network:
        account["network"] = network
    if policy:
        account["policy"] = policy
    return account, notes


def _migrate_login(raw: Mapping[str, Any], *, action: str, notes: list[str]) -> dict[str, Any]:
    auth = str(raw.get("auth_method") or "").strip().lower()
    if not auth:
        auth = "oauth" if action in {"relogin", "browser_script"} else (
            "access_token" if str(raw.get("access_token") or "").strip() else "cookie"
        )
        notes.append(f"未指定 auth_method，按旧规则推断为 {auth}")
    method = {"browser": "browser_state"}.get(auth, auth)
    login: dict[str, Any] = {"method": method}
    if method != auth:
        notes.append(f"auth_method={auth} → login.method={method}")
    else:
        notes.append(f"auth_method={auth} → login.method={method}")

    provider = str(raw.get("oauth_provider") or "").strip().lower()
    if provider:
        login["provider"] = provider
    account_name = str(raw.get("oauth_account") or "").strip()
    if account_name and account_name != DEFAULT_OAUTH_ACCOUNT:
        login["account"] = account_name

    fallback_provider = str(raw.get("oauth_fallback_provider") or "").strip().lower()
    if fallback_provider:
        entry: dict[str, Any] = {"method": "oauth", "provider": fallback_provider}
        fallback_account = str(raw.get("oauth_fallback_account") or "").strip()
        if fallback_account and fallback_account != DEFAULT_OAUTH_ACCOUNT:
            entry["account"] = fallback_account
        login["fallback"] = [entry]
        notes.append(f"oauth_fallback_provider={fallback_provider} → login.fallback[0]")

    # 旧脚本的账密兜底藏在 script_args 里；搬到登录方式的参数上，凭据不再进任务参数。
    args = dict(raw.get("script_args") or {})
    credentials = {
        key: args[key]
        for key in ("email", "password", "email_env", "password_env")
        if args.get(key) not in (None, "")
    }
    if credentials:
        entry = {"method": "password", "args": credentials}
        login.setdefault("fallback", []).append(entry)
        notes.append("script_args 里的账密 → login.fallback[password].args")
    return login


def _map_script(script: str) -> tuple[str | None, str]:
    normalized = script.replace("\\", "/").strip()
    if normalized in BUILTIN_SCRIPTS:
        return None, f"丢弃 script={normalized}：{BUILTIN_SCRIPTS[normalized]}"
    for old, new in SCRIPT_DIR_MAP:
        if normalized.startswith(old):
            moved = new + normalized[len(old):]
            return moved, f"script={normalized} → template={moved}（脚本目录已改名）"
    return normalized, f"script={normalized} → template={normalized}"


def legacy_cache_keys(raw: Any) -> dict[str, str]:
    """只算「旧缓存键 → 新账号 id」的映射，不做完整迁移。"""
    return migrate_document(raw).cache_keys


# ── 内部 ────────────────────────────────────────────────────────────────────
def _split(raw: Any) -> tuple[list[Any], dict[str, Any]]:
    if isinstance(raw, list):
        return list(raw), {}
    if not isinstance(raw, Mapping):
        return [], {}
    accounts = raw.get("accounts")
    if not isinstance(accounts, list):
        accounts = raw.get("sites") if isinstance(raw.get("sites"), list) else []
    states = raw.get("oauth_states")
    return list(accounts), dict(states) if isinstance(states, Mapping) else {}


def _legacy_key(raw: Mapping[str, Any]) -> str:
    base = normalize_base_url(raw.get("base_url") or raw.get("url"))
    name = str(raw.get("name") or "").strip()
    return f"{base}|{name}" if base else ""


def _unique_id(name: str, base_url: str, taken: set[str]) -> str:
    base = slug_seed(name, base_url)
    candidate = base
    suffix = 2
    while candidate in taken:
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def _bool(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
