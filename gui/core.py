# -*- coding: utf-8 -*-
"""纯逻辑层：不依赖 Qt，可单独测试。

这里集中了旧版 manage_accounts.py 里散落十余处的规则，每条规则只此一份：
- effective_auth ：checkin_action 对 auth_method 的矫正（relogin→oauth 等）；
- SiteRow        ：GUI 行模型与 store 行的双向映射；
- task_params    ：后台任务参数装配（旧版三处手写 dict 的唯一来源）；
- build_form_plan：表单显隐/文案联动（旧版 _sync_type 的 if 森林）；
- StatusStore    ：checkin_result.json + gui_status_cache.json 的合并与落盘；
- bg_log         ：脱敏后台日志（stderr + GUI 日志面板 sink）。
"""

from __future__ import annotations

import copy
import json
import sys
from collections import deque
import traceback
import uuid
from dataclasses import dataclass, field, fields, replace
from datetime import datetime
from typing import Any, Callable

from config.settings import Timeouts as _Timeouts
from core.masking import is_sensitive_key, mask_secrets

from config import paths as _paths
from config import schema as _schema
from config import store as _config_store
from config.overlay import Overlay as _Overlay
from core.account import (
    CREDENTIAL_FIELDS as _CREDENTIAL_FIELDS,
    AccountSpec,
    CredentialSet,
    LoginSpec,
    NetworkSpec,
    PolicySpec,
    TaskSpec,
    normalize_base_url,
)
from core.outcome import REASONS as _REASONS
from core.outcome import Verdict as _Verdict
from core.outcome import parse_verdict as _parse_verdict
from login import LOGINS as _LOGINS
from task import TASKS as _TASKS
from templates import registry as _templates

from .status_store import StatusStore as StatusStore

_SCRIPT_TIMEOUT_DEFAULT = _Timeouts.BROWSER_SCRIPT_DEFAULT
SCRIPT_TIMEOUT_DEFAULT = _SCRIPT_TIMEOUT_DEFAULT

# 与 core.account 的默认值
# 保持一致：GUI 用同一套默认值，空值才不会在往返中被解释成「用户改了配置」。
_REFERER_PATH_DEFAULT = "/profile"
REFERER_PATH_DEFAULT = _REFERER_PATH_DEFAULT

# ── 词表 ────────────────────────────────────────────────────────────────────
# 全部来自各自的注册表：模板、登录方式、任务方式都是**开放集合**，用户新建一个模板
# 或脚本就该立刻出现在下拉里。旧实现从封闭枚举读，新增站点族必须改内核。
def template_choices() -> tuple[str, ...]:
    """当前可选的模板 id（内置 + 用户模板）。脚本路径由用户直接输入。"""
    try:
        return _templates.ids()
    except Exception:
        return ("newapi", "sub2api")


def template_label(reference: str) -> str:
    key = str(reference or "").strip()
    if not key:
        return ""
    try:
        return _templates.get(key).manifest.title or key
    except Exception:
        return key


TYPES = template_choices()
CRED_FIELDS = ("user_id", "access_token", "refresh_token", "cookie")
AUTH_METHODS = _LOGINS.ids()
CHECKIN_ACTIONS = _TASKS.ids()
API_VARIANTS = ("legacy", "challenge")
VERIFICATION_MODES = ("auto", "turnstile", "bitmap_code", "string_captcha", "click_shape")
OAUTH_PROVIDERS = ("linuxdo", "github")
DEFAULT_OAUTH_ACCOUNT = _schema.DEFAULT_OAUTH_ACCOUNT

# 表单下拉框的兜底值。集中在这里而不是散在 app.py 的字面量里：下拉框的选项来自
# 注册表（开放集合），兜底值却必须是**具体某一个**，两者一旦漂移就会��现「选中项
# 落不到任何一个选项上」——表现为界面打开即崩，或者静默把用户的配置改成别的。
DEFAULT_TEMPLATE = "newapi"
DEFAULT_AUTH_METHOD = "cookie"
DEFAULT_ACTION = "http_api"
DEFAULT_API_VARIANT = "legacy"
DEFAULT_VERIFICATION_MODE = "auto"
DEFAULT_OAUTH_PROVIDER = "linuxdo"

TYPE_LABELS = {"newapi": "New API", "sub2api": "Sub2API"}
AUTH_METHOD_LABELS = {
    "access_token": "Access Token (Bearer)",
    "cookie": "Cookie",
    "refresh": "Refresh Token 续期",
    "password": "账密登录（纯 HTTP）",
    "browser_state": "站点浏览器登录态",
    "oauth": "OAuth 登录态（共享账号）",
}
ACTION_LABELS = {
    "http_api": "接口任务 (调站点接口)",
    "visit": "访问保活 (只读监控)",
    "relogin": "浏览器重登 (自动 OAuth 发放)",
    "browser_flow": "浏览器流程",
    "script": "自定义脚本（模板自管流程）",
}
OAUTH_PROVIDER_LABELS = {"linuxdo": "Linux.do", "github": "GitHub"}
API_VARIANT_LABELS = {
    "legacy": "旧版接口 legacy（推荐）",
    "challenge": "challenge 优先（需 Node.js）",
}
VERIFICATION_MODE_LABELS = {
    "auto": "自动识别（推荐）",
    "turnstile": "Cloudflare Turnstile",
    "bitmap_code": "点阵字符验证码（固定5位）",
    "string_captcha": "字符图片验证码（base64Captcha）",
    "click_shape": "图形点选验证码（GoCaptcha）",
}


# ── 归一化小工具（原 accounts_store 的同名函数）──────────────────────────────
def normalize_oauth_provider(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in OAUTH_PROVIDERS else ""


def normalize_oauth_account(value: Any) -> str:
    return str(value or "").strip() or DEFAULT_OAUTH_ACCOUNT


def parse_enabled(value: Any, default: bool = True) -> bool:
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


def parse_script_timeout(value: Any, default: int | None = None) -> int:
    """解析任务超时；非法值与越界值都回落到**同样被夹取过**的默认值。

    默认值也要夹取：缺省/非法输入以前能拿到超过上限的超时，一个配置手误就会让任务
    永久挂起（上限存在的意义正是防这个）。
    """
    maximum = int(_Timeouts.BROWSER_SCRIPT_MAX)
    fallback = int(default if default is not None else _Timeouts.BROWSER_SCRIPT_DEFAULT)
    fallback = min(max(fallback, 1), maximum)
    try:
        number = int(value)
    except (TypeError, ValueError):
        return fallback
    return number if 1 <= number <= maximum else fallback


def normalize_script_args(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}
    return {}


def normalize_api_variant(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in API_VARIANTS else "legacy"


def normalize_verification_mode(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in VERIFICATION_MODES else "auto"


# 「脚本路径」在两种签到方式下挂的是不同钩子，提示必须区分：
# - browser_script：脚本的 run(page, context, site, helpers) 在 Camoufox 里跑；
# - api          ：脚本的 do_checkin(client, log) 走纯 HTTP，用于站点私改的签到玩法
#                  （如 New API fork 的图形验证码），返回 None 则回落默认签到流程。
SCRIPT_HINT_BROWSER = "仓库内相对路径；模板的 run(ctx) 在此执行，例如 scripts/tasks/100xlabs.py"
SCRIPT_PLACEHOLDER_BROWSER = "scripts/tasks/100xlabs.py"
SCRIPT_HINT_API = "可留空。仅用于覆盖内置验证路由或接入其它自定义 do_checkin 钩子"
SCRIPT_PLACEHOLDER_API = "scripts/custom_checkin.py（仅自定义流程时填）"


# ── 脱敏日志（敏感键规则统一由 mask_utils 维护）───────────────────────────────
LogSink = Callable[[str], None]
_LOG_SINKS: list[LogSink] = []


def add_log_sink(sink: LogSink) -> None:
    """注册 GUI 日志监听器；sink 可能在任意线程被调用，须自行保证线程安全。"""
    if sink not in _LOG_SINKS:
        _LOG_SINKS.append(sink)


def remove_log_sink(sink: LogSink) -> None:
    if sink in _LOG_SINKS:
        _LOG_SINKS.remove(sink)


def _is_sensitive_log_key(key: Any) -> bool:
    return is_sensitive_key(str(key or ""))


def _redact_log_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(k): (f"<redacted:{len(str(v or ''))} chars>" if _is_sensitive_log_key(k) else _redact_log_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_log_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_redact_log_value(v) for v in value)
    return value


def _safe_log_value(value: Any, key: str = "") -> str:
    if value is None:
        return ""
    if _is_sensitive_log_key(key):
        text = f"<redacted:{len(str(value or ''))} chars>"
    elif isinstance(value, (dict, list, tuple)):
        try:
            text = json.dumps(_redact_log_value(value), ensure_ascii=False, default=str, separators=(",", ":"))
        except Exception:
            text = str(_redact_log_value(value))
    else:
        text = str(value)
    return mask_secrets(text.replace("\r", " ").replace("\n", " ").strip())


def bg_log(level: str, message: str, **fields_: Any) -> None:
    """输出后台任务日志：stderr + 已注册的 GUI sink（均为脱敏后文本）。"""
    try:
        extra = " ".join(
            f"{key}={_safe_log_value(value, key)}" for key, value in fields_.items() if value not in (None, "")
        )
        line = f"[{level.upper()}] {mask_secrets(str(message))}"
        if extra:
            line += f" | {extra}"
        print(line, file=sys.stderr, flush=True)
        stamp = datetime.now().strftime("%H:%M:%S")
        for sink in list(_LOG_SINKS):
            try:
                sink(f"{stamp} {line}")
            except Exception:
                pass
    except Exception:
        # 日志失败不能影响 GUI 主流程。
        pass


def error_result(message: str, exc: BaseException | None = None, **fields_: Any) -> dict[str, Any]:
    tb = traceback.format_exc() if exc is not None else ""
    error_text = f"{message}：{exc}" if exc is not None else message
    bg_log("ERROR", error_text, traceback=tb, **fields_)
    return {
        "ok": False,
        "status": "error",
        "message": mask_secrets(error_text),
        "error": mask_secrets(str(exc)) if exc is not None else mask_secrets(message),
        "traceback": tb,
    }


# ── auth 矫正（唯一实现）─────────────────────────────────────────────────────
def effective_auth(checkin_action: str, auth_method: str) -> str:
    """按任务方式矫正登录方式。

    ``relogin`` 的语义就是「重放一次 OAuth 登录来触发发放」，用别的登录方式没有意义；
    其余任务方式尊重用户选择。留空交给引擎按模板优先序自动决定。
    """
    action = str(checkin_action or "").strip().lower()
    method = str(auth_method or "").strip().lower()
    if action == "relogin":
        return "oauth"
    return method


def can_optional_oauth(site_type: str, checkin_action: str, auth_method: str) -> bool:
    """是否可以配置备选登录方式。

    新模型里备选链对任何登录方式都成立（``login.fallback``），不再是 OAuth 专属特例，
    因此这里恒为真；参数保留是为了不惊动调用方。
    """
    return True


@dataclass
class SiteRow:
    # 仅当前 GUI 进程使用的稳定身份；不写入 ACCOUNTS/Secret/状态快照。
    runtime_id: str = field(default_factory=lambda: uuid.uuid4().hex, repr=False, compare=False)
    #: 账号稳定 id（运行期缓存、历史结果与状态都挂在它上面）。新建行留空，保存时生成。
    account_id: str = ""
    #: 这一行来自哪个账号配置。表单只覆盖它认识的字段，其余（多任务、flow、policy、
    #: 用户手写的未知键）原样保留——否则一次保存就会把 GUI 不认识的配置抹掉。
    source: Any = field(default=None, repr=False, compare=False)
    name: str = ""
    base_url: str = ""
    type: str = "newapi"
    auth_method: str = "cookie"
    checkin_action: str = "api"
    script: str = ""
    script_args: dict[str, Any] = field(default_factory=dict)
    script_args_text: str = "{}"
    script_timeout: int = _SCRIPT_TIMEOUT_DEFAULT
    api_variant: str = "legacy"
    verification_mode: str = "auto"
    oauth_provider: str = "linuxdo"
    oauth_account: str = DEFAULT_OAUTH_ACCOUNT
    oauth_fallback_provider: str = ""
    oauth_fallback_account: str = ""
    enabled: bool = True
    user_id: str = ""
    access_token: str = ""
    # sub2api 的长期凭据：access_token 过期后可纯 HTTP 续期，无需启动浏览器。
    refresh_token: str = ""
    cookie: str = ""
    browser_state: str = ""
    proxy: str = ""
    verify_ssl: bool = True
    # 以下四项 checkin.py / run__all_checkin.py 都会消费，但此前 GUI 既不展示也不
    # 落盘：用户在 ACCOUNTS.json 手写的值，被 GUI 保存一次就静默抹掉。
    cookie_file: str = ""
    referer_path: str = _REFERER_PATH_DEFAULT

    def __deepcopy__(self, memo: dict[int, Any]) -> "SiteRow":
        """深拷贝时共享 ``source``，其余字段照常复制。

        ``source`` 是 ``AccountSpec``（frozen dataclass，内部 flow/display/extras 与
        TaskSpec.args 都是 ``MappingProxyType``）。``mappingproxy`` 不可 pickle，
        ``copy.deepcopy`` 会直接抛 ``TypeError``——GUI 保存的第一步就是
        ``deepcopy(rows)``，于是整个保存在写盘前就失败了。``source`` 只作为只读底稿被
        读取，从不就地修改，共享同一个对象既安全又避免这个坑。
        """
        clone = SiteRow.__new__(SiteRow)
        memo[id(self)] = clone
        for item in fields(self):
            value = getattr(self, item.name)
            object.__setattr__(
                clone,
                item.name,
                value if item.name == "source" else copy.deepcopy(value, memo),
            )
        return clone

    # -- 便捷视图 --
    @property
    def auth(self) -> str:
        """经 checkin_action 矫正后的实际登录方式。"""
        return effective_auth(self.checkin_action, self.auth_method)

    def copy(self) -> "SiteRow":
        return replace(
            self,
            runtime_id=uuid.uuid4().hex,
            script_args=dict(self.script_args),
        )

def row_from_account(spec: AccountSpec) -> SiteRow:
    """v3 账号 → GUI 表单行。

    表单是**平铺**的（一个站点一行、一个任务），而模型是分组且支持多任务的。因此
    这里只摊平「第一个任务 + 主登录方式」；其余部分留在 ``row.source`` 里，保存时原样
    带回。这样在 GUI 里编辑一个多任务账号，不会把第二个任务弄丢。
    """
    task = spec.tasks[0] if spec.tasks else TaskSpec()
    login = spec.login
    fallback = login.fallback[0] if login.fallback else None
    args = dict(task.args or {})
    flow = {**dict(spec.flow or {}), **dict(task.flow or {})}
    creds = spec.credentials
    extras_credentials = dict((spec.extras or {}).get("credentials") or {})

    return SiteRow(
        account_id=spec.id,
        source=spec,
        name=spec.name,
        base_url=spec.base_url,
        type=spec.template or "auto",
        auth_method=login.method or "",
        checkin_action=task.method or "",
        script=spec.template if _looks_like_path(spec.template) else "",
        script_args=args,
        script_args_text=json.dumps(args, ensure_ascii=False, indent=2) if args else "{}",
        script_timeout=int(task.timeout or _SCRIPT_TIMEOUT_DEFAULT),
        api_variant=normalize_api_variant(args.get("variant")),
        verification_mode=normalize_verification_mode(_first_flow(flow.get("verification"))),
        oauth_provider=normalize_oauth_provider(login.provider) or "linuxdo",
        oauth_account=normalize_oauth_account(login.account),
        oauth_fallback_provider=normalize_oauth_provider(fallback.provider) if fallback else "",
        oauth_fallback_account=normalize_oauth_account(fallback.account) if fallback else "",
        enabled=bool(spec.enabled),
        user_id=str((login.args or {}).get("user_id") or ""),
        access_token=creds.access_token,
        refresh_token=creds.refresh_token,
        cookie=creds.cookie,
        browser_state=creds.browser_state,
        proxy=spec.network.proxy,
        verify_ssl=bool(spec.network.verify_ssl),
        cookie_file=str(extras_credentials.get("cookie_file") or ""),
        referer_path=spec.network.referer_path or _REFERER_PATH_DEFAULT,
    )


def _looks_like_path(reference: Any) -> bool:
    text = str(reference or "")
    return text.endswith(".py") or "/" in text


def _first_flow(value: Any) -> str:
    """flow 值可能是字符串或优先序数组；表单只显示第一个。"""
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else ""
    return str(value or "")


def row_to_account(row: SiteRow) -> AccountSpec:
    """GUI 表单行 → v3 账号。以 ``row.source`` 为底稿，只覆盖表单负责的字段。"""
    base_url = normalize_base_url(row.base_url)
    source: AccountSpec | None = row.source if isinstance(row.source, AccountSpec) else None
    template = (row.script.strip() or row.type or "auto").strip()

    args = normalize_script_args(row.script_args_text if row.script_args_text.strip() else row.script_args)
    variant = normalize_api_variant(row.api_variant)
    if template.startswith("newapi") and variant != "legacy":
        args["variant"] = variant
    elif "variant" in args and variant == "legacy":
        args.pop("variant", None)

    task_source = source.tasks[0] if source and source.tasks else TaskSpec()
    task = replace(
        task_source,
        method=effective_auth_task(row.checkin_action),
        timeout=parse_script_timeout(row.script_timeout),
        args=dict(args),
        template="",
    )
    tasks = (task,) + (tuple(source.tasks[1:]) if source and len(source.tasks) > 1 else ())

    login_args = dict((source.login.args if source else {}) or {})
    if row.user_id.strip():
        login_args["user_id"] = row.user_id.strip()
    else:
        login_args.pop("user_id", None)
    fallback: tuple[LoginSpec, ...] = ()
    if row.oauth_fallback_provider.strip():
        fallback = (
            LoginSpec(
                method="oauth",
                provider=normalize_oauth_provider(row.oauth_fallback_provider),
                account=normalize_oauth_account(row.oauth_fallback_account),
            ),
        )
    elif source and source.login.fallback:
        # 表单里没有这一项（例如账密备选）时保留原配置，不要静默删掉。
        fallback = tuple(item for item in source.login.fallback if item.method != "oauth")
    login = LoginSpec(
        method=effective_auth(row.checkin_action, row.auth_method),
        provider=normalize_oauth_provider(row.oauth_provider),
        account=normalize_oauth_account(row.oauth_account),
        args=login_args,
        fallback=fallback,
    )

    flow = dict(source.flow if source else {})
    mode = normalize_verification_mode(row.verification_mode)
    if mode == "auto":
        flow.pop("verification", None)
    else:
        flow["verification"] = mode

    extras = dict(source.extras if source else {})
    credentials_extra = dict(extras.get("credentials") or {})
    if row.cookie_file.strip():
        credentials_extra["cookie_file"] = row.cookie_file.strip()
    else:
        credentials_extra.pop("cookie_file", None)
    if credentials_extra:
        extras["credentials"] = credentials_extra
    else:
        extras.pop("credentials", None)

    return AccountSpec(
        id=row.account_id.strip() or _new_account_id(row),
        name=row.name.strip() or base_url,
        base_url=base_url,
        template=template or "auto",
        enabled=bool(row.enabled),
        login=login,
        tasks=tasks,
        credentials=CredentialSet(
            access_token=row.access_token.strip(),
            refresh_token=row.refresh_token.strip(),
            cookie=row.cookie.strip(),
            browser_state=row.browser_state.strip(),
            session_cookie=source.credentials.session_cookie if source else "",
        ),
        network=NetworkSpec(
            proxy=row.proxy.strip(),
            verify_ssl=bool(row.verify_ssl),
            referer_path=row.referer_path.strip() or _REFERER_PATH_DEFAULT,
        ),
        policy=source.policy if source else PolicySpec(),
        flow=flow,
        display=dict(source.display if source else {}),
        extras=extras,
    )


def effective_auth_task(checkin_action: str) -> str:
    """表单里的任务方式；未知值留空交给引擎自动决定。"""
    method = str(checkin_action or "").strip().lower()
    return method if method in CHECKIN_ACTIONS else ""


def _new_account_id(row: SiteRow) -> str:
    from core.account import slug_seed

    return slug_seed(row.name, row.base_url)


def load_rows() -> list[SiteRow]:
    """读取配置（必要时自动迁移到 v3）并摊平成表单行。"""
    document = _config_store.load(overlay=_Overlay().load())
    for note in document.notes:
        bg_log("INFO", f"[migrate] {note}")
    return [row_from_account(spec) for spec in document.accounts]


def new_row(site_type: str) -> SiteRow:
    return SiteRow(name="新站点", type=site_type or "auto", auth_method="", checkin_action="")


# ── OAuth 登录态访问 ─────────────────────────────────────────────────────────
#: 各 OAuth 提供商登录态里会出现的 cookie 域名。用于「这份登录态到底是谁的」判别。
OAUTH_PROVIDER_DOMAINS: dict[str, tuple[str, ...]] = {
    "linuxdo": ("linux.do", "connect.linux.do"),
    "github": ("github.com",),
}


def _state_domains(state_text: str) -> set[str]:
    """从登录态里提取 cookie 域名集合。解码失败按「没有域名」处理。"""
    try:
        from browser.service import decode_state

        data = decode_state(state_text)
    except Exception:
        return set()
    domains: set[str] = set()
    for cookie in data.get("cookies", []) if isinstance(data, dict) else []:
        dom = str(cookie.get("domain", "")).strip().lstrip(".").rstrip(".").lower()
        if dom:
            domains.add(dom)
    return domains


def guess_oauth_provider(state_text: str) -> str:
    """按 cookie 的**严格域名边界**猜 OAuth 提供商；认不出返回空串。

    严格边界很重要：``evil-linux.do`` 不该被当成 ``linux.do``，否则会把一份陌生
    登录态当成用户的共享账号用出去。
    """
    from browser.oauth_providers import hostname_matches_domain

    domains = _state_domains(state_text)
    for provider, hints in OAUTH_PROVIDER_DOMAINS.items():
        if any(hostname_matches_domain(dom, hint) for dom in domains for hint in hints):
            return provider
    return ""


def state_contains_site_domain(state_text: str, base_url: str) -> bool:
    """登录态里是否有可发给目标站点的 Cookie。"""
    from urllib.parse import urlparse

    from browser.oauth_providers import hostname_matches_domain

    host = urlparse(normalize_base_url(base_url)).hostname or ""
    if not host:
        return False
    return any(hostname_matches_domain(host, domain) for domain in _state_domains(state_text))


def oauth_state_text(oauth_states: dict[str, Any], provider: str, account: str) -> str:
    entry = ((oauth_states.get(provider) or {}).get("accounts") or {}).get(account) or {}
    return str(entry.get("state") or "").strip()


def oauth_state_entry(oauth_states: dict[str, Any], provider: str, account: str) -> dict[str, Any]:
    return dict(((oauth_states.get(provider) or {}).get("accounts") or {}).get(account) or {})


def has_shared_oauth(oauth_states: dict[str, Any]) -> bool:
    return any(((oauth_states.get(p) or {}).get("accounts") or {}) for p in OAUTH_PROVIDERS)


def normalized_fallback(row: SiteRow) -> tuple[str, str]:
    """当前流程真正会持久化的 OAuth 兜底组合；不适用场景一律 ("", "")。"""
    if not can_optional_oauth(row.type, row.checkin_action, row.auth):
        return "", ""
    provider = normalize_oauth_provider(row.oauth_fallback_provider)
    if not provider:
        return "", ""
    return provider, normalize_oauth_account(row.oauth_fallback_account)


# ── 任务参数装配（唯一实现；旧版三处手写 dict）───────────────────────────────
def task_params(
    row: SiteRow,
    oauth_states: dict[str, Any],
    *,
    explicit_credential_fields: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """组装「立即执行这一行」用的账号载荷。

    产出的就是 v3 账号对象的 JSON 形态——与 ``--account-json`` 和批量子进程读到的
    完全同构。旧实现在 GUI、CLI、批量三处各手写一份运行参数 dict，字段增删必然漏改
    一处（实测：GUI 能用、批量静默丢脚本参数）。
    """
    spec = row_to_account(row)
    payload = _schema.dump_account(spec)
    # GUI 里刚输入（含刚清空）的凭据必须赢过运行期覆盖层，否则用户无法强制重登。
    payload["_explicit_credential_fields"] = sorted(
        field for field in explicit_credential_fields if field in _CREDENTIAL_FIELDS
    )
    payload["_oauth_states"] = {
        provider: {"accounts": dict(entry.get("accounts") or {})}
        for provider, entry in (oauth_states or {}).items()
    }
    return payload


@dataclass
class FormPlan:
    show_variant: bool = False
    show_verification: bool = False
    show_script: bool = False
    # script_args 目前只传给 browser_script 的 run()；api 钩子固定为
    # do_checkin(client, log)，显示参数框会让用户误以为它会被消费。
    show_script_args: bool = False
    # 脚本超时只对浏览器脚本有意义（它限的是 Camoufox 里 run() 的执行时间）。
    # api 方式下的脚本是纯 HTTP 的，超时由 HTTP 层自己管，显示这个框只会误导。
    show_script_timeout: bool = False
    # 「脚本路径」这一个字段在两种签到方式下挂的是不同钩子，提示必须跟着变，
    # 否则 api 方式下会照着 browser_script 的示例去填一个浏览器脚本。
    script_hint: str = SCRIPT_HINT_BROWSER
    script_placeholder: str = SCRIPT_PLACEHOLDER_BROWSER
    show_oauth: bool = False
    show_fallback: bool = False
    show_state_box: bool = False
    state_editable: bool = False
    show_oauth_status: bool = False
    show_browser_ops: bool = False
    show_delete_oauth: bool = False
    creds_enabled: bool = False
    # sub2api 的 access_token / refresh_token 是**接口凭据**，与 auth_method 无关：
    # 即使登录方式是 browser/oauth，签到仍会先走纯 API（token → refresh_token 续期），
    # 只有全失败才拉浏览器。因此这两个框不能跟着 creds_enabled 一起灰掉，否则用户
    # 手工粘贴的有效 token 根本无法保存，表现为「填了仍显示没有」。
    token_enabled: bool = False
    capture_text: str = "浏览器登录捕获"
    verify_text: str = "检测登录态"
    oauth_status: str = ""
    mode_hint: str = ""
    # sub2api 的 access_token 是短期 JWT，refresh_token 才决定能否纯 HTTP 续期
    # （不必每次签到都拉起浏览器）。除状态文案外还给出输入框：站点风控（如
    # Turnstile）可能让浏览器捕获失败，此时手工粘贴是唯一可行的补救途径。
    show_refresh_status: bool = False
    show_refresh_input: bool = False
    refresh_status: str = ""


_SCRIPT_FALLBACK_HINT = (
    "💡 自定义脚本始终先使用当前站点浏览器登录态；失效后最多通过可选 OAuth 自动登录并重试一次。"
    "不选择 OAuth 时将直接提示签到失败。可选账号来自顶层共享 OAuth 登录态。"
)
_NO_SHARED_OAUTH_HINT = "暂无共享 OAuth 登录态；请切换登录方式为“OAuth 登录态（共享账号）”后捕获，或点击“刷新账号”。"


def token_defect(value: str) -> str:
    """检出「看起来填了、实际不可用」的 access_token；正常返回空串。

    HTTP 头只能承载 latin-1，net.http.normalize_access_token 会把含非 ASCII
    的值静默判为空 token。最常见的来源是从站点后台的截断显示里复制，值中间带了
    Unicode 省略号（U+2026）。不提示的话用户只会看到「未配置 access_token」，
    完全无从判断是自己粘贴的值有问题。
    """
    text = (value or "").strip()
    # 与 net.http.normalize_access_token 保持同样的前缀剥离顺序，避免这里
    # 判「健康」而运行时判「无 token」（或反之）。
    if text.lower().startswith("authorization:"):
        text = text.split(":", 1)[1].strip()
    if text.lower().startswith("bearer "):
        text = text[7:].strip()
    if not text:
        return ""
    # 占位文本先判：模板占位符往往本身就带中文（如「<在站点后台采集的 access_token>」），
    # 若先报「含非 ASCII」会把真正的原因盖住。
    if text.startswith("<") and text.endswith(">"):
        return "Token 仍是占位文本，请粘贴真实值。"
    bad = sorted({ch for ch in text if not ch.isascii()})
    if bad:
        shown = " ".join(f"{ch!r}(U+{ord(ch):04X})" for ch in bad[:3])
        return f"Token 含非 ASCII 字符 {shown}，无法用于 HTTP 请求，会被视为未配置。"
    if text.count(".") != 2:
        return "Token 不是 JWT 结构（应为 3 段以 . 分隔），可能复制不完整。"
    return ""


def _refresh_token_status(row: SiteRow) -> str:
    """凭据卡下方的 token 健康度文案：先报硬缺陷，再报 refresh_token 有无。"""
    defect = token_defect(row.access_token)
    prefix = f"⚠ {defect}\n" if defect else ""
    if row.refresh_token.strip():
        return prefix + "已保存 refresh_token：Token 过期可纯 HTTP 自动续期，无需启动浏览器。"
    return prefix + (
        "未保存 refresh_token：Token 过期后需启动浏览器重新登录；"
        "用「浏览器登录捕获」重新捕获一次即可自动存入。"
    )


def _fallback_status(oauth_states: dict[str, Any], provider: str, account: str) -> str:
    saved = oauth_state_entry(oauth_states, provider, account)
    state_len = len(str(saved.get("state") or ""))
    label = f"{OAUTH_PROVIDER_LABELS.get(provider, provider)} / {account}"
    return f"{label}（{state_len} 字符）" if state_len else f"{label}（未保存登录态）"


def build_form_plan(row: SiteRow, oauth_states: dict[str, Any]) -> FormPlan:
    auth = row.auth
    action = row.checkin_action
    is_browser = auth == "browser_state"
    is_oauth = auth == "oauth"
    # 「脚本类」= 由模板自己跑流程的任务方式。它们要展示参数与超时输入框。
    is_script = action in {"script", "browser_flow"}
    # 模板路径框：任何任务方式都能指向一个仓库内模板文件（那就是新的「自定义脚本」）。
    allow_api_script = action in {"http_api", "visit", ""}
    needs_oauth = is_oauth or action == "relogin"
    allow_fallback = can_optional_oauth(row.type, action, auth)
    fallback_provider, fallback_account = normalized_fallback(row)
    # 接口变体与验证机制是 New API 系模板的参数；派生模板（继承 newapi）同样适用。
    newapi_family = row.type.startswith("newapi") or row.type in {"sotamodel"}

    plan = FormPlan(
        show_variant=newapi_family and action in {"http_api", ""},
        show_verification=newapi_family and action in {"http_api", ""},
        show_script=True,
        show_script_args=True,
        show_script_timeout=True,
        script_hint=SCRIPT_HINT_API if allow_api_script else SCRIPT_HINT_BROWSER,
        script_placeholder=SCRIPT_PLACEHOLDER_API if allow_api_script else SCRIPT_PLACEHOLDER_BROWSER,
        show_oauth=needs_oauth,
        show_fallback=allow_fallback,
        # 只有「真的会用到登录态」时才显示这一栏：浏览器登录态、OAuth，或者确实配了
        # 备选 OAuth。allow_fallback 现在恒为真（备选链对所有方式开放），拿它当可见性
        # 条件会让每个站点都多出一个用不上的输入框。
        show_state_box=is_browser or needs_oauth or bool(fallback_provider),
        state_editable=is_browser,
        show_oauth_status=needs_oauth or bool(fallback_provider),
        show_browser_ops=is_browser or needs_oauth,
        show_delete_oauth=needs_oauth,
        creds_enabled=auth in ("access_token", "cookie"),
        # sub2api 永远可以手填接口凭据：签到链路先纯 API（token → refresh_token
        # 续期），浏览器只是最后的兜底，所以 browser/oauth 登录方式下这两个框也必须可编辑。
        token_enabled=row.type == "sub2api" or auth in ("access_token", "cookie"),
        # refresh_token 决定 Token 过期时能否纯 HTTP 续期（不必每次拉起浏览器）。
        show_refresh_status=row.type == "sub2api",
        show_refresh_input=row.type == "sub2api",
        refresh_status=_refresh_token_status(row),
    )

    if needs_oauth:
        prov = normalize_oauth_provider(row.oauth_provider) or "linuxdo"
        account = normalize_oauth_account(row.oauth_account)
        state_len = len(oauth_state_text(oauth_states, prov, account))
        label = f"{OAUTH_PROVIDER_LABELS.get(prov, prov)} / {account}"
        plan.oauth_status = (
            f"已保存 {label} 登录态（{state_len} 字符）。"
            if state_len
            else f"尚未保存 {label} 登录态；请输入账号名后点击“捕获 OAuth 登录态”。"
        )
        plan.capture_text = "捕获 OAuth 登录态"
        plan.verify_text = "检测 OAuth 登录态"
        plan.mode_hint = (
            "💡 自定义脚本会用已保存的 OAuth 登录态启动浏览器，并由脚本控制页面点击。脚本路径请使用仓库内相对路径。"
            if is_script
            else "💡 OAuth 登录态按“提供商 + 账号”保存，可被多个站点复用；浏览器重登会自动使用 OAuth 登录方式。"
        )
    elif is_browser:
        if is_script and allow_fallback:
            if fallback_provider:
                plan.oauth_status = f"可选 OAuth：{_fallback_status(oauth_states, fallback_provider, fallback_account)}"
            else:
                plan.oauth_status = (
                    _NO_SHARED_OAUTH_HINT
                    if not has_shared_oauth(oauth_states)
                    else "可选 OAuth 当前未启用；可从已保存的共享账号中选择。"
                )
            plan.mode_hint = _SCRIPT_FALLBACK_HINT
        else:
            plan.mode_hint = "💡 站点浏览器登录态仅用于当前站点，不会作为共享 OAuth 账号使用。"
    elif allow_fallback:
        if fallback_provider:
            plan.oauth_status = _fallback_status(oauth_states, fallback_provider, fallback_account)
        elif not has_shared_oauth(oauth_states):
            plan.oauth_status = _NO_SHARED_OAUTH_HINT
        if is_script:
            plan.mode_hint = _SCRIPT_FALLBACK_HINT
    return plan


# ── 快照 / 校验 / 持久化 ─────────────────────────────────────────────────────
def _snapshot_row(row: SiteRow) -> dict[str, Any]:
    auth = row.auth
    fallback_provider, fallback_account = normalized_fallback(row)
    return {
        "name": row.name.strip(),
        "base_url": normalize_base_url(row.base_url),
        "type": (row.script.strip() or row.type or "auto"),
        "auth_method": auth,
        "checkin_action": row.checkin_action,
        "script": row.script.strip(),
        "script_args_text": row.script_args_text,
        "script_timeout": parse_script_timeout(row.script_timeout),
        "api_variant": normalize_api_variant(row.api_variant),
        "oauth_provider": normalize_oauth_provider(row.oauth_provider) or "linuxdo",
        "oauth_account": normalize_oauth_account(row.oauth_account),
        "oauth_fallback_provider": fallback_provider,
        "oauth_fallback_account": fallback_account,
        "enabled": bool(row.enabled),
        "user_id": row.user_id.strip(),
        "access_token": row.access_token.strip(),
        "refresh_token": row.refresh_token.strip(),
        "cookie": row.cookie.strip(),
        "browser_state": row.browser_state.strip() if auth == "browser" and row.checkin_action != "relogin" else "",
        "proxy": row.proxy.strip(),
        "verify_ssl": parse_enabled(row.verify_ssl, True),
        # 这两项也要进快照，否则改动它们不会把配置标记为「未保存」。
        "cookie_file": row.cookie_file.strip(),
        "referer_path": row.referer_path.strip() or _REFERER_PATH_DEFAULT,
    }


def _normalized_oauth_states(states: dict[str, Any] | None) -> dict[str, Any]:
    """共享登录态的规范化视图，供指纹比较使用。"""
    out: dict[str, Any] = {}
    for provider, entry in (states or {}).items():
        accounts = (entry or {}).get("accounts") if isinstance(entry, dict) else None
        if not isinstance(accounts, dict):
            continue
        cleaned = {
            str(name): {
                "state": str((item or {}).get("state") or ""),
                "username": str((item or {}).get("username") or ""),
                "updated_at": str((item or {}).get("updated_at") or ""),
            }
            for name, item in accounts.items()
            if isinstance(item, dict)
        }
        if cleaned:
            out[str(provider).strip().lower()] = {"accounts": cleaned}
    return out


def config_snapshot(rows: list[SiteRow], oauth_states: dict[str, Any]) -> str:
    """内存配置的规范化指纹，用于脏状态比较。"""
    payload = {
        "accounts": [_snapshot_row(row) for row in rows],
        "oauth_states": _normalized_oauth_states(oauth_states),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def credential_snapshot(row: SiteRow) -> dict[str, str]:
    """GUI 成功保存时的凭据基线；用稳定 runtime_id 关联，仅在当前进程内存在。"""
    return {
        "name": row.name.strip(),
        "base_url": normalize_base_url(row.base_url),
        "account_id": row.account_id.strip() or _new_account_id(row),
        "access_token": row.access_token.strip(),
        "refresh_token": row.refresh_token.strip(),
        "browser_state": row.browser_state.strip(),
    }


def credential_snapshots(rows: list[SiteRow]) -> dict[str, dict[str, str]]:
    """按 SiteRow.runtime_id 建立基线，避免对象销毁后 CPython id 被复用。"""
    return {row.runtime_id: credential_snapshot(row) for row in rows}


def changed_credential_fields(row: SiteRow, saved: dict[str, str] | None) -> set[str]:
    """返回相对上次成功保存真正变化的凭据字段（空值变化也保留）。"""
    current = {k: v for k, v in credential_snapshot(row).items() if k != "account_id"}
    if saved is None:
        return {"access_token", "refresh_token", "browser_state"}
    return {
        field
        for field in ("access_token", "refresh_token", "browser_state")
        if current[field] != str(saved.get(field) or "")
    }


def validate_rows(rows: list[SiteRow]) -> str | None:
    """保存前校验；返回错误文案，None 表示通过。"""
    for row in rows:
        if not row.name.strip():
            return "存在空的站点名称。"
        if not row.base_url.strip():
            return f"「{row.name}」缺少站点地址。"
    names = [row.name.strip() for row in rows]
    if len(names) != len(set(names)):
        return "站点名称重复，请改为唯一名称。"
    for row in rows:
        label = row.name or "未命名站点"
        template = row.script.strip() or row.type.strip()
        if not template:
            return f"「{label}」未选择模板，也没有填写模板路径。"
        # 模板路径写错是最常见的配置错误，而任务往后台跑，报错要隔很久才被看到，
        # 所以在保存时就查一次。内置模板 id 与仓库内路径都走同一个解析器。
        if template.lower() != "auto":
            error = _script_path_error(template)
            if error:
                return f"「{label}」的模板{error}"
        # 任务参数必须是 JSON 对象：写错时不该等到执行当天才在日志里失败。
        text = row.script_args_text.strip() or "{}"
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            return f"「{label}」的任务参数不是合法 JSON：{exc}"
        if not isinstance(parsed, dict):
            return f"「{label}」的任务参数必须是 JSON 对象。"
    return None


def _script_path_error(script_path: str) -> str | None:
    """模板是否可解析；可用返回 None，否则返回接在「模板」后面的原因。

    内置 id（``newapi``）、用户模板与仓库内脚本路径都走同一个解析器，因此这里也顺带
    校验了「选了一个不存在的模板」。
    """
    try:
        _templates.get(script_path)
    except Exception as exc:  # noqa: BLE001 - 校验失败只需给文案
        return f"不可用：{exc}"
    return None


def validate_export(rows: list[SiteRow]) -> str | None:
    enabled_rows = [row for row in rows if row.enabled]
    if not enabled_rows:
        return "没有启用的站点可导出到 GitHub Secret。"
    for row in enabled_rows:
        if not row.name.strip():
            return "启用站点中存在空的站点名称。"
        if not row.base_url.strip():
            return f"「{row.name or '未命名站点'}」缺少站点地址。"
    names = [row.name.strip() for row in enabled_rows]
    if len(names) != len(set(names)):
        return "启用站点名称重复，请改为唯一名称或禁用重复项。"
    return None


def persist_accounts(rows: list[SiteRow]) -> list[dict[str, Any]]:
    """GUI 行 → ACCOUNTS.json 的 accounts 数组（假定 validate_rows 已通过）。"""
    return [_schema.dump_account(row_to_account(row)) for row in rows]


def persist_document(rows: list[SiteRow], oauth_states: dict[str, Any]) -> Any:
    """GUI 行 + 共享登录态 → 完整 v3 文档。"""
    return _schema.Document(
        accounts=tuple(row_to_account(row) for row in rows),
        oauth_states=dict(oauth_states or {}),
        path=_paths.ACCOUNTS_PATH,
    )


def apply_credential_cache_changes(
    rows: list[SiteRow],
    saved_credentials: dict[str, dict[str, str]],
) -> int:
    """报告本次保存里有多少个账号改动了凭据。**不做任何缓存写入。**

    旧实现要在这里主动删除/标记运行期缓存。新模型不需要：覆盖层为每个缓存字段记着
    「写入时配置里那一份的摘要」，读取时发现摘要对不上就自动不采用（见
    ``config/overlay.py`` 的规则 4）。这比事件式标记更可靠——用户直接编辑
    ACCOUNTS.json、或者在别的进程里改配置，同样会被发现。

    返回值只用于保存后的提示文案。
    """
    changed = 0
    for row in rows:
        if changed_credential_fields(row, saved_credentials.get(row.runtime_id)):
            changed += 1
    return changed


# ── 剪贴板导入 / 凭据导出 ────────────────────────────────────────────────────
#: 各站点/各导出工具对令牌的叫法。归一化后按同一集合识别，避免只认一种写法。
_TOKEN_KEY_NAMES = frozenset({"accesstoken", "authtoken", "refreshtoken", "rttoken"})


def _compact_token_key(value: Any) -> str:
    """令牌键名归一化：auth_token/authToken/AUTH-TOKEN 均视为同一键。"""
    return "".join(char for char in str(value or "").casefold() if char.isalnum())


def _clean_embedded_token(value: Any) -> str:
    """清除 JSON 字符串展示时混入的换行/缩进；Bearer/rt token 不允许含空白。"""
    if not isinstance(value, str):
        return ""
    return "".join(value.split())


def _extract_json_tokens(root: Any) -> dict[str, str]:
    """从任意 JSON 结构广度优先提取 access/refresh token。

    除普通 dict/list 外，也解析看起来像 JSON 的字符串值，兼容 localStorage 导出、
    DevTools 存储快照及多层包装。相同类型优先采用标准键 access_token / refresh_token，
    找不到时再采用 auth_token / rt_token；节点预算防止异常大 JSON 长时间遍历。
    """
    found: dict[str, str] = {}
    queue: deque[Any] = deque([root])
    remaining = 10000
    decoded_strings = 0

    while queue and remaining > 0:
        node = queue.popleft()
        remaining -= 1
        if isinstance(node, dict):
            for key, value in node.items():
                normalized = _compact_token_key(key)
                if normalized in _TOKEN_KEY_NAMES and normalized not in found:
                    token = _clean_embedded_token(value)
                    if token:
                        found[normalized] = token
                if isinstance(value, (dict, list)):
                    queue.append(value)
                elif isinstance(value, str):
                    stripped = value.strip()
                    if (
                        decoded_strings < 128
                        and len(stripped) <= 2_000_000
                        and stripped.startswith(("{", "["))
                    ):
                        try:
                            nested = json.loads(stripped)
                        except json.JSONDecodeError:
                            continue
                        decoded_strings += 1
                        queue.append(nested)
        elif isinstance(node, list):
            queue.extend(node)
        elif isinstance(node, str):
            stripped = node.strip()
            if stripped.startswith(("{", "[")) and len(stripped) <= 2_000_000:
                try:
                    queue.append(json.loads(stripped))
                except json.JSONDecodeError:
                    pass

    access = found.get("accesstoken") or found.get("authtoken") or ""
    refresh = found.get("refreshtoken") or found.get("rttoken") or ""
    return {
        key: value
        for key, value in (("access_token", access), ("refresh_token", refresh))
        if value
    }


def parse_clipboard_site(text: str) -> tuple[dict[str, Any] | None, str]:
    """剪贴板 JSON → 站点字段子集；返回 (data, error)。

    原有站点/collector JSON 识别逻辑保持不变；额外从完整 JSON 的任意层级提取
    auth_token/access_token 与 rt_token/refresh_token，映射到 GUI 标准字段。
    """
    if not (text or "").strip():
        return None, "剪贴板为空。"
    try:
        root = json.loads(text)
    except json.JSONDecodeError:
        return None, "剪贴板内容不是合法 JSON。"

    extracted_tokens = _extract_json_tokens(root)
    data = root
    if isinstance(data, list) and data:
        data = data[0]
    if not isinstance(data, dict):
        if extracted_tokens:
            return extracted_tokens, ""
        return None, "JSON 结构无法识别。"
    if "name" not in data and "base_url" not in data and len(data) == 1:
        key, value = next(iter(data.items()))
        if isinstance(value, dict):
            value.setdefault("name", key)
            data = value

    # 原有顶层标准字段优先；只有缺少 access_token / refresh_token 时才补递归结果。
    for key, value in extracted_tokens.items():
        current = data.get(key)
        if not isinstance(current, str) or not current.strip():
            data[key] = value
    return data, ""


_CLIPBOARD_SITE_FIELDS = frozenset({
    "name",
    "base_url",
    "url",
    "site_profile",
    "type",
    "provider",
    "auth_method",
    "checkin_action",
    "script",
    "script_args",
    "script_timeout",
    "api_variant",
    "oauth_provider",
    "oauth_account",
    "oauth_account_id",
    "oauth_fallback_provider",
    "oauth_fallback_account",
    "enabled",
    "user_id",
    "access_token",
    "refresh_token",
    "cookie",
    "browser_state",
    "proxy",
    "verify_ssl",
    "cookie_file",
    "token_file",
    "referer_path",
})


def merge_clipboard_site(row: SiteRow, data: dict[str, Any]) -> SiteRow:
    """把 collector / 凭据 JSON 安全合并到现有行。

    只接受已知字段，避免把任意 JSON 键带进 GUI 模型；未出现在剪贴板里的字段保持原值。
    ``runtime_id`` 属于当前 GUI 身份，合并后必须保持不变。

    collector.js 仍在用旧词表（``site_profile`` / ``auth_method`` / ``checkin_action``），
    这里做一次翻译——用户不该为了粘贴一份凭据先去升级浏览器书签。
    """
    merged = replace(row, script_args=dict(row.script_args))

    for key in _CLIPBOARD_SITE_FIELDS:
        if key in data and hasattr(merged, key):
            setattr(merged, key, data[key])

    # 站点族：collector 给 site_profile，旧剪贴板可能只给 type/provider。
    for key in ("site_profile", "type", "provider"):
        if data.get(key):
            merged.type = str(data[key]).strip().lower()
            break
    if data.get("script"):
        merged.script = _map_legacy_script(str(data["script"]))
        merged.type = merged.script
    if data.get("auth_method"):
        merged.auth_method = _LEGACY_LOGIN_METHODS.get(
            str(data["auth_method"]).strip().lower(), str(data["auth_method"]).strip().lower()
        )
    if data.get("checkin_action"):
        merged.checkin_action = _LEGACY_TASK_METHODS.get(
            str(data["checkin_action"]).strip().lower(), str(data["checkin_action"]).strip().lower()
        )

    merged.base_url = normalize_base_url(merged.base_url)
    merged.oauth_provider = normalize_oauth_provider(merged.oauth_provider) or "linuxdo"
    merged.oauth_account = normalize_oauth_account(merged.oauth_account)
    merged.enabled = parse_enabled(merged.enabled, True)
    if isinstance(merged.script_args, dict) and merged.script_args:
        merged.script_args_text = json.dumps(merged.script_args, ensure_ascii=False, indent=2)
    merged.runtime_id = row.runtime_id
    return merged


#: 旧词表 → 新词表。collector.js 与用户手上的旧配置都还在用左边这一列。
_LEGACY_LOGIN_METHODS = {"browser": "browser_state"}
_LEGACY_TASK_METHODS = {"api": "http_api", "browser_script": "script"}


def _map_legacy_script(script: str) -> str:
    """旧脚本目录 → 新模板目录。"""
    normalized = script.replace("\\", "/").strip()
    return (
        "scripts/tasks/" + normalized[len("scripts/checkin/") :]
        if normalized.startswith("scripts/checkin/")
        else normalized
    )


def cred_json(row: SiteRow) -> str | None:
    cred = {k: getattr(row, k) for k in CRED_FIELDS if getattr(row, k)}
    if not cred:
        return None
    return json.dumps(cred, ensure_ascii=False, indent=2)


# ── 额度 / 状态文案 ──────────────────────────────────────────────────────────
def format_usd(value: float) -> str:
    """美元展示。GUI 侧拿到的数值已是美元，不再做单位换算。"""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return ""
    return f"${number:.2f}" if abs(number) >= 0.01 else f"${number:.4f}"


def detail_quota_usd(detail: dict[str, Any] | None) -> float | None:
    """从结果数据里取当前余额（美元）；取不到返回 None。

    新模型不再让「额度」成为框架字段——模板已经把它渲染进 ``DisplaySpec.text``。
    这里保留一条读取路径，只服务两件事：GUI 的状态缓存（它按数值排序与比较），
    以及读取旧版结果文件。

    单位判定沿用既有约定：``quota_is_usd`` 为真时值本身就是美元，否则是 New API 的
    内部 quota（除以 50 万）。判错单位会让 $0.50 显示成 $0.0000。
    """
    if not isinstance(detail, dict):
        return None
    from core.manifest import ResponseMap

    is_usd = bool(ResponseMap(balance=("quota_is_usd",)).pick(detail, "balance"))
    mapping = ResponseMap(
        balance=("current_quota", "balance", "remaining_quota", "quota"),
        unit="usd" if is_usd else "quota_500000",
    )
    return mapping.to_number(mapping.pick(detail, "balance"))


@dataclass(frozen=True, slots=True)
class _StatusMeta:
    """GUI 用的状态展示元数据。

    从新的子结果注册表派生而不是再维护一张表：``REASONS`` 已经带了标签与图标，
    这里只补 GUI 特有的两种措辞（列表里的短标签、失败提示的前缀）。
    """

    label: str
    icon: str
    ok: bool
    gui_label: str
    compact_label: str
    failure_prefix: str


_GUI_LABELS: dict[str, tuple[str, str, str]] = {
    # reason/verdict → (完整标签, 紧凑标签, 失败前缀)
    "success": ("✅ 执行成功", "✅ 成功", ""),
    "already_done": ("🎁 今日已完成", "🎁 已完成", ""),
    "no_effect": ("🚧 无影响", "🚧 无影响", ""),
    "not_open": ("🚧 活动未开放", "🚧 未开放", ""),
    "not_applicable": ("➖ 不适用", "➖ 不适用", ""),
    "tolerated": ("➖ 已豁免", "➖ 豁免", ""),
    "need_login": ("🔐 登录失效", "🔐 失效", "登录失效"),
    "need_verification": ("⚠ 需人机验证", "⚠ 验证", "需要验证"),
    "need_config": ("⚙ 配置缺失", "⚙ 配置", "配置缺失"),
    "network_error": ("🌐 站点不可达", "🌐 不可达", "站点不可达/网络异常"),
    "blocked": ("🚫 出口 IP 被拒", "🚫 被拒", "出口 IP 被拒"),
    "unconfirmed": ("❓ 结果未确认", "❓ 未确认", "结果未确认"),
    "failed": ("❌ 执行失败", "❌ 失败", "执行失败"),
}


def status_meta(value: object) -> _StatusMeta:
    """把「结论 key」翻译成展示元数据。

    接受三种输入：新的 reason（need_login）、新的 verdict（success/failed），以及
    旧结果文件里的 8 值 status——过渡期两种结果文件会同时存在。
    """
    key = str(value or "").strip().lower()
    if key in {"", "unknown"}:
        key = "failed"
    if key == "error":  # 旧 status
        key = "failed"
    spec = _REASONS.get(key, _parse_verdict(key, _Verdict.FAILED))
    verdict = spec.verdict if key in _REASONS else _parse_verdict(key, _Verdict.FAILED)
    gui_label, compact, prefix = _GUI_LABELS.get(key, (spec.label, spec.label, ""))
    return _StatusMeta(
        label=spec.label,
        icon=spec.icon,
        ok=verdict in {_Verdict.SUCCESS, _Verdict.ALREADY_DONE, _Verdict.NO_EFFECT},
        gui_label=gui_label,
        compact_label=compact,
        failure_prefix=prefix,
    )


def _failure_meta(status: str):
    meta = status_meta(status)
    return meta if meta.failure_prefix else status_meta("error")


def failure_label(status: str, *, compact: bool = False) -> str:
    meta = _failure_meta(status)
    return meta.compact_label if compact else meta.gui_label


def failure_toast(status: str, message: str) -> str:
    prefix = _failure_meta(status).failure_prefix
    return f"{prefix}：{message}" if message else prefix


# ── 稳定任务身份 / 站点租约 ──────────────────────────────────────────────────
@dataclass(frozen=True)
class TaskSnapshot:
    row_id: str
    name: str
    base_url: str
    status_key: str
    channel_key: str
    site_group_key: str
    params: dict[str, Any]


def make_task_snapshot(
    row: SiteRow,
    oauth_states: dict[str, Any],
    *,
    explicit_credential_fields: set[str] | frozenset[str] = frozenset(),
) -> TaskSnapshot:
    return TaskSnapshot(
        row_id=row.runtime_id,
        name=row.name.strip() or "未命名站点",
        base_url=normalize_base_url(row.base_url),
        status_key=StatusStore.status_key(row),
        channel_key=StatusStore.task_key(row),
        site_group_key=StatusStore.site_group_key(row),
        params=task_params(
            row,
            oauth_states,
            explicit_credential_fields=explicit_credential_fields,
        ),
    )


@dataclass(frozen=True)
class TaskLease:
    token: str
    site_key: str
    channel_keys: frozenset[str]


class TaskLeaseRegistry:
    """统一单签/批量的站点级租约；状态归属仍按渠道 key 区分。"""

    def __init__(self) -> None:
        self._sites: dict[str, str] = {}
        self._channels: dict[str, str] = {}

    def acquire(self, site_key: str, channel_keys: set[str] | frozenset[str]) -> TaskLease | None:
        site = str(site_key or "").strip()
        channels = frozenset(str(key or "").strip() for key in channel_keys if str(key or "").strip())
        if not site or not channels:
            return None
        if site in self._sites or any(key in self._channels for key in channels):
            return None
        token = uuid.uuid4().hex
        self._sites[site] = token
        for key in channels:
            self._channels[key] = token
        return TaskLease(token=token, site_key=site, channel_keys=channels)

    def acquire_single(self, row: SiteRow) -> TaskLease | None:
        return self.acquire(StatusStore.site_group_key(row), {StatusStore.task_key(row)})

    def acquire_group(self, snapshots: list[TaskSnapshot]) -> TaskLease | None:
        if not snapshots:
            return None
        return self.acquire(
            snapshots[0].site_group_key,
            {snapshot.channel_key for snapshot in snapshots},
        )

    def release(self, lease: TaskLease | None) -> bool:
        if lease is None or self._sites.get(lease.site_key) != lease.token:
            return False
        self._sites.pop(lease.site_key, None)
        for key in lease.channel_keys:
            if self._channels.get(key) == lease.token:
                self._channels.pop(key, None)
        return True

    def is_channel_running(self, channel_key: str) -> bool:
        return str(channel_key or "").strip() in self._channels

    def is_site_running(self, site_key: str) -> bool:
        return str(site_key or "").strip() in self._sites

    @property
    def running_channels(self) -> int:
        return len(self._channels)


# ── 概览统计 ─────────────────────────────────────────────────────────────────
@dataclass
class Stats:
    total: int = 0
    enabled: int = 0
    done: int = 0
    failed: int = 0
    quota_sum: float = 0.0
    quota_known: int = 0


def summarize(rows: list[SiteRow], store: StatusStore) -> Stats:
    stats = Stats(total=len(rows))
    for row in rows:
        if row.enabled:
            stats.enabled += 1
        entry = store.get(StatusStore.status_key(row)) or {}
        if entry.get("checked_in") is True:
            stats.done += 1
        if entry.get("ok") is False:
            stats.failed += 1
        quota = entry.get("quota_usd")
        if isinstance(quota, (int, float)):
            stats.quota_sum += float(quota)
            stats.quota_known += 1
    return stats
