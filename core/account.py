"""账号与任务的配置模型（v3 schema 的内存形态）。

与旧 ``providers.base.SiteConfig`` 的区别：

- **分组而非平铺**。旧 SiteConfig 有 27 个平铺字段，凭据、网络、流程、脚本参数
  混在一起，新增一个字段就要同步改 CLI 参数、worker 环境变量、GUI 行、
  Secret 导出四处。现在按 ``login`` / ``task`` / ``credentials`` / ``network`` /
  ``policy`` / ``flow`` 分组，整组传递。
- **稳定 id**。旧代码用 ``base_url|name`` 拼接串做缓存键与状态键，改个站点名
  就丢掉全部运行期缓存与历史状态。``AccountSpec.id`` 是显式稳定身份。
- **一个账号可以有多个任务**。``tasks`` 是列表，取代「一个站点只能有一个签到
  动作、附加任务只能挂在成功分支上」的旧结构。
- **运行期覆盖不改配置对象**。``AccountSpec`` 是用户配置的忠实镜像（只读语义）；
  叠加覆盖层后产出独立的 ``ResolvedAccount``，两者永不互相污染。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from .chain import ChainSpec
from .errors import ConfigError

__all__ = [
    "AccountSpec",
    "CredentialSet",
    "LoginSpec",
    "NetworkSpec",
    "PolicySpec",
    "ResolvedAccount",
    "TaskSpec",
    "normalize_base_url",
    "slug_seed",
    "slugify",
]

#: 运行期覆盖层可以接管的凭据字段。其它字段一律以配置为准。
CREDENTIAL_FIELDS: tuple[str, ...] = (
    "access_token",
    "refresh_token",
    "cookie",
    "browser_state",
    "session_cookie",
)

#: 凭据分组：覆盖层按组计算指纹，用户只换 token 时不会误伤浏览器登录态。
CREDENTIAL_GROUPS: Mapping[str, str] = MappingProxyType(
    {
        "access_token": "token",
        "refresh_token": "token",
        "cookie": "cookie",
        "session_cookie": "cookie",
        "browser_state": "state",
    }
)

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def normalize_base_url(value: object) -> str:
    """归一化站点地址：去尾斜杠、补 https、小写主机名。

    唯一实现放在 core：旧代码在 ``accounts_store`` 定义、``providers.base`` 与
    ``checkin.py`` 各 re-export 一次，容易出现三处行为不一致。
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    if not parts.netloc:
        return ""
    scheme = (parts.scheme or "https").lower()
    netloc = parts.netloc.lower()
    path = parts.path.rstrip("/")
    return f"{scheme}://{netloc}{path}"


def slugify(value: object, *, fallback: str = "account") -> str:
    """生成稳定 id：仅小写字母数字与连字符。中文名回落到 fallback+哈希。"""
    text = _SLUG_RE.sub("-", str(value or "").strip().lower()).strip("-")
    if text:
        return text[:48]
    raw = str(value or "").strip()
    if not raw:
        return fallback
    import hashlib

    return f"{fallback}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:8]}"


def slug_seed(name: object, base_url: object) -> str:
    """账号 id 的默认种子：先用名字，名字不含 ASCII 字母数字时退到站点主机名。

    中文站点名很常见，直接哈希会得到 ``account-3f2a91b0`` 这种没法读的 id——而 id 会
    出现在结果文件、日志和缓存键里，可读性直接影响排查效率。主机名总是 ASCII。
    """
    text = _SLUG_RE.sub("-", str(name or "").strip().lower()).strip("-")
    if text:
        return text[:48]
    host = urlsplit(normalize_base_url(base_url)).netloc.split(":")[0]
    text = _SLUG_RE.sub("-", host.lower()).strip("-")
    if text:
        return text[:48]
    return slugify(name or base_url)


@dataclass(frozen=True, slots=True)
class CredentialSet:
    """凭据。永不进日志、结果文件与 GUI 快照（由 mask/sanitize 层统一保证）。"""

    access_token: str = ""
    refresh_token: str = ""
    cookie: str = ""
    browser_state: str = ""
    session_cookie: str = ""

    def get(self, name: str) -> str:
        return str(getattr(self, name, "") or "")

    def nonempty(self) -> frozenset[str]:
        return frozenset(name for name in CREDENTIAL_FIELDS if self.get(name))

    def replaced(self, **fields: str) -> "CredentialSet":
        clean = {key: str(value or "") for key, value in fields.items() if key in CREDENTIAL_FIELDS}
        return replace(self, **clean) if clean else self

    def __repr__(self) -> str:  # pragma: no cover - 防止凭据在调试输出里泄露
        present = ",".join(sorted(self.nonempty())) or "-"
        return f"CredentialSet(<{present}>)"


@dataclass(frozen=True, slots=True)
class LoginSpec:
    """登录配置。``method`` 为空表示交给 flow 决定（auto/探测）。"""

    method: str = ""
    provider: str = ""              # OAuth 提供商
    account: str = "default"        # 同一 provider 下的账号名
    args: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    #: 主方式失败后依次尝试的备选（取代旧的 oauth_fallback_provider/account 单点特例）
    fallback: tuple["LoginSpec", ...] = ()

    def chain(self) -> tuple["LoginSpec", ...]:
        return (self,) + self.fallback


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """一个每日任务。"""

    id: str = "daily"
    template: str = ""              # 空 = 继承账号级 template
    method: str = ""                # 空 = 交给 flow 决定
    title: str = ""
    enabled: bool = True
    timeout: int = 240
    args: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    #: 依赖的其它任务 id：前置任务未成功则本任务判为 not_applicable，不算失败。
    depends_on: tuple[str, ...] = ()
    policy: "PolicySpec | None" = None
    text_label: str = ""            # 覆写模板的自定义文本列表头
    #: 任务级流程覆盖，与账号级 ``flow`` 逐键合并（任务级优先）。
    flow: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    #: 访问链。None = 未配置，沿用 login/flow/method 的原流程；配置后由访问链接管
    #: 「用哪种凭据、走 HTTP 还是浏览器」，原流程的 login / execute 选择不再生效。
    chain: ChainSpec | None = None


@dataclass(frozen=True, slots=True)
class NetworkSpec:
    proxy: str = ""
    verify_ssl: bool = True
    referer_path: str = "/profile"
    proxy_mode: str = ""
    proxy_group: str = ""
    extras: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}), repr=False)


@dataclass(frozen=True, slots=True)
class PolicySpec:
    #: 失败不计入整体成败（既不算成功也不算失败），由引擎改判为 no_effect/tolerated。
    tolerate_failure: bool = False
    #: 当天允许的重试轮数（批量层用）。0 表示不重试。
    retry: int = 1
    #: 是否允许为本账号启动浏览器。关闭后所有 requires={"browser"} 的方式被跳过。
    allow_browser: bool = True
    headless: bool | None = None    # None = 沿用环境策略（CI 无头、本地有头）
    humanize: bool = True


DEFAULT_POLICY = PolicySpec()
DEFAULT_NETWORK = NetworkSpec()


@dataclass(frozen=True, slots=True)
class AccountSpec:
    """一个账号的完整配置（ACCOUNTS.json 的一条）。运行期只读。"""

    id: str
    name: str
    base_url: str
    template: str = "auto"
    enabled: bool = True
    login: LoginSpec = LoginSpec()
    tasks: tuple[TaskSpec, ...] = ()
    credentials: CredentialSet = CredentialSet()
    network: NetworkSpec = DEFAULT_NETWORK
    policy: PolicySpec = DEFAULT_POLICY
    #: 各阶段的流程选择："auto" / 具体方式 / ["a","b"] 优先序 / "off"
    flow: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    display: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    #: 解析时没认出来的键，原样保留并在导出时写回。
    #:
    #: 这不是「以防万一」：用户会手写配置，GUI 会整份重写。没有这一格时，任何
    #: GUI 保存都会静默抹掉它不认识的字段——旧实现就这样丢过 cookie_file 与
    #: referer_path。保留原样也让新版本新增的字段能被旧版本安全地读写往返。
    extras: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        if not self.id:
            raise ConfigError("账号缺少 id")
        if not self.base_url:
            raise ConfigError(f"账号 {self.name or self.id} 缺少 base_url")

    @property
    def origin(self) -> str:
        parts = urlsplit(self.base_url)
        return f"{parts.scheme}://{parts.netloc}" if parts.netloc else self.base_url

    @property
    def site_key(self) -> str:
        """同站串行的分组键。同一 origin 的账号不并发，避免触发站点限流。"""
        return self.origin

    def task(self, task_id: str) -> TaskSpec | None:
        for item in self.tasks:
            if item.id == task_id:
                return item
        return None

    def enabled_tasks(self) -> tuple[TaskSpec, ...]:
        return tuple(item for item in self.tasks if item.enabled)

    def task_policy(self, task: TaskSpec) -> PolicySpec:
        return task.policy or self.policy

    def task_template(self, task: TaskSpec) -> str:
        return task.template or self.template


@dataclass(frozen=True, slots=True)
class ResolvedAccount:
    """叠加运行期覆盖层之后、真正拿去执行的账号视图。

    与 ``AccountSpec`` 分成两个类型（而不是就地改字段）是刻意的：旧实现用
    ``apply_cached_tokens(site)`` 直接 setattr 配置对象，于是「用户配的值」和
    「缓存回填的值」在同一个对象里无法区分，写回缓存时算 basis 只能靠额外的
    ``RuntimeCredentialContext`` 打补丁。这里天然分离，且保留 ``overrides``
    明细供日志与诊断。
    """

    spec: AccountSpec
    credentials: CredentialSet
    #: 字段名 → 覆盖来源说明（"overlay:refresh" / "config" / "explicit"）
    origins: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    #: 覆盖层里学到的流程结论（stage → Discovery 的 payload）
    learned_flow: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    health: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    #: 单次执行冻结的网络设置；原始 spec 始终用于保存及凭据覆盖层。
    effective_network: NetworkSpec | None = field(default=None, repr=False)

    # 常用字段直通，避免调用方到处写 account.spec.xxx
    @property
    def id(self) -> str:
        return self.spec.id

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def base_url(self) -> str:
        return self.spec.base_url

    @property
    def origin(self) -> str:
        return self.spec.origin

    @property
    def network(self) -> NetworkSpec:
        return self.effective_network or self.spec.network

    @property
    def policy(self) -> PolicySpec:
        return self.spec.policy

    @property
    def login(self) -> LoginSpec:
        return self.spec.login

    def overridden(self) -> tuple[str, ...]:
        return tuple(sorted(k for k, v in self.origins.items() if v.startswith("overlay")))

    def with_credentials(self, **fields: str) -> "ResolvedAccount":
        """运行中刷新到新凭据（如 refresh 换到新 token）后的视图。"""
        origins = dict(self.origins)
        for key in fields:
            origins[key] = "runtime"
        return replace(
            self,
            credentials=self.credentials.replaced(**fields),
            origins=MappingProxyType(origins),
        )


def sequence(value: Any) -> tuple[str, ...]:
    """把 str | list[str] | None 统一成字符串元组（flow 配置解析共用）。"""
    if value is None or value == "":
        return ()
    if isinstance(value, str):
        return (value.strip().lower(),)
    if isinstance(value, Sequence):
        return tuple(str(item).strip().lower() for item in value if str(item).strip())
    return (str(value).strip().lower(),)
