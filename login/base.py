"""登录方式插件的契约。

一个「登录方式」回答同一个问题：**怎么拿到一个已认证的会话**。它不关心站点接口长
什么样（那是模板的事），也不关心要执行什么任务（那是任务方式的事）。

与旧实现的差别：旧代码把这件事拆在四处——``providers/auth.py`` 读凭据、
``providers/actions/_common.py:build_http_client`` 按 auth_method 分支、
``Sub2ApiProfile.refresh_token_via_http`` 管续期、``actions/browser_script.py``
里又写了一遍「token → refresh → 账密」三级降级。四处各有一套「什么算可用」，于是
出现过「判定就绪但客户端拿不到该凭据」这类偏差。

现在：每种方式实现 ``available()`` + ``authenticate()`` 两个函数，候选顺序与降级
策略统一由 ``LoginBroker`` 按 ``FlowPlan`` 执行。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from core.account import ResolvedAccount
from core.outcome import EMPTY_EVIDENCE, Evidence

__all__ = [
    "Availability",
    "LoginContext",
    "LoginMethod",
    "LoginState",
    "READY",
    "render_headers",
    "unavailable",
]


@dataclass(frozen=True, slots=True)
class Availability:
    """这种登录方式此刻能不能用，以及不能用的**可读原因**。

    原因必须能直接进日志：「为什么没走 refresh」是排查里最常问的问题之一，
    旧实现只能靠读代码推断。
    """

    ready: bool
    reason: str = ""


READY = Availability(True)


def unavailable(reason: str) -> Availability:
    return Availability(False, reason)


@dataclass(frozen=True, slots=True)
class LoginState:
    """一次成功登录的产物。"""

    method: str
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    #: 需要写回运行期覆盖层的新凭据（如续期得到的 access_token）。
    credentials: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    #: 是否已向服务端确认过。浏览器类方式据此决定要不要续存登录态。
    verified: bool = False
    cookie_jar: Any = None
    evidence: Evidence = EMPTY_EVIDENCE
    #: 覆盖层里记录的来源标签（refresh / password / browser / oauth / config）。
    origin: str = "runtime"
    note: str = ""


@dataclass
class LoginContext:
    """登录插件的私有上下文。**带凭据**，因此绝不暴露给站点脚本。

    脚本拿到的是 ``sdk.AccountView``（脱敏），要用凭据只能通过已注入认证的
    ``ctx.http``。这条边界是刻意的：脚本不该自己拿着 token 拼请求，否则凭据会随
    脚本的日志、异常与结果四处扩散。
    """

    account: ResolvedAccount
    template: Any                       # LoadedTemplate
    http: Any                           # 未认证的基线 HttpClient
    args: Mapping[str, Any] = field(default_factory=dict)
    browser: Any = None                 # BrowserService | None（惰性）
    capabilities: frozenset[str] = frozenset()
    oauth_state: Callable[[str, str], str] = lambda provider, account: ""
    log: Callable[[str], None] = lambda message: None
    deadline: Any = None

    @property
    def credentials(self):
        return self.account.credentials

    @property
    def base_url(self) -> str:
        return self.account.base_url

    def endpoint(self, name: str, default: str = "") -> str:
        """取模板声明的端点路径。"""
        manifest = getattr(self.template, "manifest", None)
        endpoints = getattr(manifest, "endpoints", {}) or {}
        return str(endpoints.get(name) or default)

    def base_headers(self) -> dict[str, str]:
        """模板声明的站点族固定请求头（已填充占位符）。"""
        manifest = getattr(self.template, "manifest", None)
        return render_headers(getattr(manifest, "headers", {}) or {}, self._header_values())

    def _header_values(self) -> Mapping[str, str]:
        network = self.account.network
        return {
            "base_url": self.account.base_url,
            "origin": self.account.origin,
            "referer_path": getattr(network, "referer_path", "") or "",
            "user_id": str(self.args.get("user_id") or ""),
        }


class LoginMethod(Protocol):
    """登录方式实现契约。"""

    id: str
    requires: frozenset[str]

    def available(self, ctx: LoginContext, option: Any) -> Availability: ...

    async def authenticate(self, ctx: LoginContext, option: Any) -> LoginState: ...


def render_headers(spec: Mapping[str, str], values: Mapping[str, str]) -> dict[str, str]:
    """渲染模板声明的请求头。

    - 占位符缺失按空串处理（``defaultdict``），不抛 KeyError：一个没填 user_id 的
      站点不该因此整个登录失败；
    - 渲染后为空、或仍含未替换占位符的头一律丢弃——发一个 ``New-Api-User:`` 空头
      比不发更糟，部分站点会因此直接 400。
    """
    safe = defaultdict(str, {str(k): str(v or "") for k, v in values.items()})
    out: dict[str, str] = {}
    for name, template in (spec or {}).items():
        try:
            rendered = str(template).format_map(safe).strip()
        except (ValueError, IndexError):
            continue
        if rendered and "{" not in rendered:
            out[str(name)] = rendered
    return out
