"""浏览器：算法与调度。

两层住在同一个包里，边界靠模块划分而不是目录：

**算法**（怎么过盾、怎么解题）——不认识账号、任务与配置：
- ``bypass``：Camoufox 启动、Cloudflare 挑战页求解
- ``waf``：阿里云 WAF 判别与求解、出口 IP 熔断
- ``turnstile`` / ``hcaptcha``：两类人机验证的求解
- ``openai_vision``：hCaptcha 的视觉模型客户端
- ``oauth_flow`` / ``oauth_providers``：OAuth 回跳状态机与提供商定义
- ``state`` / ``storage_scope``：登录态编解码、按 origin 取 token 与 Cookie
- ``popups`` / ``site_messages`` / ``runtime_loop``：弹窗拦截、站点提示收集、事件循环与清理

**调度**（什么时候开、开几个、结束时存什么）：
- ``service``：``BrowserService`` 惰性租约。谁都不碰 ``ctx.browser`` 就一次都不启动；
  一个账号一个实例，登录阶段与所有任务共享同一个浏览器。

算法子模块**惰性导入**（PEP 562）：它们会连带拉起 playwright 与 camoufox
（实测 1.4s、763 个模块），而纯 HTTP 路径根本用不到，不该为此付这份代价。
``service`` 例外——它本身很轻，只在真要开浏览器时才 import 算法模块。
"""

from __future__ import annotations

from .service import (
    BrowserLease,
    BrowserService,
    PersistedSession,
    crash_outcome,
    decode_state,
    encode_state,
    is_driver_crash,
    is_network_transport_crash,
    network_transport_outcome,
)

_LAZY = (
    "bypass",
    "hcaptcha",
    "oauth_flow",
    "oauth_providers",
    "openai_vision",
    "popups",
    "runtime_loop",
    "session",
    "site_messages",
    "state",
    "storage_scope",
    "turnstile",
    "waf",
)

__all__ = [
    "BrowserLease",
    "BrowserService",
    "PersistedSession",
    "crash_outcome",
    "decode_state",
    "encode_state",
    "is_driver_crash",
    "is_network_transport_crash",
    "network_transport_outcome",
    *_LAZY,
]


def __getattr__(name: str):
    """按需导入算法子模块，保持 ``from browser import bypass`` 的写法可用。"""
    if name in _LAZY:
        import importlib

        return importlib.import_module(f".{name}", __name__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
