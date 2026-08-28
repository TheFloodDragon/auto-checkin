"""浏览器服务层。

算法层仍在仓库根目录的 ``browser/`` 包（Camoufox 启动、WAF、验证码、OAuth 回跳、
登录态编解码），本包只做调度：什么时候开、开几个、结束时存什么。
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
)

__all__ = [
    "BrowserLease",
    "BrowserService",
    "PersistedSession",
    "crash_outcome",
    "decode_state",
    "encode_state",
    "is_driver_crash",
]
