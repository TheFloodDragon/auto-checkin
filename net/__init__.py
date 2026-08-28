"""网络层：HTTP 客户端与防护页判别。"""

from __future__ import annotations

from .guard import GuardKind, describe_html_body, guard_kind, looks_like_html, not_open_hint
from .http import (
    DEFAULT_USER_AGENT,
    HttpClient,
    HttpConfig,
    describe_token_defect,
    extract_message,
    normalize_access_token,
    normalize_cookie,
    strip_session_cookie,
    unwrap_data,
)

__all__ = [
    "DEFAULT_USER_AGENT",
    "GuardKind",
    "HttpClient",
    "HttpConfig",
    "describe_html_body",
    "describe_token_defect",
    "extract_message",
    "guard_kind",
    "looks_like_html",
    "normalize_access_token",
    "normalize_cookie",
    "not_open_hint",
    "strip_session_cookie",
    "unwrap_data",
]
