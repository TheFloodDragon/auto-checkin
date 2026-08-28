"""HTTP 客户端：重试、代理、TLS、Cookie 会话与脱敏日志。

与旧 ``providers.base`` 的差别：

- **异常即结论**。失败一律抛 ``dailytask.core.errors`` 家族，异常自带
  ``verdict``/``reason``，调用方不再逐处写 ``if kind == ... elif ...`` 的翻译分支。
- **客户端是对象而不是自由函数**。base_url、请求头、代理、TLS、cookie jar 绑定在
  实例上，模板只需声明端点路径，不必每次重复拼这些参数。
- **原始返回值日志内建**。旧实现要在每个 profile 里手动调 ``log_http_exchange``，
  漏一处就整条链路静默（README 里为此专门写过一节排查）。
"""

from __future__ import annotations

import gzip
import json
import random
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from urllib.parse import urljoin

from ..core.errors import ConfigError, LoginRequired, NotApplicable, TaskError, TransientError
from . import guard

__all__ = [
    "DEFAULT_USER_AGENT",
    "HttpClient",
    "HttpConfig",
    "IDEMPOTENT_METHODS",
    "normalize_access_token",
    "normalize_cookie",
]

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0"
)

IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})

SESSION_COOKIE_NAMES = frozenset(
    {"session", "newapi_session", "new-api-session", "new_api_session"}
)


@dataclass(frozen=True, slots=True)
class HttpConfig:
    timeout: int = 30
    max_attempts: int = 3
    backoff_base: float = 0.8
    backoff_cap: float = 8.0
    retry_statuses: frozenset[int] = frozenset({429, 500, 502, 503, 504})
    proxy: str = ""
    verify_ssl: bool = True
    user_agent: str = DEFAULT_USER_AGENT
    #: 是否记录站点原始返回值（经脱敏与限长）。签到失败时最有用的信息就是它。
    log_body: bool = True
    log_body_max: int = 600

    @classmethod
    def from_settings(cls, **overrides: Any) -> "HttpConfig":
        """从仓库全局 config.py 取默认值，允许逐项覆盖。"""
        from config import LogConfig, RetryConfig, Timeouts

        base = {
            "timeout": Timeouts.HTTP_REQUEST,
            "max_attempts": RetryConfig.MAX_ATTEMPTS,
            "backoff_base": RetryConfig.BACKOFF_BASE,
            "backoff_cap": RetryConfig.BACKOFF_CAP,
            "retry_statuses": frozenset(RetryConfig.STATUS_CODES),
            "log_body": LogConfig.HTTP_BODY,
            "log_body_max": LogConfig.HTTP_BODY_MAX,
        }
        base.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**base)


@dataclass
class HttpClient:
    """绑定站点的已认证 HTTP 客户端。

    ``headers`` 是每次请求的基线头；登录方式插件通过 ``with_auth()`` 派生出带
    Authorization / Cookie 的实例，而不是就地修改——同一账号可能同时存在
    「token 客户端」和「账密登录后的新客户端」，就地改会串味。
    """

    base_url: str
    config: HttpConfig = field(default_factory=HttpConfig)
    headers: Mapping[str, str] = field(default_factory=dict)
    log: Callable[[str], None] | None = None
    tag: str = ""
    #: 需要跨请求保持会话时挂上（部分站点把会话绑定到客户端指纹，
    #: 登录下发的 cookie 不带回就会被拒：Session network fingerprint changed）。
    cookie_jar: Any = None
    #: 遇到「登录失效」时的一次性续期钩子，由 LoginBroker 安装。
    #:
    #: 为什么放在客户端里：token 过期是**请求中途**才暴露的，而调用方（模板 run()）
    #: 正处在一段业务流程中间，让它自己处理 401 就等于每个模板都要写一遍续期与重放。
    #: 旧实现把这段逻辑写进了 Sub2ApiClient 内部（``_maybe_refresh_token``），于是
    #: 只有那一个 profile 有这个能力，而且和外层的 ``_renew_access_token`` 形成两套
    #: 降级、互相不知道对方试过什么。
    auth_refresher: Callable[["TaskError"], "HttpClient | None"] | None = None
    #: 每个任务最多续期一次。多于一次说明续期本身没解决问题，继续重放只是空耗，
    #: 且会掩盖真正的原因（账号被封同样回 401）。
    _renewed: bool = field(default=False, repr=False)

    def with_auth(
        self,
        *,
        access_token: str = "",
        cookie: str = "",
        extra: Mapping[str, str] | None = None,
    ) -> "HttpClient":
        headers = dict(self.headers)
        token = normalize_access_token(access_token)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if cookie:
            headers["Cookie"] = normalize_cookie(cookie)
        headers.update(dict(extra or {}))
        return HttpClient(
            base_url=self.base_url,
            config=self.config,
            headers=headers,
            log=self.log,
            tag=self.tag,
            cookie_jar=self.cookie_jar,
            auth_refresher=self.auth_refresher,
        )

    def adopt(self, other: "HttpClient") -> None:
        """就地采用另一个客户端的认证（续期后让同一个 ctx.http 立即生效）。"""
        self.headers = dict(other.headers)
        if other.cookie_jar is not None:
            self.cookie_jar = other.cookie_jar

    def reset_auth_renewal(self) -> None:
        """新任务开始时重置一次性续期额度。"""
        self._renewed = False

    def with_session(self) -> "HttpClient":
        """派生一个带 cookie jar 的客户端（登录换 token 这类多步流程用）。"""
        from http.cookiejar import CookieJar

        clone = self.with_auth()
        clone.cookie_jar = self.cookie_jar or CookieJar()
        return clone

    # ── 请求 ────────────────────────────────────────────────────────────
    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self.request("POST", path, **kwargs)

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        data: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = None,
        retry_non_idempotent: bool = False,
        raw: bool = False,
    ) -> Any:
        """发一次请求并解析 JSON。失败抛 ``TaskError`` 家族。

        ``raw=True`` 时返回响应体文本（模板需要解析 HTML 页面时用），
        但防护页判别仍然生效——拿到 Cloudflare 拦截页时不该假装是正常页面。

        登录失效时若装了 ``auth_refresher``，续期一次并**重放同一请求**；重放只做
        一次，且不区分幂等性——续期后的重放是「换个身份重新发起」，与网络抖动重试
        不是一回事（后者才有副作用风险）。
        """
        kwargs = {
            "json_body": json_body,
            "data": data,
            "headers": headers,
            "timeout": timeout,
            "retry_non_idempotent": retry_non_idempotent,
            "raw": raw,
        }
        try:
            return self._send(method, path, **kwargs)
        except LoginRequired as exc:
            renewed = self._renew(exc)
            if renewed is None:
                raise
            return self._send(method, path, **kwargs)

    def _renew(self, exc: "TaskError") -> "HttpClient | None":
        """调用一次性续期钩子；成功则就地采用新认证。"""
        if self.auth_refresher is None or self._renewed:
            return None
        self._renewed = True
        try:
            fresh = self.auth_refresher(exc)
        except Exception:
            # 续期本身出错不该改写原始结论：调用方拿到的仍是「登录失效」。
            return None
        if fresh is None:
            return None
        self.adopt(fresh)
        return fresh

    def _send(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        data: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = None,
        retry_non_idempotent: bool = False,
        raw: bool = False,
    ) -> Any:
        url = self.resolve(path)
        method_upper = str(method or "GET").upper()
        request_headers = {"User-Agent": self.config.user_agent, "Accept": "application/json, text/plain, */*"}
        request_headers.update(dict(self.headers))
        request_headers.update(dict(headers or {}))

        body = data
        if json_body is not None:
            body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")

        retry_allowed = method_upper in IDEMPOTENT_METHODS or retry_non_idempotent
        attempts = max(1, self.config.max_attempts) if retry_allowed else 1
        last: TaskError | None = None

        for attempt in range(attempts):
            try:
                text = self._once(
                    url,
                    method=method_upper,
                    headers=request_headers,
                    body=body,
                    timeout=timeout or self.config.timeout,
                )
            except TaskError as exc:
                last = exc
                if attempt >= attempts - 1 or not isinstance(exc, TransientError):
                    self._log_exchange(method_upper, url, error=exc)
                    raise
                delay = min(self.config.backoff_cap, self.config.backoff_base * (2**attempt))
                time.sleep(delay + random.uniform(0, delay * 0.25))
                continue
            payload = text if raw else parse_json(text)
            self._log_exchange(method_upper, url, payload=payload if not raw else text)
            return payload

        raise last or TaskError("请求失败")

    def resolve(self, path: str) -> str:
        text = str(path or "").strip()
        if text.startswith(("http://", "https://")):
            return text
        return urljoin(self.base_url.rstrip("/") + "/", text.lstrip("/"))

    # ── 内部 ────────────────────────────────────────────────────────────
    def _once(
        self,
        url: str,
        *,
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: int,
    ) -> str:
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        opener = self._opener()
        try:
            with opener.open(request, timeout=timeout) as response:
                return _decode(response.read(), response.headers.get("content-encoding", ""))
        except urllib.error.HTTPError as exc:
            text = _decode(exc.read(), exc.headers.get("content-encoding", ""))
            raise _http_error(exc.code, text, retry_statuses=self.config.retry_statuses) from exc
        except urllib.error.URLError as exc:
            raise TransientError(f"网络请求失败：{exc.reason}") from exc
        except TimeoutError as exc:
            raise TransientError(f"网络请求超时：{exc}") from exc
        except OSError as exc:
            # ssl/socket 读取超时有时表现为普通 OSError（"The read operation timed out"）。
            raise TransientError(f"网络请求失败：{exc}") from exc

    def _opener(self) -> urllib.request.OpenerDirector:
        handlers: list[urllib.request.BaseHandler] = []
        if self.cookie_jar is not None:
            handlers.append(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        if not self.config.verify_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=context))

        proxy = str(self.config.proxy or "").strip()
        if not proxy:
            # 显式空 ProxyHandler：不继承进程隐式代理环境，避免「本机能跑、CI 走了
            # 别的出口」这类难查问题。
            handlers.append(urllib.request.ProxyHandler({}))
            return urllib.request.build_opener(*handlers)
        parts = urllib.parse.urlsplit(proxy)
        if parts.scheme.startswith("socks"):
            raise ConfigError("标准库 HTTP 客户端不支持 SOCKS 代理，请改用 http/https 代理（浏览器流程可用 socks5）。")
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ConfigError("代理地址无效，必须是 http:// 或 https:// URL。")
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        return urllib.request.build_opener(*handlers)

    def _log_exchange(
        self,
        method: str,
        url: str,
        *,
        payload: Any = None,
        error: TaskError | None = None,
    ) -> None:
        if not self.config.log_body:
            return
        from mask_utils import mask_secrets

        limit = self.config.log_body_max
        if error is not None:
            body = error.payload
            if guard.looks_like_html(body):
                # 整页 HTML 的原文对排查没有增量信息，message 已是归纳后的结论
                # （含 Ray ID / 出口 IP）；打原文只会把日志顶满。
                detail = error.message
            elif body not in (None, ""):
                detail = _brief(body, limit)
            else:
                detail = error.message
            suffix = f" status={error.status}" if error.status else ""
            line = f"[http:{self.tag}] {method} {url} 失败{suffix} → {detail}"
        else:
            line = f"[http:{self.tag}] {method} {url} → {_brief(payload, limit)}"
        line = mask_secrets(line)
        if self.log is not None:
            self.log(line)
        else:
            import sys

            print(line, file=sys.stderr, flush=True)


# ── 解析与判别 ──────────────────────────────────────────────────────────────
def request_url(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
    timeout: int | None = None,
    max_attempts: int = 1,
    proxy: str = "",
    verify_ssl: bool = True,
    raw: bool = False,
) -> Any:
    """一次性请求一个**绝对 URL**，不绑定站点。

    给需要打站外端点的组件用（视觉模型网关、第三方 API）。业务请求应该用
    ``HttpClient``：它带认证注入、一次性续期与站点级日志标签。
    """
    config = HttpConfig.from_settings(
        timeout=timeout, max_attempts=max_attempts, proxy=proxy, verify_ssl=verify_ssl
    )
    client = HttpClient(base_url="", config=config, tag="external")
    return client.request(
        method,
        url,
        data=body,
        headers=headers,
        timeout=timeout,
        retry_non_idempotent=max_attempts > 1,
        raw=raw,
    )


def parse_json(text: str) -> Any:
    """解析 JSON；非 JSON 响应按防护页/HTML 归类后抛出对应异常。"""
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        preview = text[:guard.BODY_PREVIEW_MAX]
        kind = guard.guard_kind(text)
        # 判定用完整响应体：CF 拦截页的 title 与 Ray ID 都在 300 字符之外，
        # 只看 preview 会把「出口 IP 被封禁」误判成普通的「接口返回非 JSON」。
        if guard.looks_like_html(text):
            raise _guard_error(kind, guard.describe_html_body(text), preview) from exc
        if guard.looks_like_verification(preview):
            from ..core.errors import VerificationRequired

            raise VerificationRequired(
                "站点要求 Cloudflare/Turnstile 验证，纯 HTTP 无法通过。",
                payload=preview,
                data={"guard": str(kind or guard.GuardKind.CHALLENGE)},
            ) from exc
        raise TaskError(f"接口返回非 JSON：{preview}", payload=preview) from exc


def _guard_error(kind: guard.GuardKind, message: str, preview: str) -> TaskError:
    from ..core.errors import VerificationRequired

    if kind is guard.GuardKind.BLOCK:
        error = TaskError(message, payload=preview, data={"guard": "block"})
        error.reason = "blocked"
        return error
    if kind is guard.GuardKind.CHALLENGE:
        return VerificationRequired(message, payload=preview, data={"guard": "challenge"})
    return TaskError(message, payload=preview)


def _http_error(status: int, text: str, *, retry_statuses: frozenset[int]) -> TaskError:
    """把 HTTP 错误响应翻译成带结论的异常。"""
    payload: Any
    try:
        payload = json.loads(text) if text else None
        message = extract_message(payload)
    except json.JSONDecodeError:
        payload = text[:guard.BODY_PREVIEW_MAX]
        message = guard.describe_html_body(text) if guard.looks_like_html(text) else (payload or f"HTTP {status}")

    if status in retry_statuses:
        return TransientError(message, status=status, payload=payload)
    if guard.not_open_hint(message):
        return NotApplicable(message, status=status, payload=payload)

    kind = guard.guard_kind(text)
    if kind is not guard.GuardKind.NONE:
        error = _guard_error(kind, message, str(payload)[:guard.BODY_PREVIEW_MAX])
        error.status = status
        return error
    if status in (401, 403) and not guard.looks_like_html(text):
        return LoginRequired(message, status=status, payload=payload)
    return TaskError(message, status=status, payload=payload)


def extract_message(payload: Any) -> str:
    keys = ("message", "msg", "errmsgcn", "errmsg", "error", "detail")
    if isinstance(payload, Mapping):
        for key in keys:
            value = payload.get(key)
            if value:
                return str(value)
        data = payload.get("data")
        if isinstance(data, Mapping):
            for key in keys:
                value = data.get(key)
                if value:
                    return str(value)
    if guard.looks_like_html(payload):
        return guard.describe_html_body(payload)
    return str(payload) if payload else "请求失败"


def unwrap_data(payload: Any) -> Any:
    if isinstance(payload, Mapping) and "data" in payload:
        return payload["data"]
    return payload


# ── 凭据规范化 ──────────────────────────────────────────────────────────────
def normalize_access_token(value: object) -> str:
    """规范化 access_token；非 ASCII 内容视为无效并返回空串。

    HTTP 头只能承载 latin-1。配置里若残留占位文本或带省略号的截断值，直接塞进
    Authorization 头会在请求发出**之前**抛 UnicodeEncodeError，绕过一切登录失效
    判定，表现为「明明有可用的 refresh_token 却从不续期」。
    """
    text = str(value or "").strip()
    if text.lower().startswith("authorization:"):
        text = text.split(":", 1)[1].strip()
    if text.lower().startswith("bearer "):
        text = text[7:].strip()
    if not text:
        return ""
    try:
        text.encode("ascii")
    except UnicodeEncodeError:
        return ""
    return text


def describe_token_defect(value: object) -> str:
    """说明「为什么这个 token 不可用」，区分留空 / 值损坏 / 占位文本。"""
    raw = str(value or "").strip()
    if not raw:
        return "配置里 access_token 为空"
    bad = sorted({ch for ch in raw if not ch.isascii()})
    if bad:
        shown = " ".join(f"{ch!r}(U+{ord(ch):04X})" for ch in bad[:3])
        return (
            f"access_token 含非 ASCII 字符 {shown}（共 {len(raw)} 字符），无法用于 HTTP 头，"
            "已视为未配置——多半是从截断显示里复制的残缺值"
        )
    if raw.startswith("<") and raw.endswith(">"):
        return "access_token 仍是占位文本，未填真实值"
    if raw.count(".") != 2:
        return f"access_token 不是 JWT 结构（{len(raw)} 字符，{raw.count('.') + 1} 段），可能复制不完整"
    return f"access_token 被判定为不可用（{len(raw)} 字符）"


def normalize_cookie(value: object) -> str:
    """标准化并去重 Cookie 字符串（重复键保留最后一个）。"""
    text = str(value or "").strip()
    if text.lower().startswith("cookie:"):
        text = text.split(":", 1)[1].strip()
    items: dict[str, str] = {}
    for chunk in text.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, _, val = chunk.partition("=")
        items[key.strip()] = val.strip()
    return "; ".join(f"{k}={v}" for k, v in items.items()) if items else text


def strip_session_cookie(cookie: str) -> str:
    """保留 cf_clearance 等辅助 Cookie，移除 session 以优先走 Access token。"""
    return "; ".join(
        part
        for part in (chunk.strip() for chunk in normalize_cookie(cookie).split(";"))
        if part and part.partition("=")[0].strip().lower() not in SESSION_COOKIE_NAMES
    )


# ── 小工具 ──────────────────────────────────────────────────────────────────
def _decode(body: bytes, content_encoding: str = "") -> str:
    if "gzip" in content_encoding.lower() or body.startswith(b"\x1f\x8b"):
        body = gzip.decompress(body)
    return body.decode("utf-8", "replace")


def _brief(payload: Any, limit: int) -> str:
    if isinstance(payload, (dict, list)):
        try:
            text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            text = str(payload)
    else:
        text = str(payload)
    text = " ".join(text.split())
    if len(text) > limit:
        return f"{text[:limit]}…（共 {len(text)} 字符，已截断）"
    return text
