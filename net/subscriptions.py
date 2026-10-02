"""受限的订阅来源读取器：不携带凭据、不记录正文、严格限制大小。"""

from __future__ import annotations

import base64
import codecs
import hashlib
import os
import re
import ssl
import tempfile
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field
from email.message import Message
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
from urllib.parse import unquote, urlsplit

from core.errors import ConfigError

__all__ = [
    "FetchedSource", "USER_AGENT", "parse_profile_title", "parse_userinfo", "read_source", "write_text_file",
]

MAX_RAW_BYTES = 4 * 1024 * 1024
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_REDIRECTS = 3
REQUEST_TIMEOUT = 15
MAX_TITLE = 80
#: 机场面板（v2board / xboard / sub-store 等）按 UA 决定输出格式；带 clash.meta / mihomo
#: 才会返回含 vless / anytls 等节点的 Clash Meta YAML，而不是只有 Base64 的通用列表。
USER_AGENT = "clash.meta/1.19 mihomo/1.19 DailyTask-Subscription-Importer/2"
_USERINFO_KEYS = ("upload", "download", "total", "expire")


@dataclass(frozen=True, slots=True)
class FetchedSource:
    text: str = field(repr=False)
    label: str
    kind: str
    title: str = ""
    userinfo: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    content_hash: str = ""


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802 - urllib API
        self.count += 1
        if self.count > MAX_REDIRECTS:
            raise ConfigError("订阅链接重定向次数过多")
        _validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_source(reference: str, *, kind: str) -> FetchedSource:
    """读取本地文件或 HTTP(S) 来源；错误文案不复述来源正文与认证信息。"""
    value = str(reference or "").strip()
    source_kind = str(kind or "").strip().lower()
    if source_kind == "file":
        return _read_file(value)
    if source_kind == "url":
        return _read_url(value)
    raise ConfigError("订阅来源必须是链接或文件")


def _read_file(reference: str) -> FetchedSource:
    if not reference:
        raise ConfigError("请选择要导入的订阅或节点文件")
    path = Path(reference)
    try:
        size = path.stat().st_size
        if size > MAX_RAW_BYTES:
            raise ConfigError("订阅文件过大，不能超过 4 MiB")
        data = path.read_bytes()
    except ConfigError:
        raise
    except (OSError, ValueError):
        raise ConfigError("订阅文件读取失败，请检查文件权限与路径") from None
    if len(data) > MAX_RAW_BYTES:
        raise ConfigError("订阅文件过大，不能超过 4 MiB")
    text = _decode_text(data)
    return FetchedSource(text, path.name[:120] or "订阅文件", "file", content_hash=_content_hash(text))


def _read_url(reference: str) -> FetchedSource:
    _validate_url(reference)
    handler = _SafeRedirectHandler()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        handler,
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    request = urllib.request.Request(
        reference,
        headers={
            "Accept": "text/plain, text/yaml, application/yaml, application/octet-stream;q=0.8",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            length = response.headers.get("Content-Length")
            try:
                if length is not None and int(length) > MAX_RAW_BYTES:
                    raise ConfigError("订阅响应过大，不能超过 4 MiB")
            except ValueError:
                pass
            raw = _read_bounded(response)
            content_encoding = str(response.headers.get("Content-Encoding") or "").lower().strip()
            title = parse_profile_title(response.headers.get("profile-title"),
                                        response.headers.get("Content-Disposition"))
            userinfo = parse_userinfo(response.headers.get("subscription-userinfo"))
    except ConfigError:
        raise
    except urllib.error.HTTPError as exc:
        raise ConfigError(f"订阅请求失败：HTTP {int(exc.code)}") from None
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError):
        raise ConfigError("订阅请求失败，请检查网络、链接和证书") from None
    text = _decode_content(raw, content_encoding)
    return FetchedSource(text, _url_label(reference), "url", title, MappingProxyType(userinfo), _content_hash(text))


def parse_profile_title(profile_title: str | None, disposition: str | None = None) -> str:
    """``profile-title``（可带 ``base64:`` 前缀）优先，其次 Content-Disposition 文件名。"""
    title = ""
    raw = str(profile_title or "").strip()
    if raw:
        if raw.lower().startswith("base64:"):
            try:
                encoded = raw[7:].strip()
                encoded += "=" * (-len(encoded) % 4)
                title = base64.b64decode(encoded, altchars=b"-_", validate=False).decode("utf-8")
            except (ValueError, UnicodeError):
                title = ""
        else:
            title = raw
    if not title and disposition:
        message = Message()
        message["Content-Disposition"] = str(disposition)[:1024]
        try:
            name = message.get_filename() or ""
        except (ValueError, LookupError):
            name = ""
        title = unquote(name, errors="replace")
        title = re.sub(r"\.(ya?ml|txt|conf)$", "", title, flags=re.IGNORECASE)
    title = re.sub(r"[\x00-\x1f\x7f]", "", title).strip()
    return title[:MAX_TITLE]


def parse_userinfo(header: str | None) -> dict[str, int]:
    """解析 ``upload=1; download=2; total=3; expire=4``；只保留已知数值键。"""
    result: dict[str, int] = {}
    for item in str(header or "")[:512].split(";"):
        key, _, value = item.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key in _USERINFO_KEYS and re.fullmatch(r"\d{1,20}", value):
            result[key] = int(value)
    return result


def _validate_url(value: str) -> None:
    try:
        parts = urlsplit(str(value or "").strip())
        valid = parts.scheme.lower() in {"http", "https"} and bool(parts.hostname)
        valid = valid and not parts.username and not parts.password and not parts.fragment
        valid = valid and not any(char.isspace() or ord(char) < 32 for char in str(value))
        valid = valid and parts.port != 0
    except ValueError:
        valid = False
    if not valid:
        raise ConfigError("订阅链接必须是有效的 HTTP(S) 地址，且不能内嵌账号密码")


def _read_bounded(response) -> bytes:
    output = bytearray()
    while True:
        block = response.read(64 * 1024)
        if not block:
            break
        output.extend(block)
        if len(output) > MAX_RAW_BYTES:
            raise ConfigError("订阅响应过大，不能超过 4 MiB")
    return bytes(output)


def _decode_content(data: bytes, encoding: str) -> str:
    if encoding == "gzip":
        data = _gunzip_bounded(data)
    if len(data) > MAX_TEXT_BYTES:
        raise ConfigError("订阅解码后的内容过大，不能超过 8 MiB")
    return _decode_text(data)


def _gunzip_bounded(data: bytes) -> bytes:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = bytearray()
    try:
        for offset in range(0, len(data), 64 * 1024):
            block = decompressor.decompress(data[offset:offset + 64 * 1024], MAX_TEXT_BYTES - len(output) + 1)
            output.extend(block)
            if len(output) > MAX_TEXT_BYTES:
                raise ConfigError("压缩订阅解码后的内容过大，不能超过 8 MiB")
        output.extend(decompressor.flush(MAX_TEXT_BYTES - len(output) + 1))
    except ConfigError:
        raise
    except (OSError, zlib.error):
        raise ConfigError("订阅压缩内容无效") from None
    if len(output) > MAX_TEXT_BYTES:
        raise ConfigError("压缩订阅解码后的内容过大，不能超过 8 MiB")
    return bytes(output)


def _decode_text(data: bytes) -> str:
    try:
        return codecs.decode(data, "utf-8-sig")
    except UnicodeDecodeError:
        raise ConfigError("订阅内容不是有效的 UTF-8 文本") from None


def _url_label(reference: str) -> str:
    try:
        parts = urlsplit(reference)
        host = parts.hostname or "订阅链接"
        port = f":{parts.port}" if parts.port else ""
        return (host + port)[:120]
    except ValueError:
        return "订阅链接"


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_text_file(reference: str, text: str) -> str:
    """以 UTF-8 和同目录临时文件原子写入本地订阅正文。"""
    value = str(reference or "").strip()
    if not value:
        raise ConfigError("请选择要保存的订阅文件")
    if not isinstance(text, str):
        raise ConfigError("订阅正文必须是文本")
    try:
        data = text.encode("utf-8")
        path = Path(value)
        if len(data) > MAX_TEXT_BYTES:
            raise ConfigError("订阅正文过大，不能超过 8 MiB")
        if path.exists() and path.is_dir():
            raise ConfigError("订阅保存目标不能是目录")
        parent = path.parent
        if not parent.is_dir():
            raise ConfigError("订阅保存目录不存在")
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(parent))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    except ConfigError:
        raise
    except (OSError, UnicodeError):
        raise ConfigError("订阅文件保存失败，请检查路径与权限") from None
    return str(path)
