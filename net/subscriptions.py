"""受限的订阅来源读取器：不携带凭据、不记录正文、严格限制大小。"""

from __future__ import annotations

import codecs
import ssl
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from core.errors import ConfigError

__all__ = ["FetchedSource", "read_source"]

MAX_RAW_BYTES = 4 * 1024 * 1024
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_REDIRECTS = 3
REQUEST_TIMEOUT = 15


@dataclass(frozen=True, slots=True)
class FetchedSource:
    text: str
    label: str
    kind: str


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
    return FetchedSource(_decode_text(data), path.name[:120] or "订阅文件", "file")


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
            "User-Agent": "DailyTask-Subscription-Importer/1",
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
    except ConfigError:
        raise
    except urllib.error.HTTPError as exc:
        raise ConfigError(f"订阅请求失败：HTTP {int(exc.code)}") from None
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError):
        raise ConfigError("订阅请求失败，请检查网络、链接和证书") from None
    return FetchedSource(_decode_content(raw, content_encoding), _url_label(reference), "url")


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
