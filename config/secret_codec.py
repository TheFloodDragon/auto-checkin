"""GitHub Secret 文本的安全编码与解码。"""

from __future__ import annotations

import base64
import gzip
import json
import zlib
from dataclasses import dataclass

SECRET_SIZE_LIMIT = 48 * 1024
MAX_DECODED_BYTES = 16 * 1024 * 1024
PREFIX = "DTG1:"


@dataclass(frozen=True, slots=True)
class SecretText:
    text: str
    raw_size: int
    encoded_size: int
    compressed: bool


def _gzip(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=9, mtime=0)


def encode_secret(text: str, *, limit: int = SECRET_SIZE_LIMIT) -> SecretText:
    if not isinstance(text, str):
        raise TypeError("Secret 文本必须是字符串")
    raw = text.encode("utf-8")
    raw_size = len(raw)
    if raw_size <= limit:
        return SecretText(text, raw_size, raw_size, False)
    packed = PREFIX + base64.b64encode(_gzip(raw)).decode("ascii")
    return SecretText(packed, raw_size, len(packed.encode("ascii")), True)


def _bounded_gzip(data: bytes) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    chunks: list[bytes] = []
    total = 0
    cursor = 0
    while cursor < len(data):
        chunk = decoder.decompress(data[cursor:cursor + 64 * 1024], MAX_DECODED_BYTES - total + 1)
        cursor += 64 * 1024
        total += len(chunk)
        if total > MAX_DECODED_BYTES:
            raise ValueError("Secret 解压后超过安全大小上限")
        chunks.append(chunk)
        if decoder.eof:
            break
    tail = decoder.flush(MAX_DECODED_BYTES - total + 1)
    total += len(tail)
    if total > MAX_DECODED_BYTES or not decoder.eof:
        raise ValueError("Secret 压缩内容不完整或超过安全大小上限")
    chunks.append(tail)
    return b"".join(chunks)


def decode_secret(text: str) -> str:
    if not isinstance(text, str):
        raise ValueError("Secret 内容必须是文本")
    value = text.strip()
    if not value.startswith(PREFIX):
        return value
    encoded = value[len(PREFIX):]
    try:
        packed = base64.b64decode(encoded.encode("ascii"), validate=True)
        decoded = _bounded_gzip(packed).decode("utf-8")
        payload = json.loads(decoded)
    except (ValueError, UnicodeError, OSError, json.JSONDecodeError) as exc:
        raise ValueError("Secret 压缩内容无效") from exc
    if not isinstance(payload, dict):
        raise ValueError("Secret 解压内容必须是 JSON 对象")
    return decoded
