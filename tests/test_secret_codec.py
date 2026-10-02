"""GitHub Secret 精简、压缩与自动解码回归。"""
from __future__ import annotations

import json

import pytest

from config import secrets, store
from config.secret_codec import decode_secret


def test_small_secret_stays_plain_and_compact() -> None:
    payload = {"version": 3, "accounts": [{"id": "site", "enabled": True, "template": "auto"}]}
    result = secrets.encode_payload(payload)
    decoded = json.loads(result.text)

    assert result.compressed is False
    assert decoded["accounts"][0] == {"id": "site"}
    assert result.text == decode_secret(result.text)


def test_large_secret_uses_gzip_prefix_and_round_trips() -> None:
    payload = {"version": 3, "accounts": [{"id": "site", "credentials": {"cookie": "x" * 100_000}}]}
    result = secrets.encode_payload(payload)

    assert result.compressed is True
    assert result.text.startswith("DTG1:")
    assert json.loads(decode_secret(result.text)) == secrets.minimize_payload(payload)
    assert secrets.check_size(result.text) == ""


def test_store_load_decodes_compressed_account_file(tmp_path) -> None:
    payload = {"version": 3, "accounts": [{"id": "site", "base_url": "https://site.invalid"}]}
    packed = secrets.encode_payload(payload).text
    path = tmp_path / "ACCOUNTS.json"
    path.write_text(packed, encoding="utf-8")

    document = store.load(path)
    assert document.accounts[0].id == "site"


def test_decode_rejects_invalid_compressed_secret_without_echoing_payload() -> None:
    with pytest.raises(ValueError, match="Secret 压缩内容无效") as caught:
        decode_secret("DTG1:not-valid")
    assert "not-valid" not in str(caught.value)


def test_secret_limit_matches_github_documented_limit() -> None:
    assert secrets.SECRET_SIZE_LIMIT == 48 * 1024
