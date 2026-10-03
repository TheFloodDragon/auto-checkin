"""代理日志诊断只能输出固定类别和计数，不能泄露原文。"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from ci import proxy_diagnostics as diagnostics


@pytest.mark.parametrize("message,category", [
    ("lookup private-host: no such host", "dns_resolution"),
    ("lookup private-host on 192.0.2.1:53: i/o timeout", "dns_resolution"),
    ("all DNS requests failed", "dns_resolution"),
    ("interface private-interface not found", "interface_binding"),
    ("bind: cannot assign requested address", "interface_binding"),
    ("proxy authentication required: private-user", "authentication"),
    ("invalid password: private-password", "authentication"),
    ("x509: certificate signed by unknown authority for private-host", "tls_certificate"),
    ("failed to verify certificate private-host", "tls_certificate"),
    ("dial tcp 192.0.2.2:443: i/o timeout", "upstream_connect"),
    ("connect: connection refused 192.0.2.2", "upstream_connect"),
    ("curl_exit=35 TLS handshake EOF private-host", "unknown"),
])
def test_classification_never_returns_log_fragments(tmp_path, capsys, message, category):
    log = tmp_path / "private.log"
    content = message + " token=PRIVATE_SECRET https://private.invalid/sub\n"
    log.write_text(content, encoding="utf-8")
    rows = diagnostics.summarize_log(log)
    assert len(rows) == 1 and rows[0][0:2] == (category, 1)
    assert diagnostics.main([str(log)]) == 0
    output = capsys.readouterr()
    assert f"category={category} count=1" in output.out
    for secret in ("private", "PRIVATE_SECRET", "192.0.2.", "https://", str(tmp_path)):
        assert secret not in output.out.replace("privately", "") + output.err
    assert log.read_text(encoding="utf-8") == content


def test_tail_read_is_bounded_and_discards_partial_line(tmp_path):
    log = tmp_path / "large.log"
    log.write_bytes(b"private-first-line:" + b"x" * (diagnostics.MAX_LOG_BYTES * 3) + b"\nconnection refused private-last\n")
    data = diagnostics.read_log_tail(log)
    assert len(data) <= diagnostics.MAX_LOG_BYTES
    assert data == b"connection refused private-last\n"
    assert diagnostics.summarize_log(log) == [("upstream_connect", 1, "check_upstream_reachability_and_port")]


def test_single_oversized_line_is_not_replayed(tmp_path, capsys):
    log = tmp_path / "large-line.log"
    log.write_bytes(b"PRIVATE" * diagnostics.MAX_LOG_BYTES)
    assert diagnostics.read_log_tail(log) == b""
    diagnostics.main([str(log)])
    assert "PRIVATE" not in capsys.readouterr().out


def test_unknown_binary_log_is_safe(tmp_path, capsys):
    log = tmp_path / "binary.log"
    log.write_bytes(b"\xff\xfe\x00PRIVATE\n\n")
    assert diagnostics.main([str(log)]) == 0
    output = capsys.readouterr()
    assert "category=unknown count=1" in output.out
    assert "PRIVATE" not in output.out and not output.err


def test_categories_are_aggregated_not_raw_log_lines(tmp_path):
    log = tmp_path / "counts.log"
    log.write_text("no such host private-a\nno such host private-b\nconnection refused private-c\n", encoding="utf-8")
    assert diagnostics.summarize_log(log) == [
        ("dns_resolution", 2, "check_dns_and_proxy_hostname"),
        ("upstream_connect", 1, "check_upstream_reachability_and_port"),
    ]


@pytest.mark.parametrize("kind", ["missing", "directory", "exception", "no-argument"])
def test_unavailable_diagnostics_fail_safely(tmp_path, monkeypatch, capsys, kind):
    path = tmp_path / "PRIVATE_PATH"
    if kind == "directory":
        path.mkdir()
    elif kind == "exception":
        def fail(path):
            raise RuntimeError("PRIVATE_RUNTIME_SECRET")
        monkeypatch.setattr(diagnostics, "summarize_log", fail)
    args = [] if kind == "no-argument" else [str(path)]
    assert diagnostics.main(args) == 0
    output = capsys.readouterr()
    assert "hint=diagnostics_unavailable" in output.out
    assert "PRIVATE" not in output.out + output.err


@pytest.mark.skipif(os.name == "nt", reason="FIFO 仅适用于 POSIX")
def test_fifo_is_rejected_without_blocking(tmp_path):
    fifo = Path(tmp_path) / "log-fifo"
    os.mkfifo(fifo)
    with pytest.raises(OSError):
        diagnostics.read_log_tail(fifo)
