"""Classify a bounded mihomo log tail without reproducing any log content.

Counts are nonempty tail lines, not unique failures or a proven root cause.
Every displayed category and hint is a constant; generic TLS failures remain
unknown unless the log explicitly describes certificate verification.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import sys


MAX_LOG_BYTES = 64 * 1024
# Order gives specific DNS/interface failures precedence over generic dial errors.
_RULES = (
    ("dns_resolution", "check_dns_and_proxy_hostname", (
        rb"no such host", rb"dns (?:resolve|resolution|lookup) (?:failed|failure|error)",
        rb"(?:resolve|resolving) (?:dns|host(?:name)?|domain).{0,512}fail",
        rb"lookup .{0,512}(?:i/o timeout|server misbehaving|temporary failure|no such host)",
        rb"all dns requests failed", rb"dns:.{0,512}(?:timeout|refused|fail)",
    )),
    ("interface_binding", "check_interface_and_bind_settings", (
        rb"no such (?:network )?interface", rb"interface.{0,512}(?:not found|does not exist)",
        rb"bind:.{0,512}(?:cannot assign requested address|no such device|invalid argument)",
        rb"failed to bind", rb"bind interface.{0,512}(?:fail|error)",
        rb"setsockopt.{0,512}(?:no such device|operation not permitted)",
    )),
    ("authentication", "check_proxy_authentication", (
        rb"auth(?:entication)? (?:failed|failure|error|required)",
        rb"proxy authentication required", rb"invalid (?:password|credentials)",
    )),
    ("tls_certificate", "check_certificate_hostname_and_clock", (
        rb"x509:", rb"certificate verif(?:y|ication) failed",
        rb"failed to verify certificate", rb"certificate (?:has expired|is not yet valid)",
        rb"certificate signed by unknown authority", rb"certificate.{0,512}hostname mismatch",
    )),
    ("upstream_connect", "check_upstream_reachability_and_port", (
        rb"connection refused", rb"(?:dial|connect).{0,512}i/o timeout",
        rb"(?:dial|connect).{0,512}(?:connection timed out|connect(?:ion)? timeout)",
        rb"connect(?:ion)? (?:timed out|timeout)",
    )),
)
_RULES = tuple((category, hint, tuple(re.compile(pattern, re.I) for pattern in patterns))
               for category, hint, patterns in _RULES)
_UNKNOWN_HINT = "inspect_local_log_privately"
_UNAVAILABLE = "[setup_proxy] mihomo故障摘要：category=unknown count=0 hint=diagnostics_unavailable"


def read_log_tail(path: Path) -> bytes:
    """Read at most 64 KiB; discard the first partial line of a truncated tail."""
    # Nonblocking open also prevents an unexpected FIFO from stalling the failure path.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb", buffering=0) as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise OSError("diagnostic input is not a regular file")
        size = stream.seek(0, os.SEEK_END)
        start = max(0, size - MAX_LOG_BYTES)
        stream.seek(start, os.SEEK_SET)
        data = stream.read(MAX_LOG_BYTES)
    if start:
        _, separator, data = data.partition(b"\n")
        if not separator:
            return b""
    return data


def summarize_log(path: Path) -> list[tuple[str, int, str]]:
    """Return only fixed whitelist tokens and integer counts, never matched text."""
    counts = {category: 0 for category, _, _ in _RULES}
    counts["unknown"] = 0
    for line in read_log_tail(path).splitlines():
        if not line.strip():
            continue
        category = "unknown"
        for candidate, _, patterns in _RULES:
            if any(pattern.search(line) for pattern in patterns):
                category = candidate
                break
        counts[category] += 1
    rows = [(category, counts[category], hint)
            for category, hint, _ in _RULES if counts[category]]
    if counts["unknown"] or not rows:
        rows.append(("unknown", counts["unknown"], _UNKNOWN_HINT))
    return rows


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        if len(args) != 1:
            raise ValueError("expected one log file")
        rows = summarize_log(Path(args[0]))
    except Exception:
        # Exception messages can contain sensitive paths/log fragments. Never replay them.
        print(_UNAVAILABLE)
        return 0
    for category, count, hint in rows:
        print(f"[setup_proxy] mihomo故障摘要：category={category} count={count} hint={hint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
