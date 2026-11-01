"""阿里云 ESA ``acw_sc__v2`` JS 挑战的纯算法部分（无浏览器依赖）。

ESA 的 ``http_custom`` 规则以 200 + ``X-Tengine-Error: denied by http_custom`` 返回一段
JS（``var arg1='…'``），浏览器执行后写 ``acw_sc__v2`` 再重发。纯 HTTP 客户端不执行 JS，
于是同一请求永远拿到挑战页（实测 AnyRouter OAuth 成功后的 ``/api/user/self`` 只读确认）。
算法是公开的固定置换 + 异或，这里按它求值，供 HTTP 客户端与浏览器自愈共用。
"""

from __future__ import annotations

import re

__all__ = [
    "ESA_CHALLENGE_HEADER", "ESA_WAF_COOKIES", "acw_sc_v2", "challenge_kind", "is_esa_challenge",
    "is_markerless_acw_challenge", "solve_acw_challenge",
]

ESA_CHALLENGE_HEADER = "x-tengine-error"
ESA_WAF_COOKIES = ("acw_sc__v2", "acw_tc", "cdn_sec_tc")
ACW_POSITIONS = (
    0xF, 0x23, 0x1D, 0x18, 0x21, 0x10, 0x1, 0x26, 0xA, 0x9, 0x13, 0x1F, 0x28, 0x1B, 0x16, 0x17, 0x19, 0xD, 0x6, 0xB,
    0x27, 0x12, 0x14, 0x8, 0xE, 0x15, 0x20, 0x1A, 0x2, 0x1E, 0x7, 0x4, 0x11, 0x5, 0x3, 0x1C, 0x22, 0x25, 0xC, 0x24,
)
ACW_XOR_KEY = "3000176000856006061501533003690027800375"
_ARG1_RE = re.compile(r"var\s+arg1\s*=\s*'([0-9A-Fa-f]{40})'")
_POSITIONS_RE = re.compile(r"var\s+m\s*=\s*\[([0-9a-fx,\s]+)\]", re.I)


def acw_sc_v2(arg1: str) -> str:
    """按挑战脚本的算法由 ``arg1`` 计算 ``acw_sc__v2``（固定置换后与固定 key 异或）。"""
    text = str(arg1 or "").strip().upper()
    if len(text) != 40 or any(ch not in "0123456789ABCDEF" for ch in text):
        raise ValueError("arg1 必须是 40 位十六进制")
    shuffled = "".join(text[pos - 1] for pos in ACW_POSITIONS)
    return "".join(
        f"{int(shuffled[i:i + 2], 16) ^ int(ACW_XOR_KEY[i:i + 2], 16):02x}" for i in range(0, 40, 2)
    )


def solve_acw_challenge(html: str) -> str:
    """从挑战页提取 arg1 并求值；置换表与已知算法不一致（站点换了算法）时返回空串。"""
    text = str(html or "")
    match = _ARG1_RE.search(text)
    if not match:
        return ""
    positions = _POSITIONS_RE.search(text)
    if positions:
        try:
            parsed = tuple(int(item.strip(), 0) for item in positions.group(1).split(",") if item.strip())
        except ValueError:
            parsed = ()
        if parsed != ACW_POSITIONS:
            return ""
    return acw_sc_v2(match.group(1))


def is_esa_challenge(status: int, marker: str, body: str) -> bool:
    """200 + ``denied`` 标记 + 可识别的 ``arg1`` 算可自动求解的 ESA 挑战。

    没有 ``X-Tengine-Error`` 标记时（实测 AgentRouter 的 CI 出口），只接受形态完全确定的挑战页：
    HTML 文档 + 40 位 ``arg1`` + 与已知算法一致的置换表。只有 ``arg1`` 的页面不碰。
    """
    if int(status or 0) != 200:
        return False
    text = str(body or "")
    if "denied" in str(marker or "").lower():
        return bool(_ARG1_RE.search(text))
    return is_markerless_acw_challenge(text)


def is_markerless_acw_challenge(body: str) -> bool:
    text = str(body or "")
    # 无响应头标记时要求真正的 HTML 文档，不能把任意 script 片段或展示算法的文本
    # 当作边缘挑战；DOCTYPE 可以省略，根 html 标签不可省略。
    if (not re.match(r"^\s*(?:<!doctype\s+html\b[^>]*>\s*)?<html(?:\s|>)", text, re.I)
            or not _ARG1_RE.search(text)):
        return False
    positions = _POSITIONS_RE.search(text)
    if not positions:
        return False
    try:
        parsed = tuple(int(item.strip(), 0) for item in positions.group(1).split(",") if item.strip())
    except ValueError:
        return False
    return parsed == ACW_POSITIONS


def challenge_kind(body: str) -> str:
    """把 HTML 挑战页粗分为 acw（可按算法求解）、slider、cloudflare、html；非 HTML 返回空串。"""
    text = str(body or "")
    if not text.lstrip().startswith("<") and not re.search(r"var\s+arg1\s*=", text):
        return ""
    if solve_acw_challenge(text):
        return "acw"
    lowered = text.lower()
    if "slidecaptcha" in lowered or "nc_1_wrapper" in lowered or ("aliyun_waf" in lowered and "captcha" in lowered):
        return "slider"
    if "just a moment" in lowered or "cf-challenge" in lowered or "challenge-platform" in lowered:
        return "cloudflare"
    return "html"
