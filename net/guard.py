"""防护页与非业务响应的判别。

这个模块承载的是长期踩坑换来的判据，重构中**原样迁移，不重写**：

- Cloudflare **拦截页**（出口 IP 被安全规则拒绝）与**挑战页**（浏览器执行一次 JS
  就能过）必须分开：把拦截页当挑战页会白启一次浏览器再失败一次；反过来会把可解的
  验证误报成封禁。判据不能用 ``challenge-platform``——拦截页也会加载那段 JS。
- 整页 HTML 绝不能当作错误消息：它会一路进汇总行、结果文件与通知，把真正有用的
  信息顶掉，而且看不出到底是被 CF 拦下还是站点回了登录页。
- 「验证」这类宽泛词不能进人机验证词表，否则「token 验证失败」这类登录问题会被
  误分类为需要人机验证。
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

__all__ = [
    "ALREADY_DONE_PATTERNS",
    "BODY_PREVIEW_MAX",
    "GuardKind",
    "already_done_hint",
    "cloudflare_block_details",
    "contains_any",
    "describe_html_body",
    "guard_kind",
    "looks_like_html",
    "looks_like_verification",
    "not_open_hint",
]

#: 非 JSON 响应体存进异常 payload 的字符上限。payload 会作为诊断进结果文件与 GUI，
#: 整页 HTML 放进去只会挤占版面；模式匹配用这段预览足够。
BODY_PREVIEW_MAX = 300


class GuardKind(StrEnum):
    NONE = ""
    #: 浏览器执行 JS / 点一次验证就能通过，值得启动浏览器兜底。
    CHALLENGE = "challenge"
    #: 出口 IP 被安全规则终局拒绝，浏览器同样过不去，唯一动作是换代理节点。
    BLOCK = "block"


# 人机验证特征唯一词表（匹配时双方都转小写）。只收高置信标记。
VERIFICATION_PATTERNS: tuple[str, ...] = (
    "turnstile",
    "cloudflare",
    "just a moment",
    "challenge-platform",
    "人机",
    "captcha",
    "安全验证",
    # 「验证码」比宽泛的「验证」具体得多，不会误伤「token 验证失败」这类登录报错。
    "验证码",
)

# Cloudflare 挑战页特征。不能用 "challenge-platform"：拦截页也会加载
# /cdn-cgi/challenge-platform/scripts/jsd/main.js，用它判定会把「出口 IP 被封禁」
# 误判成「可解挑战」，白启动一次浏览器。
CF_CHALLENGE_PATTERNS: tuple[str, ...] = (
    "just a moment",
    "checking your browser",
    "cf-challenge",
    "cf_chl_opt",
    "_cf_chl_opt",
)

# Cloudflare 硬拦截页特征（HTTP 403 + error 1020 / WAF 规则 / IP 信誉封禁）。
CF_BLOCK_PATTERNS: tuple[str, ...] = (
    "sorry, you have been blocked",
    "attention required! | cloudflare",
    "you are unable to access",
    "error 1020",
    "access denied | cloudflare",
    "cf-error-details",
)

# 阿里云 WAF 的 JS 挑战特征（纯 HTTP 只会拿到这段混淆 JS）。浏览器能执行它，
# 因此与 Cloudflare 挑战页同属「值得开浏览器」的一类。
ALIYUN_WAF_PATTERNS: tuple[str, ...] = (
    "aliyun_waf",
    "acw_sc__",
    "slidecaptcha",
    "var arg1=",
)

# 「活动未开放」特征。只收「功能/活动整体不可用」的说法——「资格不足」「等级不够」
# 是针对单个账号的限制，属于需要用户处理的失败，绝不能进这张表。
NOT_OPEN_PATTERNS: tuple[str, ...] = (
    "签到功能未启用",
    "签到功能已关闭",
    "签到功能暂未开放",
    "签到未开放",
    "签到已关闭",
    "未开启签到",
    "活动未开始",
    "活动已结束",
    "活动未开放",
    "checkin disabled",
    "check-in disabled",
    "checkin is disabled",
    "checkin not enabled",
    "not available yet",
)

# 「今日已完成」特征。各站文案不同但高度趋同；只收明确表示「今天这件事已经做过」
# 的说法，不收「不能重复提交」这类可能来自限流的措辞。
ALREADY_DONE_PATTERNS: tuple[str, ...] = (
    "已签到",
    "今日已",
    "已领取",
    "已完成",
    "明天再来",
    "already checked",
    "already claimed",
    "already completed",
    "duplicate check-in",
)

_CF_RAY_RE = re.compile(r"Cloudflare Ray ID:\s*(?:<[^>]+>\s*)*([0-9a-f]{8,32})", re.I)
_CF_CLIENT_IP_RE = re.compile(r'id="cf-footer-ip"[^>]*>\s*([0-9a-fA-F:.]{3,45})\s*<', re.I)
_HTML_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_HTML_HEADING_RE = re.compile(r"<h[12][^>]*>(.*?)</h[12]>", re.I | re.S)
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def contains_any(text: Any, patterns: tuple[str, ...] | list[str]) -> bool:
    if not isinstance(text, str) or not text:
        return False
    lowered = text.lower()
    return any(pattern.lower() in lowered for pattern in patterns)


def looks_like_html(text: Any) -> bool:
    """响应体是否是 HTML 页面（而不是业务 JSON 或一句纯文本错误）。"""
    if not isinstance(text, str):
        return False
    head = text.lstrip()[:400].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<html" in head


def looks_like_verification(text: Any) -> bool:
    return contains_any(text, VERIFICATION_PATTERNS)


def not_open_hint(text: Any) -> bool:
    return contains_any(text, NOT_OPEN_PATTERNS)


def already_done_hint(text: Any) -> bool:
    """站点是否在说「今天这件事已经做过了」。

    判定顺序上必须先于登录词表：不少站点的「已签到」提示带 code≠0，而登录词表里的
    「无效/过期」很容易误伤，把「今天已经完成」报成登录失效。
    """
    return contains_any(text, ALREADY_DONE_PATTERNS)


def cloudflare_block_details(text: Any) -> dict[str, str] | None:
    """识别 Cloudflare 硬拦截页，返回 Ray ID 与站点回显的出口 IP。

    只在拦截页上返回结果；挑战页（Just a moment）不算——那是可由浏览器执行 JS
    通过的，仍应走浏览器兜底。
    """
    if not isinstance(text, str) or not text:
        return None
    if not contains_any(text, CF_BLOCK_PATTERNS):
        return None
    if contains_any(text, CF_CHALLENGE_PATTERNS):
        return None
    ray = _CF_RAY_RE.search(text)
    client_ip = _CF_CLIENT_IP_RE.search(text)
    return {
        "ray_id": ray.group(1) if ray else "",
        "client_ip": client_ip.group(1) if client_ip else "",
    }


def guard_kind(text: Any) -> GuardKind:
    """判断响应体是哪类防护页。这个区分决定「值不值得启动浏览器」。"""
    if not isinstance(text, str) or not text:
        return GuardKind.NONE
    if cloudflare_block_details(text) is not None:
        return GuardKind.BLOCK
    if contains_any(text, CF_CHALLENGE_PATTERNS + ALIYUN_WAF_PATTERNS):
        return GuardKind.CHALLENGE
    return GuardKind.NONE


def _snippet(pattern: re.Pattern[str], text: str, limit: int = 120) -> str:
    match = pattern.search(text)
    if not match:
        return ""
    inner = _HTML_TAG_RE.sub(" ", match.group(1) or "")
    return " ".join(inner.split())[:limit]


def describe_html_body(text: str, *, limit: int = 160) -> str:
    """把 HTML 响应体压成一句可行动的诊断，绝不把整页 HTML 当错误消息。"""
    block = cloudflare_block_details(text)
    if block is not None:
        marks = [f"Ray ID={block['ray_id']}"] if block["ray_id"] else []
        if block["client_ip"]:
            marks.append(f"出口 IP={block['client_ip']}")
        suffix = f"（{'，'.join(marks)}）" if marks else ""
        return (
            f"Cloudflare 已拒绝当前出口 IP{suffix}：这是站点安全规则的封禁，"
            "不是可作答的验证码，浏览器同样无法通过，与登录态无关。"
            "请更换代理节点/出口 IP 后重试，或联系站长放行。"
        )
    if contains_any(text, CF_CHALLENGE_PATTERNS):
        return "站点返回 Cloudflare 人机验证挑战页（需浏览器执行 JS 挑战），纯 HTTP 无法通过。"
    title = _snippet(_HTML_TITLE_RE, text)
    heading = _snippet(_HTML_HEADING_RE, text)
    summary = " / ".join(dict.fromkeys(part for part in (title, heading) if part))[:limit]
    if summary:
        return f"接口返回 HTML 页面而不是 JSON（{summary}；共 {len(text)} 字符）"
    return f"接口返回 HTML 页面而不是 JSON（共 {len(text)} 字符）"
