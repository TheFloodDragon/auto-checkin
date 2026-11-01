#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""浏览器内的 WAF 检测、求解熔断与用户信息读取。"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import urlsplit

from config.settings import WAFConfig
from net.esa import ACW_POSITIONS as _ACW_POSITIONS  # noqa: F401 - 兼容旧引用
from net.esa import ESA_CHALLENGE_HEADER, ESA_WAF_COOKIES, acw_sc_v2, solve_acw_challenge

from .runtime_loop import LogFn, is_driver_closed_error, noop, safe_goto

WAF_RETRY = WAFConfig.RETRY_ATTEMPTS
WAF_BLOCK_THRESHOLD = WAFConfig.BLOCK_THRESHOLD


def _quota_to_usd(value: Any) -> str:
    """内部 quota → $ 展示。

    New API 的内部额度单位是「quota」，除以 50 万得美元。这里只做展示，不参与任何
    判定；拿不到数值时原样回显，不编造 $0。
    """
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    usd = number / 500_000
    return f"${usd:.2f}" if abs(usd) >= 0.01 else f"${usd:.4f}"


async def fetch_self(page: Any, base_url: str, fallback_uid: str) -> dict[str, Any] | None:
    """在页面上下文读取 ``/api/user/self``，包含同源 Cookie 与用户头。"""
    try:
        return await page.evaluate(
            """async ([baseUrl, fallbackUid, timeoutMs]) => {
                let uid = '';
                for (const key of ['user', 'auth_user']) {
                    try {
                        const stored = JSON.parse(localStorage.getItem(key) || '{}');
                        const id = stored.id ?? stored.user_id;
                        if (id != null && id !== '') { uid = String(id); break; }
                    } catch (_) { /* 忽略 */ }
                }
                if (!uid && fallbackUid) uid = String(fallbackUid);
                const headers = { 'Accept': 'application/json' };
                if (uid) headers['New-Api-User'] = uid;
                const controller = new AbortController();
                const timer = setTimeout(() => controller.abort(), timeoutMs);
                try {
                    const r = await fetch(baseUrl + '/api/user/self', { credentials: 'include', headers, signal: controller.signal });
                    const t = await r.text();
                    const isWaf = /aliyun_waf|slidecaptcha|acw_sc__|Just a moment|cf-challenge/i.test(t);
                    try { return { ok: r.ok, status: r.status, uid, body: JSON.parse(t), is_waf: false }; }
                    catch { return { ok: r.ok, status: r.status, uid, body: t.slice(0, 200), is_waf: isWaf }; }
                } catch (e) {
                    return { ok: false, status: 0, uid, body: String(e && e.name === 'AbortError' ? 'fetch timeout' : e), is_waf: false };
                } finally {
                    clearTimeout(timer);
                }
            }""",
            [base_url, fallback_uid, 15000],
        )
    except Exception as exc:
        if is_driver_closed_error(exc):
            raise
        return None


# ── 阿里云 ESA ``acw_sc__v2`` 挑战自愈 ─────────────────────────────────────────
#
# ESA 的 ``http_custom`` 规则会以 200 + ``X-Tengine-Error: denied by http_custom`` 返回一段
# JS（``var arg1='…'``），脚本算出 ``acw_sc__v2`` 写进 ``document.cookie`` 后 reload。但 ESA 也会在
# 子资源的 307 跳转里用 Set-Cookie 下发 **HttpOnly** 的同名 Cookie；acw_tc 轮换后它就失效了，
# 而页面脚本按规范**写不动 HttpOnly 同名 Cookie**——于是每次 reload 都带着同一个旧值，被重新出题，
# 实测每 0.2s 一跳的死循环（AnyRouter 约 1/4 的会话命中）。等多久都不会自然放行，只有删掉那个
# HttpOnly 值，页面脚本写的新值才能生效（实测 24 轮导航 0 次死循环）。
#
# 页面内 fetch 命中同一挑战时不会执行脚本：此时在 Python 侧按挑战脚本的公开算法补一个非 HttpOnly
# 的 ``acw_sc__v2``，让调用方的下一次读取放行。算法本身在 ``net.esa``，纯 HTTP 客户端共用。


def is_esa_challenge_response(response: Any) -> bool:
    try:
        status = int(getattr(response, "status", 0) or 0)
        headers = getattr(response, "headers", None) or {}
        marker = str(headers.get(ESA_CHALLENGE_HEADER) or "")
    except Exception:
        return False
    return status == 200 and "denied" in marker.lower()


async def heal_esa_response(context: Any, response: Any) -> str:
    """对一条 ESA 挑战响应执行自愈；返回执行的动作（测试与诊断用），不记录 Cookie 值。"""
    if not is_esa_challenge_response(response):
        return ""
    url = str(getattr(response, "url", "") or "")
    try:
        resource = str(getattr(getattr(response, "request", None), "resource_type", "") or "")
    except Exception:
        resource = ""
    action = ""
    for cookie in await context.cookies(url):
        if cookie.get("name") == "acw_sc__v2" and cookie.get("httpOnly"):
            await context.clear_cookies(name="acw_sc__v2", domain=cookie.get("domain"))
            action = "cleared_httponly"
    if resource == "document":
        # 文档挑战交给页面脚本自己写新值；这里只负责移除挡路的 HttpOnly 旧值。
        return action
    try:
        value = solve_acw_challenge(await response.text())
    except Exception:
        value = ""
    if not value:
        return action
    host = urlsplit(url).hostname or ""
    if not host:
        return action
    await context.add_cookies([{
        "name": "acw_sc__v2", "value": value, "domain": host, "path": "/",
        "expires": time.time() + 3600, "httpOnly": False, "secure": False, "sameSite": "Lax",
    }])
    return (action + "+" if action else "") + "computed"


def install_esa_healer(context: Any) -> bool:
    """在 BrowserContext 上挂响应监听；幂等，失败不影响浏览器使用。"""
    if context is None or getattr(context, "_esa_healer_installed", False):
        return False

    def on_response(response: Any) -> None:
        if not is_esa_challenge_response(response):
            return

        async def run() -> None:
            try:
                await heal_esa_response(context, response)
            except Exception:
                pass  # 上下文关闭/导航中断：下一条挑战响应会再试

        try:
            asyncio.get_running_loop().create_task(run())
        except RuntimeError:
            pass

    try:
        context.on("response", on_response)
        setattr(context, "_esa_healer_installed", True)
    except Exception:
        return False
    return True


async def reset_waf_cookies(page: Any, base_url: str) -> None:
    """清掉站点的阿里云 WAF Cookie，让下一跳重新完整出题（打断已形成的挑战循环）。"""
    host = (urlsplit(base_url).hostname or "").lower()
    context = getattr(page, "context", None)
    if not host or context is None:
        return
    labels = host.split(".")
    suffixes = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    domain_re = re.compile(r"^\.?(" + "|".join(re.escape(s) for s in suffixes) + r")$", re.I)
    for name in ESA_WAF_COOKIES:
        try:
            await context.clear_cookies(name=name, domain=domain_re)
        except Exception:
            pass


def waf_circuit(page: Any) -> dict[str, Any]:
    """返回附着在 page 上、跨多次求解共享的熔断状态。"""
    circuit = getattr(page, "_waf_circuit_state", None)
    if not isinstance(circuit, dict):
        circuit = {"fails": 0, "blocked": False}
        try:
            setattr(page, "_waf_circuit_state", circuit)
        except Exception:
            pass
    return circuit


def waf_is_blocked(page: Any) -> bool:
    """当前页面的出口 IP 是否已被判定为持续风控。"""
    return bool(waf_circuit(page).get("blocked"))


async def is_waf_html(page: Any) -> bool:
    """检测当前 HTML 是否仍为阿里云或 Cloudflare 挑战页。"""
    try:
        html = (await page.content() or "").lower()
    except Exception:
        return True
    return (
        "aliyun_waf" in html
        or "acw_sc__" in html
        or "var arg1=" in html
        or "slidecaptcha" in html
        or "just a moment" in html
        or "cf-challenge" in html
        or "checking your browser" in html
    )


async def wait_for_ready(page: Any, timeout_ms: int = 30000, log: LogFn = noop) -> bool:
    """等待页面脱离挑战并渲染出可见链接或按钮。"""
    ready_js = """() => {
        const text = document.body ? document.body.innerText : '';
        const blocked = /请进行验证|为了更好的访问体验|访问受限|Access denied|verify you are human|Just a moment|Checking your browser/i.test(text);
        if (blocked) return false;
        const isVisible = (el) => {
            if (!el || !el.isConnected) return false;
            const s = window.getComputedStyle(el);
            if (s.display === 'none' || s.visibility === 'hidden' || parseFloat(s.opacity) === 0) return false;
            const r = el.getBoundingClientRect();
            return r.width > 0 && r.height > 0;
        };
        const countVisible = (sel) => [...document.querySelectorAll(sel)].filter(isVisible).length;
        return countVisible('a') > 0 || countVisible('button') > 0;
    }"""
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
    except Exception:
        pass
    if await is_waf_html(page):
        log("页面为 WAF 挑战页，跳过就绪等待")
        return False
    try:
        await page.wait_for_function(ready_js, timeout=min(timeout_ms, 10000))
        return True
    except Exception:
        log("页面就绪检测超时（继续尝试操作）")
        return False


async def _solve_cloudflare(page: Any, log: LogFn, circuit: dict[str, Any]) -> bool:
    from .bypass import TurnstileBypass
    from runtime.events import challenge_data, emit_challenge

    result = await TurnstileBypass(log=log).solve_result(page, mode="page_access", timeout=20)
    circuit["challenge"] = challenge_data(result)
    emit_challenge(result)
    if result.ok:
        circuit["fails"] = 0
    return result.ok


async def solve_waf(page: Any, base_url: str, log: LogFn = noop, rounds: int = 3) -> bool:
    """通过真实页面导航执行 WAF JS 挑战，并对持续失败进行熔断。"""
    circuit = waf_circuit(page)
    if circuit.get("blocked"):
        log("WAF 已熔断（出口 IP 被持续风控），跳过重复求解")
        return False

    # 已有 CF 挑战必须在原文档里观察，不用导航为同一挑战重新开预算。
    try:
        html = (await page.content() or "").lower()
    except Exception:
        html = ""
    if not any(marker in html for marker in ("aliyun_waf", "acw_sc__", "slidecaptcha", "var arg1=")):
        return await _solve_cloudflare(page, log, circuit)

    install_esa_healer(getattr(page, "context", None))
    for round_index in range(rounds):
        log(f"WAF 绕过尝试 {round_index + 1}/{rounds}（页面导航触发 JS 挑战）...")
        if round_index:
            # 上一轮没放行多半是 HttpOnly 旧 acw_sc__v2 卡住的重出题循环：清掉整组 WAF
            # Cookie 让这一轮从头出题，而不是带着同一个旧值继续空等。
            await reset_waf_cookies(page, base_url)
        try:
            await safe_goto(page, base_url + "/console", wait_until="domcontentloaded", timeout=25000, log=log)
        except Exception as exc:
            if is_driver_closed_error(exc):
                raise
            log(f"WAF 求解导航中断（继续等待）：{type(exc).__name__}")

        # 阿里云 JS 挑战仅观察自然放行；若这一跳转为 CF，交给同一结构化会话。
        for _ in range(15):
            await asyncio.sleep(1.0)
            try:
                current_html = (await page.content() or "").lower()
            except Exception:
                current_html = ""
            if any(marker in current_html for marker in ("just a moment", "cf-challenge", "challenge-platform", "checking your browser")):
                return await _solve_cloudflare(page, log, circuit)
            if current_html and not await is_waf_html(page):
                log(f"WAF 挑战已通过（第 {round_index + 1} 轮）")
                circuit["fails"] = 0
                return True
        log(f"WAF 挑战未通过，重试 {round_index + 1}/{rounds}")

    circuit["fails"] = int(circuit.get("fails", 0)) + 1
    if circuit["fails"] >= WAF_BLOCK_THRESHOLD:
        circuit["blocked"] = True
        log(f"WAF 求解连续失败 {circuit['fails']} 次，判定出口 IP 被持续风控（熔断，后续跳过求解）")
    else:
        log(f"WAF 挑战求解失败（{circuit['fails']}/{WAF_BLOCK_THRESHOLD}，IP 可能被持续风控）")
    return False


async def read_user(
    page: Any,
    base_url: str,
    fallback_uid: str = "",
    log: LogFn = noop,
) -> dict[str, Any] | None:
    """读取用户信息，在 WAF 命中时求解并按配置重试。"""
    if await is_waf_html(page):
        if waf_is_blocked(page):
            log("WAF 已熔断（出口 IP 被持续风控），跳过读取额度")
            return None
        log("当前页面为 WAF 挑战页，先用页面导航求解...")
        if not await solve_waf(page, base_url, log, rounds=WAF_RETRY):
            return None
        if waf_is_blocked(page):
            return None

    for attempt in range(WAF_RETRY):
        result = await fetch_self(page, base_url, fallback_uid)
        if not isinstance(result, dict):
            await asyncio.sleep(1.0)
            continue

        body = result.get("body")
        if isinstance(body, dict) and body.get("success") and body.get("data"):
            data = body["data"]
            username = data.get("username") or ""
            quota = data.get("quota")
            log(f"当前用户：{username}，额度 {_quota_to_usd(quota)}")
            return data

        if result.get("is_waf") and attempt < WAF_RETRY - 1:
            if waf_is_blocked(page):
                log("WAF 已熔断，停止重试读取额度")
                break
            log(f"命中 WAF，导航求解后重试 {attempt + 1}/{WAF_RETRY - 1}")
            if not await solve_waf(page, base_url, log, rounds=2):
                return None
            if waf_is_blocked(page):
                log("WAF 已熔断，停止重试读取额度")
                break
            await asyncio.sleep(1.0)
            continue

        snippet = body if isinstance(body, str) else str(body)[:120]
        log(
            f"读取额度未成功：status={result.get('status')} uid={result.get('uid')!r} "
            f"waf={result.get('is_waf')} body={snippet}"
        )
        return None

    log("读取用户信息失败（登录态可能已失效或 WAF 无法绕过）")
    return None


__all__ = [
    "ESA_WAF_COOKIES",
    "WAF_BLOCK_THRESHOLD",
    "WAF_RETRY",
    "acw_sc_v2",
    "heal_esa_response",
    "install_esa_healer",
    "is_esa_challenge_response",
    "reset_waf_cookies",
    "solve_acw_challenge",
    "fetch_self",
    "is_waf_html",
    "read_user",
    "solve_waf",
    "waf_circuit",
    "waf_is_blocked",
    "wait_for_ready",
]
