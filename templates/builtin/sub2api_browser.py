#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sub2API 站点的浏览器登录态捕获与 token 刷新。

这些函数是 Sub2API 站点特定的，不属于通用的浏览器会话管理。
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable

from browser import bypass, popups
from browser.state import BrowserStateError, decode_state, encode_state, restore_storage_state, state_summary


class Sub2APIBrowserError(Exception):
    """Sub2API 浏览器操作错误。"""

    def __init__(self, message: str, status: str = "error") -> None:
        super().__init__(message)
        self.message = message
        self.status = status


LogFn = Callable[[str], None]


def _noop(_: str) -> None:
    """空日志函数。"""


class BrowserResources:
    """浏览器资源管理器，用于自动清理。"""

    def __init__(self, browser: Any) -> None:
        self.browser = browser
        self.pages: list[Any] = []

    def track_page(self, page: Any) -> Any:
        """跟踪页面对象。"""
        self.pages.append(page)
        return page

    async def close(self) -> None:
        """关闭所有资源。"""
        for page in self.pages:
            try:
                await page.close()
            except Exception:
                pass
        try:
            await self.browser.close()
        except Exception:
            pass


def _origin_from_url(url: str) -> str:
    """从 URL 中提取 origin（scheme://host）。"""
    text = str(url or "").strip()
    scheme, sep, rest = text.partition("://")
    if not sep:
        return text.rstrip("/")
    return f"{scheme}://{rest.split('/', 1)[0]}"


async def _safe_goto(page: Any, url: str, wait_until: str, timeout: int, log: LogFn) -> None:
    """安全的页面导航，捕获常见错误。"""
    try:
        await page.goto(url, wait_until=wait_until, timeout=timeout)
    except Exception as exc:
        log(f"导航到 {url} 失败：{exc}")
        raise


async def _wait_for_ready(page: Any, timeout_ms: int, log: LogFn) -> None:
    """等待页面就绪。"""
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
    except Exception:
        pass
    try:
        await page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 8000))
    except Exception:
        pass


async def _safe_storage_state(context: Any, log: LogFn) -> dict[str, Any]:
    """安全地获取存储状态。"""
    try:
        return await context.storage_state()
    except Exception as exc:
        log(f"获取存储状态失败：{exc}")
        return {"cookies": [], "origins": []}


def storage_refresh_token(storage_state: dict[str, Any], base_url: str = "") -> str:
    """从存储状态中提取 refresh_token。"""
    origins = storage_state.get("origins", [])
    if not isinstance(origins, list):
        return ""
    
    for origin_data in origins:
        if not isinstance(origin_data, dict):
            continue
        if base_url and not str(origin_data.get("origin", "")).startswith(base_url.rstrip("/")):
            continue
        
        local_storage = origin_data.get("localStorage", [])
        if not isinstance(local_storage, list):
            continue
        
        for item in local_storage:
            if not isinstance(item, dict):
                continue
            if item.get("name") == "refresh_token":
                value = item.get("value", "")
                if isinstance(value, str) and len(value) > 20:
                    return value
    
    return ""


def _is_driver_closed_error(exc: Exception) -> bool:
    """判断是否为浏览器驱动关闭错误。"""
    msg = str(exc).lower()
    return any(
        marker in msg
        for marker in ("target closed", "execution context", "browser closed", "connection closed")
    )


async def capture_login(
    base_url: str,
    proxy: str = "",
    log: LogFn = _noop,
    wait_for_close: Any = None,
    email: str = "",
    password: str = "",
) -> dict[str, Any]:
    """有头浏览器捕获 Sub2API 站点登录态，支持账密自动登录或人工登录。

    Sub2API 不是 New API，不能用 /api/user/self 验证。捕获时只要求：
    - 用户已在站点完成登录（或提供 email/password 自动登录）；
    - localStorage/sessionStorage 中存在 auth_token/access_token/token/jwt；
    - 尽量用 /api/v1/user/profile、/api/v1/auth/me 验证该前端登录 token。

    Args:
        base_url: 站点地址。
        proxy: 代理 URL（可选）。
        log: 日志回调。
        wait_for_close: 人工登录模式下，等待用户关闭浏览器的回调。
        email: 账号邮箱（提供时自动登录）。
        password: 账号密码（提供时自动登录）。
    """
    auto_login = bool(email and password)
    mode = "自动账密登录" if auto_login else "人工登录"
    log(f"启动 Camoufox 浏览器（有头模式），{mode}...")

    try:
        browser, context = await bypass.launch_camoufox(
            headless=False,
            humanize=True,
            geoip=True,
            proxy=proxy or None,
        )
    except Exception as exc:
        raise Sub2APIBrowserError(
            f"启动 Camoufox 失败（请先运行 `camoufox fetch` 安装浏览器）：{exc}"
        ) from exc

    resources = BrowserResources(browser=browser)
    page = None
    try:
        page = resources.track_page(await context.new_page())
        await popups.setup_popup_guard(page, allowed_origin=_origin_from_url(base_url))
        
        if auto_login:
            # 自动账密登录流程
            login_url = base_url.rstrip("/") + "/login"
            await _safe_goto(page, login_url, wait_until="domcontentloaded", timeout=30000, log=log)
            await asyncio.sleep(2)  # 等待页面稳定
            
            # 填写登录表单
            log("填写登录表单...")
            fill_result = await page.evaluate(
                """([email, password]) => {
                    const assign = (selector, value) => {
                        const el = document.querySelector(selector);
                        if (!(el instanceof HTMLInputElement)) return false;
                        const desc = Object.getOwnPropertyDescriptor(
                            window.HTMLInputElement.prototype, 'value'
                        );
                        if (!desc || typeof desc.set !== 'function') return false;
                        desc.set.call(el, value);
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                        return true;
                    };
                    const okEmail = assign('#email', email) || assign('input[type="email"]', email) || assign('input[name="email"]', email);
                    const okPass = assign('#password', password) || assign('input[type="password"]', password) || assign('input[name="password"]', password);
                    return Boolean(okEmail && okPass);
                }""",
                [email, password]
            )
            
            if not fill_result:
                return {
                    "ok": False,
                    "message": "无法找到登录表单的邮箱或密码字段，请手动登录或检查站点页面结构。",
                    "state": "",
                    "username": "",
                    "access_token": "",
                }
            
            log("等待 Turnstile 验证...")
            # 等待 Turnstile 完成（最多 30 秒）
            await asyncio.sleep(3)
            
            # 尝试查找并点击登录按钮
            log("查找登录按钮...")
            login_button_clicked = await page.evaluate(
                """() => {
                    const selectors = [
                        'button[type="submit"]',
                        'button:has-text("登录")',
                        'button:has-text("Login")',
                        'button:has-text("Sign in")',
                        'input[type="submit"]',
                        '.login-button',
                        '#login-button'
                    ];
                    for (const sel of selectors) {
                        try {
                            const btn = document.querySelector(sel);
                            if (btn && !btn.disabled) {
                                btn.click();
                                return true;
                            }
                        } catch {}
                    }
                    return false;
                }"""
            )
            
            if not login_button_clicked:
                log("无法自动点击登录按钮，尝试提交表单...")
                await page.evaluate(
                    """() => {
                        const form = document.querySelector('form');
                        if (form) form.submit();
                    }"""
                )
            
            log("等待登录完成...")
            await asyncio.sleep(5)  # 等待登录响应
        else:
            # 人工登录模式
            await _safe_goto(page, base_url, wait_until="domcontentloaded", timeout=30000, log=log)
            
            if wait_for_close:
                import inspect
                ret = wait_for_close()
                if inspect.isawaitable(ret):
                    await ret
            else:
                log("等待 60 秒后自动关闭浏览器...")
                await asyncio.sleep(60)

        token = await page.evaluate(
            """() => {
                for (const key of ['auth_token', 'access_token', 'token', 'jwt']) {
                    const value = localStorage.getItem(key) || sessionStorage.getItem(key) || '';
                    if (value && value.length > 20) return value;
                }
                return '';
            }"""
        )
        if not token:
            return {
                "ok": False,
                "message": "未在 localStorage/sessionStorage 中读取到 Sub2API auth_token，请确认已完成登录后再点击完成。",
                "state": "",
                "username": "",
                "access_token": "",
            }

        verify = await page.evaluate(
            """async ([baseUrl, token, timeoutMs]) => {
                let last = null;
                for (const path of ['/api/v1/user/profile', '/api/v1/auth/me', '/api/v1/usage?page=1&page_size=1&sort_by=created_at&sort_order=desc']) {
                    const controller = new AbortController();
                    const timer = setTimeout(() => controller.abort(), timeoutMs);
                    try {
                        const r = await fetch(baseUrl + path, {
                            credentials: 'include',
                            headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
                            signal: controller.signal,
                        });
                        const t = await r.text();
                        let body;
                        try { body = JSON.parse(t); } catch { body = t.slice(0, 200); }
                        const result = { ok: false, status: r.status, path, body };
                        if (r.ok) return { ok: true, status: r.status, path, body };
                        if (r.status === 401 || r.status === 403) return result;
                        last = result;
                    } catch (e) {
                        last = { ok: false, status: 0, path, body: String(e && e.name === 'AbortError' ? 'fetch timeout' : e) };
                    } finally {
                        clearTimeout(timer);
                    }
                }
                return last || { ok: false, status: 404, path: '', body: 'profile endpoints not found' };
            }""",
            [base_url.rstrip("/"), token, 15000],
        )
        ok = bool(isinstance(verify, dict) and verify.get("ok"))
        body = verify.get("body") if isinstance(verify, dict) else None
        data = body.get("data") if isinstance(body, dict) and isinstance(body.get("data"), dict) else (body if isinstance(body, dict) else {})
        username = ""
        if isinstance(data, dict):
            user_data = data
            items = data.get("items")
            if isinstance(items, list) and items and isinstance(items[0], dict) and isinstance(items[0].get("user"), dict):
                user_data = items[0]["user"]
            username = str(user_data.get("username") or user_data.get("name") or user_data.get("email") or user_data.get("id") or "")
        if ok:
            log(f"Sub2API 登录态验证成功：{username or '已登录'}")
        else:
            status = verify.get("status") if isinstance(verify, dict) else "?"
            path = verify.get("path") if isinstance(verify, dict) else ""
            log(f"已读取 auth_token，但 {path or '/api/v1/user/profile'} 验证未成功（HTTP {status}）；仍保存登录态供后续刷新使用")

        storage_state_dict = await _safe_storage_state(context, log)
        encoded_state = encode_state(storage_state_dict)
        return {
            "ok": True,
            "message": f"Sub2API 登录态捕获成功，已读取 auth_token（{len(token)} 字符）" + ("" if ok else "；但标准用户接口未验证通过"),
            "state": encoded_state,
            "username": username,
            "access_token": token,
            # refresh_token 存进配置后，纯 HTTP 路径可自行续期短期 JWT，
            # 无需为「access_token 过期」这一常见情况再启动浏览器。
            "refresh_token": storage_refresh_token(storage_state_dict, base_url=base_url),
            "auth_verified": ok,
        }
    except Exception as exc:
        if _is_driver_closed_error(exc):
            raise Sub2APIBrowserError(
                "浏览器驱动已关闭，Sub2API 登录态捕获中断；请重试，若反复出现请更新 camoufox/playwright。"
            ) from exc
        raise
    finally:
        await resources.close()


# ══════════════════════════════════════════════════════════════════════════════
# Token 刷新
# ══════════════════════════════════════════════════════════════════════════════

async def capture_token(
    base_url: str,
    browser_state_text: str = "",
    proxy: str = "",
    log: LogFn = _noop,
    return_state: bool = False,
) -> str | dict[str, Any] | None:
    """用浏览器登录态打开 sub2api 站点，从 localStorage 提取最新 auth_token。

    sub2api 的 JWT（auth_token）会过期，但只要浏览器持有有效的 linux.do
    登录态，打开站点后前端会自动用 refresh 流程刷新出新的 auth_token。
    本函数加载登录态、打开站点、等待并读取 localStorage 的 auth_token。

    Args:
        base_url: sub2api 站点地址。
        browser_state_text: 登录态 base64 文本。
        proxy: 代理 URL（可选）。
        log: 日志回调。
        return_state: 是否返回完整状态（包含 access_token/refresh_token/state）。

    Returns:
        默认返回最新的 auth_token 字符串，失败返回 None；return_state=True 时返回包含 access_token/state 的 dict。
    """
    if not browser_state_text:
        log("未提供 browser_state，无法自动刷新 token")
        return None

    try:
        storage_state_dict = decode_state(browser_state_text)
        log(f"已解码登录态：{state_summary(storage_state_dict)}")
    except BrowserStateError as exc:
        raise Sub2APIBrowserError(f"登录态解码失败：{exc}", status="need_config") from exc

    import os
    headless_env = os.getenv("CAMOUFOX_HEADLESS", "").strip().lower()
    headless = headless_env in ("1", "true", "yes")
    mode_label = "无头" if headless else "有头"
    log(f"Camoufox 运行模式：{mode_label}" + (" / proxy" if proxy else ""))
    
    try:
        browser, context = await bypass.launch_camoufox(
            headless=headless, humanize=False, geoip=True, proxy=proxy or None,
        )
    except Exception as exc:
        raise Sub2APIBrowserError(f"启动 Camoufox 失败：{exc}") from exc

    resources = BrowserResources(browser=browser)
    page = None
    try:
        await restore_storage_state(context, storage_state_dict)

        page = resources.track_page(await context.new_page())
        await popups.setup_popup_guard(page, allowed_origin=_origin_from_url(base_url))
        await _safe_goto(page, base_url, wait_until="domcontentloaded", timeout=30000, log=log)
        await _wait_for_ready(page, timeout_ms=30000, log=log)

        async def _read_token() -> str:
            try:
                return await page.evaluate(
                    """() => {
                        for (const key of ['auth_token', 'access_token', 'token', 'jwt']) {
                            const value = localStorage.getItem(key) || sessionStorage.getItem(key) || '';
                            if (value && value.length > 20) return value;
                        }
                        return '';
                    }"""
                )
            except Exception:
                return ""

        async def _success(token_value: str) -> str | dict[str, Any]:
            if not return_state:
                return token_value
            storage_state = await _safe_storage_state(context, log)
            # 一并交出 refresh_token：它有效期远长于 access_token，存进配置后
            # 纯 HTTP 路径即可自行续期，无需为「JWT 过期」拉起浏览器。
            #
            # 不能只看导出的活 storage_state：access_token 过期时前端会在收到 401 后
            # 清空 localStorage 跳登录页（实测每 2 秒左右清一次，与 add_init_script
            # 的重注入来回竞争）。恰好在清空后导出就会丢掉一个仍然有效的
            # refresh_token。传入的登录态是解码后的静态快照，不受该竞争影响，
            # 因此活存储读不到时回落到它。
            refresh = storage_refresh_token(storage_state, base_url=base_url) or storage_refresh_token(
                storage_state_dict, base_url=base_url
            )
            return {
                "access_token": token_value,
                "refresh_token": refresh,
                "state": encode_state(storage_state),
            }

        async def _clear_cached_token() -> None:
            try:
                await page.evaluate(
                    """() => {
                        for (const key of ['auth_token', 'access_token', 'token', 'jwt']) {
                            try { localStorage.removeItem(key); } catch (_) {}
                            try { sessionStorage.removeItem(key); } catch (_) {}
                        }
                    }"""
                )
            except Exception:
                pass

        async def _verify_token(token_value: str) -> dict[str, Any]:
            """验证 token 是否有效；返回 {"ok": bool, "status": int, "path": str}。"""
            try:
                result = await page.evaluate(
                    """async ([baseUrl, token]) => {
                        for (const path of ['/api/v1/user/profile', '/api/v1/auth/me']) {
                            try {
                                const r = await fetch(baseUrl + path, {
                                    credentials: 'include',
                                    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
                                });
                                if (r.ok) return { ok: true, status: r.status, path };
                                if (r.status === 401 || r.status === 403) return { ok: false, status: r.status, path };
                            } catch {}
                        }
                        return { ok: false, status: 404, path: '' };
                    }""",
                    [base_url.rstrip("/"), token_value]
                )
                return result if isinstance(result, dict) else {"ok": False, "status": 0, "path": ""}
            except Exception:
                return {"ok": False, "status": 0, "path": ""}

        async def _refresh_via_refresh_token() -> str:
            """用 refresh_token 刷新 access_token；成功返回新 token，失败返回空。"""
            refresh_token = storage_refresh_token(storage_state_dict, base_url=base_url)
            if not refresh_token:
                return ""
            try:
                return await page.evaluate(
                    """async ([baseUrl, refreshToken]) => {
                        try {
                            const r = await fetch(baseUrl + '/api/v1/auth/refresh', {
                                method: 'POST',
                                credentials: 'include',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ refresh_token: refreshToken }),
                            });
                            if (!r.ok) return '';
                            const data = await r.json();
                            const newToken = data && data.access_token;
                            if (newToken && typeof newToken === 'string' && newToken.length > 20) {
                                localStorage.setItem('auth_token', newToken);
                                return newToken;
                            }
                        } catch {}
                        return '';
                    }""",
                    [base_url.rstrip("/"), refresh_token]
                )
            except Exception:
                return ""

        async def _validated_token(label: str) -> str:
            token_value = await _read_token()
            if not token_value:
                return ""
            verify = await _verify_token(token_value)
            if verify.get("ok"):
                log(f"已读取并验证 auth_token（{len(token_value)} 字符，{verify.get('path') or '/api/v1/user/profile'}）")
                return token_value
            status = verify.get("status")
            path = verify.get("path") or "/api/v1/user/profile"
            if status in (401, 403):
                log(f"{label} auth_token 已失效（{path} HTTP {status}），尝试用 refresh_token 刷新...")
                refreshed = await _refresh_via_refresh_token()
                if refreshed:
                    refreshed_verify = await _verify_token(refreshed)
                    if refreshed_verify.get("ok"):
                        log(f"refresh_token 刷新后的 auth_token 验证成功（{refreshed_verify.get('path') or '/api/v1/user/profile'}）")
                        return refreshed
                await _clear_cached_token()
                return ""
            if status == 404:
                log(f"未找到 Sub2API 标准验证接口，保留已读取 token 供兼容旧 fork 使用（{len(token_value)} 字符）")
                return token_value
            log(f"{label} auth_token 验证未成功（{path} HTTP {status}），准备触发前端登录刷新...")
            return ""

        # 给前端 token 刷新流程一点时间；旧 localStorage token 必须先经 /api/v1/* 验证，避免返回过期 JWT。
        await asyncio.sleep(3)
        token = await _validated_token("当前")
        if token:
            return await _success(token)

        # 只有第三方登录态、没有站点态时，前端可能不会自动刷新；打开登录页并点击 OAuth 登录按钮。
        log("未在 localStorage 中找到 auth_token，尝试触发 Sub2API 登录流程...")
        try:
            await _safe_goto(page, base_url.rstrip("/") + "/login", wait_until="domcontentloaded", timeout=30000, log=log)
            await _wait_for_ready(page, timeout_ms=20000, log=log)
            await asyncio.sleep(1)
        except Exception:
            pass
        
        # 尝试点击 OAuth 登录按钮
        login_clicked = await page.evaluate(
            """() => {
                const selectors = [
                    "button:has-text('使用 Linux.do 登录')",
                    "button:has-text('Continue with Linux.do')",
                    "button:has-text('Linux.do')",
                    "button:has-text('LinuxDO')",
                ];
                for (const sel of selectors) {
                    try {
                        const btn = document.querySelector(sel);
                        if (btn) {
                            btn.click();
                            return true;
                        }
                    } catch {}
                }
                return false;
            }"""
        )
        
        if login_clicked:
            log("已点击 OAuth 登录按钮，等待登录完成...")
            await asyncio.sleep(5)
            token = await _validated_token("OAuth 登录后")
            if token:
                return await _success(token)

        log("无法获取有效的 auth_token，请重新捕获 browser_state")
        return None

    except Exception as exc:
        if _is_driver_closed_error(exc):
            raise Sub2APIBrowserError(
                "浏览器驱动已关闭，token 刷新中断；请重试，若反复出现请更新 camoufox/playwright。"
            ) from exc
        raise
    finally:
        await resources.close()
