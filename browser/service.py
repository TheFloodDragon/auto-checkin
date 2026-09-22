"""浏览器调度：惰性租约、跨任务复用、收尾续存。

与仓库根目录的 ``browser/`` 包的关系：那里是**算法层**（Camoufox 启动、Cloudflare /
阿里云 WAF、Turnstile、hCaptcha、OAuth 回跳、登录态编解码），全部保留不动；这里是
**服务层**，只负责「什么时候开、开几个、结束时存什么」。

三个旧问题在这里被解决：

1. **启动时机靠猜**。旧实现用 ``_should_try_api_first`` 这类看凭据的启发式决定要不要
   开浏览器（``providers/actions/browser_script.py:59``），判定在 action 层，脚本无从
   参与。现在改成惰性：谁都不碰 ``ctx.browser`` 就一次都不启动。
2. **同一账号反复启动**。旧实现里 relogin / api / browser_script 各自 launch 一次，
   OAuth 预处理与脚本 ``run()`` 虽同 context 但跨任务不复用。现在一个账号一个实例，
   登录阶段与所有任务共享。
3. **登录态该不该存**。判定规则（先看是否登录成功、再看任务结论；没有认证证据就不写，
   避免用登出态覆盖上次可用缓存）从 ``browser/script_runner.py:199-267`` 原样迁移，
   只把「写到哪」换成覆盖层。
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

from core.errors import ConfigError, TaskError, TransientError

__all__ = [
    "BrowserLease",
    "BrowserService",
    "PersistedSession",
    "decode_state",
    "encode_state",
]

#: 导出登录态的超时。超过就放弃续存——缓存写不进去只是下次多开一次浏览器，
#: 而卡在这里会让整个任务在收尾阶段被硬超时杀掉，连结论都拿不到。
STATE_EXPORT_TIMEOUT = 8.0
# 首次冷启动（Defender 扫描 / 新建 profile）实测可超过 30 秒；超时后放宽再试一次。
LAUNCH_TIMEOUTS_MS = (60_000, 120_000)
#: 驱动断连重试前的等待。并发启动撞上驱动补丁/profile 初始化时，立刻重试往往会
#: 撞进同一个窗口；短暂退避让先行者先完成。
LAUNCH_RETRY_BACKOFF_SECONDS = 2.0

#: 明确表示「这次没登录成功」的结论。仅当没有任何登录成功证据时才据此拒绝续存：
#: 登录成功而任务失败（如验证码没过）时，登录态仍必须保存。
UNAUTHENTICATED_REASONS = frozenset({"need_login", "need_verification", "need_config"})


@dataclass(frozen=True, slots=True)
class PersistedSession:
    """收尾时要写回覆盖层的东西。"""

    state_text: str = ""
    access_token: str = ""
    refresh_token: str = ""
    auth_verified: bool = False

    def is_empty(self) -> bool:
        return not (self.state_text or self.access_token or self.refresh_token)


def encode_state(storage_state: dict[str, Any]) -> str:
    from . import state as _state

    return _state.encode_state(storage_state)


def decode_state(text: str) -> dict[str, Any]:
    """解码登录态；空串返回空态（合法输入：脚本自行登录）。"""
    from . import state as _state

    if not str(text or "").strip():
        return {"cookies": [], "origins": []}
    try:
        return _state.decode_state(text)
    except _state.BrowserStateError as exc:
        from core.errors import LoginRequired

        raise LoginRequired(f"登录态解码失败：{exc}") from exc


def _launch_error(exc: Exception) -> TaskError:
    """网络/资源错误不是安装错误：仅确实缺少依赖或浏览器时建议 fetch。"""
    from core.masking import mask_secrets

    if isinstance(exc, TaskError):
        return exc
    message = mask_secrets(str(exc))
    lowered = message.lower()
    missing = isinstance(exc, (FileNotFoundError, ImportError)) or any(
        marker in lowered for marker in (
            "executable doesn't exist", "camoufox 未安装", "camoufox 导入失败",
            "camoufox 未安装或导入失败", "browser not found", "camoufox fetch",
        )
    )
    if missing:
        return ConfigError(
            f"Camoufox 浏览器或依赖缺失，请安装项目依赖并运行 `python -m camoufox fetch`：{message}"
        )
    if isinstance(exc, (TypeError, ValueError)) or type(exc).__name__ in {"InvalidProxy", "InvalidIP"}:
        if "failed to get ip address" not in lowered:
            return ConfigError(f"Camoufox 启动参数无效，请检查浏览器/代理配置：{message}")
    return TransientError(
        f"Camoufox 启动失败，请检查网络、代理或运行器资源后重试：{message}",
        data={"stage": "browser_launch", "error_type": type(exc).__name__},
    )


class BrowserService:
    """一个账号一次运行一个实例。首个 ``lease()`` 才真正启动浏览器。"""

    __slots__ = (
        "base_url", "proxy", "headless", "humanize", "log", "evidence",
        "_browser", "_context", "_started", "_auth_verified", "_last_reason",
        "_restored", "_persist",
    )

    def __init__(
        self,
        *,
        base_url: str,
        proxy: str = "",
        headless: bool | None = None,
        humanize: bool = True,
        log: Callable[[str], None] | None = None,
        evidence: Any = None,
        persist: Callable[[PersistedSession], None] | None = None,
    ) -> None:
        self.base_url = str(base_url or "")
        self.proxy = str(proxy or "")
        self.headless = headless
        self.humanize = bool(humanize)
        self.log = log
        self.evidence = evidence
        self._persist = persist
        self._browser: Any = None
        self._context: Any = None
        self._started = False
        self._auth_verified = False
        self._last_reason = ""
        self._restored: set[str] = set()

    # ── 状态 ────────────────────────────────────────────────────────────
    @property
    def started(self) -> bool:
        """浏览器是否真的被用到过。引擎据此决定要不要做收尾。"""
        return self._started

    @property
    def origin(self) -> str:
        parts = urlsplit(self.base_url)
        return f"{parts.scheme}://{parts.netloc}" if parts.netloc else self.base_url.rstrip("/")

    def mark_authenticated(self) -> None:
        """由脚本/登录插件调用：本次确实完成了登录（哪怕后续任务失败）。"""
        self._auth_verified = True

    def note_outcome(self, outcome: Any) -> None:
        """记录任务结论，供收尾判定使用。"""
        ok = bool(getattr(outcome, "ok", False))
        if ok:
            self._auth_verified = True
        self._last_reason = str(getattr(outcome, "reason", "") or "")

    def _emit(self, message: str) -> None:
        if self.log is not None:
            try:
                self.log(message)
            except Exception:
                pass

    # ── 租约 ────────────────────────────────────────────────────────────
    def lease(self, *, reason: str = "", state_text: str = "") -> "_LeaseContext":
        """``async with service.lease(...) as lease:``；首次进入才启动浏览器。"""
        return _LeaseContext(self, reason=reason, state_text=state_text)

    async def _ensure_started(self, *, reason: str) -> None:
        if self._started:
            return
        from . import bypass, runtime_loop

        headless = runtime_loop.env_headless() if self.headless is None else bool(self.headless)
        label = "headless" if headless else "headful"
        self._emit(f"启动浏览器（{label}{'，' + reason if reason else ''}）")
        last_error: Exception | None = None
        for attempt, timeout in enumerate(LAUNCH_TIMEOUTS_MS, start=1):
            try:
                self._browser, self._context = await bypass.launch_camoufox(
                    headless=headless,
                    humanize=self.humanize,
                    geoip=True,
                    proxy=self.proxy or None,
                    timeout=timeout,
                    log=self._emit,
                )
                break
            except TaskError:
                raise
            except Exception as exc:
                last_error = exc
                timed_out = "Timeout" in type(exc).__name__ or "Timeout" in str(exc)
                # 驱动断连（"Connection closed while reading from the driver"）和超时
                # 一样是可重试的环境问题：组间并发启动时，驱动补丁/profile 初始化可能
                # 让先启动的进程把驱动带崩。旧判据只认 Timeout，于是首个浏览器任务一崩
                # 就零重试直接判成「站点不可达」，实测 CI 里 AnyRouter/AgentRouter 每轮
                # 被这样误杀。
                crashed = runtime_loop.is_driver_closed_error(exc)
                if (not timed_out and not crashed) or attempt >= len(LAUNCH_TIMEOUTS_MS):
                    raise _launch_error(exc) from exc
                nxt = LAUNCH_TIMEOUTS_MS[attempt] // 1000
                if timed_out:
                    self._emit(f"浏览器启动超时（{timeout // 1000}s），放宽到 {nxt}s 重试")
                else:
                    self._emit(f"浏览器驱动启动时断开（{type(exc).__name__}），等待后放宽到 {nxt}s 重试")
                    await asyncio.sleep(LAUNCH_RETRY_BACKOFF_SECONDS)
        else:  # pragma: no cover - 循环必然 break 或 raise
            raise RuntimeError(str(last_error))
        self._started = True

    async def _restore(self, state_text: str) -> bool:
        """把登录态注入 context。同一份态只注入一次（跨租约不重复）。"""
        text = str(state_text or "").strip()
        if not text or self._context is None:
            return False
        marker = f"{len(text)}:{hash(text)}"
        if marker in self._restored:
            return False
        storage_state = decode_state(text)
        from . import state as _state

        await _state.restore_storage_state(self._context, storage_state)
        self._restored.add(marker)
        return True

    # ── 收尾 ────────────────────────────────────────────────────────────
    async def aclose(self) -> None:
        """导出并续存登录态，然后关闭浏览器。未启动则零成本。"""
        if not self._started:
            return
        try:
            await self._persist_session()
        finally:
            from . import runtime_loop

            context, browser = self._context, self._browser
            self._context = self._browser = None
            self._started = False
            try:
                if context is not None:
                    await context.close()
            except Exception:
                pass
            await runtime_loop.safe_close_browser(browser)

    async def _persist_session(self) -> None:
        """判定并写回登录态。任何失败都静默：缓存写不进去不该影响本次结论。"""
        if self._persist is None or self._context is None:
            return
        if not self._auth_verified and self._last_reason in UNAUTHENTICATED_REASONS:
            self._emit(f"结论为 {self._last_reason}（未完成登录），跳过续存以保留上次可用的登录态")
            return
        try:
            storage_state = await asyncio.wait_for(
                self._context.storage_state(), timeout=STATE_EXPORT_TIMEOUT
            )
        except asyncio.TimeoutError:
            self._emit(f"导出登录态超过 {STATE_EXPORT_TIMEOUT:.0f} 秒，跳过本次续存以避免阻塞退出")
            return
        except Exception:
            return
        try:
            encoded = encode_state(storage_state)
        except Exception:
            encoded = ""
        # 必须限定站点来源：跑完的 storage_state 常含多个 origin（站点自身 + 共享 OAuth
        # provider + 第三方 iframe），而 auth_token / refresh_token 这两个键名各站通用。
        # 不限定就会把别站的同名值当成本站 token 写进缓存，表现为「刚捕获成功却一直登录失效」。
        from . import storage_scope

        access = storage_scope.storage_access_token(storage_state, base_url=self.base_url)
        refresh = storage_scope.storage_refresh_token(storage_state, base_url=self.base_url)
        if not self._auth_verified and not access and not refresh:
            self._emit("未检测到有效 token，且本次未验证登录态，跳过续存登出态快照")
            return
        session = PersistedSession(
            state_text=encoded,
            access_token=access,
            refresh_token=refresh,
            auth_verified=self._auth_verified,
        )
        if session.is_empty():
            return
        try:
            self._persist(session)
        except Exception:
            return
        hints = [
            name
            for name, value in (("登录态", encoded), ("token", access), ("refresh_token", refresh))
            if value
        ]
        self._emit("已续存到运行期覆盖层：" + "、".join(hints))


class BrowserLease:
    """一段浏览器使用期。页面由租约管理，浏览器实例由 service 管理。"""

    __slots__ = ("service", "reason", "_pages", "_primary")

    def __init__(self, service: BrowserService, *, reason: str = "") -> None:
        self.service = service
        self.reason = reason
        self._pages: list[Any] = []
        self._primary: Any = None

    # -- 页面 --
    @property
    def context(self) -> Any:
        return self.service._context

    @property
    def page(self) -> Any:
        """主页面。没有时抛错而不是隐式新建：隐式新建会掩盖「忘了 new_page」。"""
        if self._primary is None:
            raise RuntimeError("尚未创建页面，请先 await lease.new_page()")
        return self._primary

    async def new_page(self, *, guard_origin: str | None = None) -> Any:
        from . import popups

        page = await self.context.new_page()
        self._pages.append(page)
        if self._primary is None:
            self._primary = page
        origin = self.service.origin if guard_origin is None else guard_origin
        if origin:
            await popups.setup_popup_guard(page, allowed_origin=origin)
        return page

    async def goto(self, path: str = "", *, page: Any = None, **kwargs: Any) -> Any:
        """跳转。相对路径按站点 base_url 解析。

        默认只等导航提交（commit）并吞掉超时：部分站点长期不触发 domcontentloaded，
        直接失败会把「页面其实已经可用」误报成错误（旧 helpers.goto 的既有行为）。
        """
        target = self.resolve(path)
        options: dict[str, Any] = {"wait_until": "commit", "timeout": 60000}
        options.update(kwargs)
        ignore_timeout = bool(options.pop("ignore_timeout", True))
        current = page or self.page
        try:
            return await current.goto(target, **options)
        except Exception as exc:
            if ignore_timeout and ("Timeout" in type(exc).__name__ or "Timeout" in str(exc)):
                return None
            raise

    def resolve(self, path: str = "") -> str:
        target = str(path or "").strip()
        if target.startswith(("http://", "https://")):
            return target
        base = self.service.base_url
        if not base:
            raise ValueError("站点 base_url 为空，无法解析相对路径")
        if not target:
            return base
        return urljoin(base.rstrip("/") + "/", target.lstrip("/"))

    async def dismiss_popups(self, *, page: Any = None) -> int:
        from . import popups

        return await popups.dismiss_popups(page or self.page)

    # -- 登录态 --
    async def restore_state(self, state_text: str) -> bool:
        return await self.service._restore(state_text)

    async def export_state(self) -> str:
        state = await self.context.storage_state()
        return encode_state(state)

    def mark_authenticated(self) -> None:
        self.service.mark_authenticated()

    # -- OAuth --
    async def oauth(self, provider: str, *, page: Any = None) -> dict[str, Any]:
        """在站点上完成一次 OAuth 回跳，返回 ``oauth_flow`` 的结果字典。"""
        from . import oauth_flow

        target = page or self.page
        return await oauth_flow.trigger_oauth(
            target,
            self.service.base_url.rstrip("/"),
            provider,
            self.service.log or (lambda _m: None),
        )

    # -- 证据 --
    async def screenshot(self, name: str, *, target: Any = None, page: Any = None) -> str:
        collector = self.service.evidence
        if collector is not None and hasattr(collector, "capture"):
            return await collector.capture(name, target=target, page=page or self._primary)
        return await _fallback_screenshot(name, target=target, page=page or self._primary)

    # -- 生命周期 --
    async def aclose(self) -> None:
        from . import runtime_loop

        pages, self._pages, self._primary = self._pages, [], None
        for page in pages:
            await runtime_loop.safe_close_page(page)


class _LeaseContext:
    """``service.lease()`` 的 async 上下文管理器。"""

    __slots__ = ("_service", "_reason", "_state_text", "_lease")

    def __init__(self, service: BrowserService, *, reason: str, state_text: str) -> None:
        self._service = service
        self._reason = reason
        self._state_text = state_text
        self._lease: BrowserLease | None = None

    async def __aenter__(self) -> BrowserLease:
        await self._service._ensure_started(reason=self._reason)
        if self._state_text:
            await self._service._restore(self._state_text)
        self._lease = BrowserLease(self._service, reason=self._reason)
        return self._lease

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool:
        # 只关自己开的页面，不关浏览器：下一个任务要接着用。
        if self._lease is not None:
            await self._lease.aclose()
        return False


async def _fallback_screenshot(name: str, *, target: Any = None, page: Any = None) -> str:
    """没有证据收集器时的兜底截图（仅用于单元测试与脱离引擎的调用）。"""
    from config import paths

    if page is None and target is None:
        return ""
    directory = Path(paths.EVIDENCE_DIR)
    directory.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.\-一-鿿]+", "_", str(name or "shot.png")).strip("._") or "shot.png"
    if "." not in Path(safe).name:
        safe += ".png"
    destination = directory / safe
    try:
        if target is not None:
            await target.screenshot(path=str(destination), type="png")
        else:
            await page.screenshot(path=str(destination), full_page=True)
    except Exception:
        return ""
    return str(destination)


def is_driver_crash(exc: BaseException) -> bool:
    """Playwright Firefox 驱动崩溃/关闭的既有判据（重试可修，不是账号问题）。"""
    from . import runtime_loop

    return bool(runtime_loop.is_driver_closed_error(exc))


def crash_outcome(exc: BaseException) -> TaskError:
    return TaskError(
        "浏览器驱动已关闭或页面脚本触发 Playwright Firefox 兼容问题，请重试。",
        reason="network_error",
        data={"driver_crashed": True, "error": str(exc)},
    )
