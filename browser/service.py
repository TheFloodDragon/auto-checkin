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
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType, TracebackType
from typing import Any, Callable, Iterable, Mapping
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

#: 导航遇到传输层连接重置/拒绝（NS_ERROR_NET_RESET 等）时的重试次数与退避基数。这类
#: 错误多是出口 IP/代理节点到站点的链路瞬时抖动，重来一次常能连上；有限重试比一遇
#: reset 就让整轮登录/签到失败稳。RST 通常瞬时失败，重试的额外耗时很小。
GOTO_TRANSPORT_RETRIES = 2
GOTO_RETRY_BACKOFF_SECONDS = 0.6

#: 浏览器快照里会被续存成独立凭据字段的 token。
_TOKEN_FIELDS = ("access_token", "refresh_token")

@dataclass(frozen=True, slots=True)
class PersistedSession:
    """收尾时要写回覆盖层的东西。"""

    state_text: str = field(default="", repr=False)
    access_token: str = field(default="", repr=False)
    refresh_token: str = field(default="", repr=False)
    auth_verified: bool = False
    expected_revisions: Mapping[str, str] | None = field(default=None, repr=False)
    auth_scope: str = field(default="", repr=False)
    identity: Mapping[str, Any] | None = field(default=None, repr=False)

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
        "_browser", "_context", "_started", "_last_reason", "_generation", "_verified_generation",
        "_restored", "_persist", "_revision_reader", "_credential_revisions", "_published_credentials",
        "_restoration_guard", "_stale_credentials", "_shared_writer", "_shared_lineage",
        "_verified_auth_scope", "_verified_identity",
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
        persist: Callable[[PersistedSession], bool | None] | None = None,
        revision_reader: Callable[[], Mapping[str, str]] | None = None,
        restoration_guard: Callable[[str], Mapping[str, Iterable[str]]] | None = None,
        shared_writer: Callable[[str, str, dict[str, Any], frozenset[str]], bool | None] | None = None,
    ) -> None:
        self.base_url = str(base_url or "")
        self.proxy = str(proxy or "")
        self.headless = headless
        # 只影响 CF 验证点击的有限拟人移动；普通点击始终直接落点（见 bypass.launch_camoufox）。
        self.humanize = bool(humanize)
        self.log = log
        self.evidence = evidence
        self._persist = persist
        self._revision_reader = revision_reader
        self._restoration_guard = restoration_guard
        #: 共享 OAuth 态的写回钩子与谱系：(provider, account) → 已知属于本上下文会话的认证值。
        #: 只有恢复自共享态（或刚写回共享态）的会话才有谱系；任何其他恢复都会清空它。
        self._shared_writer = shared_writer
        self._shared_lineage: dict[tuple[str, str], set[str]] = {}
        self._credential_revisions: dict[str, str] | None = None
        #: 浏览器侧已交接（服务端确认）的 AT/RT；导出必须与之一致。
        self._published_credentials: dict[str, str] = {}
        #: 已被更新的 token 取值：本运行写入前的旧值，以及恢复快照里比磁盘更旧的值。
        self._stale_credentials: dict[str, set[str]] = {}
        self._browser: Any = None
        self._context: Any = None
        self._started = False
        self._generation = 0
        self._verified_generation: int | None = None
        self._last_reason = ""
        self._restored: set[str] = set()
        # 版本基线绑定创建本服务时的账号来源；惰性启动不能认领期间写入的新版本。
        self._begin_generation(capture_revisions=True)

    # ── 状态 ────────────────────────────────────────────────────────────
    @property
    def started(self) -> bool:
        """浏览器是否真的被用到过。引擎据此决定要不要做收尾。"""
        return self._started

    @property
    def origin(self) -> str:
        parts = urlsplit(self.base_url)
        return f"{parts.scheme}://{parts.netloc}" if parts.netloc else self.base_url.rstrip("/")

    def mark_authenticated(self, *, auth_scope: str = "", identity: Mapping[str, Any] | None = None) -> None:
        """认证证明及安全身份元数据绑定当前代次，不沿用创建服务时的旧账号身份。"""
        if self._started and self._context is not None:
            same_generation = self._verified_generation == self._generation
            self._verified_generation = self._generation
            self._last_reason = ""
            scope = str(auth_scope or "").strip()
            if scope or not same_generation:
                self._verified_auth_scope = scope
            if identity is not None:
                value = identity.get("user_id") if isinstance(identity, Mapping) else None
                self._verified_identity = MappingProxyType({"user_id": str(value).strip()} if (
                    isinstance(value, (str, int)) and not isinstance(value, bool) and str(value).strip()
                ) else {})
            elif not same_generation:
                self._verified_identity = None

    def note_outcome(self, outcome: Any) -> None:
        """只有明确的登录失效会撤销证明；普通任务成功不会产生认证证明。"""
        self._last_reason = str(getattr(outcome, "reason", "") or "")
        if self._last_reason == "need_login":
            self._begin_generation()
            self._shared_lineage.clear()

    def track_shared(self, provider: str, account: str, values: Iterable[str]) -> None:
        """登记：本上下文当前的提供商会话就是共享态 (provider, account) 的这些认证值。

        Discourse 等站点会在正常访问中滚动轮换认证 Cookie，旧值只有约一分钟宽限。
        同一会话的多份副本（共享态、站点快照）若不同步，没被更新的那份很快就失效；
        登记谱系后，收尾时可把本会话最新的认证值安全写回共享态。
        """
        clean = {str(value) for value in values if str(value or "")}
        if self._started and self._context is not None and clean:
            key = (str(provider or "").strip().lower(), str(account or "").strip() or "default")
            self._shared_lineage.setdefault(key, set()).update(clean)

    @property
    def credential_revisions(self) -> Mapping[str, str] | None:
        """当前上下文的写回基线；缺少基线时引擎必须拒绝浏览器写回。"""
        return dict(self._credential_revisions) if self._credential_revisions is not None else None

    def note_credentials_written(
        self,
        credentials: Mapping[str, str],
        revisions: Mapping[str, str],
        *,
        previous: Mapping[str, str],
        published: bool = False,
        group: Mapping[str, str] | None = None,
    ) -> None:
        """本运行发布了新凭据：旧值作废，基线只按本次写入的原子回执推进。

        整组版本只在写前版本仍等于基线时推进；期间有别处写入就保留旧基线，
        让收尾续存按 CAS 失败而不是覆盖对方。
        """
        for name in _TOKEN_FIELDS:
            if name not in credentials:
                continue
            old = str(previous.get(name) or "")
            if old and old != credentials[name]:
                self._stale_credentials.setdefault(name, set()).add(old)
            self._stale_credentials.get(name, set()).discard(credentials[name])
        if self._credential_revisions is not None:
            for name, revision in revisions.items():
                if name != "__group__" and name in self._credential_revisions:
                    self._credential_revisions[name] = revision
            baseline = self._credential_revisions.get("__group__")
            before, after = (group or {}).get("before"), (group or {}).get("after")
            if baseline is not None and before and after and before == baseline:
                self._credential_revisions["__group__"] = after
        if published and self._started:
            self._published_credentials.update({
                name: credentials[name] for name in _TOKEN_FIELDS if name in credentials
            })

    def is_stale(self, credentials: Mapping[str, str]) -> bool:
        """凭据里是否含已被更新/清除的 token，或与已交接的新凭据冲突。"""
        return self.superseded(credentials, include_published=True)

    def superseded(self, credentials: Mapping[str, str], *, include_published: bool = False) -> bool:
        """只判断已作废的旧值；新交接本身可以替换上一次交接。"""
        return any(
            self._stale_value(name, credentials[name], include_published=include_published)
            for name in _TOKEN_FIELDS if name in credentials
        )

    def _stale_value(self, name: str, value: Any, *, include_published: bool = True) -> bool:
        text = str(value or "")
        if include_published and name in self._published_credentials and text != self._published_credentials[name]:
            return True
        return bool(text) and text in self._stale_credentials.get(name, ())

    def filter_credentials(self, credentials: Mapping[str, str]) -> dict[str, str]:
        """旧快照仍可用于尝试登录，但不能重新发布已被更新/清除的 token。"""
        return {
            name: value for name, value in credentials.items()
            if name not in _TOKEN_FIELDS or not self._stale_value(name, value)
        }

    def _begin_generation(self, *, capture_revisions: bool = False) -> None:
        self._generation += 1
        self._verified_generation = None
        self._verified_auth_scope = ""
        self._verified_identity: Mapping[str, Any] | None = None
        self._last_reason = ""
        if capture_revisions:
            self._credential_revisions = None
            if self._revision_reader is not None:
                try:
                    self._credential_revisions = dict(self._revision_reader())
                except Exception:
                    self._emit("无法读取凭据版本，跳过本次浏览器续存")

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
        self._begin_generation(capture_revisions=self._credential_revisions is None)
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

        # 导入另一份态即进入新代次。保留该 context 原有的版本基线，不能把期间
        # HTTP/其他进程保存的新 token 误当成这份待恢复快照的来源。
        self._begin_generation()
        # 提供商 Cookie 可能被换成别的身份：谱系作废，由调用方在确认来源后重新登记。
        self._shared_lineage.clear()
        if self._restoration_guard is not None:
            # 快照里比磁盘当前值更旧的 token 记为作废：可以拿来尝试，但不能再发布。
            try:
                for name, values in self._restoration_guard(text).items():
                    if name in _TOKEN_FIELDS:
                        self._stale_credentials.setdefault(name, set()).update(str(v) for v in values if v)
            except Exception:
                self._credential_revisions = None
                self._emit("无法确认快照来源，保留已有凭据且跳过续存")
        await _state.restore_storage_state(self._context, storage_state, log=self._emit)
        self._restored.add(marker)
        return True

    async def aclose(self, *, persist: bool = True) -> None:
        """关闭本上下文；被新 OAuth 会话替代的旧上下文不得再次续存。"""
        if not self._started and self._context is None and self._browser is None:
            return
        try:
            if persist:
                await self._persist_session()
        finally:
            from . import runtime_loop

            context, browser = self._context, self._browser
            self._context = self._browser = None
            self._started = False
            self._restored.clear()
            self._begin_generation()
            self._credential_revisions = None
            self._published_credentials.clear()
            self._stale_credentials.clear()
            self._shared_lineage.clear()
            try:
                if context is not None:
                    await asyncio.wait_for(context.close(), timeout=runtime_loop.BROWSER_CLOSE_TIMEOUT_SECONDS)
            except Exception:
                pass
            finally:
                await runtime_loop.safe_close_browser(browser)

    async def _persist_session(self) -> None:
        """只续存当前代次已确认的浏览器态；写入失败不影响本次任务结论。"""
        if (self._persist is None and self._shared_writer is None) or self._context is None:
            return
        generation = self._generation
        if self._verified_generation != generation:
            self._emit("当前浏览器会话未经确认或已失效，保留上次可用的登录态")
            return
        expected = self.credential_revisions
        auth_scope, identity = self._verified_auth_scope, self._verified_identity
        try:
            storage_state = await asyncio.wait_for(
                self._context.storage_state(), timeout=STATE_EXPORT_TIMEOUT
            )
        except asyncio.TimeoutError:
            self._emit(f"导出登录态超过 {STATE_EXPORT_TIMEOUT:.0f} 秒，跳过本次续存以避免阻塞退出")
            return
        except Exception:
            return
        # 导出期间也可能有另一租约恢复新态，或业务请求明确返回登录失效。
        if (self._generation != generation or self._verified_generation != generation
                or self._verified_auth_scope != auth_scope or self._verified_identity != identity):
            return
        from . import storage_scope
        candidate = storage_scope.storage_login_candidate(storage_state, base_url=self.base_url)
        captured_id = candidate["identity"].get("user_id", "")
        verified_id = str((identity or {}).get("user_id") or "")
        if candidate["conflict"] or (captured_id and verified_id and captured_id != verified_id):
            self._emit("浏览器导出身份与已确认代次冲突，跳过续存")
            return
        try:
            encoded = encode_state(storage_state)
        except Exception:
            encoded = ""
        self._persist_shared(storage_state)
        if self._persist is None:
            return
        # 只从本站来源取凭据，不能续存第三方 iframe / OAuth provider 的同名 token。
        access = candidate["access_token"]
        refresh = storage_scope.storage_refresh_token(storage_state, base_url=self.base_url)
        # 快照整体内嵌 token：只要有一个是已作废的旧值，就整份不写，避免旧 RT 复活。
        if self.is_stale({"access_token": access, "refresh_token": refresh}):
            self._emit("浏览器快照含已更新/清除的旧凭据，跳过续存以保留新凭据")
            return
        session = PersistedSession(
            state_text=encoded,
            access_token=access,
            refresh_token=refresh,
            auth_verified=True,
            expected_revisions=expected,
            auth_scope=auth_scope,
            identity=identity,
        )
        if session.is_empty():
            return
        try:
            written = self._persist(session)
        except Exception:
            return
        if written is False:
            self._emit("登录态未续存（缓存只读、版本已更新或写入失败），保留现有凭据")
            return
        hints = [
            name
            for name, value in (("登录态", encoded), ("token", access), ("refresh_token", refresh))
            if value
        ]
        self._emit("已续存到运行期覆盖层：" + "、".join(hints))


    def _persist_shared(self, storage_state: dict[str, Any]) -> None:
        """已确认的会话若源自共享态，把同一会话轮换出的新认证值写回共享态。"""
        if self._shared_writer is None or not self._shared_lineage:
            return
        for (provider, account), values in list(self._shared_lineage.items()):
            try:
                written = self._shared_writer(provider, account, storage_state, frozenset(values))
            except Exception:
                written = False
            if written:
                self._emit(f"共享登录态 {provider}:{account} 已同步本会话最新的认证 Cookie")


class BrowserLease:
    """一段浏览器使用期。页面由租约管理，浏览器实例由 service 管理。"""

    __slots__ = ("service", "reason", "_pages", "_primary", "_oauth_handoff")

    def __init__(self, service: BrowserService, *, reason: str = "") -> None:
        self.service = service
        self.reason = reason
        self._pages: list[Any] = []
        self._primary: Any = None
        self._oauth_handoff: Any = None

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

        传输层连接被重置/拒绝（NS_ERROR_NET_RESET 等）多是出口 IP/代理节点到站点的链路
        瞬时抖动，驱动还活着、重来一次常能连上：先退避重试有限次，全部失败才翻译成可
        重试的 TransientError，避免一次抖动就让整轮登录/签到失败。
        """
        from . import runtime_loop

        target = self.resolve(path)
        options: dict[str, Any] = {"wait_until": "commit", "timeout": 60000}
        options.update(kwargs)
        ignore_timeout = bool(options.pop("ignore_timeout", True))
        current = page or self.page
        for attempt in range(GOTO_TRANSPORT_RETRIES + 1):
            try:
                return await current.goto(target, **options)
            except Exception as exc:
                if ignore_timeout and ("Timeout" in type(exc).__name__ or "Timeout" in str(exc)):
                    return None
                # 传输层连接失败（Gecko 的 NS_ERROR_NET_RESET 等）不是驱动崩溃，也不是站点脚本
                # 兼容问题：驱动还活着，只是这一跳没连通。先退避重试；仍连不上才翻译成可重试
                # TransientError，附带可操作提示——而不是把带 Playwright "Call log" 的原始异常
                # 抛给引擎，显示成一句无从下手的「script 执行异常：NS_ERROR_NET_RESET」。
                transport = (
                    runtime_loop.is_network_transport_error(exc)
                    and not runtime_loop.is_driver_closed_error(exc)
                )
                if transport and attempt < GOTO_TRANSPORT_RETRIES:
                    await asyncio.sleep(GOTO_RETRY_BACKOFF_SECONDS * (attempt + 1))
                    continue
                if transport:
                    safe_url = target.split("?", 1)[0]
                    code = runtime_loop.brief_navigation_error(exc)
                    raise TransientError(
                        f"浏览器导航到 {safe_url} 时连接被重置/拒绝（{code}）：已自动重试仍未连通，"
                        "多为出口 IP 或代理节点到站点的链路问题，请更换代理节点或稍后重试。",
                        data={"stage": "browser_goto", "error_code": code, "attempts": attempt + 1},
                    ) from exc
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

    def mark_authenticated(self, *, auth_scope: str = "", identity: Mapping[str, Any] | None = None) -> None:
        self.service.mark_authenticated(auth_scope=auth_scope, identity=identity)

    def track_shared(self, provider: str, account: str, values: Iterable[str]) -> None:
        self.service.track_shared(provider, account, values)

    async def oauth(
        self, provider: str, *, page: Any = None, require_fresh: bool = False, deadline: float | None = None
    ) -> dict[str, Any]:
        """在站点上完成一次 OAuth 回跳，可要求本次新授权证据并传递总截止点。"""
        from . import oauth_flow

        target = page or self.page
        # 新授权可能换用户；此前浏览器确认不可用于发布本轮候选。
        self.service._begin_generation()
        if self._oauth_handoff is not None:
            self._oauth_handoff.close()
        self._oauth_handoff = oauth_flow.OAuthCallbackHandoff()
        return await oauth_flow.trigger_oauth(
            target,
            self.service.base_url.rstrip("/"),
            provider,
            self.service.log or (lambda _m: None),
            require_fresh=require_fresh,
            deadline=deadline,
            callback_handoff=self._oauth_handoff,
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

        if self._oauth_handoff is not None:
            self._oauth_handoff.close()
            self._oauth_handoff = None
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


def is_network_transport_crash(exc: BaseException) -> bool:
    """导航/请求在传输层被出口 IP 或代理重置、拒绝、读一半断开（可重试）。

    与 ``is_driver_crash`` 互斥优先：驱动断开的错误串里也可能夹带网络词，但那要走
    「驱动崩溃」文案；这里只认「驱动还活着、纯粹是这一跳没连通」的情形。多数传输层
    失败已由 ``BrowserLease.goto`` 就地翻译成 TransientError，此判据是引擎兜底——
    防止别处直接 ``page.goto`` / ``page.click`` 抛出的 ``NS_ERROR_*`` 冒泡成一句
    无从下手的「执行异常」。
    """
    from . import runtime_loop

    return bool(
        runtime_loop.is_network_transport_error(exc)
        and not runtime_loop.is_driver_closed_error(exc)
    )


def network_transport_outcome(exc: BaseException) -> TaskError:
    """把冒泡到引擎的传输层错误翻译成可重试结论，并剥掉 Playwright 的 call log。"""
    from . import runtime_loop

    code = runtime_loop.brief_navigation_error(exc)
    return TransientError(
        f"浏览器与站点的网络连接被重置/拒绝（{code}）："
        "多为出口 IP 或代理节点到站点的链路问题，请更换代理节点或稍后重试。",
        data={"stage": "browser_transport", "error_code": code},
    )
