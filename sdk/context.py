"""脚本与模板可见的执行上下文。

这是重构后**唯一**的脚本接口面。旧实现要求脚本同时理解两套对象——纯 HTTP 钩子收
``ProfileClient``、浏览器钩子收 ``(page, context, site, helpers)``，两套 site 视图、
两套日志、两套结果构造器。现在合并成一个 ``Context``：

    async def run(ctx):
        state = ctx.http.get("/api/user/checkin")          # 已注入认证，401 自动续期一次
        async with ctx.browser.lease() as lease:           # 惰性：不碰就不启动浏览器
            page = await lease.new_page()
            r = await ctx.solve("hcaptcha", page=page)
        ctx.store.put("quiz_bank", bank)                   # 缓存进覆盖层，不再自己写文件
        return ok("完成", text="$1.20", text_label="额度")

三条边界：
- **无凭据**：``ctx.account`` 是脱敏视图，要用凭据只能通过 ``ctx.http`` / ``ctx.login``；
- **无副作用配置**：脚本改不了 ACCOUNTS.json，运行期产物一律经覆盖层；
- **无隐式浏览器**：``ctx.browser`` 不被访问就一次都不启动。
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

from core.account import ResolvedAccount, TaskSpec
from core.flow import FlowPlan
from core.outcome import Evidence
from net.http import HttpClient
from runtime.budget import Budget, Deadline
from solvers import SOLVERS, SolveResult
from .store import Store

__all__ = ["AccountView", "Context", "EvidenceCollector", "LoginHandle", "TaskContext"]


@dataclass(frozen=True, slots=True)
class AccountView:
    """暴露给脚本的**只读且脱敏**账号视图。

    刻意不含任何凭据字段：脚本要用凭据就通过 ``ctx.http``（已注入认证头）或
    ``ctx.login``，而不是自己拿着 token 拼请求。凭据一旦进入脚本，就会随脚本的日志、
    异常与返回值四处扩散，脱敏层再怎么补都堵不完。
    """

    id: str
    name: str
    base_url: str
    origin: str
    template: str
    task_id: str
    proxy: str = ""
    #: 账号配置里的 OAuth 归属（非凭据，只是「用哪个 provider 的哪个账号」）。
    #: relogin 这类需要重放 OAuth 的任务方式据此回落，避免硬编码某个 provider。
    oauth_provider: str = ""
    oauth_account: str = ""

    @classmethod
    def of(cls, account: ResolvedAccount, task: TaskSpec) -> "AccountView":
        return cls(
            id=account.id,
            name=account.name,
            base_url=account.base_url,
            origin=account.origin,
            template=account.spec.task_template(task),
            task_id=task.id,
            proxy=account.network.proxy,
            oauth_provider=str(account.login.provider or ""),
            oauth_account=str(account.login.account or ""),
        )


class LoginHandle(Protocol):
    """脚本可用的登录能力（由引擎注入）。"""

    @property
    def method(self) -> str: ...

    def describe(self) -> str: ...

    async def renew(self) -> bool: ...


class EvidenceCollector:
    """证据收集器：截图、原始响应、阶段轨迹。

    任何一层都能往里追加，最终整体挂到 ``Outcome.evidence``。旧实现里这三类信息分别
    散在 ``detail["screenshot"]``、``ApiError.payload`` 和 stderr 日志里，失败后能拿到
    什么全看当时哪条分支恰好记了。
    """

    __slots__ = ("_evidence", "_dir", "_log")

    def __init__(self, directory: Any = None, log: Any = None) -> None:
        self._evidence = Evidence()
        self._dir = directory
        self._log = log

    @property
    def value(self) -> Evidence:
        return self._evidence

    def stage(self, text: str) -> None:
        self._evidence = self._evidence.with_stage(text)

    def response(self, snippet: Any) -> None:
        self._evidence = self._evidence.with_response(snippet)

    def screenshot(self, path: Any) -> None:
        self._evidence = self._evidence.with_screenshot(path)

    async def capture(self, name: str, *, target: Any = None, page: Any = None) -> str:
        """截图并登记。失败返回空串——诊断截图失败不该让任务失败。"""
        if (page is None and target is None) or self._dir is None:
            return ""
        directory = Path(self._dir)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            return ""
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
        self.screenshot(str(destination))
        return str(destination)


@runtime_checkable
class Context(Protocol):
    """脚本可依赖的稳定接口面。破坏性变更需要递增 ``dailytask.SDK_VERSION``。"""

    account: AccountView
    args: Mapping[str, Any]
    flow: FlowPlan
    capabilities: frozenset[str]
    http: HttpClient
    store: Store
    evidence: EvidenceCollector

    def log(self, message: str, /, **fields: Any) -> None: ...
    def remaining_seconds(self) -> float | None: ...
    def budget(self, name: str, seconds: float | None = None) -> Budget: ...
    async def solve(self, solver_id: str, /, **kwargs: Any) -> SolveResult: ...

    @property
    def browser(self) -> Any: ...

    @property
    def login(self) -> LoginHandle: ...


@dataclass
class TaskContext:
    """``Context`` 的标准实现。由 ``runtime.engine`` 构造。"""

    account: AccountView
    args: Mapping[str, Any]
    flow: FlowPlan
    http: HttpClient
    store: Store
    capabilities: frozenset[str] = frozenset()
    evidence: EvidenceCollector = field(default_factory=EvidenceCollector)
    clock: Deadline = field(default_factory=Deadline)
    #: BrowserService（惰性，本身不会在构造时启动浏览器）。None = 本次不可用。
    browser_service: Any = None
    login_handle: LoginHandle | None = None
    stage: str = ""
    #: 结构化日志函数：``(stage, message, **fields) -> None``。
    emit: Any = None

    # -- 日志 --
    def log(self, message: str, /, **fields: Any) -> None:
        """一行进度日志。

        worker 模式下 stdout 是机器协议通道，所有诊断一律走 stderr——这条规则在旧实现里
        被踩过多次（脚本 print 到 stdout 会污染结果 JSON）。
        """
        text = str(message or "").strip()
        if not text:
            return
        if self.emit is not None:
            self.emit(self.stage or "run", text, **fields)
            return
        from core.masking import mask_secrets

        marker = f"{self.stage}:{self.account.name}" if self.stage else self.account.name
        print(f"[{marker}] {mask_secrets(text)}", file=sys.stderr, flush=True)

    # -- 预算 --
    def remaining_seconds(self) -> float | None:
        return self.clock.remaining()

    def budget(self, name: str, seconds: float | None = None) -> Budget:
        return self.clock.slice(name, seconds)

    def expired(self) -> bool:
        return self.clock.expired()

    @property
    def deadline(self) -> float | None:
        """monotonic 截止点。解算器注册表用它统一收敛预算。"""
        return self.clock.at

    # -- 解算 --
    async def solve(self, solver_id: str, /, **kwargs: Any) -> SolveResult:
        result = await SOLVERS.solve(self, solver_id, **kwargs)
        self.evidence.stage(f"solve:{solver_id}={'ok' if result.ok else result.reason}")
        for shot in result.evidence.screenshots:
            self.evidence.screenshot(shot)
        if not result.ok and result.message:
            self.log(f"解算 {solver_id} 未成功：{result.message}")
        return result

    # -- 浏览器（惰性）--
    @property
    def browser(self) -> Any:
        if self.browser_service is None:
            raise RuntimeError(
                "本次运行没有可用浏览器（账号策略 allow_browser=false，或未安装 Camoufox）。"
                "请在任务清单里用 requires={'browser'} 声明依赖，引擎会提前给出明确结论，"
                "而不是等到这里才失败。"
            )
        return self.browser_service

    @property
    def browser_started(self) -> bool:
        """浏览器是否真的被用到过。引擎据此决定要不要做收尾。"""
        return self.browser_service is not None and bool(self.browser_service.started)

    # -- 登录 --
    @property
    def login(self) -> LoginHandle:
        if self.login_handle is None:
            raise RuntimeError("本次运行未建立登录态（flow.login=off 或匿名任务）")
        return self.login_handle

    def child(self, *, stage: str = "", args: Mapping[str, Any] | None = None) -> "TaskContext":
        """派生一个换了阶段名/参数的上下文，共享同一浏览器、证据与时钟。"""
        return TaskContext(
            account=self.account,
            args=args if args is not None else self.args,
            flow=self.flow,
            http=self.http,
            store=self.store,
            capabilities=self.capabilities,
            evidence=self.evidence,
            clock=self.clock,
            browser_service=self.browser_service,
            login_handle=self.login_handle,
            stage=stage or self.stage,
            emit=self.emit,
        )
