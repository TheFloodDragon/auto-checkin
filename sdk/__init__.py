"""脚本与模板的唯一导入面。

    from dailytask.sdk import (
        TemplateManifest, TaskOption, LoginOption, ArgSchema, ArgSpec,
        Context, ok, done, fail, no_effect, REASONS, Verdict,
    )

写一个任务脚本只需要三步：

1. 定义 ``MANIFEST = TemplateManifest(id=..., task=(TaskOption("script"),))``；
2. 实现 ``async def run(ctx) -> Outcome``；
3. 需要自定义展示时再实现 ``def render(outcome) -> DisplaySpec``。

其余钩子（``detect`` / ``login`` / ``fetch_state`` / ``confirm`` / ``extras``）
都是可选的，缺失时由引擎的通用实现兜底。
"""

from __future__ import annotations

from core.errors import (
    ConfigError,
    LoginRequired,
    NotApplicable,
    TaskError,
    TemplateError,
    TransientError,
    VerificationRequired,
)
from core.manifest import (
    ArgSchema,
    ArgSpec,
    DetectSpec,
    DisplayDefaults,
    LoginOption,
    ResponseMap,
    TaskOption,
    TemplateManifest,
)
from core.outcome import (
    REASONS,
    DisplaySpec,
    Evidence,
    Outcome,
    Verdict,
    already_done,
    blocked,
    failed,
    need_config,
    need_login,
    need_verification,
    network_error,
    no_effect,
    not_applicable,
    success,
)
from runtime.budget import Budget
from solvers import SolveResult
from .context import AccountView, Context, EvidenceCollector, LoginHandle, TaskContext
from .page import PageHelpers, parse_amount
from .store import SharedStore, Store

#: 脚本 / 模板声明依赖的 SDK 主版本。
#:
#: 破坏性变更时递增，加载器据此拒绝不兼容的模板（见 templates/registry.py）。
#: 定义在这里而不是别处：sdk 就是「对外契约」本身，版本号是契约的一部分。
SDK_VERSION = 1

#: 结果构造器的短别名。脚本里 ``return ok("完成")`` 比
#: ``return success("完成")`` 更贴合日常写法，两者完全等价。
ok = success
done = already_done
fail = failed

__all__ = [
    "REASONS",
    "SDK_VERSION",
    "AccountView",
    "ArgSchema",
    "ArgSpec",
    "Budget",
    "ConfigError",
    "Context",
    "DetectSpec",
    "DisplayDefaults",
    "DisplaySpec",
    "Evidence",
    "EvidenceCollector",
    "LoginHandle",
    "LoginOption",
    "LoginRequired",
    "NotApplicable",
    "Outcome",
    "PageHelpers",
    "ResponseMap",
    "SharedStore",
    "SolveResult",
    "Store",
    "TaskContext",
    "TaskError",
    "TaskOption",
    "TemplateError",
    "TemplateManifest",
    "TransientError",
    "Verdict",
    "VerificationRequired",
    "already_done",
    "blocked",
    "done",
    "fail",
    "failed",
    "need_config",
    "need_login",
    "need_verification",
    "network_error",
    "no_effect",
    "not_applicable",
    "ok",
    "parse_amount",
    "success",
]
