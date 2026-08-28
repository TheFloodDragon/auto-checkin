"""任务异常家族：异常即结论。

旧实现里 ``ApiError`` 用一堆布尔旗标（``transient`` / ``not_open`` / ``need_config``
/ ``waf_kind``）描述「这次失败算哪一类」，然后每个调用点再写一遍
``if kind == "already_done": ... elif kind == "not_open": ...`` 的翻译分支
（``providers/actions/api.py`` 里出现了三次，各自略有出入）。

这里换成：异常自带 ``verdict`` + ``reason``，任何一层都可以直接调用
``exc.to_outcome()``，不需要再认识具体异常类型。分类逻辑只写一次。
"""

from __future__ import annotations

from typing import Any, Mapping

from .outcome import Evidence, Outcome, Verdict

__all__ = [
    "ConfigError",
    "LoginRequired",
    "NotApplicable",
    "TaskError",
    "TemplateError",
    "TransientError",
    "VerificationRequired",
]


class TaskError(Exception):
    """所有可归类为任务结论的失败。

    ``status`` / ``payload`` 只在 HTTP 场景有值，保留是因为它们是排查时最有用的
    第一手信息；不参与判定，判定只看 ``verdict`` + ``reason``。
    """

    verdict: Verdict = Verdict.FAILED
    reason: str = ""

    def __init__(
        self,
        message: str,
        *,
        reason: str | None = None,
        verdict: Verdict | None = None,
        status: int | None = None,
        payload: Any = None,
        data: Mapping[str, Any] | None = None,
        evidence: Evidence | None = None,
    ) -> None:
        super().__init__(message)
        self.message = str(message)
        self.status = status
        self.payload = payload
        self.data: dict[str, Any] = dict(data or {})
        self.evidence = evidence
        if reason is not None:
            self.reason = reason
        if verdict is not None:
            self.verdict = verdict

    def to_outcome(self) -> Outcome:
        """把异常翻译为结论。所有 action/引擎层共用这一条路径。"""
        outcome = Outcome(
            verdict=self.verdict,
            reason=self.reason,
            message=self.message,
            data=dict(self.data),
        )
        if self.status is not None:
            outcome = outcome.with_data(http_status=self.status)
        if self.evidence is not None:
            outcome = outcome.with_evidence(self.evidence)
        return outcome

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return f"{type(self).__name__}({self.message!r}, reason={self.reason!r}, status={self.status})"


class TransientError(TaskError):
    """瞬时错误：网络失败、超时、429、5xx。可安全重试。"""

    reason = "network_error"


class LoginRequired(TaskError):
    """凭据无效或过期。"""

    reason = "need_login"


class VerificationRequired(TaskError):
    """需要人机验证且本次未能自动通过。"""

    reason = "need_verification"


class ConfigError(TaskError):
    """缺少只能由用户提供的配置项。

    同时用作配置文件解析失败的异常（取代 ``accounts_store.ConfigError``）：
    两者对用户的含义相同——「需要你去改配置」。
    """

    reason = "need_config"


class NotApplicable(TaskError):
    """站点未开放 / 任务不适用：不计失败，也不触发重试与浏览器兜底。"""

    verdict = Verdict.NO_EFFECT
    reason = "not_open"


class TemplateError(ConfigError):
    """模板或脚本加载失败（路径非法、清单缺失、SDK 版本不兼容）。

    继承 ConfigError：对用户而言这就是「配置写错了」，需要去改，而不是重试。
    """
