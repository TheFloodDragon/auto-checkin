"""需要浏览器的解算器：Turnstile / hCaptcha / Cloudflare 挑战 / 阿里云 WAF。

全部是既有实现的**适配层**——``browser.turnstile``、``browser.hcaptcha``、
``browser.bypass``、``browser.waf`` 里的算法与踩坑修复原样保留，这里只把它们的
四套不同签名统一成 ``Solver`` 契约，并把结果映射为 ``SolveResult``。

所有实现模块都在 ``solve()`` 内部 import：注册表被 import 时不该拉起 playwright。
"""

from __future__ import annotations

from typing import Any

from ..core.outcome import Evidence
from .registry import CAP_BROWSER, CAP_VISION, SolveResult

__all__ = ["AliyunWafSolver", "CloudflareSolver", "HCaptchaSolver", "TurnstileSolver", "register_all"]


def _page_of(ctx: Any, page: Any) -> Any:
    if page is not None:
        return page
    browser = getattr(ctx, "browser", None)
    return getattr(browser, "page", None) if browser is not None else None


class TurnstileSolver:
    """Cloudflare Turnstile：定位挂件、点一次、读回 token。"""

    async def solve(
        self,
        ctx: Any,
        /,
        *,
        page: Any = None,
        budget: float | None = None,
        **kwargs: Any,
    ) -> SolveResult:
        target = _page_of(ctx, page)
        if target is None:
            return SolveResult.failure("unavailable", "Turnstile 求解需要一个已打开的页面")
        from browser import turnstile

        timeout = int((budget or 45) * 1000)
        try:
            token = await turnstile.solve(target, timeout_ms=timeout, **kwargs)
        except TypeError:
            # 兼容既有签名差异：solve(page, ...) 的关键字在不同版本略有出入。
            token = await turnstile.solve(target)
        except Exception as exc:  # noqa: BLE001
            return SolveResult.failure("error", f"Turnstile 求解异常：{type(exc).__name__}: {exc}")
        if not token:
            return SolveResult.failure("timeout", "Turnstile 未在预算内产出 token")
        return SolveResult.solved(str(token))


class HCaptchaSolver:
    """hCaptcha：视觉模型作答。需要 browser + vision 两项能力。"""

    async def solve(
        self,
        ctx: Any,
        /,
        *,
        page: Any = None,
        trigger: Any = None,
        options: Any = None,
        budget: float | None = None,
        **_: Any,
    ) -> SolveResult:
        target = _page_of(ctx, page)
        if target is None:
            return SolveResult.failure("unavailable", "hCaptcha 求解需要一个已打开的页面")
        from browser import hcaptcha

        resolved = dict(options) if isinstance(options, dict) else ({} if options is None else options)
        if isinstance(resolved, dict):
            # API Key 只允许来自环境变量：即使站点配置误写了也必须忽略，
            # 否则凭据会进 ACCOUNTS/Secret 导出与脚本结果。
            if resolved.pop("api_key", None) is not None and hasattr(ctx, "log"):
                ctx.log("hCaptcha 配置中的 api_key 已忽略；模型密钥只允许通过环境变量提供")
            if budget:
                resolved.setdefault("total_timeout_ms", int(budget * 1000))
                resolved["total_timeout_ms"] = min(
                    int(resolved["total_timeout_ms"]), int(budget * 1000)
                )
                for key, share in (
                    ("widget_mount_timeout_ms", 0.5),
                    ("presence_timeout_ms", 0.3),
                    # 单轮可占满剩余总预算：宁可只跑一轮但让视觉请求跑完，也不要把它
                    # 中途切断而把真实错误（如 HTTP 424）掩盖成「单轮求解超时」。
                    ("round_timeout_ms", 1.0),
                ):
                    cap = int(resolved["total_timeout_ms"] * share)
                    if int(resolved.get(key) or 0) > cap:
                        resolved[key] = cap

        screenshot = getattr(getattr(ctx, "evidence", None), "capture", None)
        try:
            result = await hcaptcha.solve(
                target,
                trigger=trigger,
                options=resolved,
                log=getattr(ctx, "log", None),
                screenshot=screenshot,
            )
        except Exception as exc:  # noqa: BLE001
            return SolveResult.failure("error", f"hCaptcha 求解异常：{type(exc).__name__}: {exc}")

        token = str(getattr(result, "token", "") or "")
        evidence = Evidence()
        for shot in getattr(result, "screenshots", ()) or ():
            evidence = evidence.with_screenshot(shot)
        shot = getattr(result, "screenshot", "")
        if shot:
            evidence = evidence.with_screenshot(shot)
        # 诊断字段必须带出来：hCaptcha 失败有十几种成因（widget 没挂上、题型不支持、
        # 视觉端点 424、单轮超时…），只给一句「未完成」时无从下手。
        data = {
            key: value
            for key, value in (
                ("captcha", "hcaptcha"),
                ("captcha_status", str(getattr(result, "status", "") or "")),
                ("captcha_rounds", int(getattr(result, "rounds", 0) or 0)),
                ("captcha_type", str(getattr(result, "challenge_type", "") or "")),
                ("captcha_failure_stage", str(getattr(result, "failure_stage", "") or "")),
                ("captcha_error_type", str(getattr(result, "error_type", "") or "")),
                ("captcha_http_status", getattr(result, "http_status", None)),
            )
            if value not in (None, "", 0)
        }
        attempts = int(getattr(result, "rounds", 0) or 0)
        if token:
            return SolveResult.solved(token, attempts=attempts, evidence=evidence, data=data)
        return SolveResult.failure(
            str(getattr(result, "reason", "") or "uncertain"),
            str(getattr(result, "message", "") or "hCaptcha 未能在预算内完成"),
            attempts=attempts,
            evidence=evidence,
            data=data,
        )


class CloudflareSolver:
    """Cloudflare JS 挑战页：等待自动通过，必要时点一次交互挂件。"""

    async def solve(
        self, ctx: Any, /, *, page: Any = None, budget: float | None = None, **_: Any
    ) -> SolveResult:
        target = _page_of(ctx, page)
        if target is None:
            return SolveResult.failure("unavailable", "Cloudflare 挑战求解需要一个已打开的页面")
        from browser import bypass

        try:
            passed = await bypass.solve_cloudflare(
                target, log=getattr(ctx, "log", None), wait_seconds=int(budget or 10)
            )
        except Exception as exc:  # noqa: BLE001
            return SolveResult.failure("error", f"Cloudflare 挑战求解异常：{type(exc).__name__}: {exc}")
        if passed:
            return SolveResult.solved("passed")
        return SolveResult.failure("timeout", "Cloudflare 挑战未在预算内通过")


class AliyunWafSolver:
    """阿里云 WAF 的 JS 挑战与滑块。"""

    async def solve(
        self,
        ctx: Any,
        /,
        *,
        page: Any = None,
        base_url: str = "",
        rounds: int = 3,
        budget: float | None = None,
        **_: Any,
    ) -> SolveResult:
        target = _page_of(ctx, page)
        if target is None:
            return SolveResult.failure("unavailable", "阿里云 WAF 求解需要一个已打开的页面")
        from browser import waf

        url = base_url or str(getattr(getattr(ctx, "account", None), "base_url", "") or "")
        try:
            passed = await waf.solve_waf(target, url, log=getattr(ctx, "log", None), rounds=rounds)
        except Exception as exc:  # noqa: BLE001
            return SolveResult.failure("error", f"阿里云 WAF 求解异常：{type(exc).__name__}: {exc}")
        if passed:
            return SolveResult.solved("passed")
        # 熔断（连续整轮失败）意味着出口 IP 被持续风控，换代理才有意义。
        blocked = bool(getattr(waf, "waf_is_blocked", lambda _p: False)(target))
        return SolveResult.failure(
            "blocked" if blocked else "timeout",
            "阿里云 WAF 持续风控当前出口 IP，请更换代理节点"
            if blocked
            else "阿里云 WAF 挑战未在预算内通过",
        )


def register_all(registry: Any) -> None:
    registry.register(
        "turnstile",
        TurnstileSolver,
        requires={CAP_BROWSER},
        title="Turnstile",
        default_budget=45,
    )
    registry.register(
        "hcaptcha",
        HCaptchaSolver,
        requires={CAP_BROWSER, CAP_VISION},
        title="hCaptcha",
        description="视觉模型作答；模型密钥只从环境变量读取",
        default_budget=90,
    )
    registry.register(
        "waf:cloudflare",
        CloudflareSolver,
        requires={CAP_BROWSER},
        title="Cloudflare 挑战",
        default_budget=20,
    )
    registry.register(
        "waf:aliyun",
        AliyunWafSolver,
        requires={CAP_BROWSER},
        title="阿里云 WAF",
        default_budget=60,
    )
