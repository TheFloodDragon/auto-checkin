"""图形验证码解算器：包装 ``captcha_ocr`` 的三种识别器。

统一约定：**识别不确定时返回 ``ok=False`` 而不是猜一个**。验证码 id 大多单次有效，
换一张重试的成本远低于提交一次错误答案（错误提交还可能触发站点风控计数）。
"""

from __future__ import annotations

from typing import Any

from .registry import SolveResult

__all__ = ["Base64CaptchaSolver", "ClickShapeSolver", "NewApiBitmapSolver", "register_all"]


class _ImageSolver:
    """图像解算器基类：不需要浏览器，也不使用预算。"""

    scheme = ""

    async def solve(self, ctx: Any, /, *, image: Any = None, budget: float | None = None, **_: Any) -> SolveResult:
        if image is None:
            return SolveResult.failure("invalid", f"{self.scheme} 需要 image 参数（data URL / base64 / PNG 字节 / 数组）")
        try:
            return self._run(image)
        except Exception as exc:  # noqa: BLE001 - 识别器异常只该降级，不该中断任务
            return SolveResult.failure("error", f"{self.scheme} 识别失败：{type(exc).__name__}: {exc}")

    def _run(self, image: Any) -> SolveResult:  # pragma: no cover - 抽象
        raise NotImplementedError


class NewApiBitmapSolver(_ImageSolver):
    """New API fork 的点阵验证码。"""

    scheme = "image:newapi_bitmap"

    def _run(self, image: Any) -> SolveResult:
        from captcha_ocr import newapi_bitmap

        if isinstance(image, str):
            result = newapi_bitmap.solve_data_url(image)
        elif isinstance(image, (bytes, bytearray)):
            result = newapi_bitmap.solve_bytes(bytes(image))
        else:
            result = newapi_bitmap.solve_array(image)
        if not getattr(result, "exact", False):
            return SolveResult.failure(
                "uncertain",
                f"点阵验证码识别不确定（{getattr(result, 'text', '') or '空'}），建议换一张重试",
                data={"text": getattr(result, "text", "")},
            )
        return SolveResult.solved(result.text)


class Base64CaptchaSolver(_ImageSolver):
    """base64Captcha 系的字符验证码。"""

    scheme = "image:string_captcha"

    def _run(self, image: Any) -> SolveResult:
        from captcha_ocr import base64_captcha

        if isinstance(image, str):
            result = base64_captcha.solve_data_url(image)
        elif isinstance(image, (bytes, bytearray)):
            result = base64_captcha.solve_bytes(bytes(image))
        else:
            result = base64_captcha.solve_array(image)
        if not result.exact:
            return SolveResult.failure(
                "uncertain",
                f"字符验证码识别不确定（{result.text or '空'}），建议换一张重试",
                data={"text": result.text},
            )
        return SolveResult.solved(result.text)


class ClickShapeSolver(_ImageSolver):
    """go-captcha 的点选图形验证码。返回点击坐标序列的 JSON。"""

    scheme = "image:click_shape"

    async def solve(
        self,
        ctx: Any,
        /,
        *,
        image: Any = None,
        thumb: Any = None,
        budget: float | None = None,
        **_: Any,
    ) -> SolveResult:
        if not image or not thumb:
            return SolveResult.failure("invalid", "点选验证码需要 image（主图 base64）与 thumb（缩略图 base64）")
        log = getattr(ctx, "log", None)
        try:
            from captcha_ocr import go_captcha_shape

            points = go_captcha_shape.solve_challenge(str(image), str(thumb), log=log)
        except RuntimeError as exc:
            # 环境不完整（缺 opencv / 形状模板）属于配置问题，不是识别失败。
            return SolveResult.failure("unavailable", str(exc))
        except Exception as exc:  # noqa: BLE001 - 置信度不足会以 ValueError 抛出
            return SolveResult.failure("uncertain", f"点选验证码识别失败：{exc}")
        if not points:
            return SolveResult.failure("uncertain", "未能在主图中定位目标图形")
        import json

        return SolveResult.solved(
            json.dumps([[int(x), int(y)] for x, y in points], separators=(",", ":")),
            data={"points": [[int(x), int(y)] for x, y in points]},
        )


def register_all(registry: Any) -> None:
    registry.register(
        NewApiBitmapSolver.scheme,
        NewApiBitmapSolver,
        title="点阵验证码",
        description="New API fork 的 bitmap 验证码识别（模板匹配，无需网络）",
    )
    registry.register(
        Base64CaptchaSolver.scheme,
        Base64CaptchaSolver,
        title="字符验证码",
        description="base64Captcha 系字符验证码识别",
    )
    registry.register(
        ClickShapeSolver.scheme,
        ClickShapeSolver,
        title="点选图形验证码",
        description="go-captcha 点选验证码定位，返回点击坐标序列",
    )
