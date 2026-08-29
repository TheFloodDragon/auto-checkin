from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from captcha_ocr.go_captcha_shape import _decode_image, _detect_target_count, solve_challenge

from templates.builtin import newapi_verify as verify

FIXTURES = Path(__file__).parent / "fixtures" / "go_captcha_shape"


def _b64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode()


def test_click_shape_real_samples() -> None:
    """两张真实 GoCaptcha 挑战必须稳定还原按序点位。"""
    expected = {
        1: [(32, 198), (122, 127), (223, 32)],
        2: [(85, 30), (158, 31), (200, 30)],
    }
    for index, points in expected.items():
        main = _b64(FIXTURES / f"sample{index}_main.jpg")
        thumb = _b64(FIXTURES / f"sample{index}_thumb.png")
        assert _detect_target_count(_decode_image(thumb)) == 3
        assert solve_challenge(main, thumb) == points


def test_detect_modes_accepts_reversed_flag_name() -> None:
    """向量引擎用 captcha_checkin_enabled，不能只认 checkin_captcha_enabled。

    两种命名方向在不同 fork 里都出现过；只认一种会漏判，然后去探测错误的端点。
    """
    options = {"captcha_checkin_enabled": True, "captcha_type": "click-shape"}
    assert verify.detect_modes(options, {}) == ["click_shape"]

    options = {"checkin_captcha_enabled": True}
    assert verify.detect_modes(options, {}) == ["bitmap_code", "string_captcha"]


def test_detect_modes_reads_state_level_switch() -> None:
    """点阵验证码的开关在**签到状态**里，不在 /api/status。"""
    assert verify.detect_modes({}, {"captcha_enabled": True}) == ["bitmap_code", "string_captcha"]


def test_turnstile_takes_precedence_over_captcha() -> None:
    """同时开了 Turnstile 与验证码时，Turnstile 先试：它是服务端强校验。"""
    options = {
        "turnstile_check": True,
        "turnstile_site_key": "0x4A",
        "checkin_captcha_enabled": True,
    }
    modes = verify.detect_modes(options, {})
    assert modes[0] == "turnstile"
    assert "bitmap_code" in modes


def test_click_shape_token_is_submitted_to_checkin() -> None:
    """形状验证通过后必须把 token 带进签到请求，否则等于没验证。"""
    import asyncio

    calls: list[tuple[str, str]] = []

    class _Http:
        headers: dict[str, str] = {}

        def get(self, path: str, **_: Any) -> Any:
            calls.append(("GET", path))
            return {
                "code": 0,
                "captcha_key": "k1",
                "image_base64": _b64(FIXTURES / "sample1_main.jpg"),
                "thumb_base64": _b64(FIXTURES / "sample1_thumb.png"),
            }

        def request(self, method: str, path: str, **_: Any) -> Any:
            calls.append((method, path))
            if verify.GO_CAPTCHA_CHECK_PATH in path:
                return {"code": 0, "token": "tok-42"}
            return {"success": True, "data": {"quota_awarded": 1000}}

    class _Ctx:
        http = _Http()
        args: dict[str, Any] = {}

        def log(self, message: str, **_: Any) -> None:
            pass

        async def solve(self, solver_id: str, /, **kwargs: Any) -> Any:
            from solvers import SOLVERS

            return await SOLVERS.solve(self, solver_id, **kwargs)

        capabilities = frozenset()
        deadline = None

    data = asyncio.run(verify.run_mechanism(_Ctx(), "click_shape", {}))

    assert data is not None
    assert data["verification_mode"] == "click_shape"
    submitted = [path for method, path in calls if method == "POST" and "captcha_token" in path]
    assert submitted and "tok-42" in submitted[0]
