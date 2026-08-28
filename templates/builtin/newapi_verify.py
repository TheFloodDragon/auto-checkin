"""New API 系站点的签到验证机制路由。

原样迁自 ``scripts/newapi_verification.py`` + ``newapi_captcha.py`` +
``newapi_turnstile.py``：机制判据、端点方言、重试次数与「不适用 vs 失败」的区分都是
实测出来的，不重新发明。变化只在形态——不再是三个用户要手工填路径的脚本，而是 newapi
模板自带的能力，由 ``flow.verification`` 控制。

四种已知机制：

| 机制 | 开关来源 | 取挑战 | 提交 |
|---|---|---|---|
| ``turnstile``       | ``/api/status`` 的 ``turnstile_check`` + ``turnstile_site_key`` | 浏览器铸造令牌 | ``?turnstile=`` |
| ``bitmap_code``     | 签到状态 ``captcha_enabled``       | ``POST /api/user/checkin/captcha`` | ``captcha_answer`` |
| ``string_captcha``  | ``/api/status`` ``checkin_captcha_enabled`` | ``GET /api/captcha?scene=checkin`` | ``captcha_code`` |
| ``click_shape``     | ``/api/status`` ``captcha_type=click-shape`` | ``GET /api/go-captcha-data/click-shape`` | ``?captcha_token=`` |

另有一种**不是验证码**的情况：``code_required`` —— 站点要求提交站外发布的「今日口令」，
程序拿不到，只能由用户配置。裸提交必被拒，所以直接给需配置的结论，不浪费一次写请求。
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from ...core.errors import ConfigError, TaskError, TransientError, VerificationRequired
from ...net import guard
from ...net.http import unwrap_data

__all__ = [
    "CHECKIN_PATH",
    "CaptchaDialect",
    "detect_modes",
    "run_mechanism",
    "submit_checkin",
]

CHECKIN_PATH = "/api/user/checkin"
STATUS_PATH = "/api/status"
GO_CAPTCHA_DATA_PATH = "/api/go-captcha-data/click-shape"
GO_CAPTCHA_CHECK_PATH = "/api/go-captcha-check-data/click-shape"

#: captcha_id 单次有效（实测复用直接回「验证码已失效」），所以每次重试都要重新取图。
MAX_ATTEMPTS = 4
GO_CAPTCHA_MAX_ATTEMPTS = 4

#: 「这次不算」的回执：换一张重试，而不是判定站点不支持。
RETRY_PATTERNS = ("验证码错误", "验证码已失效", "验证码不正确", "captcha", "刷新后重试", "已过期")
#: 取图端点不存在：换下一种方言。
ENDPOINT_MISSING_PATTERNS = (
    "invalid url", "404", "405", "not found", "page not found", "no route", "验证码场景无效",
)
#: 机制整体不适用（换下一个机制）。
NOT_APPLICABLE_PATTERNS = (*ENDPOINT_MISSING_PATTERNS, "站点未提供已知的签到验证码端点", "挑战接口异常")


@dataclass(frozen=True, slots=True)
class CaptchaDialect:
    """一种签到验证码方言。"""

    key: str
    endpoint: str                 # 取图端点（相对站点根）
    method: str                   # bitmap_code 用 POST，string_captcha 用 GET
    image_keys: tuple[str, ...]   # 响应里承载 dataURL 的字段名
    answer_key: str               # 提交签到时答案的字段名


DIALECTS: tuple[CaptchaDialect, ...] = (
    CaptchaDialect("bitmap_code", "/api/user/checkin/captcha", "POST",
                   ("captcha_image", "image"), "captcha_answer"),
    CaptchaDialect("string_captcha", "/api/captcha?scene=checkin", "GET",
                   ("image", "captcha_image"), "captcha_code"),
)
DIALECT_BY_MODE = {item.key: item for item in DIALECTS}


# ── 机制分流 ────────────────────────────────────────────────────────────────
def detect_modes(options: dict[str, Any], state: dict[str, Any]) -> list[str]:
    """按站点**公开配置**判断需要哪些验证机制。

    只读探测：先看开关再发请求，这是探测规则第一条。不同机制把开关放在不同位置，
    只看其中一处会漏判并探测错误端点。
    """
    modes: list[str] = []
    captcha_type = str(options.get("captcha_type") or "").strip().lower()
    if captcha_type == "click-shape":
        modes.append("click_shape")
    if options.get("turnstile_check") and options.get("turnstile_site_key"):
        modes.append("turnstile")
    enabled = bool(
        state.get("captcha_enabled")
        or options.get("checkin_captcha_enabled")
        or options.get("captcha_checkin_enabled")
    )
    if enabled and captcha_type != "click-shape":
        # 两种字符图没有统一类型字段；按机制端点无副作用探测。
        modes.extend(("bitmap_code", "string_captcha"))
    return modes


def not_applicable(exc: TaskError) -> bool:
    """这次失败是「本机制不适用」（可以换下一个）还是「机制适用但被拒」（该停）。

    混淆这两者会把「站点改了端点」和「账号被封」显示成同一句话。
    """
    text = f"{exc.message} {exc.payload}"
    return exc.status in {404, 405} or guard.contains_any(text, NOT_APPLICABLE_PATTERNS)


async def run_mechanism(ctx: Any, mode: str, options: dict[str, Any]) -> dict[str, Any] | None:
    """执行一种验证机制并完成签到；机制不适用时返回 None。"""
    if mode == "turnstile":
        return await _turnstile_checkin(ctx, options)
    if mode == "click_shape":
        return await _click_shape_checkin(ctx)
    if mode in DIALECT_BY_MODE:
        return await _captcha_checkin(ctx, mode)
    return None


# ── 提交 ────────────────────────────────────────────────────────────────────
def submit_checkin(ctx: Any, *, turnstile: str = "", code: str = "", body: dict[str, Any] | None = None) -> Any:
    """调用 legacy 签到接口。

    签到 POST 是幂等的（重复签到 → already_done），因此瞬时网络错误可安全重试。
    """
    path = CHECKIN_PATH
    if turnstile:
        path += f"?turnstile={quote(turnstile)}"
    payload = dict(body or {})
    if code:
        payload["code"] = code
    return unwrap_data(
        ctx.http.request("POST", path, json_body=payload or {}, retry_non_idempotent=True)
    )


# ── Turnstile ───────────────────────────────────────────────────────────────
async def _turnstile_checkin(ctx: Any, options: dict[str, Any]) -> dict[str, Any] | None:
    sitekey = str(options.get("turnstile_site_key") or "").strip()
    if not (options.get("turnstile_check") and sitekey):
        ctx.log(f"Turnstile 不适用（turnstile_check={options.get('turnstile_check')}，sitekey={sitekey!r}）")
        return None
    ctx.log(f"站点启用 Turnstile（sitekey={sitekey[:20]}…），开始铸造令牌")
    result = await ctx.solve("turnstile:inject", sitekey=sitekey)
    if not result.ok:
        # 令牌拿不到多半是出口 IP 被风控：这是可重试的外部条件，不是账号问题。
        raise TransientError(result.message or "Turnstile 令牌求解失败")
    ctx.log("令牌已获取，提交签到接口…")
    data = submit_checkin(ctx, turnstile=result.value)
    return _as_dict(data, extra={"verification_mode": "turnstile"})


# ── 字符/点阵验证码 ─────────────────────────────────────────────────────────
async def _captcha_checkin(ctx: Any, mode: str) -> dict[str, Any] | None:
    """取图 → 离线识别 → 带答案提交，失败则换一张重试。

    每次重试都必须重新取图：captcha_id 单次有效，复用会直接回「验证码已失效」。
    识别不确定时也主动换图——取图不限次、不消耗签到机会，硬猜却会作废一次验证码；
    只有已经用到最后一次机会时才带着不确定的读数提交（总比放弃好）。
    """
    dialect = DIALECT_BY_MODE[mode]
    tried: list[str] = []
    last: TaskError | None = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        captcha_id, image = _fetch_captcha(ctx, dialect)
        ctx.log(f"第 {attempt}/{MAX_ATTEMPTS} 次取图完成（captcha_id={captcha_id[:12] or '空'}…），开始离线识别")
        solver_id, size = _pick_solver(image)
        result = await ctx.solve(solver_id, image=image)
        text = result.value or str(result.data.get("text") or "")
        exact = result.ok
        ctx.log(f"验证码 {size} → {solver_id} 识别为 {text!r}（exact={exact}）")
        if not text:
            last = VerificationRequired(f"验证码识别失败（第 {attempt} 次，未提取到字符）")
            continue
        if not exact and attempt < MAX_ATTEMPTS:
            tried.append(f"{text}?")
            ctx.log(f"验证码读数 {text} 不够可信，换一张重试（第 {attempt}/{MAX_ATTEMPTS} 次）")
            continue
        tried.append(text)
        ctx.log(
            f"提交验证码读数 {text}（{dialect.key}，字段 {dialect.answer_key}，"
            f"{'可信' if exact else '不可信（最后一次机会，仍提交）'}）"
        )
        try:
            data = submit_checkin(ctx, body={"captcha_id": captcha_id, dialect.answer_key: text})
        except TaskError as exc:
            # 站点回执必须原样打出来：「验证码错误」和「今日已签到」都会走到这里，
            # 只看最终 message 分不清是识别错了还是根本不该重试。
            ctx.log(f"第 {attempt}/{MAX_ATTEMPTS} 次提交被拒：{exc.message}；原始回执：{_brief(exc.payload)}")
            if guard.contains_any(exc.message, RETRY_PATTERNS):
                last = exc
                continue
            raise
        return _as_dict(
            data,
            extra={
                "verification_mode": dialect.key,
                "captcha_dialect": dialect.key,
                "captcha_attempts": attempt,
                "captcha_answer_exact": exact,
            },
        )

    detail = "、".join(tried) or "无"
    raise VerificationRequired(
        f"图形验证码连续 {MAX_ATTEMPTS} 次未通过（识别结果：{detail}）"
        + (f"；末次回执：{last.message}" if last else ""),
        payload=last.payload if last else None,
        data={"captcha_attempts": MAX_ATTEMPTS, "captcha_failed": True},
    )


def _fetch_captcha(ctx: Any, dialect: CaptchaDialect) -> tuple[str, str]:
    data = unwrap_data(ctx.http.request(dialect.method, dialect.endpoint, retry_non_idempotent=True))
    if not isinstance(data, dict):
        raise VerificationRequired("验证码接口返回结构无法识别", payload=data)
    captcha_id = str(data.get("captcha_id") or data.get("id") or "")
    image = ""
    for key in dialect.image_keys:
        image = str(data.get(key) or "")
        if image:
            break
    if not captcha_id or not image:
        raise VerificationRequired(
            f"验证码接口未返回 captcha_id / {dialect.image_keys[0]}", payload=data
        )
    return captcha_id, image


def _pick_solver(data_url: str) -> tuple[str, str]:
    """按图像尺寸挑识别器。

    用尺寸而不是端点：端点只说明「哪个 fork」，尺寸才说明「哪套生成器」。某个 fork
    换了生成器时，靠尺寸能自动走对，不必改接线。尺寸必须落日志——站点换生成器时症状
    只是「一直识别不对」，没有尺寸信息根本判断不出该重建哪套模板库。
    """
    import base64
    import io

    try:
        import numpy as np
        from PIL import Image

        from captcha_ocr import base64_captcha, newapi_bitmap
    except Exception as exc:  # noqa: BLE001
        raise ConfigError(
            "签到需要图形验证码，但识别器不可用（缺 numpy/pillow 或 captcha_ocr 被裁剪）。"
            "请执行 uv sync --extra dev 后重试，或在浏览器手动签到。"
        ) from exc

    payload = data_url.split(",", 1)[1] if "," in data_url else data_url
    with Image.open(io.BytesIO(base64.b64decode(payload))) as image:
        array = np.asarray(image.convert("RGB"))
    height, width = array.shape[0], array.shape[1]
    if (width, height) == (newapi_bitmap.WIDTH, newapi_bitmap.HEIGHT):
        return "image:newapi_bitmap", f"{width}×{height}"
    if (width, height) == (base64_captcha.WIDTH, base64_captcha.HEIGHT):
        return "image:string_captcha", f"{width}×{height}"
    raise VerificationRequired(
        f"验证码尺寸 {width}×{height} 没有对应的识别器"
        f"（已知 {newapi_bitmap.WIDTH}×{newapi_bitmap.HEIGHT} 与 "
        f"{base64_captcha.WIDTH}×{base64_captcha.HEIGHT}）"
    )


# ── GoCaptcha 点选 ──────────────────────────────────────────────────────────
async def _click_shape_checkin(ctx: Any) -> dict[str, Any] | None:
    last_message = ""
    for attempt in range(1, GO_CAPTCHA_MAX_ATTEMPTS + 1):
        challenge = ctx.http.get(GO_CAPTCHA_DATA_PATH)
        if not isinstance(challenge, dict) or challenge.get("code") != 0:
            raise VerificationRequired(f"click-shape 挑战接口异常：{_brief(challenge)}", payload=challenge)
        captcha_key = str(challenge.get("captcha_key") or "")
        image = str(challenge.get("image_base64") or "")
        thumb = str(challenge.get("thumb_base64") or "")
        if not captcha_key or not image or not thumb:
            raise VerificationRequired("click-shape 挑战缺少 captcha_key / 图片", payload=challenge)

        result = await ctx.solve("image:click_shape", image=image, thumb=thumb)
        if not result.ok:
            ctx.log(f"第 {attempt}/{GO_CAPTCHA_MAX_ATTEMPTS} 张形状挑战识别失败：{result.message}")
            last_message = result.message
            continue
        points = result.data.get("points") or []
        point_text = ";".join(f"{x},{y}" for x, y in points)
        ctx.log(f"第 {attempt}/{GO_CAPTCHA_MAX_ATTEMPTS} 张形状挑战提交点位：{point_text}")

        verified = _go_captcha_verify(ctx, {"key": captcha_key, "points": point_text})
        if not isinstance(verified, dict) or verified.get("code") != 0:
            last_message = str(verified.get("message") if isinstance(verified, dict) else verified)
            ctx.log(f"形状验证未通过：{_brief(verified)}，换一张重试")
            continue
        token = str(verified.get("token") or "")
        if not token:
            raise VerificationRequired("click-shape 验证通过但未返回 token", payload=verified)

        try:
            data = unwrap_data(
                ctx.http.request(
                    "POST", f"{CHECKIN_PATH}?captcha_token={quote(token)}", retry_non_idempotent=True
                )
            )
        except TaskError as exc:
            ctx.log(f"captcha_token 签到被拒：{exc.message}；原始回执：{_brief(exc.payload)}")
            if guard.contains_any(exc.message, (*RETRY_PATTERNS, "人机验证", "验证失败")):
                last_message = exc.message
                continue
            raise
        return _as_dict(
            data,
            extra={
                "verification_mode": "click_shape",
                "captcha_dialect": "click_shape",
                "captcha_attempts": attempt,
            },
        )

    raise VerificationRequired(
        f"click-shape 连续 {GO_CAPTCHA_MAX_ATTEMPTS} 次未通过"
        + (f"；末次原因：{last_message}" if last_message else "")
    )


def _go_captcha_verify(ctx: Any, fields: dict[str, str]) -> Any:
    """提交 GoCaptcha 的 multipart 验证。"""
    boundary = f"----newapi-checkin-{uuid.uuid4().hex}"
    chunks = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n".encode()
        for key, value in fields.items()
    ]
    chunks.append(f"--{boundary}--\r\n".encode())
    return ctx.http.request(
        "POST",
        GO_CAPTCHA_CHECK_PATH,
        data=b"".join(chunks),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        retry_non_idempotent=True,
    )


# ── 小工具 ──────────────────────────────────────────────────────────────────
def _as_dict(data: Any, *, extra: dict[str, Any]) -> dict[str, Any]:
    out = dict(data) if isinstance(data, dict) else {"raw": data}
    out.update(extra)
    return out


def _brief(value: Any, limit: int = 300) -> str:
    if isinstance(value, (dict, list)):
        try:
            text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            text = str(value)
    else:
        text = str(value)
    text = " ".join(text.split())
    return text if len(text) <= limit else f"{text[:limit]}…（共 {len(text)} 字符）"
