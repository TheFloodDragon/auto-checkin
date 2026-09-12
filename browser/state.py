#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""browser_oauth 登录态的编码 / 解码(跨平台 storage_state,用于 GitHub Secret)。

【为什么是 storage_state 而不是打包 profile 文件】
Chromium 的 Cookies 是用平台绑定的密钥加密的:Windows 上主密钥经 DPAPI
(CryptProtectData,per-user + per-machine)保护。若把整个 profile 二进制
打包搬到 Linux CI,那边的 Chromium 解不开 DPAPI 密钥 → 所有 cookie 失效 →
OAuth 必然失败。

Playwright 的 storage_state() 会在【捕获机器上】把 cookie 解密成明文 JSON
(cookies + localStorage origins),明文跨用户 / 跨机器 / 跨系统通用。

【编码格式与自动压缩】
本模块支持两种压缩格式,使用时自动识别:
  - gzip 格式(默认): base64(gzip(json))  兼容性好,标准库支持
  - zstd 格式(超限): "zstd:" + base64(zstd(json))  超过 GitHub Secret 限制时自动启用

encode_state() 会优先使用 gzip(level=9),若编码后超过 65535 字符(GitHub Secret 上限),
自动切换 zstd(level=22 极限压缩),通常可额外节省 15~30%。zstd 需安装: pip install zstandard

decode_state() 自动识别格式(通过 "zstd:" 前缀),无需手动指定。

登录态含明文第三方 cookie,与 ACCOUNTS.json 中其它凭据同级,靠 .gitignore /
GitHub Secret 加密存储保护。

数据格式(解码后):Playwright storage_state dict,形如
    {"cookies": [...], "origins": [{"origin": ..., "localStorage": [...]}]}
"""

from __future__ import annotations

import argparse
import base64
import gzip
import io
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

GITHUB_SECRET_LIMIT = 64 * 1024  # GitHub 单个 Secret 上限约 64KB

# 压缩前（JSON 原始字节）上限：4 MB，足以容纳大量 cookie/localStorage
_MAX_RAW_BYTES = 4 * 1024 * 1024
# base64 后必须能放进 GitHub Secret；压缩包上限按 4:3 膨胀反推。
_MAX_ENCODED_BYTES = GITHUB_SECRET_LIMIT
_MAX_PACKED_BYTES = (GITHUB_SECRET_LIMIT // 4) * 3

# encode_state 只生成标准 base64；解码时拒绝 URL-safe/混合字母表。
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+=*$")

# 流式解压时多读 1 字节用于检测是否超过 _MAX_RAW_BYTES（gzip bomb 防护哨兵）。
_GZIP_BOMB_SENTINEL = 1


class BrowserStateError(Exception):
    """browser_state 编码/解码相关错误（供 provider 捕获）。"""


async def restore_storage_state(
    context: Any,
    storage_state: dict[str, Any] | None,
    log: Any = None,
) -> None:
    """把 cookies/localStorage 恢复到浏览器上下文，并严格隔离不同 origin。

    cookie 先整批写入；整批被拒时逐条重试，只丢掉真正不合规的那一条。
    ``add_cookies`` 是全有全无的：一条 ``__Host-`` 前缀或字段组合不合规的 cookie
    就会让 14 条里的会话 cookie 全部没进去，表现为「登录态明明没过期却停在登录页」，
    而且没有任何日志能指向那一条。
    """
    data = storage_state or {}
    cookies = data.get("cookies") or []
    if cookies:
        try:
            await context.add_cookies(cookies)
        except Exception as exc:
            rejected: list[str] = []
            accepted = 0
            for cookie in cookies:
                try:
                    await context.add_cookies([cookie])
                    accepted += 1
                except Exception:
                    rejected.append(str(cookie.get("name") or "?"))
            if log:
                log(
                    f"登录态 Cookie 整批写入被拒（{type(exc).__name__}），已逐条写入 "
                    f"{accepted}/{len(cookies)} 条；被拒：{', '.join(rejected) or '无'}"
                )
            if not accepted:
                raise

    origin_map: dict[str, dict[str, str]] = {}
    for origin_data in data.get("origins", []) or []:
        if not isinstance(origin_data, dict):
            continue
        origin = str(origin_data.get("origin") or "").strip()
        if not origin:
            continue
        pairs = origin_map.setdefault(origin, {})
        for item in origin_data.get("localStorage", []) or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            if not name:
                continue
            value = item.get("value")
            pairs[name] = "" if value is None else str(value)

    origin_map = {origin: pairs for origin, pairs in origin_map.items() if pairs}
    if not origin_map:
        return

    init_js = """
    (() => {
      const states = %s;
      const pairs = states[location.origin] || {};
      for (const [key, value] of Object.entries(pairs)) {
        try { localStorage.setItem(key, value); } catch (_) {}
      }
    })();
    """ % json.dumps(origin_map, ensure_ascii=False, separators=(",", ":"))
    await context.add_init_script(init_js)


def _validate_storage_state(data: Any) -> None:
    """校验 storage_state 顶层结构及 cookies/origins/localStorage 基本类型。

    只做类型/存在性检查，不校验具体字段语义，以保持对不同版本 Playwright 的兼容。
    抛 BrowserStateError 说明不合规原因。
    """
    if not isinstance(data, dict):
        raise BrowserStateError("storage_state 必须是 JSON 对象（dict）。")
    if "cookies" not in data:
        raise BrowserStateError("storage_state 缺少必要字段 'cookies'。")

    cookies = data["cookies"]
    if not isinstance(cookies, list):
        raise BrowserStateError("storage_state.cookies 必须是数组。")
    for i, c in enumerate(cookies):
        if not isinstance(c, dict):
            raise BrowserStateError(f"storage_state.cookies[{i}] 必须是对象。")
        for required in ("name", "value", "domain", "path"):
            if required not in c:
                raise BrowserStateError(
                    f"storage_state.cookies[{i}] 缺少必要字段 '{required}'。"
                )
        if any(not isinstance(c.get(key), str) for key in ("name", "value", "domain", "path")):
            raise BrowserStateError(
                f"storage_state.cookies[{i}] 的 name/value/domain/path 必须是字符串。"
            )
        for bool_key in ("httpOnly", "secure"):
            if bool_key in c and not isinstance(c[bool_key], bool):
                raise BrowserStateError(f"storage_state.cookies[{i}].{bool_key} 必须是布尔值。")
        if "expires" in c and (isinstance(c["expires"], bool) or not isinstance(c["expires"], (int, float))):
            raise BrowserStateError(f"storage_state.cookies[{i}].expires 必须是数字。")

    origins = data.get("origins")
    if origins is None:
        return  # origins 是可选的
    if not isinstance(origins, list):
        raise BrowserStateError("storage_state.origins 必须是数组。")
    for i, origin_entry in enumerate(origins):
        if not isinstance(origin_entry, dict):
            raise BrowserStateError(f"storage_state.origins[{i}] 必须是对象。")
        if not isinstance(origin_entry.get("origin"), str):
            raise BrowserStateError(f"storage_state.origins[{i}].origin 必须是字符串。")
        ls = origin_entry.get("localStorage")
        if ls is None:
            continue
        if not isinstance(ls, list):
            raise BrowserStateError(
                f"storage_state.origins[{i}].localStorage 必须是数组。"
            )
        for j, item in enumerate(ls):
            if not isinstance(item, dict):
                raise BrowserStateError(
                    f"storage_state.origins[{i}].localStorage[{j}] 必须是对象。"
                )
            if not isinstance(item.get("name"), str) or not isinstance(
                item.get("value"), str
            ):
                raise BrowserStateError(
                    f"storage_state.origins[{i}].localStorage[{j}] "
                    "的 name/value 必须是字符串。"
                )


def encode_state(storage_state: dict[str, Any]) -> str:
    """把 Playwright storage_state dict 编码为可粘贴的 base64 文本。

    编码前校验输入结构。数据量超限时自动使用 zstd 压缩(level=22)。
    
    格式:
    - gzip 格式(兼容旧版): base64(gzip(json))
    - zstd 格式(超限时自动启用): "zstd:" + base64(zstd(json))
    
    Returns:
        编码后的文本,decode_state 会自动识别格式
    """
    _validate_storage_state(storage_state)
    raw = json.dumps(storage_state, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    
    if len(raw) > _MAX_RAW_BYTES:
        raise BrowserStateError(
            f"storage_state 序列化后过大({len(raw):,} 字节 > 上限 {_MAX_RAW_BYTES:,})，"
            "请清理不必要的 cookie/localStorage 后重新捕获。"
        )
    
    # 先尝试 gzip(level=9)
    packed = gzip.compress(raw, compresslevel=9)
    encoded = base64.b64encode(packed).decode("ascii")
    
    # 未超限，使用 gzip 格式(兼容旧版)
    if len(encoded) <= GITHUB_SECRET_LIMIT:
        return encoded
    
    # 超限，尝试 zstd 高压缩
    if not HAS_ZSTD:
        raise BrowserStateError(
            f"gzip 压缩后({len(encoded):,} 字符)超过 GitHub Secret 限制({GITHUB_SECRET_LIMIT:,})，"
            "需要 zstd 高压缩，请运行：pip install zstandard"
        )
    
    # zstd level=22 是最高压缩等级(极慢但体积最小)
    cctx = zstd.ZstdCompressor(level=22)
    zstd_packed = cctx.compress(raw)
    zstd_encoded = "zstd:" + base64.b64encode(zstd_packed).decode("ascii")
    
    if len(zstd_encoded) > GITHUB_SECRET_LIMIT:
        raise BrowserStateError(
            f"zstd 高压缩后仍过大({len(zstd_encoded):,} 字符 > 上限 {GITHUB_SECRET_LIMIT:,})，"
            f"gzip 为 {len(encoded):,} 字符，减少了 {len(encoded) - len(zstd_encoded):,} 字符，"
            "仍需手动清理 cookie/localStorage。"
        )
    
    reduction = len(encoded) - len(zstd_encoded)
    pct = (reduction / len(encoded) * 100) if encoded else 0
    print(
        f"[browser_state] gzip 超限({len(encoded)} 字符)，已自动切换 zstd 压缩 → {len(zstd_encoded)} 字符"
        f"(减少 {reduction} 字符, {pct:.1f}%)",
        file=sys.stderr,
    )
    
    return zstd_encoded


def decode_state(text: str) -> dict[str, Any]:
    """把 base64 文本解码回 storage_state dict。失败抛 BrowserStateError。

    自动识别格式：
    - gzip 格式(旧版兼容): base64(gzip(json))
    - zstd 格式(超限自动启用): "zstd:" + base64(zstd(json))
    
    对旧版(tar.xz 打包 profile)格式给出明确升级提示。
    严格校验：base64 合法性、压缩包大小、JSON schema。
    """
    text = (text or "").strip()
    if not text:
        raise BrowserStateError("登录态文本为空")
    
    # 检测 zstd 格式前缀
    is_zstd = text.startswith("zstd:")
    if is_zstd:
        if not HAS_ZSTD:
            raise BrowserStateError(
                "此登录态使用 zstd 压缩，需要安装依赖：pip install zstandard"
            )
        text = text[5:]  # 去掉 "zstd:" 前缀
    
    # 剔除粘贴时可能混入的空白/换行
    text = "".join(text.split())

    # 非 ASCII 说明数据已损坏
    try:
        ascii_bytes = text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise BrowserStateError(f"登录态包含非 ASCII 字符(已损坏)：{exc}") from exc

    # base64 解码
    try:
        packed = base64.b64decode(ascii_bytes, validate=True)
    except Exception as exc:
        # 检测旧版格式
        if text.startswith("/Td6WFoAAA"):
            raise BrowserStateError(
                "检测到旧版 tar.xz 打包 profile 格式(已废弃)，请重新捕获登录态：\n"
                "在账号详情页选择【浏览器登录态】→【捕获登录态】，使用 storage_state 新格式。"
            ) from exc
        raise BrowserStateError(f"base64 解码失败(登录态格式错误)：{exc}") from exc

    if len(packed) > _MAX_PACKED_BYTES:
        raise BrowserStateError(
            f"压缩包过大({len(packed):,} 字节 > 上限 {_MAX_PACKED_BYTES:,})，"
            "可能是错误的数据或非法构造。"
        )

    # 解压缩
    try:
        if is_zstd:
            dctx = zstd.ZstdDecompressor()
            raw = dctx.decompress(packed, max_output_size=_MAX_RAW_BYTES)
        else:
            raw = gzip.decompress(packed)
    except Exception as exc:
        comp_type = "zstd" if is_zstd else "gzip"
        raise BrowserStateError(f"{comp_type} 解压失败(登录态已损坏)：{exc}") from exc

    if len(raw) > _MAX_RAW_BYTES:
        raise BrowserStateError(
            f"解压后数据过大({len(raw):,} 字节 > 上限 {_MAX_RAW_BYTES:,})，"
            "请清理不必要的 cookie/localStorage 后重新捕获。"
        )

    # JSON 解析
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise BrowserStateError(f"JSON 解析失败(登录态已损坏)：{exc}") from exc

    # 严格校验 storage_state schema
    _validate_storage_state(data)
    return data


def state_summary(storage_state: dict[str, Any]) -> str:
    """生成登录态摘要（cookie 数 / 域名 / localStorage 条目），便于诊断。"""
    cookies = storage_state.get("cookies") or []
    origins = storage_state.get("origins") or []
    domains = sorted({str(c.get("domain", "")).lstrip(".") for c in cookies if c.get("domain")})
    ls_count = sum(len(o.get("localStorage") or []) for o in origins)
    return f"cookies={len(cookies)} 域名={','.join(domains) or '无'} localStorage条目={ls_count}"


# ── CLI(调试用:从本地 profile 导出 / 查看 storage_state)─────────────────────
def cmd_inspect(args) -> int:
    """读取一段 base64 登录态文本并打印摘要(校验格式是否有效)。"""
    if args.in_file:
        text = Path(args.in_file).read_text(encoding="ascii").strip()
    else:
        text = sys.stdin.read().strip()
    try:
        state = decode_state(text)
    except BrowserStateError as exc:
        print(f"无效:{exc}", file=sys.stderr)
        return 2
    print(state_summary(state))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="browser_oauth 登录态工具(storage_state;捕获请用 GUI 或 browser/poc_oauth.py)"
    )
    sub = parser.add_subparsers(dest="mode", required=True)
    
    pi = sub.add_parser("inspect", help="校验并打印一段 base64 登录态摘要")
    pi.add_argument("--in", dest="in_file", default="", help="从文件读取(默认读 stdin)")
    
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.mode == "inspect":
        return cmd_inspect(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
