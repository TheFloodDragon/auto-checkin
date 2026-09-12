"""GitHub Secret 导出：生成 CI 用的最小化配置。

三条规则（从旧 ``accounts_store.build_github_secret_payload`` 继承，都有实测理由）：

1. **只导出启用账号**：禁用账号的凭据没必要进 Secret。
2. **凭据与登录方式无关**：只要有 access_token / refresh_token 就导出。旧实现曾按
   ``auth_method == "access_token"`` 过滤，于是「OAuth 登录 + 有 token」的账号导出的
   Secret 里没有 token，CI 里纯 API 那一级直接被跳过，只能拉浏览器——而 CI 里
   Turnstile 基本过不去。
3. **只带用得上的共享登录态**：顶层 ``oauth_states`` 只保留被启用账号实际引用的那几个，
   一份 Secret 有 64 KiB 上限，登录态动辄几十 KB。
"""

from __future__ import annotations

import json
from typing import Any

from .schema import CONFIG_VERSION, DEFAULT_OAUTH_ACCOUNT, Document, dump_account

__all__ = ["SECRET_SIZE_LIMIT", "build_secret_payload", "check_size", "dumps"]

#: GitHub 单个 Secret 的容量上限。
SECRET_SIZE_LIMIT = 64 * 1024


def build_secret_payload(document: Document) -> dict[str, Any]:
    accounts: list[dict[str, Any]] = []
    needed: set[tuple[str, str]] = set()

    for spec in document.enabled():
        payload = dump_account(spec)
        # 运行期覆盖层里的东西不进 Secret：它们是本机产物，CI 有自己的缓存。
        payload.pop("display", None)
        # browser_state 不进 Secret：CI 环境 Turnstile 成功率极低，应优先用 token/cookie。
        # 本地环境的 browser_state 已在 overlay.json 中缓存。
        if "credentials" in payload and "browser_state" in payload["credentials"]:
            payload["credentials"].pop("browser_state")
            # 如果 credentials 空了就删掉整个键
            if not payload["credentials"]:
                payload.pop("credentials")
        accounts.append(payload)
        for login in spec.login.chain():
            if login.method == "oauth":
                provider = (login.provider or spec.login.provider or "linuxdo").strip().lower()
                account = (login.account or DEFAULT_OAUTH_ACCOUNT).strip()
                needed.add((provider, account))
        for task in spec.enabled_tasks():
            if task.method == "relogin":
                provider = (spec.login.provider or "linuxdo").strip().lower()
                needed.add((provider, (spec.login.account or DEFAULT_OAUTH_ACCOUNT).strip()))

    exported: dict[str, Any] = {}
    for provider, account in sorted(needed):
        state = document.oauth_state(provider, account)
        if not state:
            continue
        exported.setdefault(provider, {"accounts": {}})["accounts"][account] = {"state": state}

    payload: dict[str, Any] = {"version": CONFIG_VERSION, "accounts": accounts}
    if exported:
        payload["oauth_states"] = exported
    return payload


def dumps(document: Document) -> str:
    return json.dumps(build_secret_payload(document), ensure_ascii=False, separators=(",", ":"))


def check_size(text: str) -> str:
    """超限时返回可行动的提示；未超限返回空串。"""
    size = len(text.encode("utf-8"))
    if size <= SECRET_SIZE_LIMIT:
        return ""
    return (
        f"导出内容 {size / 1024:.1f} KiB，超过 GitHub Secret 的 {SECRET_SIZE_LIMIT // 1024} KiB 上限。"
        "常见原因是共享 OAuth 登录态过大：可以只保留 CI 真正需要的账号，"
        "或改用多个 Secret 分别注入。"
    )
