"""GitHub Secret 导出：生成 CI 用的最小化配置。

三条规则（从旧 ``accounts_store.build_github_secret_payload`` 继承，都有实测理由）：

1. **只导出启用账号**：禁用账号的凭据没必要进 Secret。
2. **凭据与登录方式无关**：用户配置的 token、cookie、browser_state 都保留。
   不能为了偏好纯 API 而丢弃浏览器任务必需的登录态；运行期覆盖层只有调用方显式
   传入时才采用，且仍遵循它的有效期与配置优先级。
3. **只带用得上的共享登录态**：顶层 ``oauth_states`` 只保留被启用账号实际引用的那几个，
   一份 Secret 有 64 KiB 上限，登录态动辄几十 KB。
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any, Iterable

from .overlay import Overlay
from .secret_codec import SECRET_SIZE_LIMIT, SecretText, decode_secret, encode_secret
from .proxies import network_mode
from .schema import CONFIG_VERSION, DEFAULT_OAUTH_ACCOUNT, Document, dump_account

__all__ = [
    "SECRET_SIZE_LIMIT", "SecretText", "build_secret_payload", "check_size", "decode_secret",
    "dumps", "encode_payload", "export_document", "minimize_payload",
]


def build_secret_payload(
    document: Document, *, overlay: Overlay | None = None, explicit: Iterable[str] = (),
) -> dict[str, Any]:
    """默认只导出用户配置；显式传入 overlay 才纳入启用账号的有效凭据。

    只取 apply() 的凭据视图，不导出学习数据/健康度，不续存时间戳，也不合并或
    跨来源提取浏览器快照。explicit 沿用覆盖层的「显式提供（含清空）」语义。
    """
    accounts: list[dict[str, Any]] = []
    needed: set[tuple[str, str]] = set()
    explicit_fields = tuple(explicit)

    for spec in document.enabled():
        exported_spec = spec if overlay is None else replace(
            spec, credentials=overlay.apply(spec, explicit=explicit_fields).credentials,
        )
        payload = dump_account(exported_spec)
        payload.pop("display", None)
        accounts.append(payload)
        for login in spec.login.chain():
            if login.method == "oauth":
                provider = (login.provider or spec.login.provider or "linuxdo").strip().lower()
                account = (login.account or DEFAULT_OAUTH_ACCOUNT).strip()
                needed.add((provider, account))
            # LinuxDO 的 github_fallback 是登录参数引用，不是独立的 oauth 候选。
            # fallback 参数继承主 login.args；false（含字符串形式）不能误作启用。
            args = {**spec.login.args, **login.args}
            if str(args.get("github_fallback") or "").strip().lower() in {"1", "true", "yes", "y", "on"}:
                account = str(args.get("github_account") or DEFAULT_OAUTH_ACCOUNT).strip() or DEFAULT_OAUTH_ACCOUNT
                needed.add(("github", account))
        for task in spec.enabled_tasks():
            if task.method == "relogin":
                provider = (spec.login.provider or "linuxdo").strip().lower()
                needed.add((provider, (spec.login.account or DEFAULT_OAUTH_ACCOUNT).strip()))
            # 导出可能发生在 GUI 线程，绝不为展开默认链而加载/执行模板脚本。
            # 默认链或省略浏览器 login 时无法静态排除 OAuth：保守保留该账号引用的
            # 一份共享态，而不是遗漏它或把所有 provider/account 的态全部打包。
            if task.chain is not None and (
                task.chain.use == "template" or any(
                    "oauth" in step.login or (step.kind == "browser" and not step.login)
                    for step in task.chain.steps
                )
            ):
                needed.add(_chain_oauth_reference(spec))

    exported: dict[str, Any] = {}
    for provider, account in sorted(needed):
        state = document.oauth_state(provider, account)
        if not state:
            continue
        exported.setdefault(provider, {"accounts": {}})["accounts"][account] = {"state": state}

    payload: dict[str, Any] = {"version": CONFIG_VERSION, "accounts": accounts}
    if exported:
        payload["oauth_states"] = exported
    needed_groups = {
        spec.network.proxy_group for spec in document.enabled() if network_mode(spec.network) == "group"
    }
    if document.default_proxy_group and any(network_mode(spec.network) == "inherit" for spec in document.enabled()):
        needed_groups.add(document.default_proxy_group)
        payload["default_proxy_group"] = document.default_proxy_group
    if needed_groups:
        exported_groups = []
        for group in document.proxy_groups:
            if group.id not in needed_groups:
                continue
            item = group.to_payload()
            # 订阅链接本身是凭据（常含 token），CI 只用已导入的节点，不需要也不会拉取订阅。
            item.pop("subscription", None)
            exported_groups.append(item)
        payload["proxy_groups"] = exported_groups
    return payload


def _chain_oauth_reference(spec: Any) -> tuple[str, str]:
    """与登录经纪人的 OAuth 参数覆盖顺序一致，不读取模板代码或凭据内容。"""
    login = spec.login
    args = dict(login.args or {})
    if login.provider:
        args.setdefault("provider", login.provider)
    if login.account:
        args.setdefault("account", login.account)
    for item in login.fallback:
        if item.method != "oauth":
            continue
        args.update(dict(item.args or {}))
        if item.provider:
            args["provider"] = item.provider
        if item.account:
            args["account"] = item.account
        break
    provider = str(args.get("provider") or login.provider or "linuxdo").strip().lower()
    account = str(args.get("account") or login.account or DEFAULT_OAUTH_ACCOUNT).strip()
    return provider, account


def minimize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """删除 Secret 运行时不需要的默认值与订阅导入索引，不改变执行语义。"""
    result = json.loads(json.dumps(payload, ensure_ascii=False, allow_nan=False))
    for account in result.get("accounts", []):
        if not isinstance(account, dict):
            continue
        if account.get("enabled") is True:
            account.pop("enabled", None)
        if account.get("template") == "auto":
            account.pop("template", None)
        network = account.get("network")
        if isinstance(network, dict):
            if network.get("verify_ssl") is True:
                network.pop("verify_ssl", None)
            if network.get("referer_path") == "/profile":
                network.pop("referer_path", None)
            if not network:
                account.pop("network", None)
        policy = account.get("policy")
        if isinstance(policy, dict) and not policy:
            account.pop("policy", None)
        for task in account.get("tasks", []):
            if isinstance(task, dict) and task.get("enabled") is True:
                task.pop("enabled", None)
    groups = result.get("proxy_groups")
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, dict):
                continue
            if group.get("enabled") is True:
                group.pop("enabled", None)
            group.pop("subscription", None)
            for node in group.get("proxies", []):
                if not isinstance(node, dict):
                    continue
                if node.get("enabled") is True:
                    node.pop("enabled", None)
                for key in ("source_id", "source_key", "capabilities"):
                    node.pop(key, None)
    return result


def encode_payload(payload: dict[str, Any]) -> SecretText:
    compact = json.dumps(minimize_payload(payload), ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return encode_secret(compact)


def export_document(
    document: Document, *, overlay: Overlay | None = None, explicit: Iterable[str] = (),
) -> SecretText:
    return encode_payload(build_secret_payload(document, overlay=overlay, explicit=explicit))


def dumps(document: Document, *, overlay: Overlay | None = None, explicit: Iterable[str] = ()) -> str:
    return export_document(document, overlay=overlay, explicit=explicit).text


def check_size(text: str) -> str:
    """超限时返回可行动的提示；未超限返回空串。"""
    size = len(text.encode("utf-8"))
    if size <= SECRET_SIZE_LIMIT:
        return ""
    return (
        f"导出内容 {size / 1024:.1f} KiB，超过 GitHub Secret 的 48 KB 上限（压缩后仍超限）。"
        "常见原因是站点 browser_state 或共享 OAuth 登录态过大：请仅启用 CI 真正需要的账号，"
        "无需浏览器的账号可移除多余 browser_state，或改用多个 Secret 分别注入。"
    )
