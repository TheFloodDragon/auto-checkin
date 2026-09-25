"""单账号执行入口（worker）。

一个 worker = **一个账号**（不是一个任务）：同账号的多个任务共享一次登录与一次浏览器
启动，这是多任务模型的主要收益。旧实现是「一个站点一个子进程、一个子进程一个动作」，
于是抽奖 + 签到 + 答题要各启一次 Camoufox。

用法::

    python -m apps.cli --account jisudeng --worker
    python -m apps.cli --account jisudeng --task quiz --explain
    python -m apps.cli --account-json - --worker < account.json
    python -m apps.cli --list
    python -m apps.cli --export-secret
    python -m apps.cli --export-secret --include-overlay

约定：
- ``--worker`` 时 **stdout 只有一个 JSON 对象**，所有诊断走 stderr。这条规则被踩过
  多次（脚本 print 到 stdout 会污染结果），因此这里用 ``redirect_stdout`` 强制保证。
- 凭据只从配置文件与覆盖层读，**绝不进 argv**：命令行对同机其它用户可见。
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from config import paths, store
from config.overlay import CachePolicy, Overlay
from config.schema import Document, parse_account
from config.proxies import resolve_proxy, validate_proxy_config
from core.errors import ConfigError, TaskError
from core.outcome import failed
from runtime import engine

__all__ = ["main", "run_account_sync"]

EXIT_OK = 0
EXIT_FAILED = 2
EXIT_CONFIG = 3


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="dailytask", description="广义每日任务执行器（单账号）"
    )
    parser.add_argument("--account", default="", help="要执行的账号 id")
    parser.add_argument(
        "--account-json",
        default="",
        help="直接给一份账号 JSON（路径或 - 表示标准输入），用于 GUI 试跑未保存的配置",
    )
    parser.add_argument("--task", action="append", default=[], help="只执行指定任务 id（可重复）")
    parser.add_argument("--config", default="", help=f"配置文件路径，默认 {paths.ACCOUNTS_PATH}")
    parser.add_argument("--worker", action="store_true", help="机器协议模式：stdout 只输出结果 JSON")
    parser.add_argument("--explain", action="store_true", help="只解释本次会怎么跑（覆盖层判定 + 流程计划），不执行")
    parser.add_argument("--list", action="store_true", help="列出配置里的账号")
    parser.add_argument("--export-secret", action="store_true", help="打印可粘贴到 GitHub Secret 的单行最小化配置")
    parser.add_argument(
        "--include-overlay", action="store_true",
        help="仅用于 --export-secret：显式纳入启用账号的有效缓存凭据（含 browser_state），不导出学习数据",
    )
    parser.add_argument("--requires", default="", help="打印启用账号是否需要某项能力（browser/vision/node）")
    args = parser.parse_args(argv)
    if args.include_overlay and not args.export_secret:
        parser.error("--include-overlay 仅可与 --export-secret 一起使用")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    _reconfigure_stdio()

    # worker 的 stdout 是机器协议通道：把执行期间任何 print 都赶到 stderr。
    stream = contextlib.redirect_stdout(sys.stderr) if args.worker else contextlib.nullcontext()
    try:
        with stream:
            payload, code = _dispatch(args)
    except ConfigError as exc:
        print(f"配置错误：{exc.message}", file=sys.stderr, flush=True)
        return EXIT_CONFIG
    if payload is not None:
        indent = None if args.worker else 2
        print(json.dumps(payload, ensure_ascii=False, indent=indent, separators=(",", ":") if args.worker else None))
    return code


def _dispatch(args: argparse.Namespace) -> tuple[Any, int]:
    config_path = Path(args.config) if args.config else None
    overlay = Overlay(policy=_cache_policy(), accounts_path=config_path).load()

    if args.account_json:
        raw_account = _read_account_json(args.account_json)
        spec = parse_account(raw_account)
        document = replace(store.load(config_path, overlay=overlay), accounts=(spec,)) if config_path else Document(accounts=(spec,))
        validate_proxy_config(document.to_payload())
        explicit = _explicit_fields(raw_account)
    else:
        document = store.load(config_path, overlay=overlay)
        for note in document.notes:
            print(f"[migrate] {note}", file=sys.stderr, flush=True)
        explicit = ()
        spec = None

    if args.list:
        return _list(document), EXIT_OK
    if args.export_secret:
        from config import secrets

        text = secrets.dumps(document, overlay=overlay if args.include_overlay else None, explicit=explicit)
        warning = secrets.check_size(text)
        if warning:
            print(f"[warn] {warning}", file=sys.stderr, flush=True)
        print(text)
        return None, EXIT_OK
    if args.requires:
        return _requires(document, args.requires)

    if spec is None:
        if not args.account:
            raise ConfigError("请用 --account <id> 指定账号（--list 可查看全部 id）")
        spec = document.account(args.account)
        if spec is None:
            known = "、".join(item.id for item in document.accounts) or "（空）"
            raise ConfigError(f"配置里没有 id={args.account!r} 的账号；已知：{known}")

    if args.explain:
        return _explain(spec, overlay, document=document), EXIT_OK

    run = run_account_sync(
        spec,
        overlay=overlay,
        explicit=explicit,
        only_tasks=tuple(args.task),
        oauth_state=lambda provider, account: document.oauth_state(provider, account),
        proxy_groups=document.proxy_groups,
        default_proxy_group=document.default_proxy_group,
        structured=args.worker,
    )
    payload = run.to_payload()
    return payload, EXIT_OK if run.ok else EXIT_FAILED


def run_account_sync(spec: Any, **kwargs: Any) -> engine.AccountRun:
    """同步执行一个账号。

    用 ``browser.runtime_loop.run_sync`` 而不是 ``asyncio.run``：它带着 Windows 上
    Proactor 管道析构噪声的补丁，以及事件循环残留 task 的可靠清理——这些是浏览器
    子进程稳定退出的前提（旧实现为此踩过多次）。
    """
    from browser import runtime_loop

    try:
        return runtime_loop.run_sync(engine.run_account(spec, **kwargs))
    except TaskError as exc:
        return _single(spec, exc.to_outcome())
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # noqa: BLE001 - 顶层兜底：worker 必须产出协议内的结果
        return _single(spec, failed(f"账号执行异常：{type(exc).__name__}: {exc}"))


def _single(spec: Any, outcome: Any) -> engine.AccountRun:
    """把「还没进入任务循环就失败了」包装成协议内的结果。"""
    record = engine.TaskRecord(
        account_id=spec.id,
        task_id="daily",
        name=spec.name,
        base_url=spec.base_url,
        outcome=outcome,
        template=str(spec.template or ""),
    )
    return engine.AccountRun(spec.id, spec.name, spec.base_url, (record,))


# ── 子命令 ──────────────────────────────────────────────────────────────────
def _list(document: Document) -> list[dict[str, Any]]:
    return [
        {
            "id": spec.id,
            "name": spec.name,
            "base_url": spec.base_url,
            "template": spec.template,
            "enabled": spec.enabled,
            "tasks": [
                {"id": task.id, "method": task.method or "auto", "enabled": task.enabled}
                for task in spec.tasks
            ],
        }
        for spec in document.accounts
    ]


def _requires(document: Document, capability: str) -> tuple[Any, int]:
    """CI 用：启用账号里有没有任何一条候选路径需要该能力。

    比旧 ``ci/detect_browser.py`` 按配置字段猜准确——这里读的就是引擎真正会走的候选。
    """
    from runtime import capabilities as caps_module
    from templates import registry as templates

    wanted = str(capability).strip().lower()
    needed = False
    for spec in document.enabled():
        for task in spec.enabled_tasks():
            reference = spec.task_template(task)
            try:
                template = templates.get(reference)
            except Exception:
                # 模板加载不了时保守认为可能需要：少装一次依赖的代价远大于多装一次。
                needed = True
                continue
            if wanted in caps_module.required_by(template.manifest, task.chain):
                needed = True
    print("true" if needed else "false")
    return None, EXIT_OK


def _explain(spec: Any, overlay: Overlay, *, document: Document | None = None) -> dict[str, Any]:
    """不执行，只说明本次会怎么跑。排查「为什么没用缓存的 token」的第一站。"""
    from core.flow import FlowPlan
    from runtime import capabilities as caps_module
    from templates import registry as templates

    account = overlay.apply(spec)
    selection = resolve_proxy(spec.network, document.proxy_groups if document else (),
                              document.default_proxy_group if document else "",
                              environ_proxy=os.environ.get("CHECKIN_PROXY", ""))
    caps = caps_module.detect(account)
    out: dict[str, Any] = {
        "account_id": spec.id,
        "network": selection.to_payload(),
        "capabilities": sorted(caps),
        "overlay": overlay.explain(spec),
        "tasks": [],
    }
    for task in spec.enabled_tasks():
        reference = spec.task_template(task)
        entry: dict[str, Any] = {"task_id": task.id, "template": reference}
        try:
            template = templates.get(reference) if reference.lower() != "auto" else None
        except Exception as exc:  # noqa: BLE001
            entry["error"] = str(exc)
            out["tasks"].append(entry)
            continue
        plan = FlowPlan.resolve(
            configured=engine._flow_config(spec, task),  # noqa: SLF001 - 诊断入口，刻意复用同一实现
            template=template.manifest if template else None,
            learned=account.learned_flow,
            capabilities=caps,
            failure_streak=int(account.health.get("failure_streak", 0) or 0),
        )
        entry["flow"] = plan.to_payload()
        entry["describe"] = plan.describe()
        if task.chain is not None:
            if template is None:
                entry["chain"] = {"error": "auto 模板在运行时才探测，访问链届时解析"}
            else:
                try:
                    entry["chain"] = engine.explain_chain(task, template, caps, account)
                    entry["describe"] = "访问链：" + entry["chain"]["describe"]
                except Exception as exc:  # noqa: BLE001 - 诊断入口，如实报告配置问题
                    entry["chain"] = {"error": str(exc)}
        out["tasks"].append(entry)
    return out


# ── 输入 ────────────────────────────────────────────────────────────────────
def _read_account_json(reference: str) -> dict[str, Any]:
    """读一份账号 JSON。stdin 只能读一次，因此这里一次性读完并复用。"""
    text = sys.stdin.read() if reference.strip() == "-" else Path(reference).read_text(encoding="utf-8")
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"--account-json 不是合法 JSON：{exc}") from exc
    if isinstance(raw, dict) and "accounts" in raw:
        candidates = raw.get("accounts") or []
        raw = candidates[0] if candidates else None
    if not isinstance(raw, dict):
        raise ConfigError("--account-json 需要一个账号对象")
    return raw


def _explicit_fields(raw: dict[str, Any]) -> tuple[str, ...]:
    """``--account-json`` 里出现过的凭据字段视为「调用方显式提供」（含显式清空）。

    这是覆盖层规则 2 的入口：GUI 里刚清空一个 token 就该立刻生效，否则用户永远
    无法强制重新登录。
    """
    from core.account import CREDENTIAL_FIELDS

    credentials = raw.get("credentials")
    if not isinstance(credentials, dict):
        return ()
    return tuple(key for key in credentials if key in CREDENTIAL_FIELDS)


def _cache_policy() -> str:
    raw = os.environ.get("CHECKIN_CACHE_POLICY", "").strip().lower()
    return raw if raw in {CachePolicy.COMPATIBLE, CachePolicy.IGNORE, CachePolicy.READONLY} else CachePolicy.COMPATIBLE


def _reconfigure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
