"""批量执行入口：同站串行、跨站并发、当天沿用、汇总与结果文件。

相对旧 ``run__all_checkin.py`` 的三处实质改动：

1. **沿用判定按 ``(account_id, task_id)`` 匹配**。旧实现按任务的**显示名**匹配
   （``run__all_checkin.py:391``），站点改名或流程标签一变就丢掉当天全部历史；同名任务
   还得靠出现顺序配对。
2. **一个子进程一个账号**，同账号多任务共享登录与浏览器。
3. **汇总带流程摘要**：``登录=refresh(learned) / 任务=http_api(config)``。这条信息以前
   只能去 stderr 里翻。

用法::

    python -m apps.batch                 # 全部启用账号
    python -m apps.batch --retry-failed  # 沿用当天已完成结果，只跑没完成的
    python -m apps.batch --account a --account b
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from config import paths, store
from config.overlay import Overlay
from config.schema import Document
from core.errors import ConfigError
from core.masking import mask_secrets
from core.outcome import Outcome, Verdict, failed
from core.timebase import business_date, utc_iso
from runtime.batch import run_serial_groups
from runtime.events import RunEvent

__all__ = ["TaskRow", "main", "run_batch"]

RESULT_PATH = paths.RESULT_PATH
SCHEMA_VERSION = 2
#: 子进程因超时被强制终止时使用的约定退出码（与 GNU timeout 一致）。
TIMEOUT_EXIT_CODE = 124
#: 启动浏览器 + 收尾的额外开销，加在任务超时之上。
BROWSER_OVERHEAD = 120.0


# ── 行模型 ──────────────────────────────────────────────────────────────────
@dataclass
class AccountJob:
    account_id: str
    name: str
    base_url: str
    site_key: str
    timeout: float
    task_ids: tuple[str, ...] = ()


@dataclass
class TaskRow:
    """结果文件与汇总表的一行。"""

    account_id: str
    task_id: str
    payload: dict[str, Any]
    executed_this_run: bool = True
    carried_forward: bool = False
    retried: bool = False
    retry_succeeded: bool = False
    stage_logs: tuple[str, ...] = field(default=())

    @property
    def key(self) -> tuple[str, str]:
        return (self.account_id, self.task_id)

    @property
    def ok(self) -> bool:
        return bool(self.payload.get("ok"))

    def to_payload(self) -> dict[str, Any]:
        payload = dict(self.payload)
        payload.update(
            {
                "executed_this_run": self.executed_this_run,
                "carried_forward": self.carried_forward,
                "retried": self.retried,
                "retry_succeeded": self.retry_succeeded,
            }
        )
        return payload


# ── 主流程 ──────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    _reconfigure_stdio()
    print(f"每日任务开始：{datetime.now():%Y-%m-%d %H:%M:%S}")

    overlay = Overlay().load()
    try:
        document = store.load(Path(args.config) if args.config else None, overlay=overlay)
    except ConfigError as exc:
        print(f"读取配置失败：{exc.message}")
        return 3
    for note in document.notes:
        print(f"[migrate] {note}")

    # 业务日在这里定格一次：读历史、合并结果、写盘共用同一个值。分别取「现在」等于
    # 对同一轮运行做多次时间求值，跑得久时可能落在不同业务日，写出的日期与结果实际
    # 归属不符，进而误导下一轮的沿用判定。
    business_day = business_date()
    jobs = _build_jobs(document, only=args.account)
    if not jobs:
        print("没有启用的账号。")
        _write_result([], business_day=business_day)
        return 3

    history = _load_history(business_day) if args.retry_failed else None
    if args.retry_failed:
        print(
            f"已读取当天上次结果：{len(history)} 项。" if history is not None
            else "当天没有可复用的有效结果，本轮执行全部账号。"
        )

    rows = run_batch(
        jobs,
        history=history,
        workers=args.workers,
        verbose=args.verbose,
        business_day=business_day,
        config_path=args.config,
    )
    _write_result(rows, business_day=business_day)
    _print_summary(rows)

    failed_count = sum(1 for row in rows if not row.ok)
    print(f"结果文件：{RESULT_PATH}")
    return 0 if failed_count == 0 else 2


def run_batch(
    jobs: Sequence[AccountJob],
    *,
    history: Mapping[tuple[str, str], dict[str, Any]] | None = None,
    workers: int = 0,
    verbose: bool = False,
    business_day: str = "",
    config_path: str = "",
) -> list[TaskRow]:
    """执行一批账号，返回所有任务行（含沿用项）。"""
    carried: list[TaskRow] = []
    pending: list[AccountJob] = []

    for job in jobs:
        reusable = _carried_rows(job, history, business_day)
        if reusable is not None:
            carried.extend(reusable)
            continue
        pending.append(job)

    if carried:
        print(f"沿用上次已完成结果：{len(carried)} 项；本轮待执行账号：{len(pending)} 个。")

    results: list[list[TaskRow]] = run_serial_groups(
        list(pending),
        key=lambda job: job.site_key,
        execute=lambda job: _run_job(job, verbose=verbose, config_path=config_path, history=history),
        on_error=lambda job, exc: [
            _with_retry_metadata(_error_row(job, f"子任务异常：{type(exc).__name__}: {exc}"), history)
        ],
        workers=workers,
        on_result=lambda rows: [_print_row(row, verbose=verbose) for row in rows],
    )
    executed = [row for group in results for row in group]
    return _merge(jobs, carried, executed)


# ── 子进程 ──────────────────────────────────────────────────────────────────
def _run_job(
    job: AccountJob,
    *,
    verbose: bool,
    config_path: str,
    history: Mapping[tuple[str, str], dict[str, Any]] | None,
) -> list[TaskRow]:
    command = [sys.executable, "-m", "apps.cli", "--account", job.account_id, "--worker"]
    if config_path:
        command.extend(["--config", config_path])
    for task_id in job.task_ids:
        command.extend(["--task", task_id])

    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=str(paths.REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_child_env(),
            timeout=job.timeout,
        )
    except subprocess.TimeoutExpired as exc:
        # 超时也属于本轮执行，和正常返回共用下面的耗时与重试元数据收尾。
        stderr = _text(exc.stderr)
        duration = time.perf_counter() - started
        rows = [_error_row(job, f"账号执行超时（{job.timeout:.0f}s）已被终止", duration=duration)]
    else:
        duration = time.perf_counter() - started
        stderr = completed.stderr
        rows = _parse_worker_output(job, completed.stdout, completed.returncode)
    logs = _stage_logs(stderr) if not verbose else tuple(stderr.splitlines())
    return [
        _with_retry_metadata(
            TaskRow(
                account_id=row.account_id,
                task_id=row.task_id,
                # 子进程只知道单任务耗时；整账号耗时（含启动开销）由这里补上。
                payload={**row.payload, "account_duration_seconds": round(duration, 3)},
                stage_logs=logs,
            ),
            history,
        )
        for row in rows
    ]


def _with_retry_metadata(
    row: TaskRow, history: Mapping[tuple[str, str], dict[str, Any]] | None
) -> TaskRow:
    previous = history.get(row.key) if history else None
    # 只认同一任务的明确失败：同账号已成功的任务可能因别的任务失败而陪跑。
    retried = (
        row.executed_this_run and not row.carried_forward
        and previous is not None and previous.get("ok") is False
    )
    return replace(row, retried=retried, retry_succeeded=retried and row.ok)


def _parse_worker_output(job: AccountJob, stdout: str, code: int) -> list[TaskRow]:
    text = (stdout or "").strip()
    try:
        payload = json.loads(text) if text else None
    except json.JSONDecodeError:
        payload = None
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        preview = text.splitlines()[-1][:200] if text else "无输出"
        return [_error_row(job, f"子任务结果协议错误：stdout 不是结果对象；末行：{preview}")]

    rows: list[TaskRow] = []
    for item in payload["results"]:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        # 退出码与结果不一致时以退出码为准：子进程可能在写完结果后才崩。
        if code not in (0, 2) and row.get("ok"):
            row = {**row, "ok": False, "verdict": "failed", "label": "失败",
                   "message": f"子任务退出码为 {code}，与成功结果不一致"}
        rows.append(TaskRow(str(row.get("account_id") or job.account_id), str(row.get("task_id") or "daily"), row))
    if not rows:
        return [_error_row(job, "子任务没有返回任何任务结果")]
    return rows


def _child_env() -> dict[str, str]:
    """子进程环境。

    刻意**不**透传任何凭据类环境变量：新架构下子进程自己读配置与覆盖层，
    父进程不再解析凭据。旧实现用 env 传 token，一旦某个变量残留在父进程里，
    就会漏给没配这项凭据的站点（已实测：A 账号的 token 发到 B 站点）。
    """
    env = dict(os.environ)
    for name in (
        "CHECKIN_ACCESS_TOKEN", "CHECKIN_REFRESH_TOKEN", "CHECKIN_COOKIE",
        "CHECKIN_USER_ID", "CHECKIN_BROWSER_STATE", "CHECKIN_CONFIGURED_BROWSER_STATE",
        "CHECKIN_SCRIPT_ARGS", "CHECKIN_CACHE_POLICY",
    ):
        env.pop(name, None)
    return env


# ── 计划与沿用 ──────────────────────────────────────────────────────────────
def _build_jobs(document: Document, *, only: Sequence[str] = ()) -> list[AccountJob]:
    wanted = {str(item).strip() for item in only if str(item).strip()}
    jobs: list[AccountJob] = []
    for spec in document.enabled():
        if wanted and spec.id not in wanted:
            continue
        tasks = spec.enabled_tasks()
        if not tasks:
            continue
        needs_browser = _needs_browser(spec)
        budget = sum(float(task.timeout) for task in tasks)
        jobs.append(
            AccountJob(
                account_id=spec.id,
                name=spec.name,
                base_url=spec.base_url,
                site_key=spec.site_key,
                # 浏览器开销只加给真的可能开浏览器的账号：纯 HTTP 账号没必要
                # 把硬超时抬高两分钟，那只会让卡住的任务更晚被发现。
                timeout=budget + (BROWSER_OVERHEAD if needs_browser else 30.0),
                task_ids=(),
            )
        )
    return jobs


def _needs_browser(spec: Any) -> bool:
    from runtime import capabilities as caps_module
    from templates import registry as templates

    for task in spec.enabled_tasks():
        reference = spec.task_template(task)
        if not reference or reference.lower() == "auto":
            return True
        try:
            manifest = templates.get(reference).manifest
        except Exception:
            return True
        if "browser" in caps_module.required_by(manifest):
            return True
    return False


def _load_history(business_day: str) -> dict[tuple[str, str], dict[str, Any]] | None:
    try:
        with paths.file_lock(RESULT_PATH):
            if not RESULT_PATH.exists():
                return None
            payload = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(payload, dict) or payload.get("business_date") != business_day:
        return None
    rows = payload.get("results")
    if not isinstance(rows, list):
        return None
    history: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = (str(row.get("account_id") or ""), str(row.get("task_id") or ""))
        if key[0]:
            history[key] = row
    return history


def _carried_rows(
    job: AccountJob,
    history: Mapping[tuple[str, str], dict[str, Any]] | None,
    business_day: str,
) -> list[TaskRow] | None:
    """该账号的全部任务在当天都已完成时才整体沿用。

    只要有一个任务没完成就整账号重跑：任务之间共享登录与浏览器，拆开跑反而更贵。
    """
    if not history:
        return None
    rows = [row for (account_id, _), row in history.items() if account_id == job.account_id]
    if not rows:
        return None
    if not all(_completed(row, business_day) for row in rows):
        return None
    return [
        TaskRow(
            account_id=job.account_id,
            task_id=str(row.get("task_id") or "daily"),
            payload={**row, "carried_forward": True},
            executed_this_run=False,
            carried_forward=True,
            retry_succeeded=bool(row.get("retry_succeeded")),
        )
        for row in rows
    ]


def _completed(row: Mapping[str, Any], business_day: str) -> bool:
    """只有明确成功、``ok`` 严格为真、且业务日属于今天时才可沿用。

    条目级业务日是文件头日期之外的第二道防线：文件头只有一个日期，一旦因任何原因
    与条目实际归属不一致，昨天的结果就会顶替今天的任务。
    """
    if row.get("ok") is not True:
        return False
    stamp = str(row.get("business_date") or "").strip()
    return not stamp or stamp == business_day


def _merge(
    jobs: Sequence[AccountJob], carried: list[TaskRow], executed: list[TaskRow]
) -> list[TaskRow]:
    """按账号顺序合并沿用项与本轮执行项。"""
    by_account: dict[str, list[TaskRow]] = {}
    for row in carried + executed:
        by_account.setdefault(row.account_id, []).append(row)
    ordered: list[TaskRow] = []
    for job in jobs:
        ordered.extend(by_account.pop(job.account_id, []))
    for rest in by_account.values():
        ordered.extend(rest)
    return ordered


def _error_row(
    job: AccountJob, message: str, *, stage_logs: tuple[str, ...] = (), duration: float = 0.0
) -> TaskRow:
    outcome: Outcome = failed(message)
    payload = outcome.to_payload()
    payload.update(
        {
            "account_id": job.account_id,
            "task_id": "daily",
            "name": job.name,
            "base_url": job.base_url,
            "duration_seconds": round(duration, 3),
            "business_date": business_date(),
        }
    )
    return TaskRow(job.account_id, "daily", payload, stage_logs=stage_logs)


# ── 输出 ────────────────────────────────────────────────────────────────────
def _print_row(row: TaskRow, *, verbose: bool) -> None:
    payload = row.payload
    icon = payload.get("icon") or ""
    label = payload.get("label") or payload.get("verdict") or ""
    name = payload.get("name") or row.account_id
    task = row.task_id
    headline = f"[{name}/{task}] {icon} {label}"
    message = str(payload.get("message") or "")
    if message:
        headline += f" - {message}"
    print(headline, flush=True)
    text = payload.get("text")
    if text:
        print(f"  {payload.get('text_label') or '信息'}：{text}", flush=True)
    for key, value in payload.get("extras") or ():
        print(f"  {key}：{value}", flush=True)
    flow = payload.get("flow") or {}
    if flow:
        print("  流程：" + " / ".join(f"{k}={v}" for k, v in flow.items()), flush=True)
    # 阶段日志始终打印：这是判断「走了哪条路、卡在哪一级」的唯一线索。失败时打全量。
    logs = row.stage_logs if (verbose or not row.ok) else row.stage_logs[:12]
    if logs:
        print("  调用日志：", flush=True)
        for line in logs:
            print(f"    {line}", flush=True)
    print(flush=True)


def _stage_logs(stderr: str) -> tuple[str, ...]:
    """从子进程 stderr 里挑出结构化事件与已知前缀的诊断行。"""
    picked: list[str] = []
    for line in (stderr or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        event = RunEvent.from_line(stripped)
        if event is not None:
            picked.append(event.to_text())
        elif stripped.startswith("[http:") or stripped.startswith("[migrate]"):
            picked.append(stripped)
    return tuple(picked)


def _print_summary(rows: Sequence[TaskRow]) -> None:
    print("\n总结：")
    if not rows:
        print("  （无任务）")
        return
    name_width = max((len(str(row.payload.get("name") or row.account_id)) for row in rows), default=4)
    label_width = max((len(str(row.payload.get("label") or "")) for row in rows), default=4)
    text_labels = {str(row.payload.get("text_label") or "") for row in rows if row.payload.get("text")}
    has_failure_message = any(
        not row.ok and not row.payload.get("text") and row.payload.get("message") for row in rows
    )
    column = text_labels.pop() if len(text_labels) == 1 and not has_failure_message else "信息"

    header = f"  {'账号':<{name_width}} | {'任务':<8} | 图标 | {'状态':<{label_width}} | {column}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for row in rows:
        payload = row.payload
        text = str(payload.get("text") or "")
        if text and column == "信息" and payload.get("text_label"):
            text = f"{payload['text_label']}: {text}"
        if not text and not row.ok:
            # 新增的失败原因列也要脱敏并压成单行，避免凭据泄露或破坏汇总表。
            text = " ".join(mask_secrets(str(payload.get("message") or "")).split())
        marker = "↩ " if row.carried_forward else ("🔁 " if row.executed_this_run and row.retry_succeeded else "")
        print(
            f"  {str(payload.get('name') or row.account_id):<{name_width}} | {row.task_id:<8} | "
            f"{payload.get('icon') or ''} | {marker}{str(payload.get('label') or ''):<{label_width}} | {text}"
        )

    executed = sum(1 for row in rows if row.executed_this_run)
    carried = sum(1 for row in rows if row.carried_forward)
    failures = sum(1 for row in rows if not row.ok)
    by_verdict: dict[str, int] = {}
    for row in rows:
        key = str(row.payload.get("verdict") or "unknown")
        by_verdict[key] = by_verdict.get(key, 0) + 1
    print(
        f"\n本轮实际执行：{executed}；沿用上次完成：{carried}；失败：{failures}"
        f"（{'、'.join(f'{k}={v}' for k, v in sorted(by_verdict.items()))}）"
    )


def _write_result(rows: Sequence[TaskRow], *, business_day: str) -> None:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_iso(),
        "business_date": business_day,
        "totals": _totals(rows),
        "results": [row.to_payload() for row in rows],
    }
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with paths.file_lock(RESULT_PATH):
        paths.atomic_write_json(RESULT_PATH, payload)


def _totals(rows: Sequence[TaskRow]) -> dict[str, int]:
    counts = {str(item): 0 for item in Verdict}
    for row in rows:
        key = str(row.payload.get("verdict") or "")
        if key in counts:
            counts[key] += 1
    counts["total"] = len(rows)
    counts["executed"] = sum(1 for row in rows if row.executed_this_run)
    counts["carried_forward"] = sum(1 for row in rows if row.carried_forward)
    counts["failed"] = sum(1 for row in rows if not row.ok)
    return counts


# ── 参数 ────────────────────────────────────────────────────────────────────
def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="dailytask-batch", description="批量执行每日任务")
    parser.add_argument("--config", default="", help=f"配置文件路径，默认 {paths.ACCOUNTS_PATH}")
    parser.add_argument("--account", action="append", default=[], help="只执行指定账号 id（可重复）")
    parser.add_argument("--workers", type=int, default=0, help="并发上限，默认最多 8 个")
    parser.add_argument("--verbose", action="store_true", help="打印子进程的完整诊断输出")
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="沿用当天已完成的结果，仅执行未完成或新增的账号",
    )
    return parser.parse_args(argv)


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


def _reconfigure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8")
            except Exception:
                pass



if __name__ == "__main__":
    raise SystemExit(main())
