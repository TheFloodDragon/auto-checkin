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
import re
import subprocess
import sys
import time
import codecs
import threading
import signal
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from config import paths, store
from config.overlay import Overlay
from config.schema import Document
from core.errors import ConfigError
from core.masking import is_sensitive_key, mask_secrets
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
        return self.payload.get("ok") is True

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
    try:
        jobs = _build_jobs(document, only=args.account, only_tasks=args.task)
    except ConfigError as exc:
        print(f"任务配置错误：{mask_secrets(exc.message)}")
        return 3
    if not jobs:
        print("没有启用的账号。")
        _write_result([], business_day=business_day)
        return 3

    _KEEPALIVE_DONE[0] = False
    _keepalive(document, overlay, jobs, only=args.account, hours=args.oauth_renew_hours,
               force_verify=args.oauth_force_verify)

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
            _with_retry_metadata(row, history)
            for row in _error_rows(job, f"子任务异常：{type(exc).__name__}: {exc}", executed=False)
        ],
        workers=workers,
        on_result=lambda rows: [_print_row(row, verbose=verbose) for row in rows],
    )
    executed = [row for group in results for row in group]
    return _merge(jobs, carried, executed)


# ── 子进程 ──────────────────────────────────────────────────────────────────
MAX_STDOUT_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 2 * 1024 * 1024
MAX_EVENT_LINE = 32768


def _run_worker(command, *, cwd, env, timeout, on_event=None, **_options):
    """并行排空两个管道，stderr 逐行通知；stdout 始终是唯一机器 JSON 通道。"""
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=os.name != "nt",
                               creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)

    def terminate_tree():
        if os.name == "nt":
            # 不经 shell/MSYS2；终止 worker 及其浏览器后代，避免继承管道使 reader 永不 EOF。
            try:
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.kill()
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()

    def drain_stdout():
        while chunk := process.stdout.read1(8192):
            if len(stdout) + len(chunk) > MAX_STDOUT_BYTES:
                overflow.set()
            if not overflow.is_set():
                stdout.extend(chunk)

    def deliver(event):
        if on_event is not None:
            try:
                on_event(event)
            except Exception:
                # 展示方异常不能停止排空 stderr，进而堵住 worker。
                pass

    def drain_stderr():
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        line = ""
        dropping = False
        limited = False
        while chunk := process.stderr.read1(8192):
            if not limited:
                if len(stderr) + len(chunk) <= MAX_STDERR_BYTES:
                    stderr.extend(chunk)
                else:
                    # 丢弃最后不完整行，不能截掉敏感键名后保留裸值。
                    end = stderr.rfind(b"\n")
                    del stderr[max(0, end + 1):]
                    limited = True
            for fragment in decoder.decode(chunk).splitlines(keepends=True):
                newline = fragment.endswith(("\n", "\r"))
                if not dropping:
                    line += fragment
                    if len(line) > MAX_EVENT_LINE:
                        line = ""
                        dropping = True
                if newline:
                    if not dropping and on_event is not None:
                        event = RunEvent.from_line(line)
                        if event is not None:
                            deliver(event)
                    line = ""
                    dropping = False
        line += decoder.decode(b"", final=True)
        if line and not dropping and on_event is not None:
            event = RunEvent.from_line(line)
            if event is not None:
                deliver(event)

    readers = [threading.Thread(target=drain_stdout, daemon=True), threading.Thread(target=drain_stderr, daemon=True)]
    for reader in readers:
        reader.start()
    timed_out = False
    expires = time.monotonic() + timeout
    try:
        while process.poll() is None:
            if overflow.is_set():
                terminate_tree()
                break
            remaining = expires - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            try:
                process.wait(timeout=min(.1, remaining))
            except subprocess.TimeoutExpired:
                continue
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate_tree()
    finally:
        process.wait()
        for reader in readers:
            reader.join(timeout=max(.1, expires - time.monotonic()))
        if any(reader.is_alive() for reader in readers):
            timed_out = True
            terminate_tree()
            for reader in readers:
                reader.join(timeout=5)
        # 不在持有阻塞 read 的线程上争夺 BufferedReader 锁；极端情况下也不死锁。
        if not readers[0].is_alive():
            process.stdout.close()
        if not readers[1].is_alive():
            process.stderr.close()
    out = stdout.decode("utf-8", "replace")
    err = stderr.decode("utf-8", "replace")
    if timed_out:
        raise subprocess.TimeoutExpired(command, timeout, output=out, stderr=err)
    if overflow.is_set():
        out = ""
        err += "\n后台结果超过大小限制"
    return subprocess.CompletedProcess(command, process.returncode, out, err)


def _print_live_event(job, event, *, verbose, seen):
    if event.account != job.account_id or (event.task and job.task_ids and event.task not in job.task_ids):
        return
    fields = event.fields
    challenge = fields.get("event") == "challenge_status"
    if challenge and not all(isinstance(fields.get(key, ""), str) for key in ("status", "generation", "step")):
        return
    if not verbose and not challenge:
        return
    key = (event.account, event.task, fields.get("step", ""), fields.get("generation", ""), fields.get("status", ""))
    if challenge and (key in seen or len(seen) >= 2048):
        return
    if challenge or verbose:
        seen.add(key)
    print(_safe_diagnostic(event.to_text()), flush=True)


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
    live_seen = set()
    try:
        completed = _run_worker(
            command,
            cwd=str(paths.REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_child_env(),
            timeout=job.timeout,
            on_event=lambda event: _print_live_event(job, event, verbose=verbose, seen=live_seen),
        )
    except subprocess.TimeoutExpired as exc:
        # 超时也属于本轮执行，和正常返回共用下面的耗时与重试元数据收尾。
        stderr = _text(exc.stderr)
        duration = time.perf_counter() - started
        rows = _error_rows(job, f"账号执行超时（{job.timeout:.0f}s）已被终止；已启动 worker，无法确认各任务完成情况", duration=duration)
        rows = _diagnose_rows(rows, TIMEOUT_EXIT_CODE, stderr)
    except OSError as exc:
        duration = time.perf_counter() - started
        stderr = f"{type(exc).__name__}: {exc}"
        rows = _diagnose_rows(_error_rows(job, "子任务启动失败，未执行", executed=False), None, stderr)
    else:
        duration = time.perf_counter() - started
        stderr = completed.stderr
        rows = _parse_worker_output(job, completed.stdout, completed.returncode, stderr=stderr)
    return [
        _with_retry_metadata(
            replace(
                row,
                # 子进程只知道单任务耗时；整账号耗时（含启动开销）由这里补上。
                payload={**row.payload, "account_duration_seconds": round(duration, 3)},
                # 一个 worker 可能跑多个任务：每行只保留本任务及不属于任何任务的共享日志。
                stage_logs=(
                    tuple(_safe_diagnostic("\n".join(line for line in stderr.splitlines()
                          if not live_seen or RunEvent.from_line(line) is None)).splitlines()) if verbose
                    else _stage_logs(stderr, task_id=row.task_id, skip_challenges=bool(live_seen))
                ) + row.stage_logs,
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


def _parse_worker_output(job: AccountJob, stdout: str, code: int, *, stderr: str = "") -> list[TaskRow]:
    def protocol_error(message: str) -> list[TaskRow]:
        return _diagnose_rows(_error_rows(job, message + "；已启动 worker，无法确认各任务完成情况"), code, stderr)

    text = (stdout or "").strip()
    try:
        payload = json.loads(text) if text else None
    except json.JSONDecodeError:
        payload = None
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        preview = _safe_diagnostic(text).splitlines()[-1][:200] if text else "无输出"
        return protocol_error(f"子任务结果协议错误：stdout 不是结果对象；末行：{preview}")

    rows: list[TaskRow] = []
    for item in payload["results"]:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        if not isinstance(row.get("ok"), bool) or (
            "verdict" in row and row.get("ok") != Outcome.from_payload(row).ok
        ):
            row = {**row, "ok": False, "verdict": "failed", "label": "失败",
                   "message": "子任务结果协议错误：ok 与 verdict 不一致或不是布尔值"}
        # 退出码与结果不一致时以退出码为准：子进程可能在写完结果后才崩。
        if code not in (0, 2) and row.get("ok"):
            row = {**row, "ok": False, "verdict": "failed", "label": "失败",
                   "message": f"子任务退出码为 {code}，与成功结果不一致"}
        account_id = str(row.get("account_id") or job.account_id)
        if job.task_ids and not row.get("task_id"):
            return protocol_error("子任务结果协议错误：缺少任务标识")
        task_id = str(row.get("task_id") or "daily")
        if account_id != job.account_id or any(item.task_id == task_id for item in rows):
            return protocol_error("子任务结果协议错误：账号不匹配或任务结果重复")
        if job.task_ids and task_id not in job.task_ids:
            return protocol_error(f"子任务结果协议错误：未请求的任务 {task_id}")
        rows.append(TaskRow(account_id, task_id, row))
    if not rows:
        return protocol_error("子任务没有返回任何任务结果")
    for task_id in job.task_ids:
        if not any(row.task_id == task_id for row in rows):
            rows.append(_error_row(job, f"子任务未返回任务 {task_id} 的结果", task_id=task_id))
    if code == 2 and all(row.ok for row in rows):
        return protocol_error("子任务退出码为 2，但未返回失败结果")
    return _diagnose_rows(rows, code, stderr)


#: 父进程本轮已做过共享登录态保活：子进程据此跳过（不修改父进程自身的环境变量）。
_KEEPALIVE_DONE = [False]


def _keepalive(
    document: Document, overlay: Overlay, jobs: Sequence[AccountJob], *, only: Sequence[str], hours: float | None,
    force_verify: bool = False,
) -> None:
    """沿用筛选之前统一检查 linux.do / GitHub 共享态；子进程不再重复。"""
    from browser import runtime_loop
    from config.schema import OAuthStateReader
    from runtime import keepalive

    selected = {job.account_id for job in jobs}
    specs = [spec for spec in document.enabled() if spec.id in selected]
    references = [reference for spec in specs for reference in keepalive.references_oauth(spec)]
    captured = () if only else keepalive.oauth_accounts(document.oauth_states)
    accounts = tuple(dict.fromkeys((*captured, *references)))
    if not accounts:
        return
    try:
        results = runtime_loop.run_sync(keepalive.preflight(
            accounts,
            overlay=overlay,
            oauth_state=OAuthStateReader(document.oauth_states, document.path),
            network=keepalive.pick_network(specs),
            proxy_groups=document.proxy_groups,
            default_proxy_group=document.default_proxy_group,
            window_seconds=keepalive.renew_window_seconds(hours),
            force_verify=force_verify,
            log=lambda message: print(f"[oauth-keepalive] {mask_secrets(message)}", flush=True),
        ))
    except Exception as exc:  # noqa: BLE001 - 保活失败绝不阻断签到
        print(f"[oauth-keepalive] 保活未完成（{type(exc).__name__}），继续执行任务", flush=True)
        return
    expired = [f"{item.provider}:{item.account}" for item in results if item.status == "expired"]
    if expired:
        print(mask_secrets(f"[oauth-keepalive] 需要重新捕获的共享 OAuth 登录态：{'、'.join(expired)}"), flush=True)
    _KEEPALIVE_DONE[0] = True


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
    if _KEEPALIVE_DONE[0]:
        from runtime import keepalive

        env = keepalive.mark_done(env)
    return env


# ── 计划与沿用 ──────────────────────────────────────────────────────────────
def _build_jobs(
    document: Document, *, only: Sequence[str] = (), only_tasks: Sequence[str] = (),
) -> list[AccountJob]:
    from runtime.engine import _ordered_tasks

    wanted = {str(item).strip() for item in only if str(item).strip()}
    jobs: list[AccountJob] = []
    for spec in document.enabled():
        if wanted and spec.id not in wanted:
            continue
        tasks = _ordered_tasks(spec, only_tasks)
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
                task_ids=tuple(task.id for task in tasks),
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
    if job.task_ids:
        # 当前配置才是任务清单；旧结果中缺少的新任务不能被同账号 daily 成功覆盖。
        if any((job.account_id, task_id) not in history for task_id in job.task_ids):
            return None
        rows = [history[(job.account_id, task_id)] for task_id in job.task_ids]
    else:
        # 兼容未提供任务清单的调用方。
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
    data = row.get("data")
    if isinstance(data, Mapping) and data.get("blocked_by"):
        return False
    if "verdict" in row and not Outcome.from_payload(row).ok:
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


def _safe_diagnostic(text: str) -> str:
    """不依赖账号配置脱敏：敏感赋值所在行的余部整体丢弃，避免空格/容器泄漏。"""
    text = _text(text)
    # 非完整 JSON 的异常文本无法可靠确定多行容器边界；遇到此类敏感赋值
    # 保守省略后续文本，不能只删首行而把下一行中的值写进公开报告。
    for match in re.finditer(r"[\"']?([\w-]+)[\"']?\s*[:=][ \t]*", text):
        if not (is_sensitive_key(match.group(1)) or match.group(1).lower() in {"session", "cf_clearance"}):
            continue
        value = text[match.end():]
        if not value or value.startswith(("{", "[", "(", "\n", "\r", "|", ">", '\"\"\"', "'''")):
            text = text[:match.end()] + "<redacted: 敏感多行内容及后续文本已省略>"
            break
    # 引号包围的值可能跨行；先整体移除，再处理非引号赋值与 HTTP 头。
    text = re.sub(
        r"([\"']?([\w-]+)[\"']?\s*[:=]\s*)([\"'])(.*?)\3",
        lambda match: match.group(1) + "<redacted>" if is_sensitive_key(match.group(2)) else match.group(0),
        _text(text), flags=re.DOTALL,
    )
    lines = []
    for line in text.splitlines():
        for match in re.finditer(r"[\"']?([\w-]+)[\"']?\s*[:=]\s*", line):
            if is_sensitive_key(match.group(1)) or match.group(1).lower() in {"session", "cf_clearance"}:
                line = line[:match.end()] + "<redacted>"
                break
        lines.append(mask_secrets(line))
    return "\n".join(lines)


def _diagnose_rows(rows: list[TaskRow], code: int | None, stderr: str) -> list[TaskRow]:
    # 先脱敏再截断，避免切断凭据键名后暴露值；保留末尾的异常原因。
    safe = _safe_diagnostic(stderr).strip()
    summary = ("…" + safe[-1199:]) if len(safe) > 1200 else safe
    diagnostic = f"worker 退出码={code if code is not None else '无（未启动）'}；stderr：{summary or '无输出'}"
    result = []
    for row in rows:
        if not row.ok:
            payload = {**row.payload, "worker_exit_code": code, "worker_stderr_summary": summary,
                       "message": _safe_diagnostic(str(row.payload.get("message") or "")) + "；" + diagnostic}
            row = replace(row, payload=payload, stage_logs=row.stage_logs + (diagnostic,))
        result.append(row)
    return result


def _error_rows(
    job: AccountJob, message: str, *, duration: float = 0.0, executed: bool = True,
) -> list[TaskRow]:
    # 未提供任务集合的老调用方仍使用 daily；明确请求的任务绝不被 daily 替代。
    return [replace(_error_row(job, _safe_diagnostic(message), duration=duration, task_id=task_id),
                    executed_this_run=executed)
            for task_id in (job.task_ids or ("daily",))]


def _error_row(
    job: AccountJob, message: str, *, stage_logs: tuple[str, ...] = (), duration: float = 0.0,
    task_id: str = "daily",
) -> TaskRow:
    outcome: Outcome = failed(message)
    payload = outcome.to_payload()
    payload.update(
        {
            "account_id": job.account_id,
            "task_id": task_id,
            "name": job.name,
            "base_url": job.base_url,
            "duration_seconds": round(duration, 3),
            "business_date": business_date(),
        }
    )
    return TaskRow(job.account_id, task_id, payload, stage_logs=stage_logs)


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


def _stage_logs(stderr: str, task_id: str | None = None, *, skip_challenges: bool = False) -> tuple[str, ...]:
    """从子进程 stderr 里挑出结构化事件与已知前缀的诊断行。

    ``task_id`` 给定时，带任务归属的事件只保留属于该任务的；无归属的（网络、
    浏览器共享服务等）对所有任务都保留。
    """
    picked: list[str] = []
    for line in (stderr or "").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        event = RunEvent.from_line(stripped)
        if event is not None:
            if skip_challenges and event.fields.get("event") == "challenge_status":
                continue
            if task_id is not None and event.task and event.task != task_id:
                continue
            # 先解析协议、匹配任务，再脱敏展示文本，避免破坏事件 JSON 后静默丢日志。
            picked.append(_safe_diagnostic(event.to_text()))
        elif stripped.startswith("[http:") or stripped.startswith("[migrate]"):
            picked.append(_safe_diagnostic(stripped))
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
    parser.add_argument("--task", action="append", default=[], help="只执行指定任务 id 及其依赖（可重复）")
    parser.add_argument("--workers", type=int, default=0, help="并发上限，默认最多 8 个")
    parser.add_argument("--verbose", action="store_true", help="打印子进程的完整诊断输出")
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="沿用当天已完成的结果，仅执行未完成或新增的账号",
    )
    parser.add_argument(
        "--oauth-renew-hours", type=float, default=None,
        help="任务开始前 linux.do / GitHub 共享登录态剩余寿命低于此值（小时）就先续期；"
             "默认读 CHECKIN_OAUTH_RENEW_HOURS，否则 30；0 关闭自动保活",
    )
    parser.add_argument(
        "--oauth-force-verify", action="store_true",
        help="强制服务端验证 linux.do / GitHub 共享态（含未知到期时间，忽略临期窗口）；"
             "仅真实认证 Cookie 轮换才保存，不提交密码或二次验证",
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
