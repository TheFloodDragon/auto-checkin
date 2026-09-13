#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""读取结果 JSON（.cache-checkin/checkin_result.json），生成经过脱敏的 Markdown CI 报告。"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from config import paths as _paths
from core.masking import mask_secrets, sanitize_data
from core.outcome import Outcome, Verdict


def _cell(value: Any) -> str:
    # 0 是有效数值；HTML 转义之外还要禁止外部文本构造 Markdown 链接/图片。
    text = html.escape(mask_secrets("" if value is None else str(value)), quote=False)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return "".join("\\" + char if char in "\\`*_{}[]()!|#~" else char for char in text)


def _results(payload: Any) -> list[dict[str, Any]]:
    rows = payload.get("results", []) if isinstance(payload, dict) else payload
    return [row for row in rows if isinstance(row, dict) and row] if isinstance(rows, list) else []


def _outcome(row: dict[str, Any]) -> Outcome:
    normalized = dict(row)
    if not normalized.get("verdict"):
        normalized.pop("verdict", None)
        if normalized.get("tolerated") is True:
            normalized.update(verdict="no_effect", reason="tolerated")
        elif not normalized.get("status"):
            if normalized.get("legacy_status"):
                normalized["status"] = normalized["legacy_status"]
            else:
                # 最早的列表格式可能只有 ok/label，没有 status。
                normalized["verdict"] = "success" if normalized.get("ok") is True else "failed"
    return Outcome.from_payload(normalized)


def _executed(row: dict[str, Any]) -> bool:
    # 按行兼容无元数据的旧结果，不能因另一行带元数据就把它计为未执行。
    return row.get("carried_forward") is not True and row.get("executed_this_run", True) is True


def _row_status(row: dict[str, Any], outcome: Outcome) -> str:
    parts: list[str] = []
    if row.get("carried_forward") is True:
        parts.append("沿用上次完成")
        if row.get("retry_succeeded") is True:
            parts.append("此前重试成功")
    elif _executed(row):
        if row.get("retry_succeeded") is True:
            parts.append("本轮重试成功")
        elif row.get("retried") is True:
            parts.append("本轮重试")
    else:
        parts.append("本轮未执行")
    parts.append(f"{outcome.icon} {outcome.label}".strip())
    return _cell(" · ".join(parts))


def _named_value(label: Any, value: Any) -> str:
    label = str(label or "")
    # extras 是 [键, 值] 数组，递归脱敏不会自动把数组首项当作敏感键。
    value = sanitize_data(value, key=label)
    return f"{label}：{value}" if label else str(value)


def _row_info(row: dict[str, Any]) -> str:
    parts: list[str] = []
    if row.get("text") not in (None, ""):
        parts.append(_named_value(row.get("text_label") or "信息", row["text"]))
    else:
        # 旧额度字段没有统一货币单位，不擅自换算或添加货币符号。
        for field, label in (("quota_awarded", "本次额度"), ("current_quota", "当前额度")):
            if row.get(field) not in (None, ""):
                parts.append(_named_value(label, row[field]))
    extras = row.get("extras")
    if isinstance(extras, dict):
        extras = list(extras.items())
    if isinstance(extras, (list, tuple)):
        for item in extras:
            if isinstance(item, (list, tuple)) and len(item) == 2 and item[1] not in (None, ""):
                parts.append(_named_value(item[0], item[1]))
    return _cell("；".join(dict.fromkeys(parts)))


def _row_note(row: dict[str, Any], outcome: Outcome) -> str:
    parts = [f"原因：{outcome.reason}"] if outcome.reason else []
    for field in ("message", "note"):
        text = str(row.get(field) or "")
        if text and text not in parts:
            parts.append(text)
    return _cell("；".join(parts))


def build_report(payload: Any, *, exit_code: str | None = None) -> str:
    md = f"# 签到报告\n\n**报告时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    safe_payload = sanitize_data(payload)
    if isinstance(safe_payload, dict):
        for field, label in (("generated_at", "结果时间"), ("business_date", "业务日期")):
            if safe_payload.get(field):
                md += f"**{label}**: {_cell(safe_payload[field])}\n\n"
    if exit_code is not None:
        md += f"**签到脚本退出码**: {_cell(exit_code) if exit_code else '未产生（未执行或中断）'}\n\n"
        if exit_code and exit_code != "0":
            md += "签到进程未成功完成；任务明细不能替代进程退出码。\n\n"
    rows = _results(safe_payload)
    if not rows:
        return md + "## 错误\n\n签到脚本未生成有效结果。\n"

    outcomes = [_outcome(row) for row in rows]
    counts = Counter(outcome.verdict for outcome in outcomes)
    executed = sum(_executed(row) for row in rows)
    carried = sum(row.get("carried_forward") is True for row in rows)
    retried = sum(_executed(row) and row.get("retried") is True for row in rows)
    retry_succeeded = sum(_executed(row) and row.get("retry_succeeded") is True for row in rows)
    md += (
        "## 统计\n\n"
        f"- 成功: {counts[Verdict.SUCCESS]}\n"
        f"- 已完成/已领取: {counts[Verdict.ALREADY_DONE]}\n"
        f"- 无影响/不适用: {counts[Verdict.NO_EFFECT]}\n"
        f"- 失败: {counts[Verdict.FAILED]}\n"
        f"- 总计（任务项）: {len(rows)}\n"
        f"- 本轮实际执行: {executed}\n"
        f"- 沿用上次完成: {carried}\n"
        f"- 本轮重试: {retried}\n"
        f"- 本轮重试成功: {retry_succeeded}\n\n"
    )
    md += "## 详细结果\n\n| 站点 / 账号 | 任务 | 状态 | 数值 / 信息 | 原因 / 备注 |\n"
    md += "|------|------|------|------|------|\n"
    for row, outcome in zip(rows, outcomes):
        name = str(row.get("name") or row.get("site") or row.get("account_id") or "未知站点")
        account_id = str(row.get("account_id") or "")
        site = _cell(f"{name}（{account_id}）" if account_id and account_id != name else name)
        task = _cell(row.get("task_id") or "-")
        md += f"| {site} | {task} | {_row_status(row, outcome)} | {_row_info(row)} | {_row_note(row, outcome)} |\n"
    return md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-fresh", choices=("", "true", "false"), help="CI 是否确认本轮写入了新结果")
    parser.add_argument("--exit-code", help="签到进程的真实退出码；空字符串表示未执行或中断")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    payload: Any = None
    error = ""
    result_path = _paths.RESULT_PATH
    if args.exit_code == "":
        error = "签到步骤未执行或未产生退出码；已忽略上次缓存。"
    elif args.result_fresh is not None and args.result_fresh != "true":
        error = "本轮未生成新的签到结果；已忽略上次缓存。"
    elif not result_path.exists():
        error = "未生成签到结果文件。"
    else:
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            error = f"解析签到结果失败：{exc}"
    markdown = build_report(payload, exit_code=args.exit_code)
    if error:
        markdown += f"\n{_cell(error)}\n"

    report_path = Path("checkin_report.md")
    with _paths.file_lock(report_path):
        _paths.atomic_write_text(report_path, markdown)
    print("report generated")
    return 0 if not error and _results(payload) else 1


if __name__ == "__main__":
    raise SystemExit(main())
