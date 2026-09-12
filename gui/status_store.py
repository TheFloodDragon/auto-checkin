"""逐任务结果缓存：今日状态、跨日最近返回与稳定键原子合并写。"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from config import paths
from core import timebase

from .worker import safe_data

RecordKey = tuple[str, str]
_ORDER = "_result_order"  # 同一轮同时间任务的数组顺序；不暴露到查询结果。


def _is_newer(candidate: Any, existing: Any) -> bool:
    left = timebase.parse_timestamp(candidate)
    right = timebase.parse_timestamp(existing)
    return left is not None and (right is None or left > right)


def _read(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return None
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError(f"结果文件 {path.name} 必须是 JSON 对象")
    return payload


def _rows(payload: dict[str, Any], *, field: str = "results", default_stamp: str = "") -> dict[RecordKey, dict[str, Any]]:
    """解析已脱敏条目；历史行不能继承新快照的日期或生成时间。"""
    rows = payload.get(field, [] if field == "latest_results" else None)
    if not isinstance(rows, list):
        raise ValueError(f"v2 结果缺少 {field} 数组")
    parent_stamp = str(payload.get("generated_at") or default_stamp) if field == "results" else ""
    parent_day = str(payload.get("business_date") or "") if field == "results" else ""
    result: dict[RecordKey, dict[str, Any]] = {}
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict):
            raise ValueError("任务结果必须是 JSON 对象")
        account_id = str(raw.get("account_id") or payload.get("account_id") or "")
        task_id = str(raw.get("task_id") or "")
        if not account_id or not task_id:
            raise ValueError("任务结果缺少稳定 account_id/task_id")
        stamp = str(raw.get("generated_at") or parent_stamp)
        stamp_day = timebase.business_date_of(stamp)
        day = str(raw.get("business_date") or parent_day or stamp_day)
        if not stamp_day or day != stamp_day or (parent_day and parent_day != stamp_day):
            continue
        order = raw.get(_ORDER, index)
        if type(order) is not int or order < 0:
            raise ValueError("任务结果顺序必须是非负整数")
        entry = dict(raw)
        entry.update(account_id=account_id, task_id=task_id, generated_at=stamp, business_date=day)
        entry[_ORDER] = order
        key = (account_id, task_id)
        previous = result.get(key)
        # 单个明确结果数组里，同时间的重复任务以靠后者为准；跨快照仍严格比时间。
        if previous is None or not _is_newer(previous.get("generated_at"), stamp):
            result[key] = entry
    return result


def _merge(target: dict[RecordKey, dict[str, Any]], candidates: dict[RecordKey, dict[str, Any]]) -> None:
    for key, entry in candidates.items():
        previous = target.get(key)
        if previous is None or _is_newer(entry.get("generated_at"), previous.get("generated_at")):
            target[key] = entry


def _public(entry: dict[str, Any]) -> dict[str, Any]:
    return deepcopy({key: value for key, value in entry.items() if key != _ORDER})


def _today_rows(entries: dict[RecordKey, dict[str, Any]], today: str) -> dict[RecordKey, dict[str, Any]]:
    return {key: _public(entry) for key, entry in entries.items()
            if entry.get("business_date") == today and timebase.business_date_of(entry.get("generated_at")) == today}


def _result_sets(payload: dict[str, Any], *, today: str, default_stamp: str = "") -> tuple[dict, dict]:
    if payload.get("schema_version") != 2:
        return {}, {}  # 不转换旧版 GUI cache / flat result。
    clean = safe_data(payload)
    rows = _rows(clean, default_stamp=default_stamp)
    latest = _rows(clean, field="latest_results")
    daily = _today_rows(rows, today)
    _merge(daily, _today_rows(latest, today))
    # 快照 results 按稳定键排序，不能覆盖 latest_results 中保留的原始执行顺序。
    _merge(latest, rows)
    return daily, latest


def _latest_rank(entry: dict[str, Any]) -> tuple:
    data = entry.get("data")
    executed = not (isinstance(data, dict) and data.get("blocked_by"))
    return timebase.parse_timestamp(entry["generated_at"]), executed, entry[_ORDER]


def _payload(entries: dict[RecordKey, dict[str, Any]], latest: dict[RecordKey, dict[str, Any]], day: str) -> dict[str, Any]:
    return {"schema_version": 2, "business_date": day, "generated_at": timebase.utc_iso(),
            "results": [_public(entries[key]) for key in sorted(entries)],
            "latest_results": deepcopy(sorted(latest.values(), key=_latest_rank, reverse=True))}


class ResultStore:
    """只存执行结果，不接收 capture 凭据；读写失败不改已有内存。"""

    def __init__(self, results_dir: Path | None = None):
        self.results_dir = Path(results_dir) if results_dir is not None else paths.RESULTS_DIR
        self.entries: dict[RecordKey, dict[str, Any]] = {}
        self._latest_entries: dict[RecordKey, dict[str, Any]] = {}
        self.today = timebase.business_date()

    def load(self) -> None:
        today = timebase.business_date()
        # 换日/刷新时保留尚未异步写出的返回，磁盘只可用更新的生成时间替换。
        latest = dict(self._latest_entries)
        merged = _today_rows(latest, today)
        for name in ("checkin_result.json", "gui_results.json"):
            payload = _read(self.results_dir / name)
            if payload is not None:
                daily, recent = _result_sets(payload, today=today)
                _merge(merged, daily)
                _merge(latest, recent)
        # 事务提交，任何损坏/权限错误都不会用半份数据覆盖现有内存。
        self.entries, self._latest_entries, self.today = merged, latest, today

    def _ensure_today(self) -> None:
        if self.today != timebase.business_date():
            self.load()

    def records(self, account_id: str = "") -> list[dict]:
        try:
            self._ensure_today()
        except Exception:
            # 保留昨天内存用于错误恢复，但绝不把它展示成今天。
            return []
        today = timebase.business_date()
        return deepcopy([
            record for (owner, _), record in sorted(self.entries.items())
            if (not account_id or owner == account_id) and record.get("business_date") == today
        ])

    def get(self, account_id: str, task_id: str) -> dict | None:
        try:
            self._ensure_today()
        except Exception:
            return None
        entry = self.entries.get((account_id, task_id))
        if entry is None or entry.get("business_date") != timebase.business_date():
            return None
        return deepcopy(entry)

    def latest_records(self, account_id: str = "") -> list[dict]:
        """每个稳定账号/任务键只返回最近一条，跨日保留，按实际时间倒序。"""
        try:
            self._ensure_today()
        except Exception:
            pass  # 读盘失败仍可展示已有历史，但不据此推断今日状态。
        rows = [record for (owner, _), record in self._latest_entries.items()
                if not account_id or owner == account_id]
        return [_public(record) for record in sorted(rows, key=_latest_rank, reverse=True)]

    def latest(self, account_id: str, task_id: str = "") -> dict | None:
        """指定任务的最后返回，或账号最近一轮中靠后执行任务的返回。"""
        rows = self.latest_records(account_id)
        return next((row for row in rows if not task_id or row["task_id"] == task_id), None)

    def apply(self, account_run_payload: dict) -> None:
        if (not isinstance(account_run_payload, dict) or not account_run_payload.get("account_id")
                or account_run_payload.get("schema_version") != 2
                or account_run_payload.get("action") not in (None, "run")):
            raise ValueError("ResultStore 只接收逐任务 AccountRun 结果")
        today = timebase.business_date()
        stamp = timebase.utc_now().isoformat(timespec="microseconds").replace("+00:00", "Z")
        candidates, latest = _result_sets(account_run_payload, today=today, default_stamp=stamp)
        self._ensure_today()
        _merge(self.entries, candidates)
        _merge(self._latest_entries, latest)

    def snapshot_payload(self) -> dict:
        self._ensure_today()
        today = timebase.business_date()
        return _payload(_today_rows(self.entries, today), self._latest_entries, today)

    @staticmethod
    def write_payload(results_dir: Path, payload: dict) -> None:
        """锁内重新读取并合并最新结果；损坏文件/写盘失败显式上抛，不覆盖。"""
        today = timebase.business_date()
        if payload.get("business_date") != today:
            return  # 跨日后到达的旧快照不得让磁盘结果倒退。
        candidates, latest_candidates = _result_sets(payload, today=today)
        directory = Path(results_dir)
        target = directory / "gui_results.json"
        with paths.file_lock(target):
            merged: dict[RecordKey, dict[str, Any]] = {}
            latest: dict[RecordKey, dict[str, Any]] = {}
            # 批量结果也一并合入；正常新日快照携带磁盘旧日最近返回，不无限追加历史。
            for name in ("checkin_result.json", "gui_results.json"):
                existing = _read(directory / name)
                if existing is not None:
                    daily, recent = _result_sets(existing, today=today)
                    _merge(merged, daily)
                    _merge(latest, recent)
            _merge(merged, candidates)
            _merge(latest, latest_candidates)
            if timebase.business_date() != today:
                return  # 获取文件锁或读文件时跨业务日，交给下一份快照。
            paths.atomic_write_text(target, json.dumps(_payload(merged, latest, today), ensure_ascii=False, indent=2))

    def save(self) -> None:
        previous = self.entries, self._latest_entries, self.today
        try:
            self.write_payload(self.results_dir, self.snapshot_payload())
        except Exception:
            # 生成跨日快照会刷新内存；写盘失败时连同业务日一起回滚该刷新。
            self.entries, self._latest_entries, self.today = previous
            raise


__all__ = ["ResultStore"]
