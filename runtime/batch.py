"""批量分组语义：同站串行、跨站并发。

同一 origin 的账号必须串行：并发访问同一站点既容易触发限流，也会让两个任务抢同一份
运行期覆盖层条目。无分组键的项目各自成组，保持输入顺序。跨站点不设固定并发上限。
"""

from __future__ import annotations

import concurrent.futures
from collections.abc import Callable, Iterable
from typing import TypeVar

ItemT = TypeVar("ItemT")
ResultT = TypeVar("ResultT")

__all__ = ["run_serial_groups", "serial_groups"]


def serial_groups(items: Iterable[ItemT], key: Callable[[ItemT], str]) -> list[list[ItemT]]:
    """按非空键稳定分组；空键项目各自独立，保持输入顺序。"""
    groups: list[list[ItemT]] = []
    keyed_positions: dict[str, int] = {}
    for item in items:
        group_key = str(key(item) or "").strip()
        if not group_key:
            groups.append([item])
            continue
        position = keyed_positions.get(group_key)
        if position is None:
            keyed_positions[group_key] = len(groups)
            groups.append([item])
        else:
            groups[position].append(item)
    return groups


def run_serial_groups(
    items: list[ItemT],
    *,
    key: Callable[[ItemT], str],
    execute: Callable[[ItemT], ResultT],
    on_error: Callable[[ItemT, Exception], ResultT],
    workers: int = 0,
    on_result: Callable[[ResultT], None] | None = None,
) -> list[ResultT]:
    """组内串行、所有组并发执行，并按输入顺序返回结果。

    ``workers`` 仅作旧调用的兼容参数，不再限制跨站点并发。
    """
    if not items:
        return []
    indexed_items = list(enumerate(items))
    groups = serial_groups(indexed_items, lambda pair: key(pair[1]))
    max_workers = len(groups)
    results: list[ResultT | None] = [None] * len(items)

    def run_group(group: list[tuple[int, ItemT]]) -> list[tuple[int, ResultT]]:
        completed: list[tuple[int, ResultT]] = []
        for index, item in group:
            try:
                result = execute(item)
            except Exception as exc:
                # 单个任务失败收敛成结果；KeyboardInterrupt/SystemExit 必须继续
                # 上抛，否则 Ctrl-C 会被当成一条普通失败、批量还接着跑完。
                result = on_error(item, exc)
            completed.append((index, result))
        return completed

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(run_group, group) for group in groups]
        for future in concurrent.futures.as_completed(futures):
            for index, result in future.result():
                results[index] = result
                if on_result is not None:
                    on_result(result)

    return [result for result in results if result is not None]
