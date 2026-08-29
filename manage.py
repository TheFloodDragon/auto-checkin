#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""图形管理界面入口。

    python manage.py

需要先装 GUI 依赖：``uv sync --extra gui``。界面里的「测试运行」与批量执行走的是
**同一个引擎**（``runtime.engine``），只是前者在进程内、后者在子进程——两条路的行为
因此不会分叉。
"""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from gui.app import main as run
    except ModuleNotFoundError as exc:  # pragma: no cover - 运行期依赖提示
        if str(getattr(exc, "name", "")).startswith("PySide6"):
            print(
                "缺少 PySide6。安装图形界面依赖后重试：uv sync --extra gui",
                file=sys.stderr,
            )
            return 1
        raise
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
