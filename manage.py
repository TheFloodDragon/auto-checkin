#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""图形管理界面入口。

    python manage.py

需要先装 GUI 依赖：``uv sync --extra gui``。单账号与批量操作均通过隔离子进程
调用同一个执行引擎（``runtime.engine``），每账号的多个任务共享登录和浏览器。
使用 ``python manage.py --config 路径`` 打开指定配置。
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
