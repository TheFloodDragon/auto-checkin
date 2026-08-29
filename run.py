#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量执行入口：跑 ACCOUNTS.json 里所有启用的账号。

    python run.py                      # 全部启用账号
    python run.py --retry-failed       # 沿用当天已完成的结果，只跑没完成的
    python run.py --account jisudeng   # 只跑指定账号（可重复）

单个账号的详细执行与诊断用 ``python -m apps.cli --account <id>``。
"""

from __future__ import annotations

import sys

from apps.batch import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
