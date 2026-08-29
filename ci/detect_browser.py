#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检测本次运行是否需要浏览器依赖（CI 用）。

stdout 只打印 ``true`` / ``false``。

判据来自**引擎真正会走的候选**：每个启用账号的模板清单里，任何一个登录方式或任务
方式声明了 ``requires={"browser"}`` 就算需要。旧实现按配置字段猜（``auth_method in
{browser, oauth}`` 之类），模板一旦改变候选顺序，CI 装不装浏览器就和实际执行对不上。
"""

from __future__ import annotations

import sys


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    from apps.cli import main as cli_main

    return cli_main(["--requires", "browser"])


if __name__ == "__main__":
    raise SystemExit(main())
