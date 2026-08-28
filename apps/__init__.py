"""进程入口：单账号 worker、批量调度、图形界面。

三者共用同一套模型与引擎，不再各自拼一份「站点 → 运行参数」的 dict——旧实现里
那份映射写了三遍（``run__all_checkin.build_site_tasks`` / ``gui.core.task_params`` /
``checkin._execute``），字段增删必然漏改一处。
"""

from __future__ import annotations

__all__ = ["batch", "cli"]
