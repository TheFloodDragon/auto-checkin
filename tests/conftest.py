# -*- coding: utf-8 -*-
"""测试全局夹具：把一切运行期落盘重定向到临时目录。

为什么需要：覆盖层、共享存储与结果文件的路径都是模块级常量，而链路里多处会在
「拿到新 token」「学到一条流程」之后顺手落盘。任何忘了打补丁的用例都会写进仓库里
的真实缓存（实测出现过 ``https://s.invalid|s`` 这类测试数据污染真实运行状态）。
逐个用例 monkeypatch 不可靠——持久化入口变过一次，旧补丁就静默失效了。

因此这里用 autouse 夹具兜底：无论用例是否自己打补丁，落盘都在 tmp_path。需要断言
缓存内容的用例照常自己 monkeypatch，行为不受影响。
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_runtime_paths(tmp_path, monkeypatch):
    """所有测试的运行期文件一律写入临时目录，绝不落到仓库里的真实缓存。"""
    from config import paths

    cache = tmp_path / ".cache-checkin"
    cache.mkdir(parents=True, exist_ok=True)
    for name, value in (
        ("CACHE_DIR", cache),
        ("RESULTS_DIR", cache),
        ("OVERLAY_PATH", cache / "overlay.json"),
        ("LEGACY_TOKEN_CACHE_PATH", cache / "token_cache.json"),
        ("RESULT_PATH", cache / "checkin_result.json"),
        ("SHARED_STORE_DIR", cache / "shared"),
        ("EVIDENCE_DIR", cache / "evidence"),
        ("ACCOUNTS_PATH", tmp_path / "ACCOUNTS.json"),
    ):
        monkeypatch.setattr(paths, name, value, raising=False)
    yield
