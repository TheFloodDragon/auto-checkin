"""配置层：读写 ACCOUNTS.json、运行期覆盖层、迁移与 Secret 导出。

分工是刻意的：
- ``store`` / ``schema``：**用户配置**，运行期只读；
- ``overlay``：**运行期产物**（刷新到的凭据、探测到的流程、脚本学到的数据），
  永远不写回配置文件；
- ``migrate``：v1/v2 → v3 的一次性搬运，附带把旧缓存键重挂到新账号 id；
- ``settings``：全局可调参数（超时、重试、WAF、文件锁），全部支持 ``CHECKIN_`` 环境变量覆盖。
"""

from __future__ import annotations

from . import migrate, overlay, paths, schema, secrets, settings, store
from .overlay import CachePolicy, Overlay
from .schema import CONFIG_VERSION, Document

__all__ = [
    "CONFIG_VERSION",
    "CachePolicy",
    "Document",
    "Overlay",
    "migrate",
    "overlay",
    "paths",
    "schema",
    "secrets",
    "settings",
    "store",
]
