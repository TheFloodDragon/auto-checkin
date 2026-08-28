"""广义每日任务框架。

包结构（见 docs/REFACTOR_PLAN.md）：

- ``dailytask.core``     领域内核：结论模型、账号模型、流程计划、清单契约（零 IO）
- ``dailytask.config``   配置读写与运行期覆盖层
- ``dailytask.net``      HTTP 客户端与防护页判别
- ``dailytask.solvers``  解算器注册表（图形验证码 / Turnstile / hCaptcha / WAF）
- ``dailytask.browser``  浏览器调度（惰性租约）
- ``dailytask.login``    登录方式插件
- ``dailytask.task``     任务方式插件
- ``dailytask.templates``模板注册表（内置 newapi/sub2api 与用户模板同级）
- ``dailytask.runtime``  阶段编排、自动探测、预算与事件
- ``dailytask.sdk``      对外唯一稳定契约（脚本与模板只 import 这里）
"""

from __future__ import annotations

__all__ = ["__version__", "SDK_VERSION"]

__version__ = "2.0.0-dev"

# 脚本 / 模板声明依赖的 SDK 主版本。破坏性变更时递增，加载器据此拒绝不兼容脚本。
SDK_VERSION = 1
