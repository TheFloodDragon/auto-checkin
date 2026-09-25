"""本次运行**实际可用**的资源能力。

引擎在阶段开始前就要知道「这条路走不走得通」：没有视觉模型配置就不该选 hCaptcha
分支，跑满 90 秒预算再失败；策略关了浏览器就不该把 OAuth 排进候选。旧实现把这些
判断散在各处（``ci/detect_browser.py`` 按配置字段猜、``solve_hcaptcha`` 跑起来才发现
缺 key），结论互不一致。

能力集只回答「有没有」，不回答「用不用」——用不用由 ``FlowPlan`` 与模板 ``requires``
决定。
"""

from __future__ import annotations

import os
import shutil
from functools import lru_cache
from typing import Any, Iterable

from solvers.registry import CAP_BROWSER, CAP_NODE, CAP_VISION

__all__ = [
    "CAP_BROWSER",
    "CAP_NODE",
    "CAP_VISION",
    "detect",
    "environment",
    "missing_reason",
    "required_by",
]


@lru_cache(maxsize=1)
def _browser_installed() -> bool:
    """Camoufox 与 Playwright 是否可用。

    只做 import 检查而不真的启动：启动一次浏览器要 1~2 秒，而这个判断在每个账号
    开始前都要做一次。真正启动失败会在租约里以明确异常暴露。
    """
    try:
        import camoufox  # noqa: F401
        import playwright  # noqa: F401
    except Exception:
        return False
    return True


@lru_cache(maxsize=1)
def _vision_configured() -> bool:
    """视觉模型是否已配置（API Key + base_url + model 至少能凑齐 key）。

    只读环境与根目录配置文件，绝不打印或返回任何值——这里的判断结果会进日志。
    """
    if os.environ.get("HCAPTCHA_VISION_CONFIG", "").strip():
        return True
    for name in ("HCAPTCHA_OPENAI_API_KEY", "OPENAI_API_KEY"):
        if os.environ.get(name, "").strip():
            return True
    try:
        from browser.openai_vision import _LOCAL_CONFIG_PATH  # noqa: PLC2701

        return _LOCAL_CONFIG_PATH.is_file()
    except Exception:
        return False


@lru_cache(maxsize=1)
def _node_available() -> bool:
    return bool(shutil.which("node"))


def environment() -> frozenset[str]:
    """与账号无关的环境能力。"""
    caps: set[str] = set()
    if _browser_installed():
        caps.add(CAP_BROWSER)
    if _vision_configured():
        caps.add(CAP_VISION)
    if _node_available():
        caps.add(CAP_NODE)
    return frozenset(caps)


def detect(account: Any = None) -> frozenset[str]:
    """账号级可用能力：环境能力 ∩ 账号策略允许的能力。"""
    caps = set(environment())
    policy = getattr(account, "policy", None)
    if policy is not None and not getattr(policy, "allow_browser", True):
        caps.discard(CAP_BROWSER)
        # 浏览器被策略关掉时，依赖浏览器的视觉解算同样不可用；留着只会让
        # 候选过滤放行一条实际走不通的路。
        caps.discard(CAP_VISION)
    return frozenset(caps)


def missing_reason(missing: Iterable[str]) -> str:
    """把缺失能力翻译成可行动的说明。"""
    hints = {
        CAP_BROWSER: "缺少浏览器（未安装 Camoufox：运行 `python -m camoufox fetch`，或账号策略 allow_browser=false）",
        CAP_VISION: "缺少视觉模型配置（设置 HCAPTCHA_VISION_CONFIG 或 OPENAI_API_KEY）",
        CAP_NODE: "缺少 Node.js（WASM PoW 挑战需要）",
    }
    return "；".join(hints.get(item, f"缺少能力 {item}") for item in sorted(missing))


def required_by(manifest: Any, chain: Any = None) -> frozenset[str]:
    """一个模板在**任何**候选路径下可能用到的能力集合。

    CI 用它决定要不要预装浏览器依赖：比按配置字段猜（旧 ci/detect_browser.py）准确，
    因为它读的就是引擎真正会走的候选。
    """
    caps: set[str] = set(getattr(manifest, "capabilities", ()) or ())
    from login import LOGINS

    for option in tuple(getattr(manifest, "login", ())) + tuple(getattr(manifest, "task", ())):
        caps.update(getattr(option, "requires", ()) or ())
        method = LOGINS.get(getattr(option, "method", ""))
        caps.update(getattr(method, "requires", ()) or ())
    steps = (getattr(chain, "steps", ()) if getattr(chain, "use", "") == "custom"
             else getattr(manifest, "chain", ())) or ()
    for step in steps:
        if step.kind == "browser":
            caps.add(CAP_BROWSER)
        for source in step.login:
            # browser/password 由页面完成；其它来源也尊重登录插件声明的能力。
            caps.update(getattr(LOGINS.get(source), "requires", ()) or ())
    return frozenset(caps)


def reset_cache() -> None:
    """测试用：清掉能力探测缓存。"""
    _browser_installed.cache_clear()
    _vision_configured.cache_clear()
    _node_available.cache_clear()
