"""页面操作 helper：站点脚本最常用的那十几个动作。

为什么单独一层而不是让脚本直接用 Playwright：这些动作每个脚本都要写一遍，而且每次
手写都会漏掉同一批边界情况——超时该不该吞、找不到元素算不算失败、截图往哪存、
金额文本怎么解析。旧 ``browser/script_helpers.py`` 已经把这些沉淀下来了，这里原样
迁移并接到新的 ``Context`` 上。

脚本仍然可以直接用 ``lease.page``：helper 是便利，不是围墙。
"""

from __future__ import annotations

import re
from typing import Any, Sequence
from urllib.parse import urljoin, urlparse

__all__ = ["PageHelpers", "parse_amount"]


def parse_amount(text: Any) -> float | None:
    """从页面文本里抽取金额：``余额 $26.55`` / ``￥1,234.40`` → 26.55 / 1234.4。

    取第一个数字（允许千分位逗号与小数点），识别不了返回 None。脚本常见做法是读一段
    带货币符号和千分位的文案，手写正则容易出错。
    """
    if isinstance(text, bool):
        return None
    if isinstance(text, (int, float)):
        return float(text)
    match = re.search(r"-?\d[\d,]*(?:\.\d+)?", str(text or ""))
    if not match:
        return None
    try:
        return float(match.group(0).replace(",", ""))
    except ValueError:
        return None


class PageHelpers:
    """绑定到一个页面的便利动作集合。"""

    __slots__ = ("ctx", "lease", "page")

    def __init__(self, ctx: Any, lease: Any, page: Any = None) -> None:
        self.ctx = ctx
        self.lease = lease
        self.page = page if page is not None else lease.page

    # ── 导航 ──
    def resolve_url(self, url: str | None = None) -> str:
        target = str(url or self.ctx.account.base_url or "").strip()
        if not target:
            raise ValueError("未提供跳转 URL，且账号 base_url 为空")
        if urlparse(target).scheme in {"http", "https"}:
            return target
        base = str(self.ctx.account.base_url or "").strip()
        if not base:
            raise ValueError(f"相对路径 {target!r} 需要账号 base_url")
        return urljoin(base.rstrip("/") + "/", target.lstrip("/"))

    async def goto(self, url: str | None = None, **kwargs: Any) -> Any:
        """跳转到目标页。

        默认只等导航提交（commit）并吞掉超时：部分站点长期不触发
        domcontentloaded/load，直接失败会把「页面其实已经可用」误报成错误。
        传 ``ignore_timeout=False`` 可恢复抛错行为。
        """
        return await self.lease.goto(self.resolve_url(url), page=self.page, **kwargs)

    async def dismiss_popups(self) -> int:
        return await self.lease.dismiss_popups(page=self.page)

    # ── 查找与点击 ──
    async def visible_text(self, text: str, timeout: int = 1000) -> bool:
        if not text:
            return False
        try:
            locator = self.page.get_by_text(text, exact=False).first
            await locator.wait_for(state="visible", timeout=timeout)
            return True
        except Exception:
            return False

    async def wait_text(self, text: str, timeout: int = 10000) -> bool:
        return await self.visible_text(text, timeout=timeout)

    async def click_text(self, text: str, timeout: int = 5000) -> bool:
        if not text:
            return False
        try:
            locator = self.page.get_by_text(text, exact=False).first
            await locator.wait_for(state="visible", timeout=timeout)
            await locator.click(timeout=timeout)
            return True
        except Exception:
            return False

    async def click_first(self, selectors: Sequence[str], timeout: int = 5000) -> bool:
        """依次尝试选择器，点中第一个可见的。全都不可见返回 False（不抛）。"""
        for selector in selectors or ():
            if not selector:
                continue
            try:
                locator = self.page.locator(selector).first
                await locator.wait_for(state="visible", timeout=timeout)
                await locator.click(timeout=timeout)
                return True
            except Exception:
                continue
        return False

    async def text_of(self, selector: str, timeout: int = 3000) -> str:
        try:
            locator = self.page.locator(selector).first
            await locator.wait_for(state="visible", timeout=timeout)
            return str(await locator.inner_text() or "").strip()
        except Exception:
            return ""

    async def fill_first(self, selectors: Sequence[str], value: str, timeout: int = 5000) -> bool:
        for selector in selectors or ():
            if not selector:
                continue
            try:
                locator = self.page.locator(selector).first
                await locator.wait_for(state="visible", timeout=timeout)
                await locator.fill(value)
                return True
            except Exception:
                continue
        return False

    async def body_text(self) -> str:
        try:
            return str(await self.page.inner_text("body") or "")
        except Exception:
            return ""

    # ── 证据 ──
    async def screenshot(self, name: str, *, target: Any = None) -> str:
        return await self.lease.screenshot(name, target=target, page=self.page)

    def log(self, message: str, /, **fields: Any) -> None:
        self.ctx.log(message, **fields)

    # ── 解算 ──
    async def solve(self, solver_id: str, /, **kwargs: Any) -> Any:
        kwargs.setdefault("page", self.page)
        return await self.ctx.solve(solver_id, **kwargs)

    @staticmethod
    def parse_quota(text: Any) -> float | None:
        """兼容旧脚本的名字；实现见模块级 ``parse_amount``。"""
        return parse_amount(text)

    # ── 结果构造 ──
    # 这几个方法是 ``sdk`` 顶层构造器的便利包装：把「金额」这类最常见的自定义文本
    # 一次填好，省得每个脚本自己拼 DisplaySpec。想要完全自定义的展示，直接用
    # ``ok(...).with_display(DisplaySpec(...))`` 即可，这里不是唯一入口。
    def success(self, message: str, detail: Any = None, **kwargs: Any) -> Any:
        from core.outcome import success

        return self._result(success, message, detail, **kwargs)

    def already_done(self, message: str, detail: Any = None, **kwargs: Any) -> Any:
        from core.outcome import already_done

        return self._result(already_done, message, detail, **kwargs)

    def need_login(self, message: str, detail: Any = None, **kwargs: Any) -> Any:
        from core.outcome import need_login

        return self._result(need_login, message, detail, **kwargs)

    def need_verification(self, message: str, detail: Any = None, **kwargs: Any) -> Any:
        from core.outcome import need_verification

        return self._result(need_verification, message, detail, **kwargs)

    def need_config(self, message: str, detail: Any = None, **kwargs: Any) -> Any:
        from core.outcome import need_config

        return self._result(need_config, message, detail, **kwargs)

    def not_open(self, message: str, detail: Any = None, **kwargs: Any) -> Any:
        from core.outcome import no_effect

        return self._result(no_effect, message, detail, **kwargs)

    def error(self, message: str, detail: Any = None, **kwargs: Any) -> Any:
        from core.outcome import failed

        return self._result(failed, message, detail, **kwargs)

    def _result(
        self,
        factory: Any,
        message: str,
        detail: Any = None,
        *,
        quota: Any = None,
        awarded: Any = None,
        text: str | None = None,
        text_label: str = "",
        extras: Sequence[tuple[str, str]] = (),
        **_ignored: Any,
    ) -> Any:
        """组装结论。

        ``quota`` / ``awarded`` 是「站点展示的金额」的便利入口：它们会被格式化成
        自定义文本与「获得」附加项，同时原值进 ``data`` 供结果文件保留。
        ``_ignored`` 吸收旧脚本传的 ``quota_is_usd`` 之类参数——那时额度是框架概念，
        现在由模板自己决定怎么展示，这个开关已无处安放。
        """
        from core.outcome import DisplaySpec

        data: dict[str, Any] = {}
        if isinstance(detail, dict):
            data.update(detail)
        elif detail is not None:
            data["detail"] = detail

        display_text = text
        if display_text is None and quota is not None:
            value = parse_amount(quota)
            if value is not None:
                display_text = _money(value)
                data.setdefault("balance", value)
        pairs = list(extras)
        if awarded is not None:
            gained = parse_amount(awarded)
            # 0 视为「站点没回具体数值」而不是「获得 0」：展示成「获得 $0.0000」
            # 既不是事实，也让用户以为任务出了问题。
            if gained is not None and abs(gained) > 0:
                pairs.append(("获得", _money(gained)))
                data.setdefault("awarded", gained)

        outcome = factory(message, data=data)
        if display_text or pairs:
            outcome = outcome.with_display(
                DisplaySpec(
                    text=display_text or "",
                    text_label=text_label or ("额度" if display_text else ""),
                    extras=tuple(pairs),
                )
            )
        return outcome


def _money(value: float) -> str:
    return f"${value:.2f}" if abs(value) >= 0.01 else f"${value:.4f}"
