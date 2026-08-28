"""模板：内置 newapi/sub2api 与用户模板、自定义脚本共用同一注册表。"""

from __future__ import annotations

from .registry import (
    REGISTRY,
    LoadedTemplate,
    TemplateRegistry,
    get,
    ids,
    manifest_from_mapping,
    resolve_repo_path,
)

__all__ = [
    "REGISTRY",
    "LoadedTemplate",
    "TemplateRegistry",
    "get",
    "ids",
    "manifest_from_mapping",
    "resolve_repo_path",
]
