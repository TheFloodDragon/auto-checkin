#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""账密自动登录功能测试。"""

import sys
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))


def test_capture_sub2api_login_signature():
    """验证 capture_login 函数签名包含 email 和 password 参数。"""
    from templates.builtin import sub2api_browser
    import inspect
    
    sig = inspect.signature(sub2api_browser.capture_login)
    params = list(sig.parameters.keys())
    
    assert "email" in params, "capture_login 应包含 email 参数"
    assert "password" in params, "capture_login 应包含 password 参数"
    assert sig.parameters["email"].default == "", "email 默认值应为空字符串"
    assert sig.parameters["password"].default == "", "password 默认值应为空字符串"
    
    print("✓ capture_login 函数签名验证通过")


def test_gui_worker_preserves_login_argument_group():
    """新版 GUI 通过 v3 login.args 交给统一引擎，不再自行调用站点登录实现。"""
    from gui.worker import _account_request

    arguments = {"email": "test@example.invalid", "password": "offline-password", "future": {"keep": True}}
    request = {"account": {
        "id": "password-site", "base_url": "https://example.invalid", "template": "sub2api",
        "login": {"method": "password", "args": arguments}, "tasks": [{"id": "daily"}],
    }}
    account, selected = _account_request(request)

    assert account.login.method == "password"
    assert dict(account.login.args) == arguments
    assert selected == ("daily",)
    assert request["account"]["login"]["args"] == arguments


def test_auto_login_logic_exists():
    """验证自动登录逻辑存在于 capture_login 中。"""
    with open("templates/builtin/sub2api_browser.py", encoding="utf-8") as f:
        content = f.read()
    
    # 检查关键逻辑片段
    assert "auto_login = bool(email and password)" in content, "应包含自动登录判断逻辑"
    assert "填写登录表单" in content, "应包含填写表单的日志"
    assert "自动账密登录" in content, "应包含自动登录模式提示"
    assert "input[type=\"email\"]" in content or "input[type='email']" in content, "应包含邮箱输入框选择器"
    assert "input[type=\"password\"]" in content or "input[type='password']" in content, "应包含密码输入框选择器"
    
    print("✓ capture_login 包含自动登录逻辑")


if __name__ == "__main__":
    test_capture_sub2api_login_signature()
    test_gui_worker_preserves_login_argument_group()
    test_auto_login_logic_exists()
    print("\n所有测试通过 ✓")
