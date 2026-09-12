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


def test_browser_worker_passes_credentials():
    """验证 BrowserWorker 正确传递账密参数。"""
    import ast
    
    with open("gui/workers.py", encoding="utf-8") as f:
        tree = ast.parse(f.read())
    
    # 查找 capture_login 调用
    found_call = False
    has_email = False
    has_password = False
    
    class CallVisitor(ast.NodeVisitor):
        def visit_Call(self, node):
            nonlocal found_call, has_email, has_password
            if isinstance(node.func, ast.Attribute) and node.func.attr == "capture_login":
                found_call = True
                for keyword in node.keywords:
                    if keyword.arg == "email":
                        has_email = True
                    elif keyword.arg == "password":
                        has_password = True
            self.generic_visit(node)
    
    CallVisitor().visit(tree)
    
    assert found_call, "应找到 capture_login 调用"
    assert has_email, "capture_login 调用应包含 email 参数"
    assert has_password, "capture_login 调用应包含 password 参数"
    
    print("✓ BrowserWorker 正确传递账密参数")


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
    test_browser_worker_passes_credentials()
    test_auto_login_logic_exists()
    print("\n所有测试通过 ✓")
