"""用户模板目录。

放 ``.py``（带 ``MANIFEST`` 与钩子）或 ``.toml``（纯声明式）即可被自动发现，
文件名（去扩展名）就是模板 id。以 ``_`` 开头的文件会被忽略。

声明式示例（``my_fork.toml``）：

    id      = "my_fork"
    title   = "某 New API 私改站"
    extends = "newapi"

    [endpoints]
    checkin = "/api/user/daily-bonus"

    [[login]]
    method = "access_token"

    [display]
    text_label = "额度"
"""
