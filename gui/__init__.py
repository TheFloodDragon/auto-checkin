"""DailyTask v3 工作台。

core/config_store 管理原始配置草稿；widgets/dialogs 提供账号与多任务编辑器；
worker/workers 承接隔离执行与异步存储；status_store 独立保存逐任务结果；
app 只负责装配、状态协调和用户交互，theme 不含站点业务知识。
"""
