# dailytask

**站点无关的每日任务执行框架。** 签到只是其中一种任务——抽奖、答题、访问保活、领积分
在这里是同一件事：*每天在某个站点上完成一次某个动作，并给出一个明确的结论。*

优先走纯 HTTP；只有在 Token 续期、OAuth 回跳、Cloudflare / 阿里云 WAF 或页面交互确实
需要时，才启动 Camoufox 浏览器。

- **广义任务**：一个账号可以有多个任务，任务之间可声明依赖，共享一次登录与一次浏览器启动
- **模板化站点**：`newapi` / `sub2api` 是**内置模板**，与你自己写的模板完全同级，都能自由创建
- **强可控的流程**：七个阶段逐个可配——自动探测、固定某一种、给一个优先序、或整个关掉
- **执行即学习**：真正跑通的那条路径被记住，下次直接命中；配置一变自动失效
- **统一解算**：图形验证码、Turnstile、hCaptcha、Cloudflare、阿里云 WAF 一个入口 `ctx.solve()`
- **规范化结论**：四个基准结果（成功 / 已完成 / 失败 / 无影响）+ 自由子结果 + 自定义文本列
- 图形管理界面、GitHub Actions 定时执行与脱敏报告

> [!WARNING]
> `ACCOUNTS.json`、OAuth 登录态、`browser_state`、Token 和 Cookie 都属于敏感凭据。
> 它们已被 `.gitignore` 忽略，但仍应只保存在本机或 GitHub Secret 中，切勿提交、截图或公开转发。

---

## 1. 快速开始

```bash
# 依赖（Python ≥ 3.11，推荐 uv）
uv sync                      # 基础运行环境
uv sync --extra gui          # 额外装图形界面
uv sync --extra dev          # 额外装测试工具

# 需要浏览器的任务，首次运行前执行一次
uv run python -m camoufox fetch

# 配置
cp ACCOUNTS.example.json ACCOUNTS.json
```

跑起来：

```bash
uv run python run.py                             # 批量：全部启用账号
uv run python -m apps.cli --account example-newapi   # 单账号，看完整过程
uv run python -m apps.cli --account example-newapi --explain   # 不执行，只解释会怎么跑
uv run python manage.py                          # 图形管理界面
```

Windows 可直接双击 `run.bat`。

旧版 `ACCOUNTS.json`（v1 / v2）会在首次读取时**自动迁移**到 v3：迁移前留一份
`.bak-v2-<时间戳>` 备份，逐条打印「哪个字段搬到了哪」，并把运行期缓存重挂到新的账号 id
上——不会因为迁移丢掉已缓存的 token 与登录态。

---

## 2. 图形界面

```bash
uv sync --extra gui
uv run python manage.py
```

提供：账号增删改查、从剪贴板导入（配合 `collector.js`）、捕获站点登录态与共享 OAuth
登录态、检测登录态是否仍有效、**测试运行单个账号**、导出最小化 GitHub Secret。

界面里的「测试运行」与批量执行走的是**同一个引擎**，只是前者在进程内、后者在子进程——
两条路的行为因此不会分叉（旧实现各拼一份运行参数，长期不一致）。

---

## 3. 配置模型

一份配置 = 若干个**账号**。一个账号 = 一个站点身份 + 若干个**任务**。

```jsonc
{
  "version": 3,
  "accounts": [
    {
      "id": "jisudeng",                         // 稳定身份：缓存、历史结果、状态都挂在它上面
      "name": "极速蹬",
      "base_url": "https://jsd.example.com",
      "template": "scripts/tasks/jisudeng.py",  // 内置模板 id，或仓库内模板路径
      "enabled": true,

      "login": {                                 // 怎么拿到已认证会话
        "method": "oauth",                       // 留空 = auto（按模板优先序自动试）
        "provider": "linuxdo",
        "fallback": [                            // 主方式失败后依次尝试
          { "method": "password", "args": { "email_env": "JSD_EMAIL", "password_env": "JSD_PASSWORD" } }
        ]
      },

      "tasks": [                                 // 一个账号可以有多个任务
        { "id": "daily", "method": "script", "title": "每日签到" },
        { "id": "quiz",  "method": "script", "title": "每日答题", "depends_on": ["daily"] }
      ],

      "flow": { "verification": "auto" },        // 逐阶段控制，见 §4
      "credentials": { "access_token": "...", "refresh_token": "..." },
      "network": {                               // 代理方式见 §11
        "proxy_mode": "group", "proxy_group": "residential",
        "verify_ssl": true, "referer_path": "/profile"
      },
      "policy": { "tolerate_failure": false, "allow_browser": true, "headless": null },
      "display": { "text_label": "额度" }        // 自定义文本列的表头
    }
  ],
  "proxy_groups": [                             // 顶层共享：多个账号引用同一组节点
    {
      "id": "residential", "name": "住宅节点", "enabled": true,
      "selected": "hk",                          // 手动选定的当前出口，不自动轮换
      "proxies": [
        { "id": "hk", "name": "香港", "url": "http://user:pass@127.0.0.1:7897", "enabled": true },
        { "id": "jp", "name": "东京", "url": "socks5://127.0.0.1:1080", "enabled": false }
      ]
    }
  ],
  "default_proxy_group": "",                    // 非空时作为 inherit 账号的默认出口
  "oauth_states": { "linuxdo": { "accounts": { "default": { "state": "..." } } } }
}
```

**解析器不认识的键会原样保留并写回。** 你手写的注释键、未来版本的新字段，都不会因为
被界面保存一次而消失。

### 登录方式（`login.method`）

| 方式 | 说明 | 需要浏览器 |
|---|---|---:|
| `access_token` | 用配置/缓存里现成的 Bearer Token | 否 |
| `cookie` | 用配置/缓存里现成的 Cookie | 否 |
| `refresh` | 用 refresh_token 纯 HTTP 续期 | 否 |
| `password` | 纯 HTTP 账密登录换新 Token（站点未启 Turnstile 时可行） | 否 |
| `browser_state` | 恢复浏览器登录态快照，并从中派生可用于 HTTP 的认证 | 是 |
| `oauth` | 用共享 OAuth 登录态（Linux.do / GitHub）完成站点回跳 | 是 |

留空即 `auto`：按模板声明的优先序依次尝试，**第一个成功的会被记住**，下次直接命中。

### 任务方式（`task.method`）

| 方式 | 说明 | 需要浏览器 |
|---|---|---:|
| `http_api` | 调站点接口。模板有 `run()` 就用它，只有声明式端点时走通用驱动 | 否 |
| `script` | 模板自管流程。可以先纯 HTTP、走不通再自己开浏览器 | 按需 |
| `browser_flow` | 模板自管流程，且**必然**需要浏览器（引擎会提前检查能力） | 是 |
| `visit` | 访问保活：发一次已认证请求并记下今天访问过 | 否 |
| `relogin` | 重放一次 OAuth 登录触发发放，比较前后数值 | 是 |

---

## 4. 流程控制（`flow`）

七个阶段 —— `login` / `prepare` / `detect` / `execute` / `verification` / `confirm` / `render`
—— 每个都可以独立配置：

| 写法 | 含义 |
|---|---|
| 不写 / `"auto"` | 自动探测；**上次跑通的结论优先复用**，连续失败或配置变更后重新探测 |
| `"refresh"` | 固定这一种。失败就失败，**绝不自行扩大候选** |
| `["access_token", "refresh"]` | 只在这个优先序内降级，列表外的方式不会被尝试 |
| `"off"` | 关掉该阶段（如 `execute: off` 就是只读查询） |

```jsonc
"flow": {
  "login": ["access_token", "refresh"],  // 只在这两种之间降级
  "verification": "turnstile",           // 直接上 Turnstile，不做机制探测
  "detect": "off",                       // 不做端点探测（站点端点已固定）
  "confirm": "auto"                      // 其余阶段保持自动
}
```

「本次会怎么跑」可以直接问：

```bash
uv run python -m apps.cli --account jisudeng --explain
```

它会打印每个阶段的候选与来源（配置 / 学到的 / 模板默认），以及覆盖层对每个凭据字段的
取用判据——「为什么没用缓存的 token」不再需要读源码。

---

## 5. 运行期覆盖层

**配置文件在运行期只读。** 刷新到的 token、浏览器登录态、探测到的流程、模板学到的
数据，全部进 `.cache-checkin/overlay.json`，永不回写 `ACCOUNTS.json`。

取值优先级：

1. **调用方显式提供的值**永远赢（含显式清空）——界面里刚清空一个 token 就该立刻生效
2. 覆盖层的值只有在**配置摘要仍然一致**时才采用；用户改过配置就自动不采用
3. 有 TTL 的字段过期即失效（access_token 默认 12 小时，登录态 14 天）
4. 缓存写入之后你动过 `ACCOUNTS.json` 的，以配置为准
5. 其余情况用覆盖层的值

**只判定，不删除。** 删除不可逆——改错又改回来、只是改名或重排，本来仍然有效的登录态
就永久丢了。

---

## 6. 结论模型

四个**基准结果**，聚合、退出码与重试判定只看它：

| 基准 | 含义 | 计失败 |
|---|---|---:|
| `success` | 本次确实完成并产生效果 | 否 |
| `already_done` | 今日此前已完成 | 否 |
| `no_effect` | 站点未开放 / 任务不适用 / 已豁免 | 否 |
| `failed` | 失败 | 是 |

**子结果（`reason`）是自由字符串**：`need_login`、`need_verification`、`need_config`、
`network_error`、`blocked`、`unconfirmed`、`not_open`、`not_applicable` 是内置的，
模板可以现场注册自己的，未注册的 slug 也不会报错——回落基准标签并原样保留。

**「额度」不是框架概念。** 展示统一为「自定义文本」：`newapi` / `sub2api` 模板往里填
余额（表头「额度」），抽奖模板填奖品名，不支持的任务留空。三级优先级：内置默认 ←
模板 `render()` ← 结论自带的 `display`（脚本要改就该改得动）。

---

## 7. 写一个模板

模板与内置模板同级。两种写法：

> Lucky 福利站例外：账号的 `base_url` 仍填写主站 `https://new.lucky0625.qzz.io`，并显式使用
> `scripts/tasks/lucky_welfare.py`。签到请求会在模板内部发往固定的
> `https://fuli.lucky0625.qzz.io`；主站 Bearer/Cookie 不会直接发送到福利站。首次运行需用同一个
> LinuxDO 账号完成福利站与主站的绑定，已有福利站 Cookie 时先走 API，失败才启用浏览器回退。

### 声明式（TOML，不写 Python）

放进 `templates/user/my_site.toml`：

```toml
id = "my_site"
title = "我的站点"

[[login]]
method = "access_token"

[[task]]
method = "http_api"

[endpoints]
state  = "/api/checkin/status"
submit = "/api/checkin"
user   = "/api/me"

[response]
checked_in = ["checked_in_today"]
awarded    = ["reward", "amount"]
balance    = ["balance"]
unit       = "usd"          # raw | usd | quota_500000
```

`[response]` 是关键：没有它，通用驱动读不懂响应，也就无法判断任务是否成立——
这正是「显示成功但没到账」的成因，所以缺它会**明确报错**而不是猜。

### Python 模板

放进 `scripts/tasks/my_site.py`，配置里 `template` 填这个路径：

```python
from sdk import Outcome, TaskOption, TemplateManifest, ok, done, need_login

MANIFEST = TemplateManifest(
    id="my_site",
    title="我的站点",
    task=(TaskOption("script", owns=frozenset({"detect", "confirm"})),),
)

async def run(ctx) -> Outcome:
    state = ctx.http.get("/api/checkin/status")       # 已注入认证，401 自动续期一次
    if state.get("checked_in_today"):
        return done("今日已完成")

    async with ctx.browser.lease() as lease:          # 惰性：不碰就不启动浏览器
        page = await lease.new_page()
        await lease.goto("/checkin", page=page)
        result = await ctx.solve("hcaptcha", page=page)
        if not result.ok:
            return need_login(f"验证未通过：{result.message}")

    ctx.store.put("last_seen", "...")                 # 缓存进覆盖层，不用自己写文件
    return ok("完成")
```

可用钩子：`run` / `login` / `fetch_state` / `verify` / `confirm` / `render` / `detect`，
全部可选。`extends = "newapi"` 可继承已有模板的登录方式、端点、请求头与响应映射。

上下文 `ctx` 的完整接口面见 [`sdk/context.py`](sdk/context.py)。三条边界：

- **无凭据**：`ctx.account` 是脱敏视图，要用凭据只能通过 `ctx.http` / `ctx.login`
- **无副作用配置**：模板改不了 `ACCOUNTS.json`，运行期产物一律经覆盖层
- **无隐式浏览器**：`ctx.browser` 不被访问就一次都不启动

---

## 8. 内置模板

| 模板 | 站点族 | 说明 |
|---|---|---|
| `newapi` | New API 系 | 接口签到 + 内置验证路由（Turnstile / 点阵码 / 字符码 / 点选） |
| `sub2api` | Sub2API 系 | 端点方言自动探测并记住，token/refresh/账密多级降级 |
| `scripts/tasks/100xlabs.py` | 百倍实验室 | 纯 HTTP 优先，走不通再开浏览器点按钮 |
| `scripts/tasks/jisudeng.py` | 极速蹬 | 签到 + 每日答题（题库跨账号自学习） |
| `scripts/tasks/sotamodel.py` | SOTA Model | 继承 `newapi`，签到搬到独立端点 |
| `scripts/tasks/vcnovb_lottery.py` | VC API | 幸运轮盘，自定义文本列展示奖品 |
| `scripts/tasks/fengwind_welfare.py` | Fengwind 福利站 | LinuxDO → 主站 → 福利站双层 SSO |
| `scripts/tasks/abrdns_welfare.py` | ABR 福利站 | 表单签到 + hCaptcha 视觉求解 |
| `scripts/tasks/lucky_welfare.py` | Lucky 福利站 | 福利站 API 优先，浏览器签到按钮兜底；主站与福利站 Cookie 隔离 |

---

## 9. 凭据采集与登录态

**`collector.js`**：在已登录的站点页面按 F12，把文件内容粘进控制台执行。它会探测站点族、
认证方式与签到端点，直接输出一个 **v3 账号对象**，可以粘进 `ACCOUNTS.json` 的 `accounts`
数组，或在管理界面里「从剪贴板导入」。

**共享 OAuth 登录态**（一份登录态供多个站点复用）：

```bash
uv run python -m browser.poc_oauth setup --provider linuxdo
uv run python -m browser.poc_oauth setup --provider github
uv run python -m browser.poc_oauth run --base-url https://example.org   # 验证
```

也可以在管理界面里点「捕获 OAuth 登录态」。

---

## 10. 命令一览

```bash
python run.py                                  # 批量：全部启用账号
python run.py --retry-failed                   # 沿用当天已完成的结果，只跑没完成的
python run.py --account jisudeng --account x    # 只跑指定账号
python run.py --workers 4 --verbose

python -m apps.cli --account jisudeng           # 单账号
python -m apps.cli --account jisudeng --task quiz   # 只跑某个任务
python -m apps.cli --account jisudeng --explain     # 只解释，不执行
python -m apps.cli --account jisudeng --worker      # 机器协议：stdout 只有结果 JSON
python -m apps.cli --list                       # 列出账号
python -m apps.cli --export-secret              # 打印最小化 GitHub Secret
python -m apps.cli --requires browser           # 本次配置是否需要浏览器

python manage.py                                # 图形界面
```

诊断输出一律走 **stderr**（结构化事件行 `@checkin-event {...}`），stdout 在 worker 模式下
只有结果 JSON。批量层会把事件解析成人读的「调用日志」，成功任务也会打印——判断
「走了纯 API 还是退化到开浏览器」不用再翻源码。

---

## 11. 代理、WAF 与验证

**代理**：账号的 `network.proxy_mode` 有四种取值，互斥且不省略：

| 方式 | 含义 |
|---|---|
| `inherit`（默认） | 用 `default_proxy_group`；没设默认组就回退全局 `CHECKIN_PROXY`，都没有则直连 |
| `direct` | 明确直连。**不会**再回退 `CHECKIN_PROXY`——「这个站点必须走本机出口」要能表达 |
| `custom` | 用本账号的 `network.proxy` 单个 URL |
| `group` | 用 `network.proxy_group` 指定的**代理组**里当前选中的那个节点 |

不写 `proxy_mode` 时按旧字段推断（填了 `proxy` 即 `custom`，否则 `inherit`），所以既有
配置不需要改动。

**代理组**是顶层 `proxy_groups`：一组节点 + 一个手动选定的 `selected`。多个账号引用同一
组，换出口只改组里的选择，不用逐个账号改。**组不会自动测速或故障切换**：节点是否可用只
有真跑一次才知道，静默换节点会让「为什么今天出口变了」无从追查。组为空、已停用、未选节
点或当前节点被停用时，引用它的账号**报配置错误**，不会悄悄降级成直连——直连意味着用你的
真实 IP 去访问一个你明确要求走代理的站点。

同一次账号执行内，出口在开始时解析一次并冻结：登录、各个任务、浏览器共用同一个节点，
中途刷新 token 也不会换出口。

HTTP 层只支持 `http/https`（标准库限制），浏览器流程可用 `socks5`；选了 SOCKS5 节点时
界面会标明「仅浏览器」。没配代理时会显式禁用进程环境里的隐式代理——否则会出现「本机能跑、
CI 走了别的出口」，而出口 IP 恰恰决定会不会被风控。

界面里代理有独立的「代理」页：新建/编辑/删除组、组内增删节点、启停、排序、指定当前节点。
仍被账号或默认组引用的组不能删除，会列出引用方让你先改绑。所有改动都进草稿，保存后才落
盘。账号「基本信息」页选代理方式，状态行显示最终出口，但只反映**配置**是否可用，不代表已
检测连通性。导出 Secret 只带启用账号真正引用到的组。

**Cloudflare**：拦截页与挑战页被严格区分。挑战页值得开浏览器；拦截页（`error 1020` /
「Sorry, you have been blocked」）是安全规则对当前出口 IP 的终局拒绝，浏览器同样过不去，
结论会直接告诉你 Ray ID 与站点回显的出口 IP，让你去换节点而不是反复重试。

**验证码**：统一入口 `ctx.solve(...)`，注册表见 [`solvers/`](solvers/)：

| id | 说明 | 依赖 |
|---|---|---|
| `image:newapi_bitmap` / `image:string_captcha` / `image:click_shape` | 离线识别 | numpy / pillow / opencv |
| `turnstile` | 页面上已有的 Turnstile 挂件，点一次 | 浏览器 |
| `turnstile:inject` | 按 sitekey 注入挂件铸造令牌，交给 HTTP 层提交 | 浏览器 |
| `hcaptcha` | 视觉模型作答 | 浏览器 + 视觉模型配置 |
| `cloudflare` / `aliyun_waf` | 防护页求解 | 浏览器 |

---

## 12. GitHub Actions

1. 在仓库 Secret 里配置 `ACCOUNTS`（用管理界面的「导出 GitHub Secret」生成最小化配置）
2. 工作流自动判断是否需要浏览器（`python -m ci.detect_browser`，判据来自模板真正声明的
   `requires`，比按配置字段猜准确），按需安装 Camoufox
3. 执行结束后生成脱敏 Markdown 报告到 Job Summary

可选 Secret：`CHECKIN_PROXY`（住宅代理）、`HCAPTCHA_VISION_CONFIG` 或 `OPENAI_API_KEY`
（hCaptcha 视觉求解）。

---

## 13. 排查

| 现象 | 先看这里 |
|---|---|
| 不知道会怎么跑 | `python -m apps.cli --account <id> --explain` |
| 「为什么没用缓存的 token」 | `--explain` 输出里的 `overlay` 段，逐字段给出判据 |
| 「走了哪条路」 | 批量输出的「调用日志」，或 stderr 的 `@checkin-event` 行 |
| 结果未确认 | 结论 `reason=unconfirmed`：接口回了 2xx 但没有任何成立证据，交叉验证也没过 |
| 出口 IP 被拒 | 结论 `reason=blocked`：换代理节点，重试与开浏览器都无效 |
| 需要人机验证 | 结论 `reason=need_verification`：日志里有失败阶段与截图路径 |

结果文件：`.cache-checkin/checkin_result.json`（`schema_version: 2`）。

---

## 14. 安全设计

- 凭据只存在 `ACCOUNTS.json`、GitHub Secret 与运行期覆盖层，**绝不进 argv**（命令行对
  同机其它用户可见）
- 子进程不继承任何凭据类环境变量：子进程自己读配置，父进程不再透传
- 模板拿到的账号视图**不含任何凭据**，要用凭据只能通过已注入认证的 `ctx.http`
- Lucky 福利站使用独立同源 Cookie 客户端；主站 `Authorization`、主站 Cookie 和 `New-Api-User` 不会跨站转发
- 日志、结果文件与界面快照统一经 `core.masking` 脱敏
- 模板只能是仓库内相对路径的 `.py` / `.toml`，拒绝 URL、绝对路径与 `..`
- 用户把凭据放在单独文件里（`credentials.cookie_file`）时，保存不会把展开后的明文写回配置

---

## 15. 开发

```bash
uv run pytest -q          # 472 项测试
uv run ruff check .       # 静态检查
```

目录结构（仓库根目录就是项目根，各子包是顶层包）：

```
core/        领域内核：结论模型、账号模型、流程计划、清单契约、时间、脱敏（零 IO）
config/      配置读写、运行期覆盖层、迁移、Secret 导出、全局可调参数
net/         HTTP 客户端与防护页判别
login/       登录方式插件 + 候选链经纪人
task/        任务方式插件
templates/   模板注册表 + 内置模板（builtin/）+ 用户模板（user/）
solvers/     统一解算注册表（图形 / Turnstile / hCaptcha / WAF / 视觉）
browser/     浏览器：算法（Camoufox、WAF、验证码、OAuth）+ 调度（惰性租约）
runtime/     阶段编排、探测、预算、能力、事件、批量分组
sdk/         模板与脚本的唯一稳定契约
apps/        进程入口：单账号 worker / 批量调度
captcha_ocr/ 离线验证码识别
scripts/tasks/  站点模板
gui/         图形管理界面
ci/          CI 辅助：浏览器需求探测、脱敏报告
```

---

## License

见 [LICENSE](LICENSE)。
