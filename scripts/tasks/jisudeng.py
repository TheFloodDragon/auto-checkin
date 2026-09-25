#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""极速蹬（jisudeng.com）每日签到 + 每日答题 browser_script。

该站点是 Sub2API 系（Vue SPA + Cloudflare Turnstile 登录），与百倍
（100xlabs）同构，因此签到的共享逻辑集中在 scripts/checkin/_sub2api_common.py，
本文件声明站点差异（签到端点、按钮文案、截图前缀等）并串起主流程。

站点特征：
- 可签到按钮：立即签到
- 已签到状态：今日已签到
- 签到接口：POST /api/v1/play/checkin（补签 /makeup 需排除）
- 每日答题：GET/POST /api/v1/play/quiz/{today,submit}（本文件下半部分）

登录态优先复用 browser_state，过期时用 localStorage 的 refresh_token 刷新；
refresh_token 也失效时，可用 script_args 或环境变量中的邮箱密码在真实登录页
完成登录（只消费 Cloudflare 正常签发的 Turnstile 令牌，不伪造、不绕过）。
凭据不会写入账号配置、脚本结果或日志。

答题（题库、判定、两种传输）**全部收在本文件**：它只属于这个站点，散到仓库根或
providers 里会让「一个站点的特殊玩法」污染通用层，也让人找不到题库在哪。
通用层只提供两个钩子：``run``（浏览器）与 ``run_http_extras``（纯 HTTP）。
"""

from __future__ import annotations

import re
import sys
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

# 模板由 spec_from_file_location 加载，父目录不在 sys.path 上，
# 因此显式加入后再导入同目录的共享流程。
_HERE = Path(__file__).resolve().parent          # scripts/tasks
_REPO_ROOT = _HERE.parents[1]                    # 仓库根
for _path in (_HERE, _REPO_ROOT):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import _sub2api_flow as common  # noqa: E402

from core.timebase import utc_iso  # noqa: E402
from sdk import (  # noqa: E402
    ArgSchema,
    ArgSpec,
    ChainStep,
    DisplayDefaults,
    LoginOption,
    Outcome,
    PageHelpers,
    TaskOption,
    TemplateManifest,
)

#: 答题题库与未收录题面的存放处。
#:
#: 这是**跨账号共享**的：题目属于站点，不属于某个账号，同一道题在 A 账号学到的
#: 答案对 B 账号一样有效。旧实现直接往 ``.cache-checkin/play_quiz_learned.json``
#: 写文件，绕过了所有缓存治理（无版本、无失效、无并发保护）；现在走 SDK 的
#: SharedStore，由覆盖层统一管理。run() 在开始时绑定，模块级是因为题库本身与
#: 账号无关。
_BANK: Any = None

SPEC = common.SiteSpec(
    site_label="极速蹬",
    checkin_path="/api/v1/play/checkin",
    status_path="/api/v1/play/checkin/status",
    login_reset_sentinel="__jsd_login_reset",
    screenshot_prefix="jisudeng",
    default_start_path="/check-in",
    email_env="JISUDENG_EMAIL",
    password_env="JISUDENG_PASSWORD",
    checkin_texts=("立即签到",),
    already_texts=("今日已签到", "已签到"),
    success_texts=("已到账", "签到成功"),
    response_match=("/play/checkin",),
    # /play/checkin/makeup 是补签接口，监听签到响应时必须排除。
    response_exclude=("/play/checkin/makeup",),
    # 极速蹬的已签到文案都足够具体，无需弱文案特例。
    weak_already_texts=(),
    success_message="极速蹬签到成功",
    # 极速蹬历史上统一用 already_state 表达「已签到」信号，保持不变。
    signal_already_control="already_state",
    signal_already_text="already_state",
    signal_post_click_text="already_state",
)

# ══════════════════════════ 每日答题（Quiz Quest）══════════════════════════
#
# 接口（实测）：
#     GET  /api/v1/play/quiz/today
#          → data{enabled, coupon_pool_ready, questions:[{id, prompt, options[]}],
#                 already_submitted, reward_per_correct, server_date,
#                 previous_score, previous_total, previous_reward, previous_reward_type}
#     POST /api/v1/play/quiz/submit  body {"answers":[{"question_id":N,"choice_index":I}]}
#          → data{score, total, reward_amount, reward_type, coupon?}
#
# 每天一次，重复提交回业务码 PLAY_QUIZ_ALREADY_DONE。答对一题得 reward_per_correct
# （实测 0.1），也可能改发优惠券（此时 reward_amount 为 0）。

API_PREFIX = "/api/v1"
# 相对 API 前缀的路由（纯 HTTP 客户端自带前缀）与完整路径（页内 fetch 直接用）。
QUIZ_TODAY_ROUTE = "/play/quiz/today"
QUIZ_SUBMIT_ROUTE = "/play/quiz/submit"
QUIZ_TODAY_PATH = API_PREFIX + QUIZ_TODAY_ROUTE
QUIZ_SUBMIT_PATH = API_PREFIX + QUIZ_SUBMIT_ROUTE

#: 共享存储里的两个键（见模块顶部 _BANK 的说明）。
BANK_KEY = "play_quiz_learned"
UNKNOWN_KEY = "play_quiz_unknown"
LEARNED_BANK_VERSION = 1
LEARNED_HISTORY_LIMIT = 20

# 题库：完整题面 → 正确选项原文。
#
# 内置题库仍是最可靠基线；运行期学习题库只吸收可证明的反馈。取题接口不返回答案，
# 提交接口常只给总分：满分/零分可分别证明全部选择正确/错误；部分得分若无逐题明细
# 只能记为 unresolved，绝不能把聚合分数臆测到某一道题上。
#
# 为什么按相似度而不是精确相等匹配：站点的题面和选项都不稳定。实测题面末尾会拼上
# 「（第7题）」这类序号，且同一道题在不同日期序号会变；选项也可能微调标点或措辞
# （「、」改「，」、末尾多一个「里」）。精确匹配一旦对不上就静默退化成瞎猜，而
# 「明明补录过却还在猜」这种症状极难发现。相似度低于阈值的才算新题。
#
# 三个刻意的设计选择：
# 1. 用完整题面而不是题目 id 作键：id 只是题库主键，站点改题库时可能复用；完整题面
#    自解释，人工补录时照抄日志即可，也不必先查 id。
# 2. 值存正确选项的原文而不是下标：选项顺序由服务端给出、不保证跨天一致，存下标
#    一旦顺序变化就会答错，且错得毫无征兆。
# 3. 相似度不足、或最相似的两条咬得太紧时，一律**当作新题**去猜并记录，而不是挑
#    一个凑：挑错和瞎猜的期望收益一样，却会让人误以为题库已经覆盖。
ANSWERS: dict[str, str] = {
    "Which HTTP method is typically used to send a chat completion request?": "POST",
    "Which field usually carries the user message in an OpenAI-style chat request?": "messages",
    "What is a common purpose of an API gateway?":
        "Route, authenticate, and meter upstream API traffic",
    "Why do providers cache prompt prefixes?":
        "To reduce latency and cost for repeated context",
    "What does RPM commonly limit?": "Requests per minute",
    "以下哪项属于客户端应避免的行为": "把密钥硬编码到前端公开代码",
    "流式输出（streaming）最主要的用户价值是": "首字节更快、边生成边展示",
    "幂等键（Idempotency-Key）的主要作用是": "防止重试造成重复扣费或重复创建",
    "在生产环境中处理超时，推荐做法是": "设置超时并做有限重试",
    "提示词前缀缓存（Prompt Cache）的主要收益是": "提高重复上下文请求的速度并降低成本",
    "运营判断题库质量最应该看什么": "参与率、正确率、复玩率和转化率",
    "管理员清理无效赠送余额前应先做什么": "筛选目标用户并预览影响",
    "HTTP 429 通常表示什么": "请求过于频繁或触发限流",
    "上下文长度指的是什么": "模型一次可处理的输入输出窗口",
    "对多语言题库最稳妥的实现方式是": "后端按语言返回对应题目",
    # 以下 5 题由实测补录：当日题库未收录，按最长选项启发式作答，提交回执为
    # 5/5（获得 $0.50），因此这些选项已被服务端确认为正确答案。
    "奖池版本的价值是什么": "方便复盘不同配置效果",
    "提交客服反馈时最好提供什么": "错误截图、时间和请求信息",
    "签到失败提示应该包含什么": "失败原因和可操作下一步",
    "API Key 泄露后第一步应该做什么": "立即禁用或重置密钥",
    "请求接口时 Header 里的 Authorization 通常放什么": "访问令牌或 API Key",
}

# 相似度阈值。实测本题库：同一题的各种变体最低 0.867，而**不同题之间**最高只有
# 0.607，两者之间有很宽的空档，因此 0.75 既不会漏掉改写过的老题，也不会把新题
# 硬套到老题上。margin 再要求「最佳比次佳明显更像」，防止题库里出现两条近似条目时
# 随机二选一（实测正确命中的 margin 都在 0.45 以上，留足余量）。
PROMPT_SIMILARITY_MIN = 0.75
PROMPT_SIMILARITY_MARGIN = 0.08
# 选项通常更短，措辞也更容易被整段替换，阈值相应收紧。
OPTION_SIMILARITY_MIN = 0.80
OPTION_SIMILARITY_MARGIN = 0.12
# 覆盖率对短文本会虚高（"post" 与 "options" 能凑出 0.75），短串只用对称 ratio。
_COVERAGE_MIN_LEN = 6


def _norm(text: Any) -> str:
    """归一化文本：小写、压缩空白、去掉首尾标点差异。"""
    return re.sub(r"\s+", " ", str(text or "").strip().lower()).strip(" .?:!")


# 题面末尾的题号：实测站点把「（第7题）」直接拼进 prompt，同一道题在不同日期
# 会拿到不同序号（同一次取题里甚至出现过两个「第6题」）。序号纯属噪声，比较前剥掉。
_PROMPT_INDEX_SUFFIX_RE = re.compile(r"[（(]\s*第\s*\d+\s*题\s*[)）]\s*$")


def _norm_prompt(text: Any) -> str:
    """题面归一化：在 _norm 之上剥掉末尾题号，让同一题的不同序号归一。"""
    return _norm(_PROMPT_INDEX_SUFFIX_RE.sub("", str(text or "").strip()))


def similarity(left: str, right: str) -> float:
    """两段文本的相似度，取「对称 ratio」与「短串覆盖率」的较大值。

    只用 SequenceMatcher.ratio() 不够：站点在题面前后加料（"问题3："、题号）时，
    长度差本身就会把 ratio 拉下来，哪怕整条老题面被完整包含。覆盖率（匹配字符数 /
    短串长度）正好补上这种「包含但更长」的情形。

    覆盖率对短串会虚高，所以短串低于 _COVERAGE_MIN_LEN 时只认 ratio。
    """
    if not left or not right:
        return 0.0
    matcher = SequenceMatcher(None, left, right)
    ratio = matcher.ratio()
    shorter = min(len(left), len(right))
    if shorter < _COVERAGE_MIN_LEN:
        return ratio
    matched = sum(block.size for block in matcher.get_matching_blocks())
    return max(ratio, matched / shorter)


def _best_match(target: str, candidates: list[str], *, minimum: float, margin: float) -> int | None:
    """返回最相似候选的下标；相似度不足或与次佳咬得太紧时返回 None。"""
    if not target or not candidates:
        return None
    scored = sorted(
        ((similarity(target, candidate), index) for index, candidate in enumerate(candidates)),
        reverse=True,
    )
    best, index = scored[0]
    if best < minimum:
        return None
    if len(scored) > 1 and best - scored[1][0] < margin:
        return None
    return index


_ANSWER_ITEMS = tuple(ANSWERS.items())
_ANSWER_PROMPTS = [_norm_prompt(prompt) for prompt, _answer in _ANSWER_ITEMS]


def match_answer(prompt: Any) -> str | None:
    """按相似度找这道题的正确选项原文；判为新题或有歧义时返回 None。"""
    index = _best_match(
        _norm_prompt(prompt),
        _ANSWER_PROMPTS,
        minimum=PROMPT_SIMILARITY_MIN,
        margin=PROMPT_SIMILARITY_MARGIN,
    )
    return None if index is None else _ANSWER_ITEMS[index][1]


def _option_index(options: list[Any], answer: str) -> int | None:
    """在选项里按相似度定位答案；拿不准时返回 None。"""
    return _best_match(
        _norm(answer),
        [_norm(option) for option in options],
        minimum=OPTION_SIMILARITY_MIN,
        margin=OPTION_SIMILARITY_MARGIN,
    )


def _normalize_learning_bank(payload: Any) -> dict[str, Any]:
    """把磁盘学习数据收敛为版本化安全结构，忽略损坏条目。"""
    questions: dict[str, dict[str, Any]] = {}
    raw_questions = payload.get("questions") if isinstance(payload, dict) else None
    if not isinstance(raw_questions, dict):
        return {"version": LEARNED_BANK_VERSION, "questions": questions}
    for raw_key, raw_entry in raw_questions.items():
        if not isinstance(raw_entry, dict):
            continue
        prompt = str(raw_entry.get("prompt") or raw_key or "").strip()
        key = _norm_prompt(prompt)
        if not key:
            continue
        correct_answer = str(raw_entry.get("correct_answer") or "").strip()
        wrong_answers: list[str] = []
        raw_wrong_answers = raw_entry.get("wrong_answers")
        if not isinstance(raw_wrong_answers, list):
            raw_wrong_answers = []
        for value in raw_wrong_answers:
            text = str(value or "").strip()
            if text and _norm(text) not in {_norm(item) for item in wrong_answers}:
                wrong_answers.append(text)
        history: list[dict[str, Any]] = []
        for item in raw_entry.get("history") or []:
            if not isinstance(item, dict):
                continue
            result = str(item.get("result") or "unresolved")
            if result not in {"correct", "incorrect", "unresolved"}:
                result = "unresolved"
            history.append(
                {
                    "choice": str(item.get("choice") or ""),
                    "result": result,
                    "score": item.get("score"),
                    "total": item.get("total"),
                    "submitted_at": str(item.get("submitted_at") or ""),
                }
            )
        questions[key] = {
            "prompt": prompt,
            "correct_answer": correct_answer,
            "wrong_answers": wrong_answers,
            "history": history[-LEARNED_HISTORY_LIMIT:],
            "updated_at": str(raw_entry.get("updated_at") or ""),
        }
    return {"version": LEARNED_BANK_VERSION, "questions": questions}


def load_learning_bank(store: Any = None) -> dict[str, Any]:
    """读取运行期学习题库；缺失或损坏时返回空库。"""
    target = store if store is not None else _BANK
    if target is None:
        return _normalize_learning_bank({})
    return _normalize_learning_bank(target.get(BANK_KEY))


def _learned_key(prompt: Any, bank: dict[str, Any]) -> str | None:
    questions = bank.get("questions")
    if not isinstance(questions, dict) or not questions:
        return None
    normalized = _norm_prompt(prompt)
    if normalized in questions:
        return normalized
    keys = list(questions)
    index = _best_match(
        normalized,
        keys,
        minimum=PROMPT_SIMILARITY_MIN,
        margin=PROMPT_SIMILARITY_MARGIN,
    )
    return keys[index] if index is not None else None


def _learned_entry(prompt: Any, bank: dict[str, Any] | None = None) -> dict[str, Any] | None:
    loaded = bank if bank is not None else load_learning_bank()
    questions = loaded.get("questions")
    key = _learned_key(prompt, loaded)
    entry = questions.get(key) if isinstance(questions, dict) and key else None
    return entry if isinstance(entry, dict) else None


def _option_matches(left: Any, right: Any) -> bool:
    normalized_left, normalized_right = _norm(left), _norm(right)
    return bool(normalized_left and normalized_right) and similarity(normalized_left, normalized_right) >= OPTION_SIMILARITY_MIN


def _answer_is_wrong(answer: Any, wrong_answers: list[Any]) -> bool:
    return any(_option_matches(answer, wrong) for wrong in wrong_answers)


def summary(outcome: str, message: str, **extra: Any) -> dict[str, Any]:
    """统一摘要结构。

    字段名用 outcome 而不是 state：结果会经 mask_utils.sanitize_data 输出，
    而 "state" 命中脱敏词表（browser_state 同名前缀），会被整值替换成 <redacted>。
    """
    return {"outcome": outcome, "message": message, **extra}


def choose_index(question: Any) -> tuple[int, bool]:
    """给一道题选项，优先复用学习题库并排除已确认错误选项。

    返回 (下标, 是否由题库/排除法确定)。既无内置答案、也无足够学习证据时，仍只在
    尚未确认错误的候选中选最长项，并返回 False 让日志明确标记为猜测。
    """
    options = question.get("options") if isinstance(question, dict) else None
    if not isinstance(options, list) or not options:
        return 0, False

    prompt = question.get("prompt")
    learned = _learned_entry(prompt)
    wrong_answers = list(learned.get("wrong_answers") or []) if learned else []
    learned_answer = str(learned.get("correct_answer") or "") if learned else ""
    static_answer = match_answer(prompt) or ""

    # 服务端反馈形成的学习答案优先；若它明确把旧静态答案判错，不再复用陈旧答案。
    candidates = [learned_answer]
    if static_answer and not _answer_is_wrong(static_answer, wrong_answers):
        candidates.append(static_answer)
    for answer in candidates:
        if not answer:
            continue
        index = _option_index(options, answer)
        if index is not None and not _answer_is_wrong(options[index], wrong_answers):
            return index, True

    remaining = [
        index
        for index, option in enumerate(options)
        if not _answer_is_wrong(option, wrong_answers)
    ]
    if len(remaining) == 1:
        return remaining[0], True
    pool = remaining or list(range(len(options)))
    longest = max(pool, key=lambda index: len(str(options[index] or "")))
    return longest, False


def record_unknown(questions: list[dict[str, Any]], store: Any = None) -> None:
    """把未收录的题面记进共享存储，供人工补录题库。写入失败不影响主流程。"""
    if not questions:
        return
    target = store if store is not None else _BANK
    if target is None:
        return
    existing = target.get(UNKNOWN_KEY)
    if not isinstance(existing, list):
        existing = []
    # 去重按剥掉题号后的题面：同一道题换个位置就换个「第N题」，用原文去重会让
    # 同一题堆出好几条，人工补录时反复看到重复题。
    seen = {_norm_prompt(item.get("prompt")) for item in existing if isinstance(item, dict)}
    changed = False
    for item in questions:
        key = _norm_prompt(item.get("prompt"))
        if key and key not in seen:
            seen.add(key)
            existing.append({"prompt": item.get("prompt"), "options": item.get("options")})
            changed = True
    if changed:
        target.put(UNKNOWN_KEY, existing)


def describe_unknown(unknown: list[dict[str, Any]]) -> list[str]:
    """未收录题目的日志行：题面 + 全部选项，并标出这次猜了哪个。

    必须直接打出来。只写进缓存文件的话，用户看日志根本不知道今天有题在猜，
    也就不会去补题库。
    """
    if not unknown:
        return []
    lines = [
        f"答题有 {len(unknown)} 道题题库未能确定答案"
        f"（已按最长选项猜，并记入共享题库的 {UNKNOWN_KEY}）："
    ]
    for question in unknown:
        options = question.get("options") if isinstance(question.get("options"), list) else []
        guess, _known = choose_index(question)
        lines.append(f"  题目：{question.get('prompt')}")
        for index, option in enumerate(options):
            lines.append(f"    [{index}]{'*' if index == guess else ' '} {option}")
    return lines


def plan(data: Any) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]]]:
    """把 /quiz/today 的 data 变成 (提前结论, 待提交答案, 未收录题目)。

    提前结论非空表示不该提交（站点没开、今日已答、没有题目）。
    """
    if not isinstance(data, dict):
        return summary("error", "答题接口返回结构无法识别"), [], []
    if not data.get("enabled"):
        return summary("disabled", "站点未开启答题"), [], []
    if data.get("already_submitted"):
        score, total = data.get("previous_score"), data.get("previous_total")
        return summary("already_done", f"今日答题已完成（{score}/{total}）",
                       score=score, total=total, reward=data.get("previous_reward")), [], []
    questions = data.get("questions")
    if not isinstance(questions, list) or not questions:
        return summary("unavailable", "答题接口未返回题目"), [], []

    answers: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    for question in questions:
        if not isinstance(question, dict):
            continue
        index, known = choose_index(question)
        answers.append({"question_id": question.get("id"), "choice_index": index})
        if not known:
            unknown.append(question)
    return None, answers, unknown


def build_attempts(data: Any, answers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """构造本次选择快照；只含题面/选项，不含任何认证信息。"""
    questions = data.get("questions") if isinstance(data, dict) else None
    valid_questions = [item for item in (questions or []) if isinstance(item, dict)]
    attempts: list[dict[str, Any]] = []
    for question, answer in zip(valid_questions, answers):
        options = question.get("options") if isinstance(question.get("options"), list) else []
        try:
            choice_index = int(answer.get("choice_index", 0))
        except (TypeError, ValueError):
            choice_index = 0
        choice = str(options[choice_index] or "") if 0 <= choice_index < len(options) else ""
        attempts.append(
            {
                "question_id": question.get("id"),
                "prompt": str(question.get("prompt") or ""),
                "options": [str(option or "") for option in options],
                "choice_index": choice_index,
                "choice": choice,
            }
        )
    return attempts


def _result_verdict(item: dict[str, Any]) -> bool | None:
    for key in ("correct", "is_correct", "isCorrect", "was_correct"):
        if key not in item:
            continue
        value = item.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return bool(value)
        text = str(value or "").strip().lower()
        if text in {"true", "yes", "correct", "right", "1"}:
            return True
        if text in {"false", "no", "incorrect", "wrong", "0"}:
            return False
    text = str(item.get("result") or item.get("status") or "").strip().lower()
    if text in {"correct", "right", "passed", "success"}:
        return True
    if text in {"incorrect", "wrong", "failed", "error"}:
        return False
    return None


def _correct_answer_from_result(item: dict[str, Any], attempt: dict[str, Any]) -> str:
    for key in ("correct_answer", "correct_option", "correct_choice", "correct_option_text"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    options = attempt.get("options") if isinstance(attempt.get("options"), list) else []
    for key in ("correct_index", "correct_choice_index", "correct_option_index", "correct_choice"):
        try:
            index = int(item.get(key))
        except (TypeError, ValueError):
            continue
        if 0 <= index < len(options):
            return str(options[index] or "")
    return ""


def _question_result_items(data: dict[str, Any]) -> list[dict[str, Any]]:
    """兼容不同后端可能使用的逐题结果字段名。"""
    for key in ("question_results", "answer_results", "results", "details", "answers"):
        raw = data.get(key)
        if isinstance(raw, dict):
            raw = list(raw.values())
        if isinstance(raw, list):
            items = [item for item in raw if isinstance(item, dict)]
            if items:
                return items
    return []


def learning_evidence(data: dict[str, Any], attempts: list[dict[str, Any]]) -> list[dict[str, str]]:
    """把逐题明细/聚合总分转换成每次选择的可证明结论。"""
    evidence = [{"result": "unresolved", "correct_answer": ""} for _ in attempts]
    result_items = _question_result_items(data)
    used: set[int] = set()
    for attempt_index, attempt in enumerate(attempts):
        wanted_id = str(attempt.get("question_id"))
        matched_index: int | None = None
        for index, item in enumerate(result_items):
            if index in used:
                continue
            item_id = item.get("question_id", item.get("id"))
            if item_id is not None and str(item_id) == wanted_id:
                matched_index = index
                break
        if matched_index is None and attempt_index < len(result_items) and attempt_index not in used:
            matched_index = attempt_index
        if matched_index is None:
            continue
        used.add(matched_index)
        item = result_items[matched_index]
        verdict = _result_verdict(item)
        correct_answer = _correct_answer_from_result(item, attempt)
        if verdict is None and correct_answer:
            verdict = _option_matches(attempt.get("choice"), correct_answer)
        if verdict is not None:
            evidence[attempt_index]["result"] = "correct" if verdict else "incorrect"
        evidence[attempt_index]["correct_answer"] = correct_answer

    score, total = data.get("score"), data.get("total")
    try:
        numeric_score = float(score)
        numeric_total = float(total)
    except (TypeError, ValueError):
        numeric_score = numeric_total = -1
    if not isinstance(score, bool) and not isinstance(total, bool) and numeric_total > 0:
        aggregate = (
            "correct"
            if numeric_score == numeric_total
            else ("incorrect" if numeric_score == 0 else "")
        )
        if aggregate:
            for item in evidence:
                if item["result"] == "unresolved":
                    item["result"] = aggregate
    return evidence


def record_submit_learning(
    data: dict[str, Any],
    attempts: list[dict[str, Any]],
    store: Any = None,
) -> dict[str, Any]:
    """合并并写入本次答题证据；持久化失败不影响答题结果。"""
    counts = {"correct": 0, "incorrect": 0, "unresolved": 0, "saved": False}
    if not attempts:
        return counts
    target = store if store is not None else _BANK
    evidence = learning_evidence(data, attempts)
    for item in evidence:
        counts[item["result"]] += 1

    if target is None:
        return counts
    try:
        if True:
            bank = load_learning_bank(target)
            questions = bank.setdefault("questions", {})
            submitted_at = utc_iso()
            for attempt, proof in zip(attempts, evidence):
                prompt = str(attempt.get("prompt") or "").strip()
                normalized = _norm_prompt(prompt)
                if not normalized:
                    continue
                # 写入只按规范化题面精确聚合（题号已由 _norm_prompt 剥离）。
                # 模糊合并会把「学习题 A/B」这类短而相似的不同题误并为一题；
                # 相似度只用于读取时兼容轻微措辞变化，不能用于破坏性写合并。
                key = normalized
                entry = questions.setdefault(
                    key,
                    {
                        "prompt": prompt,
                        "correct_answer": "",
                        "wrong_answers": [],
                        "history": [],
                        "updated_at": "",
                    },
                )
                entry["prompt"] = prompt or entry.get("prompt") or key
                choice = str(attempt.get("choice") or "").strip()
                correct_answer = str(proof.get("correct_answer") or "").strip()
                wrong_answers = list(entry.get("wrong_answers") or [])
                result = proof["result"]
                if result == "correct" and choice:
                    correct_answer = correct_answer or choice
                    entry["correct_answer"] = correct_answer
                    wrong_answers = [item for item in wrong_answers if not _option_matches(item, correct_answer)]
                elif result == "incorrect" and choice:
                    if not _answer_is_wrong(choice, wrong_answers):
                        wrong_answers.append(choice)
                    if _option_matches(entry.get("correct_answer"), choice):
                        entry["correct_answer"] = ""
                if correct_answer:
                    entry["correct_answer"] = correct_answer
                    wrong_answers = [item for item in wrong_answers if not _option_matches(item, correct_answer)]
                entry["wrong_answers"] = wrong_answers
                history = list(entry.get("history") or [])
                history.append(
                    {
                        "choice": choice,
                        "result": result,
                        "score": data.get("score"),
                        "total": data.get("total"),
                        "submitted_at": submitted_at,
                    }
                )
                entry["history"] = history[-LEARNED_HISTORY_LIMIT:]
                entry["updated_at"] = submitted_at
            target.put(BANK_KEY, _normalize_learning_bank(bank))
        counts["saved"] = True
    except Exception:
        pass
    return counts


def summarize_submit(
    response: dict[str, Any],
    unknown: list[dict[str, Any]],
    attempts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """把提交回执归一成摘要。response 形如 {ok, status, code, message, data}。"""
    if not response.get("ok"):
        code = str(response.get("code") or "")
        message = str(response.get("message") or response.get("reason") or f"HTTP {response.get('status')}")
        if "ALREADY" in code.upper() or "ALREADY" in message.upper():
            return summary("already_done", "今日答题已完成")
        return summary("error", f"提交答题失败：{message}", unknown=len(unknown))

    data = response.get("data") if isinstance(response.get("data"), dict) else {}
    score, total = data.get("score"), data.get("total")
    reward = data.get("reward_amount")
    text = f"答题 {score}/{total}"
    # 奖励可能是优惠券，此时 reward_amount 为 0；不写金额也不写券名。
    if isinstance(reward, (int, float)) and not isinstance(reward, bool) and reward > 0:
        text += f"，获得 ${float(reward):.2f}"
    extra: dict[str, Any] = {
        "score": score,
        "total": total,
        "reward": reward,
        "reward_type": data.get("reward_type"),
        "unknown": len(unknown),
        "unknown_prompts": [str(item.get("prompt") or "") for item in unknown],
    }
    if attempts is not None:
        extra["learning"] = record_submit_learning(data, attempts)
    return summary("submitted", text, **extra)


def learning_log_line(outcome: dict[str, Any]) -> str:
    learning = outcome.get("learning") if isinstance(outcome, dict) else None
    if not isinstance(learning, dict):
        return ""
    text = (
        "学习题库：确认正确 "
        f"{learning.get('correct', 0)}，确认错误 {learning.get('incorrect', 0)}，"
        f"未决 {learning.get('unresolved', 0)}"
    )
    return text if learning.get("saved") else text + "（写入失败，本次不影响答题结果）"


def merge_message(base: str, extra: str) -> str:
    """把答题结论拼到签到消息后面。

    签到消息通常自带句号（「今日已签到。」），直接拼会得到「今日已签到。；答题…」，
    所以先去掉尾部句号再用分号连接。
    """
    head = str(base or "").rstrip().rstrip("。.")
    tail = str(extra or "").strip()
    if not tail:
        return str(base or "")
    return f"{head}；{tail}" if head else tail


# ── 传输一：浏览器页内 fetch ─────────────────────────────────────────────────
# 复用 _sub2api_common 的页内鉴权状态机（读 localStorage 的 auth_token、401 时刷新
# 一次再重试），因此答题与签到走同一套登录态，不必另外导出 token。

_FETCH_JS = "async ([baseUrl, path, body]) => {\n" + common._PAGE_AUTH_REQUEST_HELPERS_JS + """
    try {
        const headers = { Accept: 'application/json' };
        const init = { credentials: 'include', headers };
        if (body !== null) {
            init.method = 'POST';
            headers['Content-Type'] = 'application/json';
            init.body = JSON.stringify(body);
        }
        const response = await requestWithAuth((accessToken) => fetch(baseUrl + path, {
            ...init,
            headers: { ...headers, Authorization: `Bearer ${accessToken}` },
        }));
        if (!response) return { ok: false, status: 0, reason: 'no_token' };
        const raw = await parseBody(response);
        const payload = raw && typeof raw.data === 'object' && raw.data ? raw.data : raw;
        return {
            ok: response.ok,
            status: response.status,
            code: raw && raw.code !== undefined ? String(raw.code) : '',
            message: raw && raw.message ? String(raw.message) : '',
            data: payload,
        };
    } catch (err) {
        return { ok: false, status: 0, reason: String(err) };
    }
}"""


async def _quiz_call(page: Any, origin: str, path: str, body: Any = None) -> dict[str, Any]:
    try:
        result = await page.evaluate(_FETCH_JS, [origin, path, body])
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "status": 0, "reason": f"{type(exc).__name__}: {exc}"}
    return result if isinstance(result, dict) else {"ok": False, "status": 0, "reason": "bad_result"}


async def run_quiz(page: Any, helpers: Any, origin: str) -> dict[str, Any]:
    """浏览器路径：完成一次每日答题，返回可直接塞进 detail["quiz"] 的摘要。

    任何失败都只是「答题这一项没拿到」，不影响签到结论，所以这里永不抛异常，
    统一用 outcome 表达：submitted / already_done / disabled / unavailable / error。
    """
    today = await _quiz_call(page, origin, QUIZ_TODAY_PATH)
    if not today.get("ok"):
        reason = today.get("reason") or today.get("message") or f"HTTP {today.get('status')}"
        return summary("error", f"读取答题失败：{reason}")

    today_data = today.get("data")
    early, answers, unknown = plan(today_data)
    if early is not None:
        return early
    attempts = build_attempts(today_data, answers)
    if unknown:
        record_unknown(unknown)
        for line in describe_unknown(unknown):
            common.log(helpers, line)

    submitted = await _quiz_call(page, origin, QUIZ_SUBMIT_PATH, {"answers": answers})
    outcome = summarize_submit(submitted, unknown, attempts)
    learning_line = learning_log_line(outcome)
    if learning_line:
        common.log(helpers, learning_line)
    return outcome


# ── 传输二：纯 HTTP（不启动浏览器）────────────────────────────────────────────
# providers/actions/browser_script.py 会先尝试纯 HTTP 签到，成功时根本不会启动浏览器。
# 若答题只写在浏览器路径里，一旦某天 token 仍有效、纯 API 直接签到成功，答题就被
# 整天跳过。因此这里再给一条纯 HTTP 通路，由通用层通过 run_http_extras 钩子调用。


def _is_missing_endpoint(exc: Any) -> bool:
    """站点没有该功能（端点 404/405）——应当当作「无此项」而不是失败。"""
    status = getattr(exc, "status", None)
    if status in {404, 405}:
        return True
    text = f"{getattr(exc, 'message', '')} {getattr(exc, 'payload', '')}".lower()
    return "404" in text or "not found" in text


def run_play_quiz_http(ctx: Any) -> dict[str, Any] | None:
    """纯 HTTP 完成一次每日答题；站点无该功能返回 None。

    ``ctx.http`` 已注入认证，401 会由登录经纪人自动续期一次并重放，因此这里不必
    自己处理 token 过期。
    """
    from core.errors import TaskError

    def _unwrap(payload: Any) -> Any:
        if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
            return payload["data"]
        return payload

    try:
        today = ctx.http.get(QUIZ_TODAY_PATH)
    except TaskError as exc:
        if _is_missing_endpoint(exc):
            return None
        return summary("error", f"读取答题失败：{exc.message}")

    today_data = _unwrap(today)
    early, answers, unknown = plan(today_data)
    if early is not None:
        return early
    attempts = build_attempts(today_data, answers)
    if unknown:
        record_unknown(unknown)
        for line in describe_unknown(unknown):
            ctx.log(line)

    try:
        submitted = ctx.http.request(
            "POST", QUIZ_SUBMIT_PATH, json_body={"answers": answers}, retry_non_idempotent=True
        )
    except TaskError as exc:
        payload = exc.payload if isinstance(exc.payload, dict) else {}
        return summarize_submit(
            {
                "ok": False,
                "status": exc.status,
                # 业务判据在 reason（如 PLAY_QUIZ_ALREADY_DONE），code 只是 HTTP 化的数字
                "code": str(payload.get("reason") or payload.get("code") or ""),
                "message": exc.message,
            },
            unknown,
        )
    outcome = summarize_submit({"ok": True, "data": _unwrap(submitted)}, unknown, attempts)
    line = learning_log_line(outcome)
    if line:
        ctx.log(line)
    return outcome


# ══════════════════════════════ 签到主流程 ══════════════════════════════════

MANIFEST = TemplateManifest(
    id="jisudeng",
    title="极速蹬",
    description="Sub2API 系每日签到 + 每日答题（题库自学习）",
    login=(
        LoginOption("access_token", priority=10, title="Access Token"),
        LoginOption("refresh", priority=20, title="Refresh Token 续期"),
        LoginOption(
            "password",
            priority=30,
            title="账密登录",
            args=ArgSchema(
                (
                    ArgSpec("email", env="JISUDENG_EMAIL", secret=True, title="邮箱"),
                    ArgSpec("password", env="JISUDENG_PASSWORD", secret=True, title="密码"),
                )
            ),
        ),
        LoginOption("browser_state", priority=40, requires=frozenset({"browser"}), title="浏览器登录态"),
    ),
    task=(
        TaskOption(
            "script",
            priority=10,
            title="签到 + 答题",
            # 本流程自查状态、自点按钮、自确认结果；通用探测只会制造噪声。
            # 刻意**不**声明 requires={"browser"}：token 有效时纯 HTTP 就能跑完，
            # 浏览器是兜底而不是前提。
            owns=frozenset({"detect", "confirm"}),
            args=ArgSchema(
                (
                    ArgSpec("start_path", default="/play/checkin", title="入口路径"),
                    ArgSpec("quiz", default=True, kind="bool", title="是否执行每日答题"),
                )
            ),
        ),
    ),
    display=DisplayDefaults(text_label="额度"),
    endpoints={
        "prefix": "/api/v1",
        "submit": "/api/v1/play/checkin",
        "state": "/api/v1/play/checkin/status",
        "user": "/api/v1/user/profile",
        "login": "/api/v1/auth/login",
        "refresh": "/api/v1/auth/refresh",
    },
    # 默认访问链：先纯 HTTP（AT，失效用 RT 续期；签到成立后纯接口答题），失败再开浏览器
    # 登录并点击签到（签到成立后在同一页面答题）。登录走 Turnstile，HTTP 步骤不列 password。
    chain=(
        ChainStep("http", "http", title="HTTP 签到", login=("access_token", "refresh")),
        ChainStep("browser", "browser", title="浏览器登录并签到", login=("browser_state", "password")),
    ),
)


async def run(ctx: Any) -> Outcome:
    """签到 + 每日答题。答题失败只体现在结果数据里，不改写签到结论。

    未配置访问链的任务走这里；配置了访问链的任务由引擎分别调用 run_http / run_browser。
    """
    global _BANK
    # 题库属于站点而不属于账号：同一道题在 A 账号学到的答案对 B 账号一样有效。
    _BANK = ctx.store.shared("jisudeng_quiz")

    outcome = await common.http_first(ctx, SPEC)
    if outcome is not None:
        return _attach_quiz(ctx, outcome, run_play_quiz_http(ctx) if _quiz_enabled(ctx) else None)

    return await _browser_checkin(ctx)


async def run_http(ctx: Any) -> Outcome:
    """访问链 HTTP 步骤：纯接口签到，签到成立后再纯接口答题。"""
    global _BANK
    _BANK = ctx.store.shared("jisudeng_quiz")
    outcome = await common.http_attempt(ctx, SPEC)
    if not outcome.ok:
        return outcome
    return _attach_quiz(ctx, outcome, run_play_quiz_http(ctx) if _quiz_enabled(ctx) else None)


async def run_browser(ctx: Any) -> Outcome:
    """访问链浏览器步骤：登录后在页面签到，签到成立后在同一页面答题。"""
    global _BANK
    _BANK = ctx.store.shared("jisudeng_quiz")
    return await _browser_checkin(ctx)


async def _browser_checkin(ctx: Any) -> Outcome:
    async with ctx.browser.lease(reason="checkin") as lease:
        await lease.new_page()
        outcome = await common.run_flow(ctx, lease, SPEC)
        quiz = None
        if _quiz_enabled(ctx) and outcome.ok:
            helpers = PageHelpers(ctx, lease)
            try:
                quiz = await run_quiz(lease.page, helpers, helpers.resolve_url("/").rstrip("/"))
            except Exception as exc:  # noqa: BLE001 - 答题异常绝不能影响签到结论
                quiz = summary("error", f"答题异常：{type(exc).__name__}: {exc}")
        return _attach_quiz(ctx, outcome, quiz)


def _quiz_enabled(ctx: Any) -> bool:
    value = ctx.args.get("quiz", True)
    if isinstance(value, str):
        return value.strip().casefold() not in {"0", "false", "no", "off"}
    return bool(value)


def _attach_quiz(ctx: Any, outcome: Outcome, quiz: dict[str, Any] | None) -> Outcome:
    """把答题摘要并进结论：只加信息，不改判定。

    答题是签到之外的独立收益，成败与签到无关；旧实现把它拼在 message 尾巴上，
    站点一改文案就看不出答题跑没跑，所以这里同时进 ``data["quiz"]``（结构化，
    结果文件可长期回查）和展示附加项。
    """
    if quiz is None or not outcome.ok:
        return outcome
    ctx.log(f"答题：{quiz.get('message')}")
    merged = outcome.with_data(quiz=quiz)
    if quiz.get("outcome") in {"submitted", "already_done"}:
        message = merge_message(outcome.message, str(quiz.get("message") or ""))
        merged = merged.with_message(message)
    from core.outcome import DisplaySpec

    label = str(quiz.get("message") or quiz.get("outcome") or "")
    return merged.with_display(DisplaySpec(extras=(("答题", label),))) if label else merged

