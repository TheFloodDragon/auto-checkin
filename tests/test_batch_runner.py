"""批量层：沿用判定、子进程隔离、汇总与结果文件。

两条不变量：
- 沿用按 ``(account_id, task_id)`` 匹配，不按显示名——改个名不该丢掉当天全部历史；
- 子进程不继承任何凭据类环境变量——旧实现漏给过 A 账号的 token 到 B 站点。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from apps import batch
from ci import report
from core.timebase import business_date


def _job(account_id: str = "a", name: str = "站点 A") -> batch.AccountJob:
    return batch.AccountJob(
        account_id=account_id,
        name=name,
        base_url="https://a.invalid",
        site_key="https://a.invalid",
        timeout=60.0,
    )


def _row(account_id: str, task_id: str, *, ok: bool, day: str = "") -> dict[str, Any]:
    return {
        "account_id": account_id,
        "task_id": task_id,
        "name": "站点 A",
        "ok": ok,
        "verdict": "success" if ok else "failed",
        "label": "成功" if ok else "失败",
        "business_date": day or business_date(),
    }


def test_carry_forward_matches_on_stable_ids_not_display_names() -> None:
    """沿用判定按账号 id 匹配。

    旧实现按任务的**显示名**匹配，站点改名或流程标签一变就丢掉当天全部历史，
    整批重跑一遍。
    """
    history = {("a", "daily"): _row("a", "daily", ok=True)}
    rows = batch._carried_rows(_job(name="改了个名字"), history, business_date())

    assert rows is not None and len(rows) == 1
    assert rows[0].carried_forward and not rows[0].executed_this_run


def test_partial_completion_reruns_the_whole_account() -> None:
    """一个任务没完成就整账号重跑：任务之间共享登录与浏览器，拆开跑反而更贵。"""
    history = {
        ("a", "daily"): _row("a", "daily", ok=True),
        ("a", "quiz"): _row("a", "quiz", ok=False),
    }
    assert batch._carried_rows(_job(), history, business_date()) is None


def test_yesterdays_result_is_never_carried_forward() -> None:
    """条目级业务日是文件头日期之外的第二道防线。"""
    history = {("a", "daily"): _row("a", "daily", ok=True, day="1999-01-01")}
    assert batch._carried_rows(_job(), history, business_date()) is None


def test_child_env_carries_no_credentials(monkeypatch) -> None:
    """子进程自己读配置与覆盖层，父进程不再透传凭据。

    旧实现用环境变量传 token，只要父进程里残留一个变量，就会漏给「没配这项凭据」的
    站点——已实测把 A 账号的 token 发到 B 站点。
    """
    for name in ("CHECKIN_ACCESS_TOKEN", "CHECKIN_COOKIE", "CHECKIN_BROWSER_STATE"):
        monkeypatch.setenv(name, "leak")
    monkeypatch.setenv("CHECKIN_PROXY", "http://proxy.invalid:8080")
    monkeypatch.setenv("UNRELATED", "keep")

    env = batch._child_env()
    assert "CHECKIN_ACCESS_TOKEN" not in env
    assert "CHECKIN_COOKIE" not in env
    assert "CHECKIN_BROWSER_STATE" not in env
    assert env["CHECKIN_PROXY"] == "http://proxy.invalid:8080", "全局代理是设计上的回退"
    assert env["UNRELATED"] == "keep"


def test_protocol_error_becomes_a_readable_failure() -> None:
    """子进程没吐出合法结果时，要给一条能定位的失败，而不是崩掉整批。"""
    rows = batch._parse_worker_output(_job(), "这不是 JSON\n最后一行", code=1)
    assert len(rows) == 1
    assert not rows[0].ok
    assert "协议错误" in rows[0].payload["message"]
    assert "最后一行" in rows[0].payload["message"], "要带上末行，否则无从下手"


def test_exit_code_overrides_a_success_payload() -> None:
    """子进程可能写完结果才崩：退出码与结果不一致时以退出码为准。"""
    payload = json.dumps(
        {"results": [{"account_id": "a", "task_id": "daily", "ok": True, "verdict": "success"}]}
    )
    rows = batch._parse_worker_output(_job(), payload, code=3)
    assert not rows[0].ok


def test_result_file_totals_count_every_verdict(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(batch, "RESULT_PATH", tmp_path / "result.json")
    rows = [
        batch.TaskRow("a", "daily", _row("a", "daily", ok=True)),
        batch.TaskRow("b", "daily", _row("b", "daily", ok=False)),
    ]
    batch._write_result(rows, business_day="2026-01-01")

    payload = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert payload["schema_version"] == 2
    assert payload["business_date"] == "2026-01-01"
    assert payload["totals"]["failed"] == 1
    assert payload["totals"]["success"] == 1
    assert payload["totals"]["total"] == 2


def test_serial_groups_keep_same_site_accounts_in_one_bucket() -> None:
    """同一 origin 的账号必须串行：并发既容易触发限流，也会抢同一份覆盖层条目。"""
    from runtime.batch import serial_groups

    items = [("a", "https://x.invalid"), ("b", "https://x.invalid"), ("c", "https://y.invalid")]
    groups = serial_groups(items, key=lambda item: item[1])
    assert [len(group) for group in groups] == [2, 1]


def test_worker_retry_metadata_matches_failed_tasks_not_the_whole_account(monkeypatch) -> None:
    worker_rows = [
        _row("a", "daily", ok=True),
        _row("a", "quiz", ok=True),
        _row("a", "lottery", ok=False),
        _row("a", "new", ok=True),
    ]
    completed = subprocess.CompletedProcess([], 2, json.dumps({"results": worker_rows}), "")
    monkeypatch.setattr(batch.subprocess, "run", lambda *args, **kwargs: completed)
    history = {
        ("a", "daily"): {**_row("a", "daily", ok=True), "retry_succeeded": True},
        ("a", "quiz"): _row("a", "quiz", ok=False),
        ("a", "lottery"): _row("a", "lottery", ok=False),
        ("b", "new"): _row("b", "new", ok=False),
    }

    rows = batch._run_job(_job(), verbose=False, config_path="", history=history)
    flags = {row.task_id: (row.retried, row.retry_succeeded) for row in rows}
    assert flags == {"daily": (False, False), "quiz": (True, True), "lottery": (True, False), "new": (False, False)}
    assert all(row.executed_this_run and not row.carried_forward for row in rows)
    assert rows[1].to_payload()["retry_succeeded"] is True
    assert rows[0].to_payload()["retry_succeeded"] is False


@pytest.mark.parametrize("previous", [None, {}, {"ok": True}, {"ok": "false"}, {"verdict": "no_effect", "ok": True}])
def test_worker_does_not_invent_a_retry_without_explicit_previous_failure(monkeypatch, previous) -> None:
    current = {**_row("a", "daily", ok=True), "retried": True, "retry_succeeded": True}
    completed = subprocess.CompletedProcess([], 0, json.dumps({"results": [current]}), "")
    monkeypatch.setattr(batch.subprocess, "run", lambda *args, **kwargs: completed)
    history = None if previous is None else {("a", "daily"): previous}

    row = batch._run_job(_job(), verbose=False, config_path="", history=history)[0]
    assert not row.retried and not row.retry_succeeded
    assert row.to_payload()["retried"] is False
    assert row.to_payload()["retry_succeeded"] is False


@pytest.mark.parametrize("failure", ["timeout", "protocol", "launch"])
def test_worker_failure_paths_still_record_an_unsuccessful_retry(monkeypatch, failure) -> None:
    def run(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"], stderr="[http:request] timed out")
        if failure == "launch":
            raise OSError("无法启动子进程")
        return subprocess.CompletedProcess([], 1, "not json", "")

    monkeypatch.setattr(batch.subprocess, "run", run)
    rows = batch.run_batch([_job()], history={("a", "daily"): _row("a", "daily", ok=False)}, workers=1)
    assert len(rows) == 1
    assert rows[0].executed_this_run and rows[0].retried
    assert not rows[0].ok and not rows[0].retry_succeeded


def test_worker_abnormal_exit_cannot_be_reported_as_a_successful_retry(monkeypatch) -> None:
    completed = subprocess.CompletedProcess([], 3, json.dumps({"results": [_row("a", "daily", ok=True)]}), "")
    monkeypatch.setattr(batch.subprocess, "run", lambda *args, **kwargs: completed)
    history = {("a", "daily"): _row("a", "daily", ok=False)}
    row = batch._run_job(_job(), verbose=False, config_path="", history=history)[0]
    assert row.retried and not row.retry_succeeded
    assert not row.ok


def test_terminal_summary_shows_sanitized_failure_message_in_information_column(capsys) -> None:
    rows = [
        batch.TaskRow("a", "daily", {**_row("a", "daily", ok=True), "text": "$1.25", "text_label": "额度"}),
        batch.TaskRow("b", "login", {**_row("b", "login", ok=False), "name": "失败账号",
                                   "message": "登录失效\n请重新登录 token=very-private-credential"}),
    ]
    batch._print_summary(rows)
    output = capsys.readouterr().out
    header = next(line for line in output.splitlines() if "账号" in line and "任务" in line)
    assert header.endswith(" | 信息")
    assert "额度: $1.25" in output
    assert "登录失效 请重新登录" in output
    assert "very-private-credential" not in output
    assert "\n请重新登录" not in output


def test_terminal_summary_keeps_explicit_failure_text_ahead_of_message(capsys) -> None:
    row = batch.TaskRow("a", "daily", {
        **_row("a", "daily", ok=False), "text": "失败 2 次", "text_label": "计数", "message": "详细诊断",
    })
    batch._print_summary([row])
    output = capsys.readouterr().out
    assert "失败 2 次" in output
    assert "详细诊断" not in output


def test_terminal_summary_distinguishes_carried_and_current_retry_success(capsys) -> None:
    rows = [
        batch.TaskRow("a", "daily", {**_row("a", "daily", ok=True), "name": "沿用账号"},
                      executed_this_run=False, carried_forward=True, retry_succeeded=True),
        batch.TaskRow("b", "daily", {**_row("b", "daily", ok=True), "name": "重试账号"},
                      retried=True, retry_succeeded=True),
    ]
    batch._print_summary(rows)
    output = capsys.readouterr().out
    status_cells = [line.split("|")[3].strip() for line in output.splitlines()
                    if "账号" in line and "daily" in line]
    assert len(status_cells) == 2
    assert status_cells[0] != status_cells[1], "历史重试成功的沿用项不能冒充本轮重试成功"


def test_ci_report_renders_v2_tasks_values_reasons_and_separate_verdict_totals() -> None:
    payload = {
        "schema_version": 2,
        "generated_at": "2026-01-01T01:00:00Z",
        "business_date": "2026-01-01",
        "results": [
            {**_row("a", "daily", ok=True), "text": "$1.25 / $20.00", "text_label": "额度",
             "extras": [["连签天数", 3]], "message": "签到成功"},
            {**_row("a", "quiz", ok=True), "verdict": "already_done", "label": "今日已完成"},
            {**_row("b", "lottery", ok=True), "name": "站点 B", "verdict": "no_effect",
             "reason": "not_applicable", "label": "不适用", "message": "等级不足"},
            {**_row("c", "daily", ok=False), "name": "站点 C", "reason": "need_login",
             "message": "登录态过期", "note": "请更新凭据"},
        ],
    }
    markdown = report.build_report(payload)

    assert "Unknown" not in markdown
    assert "| 站点 A（a） | daily |" in markdown
    assert "| 站点 A（a） | quiz |" in markdown
    assert "| 站点 B（b） | lottery |" in markdown
    assert "额度：$1.25 / $20.00；连签天数：3" in markdown
    assert "原因：not\\_applicable；等级不足" in markdown
    assert "原因：need\\_login；登录态过期；请更新凭据" in markdown
    assert "**结果时间**: 2026-01-01T01:00:00Z" in markdown
    assert "**业务日期**: 2026-01-01" in markdown
    for line in ("- 成功: 1", "- 已完成/已领取: 1", "- 无影响/不适用: 1", "- 失败: 1", "- 总计（任务项）: 4"):
        assert line in markdown
    assert "成功/已领取" not in markdown


def test_ci_report_keeps_legacy_lists_statuses_and_zero_quota_values() -> None:
    markdown = report.build_report([
        {"site": "旧站点", "status": "already_done", "ok": True, "note": "旧版备注",
         "quota_awarded": 0, "current_quota": 12.5},
        {"site": "关闭站点", "status": "not_open", "ok": True, "message": "未开放"},
        {"site": "登录站点", "status": "need_login", "ok": False},
        {"site": "早期站点", "ok": True, "label": "自定义成功"},
    ])

    assert "| 旧站点 | - |" in markdown
    assert "本次额度：0；当前额度：12.5" in markdown
    assert "旧版备注" in markdown
    assert "今日已完成" in markdown
    assert "登录失效" in markdown
    assert "自定义成功" in markdown
    assert "- 成功: 1" in markdown
    assert "- 已完成/已领取: 1" in markdown
    assert "- 无影响/不适用: 1" in markdown
    assert "- 失败: 1" in markdown
    assert "- 本轮实际执行: 4" in markdown


def test_ci_report_keeps_zero_custom_text_and_skips_malformed_extras() -> None:
    markdown = report.build_report({"results": [{
        **_row("a", "daily", ok=True),
        "text_label": "积分", "text": 0, "current_quota": 99,
        "extras": [None, "bad", [], ["incomplete"], ["次数", 0], ["次数", 0], ["空值", None]],
    }]})
    assert "积分：0；次数：0" in markdown
    assert markdown.count("次数：0") == 1
    assert "当前额度" not in markdown
    assert "incomplete" not in markdown


def test_ci_report_distinguishes_current_and_historical_retry_metadata() -> None:
    rows = [
        {**_row("a", "daily", ok=True), "executed_this_run": False, "carried_forward": True,
         "retried": True, "retry_succeeded": True},
        {**_row("b", "daily", ok=True), "executed_this_run": True, "retried": True, "retry_succeeded": True},
        {**_row("c", "daily", ok=False), "executed_this_run": True, "retried": True},
        {"site": "无运行元数据的旧条目", "ok": True},
    ]
    markdown = report.build_report({"results": rows})

    assert "- 本轮实际执行: 3" in markdown
    assert "- 沿用上次完成: 1" in markdown
    assert "- 本轮重试: 2" in markdown
    assert "- 本轮重试成功: 1" in markdown
    carried_line = next(line for line in markdown.splitlines() if "站点 A（a）" in line)
    assert "沿用上次完成 · 此前重试成功" in carried_line
    assert "本轮重试" not in carried_line


def test_ci_report_escapes_and_redacts_all_display_fields() -> None:
    injected = "![image](https://bad.invalid/x)<script>|\n| forged |"
    markdown = report.build_report({"results": [{
        **_row("a[b]", "t`ask", ok=False),
        "name": injected, "label": injected, "note": injected,
        "text_label": "api_key", "text": "display-credential-value",
        "extras": [["access_token", "opaque-extra-credential"], ["说明", injected]],
        "message": "Bearer abcdefghijklmnopqrstuv session=0123456789abcdef",
    }]})

    for secret in ("display-credential-value", "opaque-extra-credential", "abcdefghijklmnopqrstuv", "0123456789abcdef"):
        assert secret not in markdown
    assert "&lt;redacted&gt;" in markdown
    assert "<script>" not in markdown
    assert "![image]" not in markdown
    assert "\\!\\[image\\]\\(https://bad.invalid/x\\)&lt;script&gt;\\|" in markdown
    assert "a\\[b\\]" in markdown
    assert "t\\`ask" in markdown
    assert markdown.count("\n|") == 3, "注入换行和竖线不能增加表格行"


@pytest.mark.parametrize("payload", [None, [], {}, {"results": "bad"}, {"results": [None, "bad", 0, {}]}])
def test_ci_report_rejects_empty_or_invalid_result_collections(payload) -> None:
    markdown = report.build_report(payload)
    assert "未生成有效结果" in markdown
    assert "## 统计" not in markdown


@pytest.mark.parametrize("exit_code,fresh", [("3", "false"), ("", ""), ("0", "false")])
def test_ci_report_does_not_present_cached_results_as_a_current_run(tmp_path, monkeypatch, exit_code, fresh) -> None:
    result_path = tmp_path / "result.json"
    old_result = json.dumps({"results": [{"site": "cached-site", "ok": True}]})
    result_path.write_text(old_result, encoding="utf-8")
    monkeypatch.setattr(report._paths, "RESULT_PATH", result_path)
    monkeypatch.chdir(tmp_path)

    code = report.main(["--exit-code", exit_code, "--result-fresh", fresh])
    markdown = (tmp_path / "checkin_report.md").read_text(encoding="utf-8")
    assert code == 1
    assert "已忽略上次缓存" in markdown
    assert "cached-site" not in markdown
    assert "## 统计" not in markdown
    assert result_path.read_text(encoding="utf-8") == old_result, "报告不能删除下次重试要用的历史结果"


def test_ci_report_shows_real_exit_code_even_when_rows_are_successful(tmp_path, monkeypatch) -> None:
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps({"results": [_row("a", "daily", ok=True)]}), encoding="utf-8")
    monkeypatch.setattr(report._paths, "RESULT_PATH", result_path)
    monkeypatch.chdir(tmp_path)

    assert report.main(["--exit-code", "3", "--result-fresh", "true"]) == 0
    markdown = (tmp_path / "checkin_report.md").read_text(encoding="utf-8")
    assert "**签到脚本退出码**: 3" in markdown
    assert "任务明细不能替代进程退出码" in markdown
    assert "- 成功: 1" in markdown


@pytest.mark.parametrize("contents", [None, "not json", '{"results": [null]}'])
def test_ci_report_main_returns_failure_for_unusable_results(tmp_path, monkeypatch, contents) -> None:
    result_path = tmp_path / "result.json"
    if contents is not None:
        result_path.write_text(contents, encoding="utf-8")
    monkeypatch.setattr(report._paths, "RESULT_PATH", result_path)
    monkeypatch.chdir(tmp_path)

    assert report.main(["--exit-code", "0", "--result-fresh", "true"]) == 1
    assert "未生成有效结果" in (tmp_path / "checkin_report.md").read_text(encoding="utf-8")


def test_ci_report_can_run_without_uv_or_optional_dependencies(tmp_path) -> None:
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    completed = subprocess.run(
        [sys.executable, "-B", "-S", "-m", "ci.report", "--result-fresh", "false", "--exit-code", "3"],
        cwd=tmp_path, env=env, capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    assert completed.returncode == 1, completed.stderr
    markdown = (tmp_path / "checkin_report.md").read_text(encoding="utf-8")
    assert "已忽略上次缓存" in markdown
    assert "**签到脚本退出码**: 3" in markdown


def _workflow_step(name: str) -> str:
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/auto_checkin.yml"
    return workflow.read_text(encoding="utf-8").split(f"      - name: {name}\n", 1)[1].split("\n      - name:", 1)[0]


def _run_workflow_shell(script: str, tmp_path, **extra_env):
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("工作流 shell 回归测试需要 Bash")
    env = {
        **os.environ,
        "RUNNER_TEMP": tmp_path.as_posix(),
        "GITHUB_OUTPUT": (tmp_path / "step-output").as_posix(),
        "RUN_ALL": "true",
        **extra_env,
    }
    return subprocess.run(
        [bash, "-e", "-o", "pipefail", "-c", script], cwd=tmp_path, env=env,
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )


@pytest.mark.parametrize("exit_code,writes_result", [(0, True), (2, True), (3, False), (0, False)])
def test_workflow_marks_only_current_results_and_preserves_exit_code(tmp_path, exit_code, writes_result) -> None:
    result_path = tmp_path / ".cache-checkin/checkin_result.json"
    result_path.parent.mkdir(exist_ok=True)
    result_path.write_text("{}", encoding="utf-8")
    os.utime(result_path, (1, 1))
    script = textwrap.dedent(_workflow_step("执行签到").split("        run: |\n", 1)[1])
    script = script.replace("${{ steps.detect_browser.outputs.need_browser }}", "false")
    # stub 只改临时结果的时间戳，不运行 uv、签到入口、浏览器或任何真实网站。
    write = 'touch -r "$result_marker" -d "+1 second" .cache-checkin/checkin_result.json; ' if writes_result else ""
    completed = _run_workflow_shell(f"uv() {{ {write}return {exit_code}; }}\n" + script, tmp_path)

    assert completed.returncode == 0, completed.stderr
    outputs = (tmp_path / "step-output").read_text(encoding="utf-8")
    assert f"exit_code={exit_code}\n" in outputs
    assert f"result_fresh={str(writes_result).lower()}\n" in outputs


@pytest.mark.parametrize("exit_code,fresh,expected", [("0", "true", 0), ("0", "false", 1), ("", "", 1),
                                                     ("2", "true", 2), ("3", "false", 3), ("124", "false", 124)])
def test_workflow_final_check_propagates_task_failure_codes(tmp_path, exit_code, fresh, expected) -> None:
    script = textwrap.dedent(_workflow_step("检查签到结果").split("        run: |\n", 1)[1])
    script = script.replace("${{ steps.checkin.outputs.exit_code }}", exit_code)
    script = script.replace("${{ steps.checkin.outputs.result_fresh }}", fresh)
    completed = _run_workflow_shell(script, tmp_path)
    assert completed.returncode == expected, completed.stderr


def test_workflow_report_and_cache_require_current_run_evidence() -> None:
    report_step = _workflow_step("生成签到报告")
    assert 'python -m ci.report --result-fresh "$RESULT_FRESH" --exit-code "$CHECKIN_EXIT_CODE"' in report_step
    assert "uv run" not in report_step
    assert "RESULT_FRESH: ${{ steps.checkin.outputs.result_fresh }}" in report_step
    assert "CHECKIN_EXIT_CODE: ${{ steps.checkin.outputs.exit_code }}" in report_step
    cache_step = _workflow_step("保存本次签到结果缓存")
    assert "steps.checkin.outputs.result_fresh == 'true'" in cache_step
    assert "steps.report.outcome == 'success'" in cache_step


def test_stage_logs_are_filtered_per_task() -> None:
    from runtime.events import RunEvent

    def line(task: str, message: str) -> str:
        return RunEvent(stage="http", message=message, account="站", task=task).to_line()

    stderr = "\n".join([
        RunEvent(stage="network", message="共享代理", account="站").to_line(),
        line("daily", "签到请求"),
        line("chop_tree", "砍树请求"),
    ])

    daily = batch._stage_logs(stderr, task_id="daily")
    assert any("共享代理" in text for text in daily)
    assert any("签到请求" in text for text in daily)
    assert not any("砍树请求" in text for text in daily)
    tree = batch._stage_logs(stderr, task_id="chop_tree")
    assert not any("签到请求" in text for text in tree)
    assert len(batch._stage_logs(stderr)) == 3
