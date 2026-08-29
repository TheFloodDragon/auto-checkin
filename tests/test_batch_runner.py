"""批量层：沿用判定、子进程隔离、汇总与结果文件。

两条不变量：
- 沿用按 ``(account_id, task_id)`` 匹配，不按显示名——改个名不该丢掉当天全部历史；
- 子进程不继承任何凭据类环境变量——旧实现漏给过 A 账号的 token 到 B 站点。
"""

from __future__ import annotations

import json
from typing import Any

from apps import batch
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
