"""CI 诊断与最终结果门禁的离线回归测试。"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import textwrap

import pytest

from ci import report


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/auto_checkin.yml"


def test_report_identifies_upstream_failure_without_exposing_outputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CHECKIN_STEPS_JSON", json.dumps({
        "setup_proxy": {"outcome": "failure", "outputs": {"config": "DO-NOT-DISCLOSE"}},
        "checkin": {"outcome": "skipped"},
        "uv_sync": {"outcome": "success"},
    }))
    assert report.main(["--exit-code", "", "--result-fresh", ""]) == 1
    markdown = (tmp_path / "checkin_report.md").read_text(encoding="utf-8")
    assert "启动 Clash 代理: failure" in markdown
    assert "已忽略上次缓存" in markdown
    assert "DO-NOT-DISCLOSE" not in markdown
    assert "安装锁定依赖: success" not in markdown


@pytest.mark.parametrize("raw", ["broken-json", "[]", "null"])
def test_malformed_step_context_does_not_prevent_report(raw):
    assert "工作流诊断" in report._workflow_diagnostics(raw)


def test_step_context_only_reports_failed_or_cancelled_states():
    text = report._workflow_diagnostics(json.dumps({
        "checkout": {"outcome": "cancelled"},
        "setup_uv": {"outcome": "skipped"},
        "uv_sync": {"outcome": "failure", "conclusion": "success"},
        "invalid": None,
    }))
    assert "检出代码: cancelled" in text
    assert "安装锁定依赖: failure" in text
    assert "设置 uv" not in text
    assert report._workflow_diagnostics("") == ""
    assert report._workflow_diagnostics('{"checkin":{"outcome":"success"}}') == ""


@pytest.mark.parametrize("outcome", ["failure", "skipped", "cancelled", ""])
def test_final_gate_rejects_invalid_report_even_with_zero_exit_code(tmp_path, outcome):
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("需要 Git Bash 或 Bash")
    block = WORKFLOW.read_text(encoding="utf-8").split("      - name: 检查签到结果\n", 1)[1]
    script = textwrap.dedent(block.split("        run: |\n", 1)[1])
    script = script.replace("${{ steps.checkin.outputs.exit_code }}", "0")
    script = script.replace("${{ steps.checkin.outputs.result_fresh }}", "true")
    script = script.replace("${{ steps.report.outcome }}", outcome)
    completed = subprocess.run([bash, "-e", "-o", "pipefail", "-c", script], cwd=tmp_path,
                               env=os.environ.copy(), capture_output=True, text=True,
                               encoding="utf-8", timeout=10)
    assert completed.returncode == 1, completed.stderr
    assert "报告校验失败" in completed.stdout
    assert "所有签到任务完成" not in completed.stdout


def test_workflow_passes_step_context_and_names_diagnostic_steps():
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = {step.get("id"): step for step in workflow["jobs"]["checkin"]["steps"] if step.get("id")}
    for name in ("checkout", "setup_uv", "setup_python", "uv_sync", "restore_accounts",
                 "detect_mihomo", "install_mihomo", "detect_browser", "browser_dependencies",
                 "setup_proxy", "checkin", "stop_proxy"):
        assert name in steps
    assert steps["report"]["env"]["CHECKIN_STEPS_JSON"] == "${{ toJSON(steps) }}"


def test_workflow_installs_mihomo_only_for_bridge_nodes():
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = {step.get("id"): step for step in workflow["jobs"]["checkin"]["steps"] if step.get("id")}
    assert steps["detect_mihomo"]["run"].find("'clash' in value") >= 0
    assert steps["install_mihomo"]["if"] == "steps.detect_mihomo.outputs.need_mihomo == 'true'"
    installer = (WORKFLOW.parents[2] / "ci/install_mihomo.sh").read_text(encoding="utf-8")
    assert "RUNNER_TEMP" in installer and "mihomo" in installer
    assert "CLASH_CONFIG" not in installer
