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


def test_browser_detection_includes_github_shared_keepalive_and_force(monkeypatch, capsys):
    from apps import cli
    from config import schema
    from runtime import capabilities
    from templates import registry as templates
    from types import SimpleNamespace

    document = schema.parse_document({"version": 3, "accounts": [{
        "id": "http-only", "base_url": "https://site.invalid", "template": "fixture",
    }], "oauth_states": {"github": {"accounts": {"work": {"state": "offline-fixture"}}}}})
    monkeypatch.setattr(templates, "get", lambda _reference: SimpleNamespace(manifest=object()))
    monkeypatch.setattr(capabilities, "required_by", lambda _manifest: frozenset())
    cli._requires(document, "browser")
    assert capsys.readouterr().out.strip() == "true"
    cli._requires(document, "browser", oauth_renew_hours=0)
    assert capsys.readouterr().out.strip() == "false"
    cli._requires(document, "browser", oauth_renew_hours=0, oauth_force_verify=True)
    assert capsys.readouterr().out.strip() == "true"


def test_browser_detection_includes_implicit_github_fallback(monkeypatch, capsys):
    from apps import cli
    from config import schema
    from runtime import capabilities
    from templates import registry as templates
    from types import SimpleNamespace

    document = schema.parse_document({"version": 3, "accounts": [{
        "id": "forum", "base_url": "https://linux.do", "template": "fixture",
        "login": {"method": "browser_state", "args": {"github_fallback": "true", "github_account": "work"}},
    }]})
    monkeypatch.setattr(templates, "get", lambda _reference: SimpleNamespace(manifest=object()))
    monkeypatch.setattr(capabilities, "required_by", lambda _manifest: frozenset())
    cli._requires(document, "browser")
    assert capsys.readouterr().out.strip() == "true"


@pytest.mark.parametrize("exit_code", [2, 124])
def test_workflow_preserves_overlay_only_renewal_when_tasks_fail(tmp_path, exit_code):
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("需要 Git Bash 或 Bash")
    text = WORKFLOW.read_text(encoding="utf-8")
    block = text.split("      - name: 执行签到\n", 1)[1].split("\n      - name:", 1)[0]
    script = textwrap.dedent(block.split("        run: |\n", 1)[1])
    script = script.replace("${{ steps.detect_browser.outputs.need_browser }}", "false")
    cache = tmp_path / ".cache-checkin"
    cache.mkdir(exist_ok=True)
    overlay = cache / "overlay.json"
    overlay.write_text('{"oauth_states":{"github":{}}}', encoding="utf-8")
    os.utime(overlay, (1, 1))
    output = tmp_path / "step-output"
    stub = 'uv() { touch -r "$result_marker" -d "+1 second" .cache-checkin/overlay.json; return ' + str(exit_code) + '; }\n'
    completed = subprocess.run([bash, "-e", "-o", "pipefail", "-c", stub + script], cwd=tmp_path,
                               env={**os.environ, "RUNNER_TEMP": tmp_path.as_posix(), "GITHUB_OUTPUT": output.as_posix(),
                                    "RUN_ALL": "true", "CHECKIN_ACCOUNT_IDS": "", "CHECKIN_TASK_IDS": "", "OAUTH_FORCE_VERIFY": "false"},
                               capture_output=True, text=True, encoding="utf-8", timeout=15)
    assert completed.returncode == 0, completed.stderr
    outputs = output.read_text(encoding="utf-8")
    assert f"exit_code={exit_code}\n" in outputs
    assert "result_fresh=false\n" in outputs and "overlay_fresh=true\n" in outputs
    cache_step = text.split("      - name: 保存本次签到结果缓存\n", 1)[1].split("\n      - name:", 1)[0]
    assert "if: always()" in cache_step
    assert "|| steps.checkin.outputs.overlay_fresh == 'true'" in cache_step
    assert "path: .cache-checkin" in cache_step
