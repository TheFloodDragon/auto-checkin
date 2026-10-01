"""执行真实 Bash 健康检查段，curl 用本地替身；不启动 mihomo、不访问外网。"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ci" / "setup_proxy.sh"
TARGETS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/",
    "https://detectportal.firefox.com/success.txt",
)

# 每个 curl 子进程独立记录参数，避免并发写同一文件丢掉空的 --noproxy 参数。
CURL_STUB = r'''
curl() {
  local target="${!#}" code=0 http="${HEALTH_HTTP_CODE}"
  printf '%s\0' "$@" > "${HEALTH_TRACE}/${BASHPID}.args"
  printf '%s' "${HEALTH_STDERR}" >&2
  case "${HEALTH_SCENARIO}" in
    one)
      if [ "${target}" != "${HEALTH_SUCCESS_URL}" ]; then
        code="${HEALTH_FAILURE_CODE}"; http="${HEALTH_FAILURE_HTTP}"
      fi
      ;;
    race)
      if [ "${target}" = "${HEALTH_SUCCESS_URL}" ]; then
        command sleep 0.2
      else
        # exec 确保被清理的是探测本身，不遗留替身的孙进程。
        exec sleep 30
      fi
      ;;
    hanging)
      exec sleep 30
      ;;
    recover)
      if [ "${target}" != "${HEALTH_SUCCESS_URL}" ] || [ ! -f "${HEALTH_TRACE}/retry" ]; then
        if [ "${target}" = "${HEALTH_SUCCESS_URL}" ]; then
          : > "${HEALTH_TRACE}/retry"
        fi
        code="${HEALTH_FAILURE_CODE}"; http="${HEALTH_FAILURE_HTTP}"
      fi
      ;;
    *) code="${HEALTH_FAILURE_CODE}"; http="${HEALTH_FAILURE_HTTP}" ;;
  esac
  printf '%s %s\n' "${http}" "${HEALTH_ELAPSED}"
  return "${code}"
}
'''


@pytest.fixture(scope="module")
def native_bash():
    candidate = shutil.which("bash")
    if os.name == "nt":
        # 只能使用原生 Git Bash，不能误选 Windows 的 WSL 启动器。
        git = shutil.which("git")
        if git:
            for root in list(Path(git).resolve().parents)[:3]:
                for suffix in ("usr/bin/bash.exe", "bin/bash.exe"):
                    path = root / suffix
                    if path.is_file():
                        return str(path)
        if candidate and "/windows/" in Path(candidate).as_posix().lower():
            candidate = None
    if not candidate:
        pytest.skip("需要原生 Bash（Windows 使用 Git Bash）")
    return candidate


def _env(tmp_path, required):
    # 仅继承启动原生 Bash 所需的环境，不读取/传递真实代理配置或其他 Secrets。
    keys = ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "SYSTEMDRIVE",
            "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "LANG", "LC_ALL", "MSYSTEM")
    env = {key: os.environ[key] for key in keys if key in os.environ}
    env.update(RUNNER_TEMP=tmp_path.as_posix(), NO_PROXY="*", no_proxy="*")
    if required is not None:
        env["PROXY_REQUIRED"] = required
    return env


def _record(path: Path) -> list[str]:
    r"""读取一个 curl 替身写下的参数记录；没有完整落盘时返回空列表。

    替身的第一条语句是 ``printf '%s\0' "$@" > "${HEALTH_TRACE}/${BASHPID}.args"``：
    重定向会先建好文件，printf 的内容随后才落盘。任一目标成功后脚本立刻 kill 其余
    探测——这正是被测的早退行为——于是可能留下一个 0 字节（或理论上被截断）的 .args。

    此前读取侧直接对解析结果取 ``args[-1]``，空列表就抛 IndexError，表现为随机某个
    参数化组合失败（每次漂移到不同的 healthy 目标）。这是测试读取侧的竞态，不是脚本
    缺陷，所以修在这里。

    判据是「写入是否完整」而非「URL 像不像目标」：每个参数都以 NUL 结尾，完整记录的
    最后一个字节必然是 NUL。这样既滤掉被杀在半路的探测，又不会掩盖脚本真的传错参数
    或打错目标——那种记录是完整的，仍会让断言失败。
    """
    data = path.read_bytes()
    if not data or not data.endswith(b"\0"):
        return []
    return data.decode("utf-8").split("\0")[:-1]


def _run_health(native_bash, tmp_path, *, scenario="one", healthy=TARGETS[1], required=None,
                failure_code=28, budget=None, dead_process=False, process_timeout=8,
                http_code="204", failure_http=None, elapsed="0.020000", targets=None):
    source = SCRIPT.read_text(encoding="utf-8")
    # 保留实际常量、give_up 和完整健康检查段，仅跳过下载/写配置/启动 daemon。
    prefix = source.split("# ---- 1. 未配置则跳过 ----", 1)[0]
    health = source.split("# ---- 6. 健康检查 ----", 1)[1]
    trace = tmp_path / "calls"
    trace.mkdir()
    env = _env(tmp_path, required)
    env.update(HEALTH_TRACE=trace.as_posix(), HEALTH_SCENARIO=scenario,
               HEALTH_SUCCESS_URL=healthy, HEALTH_FAILURE_CODE=str(failure_code),
               HEALTH_HTTP_CODE=http_code, HEALTH_ELAPSED=elapsed,
               HEALTH_FAILURE_HTTP=failure_http if failure_http is not None else ("403" if failure_code == 22 else "000"),
               HEALTH_STDERR="SYNTHETIC_PRIVATE_CURL_ERROR")
    overrides = ""
    if budget is not None:
        overrides = f"HEALTHCHECK_BUDGET={budget}\nHEALTHCHECK_RETRY_INTERVAL=1\n"
    if targets is not None:
        overrides += "HEALTHCHECK_URLS=(" + " ".join(f'[{i}]="{url}"' for i, url in targets.items()) + ")\n"
    work_dir = tmp_path / "mihomo"
    work_dir.mkdir()
    (work_dir / "mihomo.log").write_text("SYNTHETIC_PRIVATE_MIHOMO_LOG\n", encoding="ascii")
    if dead_process:
        (work_dir / "mihomo.pid").write_text("999999999\n", encoding="ascii")
    result = subprocess.run(
        [native_bash, "--noprofile", "--norc"], input=prefix + overrides + CURL_STUB + health,
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=process_timeout,
    )
    calls = [record for record in (_record(path) for path in sorted(trace.glob("*.args"))) if record]
    assert "SYNTHETIC_PRIVATE" not in result.stdout + result.stderr
    assert not list(work_dir.glob("health.*")), "探测临时文件未清理"
    assert (work_dir / "mihomo.log").read_text(encoding="ascii") == "SYNTHETIC_PRIVATE_MIHOMO_LOG\n"
    diagnostics = [line for line in result.stdout.splitlines() if line.startswith("[setup_proxy] 健康探测：")]
    for line in diagnostics:
        assert len(line) < 200
        assert re.fullmatch(
            r"\[setup_proxy\] 健康探测：https://\S+ curl_exit=\d{1,3} http_status=\d{3} elapsed=\d+(?:\.\d+)?s", line,
        ), line
    # 仅检查替身自己记录的 PID；若回归造成泄漏，先清理以免测试留下进程。
    cleanup = subprocess.run(
        [native_bash, "--noprofile", "--norc", "-c",
         'leaked=0; for pid in "$@"; do if kill -0 "$pid" 2>/dev/null; then '
         'kill "$pid" 2>/dev/null; leaked=1; fi; done; exit "$leaked"',
         "probe-cleanup", *(path.stem for path in trace.glob("*.args"))],
        cwd=ROOT, env=env, capture_output=True, timeout=8,
    )
    assert cleanup.returncode == 0, "健康探测留下了未清理的子进程"
    return result, calls


@pytest.mark.parametrize("healthy", TARGETS)
@pytest.mark.parametrize("required", [None, "false", "true"])
def test_any_successful_target_accepts_proxy(native_bash, tmp_path, healthy, required):
    result, calls = _run_health(native_bash, tmp_path, healthy=healthy, required=required)
    assert result.returncode == 0, result.stderr
    assert "代理就绪" in result.stdout
    assert "跳过代理" not in result.stdout
    assert f"健康探测通过：{healthy}" in result.stdout
    assert f"{healthy} curl_exit=0 http_status=204 elapsed=0.020000s" in result.stdout
    assert "总预算 60s" in result.stdout
    assert healthy in {args[-1] for args in calls}
    for args in calls:
        assert args[0] == "-q"
        assert args[args.index("--proxy") + 1] == "http://127.0.0.1:7897"
        assert args[args.index("--noproxy") + 1] == ""
        assert args[args.index("--connect-timeout") + 1] == "2"
        assert args[args.index("--max-time") + 1] == "5"
        assert "-fsS" in args
        assert args[args.index("-o") + 1] == "/dev/null"
        assert args[args.index("--write-out") + 1] == "%{http_code} %{time_total}\\n"
        assert not any(arg in args for arg in ("-L", "--location", "-k", "--insecure"))
        assert args[-1] in TARGETS


@pytest.mark.parametrize("http_code", ["200", "201", "204", "299"])
def test_only_successful_2xx_is_healthy(native_bash, tmp_path, http_code):
    result, _ = _run_health(native_bash, tmp_path, required="true", http_code=http_code)
    assert result.returncode == 0, result.stderr
    assert "代理就绪" in result.stdout
    assert f"curl_exit=0 http_status={http_code} elapsed=0.020000s" in result.stdout


@pytest.mark.parametrize("http_code", ["000", "199", "300", "301", "302", "307", "308", "403", "407", "429", "500"])
def test_zero_curl_exit_does_not_accept_non_2xx(native_bash, tmp_path, http_code):
    result, _ = _run_health(native_bash, tmp_path, required="true", http_code=http_code, dead_process=True)
    assert result.returncode == 1, result.stderr
    assert "代理就绪" not in result.stdout
    assert f"{TARGETS[1]} curl_exit=0 http_status={http_code} elapsed=0.020000s" in result.stdout


@pytest.mark.parametrize("failure_code", [7, 22, 28])
def test_nonzero_curl_exit_rejects_even_2xx(native_bash, tmp_path, failure_code):
    result, _ = _run_health(
        native_bash, tmp_path, scenario="failed", required="true", dead_process=True,
        failure_code=failure_code, failure_http="200",
    )
    assert result.returncode == 1, result.stderr
    assert "代理就绪" not in result.stdout
    for target in TARGETS:
        assert f"{target} curl_exit={failure_code} http_status=200 elapsed=0.020000s" in result.stdout


@pytest.mark.parametrize("http_code,elapsed", [
    ("", ""), ("20", "0.1"), ("204", ""), ("204", "NaN"),
    ("204", "0.1 SYNTHETIC_PRIVATE_RESPONSE"),
    ("SYNTHETIC_PRIVATE_RESPONSE" * 1000, "0.1"),
])
def test_malformed_metrics_are_bounded_private_and_fail_closed(native_bash, tmp_path, http_code, elapsed):
    result, _ = _run_health(
        native_bash, tmp_path, required="true", dead_process=True, http_code=http_code, elapsed=elapsed,
    )
    assert result.returncode == 1, result.stderr
    assert "代理就绪" not in result.stdout
    assert f"{TARGETS[1]} curl_exit=0 http_status=000" in result.stdout
    assert len(result.stdout) < 2000


@pytest.mark.parametrize("targets,http_code,healthy", [
    ({}, "204", TARGETS[1]),
    ({9: TARGETS[1]}, "302", TARGETS[1]),
    ({9: TARGETS[1]}, "204", TARGETS[1]),
    ({2: TARGETS[0], 7: TARGETS[1], 19: TARGETS[2]}, "204", TARGETS[2]),
])
def test_empty_and_sparse_target_arrays(native_bash, tmp_path, targets, http_code, healthy):
    result, calls = _run_health(
        native_bash, tmp_path, required="true", targets=targets, http_code=http_code,
        healthy=healthy, dead_process=True,
    )
    assert "unbound variable" not in result.stderr
    expected_success = bool(targets) and http_code == "204"
    assert result.returncode == (0 if expected_success else 1), result.stderr
    assert ("代理就绪" in result.stdout) == expected_success
    if expected_success:
        assert f"健康探测通过：{healthy}" in result.stdout
    if not targets:
        assert calls == []
        assert "健康探测目标为空" in result.stdout


def test_slow_gstatic_does_not_delay_another_success(native_bash, tmp_path):
    # gstatic 挂起30秒，Cloudflare可用；若没有并发/早退/清理，会撞上8秒外部上限。
    result, calls = _run_health(native_bash, tmp_path, scenario="race", healthy=TARGETS[1], required="true")
    assert result.returncode == 0, result.stderr
    assert "代理就绪" in result.stdout
    assert TARGETS[1] in result.stdout
    assert TARGETS[0] in {args[-1] for args in calls}
    for target in (TARGETS[0], TARGETS[2]):
        assert f"{target} curl_exit=143 http_status=000 elapsed=" in result.stdout


@pytest.mark.parametrize("required,expected_code", [(None, 0), ("false", 0), ("true", 1)])
@pytest.mark.parametrize("failure_code", [7, 22, 28])
def test_all_targets_fail_preserves_required_behavior(native_bash, tmp_path, required, expected_code, failure_code):
    # 这里只验证各目标失败后的 required 语义，不测试抢占计时。Git Bash 的 SECONDS
    # 是整秒时钟，1 秒预算在繁忙机器上可能先杀掉尚未记录参数的子进程。
    # 留足本轮启动时间，再由假 daemon 已退出阻止重试；硬预算另有挂起探测用例覆盖。
    # 外层还要给 Windows 的进程创建/管道收尾留余量，不能用原来的8秒截断这项行为测试。
    # race/hanging 用例继续保留8秒上限，不削弱早退和清理探针的验证。
    result, calls = _run_health(
        native_bash, tmp_path, scenario="failed", required=required, failure_code=failure_code,
        budget=5, dead_process=True, process_timeout=20,
    )
    assert result.returncode == expected_code, result.stderr
    assert {args[-1] for args in calls} == set(TARGETS)
    assert "代理健康检查失败" in result.stdout
    assert "代理就绪" not in result.stdout
    for target in TARGETS:
        http_status = "403" if failure_code == 22 else "000"
        assert f"{target} curl_exit={failure_code} http_status={http_status} elapsed=0.020000s" in result.stdout
    assert ("PROXY_REQUIRED=true，终止" if required == "true" else "PROXY_REQUIRED!=true，跳过代理") in result.stdout


def test_total_budget_cancels_all_stalled_probes(native_bash, tmp_path):
    result, calls = _run_health(native_bash, tmp_path, scenario="hanging", required="true", budget=1)
    assert result.returncode == 1, result.stderr
    assert "代理健康检查失败" in result.stdout
    assert {args[-1] for args in calls} == set(TARGETS)
    assert all(args[args.index("--max-time") + 1] == "1" for args in calls)
    assert all(args[args.index("--connect-timeout") + 1] == "1" for args in calls)
    for target in TARGETS:
        assert f"{target} curl_exit=143 http_status=000 elapsed=" in result.stdout


def test_startup_can_recover_on_later_round(native_bash, tmp_path):
    result, calls = _run_health(native_bash, tmp_path, scenario="recover", required="true", budget=4)
    assert result.returncode == 0, result.stderr
    assert "代理就绪" in result.stdout
    assert sum(args[-1] == TARGETS[1] for args in calls) == 2


def test_dead_mihomo_stops_after_failed_round(native_bash, tmp_path):
    result, calls = _run_health(native_bash, tmp_path, scenario="failed", required="true", dead_process=True)
    assert result.returncode == 1, result.stderr
    assert "mihomo 进程已退出" in result.stdout
    assert len(calls) == len(TARGETS)


def test_forced_overrides_disable_ipv6_and_strip_user_supplied_key(native_bash, tmp_path):
    """CI 出站没有可用 IPv6：实测每次拨号都要先超时遍历全部 IPv6 候选才降级到
    IPv4，白白吃掉大半个健康检查预算。第 3 步生成的 config.yaml 必须强制
    ``ipv6: false``，且不能因为用户配置里已有顶层 ``ipv6:`` 键而产生重复键。
    """
    source = SCRIPT.read_text(encoding="utf-8")
    prefix = source.split("# ---- 1. 未配置则跳过 ----", 1)[0]
    write_config = source.split("# ---- 3. 写 config.yaml", 1)[1].split("# ---- 4. 校验配置 ----", 1)[0]
    write_config = "# ---- 3. 写 config.yaml" + write_config
    env = _env(tmp_path, None)
    env["CLASH_CONFIG"] = "ipv6: true\nproxies: []\n"
    (tmp_path / "mihomo").mkdir()
    result = subprocess.run(
        [native_bash, "--noprofile", "--norc"], input=prefix + write_config,
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=8,
    )
    assert result.returncode == 0, result.stderr
    config = (tmp_path / "mihomo" / "config.yaml").read_text(encoding="utf-8")
    assert config.count("\nipv6:") == 1
    assert re.search(r"^ipv6: false$", config, re.MULTILINE)


@pytest.mark.parametrize("required,expected_code", [(None, 0), ("true", 1)])
def test_config_validation_does_not_replay_private_output(native_bash, tmp_path, required, expected_code):
    source = SCRIPT.read_text(encoding="utf-8")
    prefix = source.split("# ---- 1. 未配置则跳过 ----", 1)[0]
    validation = source.split("# ---- 4. 校验配置 ----", 1)[1].split("# ---- 5. 后台启动 ----", 1)[0]
    env = _env(tmp_path, required)
    env["VALIDATION_TRACE"] = (tmp_path / "validation.calls").as_posix()
    stub = r'''
mock_mihomo() {
  printf 'called\n' >> "${VALIDATION_TRACE}"
  printf 'SYNTHETIC_PRIVATE_CONFIG\n' >&2
  return 1
}
BIN_FILE=mock_mihomo
'''
    result = subprocess.run(
        [native_bash, "--noprofile", "--norc"], input=prefix + stub + validation,
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=8,
    )
    assert result.returncode == expected_code, result.stderr
    assert "SYNTHETIC_PRIVATE" not in result.stdout + result.stderr
    assert "配置校验失败" in result.stdout
    assert (tmp_path / "validation.calls").read_text(encoding="ascii") == "called\n"


@pytest.mark.parametrize("required", [None, "true"])
def test_missing_config_keeps_existing_skip_behavior(native_bash, tmp_path, required):
    env = _env(tmp_path, required)
    env["CLASH_CONFIG"] = ""
    # 即使将来入口回归，也不允许单元测试真的下载程序。
    script = 'curl() { return 99; }\n' + SCRIPT.read_text(encoding="utf-8")
    result = subprocess.run(
        [native_bash, "--noprofile", "--norc"], input=script, cwd=ROOT, env=env,
        capture_output=True, text=True, encoding="utf-8", timeout=8,
    )
    assert result.returncode == 0
    assert "未设置 Secret CLASH_CONFIG" in result.stdout
    assert "不会自动改为直连" in result.stdout
    assert "站点直连" not in result.stdout
    assert not (tmp_path / "mihomo").exists()


def test_workflow_configures_proxy_gate_and_worker_limit():
    workflow = (ROOT / ".github" / "workflows" / "auto_checkin.yml").read_text(encoding="utf-8")
    proxy_step = workflow.split("- name: 启动 Clash 代理（可选）", 1)[1].split("- name:", 1)[0]
    checkin_step = workflow.split("- name: 执行签到", 1)[1].split("- name:", 1)[0]
    assert "PROXY_REQUIRED: ${{ vars.PROXY_REQUIRED || 'true' }}" in proxy_step
    assert "CHECKIN_WORKERS: ${{ vars.CHECKIN_WORKERS || '2' }}" in checkin_step
    assert checkin_step.count('run.py --workers "$CHECKIN_WORKERS" $RETRY_FLAG') == 2


@pytest.mark.parametrize("browser", [False, True])
@pytest.mark.parametrize("workers", ["2", "4", "2 3"])
def test_workflow_quotes_worker_limit_in_both_execution_paths(native_bash, tmp_path, browser, workers):
    workflow = (ROOT / ".github" / "workflows" / "auto_checkin.yml").read_text(encoding="utf-8")
    prefix = "xvfb-run " if browser else "uv run python -u run.py "
    command = next(line.strip() for line in workflow.splitlines() if line.strip().startswith(prefix))
    env = _env(tmp_path, None)
    env.update(CHECKIN_WORKERS=workers, RETRY_FLAG="--retry-failed")
    # 只验证实际工作流命令的参数传递，不启动签到或浏览器。
    stub = r'''
uv() { printf '%s\n' "$@"; }
xvfb-run() { shift 2; "$@"; }
'''
    result = subprocess.run(
        [native_bash, "--noprofile", "--norc"], input=stub + command,
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=8,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["run", "python", "-u", "run.py", "--workers", workers, "--retry-failed"]


@pytest.mark.parametrize("metadata,status,fallback,version", [
    ('{"tag_name": "v1.20.1"}', 0, None, "v1.20.1"),
    ("", 22, None, "v1.19.28"),
    ('{"message": "rate limited"}', 0, None, "v1.19.28"),
    ("", 22, "v1.19.29", "v1.19.29"),
])
def test_version_lookup_keeps_download_url_free_of_logs(native_bash, tmp_path, metadata, status, fallback, version):
    env = _env(tmp_path, None)
    env.pop("MIHOMO_VERSION", None)
    env.update(CLASH_CONFIG="proxies: []", RELEASE_METADATA=metadata, RELEASE_STATUS=str(status),
               DOWNLOAD_TRACE=(tmp_path / "download.args").as_posix())
    if fallback is not None:
        env["MIHOMO_VERSION"] = fallback
    # 执行完整启动入口；所有 curl 均为本地替身，下载必然停止于记录参数处。
    stub = r'''
uname() { printf '%s\n' x86_64; }
curl() {
  if [ "${!#}" = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest" ]; then
    printf '%s\n' "${RELEASE_METADATA}"
    return "${RELEASE_STATUS}"
  fi
  printf '%s\0' "$@" > "${DOWNLOAD_TRACE}"
  return 99
}
'''
    result = subprocess.run(
        [native_bash, "--noprofile", "--norc"], input=stub + SCRIPT.read_text(encoding="utf-8"),
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=8,
    )
    assert result.returncode == 0, result.stderr
    assert "不会自动改为直连" in result.stdout
    assert "站点将直连" not in result.stdout
    args = _record(tmp_path / "download.args")
    assert args[-1] == (
        f"https://github.com/MetaCubeX/mihomo/releases/download/{version}/mihomo-linux-amd64-{version}.gz"
    )
    if version != "v1.20.1":
        assert f"获取最新版本失败，回退到 {version}" in result.stderr
