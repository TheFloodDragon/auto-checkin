"""执行真实 Bash 健康检查段，curl 用本地替身；不启动 mihomo、不访问外网。"""
from __future__ import annotations

import os
from pathlib import Path
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
  local target="${!#}"
  printf '%s\0' "$@" > "${HEALTH_TRACE}/${BASHPID}.args"
  case "${HEALTH_SCENARIO}" in
    one)
      if [ "${target}" = "${HEALTH_SUCCESS_URL}" ]; then
        return 0
      fi
      return "${HEALTH_FAILURE_CODE}"
      ;;
    race)
      if [ "${target}" = "${HEALTH_SUCCESS_URL}" ]; then
        command sleep 0.2
        return 0
      fi
      # exec 确保被清理的是探测本身，不遗留替身的孙进程。
      exec sleep 30
      ;;
    hanging)
      exec sleep 30
      ;;
    recover)
      if [ "${target}" = "${HEALTH_SUCCESS_URL}" ]; then
        if [ -f "${HEALTH_TRACE}/retry" ]; then
          return 0
        fi
        : > "${HEALTH_TRACE}/retry"
      fi
      return "${HEALTH_FAILURE_CODE}"
      ;;
    *) return "${HEALTH_FAILURE_CODE}" ;;
  esac
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
    env = dict(os.environ)
    for key in ("BASH_ENV", "ENV", "PROXY_REQUIRED", "CLASH_CONFIG"):
        env.pop(key, None)
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
                failure_code=28, budget=None, dead_process=False, process_timeout=8):
    source = SCRIPT.read_text(encoding="utf-8")
    # 保留实际常量、give_up 和完整健康检查段，仅跳过下载/写配置/启动 daemon。
    prefix = source.split("# ---- 1. 未配置则跳过 ----", 1)[0]
    health = source.split("# ---- 6. 健康检查 ----", 1)[1]
    trace = tmp_path / "calls"
    trace.mkdir()
    env = _env(tmp_path, required)
    env.update(HEALTH_TRACE=trace.as_posix(), HEALTH_SCENARIO=scenario,
               HEALTH_SUCCESS_URL=healthy, HEALTH_FAILURE_CODE=str(failure_code))
    overrides = ""
    if budget is not None:
        overrides = f"HEALTHCHECK_BUDGET={budget}\nHEALTHCHECK_RETRY_INTERVAL=1\n"
    if dead_process:
        work_dir = tmp_path / "mihomo"
        work_dir.mkdir()
        (work_dir / "mihomo.pid").write_text("999999999\n", encoding="ascii")
    result = subprocess.run(
        [native_bash, "--noprofile", "--norc"], input=prefix + overrides + CURL_STUB + health,
        cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=process_timeout,
    )
    calls = [record for record in (_record(path) for path in sorted(trace.glob("*.args"))) if record]
    return result, calls


@pytest.mark.parametrize("healthy", TARGETS)
@pytest.mark.parametrize("required", [None, "false", "true"])
def test_any_successful_target_accepts_proxy(native_bash, tmp_path, healthy, required):
    result, calls = _run_health(native_bash, tmp_path, healthy=healthy, required=required)
    assert result.returncode == 0, result.stderr
    assert "代理就绪" in result.stdout
    assert "跳过代理" not in result.stdout
    assert healthy in result.stdout
    assert "总预算 60s" in result.stdout
    assert healthy in {args[-1] for args in calls}
    for args in calls:
        assert args[0] == "-q"
        assert args[args.index("--proxy") + 1] == "http://127.0.0.1:7897"
        assert args[args.index("--noproxy") + 1] == ""
        assert args[args.index("--connect-timeout") + 1] == "2"
        assert args[args.index("--max-time") + 1] == "5"
        assert "-fsS" in args
        assert args[-1] in TARGETS


def test_slow_gstatic_does_not_delay_another_success(native_bash, tmp_path):
    # gstatic 挂起30秒，Cloudflare可用；若没有并发/早退/清理，会撞上8秒外部上限。
    result, calls = _run_health(native_bash, tmp_path, scenario="race", healthy=TARGETS[1], required="true")
    assert result.returncode == 0, result.stderr
    assert "代理就绪" in result.stdout
    assert TARGETS[1] in result.stdout
    assert TARGETS[0] in {args[-1] for args in calls}


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
    assert ("PROXY_REQUIRED=true，终止" if required == "true" else "PROXY_REQUIRED!=true，跳过代理") in result.stdout


def test_total_budget_cancels_all_stalled_probes(native_bash, tmp_path):
    result, calls = _run_health(native_bash, tmp_path, scenario="hanging", required="true", budget=1)
    assert result.returncode == 1, result.stderr
    assert "代理健康检查失败" in result.stdout
    assert {args[-1] for args in calls} == set(TARGETS)
    assert all(args[args.index("--max-time") + 1] == "1" for args in calls)
    assert all(args[args.index("--connect-timeout") + 1] == "1" for args in calls)


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
    assert not (tmp_path / "mihomo").exists()
