#!/usr/bin/env bash
# 启动本地 mihomo(Clash) 代理，供部分站点过阿里云 WAF 使用。
#
# 用法（CI）：把完整 mihomo/Clash 配置文件内容放进 Secret CLASH_CONFIG，
# 在签到前执行本脚本。脚本会：
#   1. 未设置 CLASH_CONFIG -> 打印跳过并 exit 0（不影响直连站点）。
#   2. 设置了 -> 下载 mihomo、写 config.yaml（剥离用户配置里的顶层端口/控制器 key，
#      再强制注入 mixed-port=7897、关闭 external-controller）、后台启动并做健康检查。
#
# 站点侧：在 ACCOUNTS.json 里给需要走代理的站点填 "proxy": "http://127.0.0.1:7897"。
# 其它站点留空即直连。
#
# 环境变量：
#   CLASH_CONFIG    完整 mihomo 配置文件内容（含 proxies/proxy-groups/rules）。
#   PROXY_REQUIRED  设为 true 时，代理起不来则 exit 1；否则仅告警并跳过（默认 false）。
#   MIHOMO_VERSION  可选，覆盖回退版本（默认 v1.19.28）。

set -euo pipefail

# ---- 常量 ----
PROXY_PORT=7897
WORK_DIR="${RUNNER_TEMP:-/tmp}/mihomo"
CONFIG_FILE="${WORK_DIR}/config.yaml"
BIN_FILE="${WORK_DIR}/mihomo"
PID_FILE="${WORK_DIR}/mihomo.pid"
LOG_FILE="${WORK_DIR}/mihomo.log"
FALLBACK_VERSION="${MIHOMO_VERSION:-v1.19.28}"
PROXY_REQUIRED="${PROXY_REQUIRED:-false}"
# 跨服务商的轻量探测目标；单个站点被拦截不代表本地代理不可用。
HEALTHCHECK_URLS=(
  "https://www.gstatic.com/generate_204"
  "https://cp.cloudflare.com/"
  "https://detectportal.firefox.com/success.txt"
)
HEALTHCHECK_BUDGET=60
# 代理隧道和 TLS 建连可能明显慢于本地端口监听；不能用 2 秒窗口误判为节点失效。
HEALTHCHECK_CONNECT_TIMEOUT=10
HEALTHCHECK_PROBE_TIMEOUT=15
HEALTHCHECK_RETRY_INTERVAL=2

log() { printf '[setup_proxy] %s\n' "$*"; }

# 代理起不来时的统一处理：required 则失败，否则跳过。
give_up() {
  local msg="$1"
  if [ "${PROXY_REQUIRED}" = "true" ]; then
    log "❌ ${msg}（PROXY_REQUIRED=true，终止）"
    exit 1
  fi
  log "${msg}（PROXY_REQUIRED!=true，跳过代理启动；账号仍按原代理配置执行，不会自动改为直连）"
  exit 0
}

# ---- 1. 未配置则跳过 ----
if [ -z "${CLASH_CONFIG:-}" ]; then
  log "未设置 Secret CLASH_CONFIG，跳过代理启动；账号仍按原代理配置执行，不会自动改为直连。"
  exit 0
fi

mkdir -p "${WORK_DIR}"

# ---- 2. 下载 mihomo ----
detect_asset() {
  # mihomo release 资产名形如 mihomo-linux-amd64-v1.19.28.gz
  local arch
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) echo "linux-amd64" ;;
    aarch64|arm64) echo "linux-arm64" ;;
    *) echo "linux-amd64" ;;  # 默认 amd64
  esac
}

resolve_version() {
  # 取最新 release tag，失败则回退固定版本。
  local v=""
  v="$(curl -fsSL --max-time 15 \
        https://api.github.com/repos/MetaCubeX/mihomo/releases/latest 2>/dev/null \
        | grep -o '"tag_name": *"[^"]*"' | head -n1 | sed 's/.*"tag_name": *"\([^" ]*\)".*/\1/')" || true
  if [ -z "${v}" ]; then
    v="${FALLBACK_VERSION}"
    # stdout 只返回版本号，否则 VERSION 的命令替换会把日志拼进下载 URL。
    log "获取最新版本失败，回退到 ${v}" >&2
  fi
  echo "${v}"
}

if [ ! -x "${BIN_FILE}" ]; then
  ASSET="$(detect_asset)"
  VERSION="$(resolve_version)"
  URL="https://github.com/MetaCubeX/mihomo/releases/download/${VERSION}/mihomo-${ASSET}-${VERSION}.gz"
  log "下载 mihomo ${VERSION} (${ASSET})..."
  if ! curl -fsSL --max-time 120 -o "${BIN_FILE}.gz" "${URL}"; then
    give_up "mihomo 下载失败: ${URL}"
  fi
  gunzip -f "${BIN_FILE}.gz" || give_up "mihomo 解压失败"
  chmod +x "${BIN_FILE}"
fi

# ---- 3. 写 config.yaml 并强制端口约定 ----
# mihomo rejects duplicate top-level keys, so we cannot just append overrides.
# Strip any top-level (no-indent) copies of the keys we force, then append ours.
# Only lines with no leading whitespace are removed, so nested/indented keys of
# the same name (inside proxies/rules/etc.) are preserved untouched.
STRIP_KEYS='mixed-port|port|socks-port|redir-port|tproxy-port|allow-lan|bind-address|external-controller|ipv6'
printf '%s\n' "${CLASH_CONFIG}" | sed -E "/^(${STRIP_KEYS})[[:space:]]*:/d" > "${CONFIG_FILE}"
{
  echo ""
  echo "# ---- forced by setup_proxy.sh (top-level overrides) ----"
  echo "mixed-port: ${PROXY_PORT}"
  echo "allow-lan: false"
  echo "bind-address: '127.0.0.1'"
  echo "external-controller: ''"
  # GitHub Actions ubuntu-latest 出站网络没有可用的 IPv6：实测每次拨号
  # 都会先把全部 IPv6 候选依次超时一遍才降级到 IPv4，白白吃掉大半个健康检查
  # 预算并刷屏日志。显式关闭 IPv6 出站，出口不可用时能更快判定并留出重试机会。
  echo "ipv6: false"
} >> "${CONFIG_FILE}"

# ---- 4. 校验配置 ----
if ! "${BIN_FILE}" -t -d "${WORK_DIR}" -f "${CONFIG_FILE}" >/dev/null 2>&1; then
  log "配置校验未通过；为避免泄露配置，不自动输出原始诊断。"
  give_up "CLASH_CONFIG 配置校验失败"
fi

# ---- 5. 后台启动 ----
nohup "${BIN_FILE}" -d "${WORK_DIR}" -f "${CONFIG_FILE}" > "${LOG_FILE}" 2>&1 &
echo $! > "${PID_FILE}"
log "mihomo 已启动 (pid=$(cat "${PID_FILE}"))，端口 ${PROXY_PORT}"

# 启动与外网探测共用一个预算：先确认本地监听，再判断节点出口。
HEALTHCHECK_DEADLINE=$((SECONDS + HEALTHCHECK_BUDGET))
wait_for_proxy_listener() {
  local deadline="$1" mihomo_pid=""
  if ! read -r mihomo_pid < "${PID_FILE}"; then
    log "无法读取 mihomo PID（phase=process_start）"
    return 1
  fi
  if ! [[ "${mihomo_pid}" =~ ^[0-9]+$ ]]; then
    log "mihomo PID 无效（phase=process_start）"
    return 1
  fi
  while ((SECONDS < deadline)); do
    if ! kill -0 "${mihomo_pid}" 2>/dev/null; then
      log "mihomo 在本地代理端口就绪前退出（phase=process_start）"
      return 1
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/${PROXY_PORT}") 2>/dev/null; then
      log "本地代理端口 ${PROXY_PORT} 已就绪（phase=local_listener）"
      return 0
    fi
    sleep 0.2
  done
  log "本地代理端口 ${PROXY_PORT} 未在预算内就绪（phase=local_listener）"
  return 1
}

if ! wait_for_proxy_listener "${HEALTHCHECK_DEADLINE}"; then
  give_up "本地代理监听未就绪"
fi

# ---- 6. 健康检查 ----
stop_health_probes() {
  local pid
  # 只清理本轮探测的 curl，不停止 mihomo 或其他进程。
  for pid in "$@"; do
    kill "${pid}" 2>/dev/null || true
  done
  for pid in "$@"; do
    wait "${pid}" 2>/dev/null || true
  done
}


report_health_probe() {
  local url="$1" curl_exit="$2" result_file="$3" started="$4"
  local metrics="" http_status="000" time_connect="0.000000" time_appconnect="0.000000"
  local elapsed=$((SECONDS - started)) phase="unknown" metrics_valid=false
  # 只读取有界的 curl write-out 数值；缺失/非法数据失败关闭，绝不回显原始响应。
  IFS= read -r -n 128 metrics 2>/dev/null < "${result_file}" || true
  if [[ "${metrics}" =~ ^([0-9]{3})[[:blank:]]([0-9]{1,6}\.[0-9]{1,6})[[:blank:]]([0-9]{1,6}\.[0-9]{1,6})[[:blank:]]([0-9]{1,6}\.[0-9]{1,6})$ ]]; then
    http_status="${BASH_REMATCH[1]}"
    time_connect="${BASH_REMATCH[2]}"
    time_appconnect="${BASH_REMATCH[3]}"
    elapsed="${BASH_REMATCH[4]}"
    metrics_valid=true
  fi
  if [[ "${curl_exit}" = "0" && "${http_status}" =~ ^2[0-9]{2}$ ]]; then
    phase="complete"
  elif [[ "${curl_exit}" = "7" ]]; then
    phase="proxy_connect"
  elif [[ "${curl_exit}" = "28" && "${metrics_valid}" = true && "${time_connect}" = "0.000000" ]]; then
    phase="proxy_connect_timeout"
  elif [[ "${curl_exit}" = "28" && "${metrics_valid}" = true && "${time_appconnect}" = "0.000000" ]]; then
    phase="proxy_tunnel_or_tls_timeout"
  elif [[ "${curl_exit}" = "28" && "${metrics_valid}" = true ]]; then
    phase="upstream_response_timeout"
  elif [[ "${http_status}" =~ ^[45][0-9]{2}$ ]]; then
    phase="upstream_http"
  fi
  # 被预算/其他目标成功取消时可能没有 write-out，耗时退回本地计时；只输出固定阶段和数值。
  log "健康探测：${url} curl_exit=${curl_exit} http_status=${http_status} phase=${phase} connect=${time_connect}s appconnect=${time_appconnect}s elapsed=${elapsed}s"
  [[ "${curl_exit}" = "0" && "${http_status}" =~ ^2[0-9]{2}$ ]]
}

check_proxy_targets() (
  local probe_timeout="$1" overall_deadline="$2"
  local round_deadline=$((SECONDS + probe_timeout))
  local connect_timeout="${HEALTHCHECK_CONNECT_TIMEOUT}"
  local index pid curl_exit probe_dir healthy_url="" pending=0
  local -a probe_pids=() probe_started=()
  if ((${#HEALTHCHECK_URLS[@]} == 0)); then
    log "健康探测目标为空"
    return 1
  fi
  if ((round_deadline > overall_deadline)); then
    round_deadline="${overall_deadline}"
  fi
  if ((connect_timeout > probe_timeout)); then
    connect_timeout="${probe_timeout}"
  fi
  probe_dir="$(mktemp -d "${WORK_DIR}/health.XXXXXX")" || return 1
  # 独立函数子 shell 的 trap 不污染调用方；任何退出路径都回收直接启动的 curl。
  trap 'stop_health_probes "${probe_pids[@]}"; rm -rf -- "${probe_dir}"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  for index in "${!HEALTHCHECK_URLS[@]}"; do
    probe_started[index]="${SECONDS}"
    # -q 不读取 curlrc；不跟随重定向，空 noproxy 确保探测经本地代理。
    curl -q -fsS --connect-timeout "${connect_timeout}" --max-time "${probe_timeout}" \
      --proxy "http://127.0.0.1:${PROXY_PORT}" --noproxy "" \
      -o /dev/null --write-out '%{http_code} %{time_connect} %{time_appconnect} %{time_total}\n' "${HEALTHCHECK_URLS[index]}" \
      > "${probe_dir}/${index}" 2>/dev/null &
    # 使用目标的原索引，避免稀疏数组或完成顺序导致 PID/目标错配。
    probe_pids[index]="$!"
    pending=$((pending + 1))
  done

  while ((pending > 0)); do
    for index in "${!probe_pids[@]}"; do
      pid="${probe_pids[index]}"
      if ! kill -0 "${pid}" 2>/dev/null; then
        curl_exit=0
        wait "${pid}" || curl_exit=$?
        unset "probe_pids[${index}]"
        pending=$((pending - 1))
        if report_health_probe "${HEALTHCHECK_URLS[index]}" "${curl_exit}" \
            "${probe_dir}/${index}" "${probe_started[index]}"; then
          healthy_url="${HEALTHCHECK_URLS[index]}"
          break
        fi
      fi
    done
    # 独立计数器不依赖 unset 最后一个元素后的空数组长度行为。
    if [[ -n "${healthy_url}" ]] || ((pending == 0 || SECONDS >= round_deadline)); then
      break
    fi
    sleep 0.1
  done

  # 先取消所有未回收的探测，再 wait 并报告（包括取消的目标），不串行等待超时。
  for pid in "${probe_pids[@]}"; do
    kill "${pid}" 2>/dev/null || true
  done
  for index in "${!probe_pids[@]}"; do
    curl_exit=0
    wait "${probe_pids[index]}" 2>/dev/null || curl_exit=$?
    unset "probe_pids[${index}]"
    report_health_probe "${HEALTHCHECK_URLS[index]}" "${curl_exit}" \
      "${probe_dir}/${index}" "${probe_started[index]}" || true
  done
  if [[ -n "${healthy_url}" ]]; then
    log "健康探测通过：${healthy_url}"
    return 0
  fi
  return 1
)

log "健康检查中（${#HEALTHCHECK_URLS[@]} 个目标并发，任一成功即通过，总预算 ${HEALTHCHECK_BUDGET}s）..."
OK=false
# 实际入口在这里之前已消耗了监听等待预算；离线测试则在此初始化截止时间。
if [[ -z "${HEALTHCHECK_DEADLINE:-}" ]]; then
  HEALTHCHECK_DEADLINE=$((SECONDS + HEALTHCHECK_BUDGET))
fi
while ((SECONDS < HEALTHCHECK_DEADLINE)); do
  remaining=$((HEALTHCHECK_DEADLINE - SECONDS))
  probe_timeout="${HEALTHCHECK_PROBE_TIMEOUT}"
  if ((probe_timeout > remaining)); then
    probe_timeout="${remaining}"
  fi
  if check_proxy_targets "${probe_timeout}" "${HEALTHCHECK_DEADLINE}"; then
    OK=true
    break
  fi
  # 所有目标均未通过后才检查进程/重试；保留原有必需代理失败处理。
  if [ -f "${PID_FILE}" ] && ! kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    log "mihomo 进程已退出"
    break
  fi
  remaining=$((HEALTHCHECK_DEADLINE - SECONDS))
  if ((remaining <= 0)); then
    break
  fi
  retry_interval="${HEALTHCHECK_RETRY_INTERVAL}"
  if ((retry_interval > remaining)); then
    retry_interval="${remaining}"
  fi
  sleep "${retry_interval}"
done

if [ "${OK}" = "true" ]; then
  log "✅ 代理就绪：http://127.0.0.1:${PROXY_PORT}"
  exit 0
fi

log "健康检查失败；为避免泄露配置，不自动输出 mihomo 原始日志（仍保留在本地日志文件）。"
give_up "代理健康检查失败"
