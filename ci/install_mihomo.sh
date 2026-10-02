#!/usr/bin/env bash
# 安装 mihomo，供运行时代理桥使用。
# 目标路径固定为 RUNNER_TEMP/mihomo/mihomo，便于 net.proxy_bridge 自动发现。

set -euo pipefail

WORK_DIR="${RUNNER_TEMP:-/tmp}/mihomo"
BIN_FILE="${WORK_DIR}/mihomo"
FALLBACK_VERSION="${MIHOMO_VERSION:-v1.19.28}"

log() { printf '[install_mihomo] %s\n' "$*"; }

fail() {
  log "❌ $*"
  exit 1
}

detect_asset() {
  case "$(uname -m)" in
    x86_64|amd64) printf '%s\n' 'linux-amd64' ;;
    aarch64|arm64) printf '%s\n' 'linux-arm64' ;;
    *) fail "不支持的运行架构: $(uname -m)" ;;
  esac
}

resolve_version() {
  local version=""
  version="$(curl -fsSL --max-time 15 \
    https://api.github.com/repos/MetaCubeX/mihomo/releases/latest 2>/dev/null \
    | grep -o '"tag_name": *"[^"]*"' | head -n1 \
    | sed 's/.*"tag_name": *"\([^" ]*\)".*/\1/')" || true
  if [ -z "${version}" ]; then
    version="${FALLBACK_VERSION}"
    log "获取最新版本失败，使用回退版本 ${version}" >&2
  fi
  printf '%s\n' "${version}"
}

mkdir -p "${WORK_DIR}"
if [ -x "${BIN_FILE}" ]; then
  log "mihomo 已存在，跳过下载。"
  exit 0
fi

asset="$(detect_asset)"
version="$(resolve_version)"
url="https://github.com/MetaCubeX/mihomo/releases/download/${version}/mihomo-${asset}-${version}.gz"
tmp="${BIN_FILE}.gz.$$"
log "下载 mihomo ${version} (${asset})..."
trap 'rm -f -- "${tmp}"' EXIT
curl -fsSL --max-time 120 -o "${tmp}" "${url}" || fail "mihomo 下载失败"
gunzip -c "${tmp}" > "${BIN_FILE}.new" || fail "mihomo 解压失败"
chmod 700 "${BIN_FILE}.new"
mv -f "${BIN_FILE}.new" "${BIN_FILE}"
log "mihomo 已安装到临时目录。"
