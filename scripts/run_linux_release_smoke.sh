#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DASHBOARD_DIR="${REPO_ROOT}/dashboard/linux-ui"
WORKDIR="${MERCURY_RELEASE_SMOKE_WORKDIR:-$(mktemp -d)}"
ASSET_DIR="${WORKDIR}/release-assets"
INSTALLER_PATH="${ASSET_DIR}/install-mercury-linux.sh"
KEEP_WORKDIR="${KEEP_WORKDIR:-0}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run_linux_release_smoke.sh must run as root (use sudo -E)" >&2
  exit 1
fi

if systemctl is-active --quiet mercuryd \
  || [[ -e /etc/mercury || -e /var/lib/mercury || -e /var/log/mercury || -e /usr/local/bin/mercuryd ]]; then
  echo "error: packaged release smoke requires a disposable host without an existing Mercury installation" >&2
  exit 1
fi

mkdir -p "${WORKDIR}"

source "${REPO_ROOT}/scripts/lib/install_linux_common.sh"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: missing required command '$1'" >&2
    exit 1
  fi
}

on_error() {
  local status="$1"

  echo "error: Linux packaged release smoke failed with status ${status}" >&2
  systemctl status mercuryd --no-pager || true
  journalctl -u mercuryd -n 120 --no-pager || true
  echo "WORKDIR=${WORKDIR}" >&2
  exit "${status}"
}

cleanup() {
  set +e
  if [[ -x "${INSTALLER_PATH}" ]]; then
    "${INSTALLER_PATH}" --uninstall --purge >/dev/null 2>&1 || true
  fi

  if [[ "${KEEP_WORKDIR}" != "1" ]]; then
    rm -rf "${WORKDIR}"
  fi
}

trap 'on_error $?' ERR
trap cleanup EXIT

require_cmd cargo
require_cmd npm
require_cmd openssl
require_cmd curl
require_cmd sha256sum
require_cmd systemctl
require_cmd journalctl
require_cmd ss

mercury_uninstall_system 1 >/dev/null 2>&1 || true

if systemctl is-active --quiet ai-guardd; then
  echo "error: legacy ai-guardd.service is active; packaged Mercury smoke requires a clean runner" >&2
  exit 1
fi

if ss -ltn '( sport = :19080 or sport = :7480 )' | tail -n +2 | grep -q .; then
  echo "error: ports 19080 or 7480 are already in use; packaged Mercury smoke requires a clean runner" >&2
  ss -ltn '( sport = :19080 or sport = :7480 )' >&2 || true
  exit 1
fi

cargo build --release --workspace

if [[ ! -d "${DASHBOARD_DIR}/node_modules" ]]; then
  npm --prefix "${DASHBOARD_DIR}" ci
fi

npm --prefix "${DASHBOARD_DIR}" run build

./scripts/build_linux_release_bundle.sh "${ASSET_DIR}"

key_path="${WORKDIR}/linux-release-smoke-key.pem"
pubkey_path="${WORKDIR}/linux-release-smoke-key.pub.pem"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${key_path}"
openssl pkey -in "${key_path}" -pubout -out "${pubkey_path}"

./scripts/render_linux_installer.sh \
  --output "${INSTALLER_PATH}" \
  --release-tag "v0.0.0-release-smoke" \
  --repository "local/mercury" \
  --public-key-file "${pubkey_path}"

(
  cd "${ASSET_DIR}"
  sha256sum install-mercury-linux.sh mercury-linux-x86_64.tar.gz > SHA256SUMS
)
openssl dgst -sha256 -sign "${key_path}" \
  -out "${ASSET_DIR}/SHA256SUMS.sig" \
  "${ASSET_DIR}/SHA256SUMS"

"${INSTALLER_PATH}" --uninstall --purge || true
"${INSTALLER_PATH}" --preflight-only --asset-base-url "file://${ASSET_DIR}"

"${INSTALLER_PATH}" --asset-base-url "file://${ASSET_DIR}"

systemctl is-enabled mercuryd >/dev/null
systemctl is-active --quiet mercuryd
[[ -S /run/mercury/mercuryd.sock ]]
[[ -x /usr/local/bin/mercuryd ]]
[[ -x /usr/local/bin/mercury-run ]]
[[ -f /usr/local/lib/mercury/install_linux_common.sh ]]
grep -q '^d /sys/fs/cgroup/mercury 0755 root root -$' /etc/tmpfiles.d/mercuryd.tmpfiles.conf
grep -q '^d /sys/fs/cgroup/mercury/agents 0755 root root -$' /etc/tmpfiles.d/mercuryd.tmpfiles.conf

/usr/local/bin/mercury-status
/usr/local/bin/mercury-run --profile default -- /bin/true

"${INSTALLER_PATH}" --uninstall

! systemctl is-active --quiet mercuryd
[[ ! -e /etc/systemd/system/mercuryd.service ]]
[[ ! -e /etc/tmpfiles.d/mercuryd.tmpfiles.conf ]]
[[ ! -e /usr/local/bin/mercuryd ]]
[[ ! -e /usr/local/bin/mercury-run ]]
[[ ! -e /usr/local/bin/mercury-policy ]]
[[ ! -e /usr/local/bin/mercury-status ]]
[[ ! -d /usr/share/mercury/dashboard ]]
[[ ! -e /usr/local/lib/mercury/install_linux_common.sh ]]
[[ -f /etc/mercury/config.yaml ]]
[[ -f /etc/mercury/policy.yaml ]]
[[ -d /var/lib/mercury ]]
[[ -d /var/log/mercury ]]

"${INSTALLER_PATH}" --asset-base-url "file://${ASSET_DIR}"

systemctl is-active --quiet mercuryd
[[ -S /run/mercury/mercuryd.sock ]]
/usr/local/bin/mercury-status

"${INSTALLER_PATH}" --uninstall --purge

! systemctl is-active --quiet mercuryd
[[ ! -e /etc/systemd/system/mercuryd.service ]]
[[ ! -e /etc/tmpfiles.d/mercuryd.tmpfiles.conf ]]
[[ ! -e /usr/local/bin/mercuryd ]]
[[ ! -d /usr/share/mercury/dashboard ]]
[[ ! -d /etc/mercury ]]
[[ ! -d /var/lib/mercury ]]
[[ ! -d /var/log/mercury ]]

echo "WORKDIR=${WORKDIR}"
echo "linux packaged release smoke passed"
