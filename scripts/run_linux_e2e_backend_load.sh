#!/usr/bin/env bash
set -euo pipefail

: "${MERCURY_E2E_SOCKET:?}"
: "${MERCURY_E2E_BIN_DIR:?}"
: "${MERCURY_E2E_FILESYSTEM_BACKEND:?}"

status="$("${MERCURY_E2E_BIN_DIR}/mercury-status" --socket "${MERCURY_E2E_SOCKET}" --ignore-degraded --dashboard)"
[[ "${status}" == *"daemon_up=true"* ]]
[[ "${status}" == *"kernel_ready=true"* ]]
[[ "${status}" == *"network_hook=EbpfLsm"* ]]

case "${MERCURY_E2E_FILESYSTEM_BACKEND}" in
  apparmor)
    [[ "${status}" =~ kernel_program_version=kernel-ebpf-v[0-9]+-apparmor ]]
    [[ "${status}" == *"exec_hook=AppArmor"* ]]
    [[ "${status}" == *"filesystem_hook=AppArmor"* ]]
    ;;
  ebpf_lsm)
    [[ "${status}" =~ kernel_program_version=kernel-ebpf-v[0-9]+-ebpf-lsm ]]
    [[ "${status}" == *"exec_hook=EbpfLsm"* ]]
    [[ "${status}" == *"filesystem_hook=EbpfLsm"* ]]
    ;;
  *) echo "error: unsupported filesystem backend: ${MERCURY_E2E_FILESYSTEM_BACKEND}" >&2; exit 1 ;;
esac

echo "backend load smoke passed: ${MERCURY_E2E_FILESYSTEM_BACKEND}"
