#!/usr/bin/env bash
set -euo pipefail

: "${MERCURY_E2E_WORKDIR:?}"
: "${MERCURY_E2E_SOCKET:?}"
: "${MERCURY_E2E_BIN_DIR:?}"

WORKDIR="${MERCURY_E2E_WORKDIR}"
SOCKET="${MERCURY_E2E_SOCKET}"
BIN_DIR="${MERCURY_E2E_BIN_DIR}"
MMAP_PROBE="${WORKDIR}/mmap-probe.txt"
MMAP_POLICY_FILE="${WORKDIR}/mmap-hook-policy.yaml"
MMAP_PY="${WORKDIR}/test_mmap_hook.py"

printf 'protected-by-mmap-hook\n' > "${MMAP_PROBE}"
cat > "${MMAP_POLICY_FILE}" <<YAML
version: v1
defaults:
  decision: deny
  fail_mode: fail_closed
  audit_level: all
  enforcement:
    file: enforce
    process: enforce
    network: enforce
profiles:
  default:
    file_allow:
      - id: allow_abs
        pattern: /**
    file_deny:
      - id: deny_mmap_probe
        pattern: ${MMAP_PROBE}
    exec_allow:
      - id: allow_exec_abs
        path: /**
YAML

"${BIN_DIR}/mercury-policy" reload --socket "${SOCKET}" --file "${MMAP_POLICY_FILE}" > /dev/null

# The un-enrolled harness opens the file O_RDWR before mercury-run enrolls its
# child. Linux rejects writable MAP_SHARED on O_RDONLY before an LSM mmap hook.
# The descriptor is deliberately inherited to check mediation after enrollment.
exec {MMAP_FD}<>"${MMAP_PROBE}"
cat > "${MMAP_PY}" <<'PYEOF'
import mmap
import os
import sys

fd = int(os.environ["MERCURY_TEST_FD"])
try:
    mapping = mmap.mmap(fd, os.fstat(fd).st_size, access=mmap.ACCESS_WRITE)
    mapping.close()
    print("allowed")
    sys.exit(0)
except PermissionError:
    print("denied")
    sys.exit(1)
PYEOF

if MMAP_OUT="$(MERCURY_TEST_FD="${MMAP_FD}" \
  "${BIN_DIR}/mercury-run" --socket "${SOCKET}" --profile default -- \
  "${MERCURY_E2E_SYSTEM_PYTHON:-/usr/bin/python3}" "${MMAP_PY}" 2>&1)"; then
  MMAP_CODE=0
else
  MMAP_CODE=$?
fi
exec {MMAP_FD}>&-

if [[ "${MMAP_CODE}" -ne 1 || "${MMAP_OUT}" != "denied" ]]; then
  echo "FAIL: denied file was writable through an inherited MAP_SHARED descriptor" >&2
  echo "     backend=${MERCURY_E2E_FILESYSTEM_BACKEND:-unknown}, exit=${MMAP_CODE}, output=${MMAP_OUT}" >&2
  exit 1
fi

for _ in $(seq 1 100); do
  if rg -q 'FILE_MMAP' "${WORKDIR}/audit.jsonl"; then
    echo "inherited-descriptor mmap regression passed"
    exit 0
  fi
  sleep 0.05
done

echo "FAIL: mmap denial had no FILE_MMAP audit event" >&2
exit 1
