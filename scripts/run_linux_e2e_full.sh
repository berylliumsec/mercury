#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

"${SCRIPT_DIR}/run_linux_e2e_smoke.sh"
python3 "${REPO_ROOT}/samples/oss-agents/mcp_socket_policy_test.py"
TIMEOUT_SECS="${TIMEOUT_SECS:-300}" "${REPO_ROOT}/samples/oss-agents/run_smolagents_policy_test.sh"
TIMEOUT_SECS="${MAJOR_TIMEOUT_SECS:-1200}" "${REPO_ROOT}/samples/oss-agents/run_major_agents_policy_test.sh"
MAX_OVERHEAD_PERCENT="${MAX_OVERHEAD_PERCENT:-5}" "${REPO_ROOT}/samples/oss-agents/benchmark_kernel_overhead.sh"

echo "linux e2e full passed"
