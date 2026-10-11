#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/scripts/lib/install_linux_common.sh"

PURGE_UNINSTALL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge)
      PURGE_UNINSTALL=1
      shift
      ;;
    --help|-h)
      cat <<'EOF'
usage: uninstall_mercury_system.sh [--purge]

Uninstall a repo-local Mercury system install. By default, /etc/mercury, /var/lib/mercury,
and /var/log/mercury are preserved. Use --purge to remove them too.
EOF
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

mercury_require_root

mercury_uninstall_system "$PURGE_UNINSTALL"
