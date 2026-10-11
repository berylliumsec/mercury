#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/scripts/lib/install_linux_common.sh"

OUT_DIR="${1:-$REPO_ROOT/dist/linux-release}"
ARCH="${ARCH:-x86_64}"

if [[ "$ARCH" != "x86_64" ]]; then
  echo "error: unsupported Linux release architecture: $ARCH" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PAYLOAD_DIR_NAME="mercury-linux-${ARCH}"
PAYLOAD_ROOT="$WORK_DIR/$PAYLOAD_DIR_NAME"

mercury_stage_repo_payload "$REPO_ROOT" "$PAYLOAD_ROOT"

mkdir -p "$OUT_DIR"
tar -C "$WORK_DIR" -czf "$OUT_DIR/${PAYLOAD_DIR_NAME}.tar.gz" "$PAYLOAD_DIR_NAME"

echo "wrote $OUT_DIR/${PAYLOAD_DIR_NAME}.tar.gz"
