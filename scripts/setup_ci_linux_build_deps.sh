#!/usr/bin/env bash
set -euo pipefail

bpftool_can_dump_btf() {
  local candidate
  candidate="$1"

  [[ -x "${candidate}" ]] || return 1

  "${candidate}" btf dump file /sys/kernel/btf/vmlinux format c >/dev/null 2>&1
}

resolve_bpftool() {
  local release candidate
  release="$(uname -r)"

  if command -v bpftool >/dev/null 2>&1 && bpftool_can_dump_btf "$(command -v bpftool)"; then
    command -v bpftool
    return 0
  fi

  for candidate in \
    "/usr/lib/linux-tools/${release}/bpftool" \
    "/usr/lib/linux-tools-${release}/bpftool"
  do
    if bpftool_can_dump_btf "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  while IFS= read -r candidate; do
    if bpftool_can_dump_btf "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done < <(find /usr/lib /usr/libexec -name bpftool -type f 2>/dev/null | sort)

  return 1
}

emit_bpftool_diagnostics() {
  echo "warning: unable to pre-resolve a working bpftool binary" >&2
  echo "warning: command -v bpftool -> $(command -v bpftool || echo missing)" >&2

  if command -v bpftool >/dev/null 2>&1; then
    echo "warning: bpftool version output:" >&2
    bpftool version 2>&1 | sed -n '1,10p' >&2 || true
  fi

  find /usr/lib /usr/libexec \
    \( -name bpftool -o -path '*/linux-tools*' -o -path '*/linux-hwe-*tools*' \) \
    -print 2>/dev/null | sort | sed -n '1,80p' >&2 || true
}

sudo apt-get update
sudo apt-get install -y clang llvm linux-tools-common openssl

if ! resolve_bpftool >/dev/null 2>&1; then
  sudo apt-get install -y "linux-tools-$(uname -r)" "linux-cloud-tools-$(uname -r)" || \
    sudo apt-get install -y linux-tools-azure linux-cloud-tools-azure
fi

if bpftool_path="$(resolve_bpftool 2>/dev/null)"; then
  bpftool_dir="$(dirname "${bpftool_path}")"

  echo "Using bpftool at ${bpftool_path}"
  "${bpftool_path}" version >/dev/null

  if [[ -n "${GITHUB_ENV:-}" ]]; then
    printf 'BPFTOOL=%s\n' "${bpftool_path}" >> "${GITHUB_ENV}"
  fi

  if [[ -n "${GITHUB_PATH:-}" ]]; then
    printf '%s\n' "${bpftool_dir}" >> "${GITHUB_PATH}"
  fi
else
  emit_bpftool_diagnostics
  echo "warning: continuing without exporting BPFTOOL; crates/kernel-ebpf/build.rs will perform its own discovery" >&2
fi