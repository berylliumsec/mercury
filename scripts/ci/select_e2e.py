#!/usr/bin/env python3
"""Pick the local end-to-end work a change actually needs.

Each changed path is matched against RULES (first match wins) and the union of
the matched targets decides what runs:

  linux_suites        suites passed to run_linux_e2e_smoke.sh via MERCURY_E2E_SUITES
  linux_release       run the packaged Linux release smoke in a disposable host
  kernel_enforcement  run the local agent-framework harnesses + overhead gate

A path that matches no rule selects everything, so a new directory or file type
never silently loses coverage. Manual runs without --suites select everything.

Usage:
  select_e2e.py --base <sha> [--head <sha>]   # diff base...head
  select_e2e.py --all
  select_e2e.py --files a.rs b.sh            # explicit paths (tests, local use)
  select_e2e.py --suites gateway_advanced,kernel_enforcement   # manual override

When GITHUB_OUTPUT is set the result is also written there as step outputs.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field

LINUX_SUITES = (
    "playwright",
    "backend_load",
    "runtime_smoke",
    "exec_regression",
    "mmap_regression",
    "extended_hooks",
    "observe_and_lifecycle",
    "rate_limit",
    "mcp_and_audit",
    "policy_features",
    "gateway_advanced",
    "dashboard_and_errors",
)

# Target tokens: "linux:<suite>", "linux:*", "linux_release",
# "kernel_enforcement", "*" (everything).
ALL = ("*",)
NONE: tuple[str, ...] = ()

KERNEL_SUITES = (
    "linux:backend_load",
    "linux:runtime_smoke",
    "linux:exec_regression",
    "linux:mmap_regression",
    "linux:extended_hooks",
    "linux:observe_and_lifecycle",
    "linux:rate_limit",
    "linux:gateway_advanced",
)

# (glob, targets). Globs use fnmatch semantics where "*" also crosses "/".
RULES: list[tuple[str, tuple[str, ...]]] = [
    # ── no runtime impact ──────────────────────────────────────────────────
    ("*.md", NONE),
    ("docs/*", NONE),
    ("images/*", NONE),
    ("LICENSE", NONE),
    (".gitignore", NONE),
    ("fuzz/*", NONE),
    ("tools/*", NONE),
    (".github/workflows/quality.yml", NONE),
    (".github/workflows/pr-title.yml", NONE),
    (".github/workflows/github-pages-demo.yml", NONE),
    (".github/workflows/linux-release.yml", NONE),
    (".github/release-please-config.json", NONE),
    (".github/.release-please-manifest.json", NONE),
    ("scripts/run_linux_e2e_demo.sh", NONE),
    ("scripts/run_linux_e2e_runtime_only.sh", NONE),
    # ── CI plumbing ────────────────────────────────────────────────────────
    ("scripts/ci/*", ALL),
    # ── e2e scripts: a suite script selects only itself ────────────────────
    ("scripts/run_linux_e2e_smoke.sh", ("linux:*",)),
    ("scripts/linux_e2e_static_server.py", ("linux:*",)),
    *[(f"scripts/run_linux_e2e_{s}.sh", (f"linux:{s}",)) for s in LINUX_SUITES],
    ("scripts/run_linux_e2e_full.sh", ("kernel_enforcement",)),
    # ── packaging / install ────────────────────────────────────────────────
    ("scripts/run_linux_release_smoke.sh", ("linux_release",)),
    ("scripts/build_linux_release_bundle.sh", ("linux_release",)),
    ("scripts/render_linux_installer.sh", ("linux_release",)),
    ("scripts/install_mercury_system.sh", ("linux_release",)),
    ("scripts/uninstall_mercury_system.sh", ("linux_release",)),
    ("scripts/lib/*", ("linux_release",)),
    ("scripts/setup_ci_linux_build_deps.sh", ("linux_release",)),
    ("scripts/setup-agent-trust.sh", ("linux_release",)),
    ("deploy/*", ("linux_release",)),
    ("samples/config.yaml", ("linux_release",)),
    ("samples/policy.yaml", ("linux_release",)),
    ("samples/oss-agents/*", ("kernel_enforcement",)),
    # ── dashboard ──────────────────────────────────────────────────────────
    ("dashboard/linux-ui/e2e/*", ("linux:playwright",)),
    ("dashboard/*", ("linux:playwright", "linux:dashboard_and_errors")),
    # ── Rust crates, most specific first ───────────────────────────────────
    ("crates/kernel-ebpf/*", (*KERNEL_SUITES, "kernel_enforcement")),
    ("crates/kernel-runtime/*", (*KERNEL_SUITES, "kernel_enforcement")),
    ("crates/kernel-matcher/*", (*KERNEL_SUITES, "kernel_enforcement")),
    ("crates/linux-adapter/*", ("linux:*", "kernel_enforcement")),
    ("crates/daemon/src/url_gateway*.rs", ("linux:runtime_smoke", "linux:gateway_advanced")),
    ("crates/daemon/src/model_capture.rs", ("linux:runtime_smoke", "linux:gateway_advanced")),
    (
        "crates/daemon/src/dashboard*.rs",
        ("linux:playwright", "linux:dashboard_and_errors", "linux:policy_features"),
    ),
    ("crates/daemon/src/policy_sync.rs", ("linux:policy_features",)),
    ("crates/daemon/*", ("linux:*", "linux_release")),
    (
        "crates/audit/*",
        ("linux:runtime_smoke", "linux:mcp_and_audit", "linux:observe_and_lifecycle"),
    ),
    ("crates/launcher/*", ("linux:*", "kernel_enforcement")),
    ("crates/cli/*", ("linux:*", "linux_release")),
    ("crates/policy-engine/*", ("linux:*", "kernel_enforcement")),
    # control-api, core-types, platform-traits, and anything new under crates/
    ("crates/*", ALL),
    ("Cargo.toml", ALL),
    ("Cargo.lock", ALL),
    ("rust-toolchain*", ALL),
    ("Makefile", ALL),
]


@dataclass
class Selection:
    linux_suites: set[str] = field(default_factory=set)
    linux_release: bool = False
    kernel_enforcement: bool = False
    reasons: dict[str, list[str]] = field(default_factory=dict)

    def add(self, token: str, path: str) -> None:
        self.reasons.setdefault(token, []).append(path)
        if token == "*":
            self.linux_suites.update(LINUX_SUITES)
            self.linux_release = True
            self.kernel_enforcement = True
        elif token == "linux:*":
            self.linux_suites.update(LINUX_SUITES)
        elif token.startswith("linux:"):
            self.linux_suites.add(token.removeprefix("linux:"))
        elif token == "linux_release":
            self.linux_release = True
        elif token == "kernel_enforcement":
            self.kernel_enforcement = True
        else:
            raise ValueError(f"unknown target token {token!r}")

    def outputs(self) -> dict[str, str]:
        linux = [s for s in LINUX_SUITES if s in self.linux_suites]
        return {
            "linux_suites": ",".join(linux),
            "run_linux_e2e": str(bool(linux)).lower(),
            "run_linux_release": str(self.linux_release).lower(),
            "run_kernel_enforcement": str(self.kernel_enforcement).lower(),
        }


def targets_for(path: str) -> tuple[str, ...]:
    for pattern, targets in RULES:
        if fnmatch.fnmatchcase(path, pattern):
            return targets
    return ALL


def select(paths: list[str]) -> Selection:
    selection = Selection()
    for path in paths:
        for token in targets_for(path):
            selection.add(token, path)
    return selection


def select_all() -> Selection:
    selection = Selection()
    selection.add("*", "(full run)")
    return selection


def select_named(names: str) -> Selection:
    """Explicit list of suites and/or job names; "all" selects everything."""
    selection = Selection()
    for name in (n.strip() for n in names.split(",")):
        if not name:
            continue
        if name == "all":
            selection.add("*", "(manual)")
        elif name in ("linux_release", "kernel_enforcement"):
            selection.add(name, "(manual)")
        elif name in LINUX_SUITES:
            selection.add(f"linux:{name}", "(manual)")
        else:
            raise SystemExit(f"error: unknown suite or job {name!r}")
    return selection


def changed_files(base: str, head: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--base", help="base commit for the diff")
    group.add_argument("--all", action="store_true", help="select everything")
    group.add_argument("--files", nargs="*", help="explicit changed paths")
    group.add_argument("--suites", help="comma-separated suites/jobs to run")
    parser.add_argument("--head", default="HEAD", help="head commit (default HEAD)")
    args = parser.parse_args(argv)

    if args.all:
        selection = select_all()
    elif args.suites is not None:
        selection = select_named(args.suites)
    else:
        paths = args.files if args.files is not None else changed_files(args.base, args.head)
        selection = select(paths)

    outputs = selection.outputs()
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write(f"{key}={value}\n")

    summary = {"outputs": outputs, "reasons": selection.reasons}
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write("### E2E selection\n\n| Output | Value |\n| --- | --- |\n")
            for key, value in outputs.items():
                handle.write(f"| `{key}` | `{value or '-'}` |\n")
            handle.write("\n<details><summary>Why</summary>\n\n")
            for token, paths in sorted(selection.reasons.items()):
                shown = ", ".join(f"`{p}`" for p in paths[:10])
                more = f" (+{len(paths) - 10} more)" if len(paths) > 10 else ""
                handle.write(f"- **{token}**: {shown}{more}\n")
            handle.write("\n</details>\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
