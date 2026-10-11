#!/usr/bin/env python3
"""Tests for select_e2e.py. Run: python3 scripts/ci/test_select_e2e.py"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import select_e2e  # noqa: E402
from select_e2e import LINUX_SUITES, select  # noqa: E402


def outputs(*paths):
    return select(list(paths)).outputs()


class SelectE2eTest(unittest.TestCase):
    def test_docs_only_runs_nothing(self):
        out = outputs("README.md", "docs/install.md", "crates/daemon/README.md", "images/x.png")
        self.assertEqual(out["run_linux_e2e"], "false")
        self.assertEqual(out["run_linux_release"], "false")
        self.assertEqual(out["run_kernel_enforcement"], "false")

    def test_empty_diff_runs_nothing(self):
        self.assertEqual(outputs()["run_linux_e2e"], "false")

    def test_single_suite_script_selects_only_that_suite(self):
        out = outputs("scripts/run_linux_e2e_gateway_advanced.sh")
        self.assertEqual(out["linux_suites"], "gateway_advanced")
        self.assertEqual(out["run_kernel_enforcement"], "false")

    def test_gateway_module_selects_gateway_suites(self):
        out = outputs("crates/daemon/src/url_gateway.rs", "crates/daemon/src/model_capture.rs")
        self.assertEqual(out["linux_suites"], "runtime_smoke,gateway_advanced")
        self.assertEqual(out["run_linux_release"], "false")

    def test_dashboard_ui_selects_browser_suites(self):
        out = outputs("dashboard/linux-ui/src/App.tsx")
        self.assertEqual(out["linux_suites"], "playwright,dashboard_and_errors")
        self.assertEqual(out["run_kernel_enforcement"], "false")

    def test_kernel_change_skips_ui(self):
        out = outputs("crates/kernel-ebpf/src/mercury_kern.c")
        self.assertNotIn("playwright", out["linux_suites"])
        self.assertIn("extended_hooks", out["linux_suites"])
        self.assertEqual(out["run_kernel_enforcement"], "true")

    def test_daemon_core_runs_all_linux(self):
        out = outputs("crates/daemon/src/lib.rs")
        self.assertEqual(out["linux_suites"], ",".join(LINUX_SUITES))
        self.assertEqual(out["run_linux_release"], "true")

    def test_shared_types_and_lockfile_run_everything(self):
        for path in ("crates/core-types/src/lib.rs", "Cargo.lock", "crates/brand-new/src/lib.rs"):
            out = outputs(path)
            self.assertEqual(out["linux_suites"], ",".join(LINUX_SUITES), path)
            self.assertEqual(out["run_kernel_enforcement"], "true", path)
            self.assertEqual(out["run_linux_release"], "true", path)

    def test_unknown_path_fails_safe_to_everything(self):
        out = outputs("something/new.txt")
        self.assertEqual(out["linux_suites"], ",".join(LINUX_SUITES))
        self.assertEqual(out["run_linux_release"], "true")

    def test_packaging_and_agent_harness_paths(self):
        out = outputs("deploy/systemd/mercuryd.service", "samples/config.yaml")
        self.assertEqual(out["run_linux_e2e"], "false")
        self.assertEqual(out["run_linux_release"], "true")
        out = outputs("samples/oss-agents/langchain_major_matrix.py")
        self.assertEqual(out["run_kernel_enforcement"], "true")
        self.assertEqual(out["run_linux_e2e"], "false")

    def test_suite_order_is_stable_and_deduplicated(self):
        out = outputs(
            "scripts/run_linux_e2e_rate_limit.sh",
            "scripts/run_linux_e2e_extended_hooks.sh",
            "scripts/run_linux_e2e_rate_limit.sh",
        )
        self.assertEqual(out["linux_suites"], "extended_hooks,rate_limit")

    def test_every_suite_has_a_script(self):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        for suite in LINUX_SUITES:
            if suite == "playwright":
                continue
            self.assertTrue(
                os.path.exists(os.path.join(root, "scripts", f"run_linux_e2e_{suite}.sh")), suite
            )

    def test_manual_suite_override(self):
        out = select_e2e.select_named("gateway_advanced, playwright,kernel_enforcement").outputs()
        self.assertEqual(out["linux_suites"], "playwright,gateway_advanced")
        self.assertEqual(out["run_kernel_enforcement"], "true")
        self.assertEqual(out["run_linux_release"], "false")
        with self.assertRaises(SystemExit):
            select_e2e.select_named("nope")

    def test_all_rule_targets_are_valid(self):
        selection = select_e2e.Selection()
        for _, targets in select_e2e.RULES:
            for token in targets:
                selection.add(token, "rule")


if __name__ == "__main__":
    unittest.main()
