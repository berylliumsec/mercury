DASHBOARD_DIR := dashboard/linux-ui

TIMEOUT_SECS ?= 300
MAJOR_TIMEOUT_SECS ?= 1200
MAX_OVERHEAD_PERCENT ?= 5

.PHONY: format format-check lint test test-kernel e2e-smoke e2e-full e2e-release-local

format:
	cargo fmt --all
	npm --prefix $(DASHBOARD_DIR) run format

format-check:
	cargo fmt --all -- --check
	npm --prefix $(DASHBOARD_DIR) run format:check

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	npm --prefix $(DASHBOARD_DIR) run lint
	npm --prefix $(DASHBOARD_DIR) run typecheck

test:
	cargo test --workspace
	npm --prefix $(DASHBOARD_DIR) run test

test-kernel:
	sudo -E env PATH="$(PATH)" TIMEOUT_SECS=$(TIMEOUT_SECS) ./samples/oss-agents/run_smolagents_policy_test.sh
	sudo -E env PATH="$(PATH)" TIMEOUT_SECS=$(MAJOR_TIMEOUT_SECS) ./samples/oss-agents/run_major_agents_policy_test.sh
	sudo -E env PATH="$(PATH)" MAX_OVERHEAD_PERCENT=$(MAX_OVERHEAD_PERCENT) ./samples/oss-agents/benchmark_kernel_overhead.sh

e2e-smoke:
	sudo -E env PATH="$(PATH)" ./scripts/run_linux_e2e_smoke.sh

e2e-full:
	sudo -E env PATH="$(PATH)" ./scripts/run_linux_e2e_full.sh

e2e-release-local:
	sudo -E env PATH="$(PATH)" ./scripts/run_linux_release_smoke.sh
