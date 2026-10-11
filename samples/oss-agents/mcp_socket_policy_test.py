#!/usr/bin/env python3
"""
MCP socket-level policy enforcement integration test.

Starts a temporary daemon, loads a policy with an MCP server configured,
then sends RegisterMcpServer / AuthorizeMcpToolCall / CompleteMcpToolCall
requests directly over the control socket and asserts the correct decisions.

Required:
    - mercuryd and mercury-policy binaries discoverable in BIN_DIR (default: target/release, then target/debug)
  - No other daemon running on the test socket path

Exit 0 on pass, non-zero on failure.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_bin_dir() -> Path:
    """Locate the binary directory, preferring release artifacts."""
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    for candidate in [repo_root / "target" / "release", repo_root / "target" / "debug"]:
        if (candidate / "mercuryd").exists():
            return candidate
    sys.exit(
        "error: could not find mercuryd binary in target/release or target/debug\n"
        "hint: run 'cargo build --workspace'"
    )


def send_request(sock_path: str, request: dict) -> dict:
    """Send one newline-delimited JSON request and return the parsed response."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        s.sendall((json.dumps(request) + "\n").encode())
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                break
        line = buf.split(b"\n")[0].decode().strip()
    return json.loads(line)


def wait_for_socket(
    sock_path: str,
    timeout: float = 30.0,
    daemon_proc: subprocess.Popen | None = None,
    stderr_path: Path | None = None,
) -> None:
    """Block until the daemon socket is ready or timeout expires."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(sock_path):
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(sock_path)
                    return
            except OSError:
                pass
        if daemon_proc is not None and daemon_proc.poll() is not None:
            stderr = ""
            if stderr_path is not None and stderr_path.exists():
                stderr = stderr_path.read_text().strip()
            detail = f"; daemon exited with rc={daemon_proc.returncode}"
            if stderr:
                detail += f"; stderr: {stderr}"
            sys.exit(f"error: daemon socket {sock_path!r} never became ready{detail}")
        time.sleep(0.1)
    stderr = ""
    if stderr_path is not None and stderr_path.exists():
        stderr = stderr_path.read_text().strip()
    detail = f" within {timeout}s"
    if daemon_proc is not None and daemon_proc.poll() is not None:
        detail += f"; daemon exited with rc={daemon_proc.returncode}"
    if stderr:
        detail += f"; stderr: {stderr}"
    sys.exit(f"error: daemon socket {sock_path!r} did not appear{detail}")


def assert_eq(label: str, actual, expected) -> None:
    if actual != expected:
        sys.exit(f"FAIL [{label}]: expected {expected!r}, got {actual!r}")
    print(f"  ok  {label}")


# ---------------------------------------------------------------------------
# Policy YAML
# ---------------------------------------------------------------------------

MCP_POLICY = """
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
    workspace_roots: []
    file_allow: []
    file_deny: []
    exec_allow: []
    exec_deny: []
    network_allow: []
    network_deny: []
    url_allow: []
    url_deny: []
    mcp:
      default_tool_action: deny
      servers:
        - id: integration_test_mcp
          transport: stdio
          exec_path_glob: "/**"
          tools:
            allow:
              - safe_read
            deny: []
            require_approval: []
signature:
  key_id: local-dev
  alg: ed25519
  sig: ''
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    bin_dir = Path(os.environ.get("BIN_DIR", "")) if os.environ.get("BIN_DIR") else find_bin_dir()
    mercuryd = str(bin_dir / "mercuryd")

    with tempfile.TemporaryDirectory(prefix="mercury-mcp-test-") as workdir:
        workdir = Path(workdir)
        sock_path = str(workdir / "mercuryd.sock")
        policy_path = workdir / "policy.yaml"
        config_path = workdir / "config.yaml"
        audit_path = workdir / "audit.jsonl"
        server_proc = subprocess.Popen(["/bin/sleep", "600"])

        policy_path.write_text(MCP_POLICY)

        config_path.write_text(f"""\
socket_path: {sock_path}
policy_path: {policy_path}
audit_jsonl_path: {audit_path}
log_level: warn
mirror_to_journald: false
signature_verification: warn_on_invalid
policy_unavailable_mode: fail_closed
backend_mode: kernel_strict
filesystem_backend: ebpf_lsm
cgroup_base: {workdir}/cgroup
kernel:
  bpffs_path: /sys/fs/bpf
  cgroup_root: /sys/fs/cgroup
  event_buffer_pages: 64
  unmatched_host_mode: observe
dashboard:
  enabled: false
url_gateway:
  enabled: false
  required: false
""")

        daemon_stdout_path = workdir / "daemon.out"
        daemon_stderr_path = workdir / "daemon.err"

        # Start daemon
        with daemon_stdout_path.open("wb") as daemon_stdout, daemon_stderr_path.open("wb") as daemon_stderr:
            daemon_proc = subprocess.Popen(
                [mercuryd, "--config", str(config_path)],
                stdout=daemon_stdout,
                stderr=daemon_stderr,
            )
            try:
                wait_for_socket(
                    sock_path,
                    timeout=30.0,
                    daemon_proc=daemon_proc,
                    stderr_path=daemon_stderr_path,
                )
                print("daemon ready, running MCP socket integration tests...")

                # ----------------------------------------------------------------
                # Test 1: RegisterMcpServer
                # ----------------------------------------------------------------
                reg_resp = send_request(sock_path, {
                    "RegisterMcpServer": {
                        "pid": server_proc.pid,
                        "ppid": os.getpid(),
                        "uid": os.getuid(),
                        "gid": os.getgid(),
                        "profile": "default",
                        "cmdline": ["/bin/sleep", "600"],
                        "cwd": "/tmp",
                        "server_id": "integration_test_mcp",
                    }
                })
                if "RegisterMcpServer" not in reg_resp:
                    sys.exit(f"FAIL [RegisterMcpServer]: unexpected response: {reg_resp}")
                mcp_session_id = reg_resp["RegisterMcpServer"]["mcp_session_id"]
                assert mcp_session_id, "mcp_session_id must not be empty"
                print(f"  ok  RegisterMcpServer (session={mcp_session_id[:8]}...)")

                # ----------------------------------------------------------------
                # Test 2: AuthorizeMcpToolCall — denied by default action
                # ----------------------------------------------------------------
                deny_resp = send_request(sock_path, {
                    "AuthorizeMcpToolCall": {
                        "mcp_session_id": mcp_session_id,
                        "tool_name": "rm_all_files",
                        "tool_call_id": "tc-deny-001",
                        "arguments_json": "{}",
                    }
                })
                if "AuthorizeMcpToolCall" not in deny_resp:
                    sys.exit(f"FAIL [AuthorizeMcpToolCall deny]: unexpected response: {deny_resp}")
                assert_eq(
                    "AuthorizeMcpToolCall deny",
                    deny_resp["AuthorizeMcpToolCall"]["decision"],
                    "deny",
                )

                # ----------------------------------------------------------------
                # Test 3: AuthorizeMcpToolCall — explicitly allowed tool
                # ----------------------------------------------------------------
                allow_resp = send_request(sock_path, {
                    "AuthorizeMcpToolCall": {
                        "mcp_session_id": mcp_session_id,
                        "tool_name": "safe_read",
                        "tool_call_id": "tc-allow-001",
                        "arguments_json": '{"path": "/tmp/test.txt"}',
                    }
                })
                if "AuthorizeMcpToolCall" not in allow_resp:
                    sys.exit(f"FAIL [AuthorizeMcpToolCall allow]: unexpected response: {allow_resp}")
                assert_eq(
                    "AuthorizeMcpToolCall allow",
                    allow_resp["AuthorizeMcpToolCall"]["decision"],
                    "allow",
                )

                # ----------------------------------------------------------------
                # Test 4: CompleteMcpToolCall — marks the call as done
                # ----------------------------------------------------------------
                complete_resp = send_request(sock_path, {
                    "CompleteMcpToolCall": {
                        "mcp_session_id": mcp_session_id,
                        "tool_call_id": "tc-allow-001",
                        "status": "success",
                    }
                })
                if "CompleteMcpToolCall" not in complete_resp:
                    sys.exit(f"FAIL [CompleteMcpToolCall]: unexpected response: {complete_resp}")
                assert_eq(
                    "CompleteMcpToolCall completed",
                    complete_resp["CompleteMcpToolCall"]["completed"],
                    True,
                )

                # ----------------------------------------------------------------
                # Test 5: Duplicate CompleteMcpToolCall returns not-found
                # ----------------------------------------------------------------
                complete2_resp = send_request(sock_path, {
                    "CompleteMcpToolCall": {
                        "mcp_session_id": mcp_session_id,
                        "tool_call_id": "tc-allow-001",
                        "status": "success",
                    }
                })
                if "Error" not in complete2_resp:
                    sys.exit(f"FAIL [CompleteMcpToolCall duplicate]: unexpected response: {complete2_resp}")
                assert_eq(
                    "CompleteMcpToolCall duplicate error code",
                    complete2_resp["Error"]["code"],
                    "MCP_TOOL_CALL_NOT_FOUND",
                )

                # ----------------------------------------------------------------
                # Test 6: Unknown MCP session returns an error
                # ----------------------------------------------------------------
                unknown_resp = send_request(sock_path, {
                    "AuthorizeMcpToolCall": {
                        "mcp_session_id": "00000000-dead-beef-0000-000000000000",
                        "tool_name": "some_tool",
                        "tool_call_id": "tc-unknown-001",
                        "arguments_json": "{}",
                    }
                })
                if "Error" not in unknown_resp:
                    sys.exit(f"FAIL [unknown session]: expected Error response, got: {unknown_resp}")
                assert_eq(
                    "unknown session error code",
                    unknown_resp["Error"]["code"],
                    "MCP_SESSION_NOT_FOUND",
                )

                print("\nmcp_socket_policy_test: PASS")

            finally:
                daemon_proc.send_signal(signal.SIGTERM)
                try:
                    daemon_proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    daemon_proc.kill()
                server_proc.terminate()
                try:
                    server_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server_proc.kill()


if __name__ == "__main__":
    main()
