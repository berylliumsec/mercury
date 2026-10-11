use anyhow::anyhow;
use clap::{Parser, Subcommand};
use control_api::{ControlRequest, ControlResponse, HealthResponse, SOCKET_PATH};
#[cfg(all(feature = "linux", unix))]
use linux_adapter::{CapabilityReport, EnforcementAdapter, LinuxAdapter, LinuxAdapterConfig};
use serde::Serialize;
use std::env;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Parser)]
#[command(name = "mercury-status")]
#[command(about = "Daemon status command for mercury")]
struct Args {
    #[arg(long, default_value = SOCKET_PATH, global = true)]
    socket: String,
    #[arg(long, default_value_t = false)]
    dashboard: bool,
    /// Exit 0 even when the daemon reports degraded conditions.
    #[arg(long, default_value_t = false)]
    ignore_degraded: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

/// Exit status when the daemon is up but degraded (see `HealthResponse::degraded_reasons`).
const EXIT_DEGRADED: i32 = 2;

#[derive(Debug, Subcommand)]
enum Command {
    Preflight {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Export the URL gateway CA certificate in PEM format
    CaCert,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PreflightCheck {
    ok: bool,
    actual: String,
    required: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PreflightReport {
    supported: bool,
    support_level: String,
    tested_release_target: String,
    tested_release_target_match: bool,
    host_platform: String,
    kernel_strict_supported: bool,
    linux_compat_supported: bool,
    recommended_backend_mode: String,
    architecture: PreflightCheck,
    systemd: PreflightCheck,
    kernel_version: PreflightCheck,
    bpffs: PreflightCheck,
    bpf_lsm: PreflightCheck,
    cgroup_v2: PreflightCheck,
    apparmor: PreflightCheck,
}

#[cfg(all(feature = "linux", unix))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct PreflightFacts {
    architecture: String,
    systemctl_path: Option<PathBuf>,
    systemd_runtime_present: bool,
    os_release: OsReleaseFacts,
    capabilities: CapabilityReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OsReleaseFacts {
    id: String,
    version_id: String,
    pretty_name: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let Args {
        socket,
        dashboard,
        ignore_degraded,
        command,
    } = args;

    let result = match command {
        Some(Command::Preflight { json }) => run_preflight(json).map(|()| true),
        Some(Command::CaCert) => run_ca_cert(socket).await.map(|()| true),
        None => run_health(socket, dashboard).await,
    };

    match result {
        Ok(true) => {}
        Ok(false) => {
            if !ignore_degraded {
                std::process::exit(EXIT_DEGRADED);
            }
        }
        Err(err) => {
            eprintln!("mercury-status failed: {err:#}");
            std::process::exit(1);
        }
    }
}

/// Telemetry-loss and audit-health line; kept separate from the main status
/// line so existing parsers see an unchanged first line.
fn telemetry_line(payload: &HealthResponse) -> String {
    format!(
        "events_dropped_ringbuf_total={} kernel_events_rate_limited_total={} kernel_deny_events_dropped_total={} events_dropped_queue_total={} backpressure_active={} backpressure_activations_total={} audit_write_failures_total={} audit_mirror_failures_total={} apparmor_records_lost_total={} policy_reload_failures_total={} policy_sync_enabled={} policy_sync_last_error={} enrollment_sync_error={}",
        payload.events_dropped_ringbuf_total,
        payload.kernel_events_rate_limited_total,
        payload.kernel_deny_events_dropped_total,
        payload.events_dropped_queue_total,
        payload.backpressure_active,
        payload.backpressure_activations_total,
        payload.audit_write_failures_total,
        payload.audit_mirror_failures_total,
        payload.apparmor_records_lost_total,
        payload.policy_reload_failures_total,
        payload.policy_sync_enabled,
        payload.policy_sync_last_error.as_deref().unwrap_or("none"),
        payload.enrollment_sync_error.as_deref().unwrap_or("none"),
    )
}

/// `degraded=<bool>` followed by one `degraded_reason=` line per reason.
fn degraded_lines(reasons: &[String]) -> Vec<String> {
    let mut lines = vec![format!("degraded={}", !reasons.is_empty())];
    lines.extend(
        reasons
            .iter()
            .map(|reason| format!("degraded_reason={reason}")),
    );
    lines
}

/// Prints daemon health; returns Ok(false) when the daemon is degraded.
async fn run_health(socket: String, dashboard: bool) -> anyhow::Result<bool> {
    let response = cli::send_request(&socket, &ControlRequest::Health).await?;
    match response {
        ControlResponse::Health(payload) => {
            println!(
                "daemon_up={} policy_version={} backend_mode={} kernel_ready={} kernel_program_version={} auto_enroll_active_rules={} unmatched_mode={} exec_hook={} network_hook={} filesystem_hook={} apparmor_enabled={} apparmor_parser_present={} dashboard_enabled={} dashboard_ready={} dashboard_url={} dashboard_error={} url_gateway_enabled={} url_gateway_ready={} url_gateway_http_proxy={} url_gateway_https_proxy={} url_gateway_error={} events_ingested_total={} events_dropped_queue_total={} unenrolled_events_suppressed_total={} ingest_backlog_len={} enrollment_sync_error={} dashboard_schema_version={} policy_versions_total={} pending_mcp_approvals={} active_dashboard_sessions={} active_sse_clients={} active_mcp_sessions={} dashboard_sqlite_bytes={}",
                payload.daemon_up,
                payload.policy_version,
                payload.backend_mode,
                payload.kernel_ready,
                payload.kernel_program_version,
                payload.auto_enroll_active_rules,
                payload.unmatched_mode,
                payload.hook_status.exec_hook,
                payload.hook_status.network_hook,
                payload.hook_status.filesystem_hook,
                payload.apparmor_enabled,
                payload.apparmor_parser_present,
                payload.dashboard_enabled,
                payload.dashboard_ready,
                payload.dashboard_url.as_deref().unwrap_or("none"),
                payload.dashboard_error.as_deref().unwrap_or("none"),
                payload.url_gateway_enabled,
                payload.url_gateway_ready,
                payload.url_gateway_http_proxy.as_deref().unwrap_or("none"),
                payload.url_gateway_https_proxy.as_deref().unwrap_or("none"),
                payload.url_gateway_error.as_deref().unwrap_or("none"),
                payload.events_ingested_total,
                payload.events_dropped_queue_total,
                payload.unenrolled_events_suppressed_total,
                payload.ingest_backlog_len,
                payload.enrollment_sync_error.as_deref().unwrap_or("none"),
                payload.dashboard_schema_version,
                payload.policy_versions_total,
                payload.pending_mcp_approvals,
                payload.active_dashboard_sessions,
                payload.active_sse_clients,
                payload.active_mcp_sessions,
                payload.dashboard_sqlite_bytes,
            );
            println!("{}", telemetry_line(&payload));

            if dashboard {
                if let Some(url) = payload.dashboard_url.as_ref() {
                    let reachable = dashboard_reachable(url).await;
                    println!("dashboard_reachable={} dashboard_url={}", reachable, url);
                } else {
                    println!("dashboard_reachable=false dashboard_url=none");
                }
            }

            let reasons = payload.degraded_reasons();
            for line in degraded_lines(&reasons) {
                println!("{line}");
            }
            Ok(reasons.is_empty())
        }
        ControlResponse::Error(err) => Err(anyhow!("status failed: {}: {}", err.code, err.message)),
        other => Err(anyhow!("unexpected response: {other:?}")),
    }
}

async fn run_ca_cert(socket: String) -> anyhow::Result<()> {
    let response = cli::send_request(&socket, &ControlRequest::GetCaCert).await?;
    match response {
        ControlResponse::CaCert(payload) => {
            // PEM to stdout for piping; metadata to stderr
            print!("{}", payload.pem);
            eprintln!("fingerprint_sha256={}", payload.fingerprint_sha256);
            eprintln!("not_after={}", payload.not_after);
            Ok(())
        }
        ControlResponse::Error(err) => Err(anyhow!("{}: {}", err.code, err.message)),
        other => Err(anyhow!("unexpected response: {other:?}")),
    }
}

#[cfg(all(feature = "linux", unix))]
fn run_preflight(json: bool) -> anyhow::Result<()> {
    let report = build_preflight_report(collect_preflight_facts());
    emit_preflight_report(&report, json)?;

    if report.supported {
        Ok(())
    } else {
        Err(anyhow!("linux host does not satisfy mercury prerequisites"))
    }
}

#[cfg(not(all(feature = "linux", unix)))]
fn run_preflight(_json: bool) -> anyhow::Result<()> {
    Err(anyhow!("preflight checks are only supported on Linux"))
}

#[cfg(all(feature = "linux", unix))]
fn collect_preflight_facts() -> PreflightFacts {
    let adapter = LinuxAdapter::new(LinuxAdapterConfig::default());
    let capabilities = adapter.check_capabilities();

    PreflightFacts {
        architecture: env::consts::ARCH.to_string(),
        systemctl_path: find_in_path("systemctl"),
        systemd_runtime_present: Path::new("/run/systemd/system").exists(),
        os_release: read_os_release(),
        capabilities,
    }
}

#[cfg(all(feature = "linux", unix))]
fn build_preflight_report(facts: PreflightFacts) -> PreflightReport {
    let tested_release_target = "ubuntu-24.04-x86_64".to_string();
    let tested_release_target_match = facts.architecture == "x86_64"
        && facts.os_release.id == "ubuntu"
        && facts.os_release.version_id == "24.04";
    let architecture = PreflightCheck {
        ok: facts.architecture == "x86_64",
        actual: facts.architecture,
        required: "x86_64".to_string(),
    };
    let systemd = PreflightCheck {
        ok: facts.systemctl_path.is_some() && facts.systemd_runtime_present,
        actual: describe_systemd(
            facts.systemctl_path.as_deref(),
            facts.systemd_runtime_present,
        ),
        required: "systemctl in PATH and /run/systemd/system present".to_string(),
    };
    let kernel_version = PreflightCheck {
        ok: facts.capabilities.kernel_version_ok,
        actual: facts.capabilities.kernel_release.clone(),
        required: "Linux >= 6.1".to_string(),
    };
    let bpffs = PreflightCheck {
        ok: facts.capabilities.bpf_fs_present,
        actual: if facts.capabilities.bpf_fs_present {
            "/sys/fs/bpf present".to_string()
        } else {
            "/sys/fs/bpf missing".to_string()
        },
        required: "/sys/fs/bpf mounted".to_string(),
    };
    let bpf_lsm = PreflightCheck {
        ok: facts.capabilities.bpf_lsm_available,
        actual: if facts.capabilities.bpf_lsm_available {
            "bpf LSM available".to_string()
        } else {
            "bpf LSM unavailable".to_string()
        },
        required: "/sys/kernel/security/lsm contains bpf".to_string(),
    };
    let cgroup_v2 = PreflightCheck {
        ok: facts.capabilities.cgroup_v2,
        actual: if facts.capabilities.cgroup_v2 {
            "/sys/fs/cgroup/cgroup.controllers present".to_string()
        } else {
            "cgroup v2 controllers missing".to_string()
        },
        required: "cgroup v2 mounted".to_string(),
    };
    let apparmor = PreflightCheck {
        ok: facts.capabilities.apparmor_enabled && facts.capabilities.apparmor_parser_present,
        actual: format!(
            "enabled={} parser_present={}",
            facts.capabilities.apparmor_enabled, facts.capabilities.apparmor_parser_present
        ),
        required: "AppArmor enabled and parser present".to_string(),
    };
    let kernel_strict_supported = architecture.ok
        && systemd.ok
        && kernel_version.ok
        && bpffs.ok
        && bpf_lsm.ok
        && cgroup_v2.ok;
    let linux_compat_supported = architecture.ok && systemd.ok && apparmor.ok;
    let supported = kernel_strict_supported || linux_compat_supported;
    let recommended_backend_mode = if kernel_strict_supported {
        "kernel_strict".to_string()
    } else if linux_compat_supported {
        "linux_compat".to_string()
    } else {
        "unsupported".to_string()
    };
    let support_level = if !supported {
        "unsupported".to_string()
    } else if tested_release_target_match {
        "fully_tested".to_string()
    } else {
        "compatible".to_string()
    };

    PreflightReport {
        supported,
        support_level,
        tested_release_target,
        tested_release_target_match,
        host_platform: facts.os_release.pretty_name,
        kernel_strict_supported,
        linux_compat_supported,
        recommended_backend_mode,
        architecture,
        systemd,
        kernel_version,
        bpffs,
        bpf_lsm,
        cgroup_v2,
        apparmor,
    }
}

#[cfg(all(feature = "linux", unix))]
fn emit_preflight_report(report: &PreflightReport, json: bool) -> anyhow::Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).map_err(|err| anyhow!("serialize json: {err}"))?
        );
        return Ok(());
    }

    println!("supported={}", report.supported);
    println!("support_level={}", report.support_level);
    println!("tested_release_target={}", report.tested_release_target);
    println!(
        "tested_release_target_match={}",
        report.tested_release_target_match
    );
    println!("host_platform={}", report.host_platform);
    println!("kernel_strict_supported={}", report.kernel_strict_supported);
    println!("linux_compat_supported={}", report.linux_compat_supported);
    println!(
        "recommended_backend_mode={}",
        report.recommended_backend_mode
    );
    println!(
        "check=architecture ok={} actual={} required={}",
        report.architecture.ok, report.architecture.actual, report.architecture.required
    );
    println!(
        "check=systemd ok={} actual={} required={}",
        report.systemd.ok, report.systemd.actual, report.systemd.required
    );
    println!(
        "check=kernel_version ok={} actual={} required={}",
        report.kernel_version.ok, report.kernel_version.actual, report.kernel_version.required
    );
    println!(
        "check=bpffs ok={} actual={} required={}",
        report.bpffs.ok, report.bpffs.actual, report.bpffs.required
    );
    println!(
        "check=bpf_lsm ok={} actual={} required={}",
        report.bpf_lsm.ok, report.bpf_lsm.actual, report.bpf_lsm.required
    );
    println!(
        "check=cgroup_v2 ok={} actual={} required={}",
        report.cgroup_v2.ok, report.cgroup_v2.actual, report.cgroup_v2.required
    );
    println!(
        "check=apparmor ok={} actual={} required={}",
        report.apparmor.ok, report.apparmor.actual, report.apparmor.required
    );

    Ok(())
}

fn describe_systemd(systemctl_path: Option<&Path>, systemd_runtime_present: bool) -> String {
    match (systemctl_path, systemd_runtime_present) {
        (Some(path), true) => format!("systemctl={} runtime=present", path.display()),
        (Some(path), false) => format!("systemctl={} runtime=missing", path.display()),
        (None, true) => "systemctl=missing runtime=present".to_string(),
        (None, false) => "systemctl=missing runtime=missing".to_string(),
    }
}

fn read_os_release() -> OsReleaseFacts {
    let text = fs::read_to_string("/etc/os-release").unwrap_or_default();
    parse_os_release(text.as_str())
}

fn parse_os_release(text: &str) -> OsReleaseFacts {
    let mut id = String::new();
    let mut version_id = String::new();
    let mut pretty_name = String::new();

    for line in text.lines() {
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let value = raw_value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        match key {
            "ID" => id = value,
            "VERSION_ID" => version_id = value,
            "PRETTY_NAME" => pretty_name = value,
            _ => {}
        }
    }

    if pretty_name.is_empty() {
        pretty_name = match (id.is_empty(), version_id.is_empty()) {
            (false, false) => format!("{id} {version_id}"),
            (false, true) => id.clone(),
            _ => "unknown".to_string(),
        };
    }

    OsReleaseFacts {
        id,
        version_id,
        pretty_name,
    }
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

async fn dashboard_reachable(url: &str) -> bool {
    let addr = if let Some(addr) = url.strip_prefix("http://") {
        addr
    } else if let Some(addr) = url.strip_prefix("https://") {
        addr
    } else {
        return false;
    };
    let target = normalize_probe_target(addr);
    matches!(
        timeout(Duration::from_millis(800), TcpStream::connect(target)).await,
        Ok(Ok(_))
    )
}

fn normalize_probe_target(addr: &str) -> String {
    let Ok(parsed) = addr.parse::<SocketAddr>() else {
        return addr.to_string();
    };

    match parsed {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, v4.port())).to_string()
        }
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            v6.port(),
            v6.flowinfo(),
            v6.scope_id(),
        ))
        .to_string(),
        _ => addr.to_string(),
    }
}

#[cfg(all(test, feature = "linux", unix))]
mod tests {
    use super::*;
    use linux_adapter::HookBackend;
    use serde_json::Value;

    fn supported_facts() -> PreflightFacts {
        PreflightFacts {
            architecture: "x86_64".to_string(),
            systemctl_path: Some(PathBuf::from("/usr/bin/systemctl")),
            systemd_runtime_present: true,
            os_release: OsReleaseFacts {
                id: "ubuntu".to_string(),
                version_id: "24.04".to_string(),
                pretty_name: "Ubuntu 24.04 LTS".to_string(),
            },
            capabilities: CapabilityReport {
                kernel_release: "6.8.0".to_string(),
                kernel_version_ok: true,
                bpf_fs_present: true,
                bpf_lsm_available: true,
                cgroup_v2: true,
                apparmor_enabled: true,
                apparmor_parser_present: true,
                selected_filesystem_backend: HookBackend::EbpfLsm,
            },
        }
    }

    fn health_payload() -> HealthResponse {
        serde_json::from_value(serde_json::json!({
            "daemon_up": true,
            "policy_version": "v1",
            "backend_mode": "kernel_strict",
            "kernel_ready": true,
            "kernel_program_version": "kernel-ebpf-v16",
            "auto_enroll_active_rules": 0,
            "unmatched_mode": "observe",
            "hook_status": {"exec_hook": "EbpfLsm", "network_hook": "EbpfLsm", "filesystem_hook": "EbpfLsm"},
            "dashboard_enabled": false,
            "dashboard_ready": false,
            "events_ingested_total": 10,
            "events_dropped_queue_total": 1,
            "unenrolled_events_suppressed_total": 0,
            "ingest_backlog_len": 0,
            "enrollment_sync_error": null,
            "events_dropped_ringbuf_total": 7,
            "audit_write_failures_total": 0
        }))
        .expect("health payload")
    }

    #[test]
    fn telemetry_line_reports_loss_and_audit_counters() {
        let mut payload = health_payload();
        payload.kernel_events_rate_limited_total = 3;
        payload.audit_write_failures_total = 2;
        payload.policy_sync_last_error = Some("http 503".to_string());
        let line = telemetry_line(&payload);
        for expected in [
            "events_dropped_ringbuf_total=7",
            "kernel_events_rate_limited_total=3",
            "kernel_deny_events_dropped_total=0",
            "events_dropped_queue_total=1",
            "backpressure_active=false",
            "audit_write_failures_total=2",
            "policy_sync_last_error=http 503",
            "enrollment_sync_error=none",
        ] {
            assert!(line.contains(expected), "missing {expected} in {line}");
        }
    }

    #[test]
    fn degraded_lines_list_every_reason() {
        let healthy = health_payload();
        assert_eq!(
            degraded_lines(&healthy.degraded_reasons()),
            vec!["degraded=false"]
        );

        let mut degraded = health_payload();
        degraded.kernel_ready = false;
        degraded.audit_write_failures_total = 1;
        assert_eq!(
            degraded_lines(&degraded.degraded_reasons()),
            vec![
                "degraded=true".to_string(),
                "degraded_reason=kernel enforcement is not ready".to_string(),
                "degraded_reason=1 audit write failures since start".to_string(),
            ]
        );
    }

    #[test]
    fn rewrites_unspecified_ipv4_for_local_probe() {
        assert_eq!(normalize_probe_target("0.0.0.0:7480"), "127.0.0.1:7480");
    }

    #[test]
    fn leaves_normal_targets_unchanged() {
        assert_eq!(normalize_probe_target("127.0.0.1:7480"), "127.0.0.1:7480");
        assert_eq!(normalize_probe_target("10.1.2.3:7480"), "10.1.2.3:7480");
    }

    #[test]
    fn preflight_report_is_supported_when_all_checks_pass() {
        let report = build_preflight_report(supported_facts());
        assert!(report.supported);
        assert!(report.architecture.ok);
        assert!(report.systemd.ok);
        assert!(report.kernel_version.ok);
        assert!(report.bpffs.ok);
        assert!(report.bpf_lsm.ok);
        assert!(report.cgroup_v2.ok);
        assert!(report.apparmor.ok);
        assert!(report.kernel_strict_supported);
        assert!(report.linux_compat_supported);
        assert_eq!(report.recommended_backend_mode, "kernel_strict");
        assert_eq!(report.support_level, "fully_tested");
        assert!(report.tested_release_target_match);
    }

    #[test]
    fn preflight_report_fails_when_kernel_prerequisite_is_missing() {
        let mut facts = supported_facts();
        facts.capabilities.bpf_lsm_available = false;

        let report = build_preflight_report(facts);
        assert!(report.supported);
        assert!(!report.bpf_lsm.ok);
        assert_eq!(report.bpf_lsm.actual, "bpf LSM unavailable");
        assert!(!report.kernel_strict_supported);
        assert!(report.linux_compat_supported);
        assert_eq!(report.recommended_backend_mode, "linux_compat");
        assert_eq!(report.support_level, "fully_tested");
    }

    #[test]
    fn preflight_json_output_has_expected_shape() {
        let report = build_preflight_report(supported_facts());
        let rendered = serde_json::to_string(&report).expect("json");
        let parsed: Value = serde_json::from_str(&rendered).expect("parse json");

        assert_eq!(parsed["supported"], Value::Bool(true));
        assert_eq!(
            parsed["support_level"],
            Value::String("fully_tested".to_string())
        );
        assert_eq!(
            parsed["recommended_backend_mode"],
            Value::String("kernel_strict".to_string())
        );
        assert_eq!(
            parsed["architecture"]["required"],
            Value::String("x86_64".to_string())
        );
        assert_eq!(
            parsed["kernel_version"]["actual"],
            Value::String("6.8.0".to_string())
        );
        assert_eq!(parsed["bpf_lsm"]["ok"], Value::Bool(true));
    }

    #[test]
    fn preflight_report_marks_non_tested_linux_hosts_as_compatible() {
        let mut facts = supported_facts();
        facts.os_release = OsReleaseFacts {
            id: "debian".to_string(),
            version_id: "12".to_string(),
            pretty_name: "Debian GNU/Linux 12".to_string(),
        };

        let report = build_preflight_report(facts);
        assert!(report.supported);
        assert_eq!(report.support_level, "compatible");
        assert!(!report.tested_release_target_match);
        assert_eq!(report.host_platform, "Debian GNU/Linux 12");
    }

    #[test]
    fn describe_systemd_reflects_missing_runtime() {
        assert_eq!(
            describe_systemd(Some(Path::new("/usr/bin/systemctl")), false),
            "systemctl=/usr/bin/systemctl runtime=missing"
        );
        assert_eq!(
            describe_systemd(None, false),
            "systemctl=missing runtime=missing"
        );
    }

    #[test]
    fn read_os_release_parses_key_fields() {
        let parsed = parse_os_release(
            "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n",
        );
        assert_eq!(parsed.id, "ubuntu");
        assert_eq!(parsed.version_id, "24.04");
        assert_eq!(parsed.pretty_name, "Ubuntu 24.04.1 LTS");
    }
}
