use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, bail};
use audit::{ChainReport, Severity, VerifyOptions};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "mercury-audit")]
#[command(about = "Audit log tools for mercury")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify the HMAC integrity chain across an audit log rotation set.
    /// Exits 0 when intact, 1 on any integrity error, 2 on usage or I/O errors.
    Verify {
        /// Integrity key file (64 hex characters); `-` reads the key from stdin
        #[arg(long, default_value = audit::DEFAULT_INTEGRITY_KEY_PATH)]
        key: String,
        /// The files are only part of the set: a missing predecessor of the
        /// first file is a warning instead of an error
        #[arg(long, default_value_t = false)]
        partial: bool,
        /// Print the full report as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Audit files, oldest first (numbered rotation suffixes are ordered
        /// automatically). Defaults to the rotation set of
        /// /var/log/mercury/audit.jsonl
        files: Vec<PathBuf>,
    },
}

fn main() -> ExitCode {
    let args = Args::parse();
    match args.command {
        Command::Verify {
            key,
            partial,
            json,
            files,
        } => match verify(&key, partial, json, files) {
            Ok((report, output)) => {
                print!("{output}");
                if report.is_ok() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
            Err(err) => {
                eprintln!("mercury-audit: {err:#}");
                ExitCode::from(2)
            }
        },
    }
}

fn verify(
    key: &str,
    partial: bool,
    json: bool,
    files: Vec<PathBuf>,
) -> anyhow::Result<(ChainReport, String)> {
    let key = read_key(key)?;
    let files = if files.is_empty() {
        let base = Path::new(audit::DEFAULT_AUDIT_PATH);
        audit::rotation_set(base).with_context(|| format!("listing {}", base.display()))?
    } else {
        audit::order_rotation_files(&files)
    };
    if files.is_empty() {
        bail!("no audit files to verify");
    }
    let report = audit::verify_chain(&files, &key, VerifyOptions { partial })?;
    let output = if json {
        let mut text = serde_json::to_string_pretty(&report)?;
        text.push('\n');
        text
    } else {
        render(&report)
    };
    Ok((report, output))
}

fn read_key(source: &str) -> anyhow::Result<[u8; 32]> {
    if source == "-" {
        let mut raw = String::new();
        std::io::stdin()
            .read_to_string(&mut raw)
            .context("reading the integrity key from stdin")?;
        return Ok(audit::parse_key_hex(&raw)?);
    }
    Ok(audit::load_key(Path::new(source))?)
}

fn render(report: &ChainReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Files (oldest first):");
    for file in &report.files {
        let _ = write!(
            out,
            "  {}  lines={} signed={}",
            file.path.display(),
            file.lines,
            file.signed_records
        );
        if let (Some(first), Some(last)) = (file.first_seq, file.last_seq) {
            let _ = write!(out, " seq={first}..{last}");
        }
        if file.legacy_v1_records > 0 {
            let _ = write!(out, " legacy_v1={}", file.legacy_v1_records);
        }
        if file.legacy_unsigned_records > 0 {
            let _ = write!(out, " unsigned={}", file.legacy_unsigned_records);
        }
        out.push('\n');
    }
    let _ = write!(out, "Records verified: {}", report.records_verified);
    if let (Some(first), Some(last)) = (report.first_seq, report.last_seq) {
        let _ = write!(out, " (seq {first}..{last})");
    }
    out.push('\n');
    let _ = writeln!(
        out,
        "Issues: {} error(s), {} warning(s)",
        report.errors, report.warnings
    );
    for issue in &report.issues {
        let label = match issue.severity {
            Severity::Error => "ERROR",
            Severity::Warning => "WARN ",
            Severity::Info => "INFO ",
        };
        let location = match (&issue.file, issue.line) {
            (Some(file), Some(line)) => format!("{}:{line}", file.display()),
            (Some(file), None) => file.display().to_string(),
            _ => "-".to_string(),
        };
        let kind = serde_json::to_value(issue.kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_default();
        let _ = writeln!(out, "  {label} {kind} {location}: {}", issue.detail);
    }
    if report.issues_omitted > 0 {
        let _ = writeln!(
            out,
            "  ... {} more issue(s) not shown",
            report.issues_omitted
        );
    }
    let _ = writeln!(
        out,
        "Result: {}",
        if report.is_ok() {
            "OK"
        } else {
            "FAILED (integrity errors found)"
        }
    );
    out
}

#[cfg(test)]
mod tests {
    use std::fs;

    use audit::{AuditConfig, AuditLogger, FsyncMode, IntegrityKeySource};
    use core_types::{AuditEvent, SystemResource};

    use super::*;

    fn write_rotated_log(dir: &Path) -> (PathBuf, PathBuf) {
        let key = dir.join("key");
        fs::write(&key, "12".repeat(32)).expect("write key");
        let log = dir.join("audit.jsonl");
        let logger = AuditLogger::new(AuditConfig {
            jsonl_path: log.clone(),
            max_bytes: 1024,
            max_files: 10,
            mirror_to_journald: false,
            integrity: IntegrityKeySource::File(key.clone()),
            fsync: FsyncMode::None,
            ..AuditConfig::default()
        })
        .expect("logger");
        for i in 0..8 {
            let event = AuditEvent::system(
                "daemon",
                SystemResource::new("daemon_start").attr("n", i),
                "v1",
                "started",
            );
            logger.log(&event).expect("log");
        }
        (log, key)
    }

    #[test]
    fn verifies_rotation_set_in_any_argument_order() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (log, key) = write_rotated_log(tmp.path());
        let mut files = audit::rotation_set(&log).expect("set");
        assert!(files.len() > 2);
        files.reverse();
        let (report, output) = verify(key.to_str().unwrap(), false, false, files).expect("verify");
        assert!(report.is_ok(), "{output}");
        assert!(output.contains("Result: OK"), "{output}");
        assert!(output.contains("Issues: 0 error(s)"), "{output}");
    }

    #[test]
    fn reports_tampering_as_failure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (log, key) = write_rotated_log(tmp.path());
        let files = audit::rotation_set(&log).expect("set");
        let content = fs::read_to_string(&files[1]).expect("read");
        fs::write(&files[1], content.replacen("started", "stopped", 1)).expect("tamper");
        let (report, output) =
            verify(key.to_str().unwrap(), false, false, files.clone()).expect("verify");
        assert!(!report.is_ok());
        assert!(output.contains("ERROR mac_mismatch"), "{output}");
        assert!(output.contains("Result: FAILED"), "{output}");

        let (_, json) = verify(key.to_str().unwrap(), false, true, files).expect("verify");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json report");
        assert_eq!(value["issues"][0]["kind"], "mac_mismatch");
    }

    #[test]
    fn missing_key_is_a_usage_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (log, _) = write_rotated_log(tmp.path());
        let err = verify(
            tmp.path().join("absent-key").to_str().unwrap(),
            false,
            false,
            vec![log],
        )
        .expect_err("missing key");
        assert!(err.to_string().contains("integrity key"), "{err}");
    }
}
