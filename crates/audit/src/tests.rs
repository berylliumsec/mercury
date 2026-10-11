use std::fs;
use std::sync::Arc;
use std::thread;

use core_types::{ActionType, Decision, DecisionReason, FileOp, FileResource, Resource};
use serde_json::Value;
use tempfile::{TempDir, tempdir};

use super::*;

const KEY_HEX: &str = "abababababababababababababababababababababababababababababababab";

fn sample_event() -> AuditEvent {
    AuditEvent {
        timestamp: chrono::Utc::now(),
        agent_id: "agent-1".to_string(),
        pid: Some(1234),
        ppid: Some(1),
        uid: Some(1000),
        action_type: ActionType::FileRead,
        decision: Decision::Deny,
        reason: DecisionReason::DenyByDefault,
        rule_id: None,
        resource: Resource::File(FileResource {
            path: "/etc/passwd".to_string(),
            resolved_path: None,
            op: FileOp::Read,
            source_path: None,
        }),
        profile: "default".to_string(),
        policy_version: "v1".to_string(),
        message: "blocked".to_string(),
        mcp: None,
        kernel_seq: None,
        events_dropped: None,
        model: None,
        context: Default::default(),
    }
}

fn event_for(agent: &str) -> AuditEvent {
    let mut event = sample_event();
    event.agent_id = agent.to_string();
    event
}

struct Fixture {
    dir: TempDir,
    key_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempdir().expect("tempdir");
        let key_path = dir.path().join("key");
        fs::write(&key_path, KEY_HEX).expect("write key");
        Self { dir, key_path }
    }

    fn log_path(&self) -> PathBuf {
        self.dir.path().join("audit.jsonl")
    }

    fn config(&self) -> AuditConfig {
        AuditConfig {
            jsonl_path: self.log_path(),
            max_bytes: 10 * 1024 * 1024,
            max_files: 5,
            mirror_to_journald: false,
            integrity: IntegrityKeySource::File(self.key_path.clone()),
            fsync: FsyncMode::None,
            ..AuditConfig::default()
        }
    }

    fn logger(&self) -> AuditLogger {
        AuditLogger::new(self.config()).expect("create logger")
    }

    fn key(&self) -> [u8; 32] {
        load_key(&self.key_path).expect("key")
    }

    fn verify(&self, options: VerifyOptions) -> ChainReport {
        let files = rotation_set(&self.log_path()).expect("rotation set");
        verify_chain(&files, &self.key(), options).expect("verify")
    }

    fn lines(&self, path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .expect("read log")
            .lines()
            .map(|line| serde_json::from_str(line).expect("every line is JSON"))
            .collect()
    }
}

fn system_event_name(record: &Value) -> Option<&str> {
    (record["action_type"] == "SYSTEM_EVENT")
        .then(|| record["resource"]["event"].as_str())
        .flatten()
}

fn kinds(report: &ChainReport, severity: Severity) -> Vec<IssueKind> {
    report
        .issues
        .iter()
        .filter(|issue| issue.severity == severity)
        .map(|issue| issue.kind)
        .collect()
}

#[test]
fn writes_stamped_jsonl_event_without_integrity() {
    let fixture = Fixture::new();
    let logger = AuditLogger::new(AuditConfig {
        integrity: IntegrityKeySource::Disabled,
        ..fixture.config()
    })
    .expect("create logger");
    logger.log(&sample_event()).expect("log event");

    let records = fixture.lines(&fixture.log_path());
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record["agent_id"], "agent-1");
    assert_eq!(record["schema_version"], AUDIT_SCHEMA_VERSION);
    assert!(Uuid::parse_str(record["event_id"].as_str().unwrap()).is_ok());
    assert_eq!(record["host"].as_str(), hostname().as_deref());
    assert!(record.get("integrity").is_none());
    let stats = logger.stats();
    assert_eq!(stats.records_written, 1);
    assert!(!stats.integrity_enabled);
    assert_eq!(stats.chain_seq, None);
}

#[test]
fn stamping_keeps_existing_context_values() {
    let fixture = Fixture::new();
    let logger = fixture.logger();
    let mut event = sample_event();
    event.context.event_id = Some("pre-stamped".to_string());
    event.context.host = Some("elsewhere".to_string());
    logger.log(&event).expect("log event");

    let records = fixture.lines(&fixture.log_path());
    let record = records.last().unwrap();
    assert_eq!(record["event_id"], "pre-stamped");
    assert_eq!(record["host"], "elsewhere");
    assert_eq!(record["schema_version"], AUDIT_SCHEMA_VERSION);
}

#[test]
fn new_chain_starts_with_chain_start_record() {
    let fixture = Fixture::new();
    let logger = fixture.logger();
    for i in 0..5 {
        logger.log(&event_for(&format!("agent-{i}"))).expect("log");
    }
    let records = fixture.lines(&fixture.log_path());
    assert_eq!(records.len(), 6);
    assert_eq!(system_event_name(&records[0]), Some(EVENT_CHAIN_START));
    assert_eq!(records[0]["resource"]["attributes"]["reason"], "new_log");
    assert_eq!(records[0]["source"], AUDIT_SOURCE);
    let seqs: Vec<u64> = records
        .iter()
        .map(|r| r["integrity"]["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(logger.stats().chain_seq, Some(6));

    let report = fixture.verify(VerifyOptions::default());
    assert!(report.is_ok(), "{report:#?}");
    assert_eq!(report.records_verified, 6);
    assert!(report.issues.is_empty(), "{:#?}", report.issues);
}

#[test]
fn chain_resumes_across_restarts() {
    let fixture = Fixture::new();
    for round in 0..3 {
        let logger = fixture.logger();
        logger
            .log(&event_for(&format!("round-{round}")))
            .expect("log");
    }
    let records = fixture.lines(&fixture.log_path());
    assert_eq!(records.len(), 4, "one chain start, then one record per run");
    let starts = records
        .iter()
        .filter(|r| system_event_name(r) == Some(EVENT_CHAIN_START))
        .count();
    assert_eq!(starts, 1);
    let report = fixture.verify(VerifyOptions::default());
    assert!(report.is_ok(), "{report:#?}");
    assert_eq!(report.last_seq, Some(4));
}

#[test]
fn detects_modified_record() {
    let fixture = Fixture::new();
    let logger = fixture.logger();
    for i in 0..3 {
        logger.log(&event_for(&format!("agent-{i}"))).expect("log");
    }
    drop(logger);
    let content = fs::read_to_string(fixture.log_path()).unwrap();
    fs::write(
        fixture.log_path(),
        content.replacen("agent-1", "agent-X", 1),
    )
    .unwrap();

    let report = fixture.verify(VerifyOptions::default());
    assert!(!report.is_ok());
    assert_eq!(
        kinds(&report, Severity::Error),
        vec![IssueKind::MacMismatch]
    );
    assert_eq!(report.issues[0].line, Some(3));
    // Verification resynchronizes: the following record still verifies.
    assert_eq!(report.records_verified, 3);
}

#[test]
fn detects_deleted_record_as_sequence_gap() {
    let fixture = Fixture::new();
    let logger = fixture.logger();
    for i in 0..4 {
        logger.log(&event_for(&format!("agent-{i}"))).expect("log");
    }
    drop(logger);
    let content = fs::read_to_string(fixture.log_path()).unwrap();
    let kept: Vec<&str> = content
        .lines()
        .enumerate()
        .filter(|(index, _)| *index != 2)
        .map(|(_, line)| line)
        .collect();
    fs::write(fixture.log_path(), kept.join("\n") + "\n").unwrap();

    let report = fixture.verify(VerifyOptions::default());
    assert_eq!(
        kinds(&report, Severity::Error),
        vec![IssueKind::SequenceGap]
    );
    assert!(report.issues[0].detail.contains("1 record(s) missing"));
}

#[test]
fn truncated_tail_is_reported_and_writer_recovers() {
    let fixture = Fixture::new();
    let logger = fixture.logger();
    for i in 0..3 {
        logger.log(&event_for(&format!("agent-{i}"))).expect("log");
    }
    drop(logger);
    let content = fs::read(fixture.log_path()).unwrap();
    fs::write(fixture.log_path(), &content[..content.len() - 20]).unwrap();

    let report = fixture.verify(VerifyOptions::default());
    assert_eq!(
        kinds(&report, Severity::Error),
        vec![IssueKind::TruncatedTail]
    );

    // The next writer terminates the fragment and continues the chain from
    // the last complete record, so only the damaged line is flagged.
    let logger = fixture.logger();
    logger.log(&event_for("after-crash")).expect("log");
    drop(logger);
    let report = fixture.verify(VerifyOptions::default());
    assert_eq!(
        kinds(&report, Severity::Error),
        vec![IssueKind::MalformedLine]
    );
    assert_eq!(report.issues[0].line, Some(4));
    assert_eq!(report.last_seq, Some(4));
}

#[test]
fn rotation_links_files_and_expires_oldest_with_record() {
    let fixture = Fixture::new();
    let logger = AuditLogger::new(AuditConfig {
        max_bytes: 2048,
        max_files: 2,
        ..fixture.config()
    })
    .expect("create logger");
    for i in 0..40 {
        logger.log(&event_for(&format!("agent-{i}"))).expect("log");
    }
    let stats = logger.stats();
    assert!(stats.rotations >= 3, "{stats:?}");
    assert!(stats.files_expired >= 1, "{stats:?}");
    drop(logger);

    let files = rotation_set(&fixture.log_path()).unwrap();
    assert_eq!(files.len(), 3, "{files:?}");
    for path in &files[1..] {
        let first = &fixture.lines(path)[0];
        assert_eq!(system_event_name(first), Some(EVENT_CHAIN_LINK));
    }
    let expired: Vec<Value> = files
        .iter()
        .flat_map(|path| fixture.lines(path))
        .filter(|r| system_event_name(r) == Some(EVENT_FILE_EXPIRED))
        .collect();
    assert!(!expired.is_empty());
    let attrs = &expired[0]["resource"]["attributes"];
    assert!(attrs["last_seq"].as_u64().is_some());
    assert_eq!(attrs["final_mac"].as_str().map(str::len), Some(64));

    let report = fixture.verify(VerifyOptions::default());
    assert!(report.is_ok(), "{report:#?}");
    assert_eq!(
        kinds(&report, Severity::Info),
        vec![IssueKind::ExpiredPredecessor]
    );
}

#[test]
fn removed_files_are_detected() {
    let fixture = Fixture::new();
    let logger = AuditLogger::new(AuditConfig {
        max_bytes: 2048,
        max_files: 10,
        ..fixture.config()
    })
    .expect("create logger");
    for i in 0..30 {
        logger.log(&event_for(&format!("agent-{i}"))).expect("log");
    }
    drop(logger);
    let files = rotation_set(&fixture.log_path()).unwrap();
    assert!(files.len() >= 4, "{files:?}");

    // A file from the middle of the set.
    fs::remove_file(&files[1]).unwrap();
    let report = fixture.verify(VerifyOptions::default());
    assert_eq!(kinds(&report, Severity::Error), vec![IssueKind::BrokenLink]);

    // The oldest file, without an expiry record.
    fs::remove_file(&files[0]).unwrap();
    let report = fixture.verify(VerifyOptions::default());
    assert!(
        kinds(&report, Severity::Error).contains(&IssueKind::MissingPredecessor),
        "{report:#?}"
    );
    let partial = fixture.verify(VerifyOptions { partial: true });
    assert!(kinds(&partial, Severity::Warning).contains(&IssueKind::MissingPredecessor));
}

#[test]
fn reopen_after_external_rename_links_files() {
    let fixture = Fixture::new();
    let logger = fixture.logger();
    logger.log(&event_for("before")).expect("log");
    // SIGHUP without rotation: same file, nothing written.
    logger.reopen().expect("reopen");
    assert_eq!(fixture.lines(&fixture.log_path()).len(), 2);

    fs::rename(fixture.log_path(), backup_path(&fixture.log_path(), 1)).unwrap();
    logger.reopen().expect("reopen");
    logger.log(&event_for("after")).expect("log");
    drop(logger);

    let records = fixture.lines(&fixture.log_path());
    assert_eq!(system_event_name(&records[0]), Some(EVENT_CHAIN_LINK));
    let attrs = &records[0]["resource"]["attributes"];
    assert_eq!(attrs["reason"], "reopen");
    assert_eq!(attrs["prev_seq"], 2);
    assert!(
        attrs["prev_file"]
            .as_str()
            .unwrap()
            .ends_with("audit.jsonl.1"),
        "{attrs}"
    );
    let report = fixture.verify(VerifyOptions::default());
    assert!(report.is_ok(), "{report:#?}");
    assert!(report.issues.is_empty(), "{:#?}", report.issues);
}

#[test]
fn replaced_or_deleted_active_file_is_followed() {
    let fixture = Fixture::new();
    let logger = fixture.logger();
    logger.log(&event_for("one")).expect("log");
    fs::remove_file(fixture.log_path()).unwrap();
    logger.log(&event_for("two")).expect("log");
    drop(logger);

    let records = fixture.lines(&fixture.log_path());
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0]["resource"]["attributes"]["reason"],
        "file_missing"
    );
    assert_eq!(records[1]["agent_id"], "two");
    // The deleted records are gone; the link exposes that.
    let report = fixture.verify(VerifyOptions::default());
    assert!(kinds(&report, Severity::Error).contains(&IssueKind::MissingPredecessor));
}

#[test]
fn key_change_starts_new_chain_that_is_flagged() {
    let fixture = Fixture::new();
    let logger = fixture.logger();
    logger.log(&event_for("old-key")).expect("log");
    drop(logger);

    fs::write(&fixture.key_path, "cd".repeat(32)).unwrap();
    let logger = fixture.logger();
    logger.log(&event_for("new-key")).expect("log");
    drop(logger);

    let records = fixture.lines(&fixture.log_path());
    let restart = &records[2];
    assert_eq!(system_event_name(restart), Some(EVENT_CHAIN_START));
    assert_eq!(
        restart["resource"]["attributes"]["reason"],
        "tail_mac_mismatch"
    );
    assert_eq!(restart["integrity"]["seq"], 3, "seq keeps counting");
    let report = fixture.verify(VerifyOptions::default());
    let errors = kinds(&report, Severity::Error);
    assert!(errors.contains(&IssueKind::ChainRestart), "{errors:?}");
    assert!(errors.contains(&IssueKind::MacMismatch), "{errors:?}");
}

#[test]
fn unsigned_legacy_records_precede_new_chain() {
    let fixture = Fixture::new();
    let plain = AuditLogger::new(AuditConfig {
        integrity: IntegrityKeySource::Disabled,
        ..fixture.config()
    })
    .expect("create logger");
    plain.log(&event_for("legacy")).expect("log");
    drop(plain);

    let logger = fixture.logger();
    logger.log(&event_for("signed")).expect("log");
    drop(logger);

    let records = fixture.lines(&fixture.log_path());
    assert_eq!(
        records[1]["resource"]["attributes"]["reason"],
        "unsigned_tail"
    );
    let report = fixture.verify(VerifyOptions::default());
    assert!(report.is_ok(), "{report:#?}");
    assert_eq!(
        kinds(&report, Severity::Warning),
        vec![IssueKind::LegacyRecords]
    );

    // Unsigned records after the chain began are errors.
    let plain = AuditLogger::new(AuditConfig {
        integrity: IntegrityKeySource::Disabled,
        ..fixture.config()
    })
    .expect("create logger");
    plain.log(&event_for("unsigned")).expect("log");
    drop(plain);
    let report = fixture.verify(VerifyOptions::default());
    assert_eq!(
        kinds(&report, Severity::Error),
        vec![IssueKind::UnsignedRecord]
    );
}

#[test]
fn verifies_legacy_v1_files_with_restarts() {
    let fixture = Fixture::new();
    let key = fixture.key();
    let v1_mac = |prev: &[u8; 32], json: &str| -> [u8; 32] {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
        mac.update(prev);
        mac.update(json.as_bytes());
        mac.finalize().into_bytes().into()
    };
    let mut content = String::new();
    let mut prev = [0u8; 32];
    for (i, restart) in [false, false, true, false].into_iter().enumerate() {
        if restart {
            prev = [0u8; 32];
        }
        let json = format!("{{\"n\":{i}}}");
        let mac = v1_mac(&prev, &json);
        content.push_str(&format!("{json}\t|integrity=sha256:{}\n", hex::encode(mac)));
        prev = mac;
    }
    fs::write(fixture.log_path(), &content).unwrap();

    let report = fixture.verify(VerifyOptions::default());
    assert!(report.is_ok(), "{report:#?}");
    assert_eq!(report.records_verified, 4);
    assert_eq!(report.files[0].v1_restarts, 1);

    let tampered = content.replacen("\"n\":1", "\"n\":9", 1);
    fs::write(fixture.log_path(), tampered).unwrap();
    let report = fixture.verify(VerifyOptions::default());
    assert_eq!(
        kinds(&report, Severity::Error),
        vec![IssueKind::MacMismatch]
    );

    // The writer starts a v2 chain after a v1 tail.
    fs::write(fixture.log_path(), &content).unwrap();
    let logger = fixture.logger();
    logger.log(&event_for("v2")).expect("log");
    drop(logger);
    let records: Vec<String> = fs::read_to_string(fixture.log_path())
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert!(records[4].contains("legacy_v1_tail"));
    let report = fixture.verify(VerifyOptions::default());
    assert!(report.is_ok(), "{report:#?}");
}

#[test]
fn empty_set_has_no_signed_records() {
    let fixture = Fixture::new();
    fs::write(fixture.log_path(), "").unwrap();
    let report = fixture.verify(VerifyOptions::default());
    assert_eq!(
        kinds(&report, Severity::Error),
        vec![IssueKind::NoSignedRecords]
    );
}

#[test]
fn auto_generates_integrity_key_once() {
    let fixture = Fixture::new();
    let key_path = fixture.dir.path().join("state").join("audit-integrity.key");
    let config = AuditConfig {
        integrity: IntegrityKeySource::AutoGenerate(key_path.clone()),
        ..fixture.config()
    };
    let logger = AuditLogger::new(config.clone()).expect("create logger");
    logger.log(&sample_event()).expect("log");
    drop(logger);
    let key = fs::read_to_string(&key_path).expect("key written");
    assert_eq!(key.trim().len(), 64);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let logger = AuditLogger::new(config).expect("reuse key");
    logger.log(&sample_event()).expect("log");
    drop(logger);
    assert_eq!(fs::read_to_string(&key_path).unwrap(), key);
    let report = verify_chain(
        &rotation_set(&fixture.log_path()).unwrap(),
        &load_key(&key_path).unwrap(),
        VerifyOptions::default(),
    )
    .unwrap();
    assert!(report.is_ok(), "{report:#?}");
    assert_eq!(report.records_verified, 3);
}

#[test]
fn unavailable_default_key_is_recorded_not_fatal() {
    let fixture = Fixture::new();
    let blocker = fixture.dir.path().join("not-a-dir");
    fs::write(&blocker, "").unwrap();
    let logger = AuditLogger::new(AuditConfig {
        integrity: IntegrityKeySource::AutoGenerate(blocker.join("key")),
        ..fixture.config()
    })
    .expect("logger starts without integrity");
    logger.log(&sample_event()).expect("log");

    let stats = logger.stats();
    assert!(!stats.integrity_enabled);
    assert!(stats.last_error.unwrap().contains("integrity disabled"));
    assert!(stats.last_error_at.is_some());
    let records = fixture.lines(&fixture.log_path());
    assert_eq!(
        system_event_name(&records[0]),
        Some(EVENT_INTEGRITY_UNAVAILABLE)
    );
    assert!(records[1].get("integrity").is_none());

    // An explicitly configured key path stays strict.
    let err = AuditLogger::new(AuditConfig {
        integrity: IntegrityKeySource::File(blocker.join("key")),
        ..fixture.config()
    })
    .expect_err("missing explicit key");
    assert!(matches!(err, AuditError::IntegrityKey(_)));
}

#[test]
fn secret_key_material_is_used_without_touching_disk() {
    let fixture = Fixture::new();
    let config = AuditConfig {
        integrity: IntegrityKeySource::Hex(KEY_HEX.to_string()),
        ..fixture.config()
    };
    assert!(!format!("{config:?}").contains(KEY_HEX));
    let logger = AuditLogger::new(config).expect("create logger");
    logger.log(&sample_event()).expect("log");
    drop(logger);
    assert!(fixture.verify(VerifyOptions::default()).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn write_failures_are_counted() {
    let dev_full = Path::new("/dev/full");
    if !dev_full.exists() {
        return;
    }
    let logger = AuditLogger::new(AuditConfig {
        jsonl_path: dev_full.to_path_buf(),
        mirror_to_journald: false,
        integrity: IntegrityKeySource::Disabled,
        fsync: FsyncMode::None,
        ..AuditConfig::default()
    })
    .expect("open /dev/full");
    assert!(logger.log(&sample_event()).is_err());
    let stats = logger.stats();
    assert_eq!(stats.write_failures, 1);
    assert_eq!(stats.records_written, 0);
    assert!(stats.last_error.unwrap().contains("audit write"));
}

#[cfg(target_os = "linux")]
#[test]
fn mirrors_records_and_counts_failures() {
    use std::os::unix::net::UnixDatagram;

    let fixture = Fixture::new();
    let socket_path = fixture.dir.path().join("journal.sock");
    let receiver = UnixDatagram::bind(&socket_path).expect("bind");
    let logger = AuditLogger::new(AuditConfig {
        mirror_to_journald: true,
        journald_socket_path: Some(socket_path.clone()),
        ..fixture.config()
    })
    .expect("create logger");
    logger.log(&sample_event()).expect("log");

    let (start, _) = journal::tests::recv_journal(&receiver);
    let start = journal::tests::decode_fields(&start);
    assert_eq!(start["MERCURY_AUDIT_SEQ"], b"1");
    assert_eq!(start["PRIORITY"], b"5");
    let (payload, _) = journal::tests::recv_journal(&receiver);
    let payload = journal::tests::decode_fields(&payload);
    let file_line = fixture.lines(&fixture.log_path())[1].clone();
    let mirrored: Value = serde_json::from_slice(&payload["MERCURY_JSON"]).unwrap();
    assert_eq!(payload["MERCURY_AUDIT_SEQ"], b"2");
    assert_eq!(
        payload["MERCURY_EVENT_ID"],
        file_line["event_id"].as_str().unwrap().as_bytes()
    );
    // The mirror carries the record without its integrity member.
    let mut expected = file_line;
    expected.as_object_mut().unwrap().remove("integrity");
    assert_eq!(mirrored, expected);
    assert_eq!(logger.stats().mirror_failures, 0);

    drop(receiver);
    fs::remove_file(&socket_path).unwrap();
    logger
        .log(&sample_event())
        .expect("file write still succeeds");
    let stats = logger.stats();
    assert_eq!(stats.mirror_failures, 1);
    assert!(stats.last_error.unwrap().contains("journald mirror failed"));
}

#[test]
fn interval_mode_syncs_soon_after_deny() {
    let fixture = Fixture::new();
    let logger = AuditLogger::new(AuditConfig {
        fsync: FsyncMode::Interval,
        ..fixture.config()
    })
    .expect("create logger");
    logger.log(&sample_event()).expect("log");
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if !logger.inner.writer.lock().unwrap().dirty {
            break;
        }
        assert!(Instant::now() < deadline, "flusher never synced");
        thread::sleep(Duration::from_millis(20));
    }
    let mut allow = sample_event();
    allow.decision = Decision::Allow;
    logger.log(&allow).expect("log");
    logger.sync().expect("explicit sync");
    assert!(!logger.inner.writer.lock().unwrap().dirty);
    // Drop joins the flusher thread.
    drop(logger);
}

#[test]
fn always_mode_leaves_nothing_dirty() {
    let fixture = Fixture::new();
    let logger = AuditLogger::new(AuditConfig {
        fsync: FsyncMode::Always,
        ..fixture.config()
    })
    .expect("create logger");
    let mut allow = sample_event();
    allow.decision = Decision::Allow;
    logger.log(&allow).expect("log");
    assert!(!logger.inner.writer.lock().unwrap().dirty);
}

#[test]
fn concurrent_rotation_preserves_all_events_and_chain() {
    let fixture = Fixture::new();
    let logger = Arc::new(
        AuditLogger::new(AuditConfig {
            max_bytes: 1024,
            max_files: 512,
            ..fixture.config()
        })
        .expect("create logger"),
    );

    let threads = 8usize;
    let events_per_thread = 25usize;
    let mut handles = Vec::with_capacity(threads);
    for idx in 0..threads {
        let logger = Arc::clone(&logger);
        handles.push(thread::spawn(move || {
            for event_idx in 0..events_per_thread {
                let mut event = event_for(&format!("agent-{idx}-{event_idx}"));
                event.message = "x".repeat(96);
                logger.log(&event).expect("log event");
            }
        }));
    }
    for handle in handles {
        handle.join().expect("join logger thread");
    }
    assert!(logger.stats().rotations > 0);
    drop(logger);

    let files = rotation_set(&fixture.log_path()).unwrap();
    assert!(files.len() > 1, "expected rotated files");
    let events = files
        .iter()
        .flat_map(|path| fixture.lines(path))
        .filter(|record| record["source"] != AUDIT_SOURCE)
        .count();
    assert_eq!(events, threads * events_per_thread);
    let report = fixture.verify(VerifyOptions::default());
    assert!(report.is_ok(), "{report:#?}");
    assert!(report.issues.is_empty(), "{:#?}", report.issues);
}

#[test]
fn config_enums_use_snake_case_names() {
    for (text, mode) in [
        ("\"none\"", FsyncMode::None),
        ("\"interval\"", FsyncMode::Interval),
        ("\"always\"", FsyncMode::Always),
    ] {
        assert_eq!(serde_json::from_str::<FsyncMode>(text).unwrap(), mode);
    }
    for (text, mode) in [
        ("\"native\"", JournaldMirrorMode::Native),
        ("\"syslog\"", JournaldMirrorMode::Syslog),
    ] {
        assert_eq!(
            serde_json::from_str::<JournaldMirrorMode>(text).unwrap(),
            mode
        );
    }
    let defaults = AuditConfig::default();
    assert_eq!(defaults.max_bytes, 100 * 1024 * 1024);
    assert_eq!(defaults.max_files, 10);
    assert_eq!(defaults.fsync, FsyncMode::Interval);
    assert_eq!(defaults.journald_mirror_mode, JournaldMirrorMode::Native);
    assert_eq!(
        defaults.integrity,
        IntegrityKeySource::AutoGenerate(PathBuf::from(DEFAULT_INTEGRITY_KEY_PATH))
    );
    let stats = serde_json::to_value(AuditStats::default()).unwrap();
    for key in [
        "records_written",
        "write_failures",
        "mirror_failures",
        "mirror_truncated",
        "rotations",
        "files_expired",
        "last_error",
        "last_error_at",
    ] {
        assert!(stats.get(key).is_some(), "missing {key}");
    }
}
