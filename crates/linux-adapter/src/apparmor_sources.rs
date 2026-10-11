//! Readers that deliver raw AppArmor audit lines with resumable positions:
//! journald (`_TRANSPORT=audit` and/or `_TRANSPORT=kernel`) and the auditd
//! log file.
//!
//! Readers never advance their own position. The caller commits the position
//! of the last line it actually processed, so a partially processed batch is
//! re-read on the next call instead of being lost.

use std::fs;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, anyhow};
use serde::{Deserialize, Deserializer};
use tracing::{debug, warn};

use crate::apparmor_records::{RawAuditLine, RecordOrigin};

pub(crate) const JOURNAL_CURSOR_FILE: &str = "journal.cursor";
pub(crate) const AUDIT_LOG_CURSOR_FILE: &str = "auditlog.cursor";
/// Upper bound on bytes read from the audit log per call.
const AUDIT_LOG_MAX_READ_BYTES: u64 = 4 << 20;
/// AppArmor records are `type=1400` (AVC); dbus mediation is `type=1107`.
const JOURNAL_AUDIT_MATCHES: [&str; 3] =
    ["_TRANSPORT=audit", "_AUDIT_TYPE=1400", "_AUDIT_TYPE=1107"];
const JOURNAL_KERNEL_MATCH: &str = "_TRANSPORT=kernel";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Position {
    Journal(String),
    AuditLog(AuditLogCursor),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuditLogCursor {
    pub inode: u64,
    pub offset: u64,
}

/// A source lost its place and resumed elsewhere; records in between may be
/// missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CursorReset {
    pub source: &'static str,
    /// Stable reason code (`corrupt_cursor_file`, `journal_rejected_cursor`,
    /// `audit_log_truncated`, `audit_log_rotated`).
    pub reason: &'static str,
    pub detail: String,
    /// Time of the last consumed position, when known (microseconds).
    pub gap_start_us: Option<i64>,
}

#[derive(Debug, Default)]
pub(crate) struct SourceBatch {
    pub lines: Vec<(RawAuditLine, Position)>,
    /// Position after everything that was read, including lines filtered
    /// out as irrelevant. Commit it only when every line was processed.
    pub end: Option<Position>,
    pub resets: Vec<CursorReset>,
    /// Entries that could not be decoded.
    pub malformed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalSelection {
    /// `_TRANSPORT=audit` (AVC/USER_AVC) OR `_TRANSPORT=kernel`.
    AuditAndKernel,
    Audit,
    Kernel,
}

#[derive(Debug)]
pub(crate) struct JournaldReader {
    bin: PathBuf,
    selection: JournalSelection,
    cursor_path: PathBuf,
    cursor: Option<String>,
}

impl JournaldReader {
    pub(crate) fn new(bin: PathBuf, selection: JournalSelection, state_dir: &Path) -> Self {
        Self {
            bin,
            selection,
            cursor_path: state_dir.join(JOURNAL_CURSOR_FILE),
            cursor: None,
        }
    }

    /// Resumes from the persisted cursor, or starts at the journal tail.
    pub(crate) fn start(&mut self) -> anyhow::Result<Vec<CursorReset>> {
        let mut resets = Vec::new();
        match read_state_file(&self.cursor_path)? {
            Some(cursor) if is_well_formed_journal_cursor(&cursor) => {
                self.cursor = Some(cursor);
                return Ok(resets);
            }
            Some(_) => {
                // An unclean shutdown can leave the file NUL-filled or
                // truncated; journalctl would reject it on every drain.
                warn!(path = %self.cursor_path.display(), "ignoring corrupt AppArmor journal cursor");
                resets.push(CursorReset {
                    source: "journald",
                    reason: "corrupt_cursor_file",
                    detail: format!(
                        "journal cursor file {} was corrupt; resuming at the journal tail",
                        self.cursor_path.display()
                    ),
                    gap_start_us: None,
                });
            }
            None => {}
        }
        self.reset_to_tail()?;
        Ok(resets)
    }

    pub(crate) fn match_args(&self) -> Vec<&'static str> {
        match self.selection {
            JournalSelection::AuditAndKernel => {
                let mut args = JOURNAL_AUDIT_MATCHES.to_vec();
                args.push("+");
                args.push(JOURNAL_KERNEL_MATCH);
                args
            }
            JournalSelection::Audit => JOURNAL_AUDIT_MATCHES.to_vec(),
            JournalSelection::Kernel => vec![JOURNAL_KERNEL_MATCH],
        }
    }

    /// Reads at most `max_entries` journal entries after the cursor.
    pub(crate) fn read(&mut self, max_entries: usize) -> anyhow::Result<SourceBatch> {
        let mut command = Command::new(&self.bin);
        command.args(["--output=json", "--no-pager", "--quiet"]);
        if let Some(cursor) = self.cursor.as_deref() {
            command.arg(format!("--after-cursor={cursor}"));
        }
        command
            .args(self.match_args())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command
            .spawn()
            .with_context(|| format!("run {} for AppArmor audit", self.bin.display()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("journalctl stdout not captured"))?;
        // Drain stderr concurrently so a chatty journalctl (e.g. one warning
        // per corrupt journal file) can never block on a full pipe while we
        // wait on stdout.
        let stderr_reader = child.stderr.take().map(|mut pipe| {
            std::thread::spawn(move || {
                let mut text = String::new();
                let _ = pipe.read_to_string(&mut text);
                text
            })
        });

        let mut batch = SourceBatch::default();
        let mut reader = BufReader::new(stdout);
        let mut buf = Vec::new();
        let mut entries = 0usize;
        let mut stopped_early = false;
        loop {
            buf.clear();
            let read = match reader.read_until(b'\n', &mut buf) {
                Ok(read) => read,
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    join_stderr(stderr_reader);
                    return Err(err).context("read journalctl output");
                }
            };
            if read == 0 {
                break;
            }
            let line = String::from_utf8_lossy(&buf);
            let line = line.trim();
            if line.is_empty() || line.starts_with("--") {
                continue;
            }
            match serde_json::from_str::<JournalEntry>(line) {
                Ok(entry) => {
                    entries += 1;
                    let Some(cursor) = entry.cursor.clone() else {
                        batch.malformed += 1;
                        continue;
                    };
                    batch.end = Some(Position::Journal(cursor.clone()));
                    if let Some(raw) = entry.into_raw_line()
                        && is_candidate_line(raw.text.as_str())
                    {
                        batch.lines.push((raw, Position::Journal(cursor)));
                    }
                    if entries >= max_entries {
                        stopped_early = true;
                        break;
                    }
                }
                Err(err) => {
                    // A single malformed line must not abort the batch.
                    batch.malformed += 1;
                    debug!(error = %err, "skipping unparseable journalctl line");
                }
            }
        }

        if stopped_early {
            let _ = child.kill();
            let _ = child.wait();
            join_stderr(stderr_reader);
            return Ok(batch);
        }

        let status = child.wait().context("wait for journalctl")?;
        let stderr = join_stderr(stderr_reader);
        if status.success() {
            return Ok(batch);
        }

        let stderr = stderr.trim();
        if let Some(cursor) = self.cursor.clone()
            && stderr.contains("seek to cursor")
        {
            // journald rejects this cursor on every poll; keeping it would
            // stall AppArmor audit ingestion permanently.
            warn!(
                error = stderr,
                "journald rejected saved AppArmor cursor; resuming from journal tail"
            );
            self.reset_to_tail()?;
            batch.resets.push(CursorReset {
                source: "journald",
                reason: "journal_rejected_cursor",
                detail: format!("journalctl rejected the saved cursor: {stderr}"),
                gap_start_us: journal_cursor_realtime_us(&cursor),
            });
            return Ok(batch);
        }
        Err(anyhow!("journalctl exited with status {status}: {stderr}"))
    }

    /// Advances the in-memory cursor, then persists it. On a persist error the
    /// in-memory cursor is still advanced so the batch is not re-emitted.
    pub(crate) fn commit(&mut self, cursor: String) -> anyhow::Result<()> {
        if self.cursor.as_deref() == Some(cursor.as_str()) {
            return Ok(());
        }
        self.cursor = Some(cursor.clone());
        write_state_file(&self.cursor_path, cursor.as_str())
    }

    #[cfg(test)]
    pub(crate) fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }

    fn reset_to_tail(&mut self) -> anyhow::Result<()> {
        self.cursor = capture_tail_cursor(&self.bin);
        match self.cursor.clone() {
            Some(cursor) => write_state_file(&self.cursor_path, cursor.as_str()),
            None => remove_state_file(&self.cursor_path),
        }
    }
}

#[derive(Debug)]
pub(crate) struct AuditLogReader {
    path: PathBuf,
    cursor_path: PathBuf,
    cursor: Option<AuditLogCursor>,
    /// A missing or unreadable file is not an error (`auto` mode).
    optional: bool,
}

impl AuditLogReader {
    pub(crate) fn new(path: PathBuf, state_dir: &Path, optional: bool) -> Self {
        Self {
            path,
            cursor_path: state_dir.join(AUDIT_LOG_CURSOR_FILE),
            cursor: None,
            optional,
        }
    }

    /// Resumes from the persisted inode+offset, or starts at the end of the
    /// current file. When the file does not exist yet it is read from the
    /// start once it appears.
    pub(crate) fn start(&mut self) -> anyhow::Result<Vec<CursorReset>> {
        let mut resets = Vec::new();
        if let Some(raw) = read_state_file(&self.cursor_path)? {
            if let Some(cursor) = parse_audit_log_cursor(raw.as_str()) {
                self.cursor = Some(cursor);
                return Ok(resets);
            }
            resets.push(CursorReset {
                source: "audit_log",
                reason: "corrupt_cursor_file",
                detail: format!(
                    "audit log cursor file {} was corrupt; resuming at the end of {}",
                    self.cursor_path.display(),
                    self.path.display()
                ),
                gap_start_us: None,
            });
        }
        self.cursor = match fs::metadata(&self.path) {
            Ok(meta) => Some(AuditLogCursor {
                inode: meta.ino(),
                offset: meta.len(),
            }),
            Err(_) => None,
        };
        match self.cursor {
            Some(cursor) => write_state_file(&self.cursor_path, &format_audit_log_cursor(cursor))?,
            None => remove_state_file(&self.cursor_path)?,
        }
        Ok(resets)
    }

    /// Reads at most `max_lines` candidate lines after the cursor. Finishes a
    /// rotated file (`<path>.1` with the cursor's inode) before moving on.
    pub(crate) fn read(&mut self, max_lines: usize) -> anyhow::Result<SourceBatch> {
        let mut batch = SourceBatch::default();
        let meta = match fs::metadata(&self.path) {
            Ok(meta) => meta,
            Err(err)
                if self.optional
                    && matches!(
                        err.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) =>
            {
                return Ok(batch);
            }
            Err(err) => {
                return Err(err).with_context(|| format!("stat {}", self.path.display()));
            }
        };
        let inode = meta.ino();
        let len = meta.len();

        let mut offset = 0;
        match self.cursor {
            None => {}
            Some(cursor) if cursor.inode == inode => {
                if len < cursor.offset {
                    batch.resets.push(CursorReset {
                        source: "audit_log",
                        reason: "audit_log_truncated",
                        detail: format!(
                            "{} shrank below the saved offset {}; re-reading from the start",
                            self.path.display(),
                            cursor.offset
                        ),
                        gap_start_us: None,
                    });
                } else {
                    offset = cursor.offset;
                }
            }
            Some(cursor) => {
                let rotated = rotated_path(&self.path);
                match fs::metadata(&rotated) {
                    Ok(rotated_meta) if rotated_meta.ino() == cursor.inode => {
                        let start = cursor.offset.min(rotated_meta.len());
                        let (end, oversized) =
                            scan_audit_log(&rotated, cursor.inode, start, max_lines, &mut batch)?;
                        batch.malformed += oversized;
                        if batch.lines.len() >= max_lines || end < rotated_meta.len() {
                            batch.end = Some(Position::AuditLog(AuditLogCursor {
                                inode: cursor.inode,
                                offset: end,
                            }));
                            return Ok(batch);
                        }
                    }
                    _ => batch.resets.push(CursorReset {
                        source: "audit_log",
                        reason: "audit_log_rotated",
                        detail: format!(
                            "{} was rotated and the previous file (inode {}) is gone; \
                             resuming at the start of the current file",
                            self.path.display(),
                            cursor.inode
                        ),
                        gap_start_us: None,
                    }),
                }
            }
        }

        let remaining = max_lines.saturating_sub(batch.lines.len());
        let (end, oversized) = scan_audit_log(&self.path, inode, offset, remaining, &mut batch)?;
        batch.malformed += oversized;
        batch.end = Some(Position::AuditLog(AuditLogCursor { inode, offset: end }));
        Ok(batch)
    }

    pub(crate) fn commit(&mut self, cursor: AuditLogCursor) -> anyhow::Result<()> {
        if self.cursor == Some(cursor) {
            return Ok(());
        }
        self.cursor = Some(cursor);
        write_state_file(&self.cursor_path, &format_audit_log_cursor(cursor))
    }

    #[cfg(test)]
    pub(crate) fn cursor(&self) -> Option<AuditLogCursor> {
        self.cursor
    }
}

/// Appends candidate lines from `path` starting at `offset`. Returns the
/// offset after the last scanned complete line and the number of oversized
/// lines skipped.
fn scan_audit_log(
    path: &Path,
    inode: u64,
    offset: u64,
    max_lines: usize,
    batch: &mut SourceBatch,
) -> anyhow::Result<(u64, u64)> {
    if max_lines == 0 {
        return Ok((offset, 0));
    }
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("seek {}", path.display()))?;
    let mut buf = Vec::new();
    file.take(AUDIT_LOG_MAX_READ_BYTES)
        .read_to_end(&mut buf)
        .with_context(|| format!("read {}", path.display()))?;

    let mut consumed = 0usize;
    let mut added = 0usize;
    while consumed < buf.len() && added < max_lines {
        let Some(newline) = buf[consumed..].iter().position(|byte| *byte == b'\n') else {
            break;
        };
        let line = String::from_utf8_lossy(&buf[consumed..consumed + newline]).into_owned();
        consumed += newline + 1;
        // audit.log carries every audit record type; only AppArmor ones matter.
        if line.contains("apparmor=") {
            batch.lines.push((
                RawAuditLine {
                    text: line,
                    origin: RecordOrigin::AuditLog,
                    audit_id: None,
                    source_realtime_us: None,
                    receive_realtime_us: None,
                },
                Position::AuditLog(AuditLogCursor {
                    inode,
                    offset: offset + consumed as u64,
                }),
            ));
            added += 1;
        }
    }

    // A single line longer than the read window would otherwise stall the
    // reader forever; skip it.
    if consumed == 0 && buf.len() as u64 == AUDIT_LOG_MAX_READ_BYTES {
        warn!(path = %path.display(), offset, "skipping oversized audit log line");
        return Ok((offset + buf.len() as u64, 1));
    }
    Ok((offset + consumed as u64, 0))
}

fn join_stderr(reader: Option<std::thread::JoinHandle<String>>) -> String {
    reader
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default()
}

fn rotated_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".1");
    PathBuf::from(name)
}

/// Cheap pre-filter so unrelated journal/log lines are not kept in memory.
fn is_candidate_line(text: &str) -> bool {
    text.contains("apparmor=") || text.contains("audit")
}

fn parse_audit_log_cursor(raw: &str) -> Option<AuditLogCursor> {
    let mut parts = raw.split_whitespace();
    let inode = parts.next()?.parse().ok()?;
    let offset = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(AuditLogCursor { inode, offset })
}

fn format_audit_log_cursor(cursor: AuditLogCursor) -> String {
    format!("{} {}", cursor.inode, cursor.offset)
}

#[derive(Debug, Deserialize)]
struct JournalEntry {
    #[serde(
        rename = "MESSAGE",
        default,
        deserialize_with = "deserialize_journal_message"
    )]
    message: Option<String>,
    #[serde(rename = "__CURSOR", default)]
    cursor: Option<String>,
    #[serde(rename = "__REALTIME_TIMESTAMP", default)]
    realtime_timestamp: Option<String>,
    #[serde(rename = "_TRANSPORT", default)]
    transport: Option<String>,
    #[serde(rename = "_AUDIT_ID", default)]
    audit_id: Option<String>,
    #[serde(rename = "_SOURCE_REALTIME_TIMESTAMP", default)]
    source_realtime_timestamp: Option<String>,
}

impl JournalEntry {
    fn into_raw_line(self) -> Option<RawAuditLine> {
        let origin = match self.transport.as_deref() {
            Some("audit") => RecordOrigin::JournaldAudit,
            _ => RecordOrigin::JournaldKernel,
        };
        Some(RawAuditLine {
            text: self.message?,
            origin,
            audit_id: self.audit_id.and_then(|raw| raw.parse().ok()),
            source_realtime_us: self
                .source_realtime_timestamp
                .and_then(|raw| raw.parse().ok()),
            receive_realtime_us: self.realtime_timestamp.and_then(|raw| raw.parse().ok()),
        })
    }
}

// journalctl --output=json emits MESSAGE as a JSON string when the original
// is UTF-8, but as an array of u8 (e.g. [27,91,...]) for binary payloads.
// A non-string MESSAGE used to abort the entire drain batch; decode both
// shapes lossily so a single weird record can't stall the audit pipeline.
fn deserialize_journal_message<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde_json::Value;
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(match value {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s),
        Some(Value::Array(items)) => {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        Some(other) => Some(other.to_string()),
    })
}

fn capture_tail_cursor(bin: &Path) -> Option<String> {
    let output = Command::new(bin)
        .args(["-n", "1", "--output=json", "--no-pager", "--quiet"])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<JournalEntry>(line).ok())
        .filter_map(|entry| entry.cursor)
        .next_back()
}

/// journald cursors are `;`-separated `key=value` fields of printable ASCII
/// (e.g. `s=…;i=…;b=…;m=…;t=…;x=…`). This is a sanity check, not a parser:
/// it rejects garbage such as NUL-filled files, which `Command` cannot even
/// pass as an argument.
pub(crate) fn is_well_formed_journal_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.bytes().all(|byte| byte.is_ascii_graphic())
        && cursor.split(';').all(|field| {
            field
                .split_once('=')
                .is_some_and(|(key, value)| !key.is_empty() && !value.is_empty())
        })
}

/// The `t=` field of a journal cursor is the entry's realtime in hex µs.
fn journal_cursor_realtime_us(cursor: &str) -> Option<i64> {
    cursor
        .split(';')
        .find_map(|field| field.strip_prefix("t="))
        .and_then(|hex| i64::from_str_radix(hex, 16).ok())
}

fn read_state_file(path: &Path) -> anyhow::Result<Option<String>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("read AppArmor cursor {}", path.display()));
        }
    };
    let value = String::from_utf8_lossy(&bytes).trim().to_string();
    Ok((!value.is_empty()).then_some(value))
}

/// Write-then-rename so a crash can never leave a partial cursor behind.
fn write_state_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = PathBuf::from(tmp_name);
    let mut file = fs::File::create(&tmp_path)
        .with_context(|| format!("create AppArmor cursor {}", tmp_path.display()))?;
    file.write_all(format!("{contents}\n").as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("write AppArmor cursor {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("replace AppArmor cursor {}", path.display()))
}

fn remove_state_file(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove AppArmor cursor {}", path.display())),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// A stand-in `journalctl` that records its arguments and prints the
    /// fixture file (or fails with `stderr` when `exit_code` is non-zero).
    pub(crate) fn fake_journalctl(
        dir: &Path,
        fixture: &str,
        tail_cursor: &str,
        exit_code: i32,
        stderr: &str,
    ) -> PathBuf {
        let fixture_path = dir.join("journal.fixture");
        fs::write(&fixture_path, fixture).expect("write fixture");
        let script = dir.join("journalctl");
        // Honors --after-cursor by printing the fixture lines that follow
        // the line carrying that cursor.
        let body = format!(
            "#!/bin/sh\n\
             echo \"$@\" >> '{args}'\n\
             cursor=''\n\
             for a in \"$@\"; do case \"$a\" in --after-cursor=*) cursor=\"${{a#--after-cursor=}}\";; esac; done\n\
             if [ \"$1\" = \"-n\" ]; then echo '{{\"__CURSOR\":\"{tail}\"}}'; exit 0; fi\n\
             if [ {code} -ne 0 ]; then echo '{stderr}' >&2; exit {code}; fi\n\
             if [ -z \"$cursor\" ]; then cat '{fixture}'; exit 0; fi\n\
             awk -v c=\"\\\"__CURSOR\\\":\\\"$cursor\\\"\" 'found {{print}} index($0, c) {{found=1}}' '{fixture}'\n",
            args = dir.join("journalctl.args").display(),
            tail = tail_cursor,
            code = exit_code,
            stderr = stderr,
            fixture = fixture_path.display(),
        );
        fs::write(&script, body).expect("write script");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
        script
    }

    fn journal_line(cursor: &str, transport: &str, message: &str) -> String {
        serde_json::json!({
            "__CURSOR": cursor,
            "__REALTIME_TIMESTAMP": "1790684426066631",
            "_TRANSPORT": transport,
            "MESSAGE": message,
        })
        .to_string()
    }

    #[test]
    fn journal_cursor_validation_rejects_garbage() {
        assert!(is_well_formed_journal_cursor(
            "s=99844ab8b125438a9a9583bf25930004;i=1e47c;b=c7bf48a5058b42418f22dbdcd2abdc71;m=12365a165;t=65bd6eefae138;x=f4cd6fa68e5e40d9"
        ));
        assert!(!is_well_formed_journal_cursor(""));
        assert!(!is_well_formed_journal_cursor(&"\0".repeat(127)));
        assert!(!is_well_formed_journal_cursor("s=abc;i"));
        assert!(!is_well_formed_journal_cursor("s=abc; i=1"));
        assert_eq!(
            journal_cursor_realtime_us("s=a;i=1;t=65c9e351edac7;x=1"),
            Some(0x65c9e351edac7)
        );
    }

    #[test]
    fn corrupt_journal_cursor_resets_to_tail_and_reports_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut contents = vec![0u8; 127];
        contents.push(b'\n');
        fs::write(dir.path().join(JOURNAL_CURSOR_FILE), contents).expect("write cursor");
        let bin = fake_journalctl(dir.path(), "", "s=tail;i=9", 0, "");

        let mut reader = JournaldReader::new(bin, JournalSelection::Kernel, dir.path());
        let resets = reader.start().expect("start");
        assert_eq!(resets.len(), 1);
        assert_eq!(resets[0].reason, "corrupt_cursor_file");
        assert_eq!(reader.cursor(), Some("s=tail;i=9"));
        assert_eq!(
            read_state_file(&dir.path().join(JOURNAL_CURSOR_FILE)).expect("read"),
            Some("s=tail;i=9".to_string())
        );
    }

    #[test]
    fn journal_commit_round_trips_without_leaving_temp_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = fake_journalctl(dir.path(), "", "s=tail;i=1", 0, "");
        let mut reader = JournaldReader::new(bin.clone(), JournalSelection::Kernel, dir.path());
        reader
            .commit("s=abc;i=1;b=def;m=2;t=3;x=4".to_string())
            .expect("commit");
        assert!(
            !dir.path()
                .join(format!("{JOURNAL_CURSOR_FILE}.tmp"))
                .exists()
        );

        let mut restarted = JournaldReader::new(bin, JournalSelection::Kernel, dir.path());
        assert!(restarted.start().expect("start").is_empty());
        assert_eq!(restarted.cursor(), Some("s=abc;i=1;b=def;m=2;t=3;x=4"));
    }

    #[test]
    fn journal_read_uses_selected_transports_and_keeps_positions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fixture = [
            journal_line(
                "s=1;i=1",
                "kernel",
                r#"audit: type=1400 audit(1.000:1): apparmor="DENIED" operation="open" profile="mercury-agent-abc" name="/x" pid=5"#,
            ),
            journal_line("s=1;i=2", "kernel", "usb 1-1: new high-speed USB device"),
            "not json".to_string(),
            r#"{"MESSAGE":[104,105],"__CURSOR":"s=1;i=3","_TRANSPORT":"audit","_AUDIT_ID":"7","_SOURCE_REALTIME_TIMESTAMP":"1000000"}"#.to_string(),
        ]
        .join("\n");
        let bin = fake_journalctl(dir.path(), &fixture, "s=1;i=0", 0, "");
        let mut reader = JournaldReader::new(bin, JournalSelection::AuditAndKernel, dir.path());

        // The entry limit stops reading and leaves the rest for later.
        let limited = reader.read(1).expect("read limited");
        assert_eq!(limited.end, Some(Position::Journal("s=1;i=1".to_string())));

        let batch = reader.read(100).expect("read");
        assert_eq!(batch.malformed, 1);
        assert_eq!(batch.lines.len(), 1, "only candidate lines are kept");
        assert_eq!(batch.lines[0].1, Position::Journal("s=1;i=1".to_string()));
        assert_eq!(batch.end, Some(Position::Journal("s=1;i=3".to_string())));
        let args = fs::read_to_string(dir.path().join("journalctl.args")).expect("args");
        assert!(
            args.contains("_TRANSPORT=audit _AUDIT_TYPE=1400 _AUDIT_TYPE=1107 + _TRANSPORT=kernel")
        );

        reader.commit("s=1;i=1".to_string()).expect("commit");
        let rest = reader.read(100).expect("read after cursor");
        assert!(rest.lines.is_empty());
        assert_eq!(rest.end, Some(Position::Journal("s=1;i=3".to_string())));
        let args = fs::read_to_string(dir.path().join("journalctl.args")).expect("args");
        assert!(args.contains("--after-cursor=s=1;i=1"));
    }

    #[test]
    fn journal_audit_entry_carries_audit_id_and_source_time() {
        let entry: JournalEntry = serde_json::from_str(
            r#"{"MESSAGE":"AVC apparmor=\"DENIED\"","__CURSOR":"s=1","_TRANSPORT":"audit","_AUDIT_ID":"77","_SOURCE_REALTIME_TIMESTAMP":"1790684426065000","__REALTIME_TIMESTAMP":"1790684426066000"}"#,
        )
        .expect("entry");
        let raw = entry.into_raw_line().expect("line");
        assert_eq!(raw.origin, RecordOrigin::JournaldAudit);
        assert_eq!(raw.audit_id, Some(77));
        assert_eq!(raw.source_realtime_us, Some(1_790_684_426_065_000));
    }

    #[test]
    fn rejected_journal_cursor_resets_with_gap_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = fake_journalctl(
            dir.path(),
            "",
            "s=tail;i=9",
            1,
            "Failed to seek to cursor: Invalid argument",
        );
        let mut reader = JournaldReader::new(bin, JournalSelection::Kernel, dir.path());
        reader.commit("s=old;i=1;t=10".to_string()).expect("commit");

        let batch = reader.read(10).expect("reset is not an error");
        assert_eq!(batch.resets.len(), 1);
        assert_eq!(batch.resets[0].reason, "journal_rejected_cursor");
        assert_eq!(batch.resets[0].gap_start_us, Some(16));
        assert_eq!(reader.cursor(), Some("s=tail;i=9"));
    }

    #[test]
    fn journal_failure_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = fake_journalctl(dir.path(), "", "s=tail", 1, "No journal files were found.");
        let mut reader = JournaldReader::new(bin, JournalSelection::Kernel, dir.path());
        let err = reader.read(10).expect_err("should fail");
        assert!(err.to_string().contains("No journal files were found."));
    }

    #[test]
    fn journal_entry_accepts_binary_and_missing_message() {
        let entry: JournalEntry =
            serde_json::from_str(r#"{"MESSAGE":[104,105,33,255,255],"__CURSOR":"s=2"}"#)
                .expect("array MESSAGE");
        assert!(entry.message.expect("message").starts_with("hi!"));
        let entry: JournalEntry =
            serde_json::from_str(r#"{"__CURSOR":"s=3"}"#).expect("missing MESSAGE");
        assert!(entry.into_raw_line().is_none());
    }

    const AVC_A: &str = r#"type=AVC msg=audit(1790684426.065:1): apparmor="DENIED" operation="open" profile="mercury-agent-abc" name="/a" pid=5"#;
    const AVC_B: &str = r#"type=AVC msg=audit(1790684426.066:2): apparmor="AUDIT" operation="open" profile="mercury-agent-abc" name="/b" pid=5"#;
    const SYSCALL: &str =
        r#"type=SYSCALL msg=audit(1790684426.065:1): arch=c000003e syscall=257 success=no"#;

    #[test]
    fn audit_log_starts_at_end_and_tails_new_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("audit.log");
        fs::write(&log, format!("{AVC_A}\n")).expect("write log");

        let mut reader = AuditLogReader::new(log.clone(), dir.path(), false);
        assert!(reader.start().expect("start").is_empty());
        assert!(reader.read(10).expect("read").lines.is_empty());

        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .expect("open");
        write!(file, "{SYSCALL}\n{AVC_B}\npartial").expect("append");
        let batch = reader.read(10).expect("read");
        let texts: Vec<_> = batch
            .lines
            .iter()
            .map(|(line, _)| line.text.as_str())
            .collect();
        assert_eq!(texts, vec![AVC_B]);
        let Some(Position::AuditLog(end)) = batch.end.clone() else {
            panic!("expected audit log position");
        };
        // The unterminated "partial" line is left for the next read.
        assert_eq!(
            end.offset,
            (AVC_A.len() + 1 + SYSCALL.len() + 1 + AVC_B.len() + 1) as u64
        );
        reader.commit(end).expect("commit");

        let mut restarted = AuditLogReader::new(log, dir.path(), false);
        assert!(restarted.start().expect("start").is_empty());
        assert_eq!(restarted.cursor(), Some(end));
    }

    #[test]
    fn audit_log_finishes_rotated_file_before_the_new_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("audit.log");
        fs::write(&log, "").expect("write log");
        let mut reader = AuditLogReader::new(log.clone(), dir.path(), false);
        reader.start().expect("start");

        fs::write(&log, format!("{AVC_A}\n")).expect("write");
        fs::rename(&log, dir.path().join("audit.log.1")).expect("rotate");
        fs::write(&log, format!("{AVC_B}\n")).expect("new log");

        let batch = reader.read(10).expect("read");
        assert!(batch.resets.is_empty());
        let texts: Vec<_> = batch
            .lines
            .iter()
            .map(|(line, _)| line.text.as_str())
            .collect();
        assert_eq!(texts, vec![AVC_A, AVC_B]);
    }

    #[test]
    fn audit_log_rotation_without_previous_file_is_a_reset() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("audit.log");
        fs::write(&log, format!("{AVC_A}\n")).expect("write log");
        let mut reader = AuditLogReader::new(log.clone(), dir.path(), false);
        reader.start().expect("start");

        // Create the replacement while the old file still exists so it
        // cannot reuse the old inode.
        let replacement = dir.path().join("audit.log.new");
        fs::write(&replacement, format!("{AVC_B}\n")).expect("new log");
        fs::rename(&replacement, &log).expect("replace log");
        let batch = reader.read(10).expect("read");
        assert_eq!(batch.resets.len(), 1);
        assert_eq!(batch.resets[0].reason, "audit_log_rotated");
        assert_eq!(batch.lines.len(), 1);
    }

    #[test]
    fn audit_log_truncation_is_a_reset() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("audit.log");
        fs::write(&log, format!("{AVC_A}\n{AVC_B}\n")).expect("write log");
        let mut reader = AuditLogReader::new(log.clone(), dir.path(), false);
        reader.start().expect("start");

        // copytruncate-style rotation keeps the inode.
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&log)
            .and_then(|mut file| writeln!(file, "{AVC_B}"))
            .expect("truncate");
        let batch = reader.read(10).expect("read");
        assert_eq!(batch.resets[0].reason, "audit_log_truncated");
        assert_eq!(batch.lines.len(), 1);
    }

    #[test]
    fn missing_optional_audit_log_is_not_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("missing.log");
        let mut optional = AuditLogReader::new(log.clone(), dir.path(), true);
        optional.start().expect("start");
        assert!(optional.read(10).expect("read").lines.is_empty());

        // Once the file appears it is read from the beginning.
        fs::write(&log, format!("{AVC_A}\n")).expect("write");
        assert_eq!(optional.read(10).expect("read").lines.len(), 1);

        let mut required = AuditLogReader::new(dir.path().join("nope.log"), dir.path(), false);
        assert!(required.read(10).is_err());
    }

    #[test]
    fn corrupt_audit_log_cursor_is_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("audit.log");
        fs::write(&log, format!("{AVC_A}\n")).expect("write log");
        fs::write(dir.path().join(AUDIT_LOG_CURSOR_FILE), "garbage").expect("cursor");
        let mut reader = AuditLogReader::new(log, dir.path(), false);
        let resets = reader.start().expect("start");
        assert_eq!(resets[0].reason, "corrupt_cursor_file");
        assert_eq!(
            reader.cursor().map(|cursor| cursor.offset),
            Some((AVC_A.len() + 1) as u64)
        );
    }
}
