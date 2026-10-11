//! Integrity chain: record line format, MAC computation, tail recovery for
//! the writer, and verification of a rotation set.
//!
//! A signed (v2) record is the event JSON with one extra trailing member:
//! `{...,"integrity":{"v":2,"seq":N,"mac":"<hex>"}}`, so every line stays
//! valid JSON. The MAC is `HMAC-SHA256(key, prev_mac || seq_be64 || json)`
//! where `json` is the line without the integrity member. `seq` increases by
//! one per record for the whole life of the chain, across restarts and
//! rotated files, so removed records and files show up as gaps.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;

use crate::{AUDIT_SOURCE, AuditError};

pub(crate) type Mac32 = [u8; 32];
pub(crate) const ZERO_MAC: Mac32 = [0u8; 32];

const V2_MARKER: &str = ",\"integrity\":{\"v\":2,\"seq\":";
const V2_MAC_KEY: &str = ",\"mac\":\"";
const V2_END: &str = "\"}}";
/// Separator of the legacy (v1) tab-suffixed integrity tag.
const V1_MARKER: &str = "\t|integrity=sha256:";

pub const EVENT_CHAIN_START: &str = "audit_chain_start";
pub const EVENT_CHAIN_LINK: &str = "audit_chain_link";
pub const EVENT_FILE_EXPIRED: &str = "audit_file_expired";
const SYSTEM_EVENT_MARKER: &str = "\"action_type\":\"SYSTEM_EVENT\"";
const CHAIN_EVENT_MARKERS: [(&str, &str); 3] = [
    (EVENT_CHAIN_START, "\"event\":\"audit_chain_start\""),
    (EVENT_CHAIN_LINK, "\"event\":\"audit_chain_link\""),
    (EVENT_FILE_EXPIRED, "\"event\":\"audit_file_expired\""),
];

const TAIL_CHUNK_BYTES: u64 = 64 * 1024;
const TAIL_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Individual issues kept in a report; the rest are only counted.
const MAX_REPORTED_ISSUES: usize = 1000;

/// Position of the writer in the chain: the last record written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChainState {
    pub seq: u64,
    pub mac: Mac32,
}

pub(crate) fn mac_v2(key: &Mac32, prev: &Mac32, seq: u64, parts: &[&[u8]]) -> Mac32 {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(prev);
    mac.update(&seq.to_be_bytes());
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn mac_v1(key: &Mac32, prev: &Mac32, json: &str) -> Mac32 {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(prev);
    mac.update(json.as_bytes());
    mac.finalize().into_bytes().into()
}

/// Appends the integrity member to `json` (a serialized JSON object) and
/// terminates the line.
pub(crate) fn format_v2_line(json: &str, seq: u64, mac: &Mac32) -> String {
    debug_assert!(json.ends_with('}'), "audit record must be a JSON object");
    let body = &json[..json.len() - 1];
    let mut line = String::with_capacity(json.len() + V2_MARKER.len() + 96);
    line.push_str(body);
    line.push_str(V2_MARKER);
    line.push_str(&seq.to_string());
    line.push_str(V2_MAC_KEY);
    line.push_str(&hex::encode(mac));
    line.push_str(V2_END);
    line.push('\n');
    line
}

pub(crate) fn decode_mac(text: &str) -> Option<Mac32> {
    if text.len() != 64 {
        return None;
    }
    let bytes = hex::decode(text).ok()?;
    bytes.try_into().ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Line<'a> {
    Blank,
    /// `body` is the record JSON without its closing brace.
    V2 {
        body: &'a str,
        seq: u64,
        mac: Mac32,
    },
    V1 {
        json: &'a str,
        mac: Option<Mac32>,
    },
    /// Valid JSON without an integrity field.
    Plain,
    Malformed,
}

pub(crate) fn parse_line(line: &str) -> Line<'_> {
    if line.trim().is_empty() {
        return Line::Blank;
    }
    if let Some(parsed) = line
        .rfind(V2_MARKER)
        .and_then(|start| parse_v2(line, start))
    {
        return parsed;
    }
    if let Some((json, tag)) = line.split_once(V1_MARKER) {
        return Line::V1 {
            json,
            mac: decode_mac(tag.trim()),
        };
    }
    if serde_json::from_str::<serde::de::IgnoredAny>(line).is_ok() {
        Line::Plain
    } else {
        Line::Malformed
    }
}

fn parse_v2(line: &str, start: usize) -> Option<Line<'_>> {
    let rest = &line[start + V2_MARKER.len()..];
    let (seq_text, rest) = rest.split_once(V2_MAC_KEY)?;
    if seq_text.is_empty() || !seq_text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let seq = seq_text.parse::<u64>().ok()?;
    let mac = decode_mac(rest.strip_suffix(V2_END)?)?;
    Some(Line::V2 {
        body: &line[..start],
        seq,
        mac,
    })
}

/// Chain bookkeeping records written by the audit writer itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChainRecord {
    Start {
        reason: Option<String>,
    },
    Link {
        prev_seq: Option<u64>,
        prev_mac: Option<Mac32>,
        prev_file: Option<String>,
    },
    Expired {
        last_seq: Option<u64>,
        final_mac: Option<Mac32>,
    },
}

/// Recognizes chain bookkeeping records. Agent-controlled strings are always
/// JSON-escaped, so the unescaped markers can only come from real keys; the
/// record is then parsed and checked field by field.
pub(crate) fn chain_record(body: &str) -> Option<ChainRecord> {
    if !body.contains(SYSTEM_EVENT_MARKER) {
        return None;
    }
    let (name, _) = CHAIN_EVENT_MARKERS
        .iter()
        .find(|(_, marker)| body.contains(marker))?;
    let mut json = String::with_capacity(body.len() + 1);
    json.push_str(body);
    json.push('}');
    let value: Value = serde_json::from_str(&json).ok()?;
    if value.get("source").and_then(Value::as_str) != Some(AUDIT_SOURCE) {
        return None;
    }
    let resource = value.get("resource")?;
    if resource.get("kind").and_then(Value::as_str) != Some("SYSTEM")
        || resource.get("event").and_then(Value::as_str) != Some(name)
    {
        return None;
    }
    let attr = |key: &str| resource.get("attributes").and_then(|attrs| attrs.get(key));
    let attr_u64 = |key: &str| attr(key).and_then(Value::as_u64);
    let attr_str = |key: &str| attr(key).and_then(Value::as_str).map(str::to_string);
    let attr_mac = |key: &str| attr(key).and_then(Value::as_str).and_then(decode_mac);
    Some(match *name {
        EVENT_CHAIN_START => ChainRecord::Start {
            reason: attr_str("reason"),
        },
        EVENT_CHAIN_LINK => ChainRecord::Link {
            prev_seq: attr_u64("prev_seq"),
            prev_mac: attr_mac("prev_mac"),
            prev_file: attr_str("prev_file"),
        },
        _ => ChainRecord::Expired {
            last_seq: attr_u64("last_seq"),
            final_mac: attr_mac("final_mac"),
        },
    })
}

/// The last complete lines of a file.
#[derive(Debug, Clone, Default)]
pub(crate) struct Tail {
    /// Oldest first; excludes an unterminated final fragment.
    pub lines: Vec<String>,
    /// The file does not end with a newline (a record was cut off).
    pub torn: bool,
    pub len: u64,
}

/// Reads up to `max_lines` complete lines from the end of `path`.
pub(crate) fn read_tail(path: &Path, max_lines: usize) -> io::Result<Tail> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(Tail::default());
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut pos = len;
    let mut newlines = 0usize;
    loop {
        let start = pos.saturating_sub(TAIL_CHUNK_BYTES);
        let mut chunk = vec![0u8; (pos - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut chunk)?;
        newlines += chunk.iter().filter(|b| **b == b'\n').count();
        chunk.extend_from_slice(&buf);
        buf = chunk;
        pos = start;
        if pos == 0 || newlines > max_lines || len - pos >= TAIL_MAX_BYTES {
            break;
        }
    }
    let torn = buf.last() != Some(&b'\n');
    let mut pieces: Vec<&[u8]> = buf.split(|b| *b == b'\n').collect();
    // Either the empty piece after the final newline or the torn fragment.
    pieces.pop();
    if pos > 0 && !pieces.is_empty() {
        // Started mid-line.
        pieces.remove(0);
    }
    let skip = pieces.len().saturating_sub(max_lines);
    let lines = pieces[skip..]
        .iter()
        .map(|piece| String::from_utf8_lossy(piece).into_owned())
        .collect();
    Ok(Tail { lines, torn, len })
}

/// Seq and MAC of the last signed record in `path`, if the last complete
/// line is a v2 record.
pub(crate) fn last_signed(path: &Path) -> io::Result<Option<ChainState>> {
    let tail = read_tail(path, 1)?;
    Ok(tail.lines.last().and_then(|line| match parse_line(line) {
        Line::V2 { seq, mac, .. } => Some(ChainState { seq, mac }),
        _ => None,
    }))
}

/// Seq of the first record in `path` when it is signed.
pub(crate) fn first_signed_seq(path: &Path) -> io::Result<Option<u64>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut first = Vec::new();
    reader.read_until(b'\n', &mut first)?;
    let text = String::from_utf8_lossy(&first);
    Ok(match parse_line(text.trim_end_matches('\n')) {
        Line::V2 { seq, .. } => Some(seq),
        _ => None,
    })
}

/// What the writer should do with the chain found at the end of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TailState {
    Empty,
    Resume(ChainState),
    Restart {
        reason: &'static str,
        last_seq: Option<u64>,
    },
}

/// Decides how to continue the chain from `tail`. The last record's MAC is
/// checked against its predecessor when that is available, so a changed key
/// or an edited tail starts a new, clearly marked chain instead of silently
/// extending a broken one.
pub(crate) fn analyze_tail(tail: &Tail, key: &Mac32) -> TailState {
    let lines: Vec<&str> = tail
        .lines
        .iter()
        .map(String::as_str)
        .filter(|line| !line.trim().is_empty())
        .collect();
    let Some((last, earlier)) = lines.split_last() else {
        return if tail.len == 0 {
            TailState::Empty
        } else {
            TailState::Restart {
                reason: "unrecognized_tail",
                last_seq: None,
            }
        };
    };
    match parse_line(last) {
        Line::V2 { body, seq, mac } => {
            let prev = match chain_record(body) {
                Some(ChainRecord::Start { .. }) => Some(ZERO_MAC),
                Some(ChainRecord::Link { prev_mac, .. }) => prev_mac,
                _ => earlier.last().and_then(|line| match parse_line(line) {
                    Line::V2 {
                        seq: prev_seq,
                        mac: prev_mac,
                        ..
                    } if prev_seq.checked_add(1) == Some(seq) => Some(prev_mac),
                    _ => None,
                }),
            };
            if let Some(prev) = prev
                && mac_v2(key, &prev, seq, &[body.as_bytes(), b"}"]) != mac
            {
                return TailState::Restart {
                    reason: "tail_mac_mismatch",
                    last_seq: Some(seq),
                };
            }
            TailState::Resume(ChainState { seq, mac })
        }
        Line::V1 { .. } => TailState::Restart {
            reason: "legacy_v1_tail",
            last_seq: None,
        },
        Line::Plain => TailState::Restart {
            reason: "unsigned_tail",
            last_seq: None,
        },
        Line::Malformed | Line::Blank => TailState::Restart {
            reason: "unrecognized_tail",
            last_seq: None,
        },
    }
}

/// Loads a 64-hex-character integrity key from `path`.
pub fn load_key(path: &Path) -> Result<[u8; 32], AuditError> {
    let raw = fs::read_to_string(path).map_err(|err| {
        AuditError::IntegrityKey(format!(
            "failed to read integrity key from {}: {err}",
            path.display()
        ))
    })?;
    parse_key_hex(&raw)
}

/// Parses a 64-hex-character integrity key (surrounding whitespace allowed).
pub fn parse_key_hex(raw: &str) -> Result<[u8; 32], AuditError> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return Err(AuditError::IntegrityKey(format!(
            "integrity key must be 64 hex chars, got {}",
            trimmed.len()
        )));
    }
    let bytes = hex::decode(trimmed).map_err(|err| {
        AuditError::IntegrityKey(format!("integrity key is not valid hex: {err}"))
    })?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// `<base>.<n>` backups of `base`, highest (oldest) index first.
pub(crate) fn rotation_backups(base: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let dir = match base.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Some(name) = base.file_name().and_then(|name| name.to_str()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("audit path {} has no UTF-8 file name", base.display()),
        ));
    };
    let mut backups = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(index) = file_name
            .to_str()
            .and_then(|candidate| candidate.strip_prefix(name))
            .and_then(|rest| rest.strip_prefix('.'))
            .filter(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|suffix| suffix.parse::<u64>().ok())
        else {
            continue;
        };
        backups.push((index, dir.join(&file_name)));
    }
    backups.sort_by_key(|backup| std::cmp::Reverse(backup.0));
    Ok(backups)
}

/// The files of a rotation set, oldest first: `<base>.<n>` from the highest
/// index down, then `base` itself when it exists.
pub fn rotation_set(base: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = rotation_backups(base)?
        .into_iter()
        .map(|(_, path)| path)
        .collect();
    if base.exists() {
        files.push(base.to_path_buf());
    }
    Ok(files)
}

/// Orders files that belong to one rotation set oldest first (`.N` highest
/// first, the unnumbered file last). Any other list is returned unchanged.
pub fn order_rotation_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let split: Vec<(PathBuf, Option<u64>)> = paths.iter().map(|p| split_rotation(p)).collect();
    let same_set = split.windows(2).all(|pair| pair[0].0 == pair[1].0);
    if !same_set {
        return paths.to_vec();
    }
    let mut indexed: Vec<(Option<u64>, PathBuf)> = split
        .into_iter()
        .zip(paths)
        .map(|((_, index), path)| (index, path.clone()))
        .collect();
    indexed.sort_by(|a, b| match (a.0, b.0) {
        (Some(x), Some(y)) => y.cmp(&x),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    indexed.into_iter().map(|(_, path)| path).collect()
}

fn split_rotation(path: &Path) -> (PathBuf, Option<u64>) {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return (path.to_path_buf(), None);
    };
    if let Some((stem, suffix)) = name.rsplit_once('.')
        && !stem.is_empty()
        && !suffix.is_empty()
        && suffix.bytes().all(|b| b.is_ascii_digit())
        && let Ok(index) = suffix.parse::<u64>()
    {
        return (path.with_file_name(stem), Some(index));
    }
    (path.to_path_buf(), None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueKind {
    /// A record's MAC does not verify (edited record, wrong key).
    MacMismatch,
    /// Sequence numbers skip or go backwards (records removed or reordered).
    SequenceGap,
    /// A link record does not point at the record before it (file missing
    /// or replaced).
    BrokenLink,
    /// A new chain was started after signed records (key change, damaged or
    /// unsigned tail).
    ChainRestart,
    /// The set starts mid-chain and no expiry record explains the
    /// predecessor.
    MissingPredecessor,
    /// The set starts with a link to a file whose rotation expiry is
    /// recorded in the log.
    ExpiredPredecessor,
    /// A record without a v2 integrity field inside a signed chain.
    UnsignedRecord,
    MalformedLine,
    /// The last line has no newline: the final record was cut off.
    TruncatedTail,
    /// Unsigned or v1-signed records written before the v2 chain began.
    LegacyRecords,
    NoSignedRecords,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainIssue {
    pub severity: Severity,
    pub kind: IssueKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FileReport {
    pub path: PathBuf,
    pub lines: u64,
    /// v2 records (whether or not they verified).
    pub signed_records: u64,
    pub legacy_v1_records: u64,
    pub legacy_unsigned_records: u64,
    /// Times a v1 chain restarted from zero (every v1 daemon start).
    pub v1_restarts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_mac: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ChainReport {
    pub files: Vec<FileReport>,
    /// Records (v2 and legacy v1) whose MAC verified.
    pub records_verified: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seq: Option<u64>,
    pub errors: u64,
    pub warnings: u64,
    pub issues: Vec<ChainIssue>,
    /// Issues counted in `errors`/`warnings` but not listed.
    pub issues_omitted: u64,
}

impl ChainReport {
    /// True when no error-severity issue was found.
    pub fn is_ok(&self) -> bool {
        self.errors == 0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifyOptions {
    /// The files are a subset of the set: a missing predecessor of the first
    /// file is a warning instead of an error.
    pub partial: bool,
}

/// Verifies the integrity chain across `files`, given oldest first (see
/// [`rotation_set`] and [`order_rotation_files`]).
pub fn verify_chain(
    files: &[PathBuf],
    key: &[u8; 32],
    options: VerifyOptions,
) -> Result<ChainReport, AuditError> {
    let mut verifier = Verifier {
        key,
        options,
        prev: None,
        seen_signed: false,
        head: None,
        expired: Vec::new(),
        report: ChainReport::default(),
    };
    for path in files {
        verifier.verify_file(path)?;
    }
    Ok(verifier.finish())
}

/// The chain position the first record of the set claims to follow.
struct HeadClaim {
    file: PathBuf,
    line: u64,
    seq: Option<u64>,
    mac: Option<Mac32>,
    link_file: Option<String>,
}

struct Verifier<'k> {
    key: &'k Mac32,
    options: VerifyOptions,
    prev: Option<ChainState>,
    seen_signed: bool,
    head: Option<HeadClaim>,
    /// `(last_seq, final_mac)` of files recorded as expired.
    expired: Vec<(u64, Mac32)>,
    report: ChainReport,
}

impl Verifier<'_> {
    fn issue(
        &mut self,
        severity: Severity,
        kind: IssueKind,
        file: Option<&Path>,
        line: Option<u64>,
        detail: String,
    ) {
        match severity {
            Severity::Error => self.report.errors += 1,
            Severity::Warning => self.report.warnings += 1,
            Severity::Info => {}
        }
        if self.report.issues.len() < MAX_REPORTED_ISSUES {
            self.report.issues.push(ChainIssue {
                severity,
                kind,
                file: file.map(Path::to_path_buf),
                line,
                detail,
            });
        } else {
            self.report.issues_omitted += 1;
        }
    }

    fn verify_file(&mut self, path: &Path) -> Result<(), AuditError> {
        let context = |err: io::Error| {
            AuditError::Io(io::Error::new(
                err.kind(),
                format!("{}: {err}", path.display()),
            ))
        };
        let mut reader = BufReader::with_capacity(256 * 1024, File::open(path).map_err(context)?);
        let mut file_report = FileReport {
            path: path.to_path_buf(),
            ..FileReport::default()
        };
        // v1 chains restarted from zero in every file.
        let mut v1_prev = ZERO_MAC;
        let mut buf = Vec::new();
        let mut line_no = 0u64;
        loop {
            buf.clear();
            if reader.read_until(b'\n', &mut buf).map_err(context)? == 0 {
                break;
            }
            line_no += 1;
            file_report.lines += 1;
            if buf.last() != Some(&b'\n') {
                self.issue(
                    Severity::Error,
                    IssueKind::TruncatedTail,
                    Some(path),
                    Some(line_no),
                    format!(
                        "last line is incomplete ({} bytes without a newline); the record was cut off",
                        buf.len()
                    ),
                );
                break;
            }
            buf.pop();
            let Ok(text) = std::str::from_utf8(&buf) else {
                self.issue(
                    Severity::Error,
                    IssueKind::MalformedLine,
                    Some(path),
                    Some(line_no),
                    "line is not valid UTF-8".to_string(),
                );
                continue;
            };
            match parse_line(text) {
                Line::Blank => {}
                Line::V2 { body, seq, mac } => {
                    self.check_v2(path, line_no, &mut file_report, body, seq, mac)
                }
                Line::V1 { json, mac } => {
                    self.check_v1(path, line_no, &mut file_report, json, mac, &mut v1_prev)
                }
                Line::Plain => {
                    if self.seen_signed {
                        self.issue(
                            Severity::Error,
                            IssueKind::UnsignedRecord,
                            Some(path),
                            Some(line_no),
                            "record has no integrity field inside a signed chain".to_string(),
                        );
                    } else {
                        file_report.legacy_unsigned_records += 1;
                    }
                }
                Line::Malformed => self.issue(
                    Severity::Error,
                    IssueKind::MalformedLine,
                    Some(path),
                    Some(line_no),
                    "line is not a JSON audit record (torn write or edit)".to_string(),
                ),
            }
        }
        if file_report.legacy_unsigned_records > 0 {
            self.issue(
                Severity::Warning,
                IssueKind::LegacyRecords,
                Some(path),
                None,
                format!(
                    "{} unsigned record(s) precede the integrity chain and cannot be verified",
                    file_report.legacy_unsigned_records
                ),
            );
        }
        if file_report.legacy_v1_records > 0 {
            self.issue(
                Severity::Warning,
                IssueKind::LegacyRecords,
                Some(path),
                None,
                format!(
                    "{} legacy v1 record(s), {} v1 chain restart(s): v1 chains restart on every daemon start and rotation, so removed records at those points are not detectable",
                    file_report.legacy_v1_records, file_report.v1_restarts
                ),
            );
        }
        self.report.files.push(file_report);
        Ok(())
    }

    fn check_v2(
        &mut self,
        path: &Path,
        line: u64,
        file_report: &mut FileReport,
        body: &str,
        seq: u64,
        mac: Mac32,
    ) {
        let record = chain_record(body);
        let parts: [&[u8]; 2] = [body.as_bytes(), b"}"];
        let mut verified = false;
        match &record {
            Some(ChainRecord::Start { reason }) => {
                if let Some(prev) = self.prev {
                    self.issue(
                        Severity::Error,
                        IssueKind::ChainRestart,
                        Some(path),
                        Some(line),
                        format!(
                            "a new chain starts after seq {} (reason: {}); earlier records are no longer tied to later ones",
                            prev.seq,
                            reason.as_deref().unwrap_or("unknown")
                        ),
                    );
                }
                verified = self.check_mac(path, line, &ZERO_MAC, seq, &parts, &mac);
            }
            Some(ChainRecord::Link {
                prev_seq,
                prev_mac,
                prev_file,
            }) => {
                let (Some(claimed_seq), Some(claimed_mac)) = (*prev_seq, *prev_mac) else {
                    self.issue(
                        Severity::Error,
                        IssueKind::MalformedLine,
                        Some(path),
                        Some(line),
                        "chain link record lacks prev_seq/prev_mac".to_string(),
                    );
                    self.accept(file_report, seq, mac, false);
                    return;
                };
                if claimed_seq.checked_add(1) != Some(seq) {
                    self.issue(
                        Severity::Error,
                        IssueKind::SequenceGap,
                        Some(path),
                        Some(line),
                        format!("link record seq {seq} does not follow its predecessor seq {claimed_seq}"),
                    );
                }
                match self.prev {
                    Some(prev) if prev.seq != claimed_seq || prev.mac != claimed_mac => {
                        self.issue(
                            Severity::Error,
                            IssueKind::BrokenLink,
                            Some(path),
                            Some(line),
                            format!(
                                "link from {} expects predecessor seq {claimed_seq} (mac {}), but the preceding record is seq {} (mac {}): records or files are missing or were replaced",
                                prev_file.as_deref().unwrap_or("previous file"),
                                short_mac(&claimed_mac),
                                prev.seq,
                                short_mac(&prev.mac)
                            ),
                        );
                    }
                    Some(_) => {}
                    None => {
                        self.head = Some(HeadClaim {
                            file: path.to_path_buf(),
                            line,
                            seq: Some(claimed_seq),
                            mac: Some(claimed_mac),
                            link_file: prev_file.clone(),
                        });
                    }
                }
                verified = self.check_mac(path, line, &claimed_mac, seq, &parts, &mac);
            }
            _ => {
                match self.prev {
                    Some(prev) if prev.seq.checked_add(1) == Some(seq) => {
                        verified = self.check_mac(path, line, &prev.mac, seq, &parts, &mac);
                    }
                    Some(prev) => {
                        let detail = if seq <= prev.seq {
                            format!("sequence goes backwards: seq {seq} after seq {}", prev.seq)
                        } else {
                            format!(
                                "{} record(s) missing: expected seq {}, found seq {seq}",
                                seq - prev.seq - 1,
                                prev.seq + 1
                            )
                        };
                        self.issue(
                            Severity::Error,
                            IssueKind::SequenceGap,
                            Some(path),
                            Some(line),
                            detail,
                        );
                    }
                    None => {
                        self.head = Some(HeadClaim {
                            file: path.to_path_buf(),
                            line,
                            seq: seq.checked_sub(1),
                            mac: None,
                            link_file: None,
                        });
                    }
                }
                if verified
                    && let Some(ChainRecord::Expired {
                        last_seq: Some(last_seq),
                        final_mac: Some(final_mac),
                    }) = &record
                {
                    self.expired.push((*last_seq, *final_mac));
                }
            }
        }
        self.accept(file_report, seq, mac, verified);
    }

    fn accept(&mut self, file_report: &mut FileReport, seq: u64, mac: Mac32, verified: bool) {
        self.seen_signed = true;
        self.prev = Some(ChainState { seq, mac });
        file_report.signed_records += 1;
        file_report.first_seq.get_or_insert(seq);
        file_report.last_seq = Some(seq);
        file_report.final_mac = Some(hex::encode(mac));
        self.report.first_seq.get_or_insert(seq);
        self.report.last_seq = Some(seq);
        if verified {
            self.report.records_verified += 1;
        }
    }

    fn check_mac(
        &mut self,
        path: &Path,
        line: u64,
        prev: &Mac32,
        seq: u64,
        parts: &[&[u8]],
        mac: &Mac32,
    ) -> bool {
        if mac_v2(self.key, prev, seq, parts) == *mac {
            return true;
        }
        self.issue(
            Severity::Error,
            IssueKind::MacMismatch,
            Some(path),
            Some(line),
            format!(
                "MAC of seq {seq} does not verify: the record was modified or the key is wrong"
            ),
        );
        false
    }

    fn check_v1(
        &mut self,
        path: &Path,
        line: u64,
        file_report: &mut FileReport,
        json: &str,
        mac: Option<Mac32>,
        v1_prev: &mut Mac32,
    ) {
        if self.prev.is_some() {
            self.issue(
                Severity::Error,
                IssueKind::UnsignedRecord,
                Some(path),
                Some(line),
                "legacy v1 record inside the v2 chain".to_string(),
            );
            return;
        }
        file_report.legacy_v1_records += 1;
        self.seen_signed = true;
        let Some(mac) = mac else {
            self.issue(
                Severity::Error,
                IssueKind::MalformedLine,
                Some(path),
                Some(line),
                "v1 integrity tag is not 64 hex characters".to_string(),
            );
            return;
        };
        if mac_v1(self.key, v1_prev, json) == mac {
            self.report.records_verified += 1;
        } else if mac_v1(self.key, &ZERO_MAC, json) == mac {
            file_report.v1_restarts += 1;
            self.report.records_verified += 1;
        } else {
            self.issue(
                Severity::Error,
                IssueKind::MacMismatch,
                Some(path),
                Some(line),
                "v1 record MAC does not verify: the record was modified, removed or the key is wrong"
                    .to_string(),
            );
        }
        *v1_prev = mac;
    }

    fn finish(mut self) -> ChainReport {
        if let Some(head) = self.head.take() {
            let expired = matches!(
                (head.seq, head.mac),
                (Some(seq), Some(mac)) if self.expired.contains(&(seq, mac))
            );
            let link_file = head.link_file.as_deref().unwrap_or("an earlier file");
            if expired {
                self.issue(
                    Severity::Info,
                    IssueKind::ExpiredPredecessor,
                    Some(&head.file),
                    Some(head.line),
                    format!(
                        "chain continues from {link_file} (seq {}), whose expiry by rotation is recorded in the log",
                        head.seq.unwrap_or_default()
                    ),
                );
            } else {
                let severity = if self.options.partial {
                    Severity::Warning
                } else {
                    Severity::Error
                };
                let detail = match (head.mac, head.seq) {
                    (Some(_), Some(seq)) => format!(
                        "the set begins with a link to {link_file} (seq {seq}), which is neither present nor recorded as expired"
                    ),
                    (_, seq) => format!(
                        "the set begins mid-chain after seq {}; earlier records are missing",
                        seq.unwrap_or_default()
                    ),
                };
                self.issue(
                    severity,
                    IssueKind::MissingPredecessor,
                    Some(&head.file),
                    Some(head.line),
                    detail,
                );
            }
        }
        if !self.seen_signed {
            self.issue(
                Severity::Error,
                IssueKind::NoSignedRecords,
                None,
                None,
                "no signed records found; integrity cannot be established".to_string(),
            );
        }
        self.report
    }
}

fn short_mac(mac: &Mac32) -> String {
    hex::encode(&mac[..6])
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Mac32 = [7u8; 32];

    fn signed(json: &str, prev: &Mac32, seq: u64) -> (String, Mac32) {
        let mac = mac_v2(&KEY, prev, seq, &[json.as_bytes()]);
        (format_v2_line(json, seq, &mac), mac)
    }

    #[test]
    fn v2_line_is_valid_json_and_round_trips() {
        let json = r#"{"a":"x\"y","n":1}"#;
        let (line, mac) = signed(json, &ZERO_MAC, 42);
        let value: Value = serde_json::from_str(line.trim_end()).expect("line is JSON");
        assert_eq!(value["integrity"]["seq"], 42);
        assert_eq!(value["integrity"]["v"], 2);
        match parse_line(line.trim_end()) {
            Line::V2 {
                body,
                seq,
                mac: parsed,
            } => {
                assert_eq!(format!("{body}}}"), json);
                assert_eq!(seq, 42);
                assert_eq!(parsed, mac);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn classifies_legacy_plain_and_malformed_lines() {
        assert!(matches!(parse_line(r#"{"a":1}"#), Line::Plain));
        assert!(matches!(parse_line("{\"a\":"), Line::Malformed));
        assert!(matches!(parse_line("   "), Line::Blank));
        let v1 = format!("{{\"a\":1}}{V1_MARKER}{}", "ab".repeat(32));
        assert!(matches!(parse_line(&v1), Line::V1 { mac: Some(_), .. }));
        // An integrity-shaped member nested elsewhere is not a v2 suffix.
        let nested = r#"{"x":{"a":1,"integrity":{"v":2,"seq":1,"mac":"00"}},"y":2}"#;
        assert!(matches!(parse_line(nested), Line::Plain));
    }

    #[test]
    fn read_tail_skips_torn_fragment() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("f");
        fs::write(&path, "one\ntwo\nthree\npartial").expect("write");
        let tail = read_tail(&path, 2).expect("tail");
        assert_eq!(tail.lines, vec!["two".to_string(), "three".to_string()]);
        assert!(tail.torn);

        let long = "x".repeat(200 * 1024);
        fs::write(&path, format!("{long}\nlast\n")).expect("write");
        let tail = read_tail(&path, 2).expect("tail");
        assert_eq!(tail.lines, vec![long, "last".to_string()]);
        assert!(!tail.torn);
    }

    #[test]
    fn orders_rotation_files_oldest_first() {
        let paths: Vec<PathBuf> = ["/l/audit.jsonl", "/l/audit.jsonl.10", "/l/audit.jsonl.2"]
            .iter()
            .map(PathBuf::from)
            .collect();
        assert_eq!(
            order_rotation_files(&paths),
            vec![
                PathBuf::from("/l/audit.jsonl.10"),
                PathBuf::from("/l/audit.jsonl.2"),
                PathBuf::from("/l/audit.jsonl"),
            ]
        );
        let mixed: Vec<PathBuf> = ["/l/b.log", "/l/a.log"].iter().map(PathBuf::from).collect();
        assert_eq!(order_rotation_files(&mixed), mixed);
    }

    #[test]
    fn tail_with_wrong_key_restarts_chain() {
        let (line, first_mac) = signed(r#"{"a":1}"#, &ZERO_MAC, 1);
        let (second, mac) = signed(r#"{"a":2}"#, &first_mac, 2);
        let tail = Tail {
            lines: vec![line.trim_end().to_string(), second.trim_end().to_string()],
            torn: false,
            len: 10,
        };
        assert_eq!(
            analyze_tail(&tail, &KEY),
            TailState::Resume(ChainState { seq: 2, mac })
        );
        assert_eq!(
            analyze_tail(&tail, &[9u8; 32]),
            TailState::Restart {
                reason: "tail_mac_mismatch",
                last_seq: Some(2)
            }
        );
    }
}
