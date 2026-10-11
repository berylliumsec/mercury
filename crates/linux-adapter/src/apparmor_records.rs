//! Parsing of AppArmor audit records.
//!
//! The same kernel record reaches Mercury in three shapes:
//! - journald `_TRANSPORT=kernel` (printk):
//!   `audit: type=1400 audit(1790684426.065:62057388): apparmor="AUDIT" ...`
//! - journald `_TRANSPORT=audit` (audit multicast): `AVC apparmor="AUDIT" ...`
//!   with the stamp moved into `_SOURCE_REALTIME_TIMESTAMP` / `_AUDIT_ID`
//! - auditd's log: `type=AVC msg=audit(1790684426.065:62057388): apparmor=...`
//!
//! Everything after `apparmor=` is identical, which is what deduplication
//! keys on.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};

use chrono::{DateTime, TimeZone, Utc};
use core_types::{ActionType, Decision, FileOp};

pub(crate) const PROFILE_PREFIX: &str = "mercury-agent-";

/// Comm of the Mercury launcher (`mercury-run`), whose own start-up records
/// may be suppressed briefly after a pre-exec launch.
pub(crate) const LAUNCHER_COMM: &str = "mercury-run";

/// String fields AppArmor logs with `audit_log_untrustedstring`: quoted when
/// printable, otherwise unquoted upper-case hex.
const UNTRUSTED_STRING_FIELDS: &[&str] = &[
    "name",
    "name2",
    "comm",
    "exe",
    "target",
    "profile",
    "label",
    "peer",
    "peer_label",
    "srcname",
    "fstype",
    "addr",
    "peer_addr",
    "path",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordOrigin {
    JournaldAudit,
    JournaldKernel,
    AuditLog,
}

impl RecordOrigin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::JournaldAudit => "journald_audit",
            Self::JournaldKernel => "journald_kernel",
            Self::AuditLog => "audit_log",
        }
    }
}

/// One line/entry read from a source, before parsing.
#[derive(Debug, Clone)]
pub(crate) struct RawAuditLine {
    pub text: String,
    pub origin: RecordOrigin,
    /// `_AUDIT_ID` (audit transport only).
    pub audit_id: Option<u64>,
    /// `_SOURCE_REALTIME_TIMESTAMP` in microseconds (audit transport only).
    pub source_realtime_us: Option<i64>,
    /// When journald received the entry, in microseconds.
    pub receive_realtime_us: Option<i64>,
}

impl RawAuditLine {
    #[cfg(test)]
    pub(crate) fn kernel(text: &str) -> Self {
        Self {
            text: text.to_string(),
            origin: RecordOrigin::JournaldKernel,
            audit_id: None,
            source_realtime_us: None,
            receive_realtime_us: None,
        }
    }

    pub(crate) fn receive_time(&self) -> Option<DateTime<Utc>> {
        self.receive_realtime_us
            .and_then(|micros| Utc.timestamp_micros(micros).single())
    }
}

/// `audit(<secs>.<millis>:<serial>)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct AuditStamp {
    pub secs: i64,
    pub millis: u32,
    pub serial: u64,
}

impl AuditStamp {
    pub(crate) fn timestamp(&self) -> Option<DateTime<Utc>> {
        Utc.timestamp_opt(self.secs, self.millis.saturating_mul(1_000_000))
            .single()
    }

    /// Stable id shared by every record the kernel emitted for one event
    /// (e.g. `rename_src` and `rename_dest`).
    pub(crate) fn correlation_id(&self) -> String {
        format!("audit({}.{:03}:{})", self.secs, self.millis, self.serial)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum Verdict {
    /// Allowed access logged because the profile has the `audit` flag.
    Audit,
    /// Would-deny allowed by complain (observe) mode.
    Allowed,
    Denied,
    /// Denied and the task was killed.
    Killed,
    /// Profile load / replace / remove.
    Status,
    /// HINT, ERROR, AUTO or anything newer.
    #[default]
    Unknown,
}

impl Verdict {
    fn parse(raw: &str) -> Self {
        match raw {
            "AUDIT" => Self::Audit,
            "ALLOWED" => Self::Allowed,
            "DENIED" => Self::Denied,
            "KILLED" => Self::Killed,
            "STATUS" => Self::Status,
            _ => Self::Unknown,
        }
    }

    pub(crate) fn decision(&self) -> Decision {
        match self {
            Self::Denied | Self::Killed => Decision::Deny,
            Self::Audit | Self::Allowed | Self::Status | Self::Unknown => Decision::Allow,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ParsedAuditRecord {
    pub timestamp: DateTime<Utc>,
    pub stamp: Option<AuditStamp>,
    pub verdict: Verdict,
    /// The `apparmor=` value as logged.
    pub verdict_raw: String,
    pub operation: String,
    pub class: Option<String>,
    /// Best display path/target for the record (file name, exec target,
    /// socket address or a `<sentinel>`).
    pub path: String,
    pub name: Option<String>,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    /// Base Mercury label (`mercury-agent-<id>`) the record is about.
    pub label: String,
    /// Label as logged (may carry `//child` or `//&stack` suffixes).
    pub raw_label: String,
    pub comm: Option<String>,
    pub info: Option<String>,
    pub error: Option<String>,
    pub requested_mask: Option<String>,
    pub denied_mask: Option<String>,
    pub signal: Option<String>,
    pub capability: Option<u32>,
    pub capname: Option<String>,
    pub peer: Option<String>,
    pub peer_pid: Option<u32>,
    pub family: Option<String>,
    pub sock_type: Option<String>,
    pub protocol: Option<String>,
    pub local_ip: Option<String>,
    pub local_port: Option<u16>,
    pub peer_ip: Option<String>,
    pub peer_port: Option<u16>,
    pub addr: Option<String>,
    pub peer_addr: Option<String>,
    pub srcname: Option<String>,
    pub fstype: Option<String>,
    pub flags: Option<String>,
    /// Hash of stamp + record body; `None` when the record has no stamp.
    pub dedupe_key: Option<u64>,
}

impl ParsedAuditRecord {
    pub(crate) fn decision(&self) -> Decision {
        self.verdict.decision()
    }

    pub(crate) fn is_socket(&self) -> bool {
        self.class.as_deref() == Some("net")
            || self.family.is_some()
            || self.sock_type.is_some()
            || self.protocol.is_some()
    }

    pub(crate) fn is_unix_socket(&self) -> bool {
        self.family.as_deref() == Some("unix")
            || (self.class.as_deref() == Some("file") && self.name.is_some())
    }

    /// Socket path for AF_UNIX records: the file name for pathname sockets,
    /// otherwise the (possibly abstract `@name`) address.
    pub(crate) fn unix_socket_path(&self, peer_side: bool) -> Option<String> {
        let (first, second) = if peer_side {
            (&self.peer_addr, &self.addr)
        } else {
            (&self.addr, &self.peer_addr)
        };
        [&self.name, first, second]
            .into_iter()
            .flatten()
            .find(|value| is_socket_address(value))
            .cloned()
    }

    pub(crate) fn signal_number(&self) -> Option<u32> {
        self.signal.as_deref().and_then(signal_number)
    }
}

/// Kernel audit / printk messages that mean audit records were lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LossNotice {
    /// `kernel_printk`, `kernel_audit_lost`, `kernel_audit_backlog`,
    /// `kernel_audit_hold_queue`, `kernel_audit_rate_limit`.
    pub source: &'static str,
    pub count: u64,
    /// Cumulative `audit_lost=` counter when the notice carries it.
    pub total: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub(crate) enum ParsedLine {
    /// Not an AppArmor record for a Mercury profile.
    Ignored,
    Loss(LossNotice),
    Record(Box<ParsedAuditRecord>),
    /// Looked like a Mercury AppArmor record but could not be parsed.
    Malformed(&'static str),
}

pub(crate) fn parse_line(line: &RawAuditLine) -> ParsedLine {
    let text = strip_enriched_suffix(line.text.as_str());
    if !text.contains("apparmor=") {
        return match parse_loss_notice(text) {
            Some(notice) => ParsedLine::Loss(notice),
            None => ParsedLine::Ignored,
        };
    }
    if !text.contains(PROFILE_PREFIX) {
        return ParsedLine::Ignored;
    }

    let fields = parse_kv_fields(text);
    let Some(verdict_raw) = fields.get("apparmor").cloned() else {
        return ParsedLine::Malformed("missing apparmor= verdict");
    };
    let verdict = Verdict::parse(verdict_raw.as_str());

    // The subject is `profile=` (kernel) or `label=` (dbus USER_AVC). Status
    // and change_* records are logged by the (usually unconfined) task that
    // loads or switches to a Mercury profile, so fall back to name/target.
    let subject = first_field(&fields, &["profile", "label"]);
    let raw_label = match subject.as_deref() {
        Some(subject) if subject.starts_with(PROFILE_PREFIX) => subject.to_string(),
        _ => match first_field(&fields, &["name", "target"]) {
            Some(named) if named.starts_with(PROFILE_PREFIX) => named,
            _ => return ParsedLine::Ignored,
        },
    };
    let label = base_label(raw_label.as_str()).to_string();

    let Some(operation) = fields.get("operation").cloned() else {
        return ParsedLine::Malformed("missing operation");
    };

    let stamp = parse_audit_stamp(text).or_else(|| journald_stamp(line));
    let timestamp = stamp
        .and_then(|stamp| stamp.timestamp())
        .or_else(|| line.receive_time())
        .unwrap_or_else(Utc::now);

    let family = first_field(&fields, &["family", "family_name"]);
    let sock_type = first_field(&fields, &["sock_type", "type"]).filter(|value| {
        // `type=1400` / `type=AVC` is the audit record type, not a socket type.
        !value.chars().all(|ch| ch.is_ascii_digit()) && value != "AVC" && value != "USER_AVC"
    });
    let protocol = first_field(&fields, &["protocol"]);
    let local_ip = first_field(&fields, &["laddr", "local_addr", "src", "saddr"]);
    let local_port = first_u16_field(&fields, &["lport", "local_port", "src_port", "sport"]);
    let peer_ip = first_field(
        &fields,
        &["peer_addr", "faddr", "remote_addr", "dst", "dest", "daddr"],
    )
    .filter(|value| looks_like_ip(value));
    let peer_port = first_u16_field(
        &fields,
        &[
            "peer_port",
            "fport",
            "remote_port",
            "dest_port",
            "dport",
            "port",
        ],
    );
    let name = fields.get("name").cloned();
    let addr = fields.get("addr").cloned();
    let peer_addr = fields
        .get("peer_addr")
        .cloned()
        .filter(|value| !looks_like_ip(value));

    let path = name
        .clone()
        .or_else(|| fields.get("target").cloned())
        .unwrap_or_else(|| match operation.as_str() {
            "signal" => "<task-kill>".to_string(),
            "ptrace" => "<ptrace>".to_string(),
            "capable" => "<capable>".to_string(),
            "userns_create" => "<userns>".to_string(),
            "mount" | "umount" | "remount" | "pivotroot" | "move_mount" => "<mount>".to_string(),
            _ if family.as_deref() == Some("unix") => [&peer_addr, &addr]
                .into_iter()
                .flatten()
                .find(|value| is_socket_address(value))
                .cloned()
                .unwrap_or_else(|| "<unix>".to_string()),
            "connect" | "sendmsg" | "sendto" | "bind" | "listen" | "accept" | "create" => {
                network_record_path(
                    peer_ip.as_deref(),
                    peer_port,
                    local_ip.as_deref(),
                    local_port,
                )
            }
            _ => "<unknown>".to_string(),
        });

    let dedupe_key = stamp.map(|stamp| {
        let body = &text[text.find("apparmor=").unwrap_or(0)..];
        let mut hasher = DefaultHasher::new();
        stamp.hash(&mut hasher);
        body.trim().hash(&mut hasher);
        hasher.finish()
    });

    ParsedLine::Record(Box::new(ParsedAuditRecord {
        timestamp,
        stamp,
        verdict,
        verdict_raw,
        operation,
        class: fields.get("class").cloned(),
        path,
        name,
        pid: fields
            .get("pid")
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|pid| *pid != 0),
        // `ouid` is the file owner, not the acting task.
        uid: first_field(&fields, &["fsuid", "uid"]).and_then(|value| value.parse().ok()),
        label,
        raw_label,
        comm: fields.get("comm").cloned(),
        info: fields.get("info").cloned(),
        error: fields.get("error").cloned(),
        requested_mask: fields.get("requested_mask").cloned(),
        denied_mask: fields.get("denied_mask").cloned(),
        signal: fields.get("signal").cloned(),
        capability: fields
            .get("capability")
            .and_then(|value| value.parse::<u32>().ok()),
        capname: fields.get("capname").cloned(),
        peer: first_field(&fields, &["peer", "peer_label"]),
        peer_pid: first_field(&fields, &["peer_pid", "target_pid", "opid"])
            .and_then(|value| value.parse::<u32>().ok()),
        family,
        sock_type,
        protocol,
        local_ip,
        local_port,
        peer_ip,
        peer_port,
        addr,
        peer_addr,
        srcname: fields.get("srcname").cloned(),
        fstype: fields.get("fstype").cloned(),
        flags: fields.get("flags").cloned(),
        dedupe_key,
    }))
}

/// auditd's `log_format = ENRICHED` appends interpreted fields after a
/// 0x1d separator; they are not part of the kernel record.
fn strip_enriched_suffix(text: &str) -> &str {
    match text.find('\u{1d}') {
        Some(idx) => &text[..idx],
        None => text,
    }
}

/// `mercury-agent-<id>//null-/bin/x` or `mercury-agent-<id>//&other` → the
/// Mercury profile itself.
pub(crate) fn base_label(label: &str) -> &str {
    let label = label.trim();
    let label = label
        .strip_suffix(')')
        .and_then(|rest| rest.rsplit_once(" ("))
        .map(|(base, _mode)| base)
        .unwrap_or(label);
    match label.find("//") {
        Some(idx) => &label[..idx],
        None => label,
    }
}

fn journald_stamp(line: &RawAuditLine) -> Option<AuditStamp> {
    let micros = line.source_realtime_us?;
    let serial = line.audit_id?;
    Some(AuditStamp {
        secs: micros.div_euclid(1_000_000),
        millis: u32::try_from(micros.rem_euclid(1_000_000) / 1_000).ok()?,
        serial,
    })
}

pub(crate) fn parse_audit_stamp(text: &str) -> Option<AuditStamp> {
    let start = text.find("audit(")? + "audit(".len();
    let rest = &text[start..];
    let inner = &rest[..rest.find(')')?];
    let (time, serial) = inner.split_once(':')?;
    let (secs, millis) = time.split_once('.')?;
    Some(AuditStamp {
        secs: secs.parse().ok()?,
        millis: millis.parse().ok()?,
        serial: serial.parse().ok()?,
    })
}

pub(crate) fn parse_loss_notice(text: &str) -> Option<LossNotice> {
    let text = text.trim();
    for marker in ["kauditd_printk_skb:", "audit_printk_skb:"] {
        if let Some(idx) = text.find(marker) {
            let rest = text[idx + marker.len()..].trim_start();
            let (count, tail) = rest.split_once(char::is_whitespace)?;
            if !tail.trim_start().starts_with("callbacks suppressed") {
                return None;
            }
            return Some(LossNotice {
                source: "kernel_printk",
                count: count.parse().ok()?,
                total: None,
                detail: text.to_string(),
            });
        }
    }

    // Everything below is logged with the kernel's `audit: ` prefix.
    if !text.starts_with("audit:") && !text.contains(" audit: ") {
        return None;
    }
    if let Some(idx) = text.find("audit_lost=") {
        let digits: String = text[idx + "audit_lost=".len()..]
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect();
        let total = digits.parse().ok()?;
        return Some(LossNotice {
            source: "kernel_audit_lost",
            count: total,
            total: Some(total),
            detail: text.to_string(),
        });
    }
    let single = |source: &'static str| {
        Some(LossNotice {
            source,
            count: 1,
            total: None,
            detail: text.to_string(),
        })
    };
    if text.contains("backlog limit exceeded") {
        return single("kernel_audit_backlog");
    }
    if text.contains("hold queue overflow") {
        return single("kernel_audit_hold_queue");
    }
    if text.contains("rate limit exceeded") {
        return single("kernel_audit_rate_limit");
    }
    None
}

fn first_field(fields: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| fields.get(*key).cloned())
}

fn first_u16_field(fields: &HashMap<String, String>, keys: &[&str]) -> Option<u16> {
    keys.iter()
        .find_map(|key| fields.get(*key))
        .and_then(|value| value.parse::<u16>().ok())
}

/// `addr=none` / `addr=?` mean "no address".
fn is_socket_address(value: &str) -> bool {
    !value.is_empty() && value != "none" && value != "?"
}

fn looks_like_ip(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

fn network_record_path(
    peer_ip: Option<&str>,
    peer_port: Option<u16>,
    local_ip: Option<&str>,
    local_port: Option<u16>,
) -> String {
    if let Some(peer) = format_network_endpoint(peer_ip, peer_port) {
        return peer;
    }
    if let Some(local) = format_network_endpoint(local_ip, local_port) {
        return local;
    }
    "<network>".to_string()
}

fn format_network_endpoint(ip: Option<&str>, port: Option<u16>) -> Option<String> {
    match (ip, port) {
        (Some(ip), Some(port)) => Some(format!("{ip}:{port}")),
        (Some(ip), None) => Some(ip.to_string()),
        (None, Some(port)) => Some(format!("port:{port}")),
        (None, None) => None,
    }
}

/// Splits `key=value` / `key="value"` pairs. Unquoted values of
/// [`UNTRUSTED_STRING_FIELDS`] are hex-decoded (AppArmor hex-encodes paths
/// containing spaces, quotes or non-ASCII bytes). A `'` directly after `=`
/// opens a nested record (USER_AVC `msg='apparmor=...'`), whose pairs are
/// parsed in place.
pub(crate) fn parse_kv_fields(message: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let bytes = message.as_bytes();
    let mut idx = 0usize;

    while idx < bytes.len() {
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        let key_start = idx;
        while idx < bytes.len() && (bytes[idx].is_ascii_alphanumeric() || bytes[idx] == b'_') {
            idx += 1;
        }
        if idx == key_start || idx >= bytes.len() || bytes[idx] != b'=' {
            idx += 1;
            continue;
        }
        let key = &message[key_start..idx];
        idx += 1;
        if idx < bytes.len() && bytes[idx] == b'\'' {
            idx += 1;
            continue;
        }
        let value = if idx < bytes.len() && bytes[idx] == b'"' {
            idx += 1;
            let value_start = idx;
            while idx < bytes.len() && bytes[idx] != b'"' {
                idx += 1;
            }
            let out = message[value_start..idx].to_string();
            if idx < bytes.len() {
                idx += 1;
            }
            out
        } else {
            let value_start = idx;
            while idx < bytes.len() && !bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            let raw = message[value_start..idx].trim_end_matches('\'');
            if UNTRUSTED_STRING_FIELDS.contains(&key) {
                decode_hex_string(raw).unwrap_or_else(|| raw.to_string())
            } else {
                raw.to_string()
            }
        };
        fields.insert(key.to_string(), value);
    }

    fields
}

pub(crate) fn decode_hex_string(value: &str) -> Option<String> {
    if value.len() < 2
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|idx| u8::from_str_radix(&value[idx..idx + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Signal names as AppArmor logs them (x86/arm Linux numbering).
pub(crate) fn signal_number(name: &str) -> Option<u32> {
    let name = name.trim().to_ascii_lowercase();
    if let Ok(number) = name.parse::<u32>() {
        return Some(number);
    }
    if let Some(offset) = name.strip_prefix("rtmin+") {
        return offset.parse::<u32>().ok().map(|offset| 34 + offset);
    }
    let number = match name.as_str() {
        "exists" => 0,
        "hup" => 1,
        "int" => 2,
        "quit" => 3,
        "ill" => 4,
        "trap" => 5,
        "abrt" | "iot" => 6,
        "bus" => 7,
        "fpe" => 8,
        "kill" => 9,
        "usr1" => 10,
        "segv" => 11,
        "usr2" => 12,
        "pipe" => 13,
        "alrm" => 14,
        "term" => 15,
        "stkflt" => 16,
        "chld" => 17,
        "cont" => 18,
        "stop" => 19,
        "stp" | "tstp" => 20,
        "ttin" => 21,
        "ttou" => 22,
        "urg" => 23,
        "xcpu" => 24,
        "xfsz" => 25,
        "vtalrm" => 26,
        "prof" => 27,
        "winch" => 28,
        "io" | "poll" => 29,
        "pwr" => 30,
        "sys" => 31,
        _ => return None,
    };
    Some(number)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppArmorAction {
    File(ActionType, FileOp),
    Exec,
    Process(ActionType, &'static str),
    Network(ActionType),
}

/// Maps a record to a Mercury action. `None` means Mercury has no action
/// type for it; the caller emits it as `apparmor_unmapped_operation`.
pub(crate) fn action_from_record(record: &ParsedAuditRecord) -> Option<AppArmorAction> {
    let operation = record.operation.as_str();
    if let Some(action_type) = socket_action(operation)
        && (operation != "create" || record.is_socket())
    {
        return Some(AppArmorAction::Network(action_type));
    }
    if record.class.as_deref() == Some("net") {
        // recvmsg, getsockopt, shutdown, ... have no Mercury action type.
        return None;
    }
    action_from_operation(operation, record.requested_mask.as_deref())
}

fn socket_action(operation: &str) -> Option<ActionType> {
    match operation {
        "connect" => Some(ActionType::NetConnect),
        "sendmsg" | "sendto" | "send" => Some(ActionType::NetSendmsg),
        "bind" => Some(ActionType::NetBind),
        "listen" => Some(ActionType::NetListen),
        "accept" => Some(ActionType::NetAccept),
        "create" => Some(ActionType::NetCreate),
        _ => None,
    }
}

pub(crate) fn action_from_operation(
    operation: &str,
    requested_mask: Option<&str>,
) -> Option<AppArmorAction> {
    match operation {
        "exec" => Some(AppArmorAction::Exec),
        "ptrace" => Some(AppArmorAction::Process(ActionType::ProcPtrace, "<ptrace>")),
        "signal" => Some(AppArmorAction::Process(ActionType::ProcKill, "<task-kill>")),
        "capable" => Some(AppArmorAction::Process(
            ActionType::ProcCapable,
            "<capable>",
        )),
        "mount" | "umount" | "remount" | "pivotroot" | "move_mount" => {
            Some(AppArmorAction::Process(ActionType::ProcMount, "<mount>"))
        }
        "userns_create" => Some(AppArmorAction::Process(ActionType::ProcUserns, "<userns>")),
        "file_mmap" | "file_mprotect" => {
            Some(AppArmorAction::File(ActionType::FileMmap, FileOp::Write))
        }
        "unlink" | "inode_unlink" => {
            Some(AppArmorAction::File(ActionType::FileDelete, FileOp::Delete))
        }
        "rename" | "rename_src" | "rename_dest" => {
            Some(AppArmorAction::File(ActionType::FileRename, FileOp::Rename))
        }
        "link" => Some(AppArmorAction::File(ActionType::FileLink, FileOp::Link)),
        "symlink_create" | "symlink" => Some(AppArmorAction::File(
            ActionType::FileSymlink,
            FileOp::Symlink,
        )),
        "mkdir" => Some(AppArmorAction::File(ActionType::FileMkdir, FileOp::Mkdir)),
        "rmdir" => Some(AppArmorAction::File(ActionType::FileRmdir, FileOp::Rmdir)),
        "create" | "mknod" => Some(AppArmorAction::File(ActionType::FileCreate, FileOp::Create)),
        "chmod" => Some(AppArmorAction::File(ActionType::FileChmod, FileOp::Chmod)),
        "chown" => Some(AppArmorAction::File(ActionType::FileChown, FileOp::Chown)),
        "truncate" => Some(AppArmorAction::File(
            ActionType::FileTruncate,
            FileOp::Truncate,
        )),
        // stat(2) and friends.
        "getattr" => Some(AppArmorAction::File(ActionType::FileRead, FileOp::Read)),
        // utimes / xattr style metadata changes.
        "setattr" => Some(AppArmorAction::File(ActionType::FileChmod, FileOp::Chmod)),
        "open" | "file_perm" | "file_inherit" | "file_receive" | "file_lock" | "sysctl" => {
            Some(file_action_from_mask(requested_mask.unwrap_or_default()))
        }
        _ => None,
    }
}

fn file_action_from_mask(mask: &str) -> AppArmorAction {
    if mask.contains('m') {
        AppArmorAction::File(ActionType::FileMmap, FileOp::Write)
    } else if mask.contains('c') {
        AppArmorAction::File(ActionType::FileCreate, FileOp::Create)
    } else if mask.contains('d') {
        AppArmorAction::File(ActionType::FileDelete, FileOp::Delete)
    } else if mask.contains('w') || mask.contains('a') || mask.contains('k') {
        AppArmorAction::File(ActionType::FileWrite, FileOp::Write)
    } else if mask.contains('l') {
        AppArmorAction::File(ActionType::FileLink, FileOp::Link)
    } else {
        AppArmorAction::File(ActionType::FileRead, FileOp::Read)
    }
}

/// Bounded FIFO set of record keys already emitted, so a record read from
/// both journald transports (or journald and audit.log) is emitted once.
#[derive(Debug)]
pub(crate) struct DedupeWindow {
    capacity: usize,
    order: VecDeque<u64>,
    seen: HashSet<u64>,
}

impl DedupeWindow {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    /// Returns false when `key` was already recorded.
    pub(crate) fn insert(&mut self, key: u64) -> bool {
        if !self.seen.insert(key) {
            return false;
        }
        self.order.push_back(key);
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(text: &str) -> ParsedAuditRecord {
        match parse_line(&RawAuditLine::kernel(text)) {
            ParsedLine::Record(record) => *record,
            other => panic!("expected record, got {other:?}"),
        }
    }

    #[test]
    fn parses_audit_verdict_with_stamp_and_comm() {
        let record = record(
            r#"audit: type=1400 audit(1700000000.065:42): apparmor="AUDIT" operation="getattr" class="file" profile="mercury-agent-test" name="/home/example/.config/x.json" pid=1234 comm="example-agent" requested_mask="r" fsuid=1000 ouid=0"#,
        );
        assert_eq!(record.verdict, Verdict::Audit);
        assert_eq!(record.decision(), Decision::Allow);
        assert_eq!(
            record.stamp,
            Some(AuditStamp {
                secs: 1700000000,
                millis: 65,
                serial: 42
            })
        );
        assert_eq!(record.timestamp.timestamp_millis(), 1_700_000_000_065);
        assert_eq!(record.comm.as_deref(), Some("example-agent"));
        assert_eq!(record.uid, Some(1000));
        assert_eq!(
            record.label,
            "mercury-agent-test"
        );
        assert_eq!(
            action_from_record(&record),
            Some(AppArmorAction::File(ActionType::FileRead, FileOp::Read))
        );
    }

    #[test]
    fn killed_is_a_deny_and_unknown_verdicts_are_kept() {
        let killed = record(
            r#"audit: type=1400 audit(1.000:1): apparmor="KILLED" operation="open" profile="mercury-agent-abc" name="/etc/shadow" pid=5 requested_mask="r" denied_mask="r""#,
        );
        assert_eq!(killed.decision(), Decision::Deny);
        let hint = record(
            r#"audit: type=1400 audit(1.000:2): apparmor="HINT" operation="exec" profile="mercury-agent-abc" name="/bin/x" pid=5"#,
        );
        assert_eq!(hint.verdict, Verdict::Unknown);
        assert_eq!(hint.verdict_raw, "HINT");
    }

    #[test]
    fn status_record_is_attributed_through_the_loaded_profile_name() {
        let status = record(
            r#"audit: type=1400 audit(1.000:3): apparmor="STATUS" operation="profile_replace" info="same as current profile, skipping" profile="unconfined" name="mercury-agent-abc" pid=77 comm="apparmor_parser""#,
        );
        assert_eq!(status.verdict, Verdict::Status);
        assert_eq!(status.label, "mercury-agent-abc");
        assert_eq!(
            status.info.as_deref(),
            Some("same as current profile, skipping")
        );
    }

    #[test]
    fn foreign_profiles_are_ignored() {
        let line = RawAuditLine::kernel(
            r#"audit: type=1400 audit(1.000:4): apparmor="DENIED" operation="open" profile="snap.firefox" name="/tmp/mercury-agent-x" pid=5"#,
        );
        assert!(matches!(parse_line(&line), ParsedLine::Ignored));
    }

    #[test]
    fn journald_audit_transport_uses_audit_id_and_source_time() {
        let line = RawAuditLine {
            text: r#"AVC apparmor="DENIED" operation="open" class="file" profile="mercury-agent-abc" name="/etc/shadow" pid=9 comm="cat" requested_mask="r" denied_mask="r" fsuid=0 ouid=0"#.to_string(),
            origin: RecordOrigin::JournaldAudit,
            audit_id: Some(4242),
            source_realtime_us: Some(1_700_000_000_065_000),
            receive_realtime_us: Some(1_790_684_427_000_000),
        };
        let ParsedLine::Record(record) = parse_line(&line) else {
            panic!("expected record");
        };
        assert_eq!(
            record.stamp,
            Some(AuditStamp {
                secs: 1700000000,
                millis: 65,
                serial: 4242
            })
        );
        assert_eq!(record.timestamp.timestamp_millis(), 1_700_000_000_065);
    }

    #[test]
    fn same_record_from_every_source_has_one_dedupe_key() {
        let body = r#"apparmor="DENIED" operation="open" class="file" profile="mercury-agent-abc" name="/etc/shadow" pid=9 comm="cat" requested_mask="r" denied_mask="r" fsuid=0 ouid=0"#;
        let kernel = record(&format!(
            "audit: type=1400 audit(1790684426.065:4242): {body}"
        ));
        let audit_log = match parse_line(&RawAuditLine {
            text: format!("type=AVC msg=audit(1790684426.065:4242): {body}\u{1d}FSUID=\"root\""),
            origin: RecordOrigin::AuditLog,
            audit_id: None,
            source_realtime_us: None,
            receive_realtime_us: None,
        }) {
            ParsedLine::Record(record) => record,
            other => panic!("unexpected {other:?}"),
        };
        let journald_audit = match parse_line(&RawAuditLine {
            text: format!("AVC {body}"),
            origin: RecordOrigin::JournaldAudit,
            audit_id: Some(4242),
            source_realtime_us: Some(1_700_000_000_065_000),
            receive_realtime_us: None,
        }) {
            ParsedLine::Record(record) => record,
            other => panic!("unexpected {other:?}"),
        };
        assert!(kernel.dedupe_key.is_some());
        assert_eq!(kernel.dedupe_key, audit_log.dedupe_key);
        assert_eq!(kernel.dedupe_key, journald_audit.dedupe_key);

        let rename_dest = record(&format!(
            "audit: type=1400 audit(1790684426.065:4242): {}",
            body.replace("operation=\"open\"", "operation=\"rename_dest\"")
        ));
        assert_ne!(kernel.dedupe_key, rename_dest.dedupe_key);
    }

    #[test]
    fn hex_encoded_names_are_decoded() {
        // "/tmp/a b.txt" and comm "my prog" arrive unquoted as hex.
        let record = record(
            r#"audit: type=1400 audit(1.000:5): apparmor="DENIED" operation="open" profile="mercury-agent-abc" name=2F746D702F6120622E747874 pid=5 comm=6D792070726F67 requested_mask="r" denied_mask="r" fsuid=1000"#,
        );
        assert_eq!(record.path, "/tmp/a b.txt");
        assert_eq!(record.comm.as_deref(), Some("my prog"));
        // Numeric fields are never hex-decoded.
        assert_eq!(record.pid, Some(5));
        assert_eq!(decode_hex_string("abc"), None);
        assert_eq!(decode_hex_string("none"), None);
    }

    #[test]
    fn user_avc_nested_message_is_parsed() {
        let record = record(
            r#"audit: type=1107 audit(1.000:6): pid=1 uid=102 auid=4294967295 ses=4294967295 subj=unconfined msg='apparmor="DENIED" operation="dbus_method_call" bus="system" path="/org/freedesktop/login1" interface="org.freedesktop.login1.Manager" member="PowerOff" mask="send" name="org.freedesktop.login1" pid=4321 label="mercury-agent-abc" peer_pid=1 peer_label="unconfined" exe="/usr/bin/dbus-daemon" sauid=102 hostname=? addr=? terminal=?'"#,
        );
        assert_eq!(record.operation, "dbus_method_call");
        assert_eq!(record.pid, Some(4321));
        assert_eq!(record.label, "mercury-agent-abc");
        assert_eq!(record.peer_pid, Some(1));
        assert_eq!(action_from_record(&record), None);
    }

    #[test]
    fn child_and_stacked_labels_resolve_to_the_base_profile() {
        assert_eq!(
            base_label("mercury-agent-abc//null-/usr/bin/foo"),
            "mercury-agent-abc"
        );
        assert_eq!(
            base_label("mercury-agent-abc (enforce)"),
            "mercury-agent-abc"
        );
        assert_eq!(
            base_label("mercury-agent-abc//&:ns:unconfined (complain)"),
            "mercury-agent-abc"
        );
    }

    #[test]
    fn loss_notices_are_recognized() {
        assert_eq!(
            parse_loss_notice("kauditd_printk_skb: 1750 callbacks suppressed"),
            Some(LossNotice {
                source: "kernel_printk",
                count: 1750,
                total: None,
                detail: "kauditd_printk_skb: 1750 callbacks suppressed".to_string(),
            })
        );
        let lost =
            parse_loss_notice("audit: audit_lost=42 audit_rate_limit=0 audit_backlog_limit=64")
                .expect("audit_lost");
        assert_eq!(lost.source, "kernel_audit_lost");
        assert_eq!(lost.total, Some(42));
        assert_eq!(
            parse_loss_notice("audit: backlog limit exceeded").map(|n| n.source),
            Some("kernel_audit_backlog")
        );
        assert_eq!(
            parse_loss_notice("net_ratelimit: 5 callbacks suppressed"),
            None
        );
        assert_eq!(parse_loss_notice("usb 1-1: new device"), None);
    }

    #[test]
    fn operation_mapping_covers_previously_dropped_operations() {
        let map = |text: &str| action_from_record(&record(text));
        assert_eq!(
            map(
                r#"audit(1.000:1): apparmor="DENIED" operation="mount" class="mount" info="failed mntpnt match" profile="mercury-agent-abc" name="/mnt/" pid=5 fstype="tmpfs" srcname="tmpfs" flags="rw""#
            ),
            Some(AppArmorAction::Process(ActionType::ProcMount, "<mount>"))
        );
        assert_eq!(
            map(
                r#"audit(1.000:2): apparmor="DENIED" operation="userns_create" class="namespace" profile="mercury-agent-abc" pid=5 requested="userns_create" denied="userns_create""#
            ),
            Some(AppArmorAction::Process(ActionType::ProcUserns, "<userns>"))
        );
        assert_eq!(
            map(
                r#"audit(1.000:3): apparmor="AUDIT" operation="setattr" class="file" profile="mercury-agent-abc" name="/w/x" pid=5 requested_mask="w""#
            ),
            Some(AppArmorAction::File(ActionType::FileChmod, FileOp::Chmod))
        );
        assert_eq!(
            map(
                r#"audit(1.000:4): apparmor="AUDIT" operation="file_receive" class="file" profile="mercury-agent-abc" name="/w/x" pid=5 requested_mask="w""#
            ),
            Some(AppArmorAction::File(ActionType::FileWrite, FileOp::Write))
        );
        assert_eq!(
            map(
                r#"audit(1.000:5): apparmor="DENIED" operation="connect" class="net" family="unix" sock_type="stream" protocol=0 profile="mercury-agent-abc" pid=5 requested_mask="send connect" addr=none peer_addr="@/tmp/.X11-unix/X0" peer="unconfined""#
            ),
            Some(AppArmorAction::Network(ActionType::NetConnect))
        );
        assert_eq!(
            map(
                r#"audit(1.000:6): apparmor="DENIED" operation="recvmsg" class="net" family="unix" sock_type="stream" protocol=0 profile="mercury-agent-abc" pid=5 addr=none"#
            ),
            None
        );
        assert_eq!(
            map(
                r#"audit(1.000:7): apparmor="DENIED" operation="change_onexec" profile="mercury-agent-abc" name="other" pid=5"#
            ),
            None
        );
        assert_eq!(
            map(
                r#"audit(1.000:8): apparmor="DENIED" operation="create" class="net" family="inet6" sock_type="dgram" protocol=17 profile="mercury-agent-abc" pid=5"#
            ),
            Some(AppArmorAction::Network(ActionType::NetCreate))
        );
        assert_eq!(
            map(
                r#"audit(1.000:9): apparmor="AUDIT" operation="create" class="file" profile="mercury-agent-abc" name="/w/new" pid=5 requested_mask="c""#
            ),
            Some(AppArmorAction::File(ActionType::FileCreate, FileOp::Create))
        );
    }

    #[test]
    fn unix_socket_path_prefers_file_name_then_address() {
        let pathname = record(
            r#"audit(1.000:1): apparmor="DENIED" operation="connect" class="file" profile="mercury-agent-abc" name="/run/dbus/system_bus_socket" pid=5 requested_mask="wr""#,
        );
        assert!(pathname.is_unix_socket());
        assert_eq!(
            pathname.unix_socket_path(true).as_deref(),
            Some("/run/dbus/system_bus_socket")
        );
        let abstract_socket = record(
            r#"audit(1.000:2): apparmor="DENIED" operation="connect" class="net" family="unix" profile="mercury-agent-abc" pid=5 addr=none peer_addr="@/tmp/.X11-unix/X0""#,
        );
        assert_eq!(
            abstract_socket.unix_socket_path(true).as_deref(),
            Some("@/tmp/.X11-unix/X0")
        );
        assert_eq!(
            abstract_socket.unix_socket_path(false).as_deref(),
            Some("@/tmp/.X11-unix/X0")
        );
    }

    #[test]
    fn signal_names_map_to_numbers() {
        assert_eq!(signal_number("term"), Some(15));
        assert_eq!(signal_number("kill"), Some(9));
        assert_eq!(signal_number("rtmin+3"), Some(37));
        assert_eq!(signal_number("exists"), Some(0));
        assert_eq!(signal_number("lost"), None);
    }

    #[test]
    fn dedupe_window_evicts_oldest() {
        let mut window = DedupeWindow::new(2);
        assert!(window.insert(1));
        assert!(!window.insert(1));
        assert!(window.insert(2));
        assert!(window.insert(3));
        assert!(window.insert(1));
    }
}
