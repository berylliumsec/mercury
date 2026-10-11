//! journald mirror.
//!
//! `native` mode speaks the journald native protocol on
//! `/run/systemd/journal/socket`: one datagram of `KEY=VALUE\n` fields, with
//! values that contain a newline sent as `KEY\n<u64 LE length><bytes>\n`.
//! Payloads too large for a datagram go through a sealed memfd passed with
//! `SCM_RIGHTS` and an empty datagram, like `sd_journal_sendv()` does.
//! `syslog` mode keeps the pre-v2 behavior of sending an RFC 3164 line to
//! journald's syslog forwarding socket, which only a local syslog daemon
//! reads.

use std::borrow::Cow;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::Duration;

use core_types::{ActionType, AuditEvent, Decision, DecisionReason, Resource};
use serde_json::Value;

use crate::JournaldMirrorMode;

pub(crate) const JOURNALD_NATIVE_SOCKET: &str = "/run/systemd/journal/socket";
pub(crate) const JOURNALD_SYSLOG_SOCKET: &str = "/run/systemd/journal/syslog";
/// Payloads above this go through a memfd without trying a datagram first
/// (the default `wmem_default` caps AF_UNIX datagrams at ~208 KiB).
const LARGE_PAYLOAD_BYTES: usize = 200 * 1024;
/// Upper bound on blocking when journald is not draining its socket.
const SEND_TIMEOUT: Duration = Duration::from_millis(250);
const MESSAGE_MAX_CHARS: usize = 512;
const SYSLOG_FACILITY_LOCAL0: u8 = 16 << 3;
/// System events that indicate lost or unverifiable audit data.
const WARNING_SYSTEM_EVENTS: [&str; 2] = ["telemetry_loss", "audit_integrity_unavailable"];
/// Captured model content dropped when a record does not fit journald.
const MODEL_CONTENT_FIELDS: [&str; 4] = ["system", "messages", "output_text", "reasoning_text"];

/// One audit record as written to the log.
pub(crate) struct MirrorRecord<'a> {
    pub event: &'a AuditEvent,
    /// Stamped record JSON without the integrity member.
    pub json: &'a str,
    pub event_id: &'a str,
    pub seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MirrorOutcome {
    Sent,
    /// Sent without (part of) the record JSON; carries the original error.
    Truncated(String),
    Failed(String),
}

#[derive(Debug)]
pub(crate) struct JournalMirror {
    mode: JournaldMirrorMode,
    socket: UnixDatagram,
    target: PathBuf,
    large_payload_bytes: usize,
    use_memfd: bool,
}

struct SendError {
    /// The payload was too large (or the large-payload path failed), so a
    /// smaller payload may still go through.
    size_related: bool,
    error: io::Error,
}

impl JournalMirror {
    pub(crate) fn new(mode: JournaldMirrorMode, target: Option<PathBuf>) -> io::Result<Self> {
        let socket = UnixDatagram::unbound()?;
        socket.set_write_timeout(Some(SEND_TIMEOUT))?;
        let target = target.unwrap_or_else(|| {
            PathBuf::from(match mode {
                JournaldMirrorMode::Native => JOURNALD_NATIVE_SOCKET,
                JournaldMirrorMode::Syslog => JOURNALD_SYSLOG_SOCKET,
            })
        });
        Ok(Self {
            mode,
            socket,
            target,
            large_payload_bytes: LARGE_PAYLOAD_BYTES,
            use_memfd: cfg!(target_os = "linux"),
        })
    }

    pub(crate) fn target(&self) -> &std::path::Path {
        &self.target
    }

    pub(crate) fn send(&self, record: &MirrorRecord<'_>) -> MirrorOutcome {
        match self.mode {
            JournaldMirrorMode::Native => self.send_native(record),
            JournaldMirrorMode::Syslog => self.send_syslog(record),
        }
    }

    fn send_native(&self, record: &MirrorRecord<'_>) -> MirrorOutcome {
        let payload = encode_journal_fields(&native_fields(record, Some(record.json), false));
        let first = match self.send_payload(&payload) {
            Ok(()) => return MirrorOutcome::Sent,
            Err(err) if !err.size_related => return MirrorOutcome::Failed(err.error.to_string()),
            Err(err) => err.error,
        };
        if let Some(stripped) = strip_model_content(record.json) {
            let payload = encode_journal_fields(&native_fields(record, Some(&stripped), true));
            if self.send_payload(&payload).is_ok() {
                return MirrorOutcome::Truncated(first.to_string());
            }
        }
        let payload = encode_journal_fields(&native_fields(record, None, true));
        match self.send_payload(&payload) {
            Ok(()) => MirrorOutcome::Truncated(first.to_string()),
            Err(err) => {
                MirrorOutcome::Failed(format!("{first}; without record JSON: {}", err.error))
            }
        }
    }

    fn send_payload(&self, payload: &[u8]) -> Result<(), SendError> {
        if payload.len() <= self.large_payload_bytes {
            match self.socket.send_to(payload, &self.target) {
                Ok(_) => return Ok(()),
                Err(err) if is_size_error(&err) => {}
                Err(error) => {
                    return Err(SendError {
                        size_related: false,
                        error,
                    });
                }
            }
        }
        self.send_memfd(payload).map_err(|error| SendError {
            size_related: true,
            error,
        })
    }

    #[cfg(target_os = "linux")]
    fn send_memfd(&self, payload: &[u8]) -> io::Result<()> {
        use std::os::fd::AsRawFd;

        if !self.use_memfd {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "large journald payloads are disabled",
            ));
        }
        let memfd = sealed_memfd(payload)?;
        send_fd(self.socket.as_raw_fd(), &self.target, memfd.as_raw_fd())
    }

    #[cfg(not(target_os = "linux"))]
    fn send_memfd(&self, _payload: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "large journald payloads need memfd (Linux only)",
        ))
    }

    fn send_syslog(&self, record: &MirrorRecord<'_>) -> MirrorOutcome {
        let event = record.event;
        let head = format!(
            "<{}>mercury decision={} reason={} agent_id={} profile={} msg={}",
            SYSLOG_FACILITY_LOCAL0 + priority(event),
            decision_str(event.decision),
            event.reason,
            event.agent_id,
            event.profile,
            clean_text(&event.message, usize::MAX)
        );
        let full = format!("{head} data={}", record.json);
        let first = match self.socket.send_to(full.as_bytes(), &self.target) {
            Ok(_) => return MirrorOutcome::Sent,
            Err(err) if is_size_error(&err) => err,
            Err(err) => return MirrorOutcome::Failed(err.to_string()),
        };
        if let Some(stripped) = strip_model_content(record.json) {
            let line = format!("{head} truncated=1 data={stripped}");
            if self.socket.send_to(line.as_bytes(), &self.target).is_ok() {
                return MirrorOutcome::Truncated(first.to_string());
            }
        }
        match self
            .socket
            .send_to(format!("{head} truncated=1").as_bytes(), &self.target)
        {
            Ok(_) => MirrorOutcome::Truncated(first.to_string()),
            Err(err) => MirrorOutcome::Failed(format!("{first}; without record JSON: {err}")),
        }
    }
}

fn is_size_error(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EMSGSIZE) | Some(libc::ENOBUFS)
    )
}

/// Encodes fields in the journald native protocol. Values containing a
/// newline use the binary-safe length-prefixed form.
pub fn encode_journal_fields<K: AsRef<str>, V: AsRef<[u8]>>(fields: &[(K, V)]) -> Vec<u8> {
    let size = fields
        .iter()
        .map(|(key, value)| key.as_ref().len() + value.as_ref().len() + 10)
        .sum();
    let mut out = Vec::with_capacity(size);
    for (key, value) in fields {
        let key = key.as_ref();
        let value = value.as_ref();
        debug_assert!(
            !key.is_empty()
                && !key.starts_with('_')
                && key
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
            "invalid journal field name {key}"
        );
        out.extend_from_slice(key.as_bytes());
        if value.contains(&b'\n') {
            out.push(b'\n');
            out.extend_from_slice(&(value.len() as u64).to_le_bytes());
            out.extend_from_slice(value);
        } else {
            out.push(b'=');
            out.extend_from_slice(value);
        }
        out.push(b'\n');
    }
    out
}

fn native_fields<'a>(
    record: &'a MirrorRecord<'a>,
    json: Option<&'a str>,
    truncated: bool,
) -> Vec<(&'static str, Cow<'a, [u8]>)> {
    let borrowed = |text: &'a str| Cow::Borrowed(text.as_bytes());
    let owned = |text: String| Cow::Owned(text.into_bytes());
    let event = record.event;
    let mut fields = vec![
        ("MESSAGE", owned(summary_message(event))),
        ("PRIORITY", owned(priority(event).to_string())),
        ("SYSLOG_IDENTIFIER", borrowed("mercury")),
        ("MERCURY_EVENT_ID", borrowed(record.event_id)),
        ("MERCURY_DECISION", borrowed(decision_str(event.decision))),
        ("MERCURY_REASON", owned(event.reason.to_string())),
        ("MERCURY_ACTION", owned(action_str(event.action_type))),
        ("MERCURY_AGENT_ID", borrowed(&event.agent_id)),
        ("MERCURY_PROFILE", borrowed(&event.profile)),
    ];
    if let Some(rule_id) = &event.rule_id {
        fields.push(("MERCURY_RULE_ID", borrowed(rule_id)));
    }
    if let Some(pid) = event.pid {
        fields.push(("MERCURY_PID", owned(pid.to_string())));
    }
    if let Some(source) = &event.context.source {
        fields.push(("MERCURY_SOURCE", borrowed(source)));
    }
    if let Some(seq) = record.seq {
        fields.push(("MERCURY_AUDIT_SEQ", owned(seq.to_string())));
    }
    if truncated {
        fields.push(("MERCURY_TRUNCATED", borrowed("1")));
    }
    if let Some(json) = json {
        fields.push(("MERCURY_JSON", borrowed(json)));
    }
    fields
}

/// journald priority: 3 for ERROR_* reasons, 4 for denies and data-loss
/// system events, 5 for other system events, 6 for allows.
pub(crate) fn priority(event: &AuditEvent) -> u8 {
    if matches!(
        event.reason,
        DecisionReason::ErrorInvalidAction
            | DecisionReason::ErrorPolicyUnavailable
            | DecisionReason::ErrorEnforcementUnavailable
    ) {
        return 3;
    }
    if event.decision == Decision::Deny {
        return 4;
    }
    if event.action_type == ActionType::SystemEvent {
        let warning = matches!(
            &event.resource,
            Resource::System(system) if WARNING_SYSTEM_EVENTS.contains(&system.event.as_str())
        );
        return if warning { 4 } else { 5 };
    }
    6
}

fn decision_str(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
    }
}

fn action_str(action: ActionType) -> String {
    match serde_json::to_value(action) {
        Ok(Value::String(name)) => name,
        _ => format!("{action:?}"),
    }
}

/// `mercury <decision> <action> <resource> agent=<id>`
pub(crate) fn summary_message(event: &AuditEvent) -> String {
    let text = format!(
        "mercury {} {} {} agent={}",
        decision_str(event.decision),
        action_str(event.action_type),
        resource_summary(&event.resource),
        event.agent_id
    );
    clean_text(&text, MESSAGE_MAX_CHARS)
}

fn resource_summary(resource: &Resource) -> String {
    match resource {
        Resource::File(file) => match &file.source_path {
            Some(source) => format!("{source} -> {}", file.path),
            None => file.path.clone(),
        },
        Resource::Exec(exec) => exec.path.clone(),
        Resource::Network(net) => {
            if let Some(url) = &net.full_url {
                url.clone()
            } else if let Some(socket) = &net.socket_path {
                socket.clone()
            } else {
                let host = net
                    .dest_host
                    .as_deref()
                    .or(net.dest_ip.as_deref())
                    .unwrap_or("?");
                format!("{host}:{}", net.dest_port)
            }
        }
        Resource::McpTool(tool) => format!("{}/{}", tool.server_id, tool.tool_name),
        Resource::McpResource(res) => format!("{} {}", res.server_id, res.uri),
        Resource::System(system) => match &system.detail {
            Some(detail) => format!("{}: {detail}", system.event),
            None => system.event.clone(),
        },
    }
}

/// Replaces control characters with spaces and caps the length.
fn clean_text(text: &str, max_chars: usize) -> String {
    let mut out: String = text
        .chars()
        .take(max_chars)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if text.chars().nth(max_chars).is_some() {
        out.push_str("...");
    }
    out
}

/// Removes captured model content (prompts, completions, tool arguments)
/// from a record, keeping the call metadata.
pub(crate) fn strip_model_content(json: &str) -> Option<String> {
    let mut value: Value = serde_json::from_str(json).ok()?;
    if let Some(model) = value.get_mut("model").and_then(Value::as_object_mut) {
        for field in MODEL_CONTENT_FIELDS {
            model.remove(field);
        }
        if let Some(calls) = model.get_mut("tool_calls").and_then(Value::as_array_mut) {
            for call in calls.iter_mut().filter_map(Value::as_object_mut) {
                call.remove("arguments");
            }
        }
    }
    serde_json::to_string(&value).ok()
}

/// A memfd holding `payload`, sealed against any further change as journald
/// requires.
#[cfg(target_os = "linux")]
fn sealed_memfd(payload: &[u8]) -> io::Result<std::fs::File> {
    use std::io::Write;
    use std::os::fd::FromRawFd;

    // SAFETY: the name is a valid NUL-terminated string; the returned fd is
    // checked and owned by the File below.
    let fd = unsafe {
        libc::memfd_create(
            c"mercury-journal".as_ptr(),
            libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly created descriptor nothing else owns.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(payload)?;
    let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
    // SAFETY: plain fcntl on a descriptor we own.
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

/// Sends an empty datagram carrying `fd` to the socket at `target`.
#[cfg(target_os = "linux")]
fn send_fd(socket: libc::c_int, target: &std::path::Path, fd: libc::c_int) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: all-zero is a valid sockaddr_un.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path = target.as_os_str().as_bytes();
    if path.len() >= addr.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journald socket path is too long",
        ));
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(path) {
        *dst = *src as libc::c_char;
    }
    let addr_len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;

    let fd_size = std::mem::size_of::<libc::c_int>() as libc::c_uint;
    // u64 storage keeps the control buffer aligned for cmsghdr.
    let mut control = [0u64; 8];
    // SAFETY: CMSG_SPACE only computes a size.
    let control_len = unsafe { libc::CMSG_SPACE(fd_size) } as usize;
    debug_assert!(control_len <= std::mem::size_of_val(&control));

    // SAFETY: all-zero is a valid msghdr; every pointer set below outlives
    // the sendmsg call, and the cmsg header fits in `control`.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = (&mut addr as *mut libc::sockaddr_un).cast();
        msg.msg_namelen = addr_len as libc::socklen_t;
        msg.msg_iov = std::ptr::null_mut();
        msg.msg_iovlen = 0;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control_len as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("no room for SCM_RIGHTS header"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_size) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), fd);
        if libc::sendmsg(socket, &msg, libc::MSG_NOSIGNAL) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use std::collections::BTreeMap;
    use std::os::fd::AsRawFd;

    use core_types::{FileOp, FileResource, ModelCallAuditContext, ModelMessage, SystemResource};

    use super::*;

    /// Decodes a native-protocol payload into its fields.
    pub(crate) fn decode_fields(mut data: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let mut fields = BTreeMap::new();
        while !data.is_empty() {
            let end = data
                .iter()
                .position(|b| *b == b'=' || *b == b'\n')
                .expect("field terminator");
            let key = String::from_utf8(data[..end].to_vec()).expect("key utf8");
            if data[end] == b'=' {
                let rest = &data[end + 1..];
                let stop = rest.iter().position(|b| *b == b'\n').expect("value end");
                fields.insert(key, rest[..stop].to_vec());
                data = &rest[stop + 1..];
            } else {
                let rest = &data[end + 1..];
                let len = u64::from_le_bytes(rest[..8].try_into().unwrap()) as usize;
                fields.insert(key, rest[8..8 + len].to_vec());
                assert_eq!(rest[8 + len], b'\n', "binary field terminator");
                data = &rest[8 + len + 1..];
            }
        }
        fields
    }

    /// Receives one message; follows an `SCM_RIGHTS` memfd when the datagram
    /// is empty. Returns the payload and whether it came through a memfd.
    pub(crate) fn recv_journal(socket: &UnixDatagram) -> (Vec<u8>, bool) {
        let mut buf = vec![0u8; 512 * 1024];
        let mut control = [0u64; 8];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: test-only recvmsg with buffers that outlive the call.
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = std::mem::size_of_val(&control) as _;
            let n = libc::recvmsg(socket.as_raw_fd(), &mut msg, 0);
            assert!(n >= 0, "recvmsg: {}", io::Error::last_os_error());
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                buf.truncate(n as usize);
                return (buf, false);
            }
            assert_eq!(n, 0, "memfd datagram must be empty");
            assert_eq!((*cmsg).cmsg_type, libc::SCM_RIGHTS);
            let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>());
            let seals = libc::fcntl(fd, libc::F_GET_SEALS);
            assert_ne!(seals & libc::F_SEAL_WRITE, 0, "memfd must be sealed");
            let size = libc::lseek(fd, 0, libc::SEEK_END) as usize;
            let mut data = vec![0u8; size];
            let read = libc::pread(fd, data.as_mut_ptr().cast(), size, 0);
            assert_eq!(read as usize, size);
            libc::close(fd);
            (data, true)
        }
    }

    fn deny_event() -> AuditEvent {
        let mut event = AuditEvent::system(
            "kernel-ebpf",
            SystemResource::new("unused"),
            "v1",
            "blocked",
        );
        event.action_type = ActionType::FileRead;
        event.decision = Decision::Deny;
        event.reason = DecisionReason::DenyByRule;
        event.rule_id = Some("deny-ssh".to_string());
        event.agent_id = "agent-7".to_string();
        event.pid = Some(4242);
        event.resource = Resource::File(FileResource {
            path: "/home/u/.ssh/id_rsa".to_string(),
            resolved_path: None,
            op: FileOp::Read,
            source_path: None,
        });
        event
    }

    fn mirror_to(path: &std::path::Path) -> JournalMirror {
        JournalMirror::new(JournaldMirrorMode::Native, Some(path.to_path_buf())).expect("mirror")
    }

    #[test]
    fn encodes_plain_and_binary_safe_fields() {
        let payload = encode_journal_fields(&[
            ("MESSAGE", "hello".as_bytes()),
            ("MULTI", b"a\nb\0c".as_slice()),
            ("EMPTY", b"".as_slice()),
        ]);
        let mut expected = b"MESSAGE=hello\nMULTI\n".to_vec();
        expected.extend_from_slice(&5u64.to_le_bytes());
        expected.extend_from_slice(b"a\nb\0c\nEMPTY=\n");
        assert_eq!(payload, expected);
        let decoded = decode_fields(&payload);
        assert_eq!(decoded["MULTI"], b"a\nb\0c");
        assert_eq!(decoded["EMPTY"], b"");
    }

    #[test]
    fn priorities_follow_decision_reason_and_event() {
        let deny = deny_event();
        assert_eq!(priority(&deny), 4);
        let mut error = deny_event();
        error.reason = DecisionReason::ErrorPolicyUnavailable;
        assert_eq!(priority(&error), 3);
        let mut allow = deny_event();
        allow.decision = Decision::Allow;
        allow.reason = DecisionReason::AllowByRule;
        assert_eq!(priority(&allow), 6);
        let loss = AuditEvent::system("daemon", SystemResource::new("telemetry_loss"), "v1", "m");
        assert_eq!(priority(&loss), 4);
        let start = AuditEvent::system("daemon", SystemResource::new("daemon_start"), "v1", "m");
        assert_eq!(priority(&start), 5);
    }

    #[test]
    fn sends_native_fields_to_socket() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&path).expect("bind");
        let event = deny_event();
        let json = r#"{"line":"one\ntwo"}"#;
        let outcome = mirror_to(&path).send(&MirrorRecord {
            event: &event,
            json,
            event_id: "id-1",
            seq: Some(9),
        });
        assert_eq!(outcome, MirrorOutcome::Sent);

        let (payload, via_memfd) = recv_journal(&receiver);
        assert!(!via_memfd);
        let fields = decode_fields(&payload);
        let text = |key: &str| String::from_utf8(fields[key].clone()).unwrap();
        assert_eq!(
            text("MESSAGE"),
            "mercury deny FILE_READ /home/u/.ssh/id_rsa agent=agent-7"
        );
        assert_eq!(text("PRIORITY"), "4");
        assert_eq!(text("SYSLOG_IDENTIFIER"), "mercury");
        assert_eq!(text("MERCURY_EVENT_ID"), "id-1");
        assert_eq!(text("MERCURY_DECISION"), "deny");
        assert_eq!(text("MERCURY_REASON"), "DENY_BY_RULE");
        assert_eq!(text("MERCURY_ACTION"), "FILE_READ");
        assert_eq!(text("MERCURY_RULE_ID"), "deny-ssh");
        assert_eq!(text("MERCURY_AGENT_ID"), "agent-7");
        assert_eq!(text("MERCURY_PID"), "4242");
        assert_eq!(text("MERCURY_PROFILE"), "system");
        assert_eq!(text("MERCURY_SOURCE"), "kernel-ebpf");
        assert_eq!(text("MERCURY_AUDIT_SEQ"), "9");
        assert_eq!(text("MERCURY_JSON"), json);
        assert!(!fields.contains_key("MERCURY_TRUNCATED"));
    }

    #[test]
    fn large_payload_goes_through_sealed_memfd() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&path).expect("bind");
        let event = deny_event();
        let json = format!("{{\"blob\":\"{}\"}}", "x".repeat(300 * 1024));
        let outcome = mirror_to(&path).send(&MirrorRecord {
            event: &event,
            json: &json,
            event_id: "id-2",
            seq: None,
        });
        assert_eq!(outcome, MirrorOutcome::Sent);
        let (payload, via_memfd) = recv_journal(&receiver);
        assert!(via_memfd);
        assert_eq!(decode_fields(&payload)["MERCURY_JSON"], json.as_bytes());
    }

    #[test]
    fn datagram_emsgsize_falls_back_to_memfd() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&path).expect("bind");
        let mut mirror = mirror_to(&path);
        mirror.large_payload_bytes = usize::MAX;
        let small: libc::c_int = 4096;
        // SAFETY: setsockopt with a valid int option value.
        let rc = unsafe {
            libc::setsockopt(
                mirror.socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&small as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0);
        let event = deny_event();
        let json = format!("{{\"blob\":\"{}\"}}", "y".repeat(64 * 1024));
        let outcome = mirror.send(&MirrorRecord {
            event: &event,
            json: &json,
            event_id: "id-3",
            seq: None,
        });
        assert_eq!(outcome, MirrorOutcome::Sent);
        let (payload, via_memfd) = recv_journal(&receiver);
        assert!(via_memfd, "EMSGSIZE must fall back to the memfd path");
        assert_eq!(decode_fields(&payload)["MERCURY_JSON"], json.as_bytes());
    }

    #[test]
    fn strips_model_content_when_large_path_fails() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("journal.sock");
        let receiver = UnixDatagram::bind(&path).expect("bind");
        let mut mirror = mirror_to(&path);
        mirror.large_payload_bytes = 8 * 1024;
        mirror.use_memfd = false;
        let mut event = deny_event();
        event.model = Some(ModelCallAuditContext {
            call_id: "call-1".to_string(),
            provider: "anthropic".to_string(),
            model: Some("claude".to_string()),
            messages: vec![ModelMessage {
                role: "user".to_string(),
                text: "secret prompt ".repeat(2000),
            }],
            output_text: Some("answer".to_string()),
            ..ModelCallAuditContext::default()
        });
        let json = serde_json::to_string(&event).expect("json");
        let outcome = mirror.send(&MirrorRecord {
            event: &event,
            json: &json,
            event_id: "id-4",
            seq: None,
        });
        assert!(
            matches!(outcome, MirrorOutcome::Truncated(_)),
            "{outcome:?}"
        );
        let (payload, _) = recv_journal(&receiver);
        let fields = decode_fields(&payload);
        assert_eq!(fields["MERCURY_TRUNCATED"], b"1");
        let stripped: Value = serde_json::from_slice(&fields["MERCURY_JSON"]).expect("json");
        assert_eq!(stripped["model"]["call_id"], "call-1");
        assert!(stripped["model"].get("messages").is_none());
        assert!(stripped["model"].get("output_text").is_none());
    }

    #[test]
    fn missing_socket_is_reported_as_failure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let event = deny_event();
        let outcome = mirror_to(&tmp.path().join("absent.sock")).send(&MirrorRecord {
            event: &event,
            json: "{}",
            event_id: "id-5",
            seq: None,
        });
        assert!(matches!(outcome, MirrorOutcome::Failed(_)), "{outcome:?}");
    }

    #[test]
    fn syslog_mode_uses_mapped_priority() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("syslog.sock");
        let receiver = UnixDatagram::bind(&path).expect("bind");
        let mirror = JournalMirror::new(JournaldMirrorMode::Syslog, Some(path)).expect("mirror");
        let event = deny_event();
        let outcome = mirror.send(&MirrorRecord {
            event: &event,
            json: "{}",
            event_id: "id-6",
            seq: None,
        });
        assert_eq!(outcome, MirrorOutcome::Sent);
        let (payload, _) = recv_journal(&receiver);
        let line = String::from_utf8(payload).expect("utf8");
        assert!(line.starts_with("<132>mercury decision=deny"), "{line}");
        assert!(line.ends_with(" data={}"));
    }
}
