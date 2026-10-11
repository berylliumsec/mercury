//! Audit support shared by the URL gateway, model capture and MCP governance.
//!
//! * Redaction. Logged URLs have userinfo passwords and the values of
//!   credential-bearing query keys replaced; captured text (model prompts and
//!   outputs, MCP argument summaries and tool results) has credential-shaped
//!   strings replaced. Policy is always evaluated against the original
//!   request: only what reaches the audit log is redacted.
//! * Rate limiting for records a peer can trigger at will before it has
//!   authenticated (bad proxy tokens, refused TLS interception).
//! * Record builders for MCP events carrying agent lineage, the approver and
//!   correlation ids.

use std::borrow::Cow;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use core_types::{
    ActionType, AuditEvent, Decision, DecisionReason, EventContext, McpAuditContext,
    McpResourceReadResource, McpToolResource, NetworkResource, Resource, SystemResource,
};

use crate::{GuardDaemon, MCP_APPROVAL_TTL, PendingMcpApprovalRecord, RegisteredMcpServer};

pub(crate) const REDACTED: &str = "[REDACTED]";
const REDACTED_PRIVATE_KEY: &str = "[REDACTED PRIVATE KEY]";

/// `context.source` of records written by the URL gateway.
pub(crate) const SOURCE_URL_GATEWAY: &str = "url-gateway";
/// `context.source` of records written by MCP governance.
pub(crate) const SOURCE_MCP: &str = "mcp";

// ── URL redaction ───────────────────────────────────────────────────────────

/// Query (and fragment) keys whose values are credentials. Keys are compared
/// lower-cased with `-`, `_` and `.` removed, so `X-Amz-Signature`,
/// `access_token` and `apiKey` all match.
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "key",
    "apikey",
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "authtoken",
    "sessiontoken",
    "sig",
    "signature",
    "password",
    "passwd",
    "pwd",
    "secret",
    "clientsecret",
    "auth",
    "code",
    "xamzsignature",
    "xamzcredential",
    "xamzsecuritytoken",
    "xgoogsignature",
    "xgoogcredential",
];

/// A key ending in one of these is sensitive too (`github_token`,
/// `db_password`, `x-api-key`, ...).
const SENSITIVE_KEY_SUFFIXES: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "signature",
    "secretkey",
];

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|ch| !matches!(ch, '-' | '_' | '.'))
        .flat_map(char::to_lowercase)
        .collect()
}

fn percent_decode_lossy(value: &str) -> Cow<'_, str> {
    if !value.contains('%') {
        return Cow::Borrowed(value);
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = value.get(i + 1..i + 3)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

pub(crate) fn is_sensitive_query_key(key: &str) -> bool {
    let key = normalized_key(&percent_decode_lossy(key));
    SENSITIVE_QUERY_KEYS.contains(&key.as_str())
        || SENSITIVE_KEY_SUFFIXES
            .iter()
            .any(|suffix| key.ends_with(suffix))
}

/// Redact a raw query string (without the leading `?`).
pub(crate) fn redact_query(query: &str) -> String {
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, value)) if !value.is_empty() && is_sensitive_query_key(key) => {
                format!("{key}={REDACTED}")
            }
            Some((key, value)) => format!("{key}={}", redact_secrets(value)),
            None => redact_secrets(pair),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// A copy of `url` that is safe to write to the audit log: the userinfo
/// password, the values of sensitive query and fragment keys, and
/// credential-shaped path segments are replaced with `[REDACTED]`.
pub(crate) fn redact_url(url: &str) -> String {
    let (before_fragment, fragment) = match url.split_once('#') {
        Some((head, fragment)) => (head, Some(fragment)),
        None => (url, None),
    };
    let (base, query) = match before_fragment.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (before_fragment, None),
    };

    let mut out = redact_url_base(base);
    if let Some(query) = query {
        out.push('?');
        out.push_str(&redact_query(query));
    }
    // OAuth implicit flows return `#access_token=...`.
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(&redact_query(fragment));
    }
    out
}

fn redact_url_base(base: &str) -> String {
    let Some((scheme, rest)) = base.split_once("://") else {
        return redact_secrets(base);
    };
    let (authority, path) = match rest.find('/') {
        Some(idx) => rest.split_at(idx),
        None => (rest, ""),
    };
    let authority = match authority.rsplit_once('@') {
        Some((userinfo, host)) => match userinfo.split_once(':') {
            Some((user, _)) => format!("{}:{REDACTED}@{host}", redact_secrets(user)),
            // A bare username can itself be a token (`https://ghp_...@github.com`).
            None => format!("{}@{host}", redact_secrets(userinfo)),
        },
        None => authority.to_string(),
    };
    format!("{scheme}://{authority}{}", redact_secrets(path))
}

/// The network resource as it should be logged. Policy must be evaluated
/// against the original.
pub(crate) fn redact_network_resource(resource: &NetworkResource) -> NetworkResource {
    let mut logged = resource.clone();
    logged.full_url = resource.full_url.as_deref().map(redact_url);
    logged.query = resource.query.as_deref().map(redact_query);
    logged.path = resource.path.as_deref().map(redact_secrets);
    logged
}

// ── content redaction ───────────────────────────────────────────────────────

/// Credential prefixes and the minimum number of token characters that must
/// follow them.
const SECRET_PREFIXES: &[(&str, usize)] = &[
    // Anthropic (`sk-ant-`) and OpenAI (`sk-`, `sk-proj-`).
    ("sk-", 20),
    // Stripe live keys.
    ("sk_live_", 16),
    ("rk_live_", 16),
    // AWS access key ids.
    ("AKIA", 16),
    ("ASIA", 16),
    // Google API keys.
    ("AIza", 30),
    // GitHub.
    ("ghp_", 30),
    ("gho_", 30),
    ("ghs_", 30),
    ("ghu_", 30),
    ("ghr_", 30),
    ("github_pat_", 30),
    // Slack.
    ("xoxa-", 10),
    ("xoxb-", 10),
    ("xoxp-", 10),
    ("xoxr-", 10),
    ("xoxs-", 10),
    // GitLab.
    ("glpat-", 20),
];

/// Keys whose value is redacted when written as `key=value`, `key: value`
/// or `"key": "value"` (compared like query keys).
const ASSIGNMENT_KEYS: &[&str] = &[
    "secret",
    "clientsecret",
    "apikey",
    "token",
    "accesstoken",
    "refreshtoken",
    "authtoken",
    "idtoken",
    "sessiontoken",
    "secretkey",
    "secretaccesskey",
    "awssecretaccesskey",
    "awssessiontoken",
    "privatekey",
    "accountkey",
    "sharedaccesskey",
];

/// Keys whose value is redacted however short it is.
const PASSWORD_KEYS: &[&str] = &["password", "passwd", "pwd", "secret", "clientsecret"];

/// Header-like keys whose whole credential is redacted, keeping an
/// authentication scheme word (`Bearer`, `Basic`).
const AUTHORIZATION_KEYS: &[&str] = &["authorization", "proxyauthorization"];
/// Header-like keys whose value runs to the end of the line.
const LINE_KEYS: &[&str] = &["cookie", "setcookie"];

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
}

/// Replace credential-shaped strings in free text with `[REDACTED]`: PEM
/// private keys, `password=`/`secret:` style assignments, URL userinfo
/// passwords, bearer tokens, JWTs, AWS secret keys and well-known API key
/// formats (OpenAI, Anthropic, Google, GitHub, Slack, Stripe, GitLab, AWS).
pub(crate) fn redact_secrets(text: &str) -> String {
    let text = redact_pem_blocks(text);
    let mut out = String::with_capacity(text.len());
    let mut rest: &str = &text;
    let mut prev_is_token = false;

    while let Some(ch) = rest.chars().next() {
        if let Some((keep, skip)) = userinfo_password_at(rest) {
            out.push_str(&rest[..keep]);
            out.push_str(REDACTED);
            rest = &rest[skip..];
            prev_is_token = false;
            continue;
        }
        if !prev_is_token {
            if let Some((keep, len)) = assignment_at(rest) {
                out.push_str(&rest[..keep]);
                out.push_str(REDACTED);
                rest = &rest[keep + len..];
                prev_is_token = true;
                continue;
            }
            if let Some(len) = secret_len_at(rest)
                .or_else(|| jwt_len_at(rest))
                .or_else(|| aws_secret_len_at(rest))
            {
                out.push_str(REDACTED);
                rest = &rest[len..];
                prev_is_token = true;
                continue;
            }
            if let Some(len) = bearer_len_at(rest) {
                out.push_str("Bearer ");
                out.push_str(REDACTED);
                rest = &rest[len..];
                prev_is_token = true;
                continue;
            }
        }
        out.push(ch);
        prev_is_token = is_token_char(ch);
        rest = &rest[ch.len_utf8()..];
    }
    out
}

/// `-----BEGIN ... PRIVATE KEY-----` through the matching END line. A block
/// cut off by truncation is redacted to the end of the text.
fn redact_pem_blocks(text: &str) -> Cow<'_, str> {
    if !text.contains("PRIVATE KEY-----") {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(begin) = rest.find("-----BEGIN ") {
        let label_start = begin + "-----BEGIN ".len();
        let Some(label_len) = rest[label_start..].find("-----") else {
            break;
        };
        let label = &rest[label_start..label_start + label_len];
        let header_end = label_start + label_len + "-----".len();
        if !label.ends_with("PRIVATE KEY") || label.len() > 64 {
            out.push_str(&rest[..header_end]);
            rest = &rest[header_end..];
            continue;
        }
        out.push_str(&rest[..begin]);
        out.push_str(REDACTED_PRIVATE_KEY);
        let footer = format!("-----END {label}-----");
        match rest[header_end..].find(footer.as_str()) {
            Some(end) => rest = &rest[header_end + end + footer.len()..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// `scheme://user:password@host`: returns (bytes to keep, bytes to skip) so
/// that only the password is replaced.
fn userinfo_password_at(text: &str) -> Option<(usize, usize)> {
    let body = text.strip_prefix("://")?;
    let end = body
        .find(|ch: char| {
            ch.is_whitespace() || matches!(ch, '/' | '?' | '#' | '"' | '\'' | '<' | '>' | '`')
        })
        .unwrap_or(body.len());
    let authority = &body[..end];
    let at = authority.rfind('@')?;
    let colon = authority[..at].find(':')?;
    if colon + 1 == at {
        return None;
    }
    Some((3 + colon + 1, 3 + at))
}

fn secret_len_at(text: &str) -> Option<usize> {
    for (prefix, min_tail) in SECRET_PREFIXES {
        if let Some(tail) = text.strip_prefix(prefix) {
            let tail_len = token_run_len(tail);
            if tail_len >= *min_tail {
                return Some(prefix.len() + tail_len);
            }
        }
    }
    None
}

fn token_run_len(text: &str) -> usize {
    text.char_indices()
        .find(|(_, ch)| !is_token_char(*ch))
        .map(|(idx, _)| idx)
        .unwrap_or(text.len())
}

/// Three base64url segments whose first two decode to JSON objects.
fn jwt_len_at(text: &str) -> Option<usize> {
    if !text.starts_with("eyJ") {
        return None;
    }
    let run = text
        .find(|ch: char| !(is_token_char(ch) || ch == '.'))
        .unwrap_or(text.len());
    // A sentence may end right after the token.
    let token = text[..run].strip_suffix('.').unwrap_or(&text[..run]);
    let parts: Vec<&str> = token.split('.').collect();
    (parts.len() == 3
        && parts[0].len() >= 10
        && parts[1].starts_with("eyJ")
        && parts[1].len() >= 10)
        .then_some(token.len())
}

/// A standalone 40-character AWS secret access key: base64 alphabet with
/// upper case, lower case and digits (so git SHAs and words never match).
fn aws_secret_len_at(text: &str) -> Option<usize> {
    let run = text
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '/' || ch == '+'))
        .unwrap_or(text.len());
    if run != 40 {
        return None;
    }
    let candidate = &text[..run];
    if text[run..].starts_with(|ch: char| is_token_char(ch) || ch == '=') {
        return None;
    }
    let upper = candidate.chars().any(|ch| ch.is_ascii_uppercase());
    let lower = candidate.chars().any(|ch| ch.is_ascii_lowercase());
    let digit = candidate.chars().any(|ch| ch.is_ascii_digit());
    let slashes = candidate.matches('/').count();
    (upper
        && lower
        && digit
        && slashes < 3
        && !candidate.starts_with('/')
        && !candidate.ends_with('/'))
    .then_some(run)
}

fn bearer_len_at(text: &str) -> Option<usize> {
    let head = text.get(..7)?;
    if !head.eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let tail = &text[7..];
    let len = tail
        .char_indices()
        .find(|(_, ch)| !(is_token_char(*ch) || matches!(ch, '.' | '~' | '+' | '/' | '=')))
        .map(|(idx, _)| idx)
        .unwrap_or(tail.len());
    (len >= 16).then_some(7 + len)
}

fn is_password_key(key: &str) -> bool {
    PASSWORD_KEYS.contains(&key) || key.ends_with("password") || key.ends_with("passwd")
}

fn is_assignment_key(key: &str) -> bool {
    ASSIGNMENT_KEYS.contains(&key)
        || SENSITIVE_KEY_SUFFIXES
            .iter()
            .any(|suffix| key.ends_with(suffix))
}

/// `key=value`, `key: value`, `"key": "value"` for a sensitive key. Returns
/// (bytes up to the value, value length).
fn assignment_at(text: &str) -> Option<(usize, usize)> {
    let key_len = text
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
        .unwrap_or(text.len());
    if key_len == 0 || key_len > 64 {
        return None;
    }
    let key = normalized_key(&text[..key_len]);
    let password = is_password_key(&key);
    let authorization = AUTHORIZATION_KEYS.contains(&key.as_str());
    let line = LINE_KEYS.contains(&key.as_str());
    if !(password || authorization || line || is_assignment_key(&key)) {
        return None;
    }

    let bytes = text.as_bytes();
    let mut i = key_len;
    if matches!(bytes.get(i), Some(b'"' | b'\'')) {
        i += 1;
    }
    while matches!(bytes.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    if !matches!(bytes.get(i), Some(b'=' | b':')) {
        return None;
    }
    i += 1;
    while matches!(bytes.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    let quote = match bytes.get(i) {
        Some(quote @ (b'"' | b'\'')) => {
            i += 1;
            Some(*quote)
        }
        _ => None,
    };
    if authorization {
        // Keep the scheme so readers can tell Bearer from Basic.
        let word = text[i..]
            .find(|ch: char| !ch.is_ascii_alphabetic())
            .unwrap_or(0);
        if word > 0 && word <= 16 && text[i + word..].starts_with(' ') {
            i += word + 1;
        }
    }

    let rest = &text[i..];
    let len = match (quote, line) {
        (Some(quote), _) => rest
            .bytes()
            .position(|b| b == quote || b == b'\n')
            .unwrap_or(rest.len()),
        (None, true) => rest.find(['\r', '\n']).unwrap_or(rest.len()),
        (None, false) => rest
            .find(|ch: char| {
                ch.is_whitespace()
                    || matches!(
                        ch,
                        '"' | '\'' | ',' | ';' | '&' | '}' | ')' | ']' | '<' | '>'
                    )
            })
            .unwrap_or(rest.len()),
    };
    let value = &rest[..len];
    if value.is_empty() || value == REDACTED || value.starts_with(REDACTED_PRIVATE_KEY) {
        return None;
    }
    if quote.is_none() && matches!(value, "null" | "true" | "false") {
        return None;
    }
    // Short values under generic keys are counts and flags (`max_token: 5`).
    if !(password || authorization || line) && value.chars().count() < 8 {
        return None;
    }
    Some((i, len))
}

// ── truncation ──────────────────────────────────────────────────────────────

/// Keep at most `max_chars` characters (never splitting one), marking a cut
/// with `…`. Returns whether the text was cut.
pub(crate) fn truncate_chars(text: &str, max_chars: usize) -> (String, bool) {
    match text.char_indices().nth(max_chars) {
        Some((idx, _)) => (format!("{}…", &text[..idx]), true),
        None => (text.to_string(), false),
    }
}

/// Redact, then keep at most `max_chars` characters followed by `...` when
/// cut. Redacting first means a credential straddling the cut is still
/// recognised.
pub(crate) fn summarize_text(text: &str, max_chars: usize) -> String {
    let redacted = redact_secrets(text);
    match redacted.char_indices().nth(max_chars) {
        Some((idx, _)) => format!("{}...", &redacted[..idx]),
        None => redacted,
    }
}

// ── rate limiting ───────────────────────────────────────────────────────────

/// Records admitted per (source, event, peer) and window.
pub(crate) const AUTH_FAILURE_RECORDS_PER_WINDOW: u32 = 20;
pub(crate) const AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// Distinct peers tracked before new peers share one `other` bucket, so a
/// peer that varies its key cannot grow the table or the record rate.
const RATE_LIMIT_MAX_KEYS: usize = 64;
const RATE_LIMIT_OVERFLOW_KEY: &str = "other";

#[derive(Debug)]
struct RateWindow {
    started: Instant,
    admitted: u32,
    suppressed: u64,
}

/// A closed window in which records were dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SuppressedRecords {
    pub source: &'static str,
    pub event: &'static str,
    pub key: String,
    pub suppressed: u64,
}

type RateKey = (&'static str, &'static str, String);

/// Fixed-window limiter for records peers can trigger at will. After
/// `per_key` records in a window the rest are counted, and the count is
/// reported once the window closes.
#[derive(Debug)]
pub(crate) struct AuditRateLimiter {
    per_key: u32,
    window: Duration,
    windows: HashMap<RateKey, RateWindow>,
}

impl Default for AuditRateLimiter {
    fn default() -> Self {
        Self::new(AUTH_FAILURE_RECORDS_PER_WINDOW, AUTH_FAILURE_WINDOW)
    }
}

impl AuditRateLimiter {
    pub(crate) fn new(per_key: u32, window: Duration) -> Self {
        Self {
            per_key,
            window,
            windows: HashMap::new(),
        }
    }

    /// Whether a record for (`source`, `event`, `key`) may be written now,
    /// plus the suppressed counts of windows that have closed.
    pub(crate) fn admit(
        &mut self,
        source: &'static str,
        event: &'static str,
        key: &str,
        now: Instant,
    ) -> (bool, Vec<SuppressedRecords>) {
        let closed = self.flush(now);
        let mut rate_key = (source, event, key.to_string());
        if !self.windows.contains_key(&rate_key) && self.windows.len() >= RATE_LIMIT_MAX_KEYS {
            rate_key.2 = RATE_LIMIT_OVERFLOW_KEY.to_string();
        }
        let window = self.windows.entry(rate_key).or_insert(RateWindow {
            started: now,
            admitted: 0,
            suppressed: 0,
        });
        if window.admitted < self.per_key {
            window.admitted += 1;
            (true, closed)
        } else {
            window.suppressed += 1;
            (false, closed)
        }
    }

    /// Close windows older than the window length, returning those that
    /// dropped records.
    pub(crate) fn flush(&mut self, now: Instant) -> Vec<SuppressedRecords> {
        let length = self.window;
        let mut closed = Vec::new();
        self.windows.retain(|(source, event, key), window| {
            if now.saturating_duration_since(window.started) < length {
                return true;
            }
            if window.suppressed > 0 {
                closed.push(SuppressedRecords {
                    source,
                    event,
                    key: key.clone(),
                    suppressed: window.suppressed,
                });
            }
            false
        });
        closed
    }
}

// ── record builders ─────────────────────────────────────────────────────────

/// `<mcp_session_id>:<tool_call_id>`: joins the records of one MCP call that
/// did not need approval (approval chains use the approval request id).
pub(crate) fn mcp_call_correlation_id(mcp_session_id: &str, call_id: &str) -> String {
    format!("{mcp_session_id}:{call_id}")
}

impl GuardDaemon {
    /// Registration pid (the enrollment root) and parent agent of `agent_id`.
    pub(crate) fn agent_lineage(&self, agent_id: &str) -> (Option<u32>, Option<String>) {
        self.registrations
            .read()
            .values()
            .find(|registration| registration.agent_id.to_string() == agent_id)
            .map(|registration| {
                (
                    Some(registration.pid),
                    registration
                        .parent_agent_id
                        .map(|parent| parent.to_string()),
                )
            })
            .unwrap_or((None, None))
    }

    /// Context of a record about an MCP server agent.
    pub(crate) fn mcp_agent_context(&self, agent_id: &str) -> EventContext {
        let (root_pid, parent_agent_id) = self.agent_lineage(agent_id);
        EventContext {
            source: Some(SOURCE_MCP.to_string()),
            root_pid,
            parent_agent_id,
            ..EventContext::default()
        }
    }

    /// Write `event` unless its (source, event, key) window is exhausted;
    /// always write the summaries of windows that have closed.
    pub(crate) fn record_rate_limited(
        &self,
        limiter: &parking_lot::Mutex<AuditRateLimiter>,
        source: &'static str,
        event_name: &'static str,
        key: &str,
        event: AuditEvent,
    ) {
        let (admit, closed) = limiter
            .lock()
            .admit(source, event_name, key, Instant::now());
        self.record_suppressed(closed);
        if admit {
            self.record_audit_event(event);
        }
    }

    /// One `SYSTEM_EVENT` per closed window that dropped records.
    pub(crate) fn record_suppressed(&self, closed: Vec<SuppressedRecords>) {
        for summary in closed {
            let event = AuditEvent::system(
                summary.source,
                SystemResource::new(summary.event)
                    .detail("rate_limited")
                    .attr("key", summary.key.clone())
                    .attr("suppressed", summary.suppressed)
                    .attr("window_seconds", AUTH_FAILURE_WINDOW.as_secs()),
                self.policy_version(),
                format!(
                    "{} {} records suppressed for {} in the last {}s",
                    summary.suppressed,
                    summary.event,
                    summary.key,
                    AUTH_FAILURE_WINDOW.as_secs()
                ),
            );
            self.record_audit_event(event);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn mcp_tool_audit_event(
        &self,
        agent_id: &str,
        profile: &str,
        pid: Option<u32>,
        resource: McpToolResource,
        decision: Decision,
        reason: DecisionReason,
        rule_id: Option<String>,
        message: String,
    ) -> AuditEvent {
        AuditEvent {
            timestamp: Utc::now(),
            agent_id: agent_id.to_string(),
            pid,
            ppid: None,
            uid: None,
            action_type: ActionType::McpToolCall,
            decision,
            reason,
            rule_id,
            resource: Resource::McpTool(resource.clone()),
            profile: profile.to_string(),
            policy_version: self.policy_version(),
            message,
            mcp: Some(McpAuditContext {
                server_id: resource.server_id,
                transport: resource.transport,
                resource_uri: None,
                tool_name: resource.tool_name,
                tool_call_id: resource.tool_call_id,
                mcp_session_id: resource.mcp_session_id,
            }),
            kernel_seq: None,
            events_dropped: None,
            model: None,
            context: self.mcp_agent_context(agent_id),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn mcp_resource_audit_event(
        &self,
        agent_id: &str,
        profile: &str,
        pid: Option<u32>,
        resource: McpResourceReadResource,
        decision: Decision,
        reason: DecisionReason,
        rule_id: Option<String>,
        message: String,
    ) -> AuditEvent {
        AuditEvent {
            timestamp: Utc::now(),
            agent_id: agent_id.to_string(),
            pid,
            ppid: None,
            uid: None,
            action_type: ActionType::McpResourceRead,
            decision,
            reason,
            rule_id,
            resource: Resource::McpResource(resource),
            profile: profile.to_string(),
            policy_version: self.policy_version(),
            message,
            mcp: None,
            kernel_seq: None,
            events_dropped: None,
            model: None,
            context: self.mcp_agent_context(agent_id),
        }
    }

    /// Approval is required but there is no dashboard to ask: the call is
    /// rejected, and that rejection is audited.
    pub(crate) fn record_mcp_approvals_unavailable(
        &self,
        session: &RegisteredMcpServer,
        resource: Resource,
        rule_id: Option<String>,
    ) {
        let agent_id = session.agent_id.to_string();
        let event = match resource {
            Resource::McpTool(tool) => {
                let message = format!(
                    "mcp tool call rejected: approval required but approvals are unavailable server={} tool={}",
                    tool.server_id, tool.tool_name
                );
                let correlation = mcp_call_correlation_id(&tool.mcp_session_id, &tool.tool_call_id);
                let mut event = self.mcp_tool_audit_event(
                    &agent_id,
                    &session.profile,
                    Some(session.pid),
                    tool,
                    Decision::Deny,
                    DecisionReason::DenyFailClosed,
                    rule_id,
                    message,
                );
                event.context.correlation_id = Some(correlation);
                event
            }
            Resource::McpResource(read) => {
                let message = format!(
                    "mcp resource read rejected: approval required but approvals are unavailable server={} uri={}",
                    read.server_id, read.uri
                );
                let correlation = read
                    .resource_call_id
                    .as_deref()
                    .map(|id| mcp_call_correlation_id(&read.mcp_session_id, id));
                let mut event = self.mcp_resource_audit_event(
                    &agent_id,
                    &session.profile,
                    Some(session.pid),
                    read,
                    Decision::Deny,
                    DecisionReason::DenyFailClosed,
                    rule_id,
                    message,
                );
                event.context.correlation_id = correlation;
                event
            }
            _ => return,
        };
        self.record_audit_event(event);
    }

    /// `SYSTEM_EVENT mcp_approval_requested`: the call is held until someone
    /// approves or denies it. `correlation_id` is the approval request id,
    /// shared with the resolution record.
    pub(crate) fn record_mcp_approval_requested(
        &self,
        request_id: &str,
        record: &PendingMcpApprovalRecord,
        expires_at: DateTime<Utc>,
    ) {
        let (kind, subject) = match (&record.tool_name, &record.resource_uri) {
            (Some(tool), _) => ("tool", tool.clone()),
            (None, Some(uri)) => (crate::mcp_resource_call_kind(uri), uri.clone()),
            (None, None) => ("tool", String::new()),
        };
        let mut resource = SystemResource::new("mcp_approval_requested")
            .detail(subject.clone())
            .attr("kind", kind)
            .attr("request_id", request_id)
            .attr("server_id", record.server_id.clone())
            .attr("mcp_session_id", record.mcp_session_id.clone())
            .attr("call_id", record.tool_call_id.clone())
            .attr("expires_at", expires_at.to_rfc3339());
        if let Some(tool) = &record.tool_name {
            resource = resource.attr("tool_name", tool.clone());
        }
        if let Some(uri) = &record.resource_uri {
            resource = resource.attr("resource_uri", uri.clone());
        }
        if let Some(sha) = &record.arguments_sha256 {
            resource = resource.attr("arguments_sha256", sha.clone());
        }
        if let Some(summary) = &record.arguments_summary {
            resource = resource.attr("arguments_summary", summary.clone());
        }
        let mut event = AuditEvent::system(
            SOURCE_MCP,
            resource,
            self.policy_version(),
            format!(
                "mcp {kind} approval requested server={} {kind}={subject} request_id={request_id}",
                record.server_id
            ),
        );
        event.agent_id = record.agent_id.clone();
        event.profile = record.profile.clone();
        event.pid = Some(record.pid);
        event.rule_id = record.rule_id.clone();
        event.mcp = Some(McpAuditContext {
            server_id: record.server_id.clone(),
            transport: record.transport,
            resource_uri: record.resource_uri.clone(),
            tool_name: record.tool_name.clone().unwrap_or_default(),
            tool_call_id: record.tool_call_id.clone(),
            mcp_session_id: record.mcp_session_id.clone(),
        });
        let context = self.mcp_agent_context(&record.agent_id);
        event.context.root_pid = context.root_pid;
        event.context.parent_agent_id = context.parent_agent_id;
        event.context.correlation_id = Some(request_id.to_string());
        self.record_audit_event(event);
    }

    /// The final authorization record of an approval: who resolved it, when
    /// it was requested and how long it waited. `correlation_id` is the
    /// approval request id.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_mcp_approval_resolution(
        &self,
        request_id: &str,
        record: &PendingMcpApprovalRecord,
        registration_pid: Option<u32>,
        decision: Decision,
        reason: DecisionReason,
        actor: Option<&str>,
    ) {
        let now = Instant::now();
        let requested = record.deadline.checked_sub(MCP_APPROVAL_TTL).unwrap_or(now);
        let latency = now.saturating_duration_since(requested);
        let requested_at = Utc::now()
            - chrono::Duration::from_std(latency).unwrap_or_else(|_| chrono::Duration::zero());
        let resolution = format!(
            "request_id={request_id} approver={} requested_at={} latency_ms={}",
            actor.unwrap_or("none"),
            requested_at.to_rfc3339(),
            latency.as_millis()
        );

        let mut event = if let Some(tool_name) = record.tool_name.as_ref() {
            let message = format!(
                "mcp tool authorization decision={decision:?} reason={reason} server={} tool={tool_name} {resolution}",
                record.server_id
            );
            self.mcp_tool_audit_event(
                &record.agent_id,
                &record.profile,
                registration_pid,
                McpToolResource {
                    server_id: record.server_id.clone(),
                    transport: record.transport,
                    tool_name: tool_name.clone(),
                    tool_call_id: record.tool_call_id.clone(),
                    mcp_session_id: record.mcp_session_id.clone(),
                    arguments_sha256: record.arguments_sha256.clone().unwrap_or_default(),
                    arguments_summary: record.arguments_summary.clone(),
                },
                decision,
                reason,
                record.rule_id.clone(),
                message,
            )
        } else if let Some(resource_uri) = record.resource_uri.as_ref() {
            let message = format!(
                "mcp resource authorization decision={decision:?} reason={reason} server={} uri={resource_uri} {resolution}",
                record.server_id
            );
            self.mcp_resource_audit_event(
                &record.agent_id,
                &record.profile,
                registration_pid,
                McpResourceReadResource {
                    server_id: record.server_id.clone(),
                    transport: record.transport,
                    uri: resource_uri.clone(),
                    mcp_session_id: record.mcp_session_id.clone(),
                    request_id: record.client_request_id.clone(),
                    resource_call_id: Some(record.tool_call_id.clone()),
                },
                decision,
                reason,
                record.rule_id.clone(),
                message,
            )
        } else {
            return;
        };
        event.context.actor = actor.map(str::to_string);
        event.context.correlation_id = Some(request_id.to_string());
        self.record_audit_event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sensitive_query_values_only() {
        let url = "https://generativelanguage.googleapis.com/v1/models?key=AIzaSyA-abcdefghijklmnopqrstuvwxyz0123&alt=sse";
        let redacted = redact_url(url);
        assert_eq!(
            redacted,
            "https://generativelanguage.googleapis.com/v1/models?key=[REDACTED]&alt=sse"
        );

        let s3 = "https://bucket.s3.amazonaws.com/o?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE%2F20260929&X-Amz-Signature=deadbeef&X-Amz-Security-Token=abc";
        let redacted = redact_url(s3);
        assert!(redacted.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(redacted.contains("X-Amz-Credential=[REDACTED]"));
        assert!(redacted.contains("X-Amz-Signature=[REDACTED]"));
        assert!(redacted.contains("X-Amz-Security-Token=[REDACTED]"));

        let sas = "https://acct.blob.core.windows.net/c/b?sv=2024-01-01&sig=abc%2Bdef&se=2026";
        assert_eq!(
            redact_url(sas),
            "https://acct.blob.core.windows.net/c/b?sv=2024-01-01&sig=[REDACTED]&se=2026"
        );

        for key in [
            "api_key",
            "apiKey",
            "access_token",
            "client_secret",
            "password",
            "code",
            "github_token",
        ] {
            let url = format!("https://h/p?{key}=value123&page=2");
            assert_eq!(
                redact_url(&url),
                format!("https://h/p?{key}=[REDACTED]&page=2"),
                "{key}"
            );
        }
        // Keys that merely contain a sensitive word are left alone.
        assert_eq!(
            redact_url("https://h/p?keyboard=1&max_tokens=5"),
            "https://h/p?keyboard=1&max_tokens=5"
        );
    }

    #[test]
    fn redacts_userinfo_and_fragment_tokens() {
        assert_eq!(
            redact_url("https://user:hunter2@example.com/repo.git"),
            "https://user:[REDACTED]@example.com/repo.git"
        );
        assert_eq!(
            redact_url("https://app.example.com/cb#access_token=abc.def&state=1"),
            "https://app.example.com/cb#access_token=[REDACTED]&state=1"
        );
        assert_eq!(
            redact_url("https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/o/r"),
            "https://[REDACTED]@github.com/o/r"
        );
        let resource = NetworkResource {
            dest_host: Some("h".to_string()),
            dest_ip: None,
            dest_port: 443,
            protocol: core_types::NetworkProtocol::Tcp,
            full_url: Some("https://h/p?token=t0p-secret-value".to_string()),
            scheme: Some("https".to_string()),
            method: Some("GET".to_string()),
            path: Some("/p".to_string()),
            query: Some("token=t0p-secret-value".to_string()),
            socket_path: None,
            family: None,
        };
        let logged = redact_network_resource(&resource);
        assert_eq!(
            logged.full_url.as_deref(),
            Some("https://h/p?token=[REDACTED]")
        );
        assert_eq!(logged.query.as_deref(), Some("token=[REDACTED]"));
    }

    #[test]
    fn redacts_known_credential_formats() {
        let cases = [
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123",
            "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA",
            "sk_live_abcdefghijklmnop1234",
            "rk_live_abcdefghijklmnop1234",
            "AKIAABCDEFGHIJKLMNOP",
            "AIzaSyA-abcdefghijklmnopqrstuvwxyz0123",
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz",
            "xoxb-1234567890-abcdefghij",
            "glpat-abcdefghijklmnopqrst",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ];
        for secret in cases {
            let text = format!("value {secret}.");
            let redacted = redact_secrets(&text);
            assert_eq!(redacted, "value [REDACTED].", "{secret}");
        }
        // Short or embedded prefixes, git SHAs and prose are left alone.
        for text in [
            "task-sk-1 and sk-short",
            "commit 3f786850e387550fdab836ed7e6dc881de23001b",
            "Basic understanding of the password manager",
            "max_tokens: 5, token_count=12",
        ] {
            assert_eq!(redact_secrets(text), text);
        }
    }

    #[test]
    fn redacts_assignments_urls_and_private_keys() {
        let text = "export AWS_SECRET_ACCESS_KEY=abc/def+ghi123456 DB_PASSWORD=x \
                    {\"password\": \"hunter2\", \"api_key\": \"0123456789abcdef\", \"max_token\": 5}";
        let redacted = redact_secrets(text);
        assert!(
            redacted.contains("AWS_SECRET_ACCESS_KEY=[REDACTED]"),
            "{redacted}"
        );
        assert!(redacted.contains("DB_PASSWORD=[REDACTED]"), "{redacted}");
        assert!(
            redacted.contains("\"password\": \"[REDACTED]\""),
            "{redacted}"
        );
        assert!(
            redacted.contains("\"api_key\": \"[REDACTED]\""),
            "{redacted}"
        );
        assert!(redacted.contains("\"max_token\": 5"), "{redacted}");

        assert_eq!(
            redact_secrets("clone postgres://svc:s3cr3t@db.internal:5432/app now"),
            "clone postgres://svc:[REDACTED]@db.internal:5432/app now"
        );
        assert_eq!(
            redact_secrets("Authorization: Basic dXNlcjpwYXNz\nnext"),
            "Authorization: Basic [REDACTED]\nnext"
        );
        assert_eq!(
            redact_secrets("with Authorization: Bearer abc.def ok"),
            "with Authorization: Bearer [REDACTED] ok"
        );

        let pem = "key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\ndone";
        assert_eq!(redact_secrets(pem), "key:\n[REDACTED PRIVATE KEY]\ndone");
        let cut = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow";
        assert_eq!(redact_secrets(cut), "[REDACTED PRIVATE KEY]");
        let cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        assert_eq!(redact_secrets(cert), cert);
    }

    #[test]
    fn summary_truncation_is_char_boundary_safe() {
        // 'é' is two bytes, so byte 160 falls inside a character.
        let text = "é".repeat(200);
        let summary = summarize_text(&text, 160);
        assert!(summary.ends_with("..."));
        assert_eq!(summary.chars().count(), 163);
        assert_eq!(summarize_text("short", 160), "short");
        assert_eq!(
            summarize_text(
                "{\"token\":\"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"}",
                160
            ),
            "{\"token\":\"[REDACTED]\"}"
        );
        let (cut, truncated) = truncate_chars("日本語テキスト", 3);
        assert_eq!(cut, "日本語…");
        assert!(truncated);
    }

    #[test]
    fn rate_limiter_admits_per_key_then_summarizes() {
        let mut limiter = AuditRateLimiter::new(2, Duration::from_secs(60));
        let start = Instant::now();
        let src = SOURCE_URL_GATEWAY;
        assert!(limiter.admit(src, "gateway_auth_failure", "pid:1", start).0);
        assert!(limiter.admit(src, "gateway_auth_failure", "pid:1", start).0);
        assert!(!limiter.admit(src, "gateway_auth_failure", "pid:1", start).0);
        assert!(!limiter.admit(src, "gateway_auth_failure", "pid:1", start).0);
        // Other peers and other events have their own windows.
        assert!(limiter.admit(src, "gateway_auth_failure", "pid:2", start).0);
        assert!(limiter.admit(src, "tls_intercept_failed", "pid:1", start).0);

        let later = start + Duration::from_secs(61);
        let mut closed = limiter.flush(later);
        closed.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(
            closed,
            vec![SuppressedRecords {
                source: src,
                event: "gateway_auth_failure",
                key: "pid:1".to_string(),
                suppressed: 2,
            }]
        );
        assert!(limiter.admit(src, "gateway_auth_failure", "pid:1", later).0);
    }

    #[test]
    fn rate_limiter_folds_excess_keys_into_one_bucket() {
        let mut limiter = AuditRateLimiter::new(1, Duration::from_secs(60));
        let now = Instant::now();
        for i in 0..RATE_LIMIT_MAX_KEYS {
            assert!(limiter.admit(SOURCE_MCP, "e", &format!("k{i}"), now).0);
        }
        assert!(limiter.admit(SOURCE_MCP, "e", "fresh-1", now).0);
        assert!(!limiter.admit(SOURCE_MCP, "e", "fresh-2", now).0);
        assert_eq!(limiter.windows.len(), RATE_LIMIT_MAX_KEYS + 1);
    }

    mod daemon {
        use std::path::Path;

        use control_api::{
            AuthorizeMcpToolCallRequest, ControlRequest, ControlResponse, RegisterMcpServerRequest,
        };
        use kernel_runtime::{FilesystemBackend, KernelRuntimeConfig};
        use serde_json::Value;
        use tempfile::tempdir;
        use uuid::Uuid;

        use crate::dashboard::DashboardConfig;
        use crate::url_gateway::UrlGatewayConfig;
        use crate::{DaemonConfig, GuardDaemon};

        const STDIO_POLICY: &str = r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    mcp:
      default_tool_action: deny
      servers:
        - id: stdio_server
          transport: stdio
          exec_path_glob: "/**"
          tools:
            allow:
              - safe_tool
            require_approval:
              - write_file
"#;

        /// Daemon without a dashboard, so approvals are unavailable.
        fn stdio_daemon(root: &Path) -> (GuardDaemon, String, Uuid) {
            let config = DaemonConfig {
                socket_path: root.join("mercuryd.sock").to_string_lossy().to_string(),
                policy_path: root.join("policy.yaml").to_string_lossy().to_string(),
                audit_jsonl_path: root.join("audit.jsonl").to_string_lossy().to_string(),
                audit_integrity: false,
                enrollment_state_path: root.join("enrollments.json").to_string_lossy().to_string(),
                mirror_to_journald: false,
                cgroup_base: root.join("cgroup").to_string_lossy().to_string(),
                filesystem_backend: FilesystemBackend::EbpfLsm,
                kernel: KernelRuntimeConfig {
                    bpffs_path: root.join("bpffs").to_string_lossy().to_string(),
                    cgroup_root: root.join("cgroup-root").to_string_lossy().to_string(),
                    ..KernelRuntimeConfig::default()
                },
                dashboard: DashboardConfig {
                    enabled: false,
                    ..DashboardConfig::default()
                },
                url_gateway: UrlGatewayConfig {
                    enabled: false,
                    required: false,
                    ..UrlGatewayConfig::default()
                },
                ..DaemonConfig::default()
            };
            let daemon = GuardDaemon::new(config).expect("daemon");
            let reload = daemon.apply_policy_from_yaml(STDIO_POLICY);
            assert!(reload.success, "{:?}", reload.errors);
            let parent = Uuid::new_v4();
            let response = daemon.handle_request(
                ControlRequest::RegisterMcpServer(RegisterMcpServerRequest {
                    pid: std::process::id(),
                    ppid: 1,
                    uid: 0,
                    gid: 0,
                    profile: "default".to_string(),
                    cmdline: vec!["stdio-server".to_string()],
                    cwd: "/tmp".to_string(),
                    server_id: "stdio_server".to_string(),
                    client_name: None,
                    parent_agent_id: Some(parent),
                }),
                0,
            );
            let ControlResponse::RegisterMcpServer(registered) = response else {
                panic!("register failed: {response:?}");
            };
            (daemon, registered.mcp_session_id, parent)
        }

        fn authorize(
            daemon: &GuardDaemon,
            session: &str,
            tool: &str,
            call_id: &str,
            arguments: &str,
        ) -> ControlResponse {
            daemon.handle_request(
                ControlRequest::AuthorizeMcpToolCall(AuthorizeMcpToolCallRequest {
                    mcp_session_id: session.to_string(),
                    tool_name: tool.to_string(),
                    tool_call_id: call_id.to_string(),
                    arguments_json: arguments.to_string(),
                    arguments_summary: None,
                }),
                0,
            )
        }

        fn tool_records(root: &Path) -> Vec<Value> {
            std::fs::read_to_string(root.join("audit.jsonl"))
                .unwrap_or_default()
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .filter(|event| event["action_type"] == "MCP_TOOL_CALL")
                .collect()
        }

        #[test]
        fn approvals_unavailable_rejection_is_audited() {
            let tmp = tempdir().expect("tempdir");
            let (daemon, session, parent) = stdio_daemon(tmp.path());
            let response = authorize(&daemon, &session, "write_file", "tc-1", "{}");
            let ControlResponse::Error(error) = response else {
                panic!("expected an error, got {response:?}");
            };
            assert_eq!(error.code, "APPROVALS_UNAVAILABLE");

            let records = tool_records(tmp.path());
            assert_eq!(records.len(), 1);
            let record = &records[0];
            assert_eq!(record["decision"], "DENY");
            assert_eq!(record["reason"], "DENY_FAIL_CLOSED");
            assert_eq!(record["source"], "mcp");
            assert_eq!(record["parent_agent_id"], parent.to_string());
            assert_eq!(record["root_pid"], std::process::id());
            assert_eq!(record["correlation_id"], format!("{session}:tc-1"));
            assert!(
                record["message"]
                    .as_str()
                    .unwrap()
                    .contains("approvals are unavailable")
            );
        }

        #[test]
        fn repeated_tool_call_id_is_still_audited() {
            let tmp = tempdir().expect("tempdir");
            let (daemon, session, _) = stdio_daemon(tmp.path());
            for _ in 0..2 {
                let response = authorize(&daemon, &session, "safe_tool", "tc-dup", "{}");
                assert!(
                    matches!(response, ControlResponse::AuthorizeMcpToolCall(_)),
                    "{response:?}"
                );
            }
            let records = tool_records(tmp.path());
            assert_eq!(records.len(), 2);
            assert!(
                records[1]["message"]
                    .as_str()
                    .unwrap()
                    .contains("repeated for active tool_call_id=tc-dup")
            );
            assert_eq!(records[0]["source"], "mcp");
        }

        #[test]
        fn argument_summaries_are_redacted_and_cut_on_char_boundaries() {
            let tmp = tempdir().expect("tempdir");
            let (daemon, session, _) = stdio_daemon(tmp.path());
            // Multibyte characters around byte 160 used to panic the daemon.
            let arguments = serde_json::json!({
                "token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
                "text": "é".repeat(300),
            })
            .to_string();
            let response = authorize(&daemon, &session, "safe_tool", "tc-utf8", &arguments);
            assert!(matches!(response, ControlResponse::AuthorizeMcpToolCall(_)));
            let records = tool_records(tmp.path());
            let summary = records[0]["resource"]["arguments_summary"]
                .as_str()
                .unwrap();
            assert!(summary.ends_with("..."), "{summary}");
            assert!(!summary.contains("ghp_"), "{summary}");
            assert_eq!(
                crate::summarize_arguments("é".repeat(200).as_str(), None)
                    .unwrap()
                    .chars()
                    .count(),
                163
            );
        }
    }
}
