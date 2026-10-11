//! Optional webhook alerting for security-relevant audit records.
//!
//! The daemon calls [`AlertSink::offer`] from its central audit record path
//! for every record. `offer` never blocks: it classifies the record, applies
//! the per-minute rate limit, serializes a compact JSON payload and hands it
//! to a bounded queue. A background task drains the queue and POSTs each
//! payload to the configured webhook. When the queue is full the payload is
//! dropped and counted instead of stalling the audit path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use core_types::{ActionType, AuditEvent, Decision, Resource};
use parking_lot::Mutex;
use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::mpsc;
use tracing::{debug, warn};

const ALERT_QUEUE_CAPACITY: usize = 256;
const ALERT_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const ALERT_RATE_WINDOW: Duration = Duration::from_secs(60);
const ALERT_MESSAGE_MAX_CHARS: usize = 1024;

/// System events that indicate lost or tampered telemetry; always alerted.
const CRITICAL_SYSTEM_EVENTS: &[&str] = &[
    "telemetry_loss",
    "audit_file_expired",
    "apparmor_cursor_reset",
];

/// System events describing a change to what is enforced; alerted at the
/// default `deny` level.
const POLICY_SYSTEM_EVENTS: &[&str] = &["policy_reload", "policy_sync"];

/// Dashboard operator actions that change the active policy.
const POLICY_DASHBOARD_ACTIONS: &[&str] = &[
    "policy_apply",
    "policy_apply_failed",
    "policy_rollback",
    "policy_rollback_failed",
    "quick_rule",
];

fn default_rate_limit_per_minute() -> u32 {
    60
}

fn default_true() -> bool {
    true
}

/// Lowest class of record that is forwarded. Each level includes the ones
/// before it: `deny` < `system` < `all`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AlertMinSeverity {
    /// Denies (including auth failures), telemetry loss, policy changes and
    /// tamper-relevant kernel operations.
    #[default]
    Deny,
    /// Additionally every other `SYSTEM_EVENT` and allowed tamper-relevant
    /// operations (observe mode).
    System,
    /// Every audit record, subject to the rate limit.
    All,
}

/// `alerts:` section of the daemon config.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AlertsConfig {
    /// HTTP(S) endpoint that receives one JSON POST per alert. Alerting is
    /// disabled when unset or empty.
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub min_severity: AlertMinSeverity,
    /// Maximum alerts sent per minute; 0 disables the limit.
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
    /// Include the full `resource` object in the payload.
    #[serde(default = "default_true")]
    pub include_resource: bool,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            webhook_url: None,
            min_severity: AlertMinSeverity::default(),
            rate_limit_per_minute: default_rate_limit_per_minute(),
            include_resource: true,
        }
    }
}

/// Process-wide sink installed at daemon start; every audit write path
/// offers its records here so alerting sees kernel, gateway, MCP and
/// dashboard records alike.
static GLOBAL_SINK: std::sync::OnceLock<AlertSink> = std::sync::OnceLock::new();

/// Installs the process-wide sink. Returns false if one was already set.
pub fn install_global(sink: AlertSink) -> bool {
    GLOBAL_SINK.set(sink).is_ok()
}

/// Offers `event` to the process-wide sink, if alerting is configured.
pub fn offer_global(event: &AuditEvent) {
    if let Some(sink) = GLOBAL_SINK.get() {
        sink.offer(event);
    }
}

/// Counters of the process-wide sink, if alerting is configured.
pub fn global_stats() -> Option<AlertStats> {
    GLOBAL_SINK.get().map(AlertSink::stats)
}

/// Severity label carried in the payload.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// What `offer` did with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertDisposition {
    /// Below `min_severity`.
    Ignored,
    RateLimited,
    Queued,
    /// The send queue was full; the alert was dropped.
    QueueFull,
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct AlertStats {
    pub matched_total: u64,
    pub queued_total: u64,
    pub sent_total: u64,
    pub send_failures_total: u64,
    pub rate_limited_total: u64,
    pub dropped_queue_full_total: u64,
}

#[derive(Debug, Default)]
struct AlertCounters {
    matched_total: AtomicU64,
    queued_total: AtomicU64,
    sent_total: AtomicU64,
    send_failures_total: AtomicU64,
    rate_limited_total: AtomicU64,
    dropped_queue_full_total: AtomicU64,
}

#[derive(Debug)]
struct RateWindow {
    started: Instant,
    sent: u32,
    /// Alerts rate limited since the last one that went out; reported in the
    /// next payload so the receiver knows it missed some.
    suppressed: u64,
}

#[derive(Debug)]
struct AlertSinkInner {
    config: AlertsConfig,
    tx: mpsc::Sender<Vec<u8>>,
    window_len: Duration,
    window: Mutex<RateWindow>,
    counters: Arc<AlertCounters>,
}

/// Cheap to clone; all clones share one queue, rate limit and counters.
#[derive(Debug, Clone)]
pub struct AlertSink {
    inner: Arc<AlertSinkInner>,
}

impl AlertSink {
    /// Returns `None` when no webhook is configured or it cannot be used.
    /// Spawns the sender on the current tokio runtime, or on a dedicated
    /// thread when called outside one.
    pub fn new(config: &AlertsConfig) -> Option<AlertSink> {
        let url = validated_webhook_url(config)?;
        let client = match ReqwestClient::builder().timeout(ALERT_HTTP_TIMEOUT).build() {
            Ok(client) => client,
            Err(err) => {
                warn!(error = %err, "alert webhook disabled: cannot build HTTP client");
                return None;
            }
        };
        let (sink, rx) = Self::build(config, ALERT_QUEUE_CAPACITY, ALERT_RATE_WINDOW);
        let sender = run_sender(url, client, rx, Arc::clone(&sink.inner.counters));
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(sender);
            }
            Err(_) => {
                let spawned = std::thread::Builder::new()
                    .name("mercury-alerts".to_string())
                    .spawn(move || {
                        match tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        {
                            Ok(runtime) => runtime.block_on(sender),
                            Err(err) => warn!(error = %err, "alert sender runtime failed"),
                        }
                    });
                if let Err(err) = spawned {
                    warn!(error = %err, "alert webhook disabled: cannot start sender thread");
                    return None;
                }
            }
        }
        Some(sink)
    }

    fn build(
        config: &AlertsConfig,
        capacity: usize,
        window_len: Duration,
    ) -> (AlertSink, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let sink = AlertSink {
            inner: Arc::new(AlertSinkInner {
                config: config.clone(),
                tx,
                window_len,
                window: Mutex::new(RateWindow {
                    started: Instant::now(),
                    sent: 0,
                    suppressed: 0,
                }),
                counters: Arc::new(AlertCounters::default()),
            }),
        };
        (sink, rx)
    }

    /// Queues an alert for `event` when it matches `min_severity`. Never
    /// blocks and never fails the caller.
    pub fn offer(&self, event: &AuditEvent) -> AlertDisposition {
        let inner = self.inner.as_ref();
        let Some(severity) = alert_severity(event, inner.config.min_severity) else {
            return AlertDisposition::Ignored;
        };
        inner.counters.matched_total.fetch_add(1, Ordering::Relaxed);

        let suppressed = {
            let mut window = inner.window.lock();
            if window.started.elapsed() >= inner.window_len {
                window.started = Instant::now();
                window.sent = 0;
            }
            let limit = inner.config.rate_limit_per_minute;
            if limit > 0 && window.sent >= limit {
                window.suppressed += 1;
                inner
                    .counters
                    .rate_limited_total
                    .fetch_add(1, Ordering::Relaxed);
                return AlertDisposition::RateLimited;
            }
            window.sent += 1;
            std::mem::take(&mut window.suppressed)
        };

        let payload = alert_payload(event, severity, inner.config.include_resource, suppressed);
        let body = match serde_json::to_vec(&payload) {
            Ok(body) => body,
            Err(err) => {
                debug!(error = %err, "failed to serialize alert payload");
                return AlertDisposition::Ignored;
            }
        };
        match inner.tx.try_send(body) {
            Ok(()) => {
                inner.counters.queued_total.fetch_add(1, Ordering::Relaxed);
                AlertDisposition::Queued
            }
            Err(_) => {
                inner
                    .counters
                    .dropped_queue_full_total
                    .fetch_add(1, Ordering::Relaxed);
                AlertDisposition::QueueFull
            }
        }
    }

    pub fn stats(&self) -> AlertStats {
        let counters = &self.inner.counters;
        AlertStats {
            matched_total: counters.matched_total.load(Ordering::Relaxed),
            queued_total: counters.queued_total.load(Ordering::Relaxed),
            sent_total: counters.sent_total.load(Ordering::Relaxed),
            send_failures_total: counters.send_failures_total.load(Ordering::Relaxed),
            rate_limited_total: counters.rate_limited_total.load(Ordering::Relaxed),
            dropped_queue_full_total: counters.dropped_queue_full_total.load(Ordering::Relaxed),
        }
    }
}

fn validated_webhook_url(config: &AlertsConfig) -> Option<String> {
    let url = config.webhook_url.as_deref().map(str::trim)?;
    if url.is_empty() {
        return None;
    }
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        warn!(
            webhook_url = %url,
            "alert webhook disabled: webhook_url must be an http(s) URL"
        );
        return None;
    }
    Some(url.to_string())
}

async fn run_sender(
    url: String,
    client: ReqwestClient,
    mut rx: mpsc::Receiver<Vec<u8>>,
    counters: Arc<AlertCounters>,
) {
    while let Some(body) = rx.recv().await {
        let result = client
            .post(url.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await;
        match result {
            Ok(response) if response.status().is_success() => {
                counters.sent_total.fetch_add(1, Ordering::Relaxed);
            }
            Ok(response) => {
                let failures = counters.send_failures_total.fetch_add(1, Ordering::Relaxed);
                if failures.is_power_of_two() || failures == 0 {
                    warn!(status = %response.status(), failures = failures + 1, "alert webhook rejected alert");
                }
            }
            Err(err) => {
                let failures = counters.send_failures_total.fetch_add(1, Ordering::Relaxed);
                if failures.is_power_of_two() || failures == 0 {
                    warn!(error = %err, failures = failures + 1, "alert webhook request failed");
                }
            }
        }
    }
}

fn is_tamper_relevant(action_type: ActionType) -> bool {
    matches!(
        action_type,
        ActionType::ProcBpf | ActionType::ProcModuleLoad | ActionType::ProcMount
    )
}

fn system_event_name(event: &AuditEvent) -> Option<&str> {
    match &event.resource {
        Resource::System(system) => Some(system.event.as_str()),
        _ => None,
    }
}

fn is_policy_change(event: &AuditEvent) -> bool {
    let Resource::System(system) = &event.resource else {
        return false;
    };
    if POLICY_SYSTEM_EVENTS.contains(&system.event.as_str()) {
        return true;
    }
    system.event == "dashboard_action"
        && system
            .attributes
            .get("action")
            .and_then(Value::as_str)
            .is_some_and(|action| POLICY_DASHBOARD_ACTIONS.contains(&action))
}

/// Classifies `event`; `None` when it is below `min_severity`.
fn alert_severity(event: &AuditEvent, min_severity: AlertMinSeverity) -> Option<AlertSeverity> {
    let system_event = system_event_name(event);
    let tamper = is_tamper_relevant(event.action_type);
    let critical = (tamper && event.decision == Decision::Deny)
        || system_event.is_some_and(|name| CRITICAL_SYSTEM_EVENTS.contains(&name));
    let (level, severity) = if critical {
        (AlertMinSeverity::Deny, AlertSeverity::Critical)
    } else if event.decision == Decision::Deny || is_policy_change(event) {
        (AlertMinSeverity::Deny, AlertSeverity::High)
    } else if tamper {
        (AlertMinSeverity::System, AlertSeverity::High)
    } else if system_event.is_some() {
        (AlertMinSeverity::System, AlertSeverity::Medium)
    } else {
        (AlertMinSeverity::All, AlertSeverity::Low)
    };
    (level <= min_severity).then_some(severity)
}

fn truncate_chars(value: &str, max: usize) -> String {
    match value.char_indices().nth(max) {
        Some((index, _)) => format!("{}...", &value[..index]),
        None => value.to_string(),
    }
}

fn alert_payload(
    event: &AuditEvent,
    severity: AlertSeverity,
    include_resource: bool,
    suppressed_since_last: u64,
) -> Value {
    let mut payload = Map::new();
    let mut put = |key: &str, value: Value| {
        if !value.is_null() {
            payload.insert(key.to_string(), value);
        }
    };
    put("source", Value::from("mercury"));
    put(
        "severity",
        serde_json::to_value(severity).unwrap_or(Value::Null),
    );
    put("timestamp", Value::from(event.timestamp.to_rfc3339()));
    put(
        "event_id",
        event
            .context
            .event_id
            .clone()
            .map_or(Value::Null, Value::from),
    );
    put(
        "host",
        event.context.host.clone().map_or(Value::Null, Value::from),
    );
    put(
        "action_type",
        serde_json::to_value(event.action_type).unwrap_or(Value::Null),
    );
    put(
        "decision",
        serde_json::to_value(event.decision).unwrap_or(Value::Null),
    );
    put("reason", Value::from(event.reason.to_string()));
    put(
        "rule_id",
        event.rule_id.clone().map_or(Value::Null, Value::from),
    );
    put("agent_id", Value::from(event.agent_id.clone()));
    put("profile", Value::from(event.profile.clone()));
    put("pid", event.pid.map_or(Value::Null, Value::from));
    put(
        "actor",
        event.context.actor.clone().map_or(Value::Null, Value::from),
    );
    put(
        "system_event",
        system_event_name(event).map_or(Value::Null, Value::from),
    );
    put(
        "message",
        Value::from(truncate_chars(
            event.message.as_str(),
            ALERT_MESSAGE_MAX_CHARS,
        )),
    );
    put("policy_version", Value::from(event.policy_version.clone()));
    if include_resource {
        put(
            "resource",
            serde_json::to_value(&event.resource).unwrap_or(Value::Null),
        );
    }
    if suppressed_since_last > 0 {
        put("suppressed_since_last", Value::from(suppressed_since_last));
    }
    Value::Object(payload)
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::extract::State;
    use axum::routing::post;
    use chrono::Utc;
    use core_types::{
        DecisionReason, EventContext, ExecResource, FileOp, FileResource, SystemResource,
    };
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::*;

    fn file_event(decision: Decision) -> AuditEvent {
        AuditEvent {
            timestamp: Utc::now(),
            agent_id: "agent-1".to_string(),
            pid: Some(42),
            ppid: Some(1),
            uid: Some(1000),
            action_type: ActionType::FileRead,
            decision,
            reason: match decision {
                Decision::Deny => DecisionReason::DenyByRule,
                Decision::Allow => DecisionReason::AllowByRule,
            },
            rule_id: Some("rule-1".to_string()),
            resource: Resource::File(FileResource {
                path: "/etc/shadow".to_string(),
                resolved_path: None,
                op: FileOp::Read,
                source_path: None,
            }),
            profile: "default".to_string(),
            policy_version: "v1".to_string(),
            message: "file read".to_string(),
            mcp: None,
            kernel_seq: None,
            events_dropped: None,
            model: None,
            context: EventContext::default(),
        }
    }

    fn tamper_event(action_type: ActionType, decision: Decision) -> AuditEvent {
        let mut event = file_event(decision);
        event.action_type = action_type;
        event.resource = Resource::Exec(ExecResource {
            path: "/usr/sbin/insmod".to_string(),
            argv_hash: None,
            cwd: "/".to_string(),
            argv: Vec::new(),
            argv_truncated: false,
        });
        event
    }

    fn system_event(name: &str) -> AuditEvent {
        AuditEvent::system("daemon", SystemResource::new(name), "v1", name)
    }

    fn config(min_severity: AlertMinSeverity, rate_limit_per_minute: u32) -> AlertsConfig {
        AlertsConfig {
            webhook_url: Some("http://127.0.0.1:9/unused".to_string()),
            min_severity,
            rate_limit_per_minute,
            include_resource: true,
        }
    }

    #[test]
    fn config_defaults_match_documentation() {
        let config: AlertsConfig =
            serde_yaml::from_str("webhook_url: https://hooks.example/x\n").expect("parse");
        assert_eq!(config.min_severity, AlertMinSeverity::Deny);
        assert_eq!(config.rate_limit_per_minute, 60);
        assert!(config.include_resource);
        let config: AlertsConfig = serde_yaml::from_str("min_severity: system\n").expect("parse");
        assert_eq!(config.min_severity, AlertMinSeverity::System);
    }

    #[test]
    fn sink_is_disabled_without_a_usable_webhook() {
        assert!(AlertSink::new(&AlertsConfig::default()).is_none());
        for url in ["  ", "ftp://example.com/hook"] {
            let config = AlertsConfig {
                webhook_url: Some(url.to_string()),
                ..AlertsConfig::default()
            };
            assert!(AlertSink::new(&config).is_none(), "{url}");
        }
    }

    #[test]
    fn deny_level_matches_denies_telemetry_loss_policy_and_tamper() {
        let min = AlertMinSeverity::Deny;
        assert_eq!(
            alert_severity(&file_event(Decision::Deny), min),
            Some(AlertSeverity::High)
        );
        assert_eq!(alert_severity(&file_event(Decision::Allow), min), None);
        assert_eq!(
            alert_severity(&system_event("telemetry_loss"), min),
            Some(AlertSeverity::Critical)
        );
        assert_eq!(
            alert_severity(&system_event("policy_reload"), min),
            Some(AlertSeverity::High)
        );
        assert_eq!(alert_severity(&system_event("agent_enrolled"), min), None);
        for action in [
            ActionType::ProcBpf,
            ActionType::ProcModuleLoad,
            ActionType::ProcMount,
        ] {
            assert_eq!(
                alert_severity(&tamper_event(action, Decision::Deny), min),
                Some(AlertSeverity::Critical)
            );
            assert_eq!(
                alert_severity(&tamper_event(action, Decision::Allow), min),
                None
            );
        }

        let mut auth_failure = system_event("auth_failure");
        auth_failure.decision = Decision::Deny;
        auth_failure.reason = DecisionReason::DenyByDefault;
        assert_eq!(
            alert_severity(&auth_failure, min),
            Some(AlertSeverity::High)
        );

        let dashboard_apply = AuditEvent::system(
            "dashboard",
            SystemResource::new("dashboard_action").attr("action", "policy_apply"),
            "v1",
            "apply",
        );
        assert_eq!(
            alert_severity(&dashboard_apply, min),
            Some(AlertSeverity::High)
        );
        let dashboard_login = AuditEvent::system(
            "dashboard",
            SystemResource::new("dashboard_action").attr("action", "login_success"),
            "v1",
            "login",
        );
        assert_eq!(alert_severity(&dashboard_login, min), None);
    }

    #[test]
    fn wider_levels_include_system_events_and_everything() {
        assert_eq!(
            alert_severity(&system_event("agent_enrolled"), AlertMinSeverity::System),
            Some(AlertSeverity::Medium)
        );
        assert_eq!(
            alert_severity(
                &tamper_event(ActionType::ProcMount, Decision::Allow),
                AlertMinSeverity::System
            ),
            Some(AlertSeverity::High)
        );
        assert_eq!(
            alert_severity(&file_event(Decision::Allow), AlertMinSeverity::System),
            None
        );
        assert_eq!(
            alert_severity(&file_event(Decision::Allow), AlertMinSeverity::All),
            Some(AlertSeverity::Low)
        );
    }

    #[test]
    fn payload_is_compact_and_honours_include_resource() {
        let mut event = file_event(Decision::Deny);
        event.context.event_id = Some("evt-1".to_string());
        event.message = "x".repeat(ALERT_MESSAGE_MAX_CHARS + 10);
        let payload = alert_payload(&event, AlertSeverity::High, true, 0);
        assert_eq!(payload["source"], "mercury");
        assert_eq!(payload["severity"], "high");
        assert_eq!(payload["action_type"], "FILE_READ");
        assert_eq!(payload["decision"], "DENY");
        assert_eq!(payload["reason"], "DENY_BY_RULE");
        assert_eq!(payload["event_id"], "evt-1");
        assert_eq!(payload["resource"]["path"], "/etc/shadow");
        assert!(payload.get("suppressed_since_last").is_none());
        assert!(payload.get("host").is_none());
        assert_eq!(
            payload["message"]
                .as_str()
                .expect("message")
                .chars()
                .count(),
            ALERT_MESSAGE_MAX_CHARS + 3
        );

        let payload = alert_payload(&event, AlertSeverity::High, false, 4);
        assert!(payload.get("resource").is_none());
        assert_eq!(payload["suppressed_since_last"], 4);
    }

    #[test]
    fn full_queue_drops_and_counts_without_blocking() {
        let (sink, _rx) = AlertSink::build(
            &config(AlertMinSeverity::Deny, 0),
            1,
            Duration::from_secs(60),
        );
        let event = file_event(Decision::Deny);
        assert_eq!(sink.offer(&event), AlertDisposition::Queued);
        assert_eq!(sink.offer(&event), AlertDisposition::QueueFull);
        assert_eq!(
            sink.offer(&file_event(Decision::Allow)),
            AlertDisposition::Ignored
        );
        let stats = sink.stats();
        assert_eq!(stats.matched_total, 2);
        assert_eq!(stats.queued_total, 1);
        assert_eq!(stats.dropped_queue_full_total, 1);
    }

    #[test]
    fn rate_limit_resets_each_window_and_reports_suppressed_count() {
        let (sink, mut rx) = AlertSink::build(
            &config(AlertMinSeverity::Deny, 2),
            16,
            Duration::from_millis(50),
        );
        let event = file_event(Decision::Deny);
        assert_eq!(sink.offer(&event), AlertDisposition::Queued);
        assert_eq!(sink.offer(&event), AlertDisposition::Queued);
        assert_eq!(sink.offer(&event), AlertDisposition::RateLimited);
        assert_eq!(sink.offer(&event), AlertDisposition::RateLimited);
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(sink.offer(&event), AlertDisposition::Queued);
        assert_eq!(sink.stats().rate_limited_total, 2);

        let bodies: Vec<Value> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|body| serde_json::from_slice(&body).expect("json"))
            .collect();
        assert_eq!(bodies.len(), 3);
        assert!(bodies[0].get("suppressed_since_last").is_none());
        assert_eq!(bodies[2]["suppressed_since_last"], 2);
    }

    async fn capture(
        State(tx): State<mpsc::UnboundedSender<Value>>,
        body: axum::body::Bytes,
    ) -> &'static str {
        let _ = tx.send(serde_json::from_slice(&body).unwrap_or(Value::Null));
        "ok"
    }

    #[tokio::test]
    async fn posts_matching_alerts_to_webhook_within_rate_limit() {
        let (tx, mut received) = mpsc::unbounded_channel();
        let app = Router::new().route("/hook", post(capture)).with_state(tx);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut config = config(AlertMinSeverity::Deny, 2);
        config.webhook_url = Some(format!("http://{addr}/hook"));
        let sink = AlertSink::new(&config).expect("sink");

        assert_eq!(
            sink.offer(&file_event(Decision::Allow)),
            AlertDisposition::Ignored
        );
        assert_eq!(
            sink.offer(&tamper_event(ActionType::ProcModuleLoad, Decision::Deny)),
            AlertDisposition::Queued
        );
        assert_eq!(
            sink.offer(&system_event("telemetry_loss")),
            AlertDisposition::Queued
        );
        assert_eq!(
            sink.offer(&file_event(Decision::Deny)),
            AlertDisposition::RateLimited
        );

        let first = timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("first alert in time")
            .expect("first alert");
        let second = timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("second alert in time")
            .expect("second alert");
        assert_eq!(first["action_type"], "PROC_MODULE_LOAD");
        assert_eq!(first["severity"], "critical");
        assert_eq!(second["system_event"], "telemetry_loss");
        assert!(
            timeout(Duration::from_millis(200), received.recv())
                .await
                .is_err(),
            "rate-limited alert must not be sent"
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        while sink.stats().sent_total < 2 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stats = sink.stats();
        assert_eq!(stats.sent_total, 2);
        assert_eq!(stats.send_failures_total, 0);
        assert_eq!(stats.rate_limited_total, 1);
    }

    #[tokio::test]
    async fn failed_deliveries_are_counted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let app = Router::new().route(
            "/hook",
            post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "no") }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let mut config = config(AlertMinSeverity::Deny, 0);
        config.webhook_url = Some(format!("http://{addr}/hook"));
        let sink = AlertSink::new(&config).expect("sink");
        assert_eq!(
            sink.offer(&file_event(Decision::Deny)),
            AlertDisposition::Queued
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        while sink.stats().send_failures_total == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(sink.stats().send_failures_total, 1);
        assert_eq!(sink.stats().sent_total, 0);
    }
}
