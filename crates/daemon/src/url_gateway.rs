use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use chrono::Utc;
use core_types::{
    ActionType, AuditEvent, Decision, DecisionReason, DecisionResult, EnforcementMode,
    EventContext, McpAuditContext, ModelCallAuditContext, NetworkProtocol, NetworkResource,
    NetworkRule, RequestOutcome, Resource, SystemResource,
};
use http::header::{
    ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderName,
    HeaderValue, PROXY_AUTHORIZATION, TRANSFER_ENCODING, UPGRADE,
};
use http::{Method, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use parking_lot::RwLock;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use reqwest::{Certificate as ReqwestCertificate, Client, ClientBuilder};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, warn};
use uuid::Uuid;

use crate::GuardDaemon;
use crate::ProxySubject;
use crate::gateway_audit::{self, AuditRateLimiter, SOURCE_URL_GATEWAY};
use crate::model_capture::{
    ModelCallRecorder, ModelTraffic, ModelTrafficConfig, WsFrameDecoder, WsMessage, WsModelSession,
};

type SocketPidCacheValue = (Option<ProxySubject>, Option<u32>, Instant);
type SocketPidCache = Arc<RwLock<HashMap<SocketAddr, SocketPidCacheValue>>>;
type PinnedClients = Arc<RwLock<HashMap<(String, Vec<SocketAddr>), Client>>>;

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Largest upstream WebSocket handshake response head accepted.
const MAX_UPGRADE_HEAD_BYTES: usize = 64 * 1024;
/// Largest non-101 handshake refusal body relayed back to the client.
const MAX_UPGRADE_REFUSAL_BODY_BYTES: usize = 1024 * 1024;
/// Upstream clients pinned to resolved addresses, kept per (host, addresses).
const MAX_PINNED_CLIENTS: usize = 256;
/// How often rate-limit windows that dropped records are reported.
const RATE_LIMIT_FLUSH_INTERVAL: Duration = Duration::from_secs(30);
/// `rule_id` of CONNECT requests refused because interception is off.
const TLS_INTERCEPT_DISABLED_RULE: &str = "url_gateway.tls_intercept_disabled";

type ProxyBody = BoxBody<Bytes, io::Error>;

fn full_body(bytes: impl Into<Bytes>) -> ProxyBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

#[derive(Debug, Clone, Deserialize)]
pub struct UrlGatewayConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default = "default_url_gateway_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_url_gateway_no_proxy")]
    pub no_proxy: String,
    #[serde(default = "default_true")]
    pub tls_intercept_enabled: bool,
    #[serde(default = "default_url_gateway_ca_cert_file")]
    pub ca_cert_file: String,
    #[serde(default = "default_url_gateway_ca_key_file")]
    pub ca_key_file: String,
    #[serde(default = "default_true")]
    pub auto_generate_ca: bool,
    #[serde(default = "default_url_gateway_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Time allowed for upstream response headers. Model hosts use
    /// `model_traffic.request_timeout_ms` instead.
    #[serde(default = "default_url_gateway_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Longest pause allowed between upstream response body chunks. Bodies
    /// are streamed, so there is no limit on total transfer time.
    #[serde(default = "default_url_gateway_body_idle_timeout_ms")]
    pub body_idle_timeout_ms: u64,
    #[serde(default)]
    pub upstream_ca_cert_file: Option<String>,
    #[serde(default)]
    pub model_traffic: ModelTrafficConfig,
}

impl Default for UrlGatewayConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            required: true,
            bind_addr: default_url_gateway_bind_addr(),
            no_proxy: default_url_gateway_no_proxy(),
            tls_intercept_enabled: true,
            ca_cert_file: default_url_gateway_ca_cert_file(),
            ca_key_file: default_url_gateway_ca_key_file(),
            auto_generate_ca: true,
            connect_timeout_ms: default_url_gateway_connect_timeout_ms(),
            request_timeout_ms: default_url_gateway_request_timeout_ms(),
            body_idle_timeout_ms: default_url_gateway_body_idle_timeout_ms(),
            upstream_ca_cert_file: None,
            model_traffic: ModelTrafficConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UrlGatewayStatus {
    pub enabled: bool,
    pub ready: bool,
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub no_proxy: Option<String>,
    pub ca_cert_path: Option<String>,
    pub error: Option<String>,
}

impl UrlGatewayStatus {
    pub fn from_config(config: &UrlGatewayConfig) -> Self {
        Self {
            enabled: config.enabled,
            ready: false,
            http_proxy: None,
            https_proxy: None,
            no_proxy: Some(config.no_proxy.clone()),
            ca_cert_path: Some(config.ca_cert_file.clone()),
            error: None,
        }
    }
}

struct CaSigner {
    cert: Certificate,
    key_pair: KeyPair,
}

#[derive(Clone)]
struct CaState {
    signer: Arc<Mutex<CaSigner>>,
    leaf_cache: Arc<RwLock<HashMap<String, Arc<ServerConfig>>>>,
}

#[derive(Clone)]
struct GatewayRuntime {
    daemon: Arc<GuardDaemon>,
    config: UrlGatewayConfig,
    http_client: Client,
    upstream_tls: Arc<rustls::ClientConfig>,
    model: Arc<ModelTraffic>,
    ca: CaState,
    /// Cache of peer socket address -> (resolved subject, socket owner pid,
    /// time inserted). TTL = 30 s.
    socket_pid_cache: SocketPidCache,
    /// Upstream clients whose DNS is pinned to the addresses the policy
    /// check approved, keyed by (host, sorted addresses).
    pinned_clients: PinnedClients,
    /// Limits the records a peer can trigger before it has authenticated.
    auth_limiter: Arc<parking_lot::Mutex<AuditRateLimiter>>,
}

#[derive(Clone)]
struct ConnectionContext {
    peer: SocketAddr,
    /// Process that owns the client end of the connection, when found.
    peer_pid: Option<u32>,
    /// Enrolled agent of `peer_pid`.
    subject: Option<ProxySubject>,
}

fn default_true() -> bool {
    true
}

fn default_url_gateway_bind_addr() -> String {
    "127.0.0.1:19080".to_string()
}

fn default_url_gateway_no_proxy() -> String {
    "localhost,127.0.0.1,::1".to_string()
}

fn default_url_gateway_ca_cert_file() -> String {
    #[cfg(unix)]
    {
        "/etc/mercury/url-gateway-ca.crt".to_string()
    }
}

fn default_url_gateway_ca_key_file() -> String {
    #[cfg(unix)]
    {
        "/etc/mercury/url-gateway-ca.key".to_string()
    }
}

fn default_url_gateway_connect_timeout_ms() -> u64 {
    10_000
}

fn default_url_gateway_request_timeout_ms() -> u64 {
    30_000
}

fn default_url_gateway_body_idle_timeout_ms() -> u64 {
    300_000
}

pub(crate) async fn spawn_url_gateway(daemon: Arc<GuardDaemon>) -> Result<(), String> {
    let config = daemon.url_gateway_config();
    if !config.enabled {
        let mut status = daemon.url_gateway_status_snapshot();
        status.enabled = false;
        status.ready = false;
        status.error = None;
        daemon.set_url_gateway_status(status);
        return Ok(());
    }

    let ca = prepare_ca(&config)?;
    let listener = TcpListener::bind(config.bind_addr.as_str())
        .await
        .map_err(|err| format!("bind url gateway {}: {err}", config.bind_addr))?;

    let client = build_http_client(&config)?;
    let upstream_tls = build_upstream_tls(&config)?;
    let model = Arc::new(ModelTraffic::new(config.model_traffic.clone())?);

    let proxy_url = format!("http://{}", config.bind_addr);
    let mut status = daemon.url_gateway_status_snapshot();
    status.enabled = true;
    status.ready = true;
    status.http_proxy = Some(proxy_url.clone());
    status.https_proxy = Some(proxy_url.clone());
    status.no_proxy = Some(config.no_proxy.clone());
    status.ca_cert_path = Some(config.ca_cert_file.clone());
    status.error = None;
    daemon.set_url_gateway_status(status);

    info!(
        bind_addr = %config.bind_addr,
        tls_intercept = config.tls_intercept_enabled,
        ca_cert_file = %config.ca_cert_file,
        "url gateway listener started"
    );

    let runtime = GatewayRuntime {
        daemon,
        config,
        http_client: client,
        upstream_tls,
        model,
        ca,
        socket_pid_cache: Arc::new(RwLock::new(HashMap::new())),
        pinned_clients: Arc::new(RwLock::new(HashMap::new())),
        auth_limiter: Arc::new(parking_lot::Mutex::new(AuditRateLimiter::default())),
    };

    // Report rate-limited records even when the offending peer goes quiet.
    let flush = runtime.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RATE_LIMIT_FLUSH_INTERVAL);
        loop {
            tick.tick().await;
            let closed = flush.auth_limiter.lock().flush(Instant::now());
            flush.daemon.record_suppressed(closed);
        }
    });

    tokio::spawn(async move {
        loop {
            let accept = listener.accept().await;
            let (stream, peer_addr) = match accept {
                Ok(value) => value,
                Err(err) => {
                    warn!(error = %err, "url gateway accept failed");
                    continue;
                }
            };

            let local_addr = match stream.local_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(error = %err, "url gateway local_addr failed");
                    continue;
                }
            };

            let runtime = runtime.clone();
            tokio::spawn(async move {
                let ctx = resolve_connection_context(&runtime, peer_addr, local_addr).await;
                if let Err(err) = handle_connection(runtime, stream, ctx).await {
                    warn!(error = %err, peer = %peer_addr, "url gateway connection failed");
                }
            });
        }
    });

    Ok(())
}

fn http_client_builder(config: &UrlGatewayConfig) -> Result<ClientBuilder, String> {
    // No total timeout: model responses stream for minutes. Header and
    // body-idle deadlines are enforced per request in `forward_upstream`.
    let mut builder = Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_millis(config.connect_timeout_ms));

    if let Some(path) = config.upstream_ca_cert_file.as_deref() {
        let pem = fs::read(path).map_err(|err| format!("read upstream CA cert {path}: {err}"))?;
        let cert = ReqwestCertificate::from_pem(&pem)
            .map_err(|err| format!("parse upstream CA cert {path}: {err}"))?;
        builder = builder.add_root_certificate(cert);
    }
    Ok(builder)
}

fn build_http_client(config: &UrlGatewayConfig) -> Result<Client, String> {
    http_client_builder(config)?
        .build()
        .map_err(|err| format!("build upstream HTTP client: {err}"))
}

/// A client that connects `host` only to `addrs`, the addresses the policy
/// check approved, so forwarding never repeats the DNS lookup (a rebinding
/// resolver could answer differently the second time). The connector still
/// falls back between those addresses (IPv6 to IPv4) as it would after DNS.
fn pinned_client(
    runtime: &GatewayRuntime,
    host: &str,
    addrs: &[SocketAddr],
) -> Result<Client, String> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(runtime.http_client.clone());
    }
    // Resolvers rotate answer order; the same set reuses the same pool.
    let mut sorted = addrs.to_vec();
    sorted.sort();
    let key = (host.to_string(), sorted);
    if let Some(client) = runtime.pinned_clients.read().get(&key) {
        return Ok(client.clone());
    }
    let client = http_client_builder(&runtime.config)?
        .resolve_to_addrs(host, addrs)
        .build()
        .map_err(|err| format!("build upstream HTTP client for {host}: {err}"))?;
    let mut clients = runtime.pinned_clients.write();
    if clients.len() >= MAX_PINNED_CLIENTS {
        clients.clear();
    }
    clients.insert(key, client.clone());
    Ok(client)
}

async fn handle_connection(
    runtime: GatewayRuntime,
    stream: tokio::net::TcpStream,
    ctx: ConnectionContext,
) -> Result<(), String> {
    let io = TokioIo::new(stream);
    let service = service_fn(move |req| {
        let runtime = runtime.clone();
        let ctx = ctx.clone();
        async move { handle_request(runtime, ctx, req).await }
    });

    http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await
        .map_err(|err| format!("serve proxy connection: {err}"))
}

async fn handle_request(
    runtime: GatewayRuntime,
    ctx: ConnectionContext,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    if req.method() == Method::CONNECT {
        return handle_connect(runtime, ctx, req).await;
    }

    let identity = match authenticate(&runtime, &ctx, &req) {
        Ok(identity) => identity,
        Err(response) => return Ok(response),
    };

    let url = match request_url(&req, "http") {
        Ok(url) => url,
        Err(err) => {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                format!("invalid proxy request URL: {err}").as_str(),
            ));
        }
    };

    Ok(dispatch(&runtime, identity, req, url).await)
}

/// Policy-check one request, pin its upstream address, write the decision
/// record, then relay it as a WebSocket or plain exchange. Every allowed
/// request gets an outcome record sharing the decision's `correlation_id`.
async fn dispatch(
    runtime: &GatewayRuntime,
    identity: RequestIdentity,
    req: Request<Incoming>,
    url: reqwest::Url,
) -> Response<ProxyBody> {
    let started = Instant::now();
    let correlation_id = Uuid::new_v4().to_string();
    let daemon = &runtime.daemon;
    let method = req.method().clone();
    let mut resource = network_resource_from_url(&method, &url);
    let (mut decision, policy_version) = daemon.evaluate_proxy_request(
        &identity.subject,
        identity.pid,
        identity.ppid,
        resource.clone(),
    );

    // Resolve only what policy allows, then check the addresses themselves.
    let mut upstream = Err("upstream address was not resolved".to_string());
    if decision.decision == Decision::Allow {
        upstream = resolve_upstream(runtime, &url).await.map(|addrs| {
            let checked =
                check_upstream_addrs(daemon, &identity.subject.profile, &resource, &addrs);
            resource.dest_ip = Some(checked.addrs[0].ip().to_canonical().to_string());
            if let Some(cidr_decision) = checked.decision {
                decision = cidr_decision;
            }
            checked.addrs
        });
    }

    let logged = gateway_audit::redact_network_resource(&resource);
    let mcp = daemon.active_mcp_context_for_agent(identity.subject.agent_id.as_str());
    daemon.record_audit_event(identity.network_event(
        logged.clone(),
        &decision,
        policy_version.clone(),
        Some(correlation_id.clone()),
        mcp.clone(),
        format!(
            "decision={:?} reason={}",
            decision.decision, decision.reason
        ),
    ));
    if decision.decision == Decision::Deny {
        let body = format!(
            "blocked by mercury policy: reason={:?} rule_id={:?}",
            decision.reason, decision.rule_id
        );
        return text_response(StatusCode::FORBIDDEN, body.as_str());
    }

    let audit = RequestAudit {
        daemon: Arc::clone(daemon),
        identity,
        resource: logged,
        decision,
        policy_version,
        mcp,
        correlation_id,
        started,
    };
    let addrs = match upstream {
        Ok(addrs) => addrs,
        Err(err) => {
            let message = format!("upstream request failed: {err}");
            audit.emit_outcome(audit.outcome(Some(502), 0, 0, Some(message.clone())), None);
            return text_response(StatusCode::BAD_GATEWAY, message.as_str());
        }
    };

    if is_websocket_upgrade(&req) {
        return proxy_websocket(runtime, audit, req, url, &addrs).await;
    }
    forward_upstream(runtime, audit, req, url, &addrs).await
}

async fn handle_connect(
    runtime: GatewayRuntime,
    ctx: ConnectionContext,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let identity = match authenticate(&runtime, &ctx, &req) {
        Ok(identity) => identity,
        Err(response) => return Ok(response),
    };

    let authority = match req.uri().authority() {
        Some(value) => value.as_str().to_string(),
        None => {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "CONNECT missing authority",
            ));
        }
    };

    let (host, port) = match parse_authority(authority.as_str(), 443) {
        Some(value) => value,
        None => {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "CONNECT authority is invalid",
            ));
        }
    };

    if !runtime.config.tls_intercept_enabled {
        record_connect_refused(&runtime.daemon, &identity, host.as_str(), port);
        return Ok(text_response(
            StatusCode::FORBIDDEN,
            "mercury url gateway requires HTTPS interception",
        ));
    }

    let key = peer_key(&ctx);
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let result = intercept_connect_stream(
                    runtime.clone(),
                    identity.clone(),
                    host.clone(),
                    port,
                    upgraded,
                )
                .await;
                match result {
                    Ok(()) => {}
                    Err(InterceptFailure::Tls { stage, error }) => {
                        record_tls_intercept_failure(
                            &runtime, &identity, &key, &host, port, stage, &error,
                        );
                    }
                    Err(InterceptFailure::Serve(error)) => {
                        warn!(error = %error, host = %host, "intercepted HTTPS connection failed");
                    }
                }
            }
            Err(err) => {
                record_tls_intercept_failure(
                    &runtime,
                    &identity,
                    &key,
                    &host,
                    port,
                    "upgrade",
                    &err.to_string(),
                );
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(full_body(Bytes::new()))
        .expect("valid CONNECT response"))
}

/// Why a CONNECT tunnel carried no traffic, or failed part way.
enum InterceptFailure {
    /// No TLS session was established with the client, so nothing was
    /// relayed (a client pinning its certificates ends up here).
    Tls { stage: &'static str, error: String },
    /// The decrypted HTTP connection failed after the handshake.
    Serve(String),
}

async fn intercept_connect_stream(
    runtime: GatewayRuntime,
    identity: RequestIdentity,
    host: String,
    port: u16,
    upgraded: Upgraded,
) -> Result<(), InterceptFailure> {
    let tls_config = runtime
        .ca
        .server_config_for_host(host.as_str())
        .await
        .map_err(|error| InterceptFailure::Tls {
            stage: "certificate",
            error,
        })?;
    let tls_acceptor = TlsAcceptor::from(tls_config);
    let upgraded_io = TokioIo::new(upgraded);
    let tls_stream =
        tls_acceptor
            .accept(upgraded_io)
            .await
            .map_err(|err| InterceptFailure::Tls {
                stage: "handshake",
                error: err.to_string(),
            })?;

    let authority = if port == 443 {
        host.clone()
    } else {
        format!("{}:{}", host, port)
    };

    let service = service_fn(move |req| {
        let runtime = runtime.clone();
        let identity = identity.clone();
        let authority = authority.clone();
        async move {
            let url = match request_url_with_authority(&req, "https", authority.as_str()) {
                Ok(url) => url,
                Err(err) => {
                    return Ok::<Response<ProxyBody>, hyper::Error>(text_response(
                        StatusCode::BAD_REQUEST,
                        format!("invalid intercepted HTTPS request: {err}").as_str(),
                    ));
                }
            };
            Ok(dispatch(&runtime, identity, req, url).await)
        }
    });

    http1::Builder::new()
        .serve_connection(TokioIo::new(tls_stream), service)
        .with_upgrades()
        .await
        .map_err(|err| {
            InterceptFailure::Serve(format!("serve intercepted HTTPS connection: {err}"))
        })
}

fn network_resource_from_url(method: &Method, url: &reqwest::Url) -> NetworkResource {
    NetworkResource {
        dest_host: url.host_str().map(|value| value.to_string()),
        dest_ip: None,
        dest_port: url
            .port_or_known_default()
            .unwrap_or_else(|| if url.scheme() == "https" { 443 } else { 80 }),
        protocol: NetworkProtocol::Tcp,
        full_url: Some(url.as_str().to_string()),
        scheme: Some(url.scheme().to_string()),
        method: Some(method.as_str().to_ascii_uppercase()),
        path: Some(url.path().to_string()),
        query: url.query().map(|value| value.to_string()),
        socket_path: None,
        family: None,
    }
}

// ── attribution and audit records ───────────────────────────────────────────

/// Who sent a proxied request: the enrolled agent that authenticated it, and
/// the process that owns the client socket.
#[derive(Clone, Debug)]
struct RequestIdentity {
    subject: ProxySubject,
    /// Owner of the client socket. Falls back to the subject's pid (the
    /// registration pid for token-authenticated requests) when the socket
    /// owner could not be found.
    pid: u32,
    ppid: u32,
    /// Registration pid of the agent (the enrollment root).
    root_pid: Option<u32>,
    parent_agent_id: Option<String>,
}

impl RequestIdentity {
    /// `from_token`: `subject` came from a proxy token and carries the
    /// registration pid, not the socket owner.
    fn resolve(
        daemon: &GuardDaemon,
        subject: ProxySubject,
        peer_pid: Option<u32>,
        from_token: bool,
    ) -> Self {
        let (registration_pid, parent_agent_id) = daemon.agent_lineage(&subject.agent_id);
        let root_pid = registration_pid.or(from_token.then_some(subject.pid));
        let (pid, ppid) = match peer_pid {
            Some(peer) if peer != subject.pid => (peer, crate::parent_pid_for(peer).unwrap_or(0)),
            _ => (subject.pid, subject.ppid),
        };
        Self {
            subject,
            pid,
            ppid,
            root_pid,
            parent_agent_id,
        }
    }

    /// Attribute a record to this request's agent and process.
    fn attribute(&self, event: &mut AuditEvent) {
        event.agent_id = self.subject.agent_id.clone();
        event.profile = self.subject.profile.clone();
        event.pid = Some(self.pid);
        event.ppid = Some(self.ppid);
        event.uid = Some(self.subject.uid);
        event.context.root_pid = self.root_pid;
        event.context.parent_agent_id = self.parent_agent_id.clone();
    }

    fn network_event(
        &self,
        resource: NetworkResource,
        decision: &DecisionResult,
        policy_version: String,
        correlation_id: Option<String>,
        mcp: Option<McpAuditContext>,
        message: String,
    ) -> AuditEvent {
        let mut event = AuditEvent {
            timestamp: Utc::now(),
            agent_id: String::new(),
            pid: None,
            ppid: None,
            uid: None,
            action_type: ActionType::NetConnect,
            decision: decision.decision,
            reason: decision.reason,
            rule_id: decision.rule_id.clone(),
            resource: Resource::Network(resource),
            profile: String::new(),
            policy_version,
            message,
            mcp,
            kernel_seq: None,
            events_dropped: None,
            model: None,
            context: EventContext {
                source: Some(SOURCE_URL_GATEWAY.to_string()),
                correlation_id,
                ..EventContext::default()
            },
        };
        self.attribute(&mut event);
        event
    }
}

/// Audit state of one allowed request. The decision record is written
/// before the request is sent; `emit_outcome` writes the matching outcome
/// record once it has finished.
#[derive(Clone)]
struct RequestAudit {
    daemon: Arc<GuardDaemon>,
    identity: RequestIdentity,
    /// Redacted copy of the request's resource, with `dest_ip` set.
    resource: NetworkResource,
    decision: DecisionResult,
    policy_version: String,
    mcp: Option<McpAuditContext>,
    correlation_id: String,
    started: Instant,
}

impl RequestAudit {
    fn record(&self, message: String) -> AuditEvent {
        self.identity.network_event(
            self.resource.clone(),
            &self.decision,
            self.policy_version.clone(),
            Some(self.correlation_id.clone()),
            self.mcp.clone(),
            message,
        )
    }

    fn outcome(
        &self,
        status: Option<u16>,
        bytes_sent: u64,
        bytes_received: u64,
        error: Option<String>,
    ) -> RequestOutcome {
        RequestOutcome {
            status,
            bytes_sent,
            bytes_received,
            duration_ms: self.started.elapsed().as_millis() as u64,
            error,
        }
    }

    /// One model call observed on a WebSocket. A connection can carry many;
    /// the connection's own outcome is written when it closes.
    fn emit_model_call(&self, model: ModelCallAuditContext) {
        let mut event = self.record(model_call_message(&model));
        event.model = Some(model);
        self.daemon.record_audit_event(event);
    }

    /// The request's outcome record. For a model API exchange it also
    /// carries the captured call, so each call is one record.
    fn emit_outcome(&self, outcome: RequestOutcome, model: Option<ModelCallAuditContext>) {
        let message = match &model {
            Some(model) => model_call_message(model),
            None => format!(
                "request outcome status={} bytes_sent={} bytes_received={} duration_ms={}{}",
                outcome
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                outcome.bytes_sent,
                outcome.bytes_received,
                outcome.duration_ms,
                outcome
                    .error
                    .as_deref()
                    .map(|error| format!(" error={error}"))
                    .unwrap_or_default()
            ),
        };
        let mut event = self.record(message);
        event.model = model;
        event.context.outcome = Some(outcome);
        self.daemon.record_audit_event(event);
    }
}

fn model_call_message(model: &ModelCallAuditContext) -> String {
    format!(
        "model call provider={} model={} status={} duration_ms={}",
        model.provider,
        model.model.as_deref().unwrap_or("unknown"),
        model
            .status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "none".to_string()),
        model.duration_ms
    )
}

/// Rate-limit key of the peer behind a connection.
fn peer_key(ctx: &ConnectionContext) -> String {
    match ctx.peer_pid {
        Some(pid) => format!("pid:{pid}"),
        None => format!("ip:{}", ctx.peer.ip()),
    }
}

/// Identify the agent behind a request: the proxy token when one is sent,
/// else the enrolled owner of the client socket. Rejections are audited.
#[allow(clippy::result_large_err)]
fn authenticate(
    runtime: &GatewayRuntime,
    ctx: &ConnectionContext,
    request: &Request<Incoming>,
) -> Result<RequestIdentity, Response<ProxyBody>> {
    let daemon = runtime.daemon.as_ref();
    let token = proxy_auth_token(request);
    let (failure, message) = match token.as_deref() {
        Some(token) => match daemon.resolve_proxy_subject_for_token(token) {
            // The token authenticates; the socket owner says which process
            // of the agent sent the request.
            Some(subject) => {
                return Ok(RequestIdentity::resolve(
                    daemon,
                    subject,
                    ctx.peer_pid,
                    true,
                ));
            }
            None => (
                "invalid_proxy_token",
                "mercury url gateway: proxy authentication token is invalid",
            ),
        },
        None => match ctx.subject.clone() {
            Some(subject) => {
                return Ok(RequestIdentity::resolve(
                    daemon,
                    subject,
                    ctx.peer_pid,
                    false,
                ));
            }
            None if request.method() == Method::CONNECT => (
                "unresolved_subject",
                "mercury url gateway: unable to resolve enrolled process for CONNECT",
            ),
            None => (
                "unresolved_subject",
                "mercury url gateway: unable to resolve enrolled process for connection",
            ),
        },
    };
    record_auth_failure(runtime, ctx, request, failure, token.is_some());
    Err(text_response(StatusCode::FORBIDDEN, message))
}

/// `SYSTEM_EVENT gateway_auth_failure`, rate-limited per peer.
fn record_auth_failure(
    runtime: &GatewayRuntime,
    ctx: &ConnectionContext,
    request: &Request<Incoming>,
    failure: &'static str,
    token_present: bool,
) {
    let target = if request.method() == Method::CONNECT {
        request
            .uri()
            .authority()
            .map(|authority| authority.to_string())
            .unwrap_or_default()
    } else {
        gateway_audit::redact_url(request.uri().to_string().as_str())
    };
    let mut resource = SystemResource::new("gateway_auth_failure")
        .detail(failure)
        .attr("failure", failure)
        .attr("peer", ctx.peer.to_string())
        .attr("method", request.method().as_str())
        .attr("target", target.clone())
        .attr("token_present", token_present);
    if let Some(pid) = ctx.peer_pid {
        resource = resource.attr("peer_pid", pid);
    }
    let daemon = &runtime.daemon;
    let mut event = AuditEvent::system(
        SOURCE_URL_GATEWAY,
        resource,
        daemon.policy_version(),
        format!(
            "url gateway rejected {} {target}: {failure}",
            request.method()
        ),
    );
    event.decision = Decision::Deny;
    event.reason = DecisionReason::DenyFailClosed;
    event.pid = ctx.peer_pid;
    if let Some(subject) = ctx.subject.as_ref() {
        event.agent_id = subject.agent_id.clone();
        event.profile = subject.profile.clone();
        event.uid = Some(subject.uid);
    }
    daemon.record_rate_limited(
        &runtime.auth_limiter,
        SOURCE_URL_GATEWAY,
        "gateway_auth_failure",
        &peer_key(ctx),
        event,
    );
}

/// `NET_CONNECT` deny for a CONNECT the gateway cannot inspect because TLS
/// interception is off (it never tunnels blind).
fn record_connect_refused(daemon: &GuardDaemon, identity: &RequestIdentity, host: &str, port: u16) {
    let resource = NetworkResource {
        dest_host: Some(host.to_string()),
        dest_ip: None,
        dest_port: port,
        protocol: NetworkProtocol::Tcp,
        full_url: None,
        scheme: Some("https".to_string()),
        method: Some("CONNECT".to_string()),
        path: None,
        query: None,
        socket_path: None,
        family: None,
    };
    let decision = DecisionResult {
        decision: Decision::Deny,
        reason: DecisionReason::DenyFailClosed,
        rule_id: Some(TLS_INTERCEPT_DISABLED_RULE.to_string()),
    };
    daemon.record_audit_event(identity.network_event(
        resource,
        &decision,
        daemon.policy_version(),
        None,
        None,
        format!("CONNECT {host}:{port} refused: TLS interception is disabled"),
    ));
}

/// `SYSTEM_EVENT tls_intercept_failed`, rate-limited per peer: the client
/// never completed a TLS session with the gateway (for example it pins
/// certificates), so nothing was relayed.
#[allow(clippy::too_many_arguments)]
fn record_tls_intercept_failure(
    runtime: &GatewayRuntime,
    identity: &RequestIdentity,
    key: &str,
    host: &str,
    port: u16,
    stage: &'static str,
    error: &str,
) {
    warn!(host, port, stage, error, "CONNECT interception failed");
    let daemon = &runtime.daemon;
    let mut event = AuditEvent::system(
        SOURCE_URL_GATEWAY,
        SystemResource::new("tls_intercept_failed")
            .detail(format!("{host}:{port}"))
            .attr("host", host)
            .attr("port", port)
            .attr("stage", stage)
            .attr("error", error),
        daemon.policy_version(),
        format!(
            "TLS interception of {host}:{port} failed at {stage}; nothing was relayed: {error}"
        ),
    );
    event.decision = Decision::Deny;
    event.reason = DecisionReason::DenyFailClosed;
    identity.attribute(&mut event);
    daemon.record_rate_limited(
        &runtime.auth_limiter,
        SOURCE_URL_GATEWAY,
        "tls_intercept_failed",
        key,
        event,
    );
}

// ── upstream address pinning ────────────────────────────────────────────────

async fn resolve_upstream(
    runtime: &GatewayRuntime,
    url: &reqwest::Url,
) -> Result<Vec<SocketAddr>, String> {
    let host = url_host(url);
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("no port for {host}"))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let deadline = Duration::from_millis(runtime.config.connect_timeout_ms);
    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(deadline, tokio::net::lookup_host((host.as_str(), port)))
            .await
            .map_err(|_| format!("resolve {host} timed out"))?
            .map_err(|err| format!("resolve {host}: {err}"))?
            .collect();
    if addrs.is_empty() {
        return Err(format!("resolve {host}: no addresses"));
    }
    Ok(addrs)
}

/// Where a request may be sent once its host is resolved.
#[derive(Debug)]
struct UpstreamCheck {
    /// Addresses to connect to, in resolver order; never empty. When every
    /// address is denied this holds the first one, for the record.
    addrs: Vec<SocketAddr>,
    /// Replaces the URL decision when a CIDR rule denies every address.
    decision: Option<DecisionResult>,
}

/// Filter the resolved addresses. `network_deny` rules with a `cidr` apply
/// to them even when a URL rule allowed the request: the policy engine lets
/// URL rules take precedence over network rules, so without this an allowed
/// hostname resolving to a denied range (link-local metadata, RFC 1918,
/// loopback) would be reachable. Denied addresses are dropped; if none is
/// left the request is denied by the first matching rule (or only recorded,
/// in observe mode).
fn check_upstream_addrs(
    daemon: &GuardDaemon,
    profile: &str,
    resource: &NetworkResource,
    addrs: &[SocketAddr],
) -> UpstreamCheck {
    let policy = daemon.active_policy.read();
    let Some(compiled) = policy
        .as_ref()
        .and_then(|policy| policy.profiles.get(profile))
    else {
        return UpstreamCheck {
            addrs: addrs.to_vec(),
            decision: None,
        };
    };
    let mut permitted = Vec::with_capacity(addrs.len());
    let mut first_denied: Option<(SocketAddr, &NetworkRule)> = None;
    for addr in addrs {
        let ip = addr.ip().to_canonical();
        match compiled
            .network_deny
            .iter()
            .find(|rule| cidr_rule_matches(rule, resource, ip))
        {
            None => permitted.push(*addr),
            Some(rule) => {
                first_denied.get_or_insert((*addr, rule));
            }
        }
    }
    let Some((denied, rule)) = first_denied.filter(|_| permitted.is_empty()) else {
        return UpstreamCheck {
            addrs: permitted,
            decision: None,
        };
    };
    if compiled.enforcement.network == EnforcementMode::Observe {
        return UpstreamCheck {
            addrs: addrs.to_vec(),
            decision: Some(DecisionResult {
                decision: Decision::Allow,
                reason: DecisionReason::AllowByObserveMode,
                rule_id: Some(rule.id.clone()),
            }),
        };
    }
    UpstreamCheck {
        addrs: vec![denied],
        decision: Some(DecisionResult {
            decision: Decision::Deny,
            reason: DecisionReason::DenyByRule,
            rule_id: Some(rule.id.clone()),
        }),
    }
}

/// A `cidr` network rule matching `ip` (plus its port, protocol and host
/// constraints, as the policy engine applies them).
fn cidr_rule_matches(rule: &NetworkRule, resource: &NetworkResource, ip: IpAddr) -> bool {
    let Some(cidr) = rule.cidr else {
        return false;
    };
    if !cidr.contains(&ip) {
        return false;
    }
    if rule
        .protocol
        .is_some_and(|protocol| protocol != resource.protocol)
    {
        return false;
    }
    if rule.port.is_some_and(|port| port != resource.dest_port) {
        return false;
    }
    if let Some(host_glob) = rule.host_glob.as_deref() {
        let Some(host) = resource.dest_host.as_deref() else {
            return false;
        };
        let Ok(glob) = globset::Glob::new(host_glob) else {
            return false;
        };
        if !glob.compile_matcher().is_match(host) {
            return false;
        }
    }
    true
}

fn header_str(headers: &http::HeaderMap, name: HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn url_host(url: &reqwest::Url) -> String {
    url.host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

fn header_timeout(runtime: &GatewayRuntime, host: &str) -> Duration {
    if runtime.model.is_model_host(host) {
        Duration::from_millis(runtime.model.request_timeout_ms())
    } else {
        Duration::from_millis(runtime.config.request_timeout_ms)
    }
}

async fn forward_upstream(
    runtime: &GatewayRuntime,
    audit: RequestAudit,
    request: Request<Incoming>,
    url: reqwest::Url,
    addrs: &[SocketAddr],
) -> Response<ProxyBody> {
    let (parts, body) = request.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            let message = format!("read request body: {err}");
            audit.emit_outcome(audit.outcome(Some(400), 0, 0, Some(message.clone())), None);
            return text_response(StatusCode::BAD_REQUEST, message.as_str());
        }
    };
    let bytes_sent = body_bytes.len() as u64;

    let host = url_host(&url);
    let mut recorder = runtime.model.target_for(&host, url.path()).map(|target| {
        ModelCallRecorder::for_http(
            runtime.model.settings(),
            &target,
            &body_bytes,
            header_str(&parts.headers, CONTENT_ENCODING),
        )
    });

    let fail = |recorder: Option<ModelCallRecorder>, status: StatusCode, message: String| {
        let model = recorder.map(|recorder| recorder.finish(Some(message.clone())));
        audit.emit_outcome(
            audit.outcome(Some(status.as_u16()), bytes_sent, 0, Some(message.clone())),
            model,
        );
        text_response(status, message.as_str())
    };

    let method = match reqwest::Method::from_bytes(parts.method.as_str().as_bytes()) {
        Ok(method) => method,
        Err(err) => {
            return fail(
                recorder,
                StatusCode::BAD_REQUEST,
                format!("unsupported method '{}': {err}", parts.method),
            );
        }
    };
    let client = match pinned_client(runtime, &host, addrs) {
        Ok(client) => client,
        Err(err) => return fail(recorder, StatusCode::BAD_GATEWAY, err),
    };
    let mut builder = client.request(method, url);

    for (name, value) in &parts.headers {
        if should_skip_request_header(name) {
            continue;
        }
        // Captured responses must arrive uncompressed so they can be parsed.
        if recorder.is_some() && *name == ACCEPT_ENCODING {
            continue;
        }
        builder = builder.header(name, value);
    }
    if recorder.is_some() {
        builder = builder.header(ACCEPT_ENCODING, "identity");
    }

    if !body_bytes.is_empty() {
        builder = builder.body(body_bytes);
    }

    let deadline = header_timeout(runtime, &host);
    let upstream = match tokio::time::timeout(deadline, builder.send()).await {
        Ok(Ok(upstream)) => upstream,
        // The URL is already in the record (redacted); keep it out of the error.
        Ok(Err(err)) => {
            return fail(
                recorder,
                StatusCode::BAD_GATEWAY,
                format!("upstream request failed: {}", err.without_url()),
            );
        }
        Err(_) => {
            return fail(
                recorder,
                StatusCode::GATEWAY_TIMEOUT,
                format!(
                    "upstream did not return response headers within {} ms",
                    deadline.as_millis()
                ),
            );
        }
    };

    let status = upstream.status();
    let headers = upstream.headers().clone();
    if let Some(recorder) = recorder.as_mut() {
        recorder.on_response_head(
            status.as_u16(),
            header_str(&headers, CONTENT_TYPE),
            header_str(&headers, CONTENT_ENCODING),
        );
    }

    let mut out = Response::builder().status(status);
    for (name, value) in &headers {
        if should_skip_response_header(name) {
            continue;
        }
        out = out.header(name, value);
    }

    let (tx, rx) = mpsc::channel(16);
    let body = StreamBody::new(ReceiverStream::new(rx)).boxed();
    let response = match out.body(body) {
        Ok(response) => response,
        Err(err) => {
            return fail(
                recorder,
                StatusCode::BAD_GATEWAY,
                format!("build response: {err}"),
            );
        }
    };

    let idle = Duration::from_millis(runtime.config.body_idle_timeout_ms);
    tokio::spawn(pump_response_body(
        upstream,
        tx,
        idle,
        recorder,
        audit,
        bytes_sent,
        status.as_u16(),
    ));
    response
}

/// Relay upstream body chunks to the client as they arrive, feeding the model
/// recorder along the way, and write the outcome record when the body ends.
async fn pump_response_body(
    mut upstream: reqwest::Response,
    tx: mpsc::Sender<Result<Frame<Bytes>, io::Error>>,
    idle: Duration,
    mut recorder: Option<ModelCallRecorder>,
    audit: RequestAudit,
    bytes_sent: u64,
    status: u16,
) {
    let mut bytes_received = 0u64;
    let note = loop {
        match tokio::time::timeout(idle, upstream.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                bytes_received += chunk.len() as u64;
                if let Some(recorder) = recorder.as_mut() {
                    recorder.on_body_chunk(&chunk);
                }
                if tx.send(Ok(Frame::data(chunk))).await.is_err() {
                    break Some("client disconnected before the response finished".to_string());
                }
            }
            Ok(Ok(None)) => break None,
            Ok(Err(err)) => {
                let message = format!("upstream response body failed: {}", err.without_url());
                let _ = tx.send(Err(io::Error::other(message.clone()))).await;
                break Some(message);
            }
            Err(_) => {
                let message = format!(
                    "upstream response body idle for more than {} ms",
                    idle.as_millis()
                );
                let _ = tx
                    .send(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        message.clone(),
                    )))
                    .await;
                break Some(message);
            }
        }
    };
    let model = recorder.map(|recorder| recorder.finish(note.clone()));
    audit.emit_outcome(
        audit.outcome(Some(status), bytes_sent, bytes_received, note),
        model,
    );
}

// ── WebSocket relay ─────────────────────────────────────────────────────────

fn header_has_token<B>(req: &Request<B>, name: HeaderName, token: &str) -> bool {
    req.headers().get_all(name).iter().any(|value| {
        value
            .to_str()
            .map(|text| {
                text.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case(token))
            })
            .unwrap_or(false)
    })
}

fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    header_has_token(req, UPGRADE, "websocket") && header_has_token(req, CONNECTION, "upgrade")
}

trait UpstreamIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> UpstreamIo for T {}

/// Connect to the first reachable of `addrs`, the addresses the policy
/// check approved, speaking TLS to `url`'s host when the scheme needs it.
async fn connect_upstream(
    runtime: &GatewayRuntime,
    url: &reqwest::Url,
    addrs: &[SocketAddr],
) -> Result<Box<dyn UpstreamIo>, String> {
    let host = url_host(url);
    let connect_timeout = Duration::from_millis(runtime.config.connect_timeout_ms);
    let mut failures = Vec::new();
    let mut connected = None;
    for addr in addrs {
        match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(tcp)) => {
                connected = Some((tcp, *addr));
                break;
            }
            Ok(Err(err)) => failures.push(format!("{addr}: {err}")),
            Err(_) => failures.push(format!("{addr}: timed out")),
        }
    }
    let Some((tcp, addr)) = connected else {
        return Err(format!("connect {host}: {}", failures.join("; ")));
    };

    if !matches!(url.scheme(), "https" | "wss") {
        return Ok(Box::new(tcp));
    }
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|err| format!("invalid TLS server name '{host}': {err}"))?;
    let tls = TlsConnector::from(Arc::clone(&runtime.upstream_tls))
        .connect(server_name, tcp)
        .await
        .map_err(|err| format!("TLS handshake with {host} ({addr}): {err}"))?;
    Ok(Box::new(tls))
}

/// Serialise the client's upgrade request for the upstream origin.
fn websocket_request_head<B>(
    req: &Request<B>,
    url: &reqwest::Url,
    strip_extensions: bool,
) -> Vec<u8> {
    let mut path = url.path().to_string();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let authority = match (url.port(), url.host_str()) {
        (Some(port), Some(host)) => format!("{host}:{port}"),
        (None, Some(host)) => host.to_string(),
        _ => String::new(),
    };

    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        req.method(),
        path,
        authority
    )
    .into_bytes();
    for (name, value) in req.headers() {
        let lower = name.as_str();
        if lower == HOST.as_str()
            || lower == PROXY_AUTHORIZATION.as_str()
            || lower == "proxy-connection"
        {
            continue;
        }
        // Without negotiated compression the observer can read frames as-is.
        if strip_extensions && lower == "sec-websocket-extensions" {
            continue;
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    head
}

struct UpstreamHead {
    status: u16,
    headers: Vec<(HeaderName, HeaderValue)>,
    /// Bytes read past the end of the head (the start of the next frame/body).
    leftover: Vec<u8>,
}

async fn read_response_head(io: &mut Box<dyn UpstreamIo>) -> Result<UpstreamHead, String> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = io
            .read(&mut chunk)
            .await
            .map_err(|err| format!("read upstream handshake: {err}"))?;
        if n == 0 {
            return Err("upstream closed during WebSocket handshake".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);

        let mut raw_headers = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut raw_headers);
        match parsed.parse(&buf) {
            Ok(httparse::Status::Complete(head_len)) => {
                let status = parsed.code.unwrap_or(502);
                let headers = parsed
                    .headers
                    .iter()
                    .filter_map(|h| {
                        Some((
                            HeaderName::from_bytes(h.name.as_bytes()).ok()?,
                            HeaderValue::from_bytes(h.value).ok()?,
                        ))
                    })
                    .collect();
                return Ok(UpstreamHead {
                    status,
                    headers,
                    leftover: buf[head_len..].to_vec(),
                });
            }
            Ok(httparse::Status::Partial) if buf.len() < MAX_UPGRADE_HEAD_BYTES => continue,
            Ok(httparse::Status::Partial) => {
                return Err("upstream WebSocket handshake head too large".to_string());
            }
            Err(err) => return Err(format!("parse upstream handshake: {err}")),
        }
    }
}

/// Relay an upstream refusal (anything but 101) back to the client. Returns
/// the response and the number of body bytes relayed.
async fn refusal_response(
    mut io: Box<dyn UpstreamIo>,
    head: UpstreamHead,
) -> (Response<ProxyBody>, u64) {
    let mut body = head.leftover;
    let declared = head
        .headers
        .iter()
        .find(|(name, _)| *name == CONTENT_LENGTH)
        .and_then(|(_, value)| value.to_str().ok()?.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_UPGRADE_REFUSAL_BODY_BYTES);
    let mut chunk = [0u8; 4096];
    while body.len() < declared {
        match tokio::time::timeout(Duration::from_secs(5), io.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => body.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    body.truncate(declared);
    let relayed = body.len() as u64;

    let status = StatusCode::from_u16(head.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut out = Response::builder().status(status);
    for (name, value) in &head.headers {
        if should_skip_response_header(name) || *name == CONTENT_LENGTH {
            continue;
        }
        out = out.header(name, value);
    }
    let response = out.body(full_body(body)).unwrap_or_else(|err| {
        text_response(StatusCode::BAD_GATEWAY, &format!("build response: {err}"))
    });
    (response, relayed)
}

async fn proxy_websocket(
    runtime: &GatewayRuntime,
    audit: RequestAudit,
    mut req: Request<Incoming>,
    url: reqwest::Url,
    addrs: &[SocketAddr],
) -> Response<ProxyBody> {
    let host = url_host(&url);
    let session = runtime
        .model
        .target_for(&host, url.path())
        .map(|target| WsModelSession::new(runtime.model.settings(), target));

    let fail = |status: StatusCode, message: String| {
        audit.emit_outcome(
            audit.outcome(Some(status.as_u16()), 0, 0, Some(message.clone())),
            None,
        );
        text_response(status, message.as_str())
    };

    let mut upstream = match connect_upstream(runtime, &url, addrs).await {
        Ok(io) => io,
        Err(err) => {
            return fail(
                StatusCode::BAD_GATEWAY,
                format!("upstream WebSocket connect failed: {err}"),
            );
        }
    };
    let request_head = websocket_request_head(&req, &url, session.is_some());
    if let Err(err) = upstream.write_all(&request_head).await {
        return fail(
            StatusCode::BAD_GATEWAY,
            format!("send upstream WebSocket handshake: {err}"),
        );
    }

    let deadline = header_timeout(runtime, &host);
    let head = match tokio::time::timeout(deadline, read_response_head(&mut upstream)).await {
        Ok(Ok(head)) => head,
        Ok(Err(err)) => return fail(StatusCode::BAD_GATEWAY, err),
        Err(_) => {
            return fail(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream WebSocket handshake timed out".to_string(),
            );
        }
    };
    if head.status != StatusCode::SWITCHING_PROTOCOLS.as_u16() {
        let status = head.status;
        let (response, relayed) = refusal_response(upstream, head).await;
        audit.emit_outcome(audit.outcome(Some(status), 0, relayed, None), None);
        return response;
    }

    let on_upgrade = hyper::upgrade::on(&mut req);
    let mut out = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (name, value) in &head.headers {
        out = out.header(name, value);
    }
    let limit = runtime.model.settings().max_capture_bytes;
    let leftover = head.leftover;
    let relay_audit = audit.clone();
    tokio::spawn(async move {
        let audit = relay_audit;
        match on_upgrade.await {
            Ok(client) => {
                let traffic = relay_websocket(
                    TokioIo::new(client),
                    upstream,
                    leftover,
                    session,
                    &audit,
                    limit,
                )
                .await;
                audit.emit_outcome(
                    audit.outcome(Some(101), traffic.sent, traffic.received, traffic.error),
                    None,
                );
            }
            Err(err) => {
                warn!(error = %err, "client WebSocket upgrade failed");
                audit.emit_outcome(
                    audit.outcome(
                        Some(101),
                        0,
                        0,
                        Some(format!("client WebSocket upgrade failed: {err}")),
                    ),
                    None,
                );
            }
        }
    });

    out.body(full_body(Bytes::new())).unwrap_or_else(|err| {
        text_response(StatusCode::BAD_GATEWAY, &format!("build response: {err}"))
    })
}

/// Bytes relayed over one WebSocket connection, per direction.
struct WsTraffic {
    /// Client to upstream.
    sent: u64,
    /// Upstream to client.
    received: u64,
    error: Option<String>,
}

/// Copy bytes both ways between client and upstream. When a model session is
/// attached, frames are decoded on the side (never altered) and each
/// completed call is audited.
async fn relay_websocket<C: AsyncRead + AsyncWrite + Unpin + Send>(
    client: C,
    upstream: Box<dyn UpstreamIo>,
    leftover: Vec<u8>,
    session: Option<WsModelSession>,
    audit: &RequestAudit,
    limit: usize,
) -> WsTraffic {
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut up_r, mut up_w) = tokio::io::split(upstream);
    let session = session.map(|s| Arc::new(parking_lot::Mutex::new(s)));
    let sent = AtomicU64::new(0);
    let received = AtomicU64::new(0);

    let client_to_upstream = {
        let session = session.clone();
        let sent = &sent;
        async move {
            let mut decoder = WsFrameDecoder::new(limit);
            let mut messages = Vec::new();
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = client_r.read(&mut buf).await?;
                if n == 0 {
                    let _ = up_w.shutdown().await;
                    return Ok::<(), io::Error>(());
                }
                up_w.write_all(&buf[..n]).await?;
                sent.fetch_add(n as u64, Ordering::Relaxed);
                if let Some(session) = &session {
                    decoder.feed(&buf[..n], &mut messages);
                    for message in messages.drain(..) {
                        let call = match message {
                            WsMessage::Text(text) => session.lock().on_client_text(&text),
                            WsMessage::Oversized => session.lock().on_client_oversized(),
                            WsMessage::Binary | WsMessage::Close => None,
                        };
                        if let Some(call) = call {
                            audit.emit_model_call(call);
                        }
                    }
                }
            }
        }
    };

    let upstream_to_client = {
        let session = session.clone();
        let received = &received;
        async move {
            let mut decoder = WsFrameDecoder::new(limit);
            let mut messages = Vec::new();
            let mut pending = leftover;
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let data: &[u8] = if pending.is_empty() {
                    let n = up_r.read(&mut buf).await?;
                    if n == 0 {
                        let _ = client_w.shutdown().await;
                        return Ok::<(), io::Error>(());
                    }
                    &buf[..n]
                } else {
                    &pending
                };
                client_w.write_all(data).await?;
                received.fetch_add(data.len() as u64, Ordering::Relaxed);
                if let Some(session) = &session {
                    decoder.feed(data, &mut messages);
                    for message in messages.drain(..) {
                        let call = match message {
                            WsMessage::Text(text) => session.lock().on_server_text(&text),
                            WsMessage::Oversized => {
                                session.lock().on_server_oversized();
                                None
                            }
                            WsMessage::Binary | WsMessage::Close => None,
                        };
                        if let Some(call) = call {
                            audit.emit_model_call(call);
                        }
                    }
                }
                pending.clear();
            }
        }
    };

    tokio::pin!(client_to_upstream, upstream_to_client);
    let drain = Duration::from_secs(30);
    let error = tokio::select! {
        result = &mut client_to_upstream => match result {
            Ok(()) => match tokio::time::timeout(drain, &mut upstream_to_client).await {
                Ok(Err(err)) => Some(format!("upstream to client: {err}")),
                _ => None,
            },
            Err(err) => Some(format!("client to upstream: {err}")),
        },
        result = &mut upstream_to_client => match result {
            Ok(()) => match tokio::time::timeout(drain, &mut client_to_upstream).await {
                Ok(Err(err)) => Some(format!("client to upstream: {err}")),
                _ => None,
            },
            Err(err) => Some(format!("upstream to client: {err}")),
        },
    };

    if let Some(session) = session
        && let Some(call) = session
            .lock()
            .close("websocket closed before the response completed")
    {
        audit.emit_model_call(call);
    }

    WsTraffic {
        sent: sent.load(Ordering::Relaxed),
        received: received.load(Ordering::Relaxed),
        error,
    }
}

fn build_upstream_tls(config: &UrlGatewayConfig) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = config.upstream_ca_cert_file.as_deref() {
        let pem = fs::read(path).map_err(|err| format!("read upstream CA cert {path}: {err}"))?;
        for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
            let cert = cert.map_err(|err| format!("parse upstream CA cert {path}: {err}"))?;
            roots
                .add(cert)
                .map_err(|err| format!("add upstream CA cert {path}: {err}"))?;
        }
    }
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| format!("configure upstream TLS: {err}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

fn should_skip_request_header(name: &HeaderName) -> bool {
    let lower = name.as_str().to_ascii_lowercase();
    if lower == HOST.as_str()
        || lower == PROXY_AUTHORIZATION.as_str()
        || lower == "proxy-connection"
    {
        return true;
    }
    HOP_BY_HOP_HEADERS.contains(&lower.as_str())
}

fn should_skip_response_header(name: &HeaderName) -> bool {
    let lower = name.as_str().to_ascii_lowercase();
    if lower == CONNECTION.as_str()
        || lower == TRANSFER_ENCODING.as_str()
        || lower == UPGRADE.as_str()
    {
        return true;
    }
    HOP_BY_HOP_HEADERS.contains(&lower.as_str())
}

fn request_url<B>(request: &Request<B>, default_scheme: &str) -> Result<reqwest::Url, String> {
    if request.uri().scheme().is_some() {
        return reqwest::Url::parse(request.uri().to_string().as_str())
            .map_err(|err| err.to_string());
    }

    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "missing host header".to_string())?;
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let absolute = format!("{}://{}{}", default_scheme, host, path);
    reqwest::Url::parse(absolute.as_str()).map_err(|err| err.to_string())
}

fn request_url_with_authority<B>(
    request: &Request<B>,
    default_scheme: &str,
    authority: &str,
) -> Result<reqwest::Url, String> {
    if request.uri().scheme().is_some() {
        return reqwest::Url::parse(request.uri().to_string().as_str())
            .map_err(|err| err.to_string());
    }

    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let absolute = format!("{}://{}{}", default_scheme, authority, path);
    reqwest::Url::parse(absolute.as_str()).map_err(|err| err.to_string())
}

fn parse_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let parsed = authority.parse::<http::uri::Authority>().ok()?;
    let host = parsed.host().to_string();
    let port = parsed.port_u16().unwrap_or(default_port);
    Some((host, port))
}

fn proxy_auth_token(request: &Request<Incoming>) -> Option<String> {
    let value = request.headers().get(PROXY_AUTHORIZATION)?.to_str().ok()?;
    parse_proxy_auth_token(value)
}

fn parse_proxy_auth_token(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let mut parts = value.splitn(2, ' ');
    let scheme = parts.next()?;
    let credentials = parts.next()?.trim();

    if scheme.eq_ignore_ascii_case("bearer") {
        if credentials.is_empty() {
            return None;
        }
        return Some(credentials.to_string());
    }

    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(credentials.as_bytes())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (_, password) = decoded.split_once(':')?;
    if password.is_empty() {
        return None;
    }
    Some(password.to_string())
}

fn text_response(status: StatusCode, body: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(full_body(body.to_string()))
        .expect("valid response")
}

async fn resolve_connection_context(
    runtime: &GatewayRuntime,
    peer: SocketAddr,
    local: SocketAddr,
) -> ConnectionContext {
    // Check cache first (keyed by the full peer socket address, TTL = 30 s)
    const CACHE_TTL_SECS: u64 = 30;
    {
        let cache = runtime.socket_pid_cache.read();
        if let Some((cached_subject, cached_pid, inserted_at)) = cache.get(&peer)
            && inserted_at.elapsed().as_secs() < CACHE_TTL_SECS
        {
            return ConnectionContext {
                peer,
                peer_pid: *cached_pid,
                subject: cached_subject.clone(),
            };
        }
    }

    let daemon = Arc::clone(&runtime.daemon);
    let (peer_pid, subject) = tokio::task::spawn_blocking(move || {
        let pid = socket_owner_pid(peer, local);
        let subject = pid.and_then(|pid| daemon.resolve_proxy_subject_for_pid(pid));
        (pid, subject)
    })
    .await
    .unwrap_or((None, None));

    // Populate cache; evict all expired entries when cache grows large
    {
        let mut cache = runtime.socket_pid_cache.write();
        if cache.len() >= 10_000 {
            let now = Instant::now();
            cache.retain(|_, (_, _, t)| now.duration_since(*t).as_secs() < CACHE_TTL_SECS);
        }
        cache.insert(peer, (subject.clone(), peer_pid, Instant::now()));
    }

    ConnectionContext {
        peer,
        peer_pid,
        subject,
    }
}

/// Pid of the process owning the client end of a loopback connection from
/// `peer` to the gateway's `local` address.
fn socket_owner_pid(peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    if !peer.ip().to_canonical().is_loopback() {
        return None;
    }

    #[cfg(unix)]
    {
        // The client socket's local address is `peer`, its remote `local`.
        let inode = match (peer, local) {
            (SocketAddr::V4(peer), SocketAddr::V4(local)) => find_tcp_inode(
                "/proc/net/tcp",
                &ipv4_to_proc_hex(*peer.ip()),
                peer.port(),
                &ipv4_to_proc_hex(*local.ip()),
                local.port(),
            ),
            _ => find_tcp_inode(
                "/proc/net/tcp6",
                &ipv6_to_proc_hex(as_ipv6(peer.ip())),
                peer.port(),
                &ipv6_to_proc_hex(as_ipv6(local.ip())),
                local.port(),
            ),
        }?;
        find_pid_by_socket_inode(inode)
    }
}

/// IPv4 addresses appear v4-mapped in `/proc/net/tcp6`.
fn as_ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    }
}

#[cfg(unix)]
fn find_tcp_inode(
    table: &str,
    local_hex: &str,
    local_port: u16,
    remote_hex: &str,
    remote_port: u16,
) -> Option<u64> {
    let contents = fs::read_to_string(table).ok()?;
    let expected_local = format!("{local_hex}:{local_port:04X}");
    let expected_remote = format!("{remote_hex}:{remote_port:04X}");

    for line in contents.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let local = cols[1];
        let remote = cols[2];
        let state = cols[3];
        let inode = cols[9];

        if (state == "01" || state == "02")
            && local == expected_local
            && remote == expected_remote
            && let Ok(parsed) = inode.parse::<u64>()
        {
            return Some(parsed);
        }
    }

    None
}

/// The kernel prints each 32-bit word of an address as a native-endian
/// integer in hex.
#[cfg(unix)]
fn ipv4_to_proc_hex(ip: Ipv4Addr) -> String {
    let raw = u32::from_ne_bytes(ip.octets());
    format!("{raw:08X}")
}

#[cfg(unix)]
fn ipv6_to_proc_hex(ip: Ipv6Addr) -> String {
    ip.octets()
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| format!("{:08X}", u32::from_ne_bytes(*word)))
        .collect()
}

#[cfg(unix)]
fn find_pid_by_socket_inode(inode: u64) -> Option<u32> {
    let needle = format!("socket:[{inode}]");
    let proc_entries = fs::read_dir("/proc").ok()?;

    for entry in proc_entries.flatten() {
        let pid_name = entry.file_name();
        let pid_str = pid_name.to_string_lossy();
        if !pid_str.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }

        let pid = match pid_str.parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        let fd_dir = entry.path().join("fd");
        let fds = match fs::read_dir(fd_dir) {
            Ok(fds) => fds,
            Err(_) => continue,
        };

        for fd_entry in fds.flatten() {
            let target = match fs::read_link(fd_entry.path()) {
                Ok(target) => target,
                Err(_) => continue,
            };
            if target.to_string_lossy() == needle {
                return Some(pid);
            }
        }
    }

    None
}

fn prepare_ca(config: &UrlGatewayConfig) -> Result<CaState, String> {
    let cert_path = Path::new(config.ca_cert_file.as_str());
    let key_path = Path::new(config.ca_key_file.as_str());

    let signer = if cert_path.is_file() && key_path.is_file() {
        // Reuse the on-disk pair across restarts so clients that already
        // trust the CA stay valid. Falling back to regen on a parse error
        // would silently invalidate that trust, so surface it instead.
        match load_ca_material(cert_path, key_path) {
            Ok(signer) => {
                info!(
                    cert_path = %cert_path.display(),
                    key_path = %key_path.display(),
                    "loaded existing URL gateway CA",
                );
                signer
            }
            Err(err) => {
                return Err(format!(
                    "load existing URL gateway CA from {} / {}: {err}",
                    cert_path.display(),
                    key_path.display(),
                ));
            }
        }
    } else if config.auto_generate_ca {
        info!(
            cert_path = %cert_path.display(),
            key_path = %key_path.display(),
            "generating new URL gateway CA",
        );
        generate_ca_material(cert_path, key_path)?
    } else {
        return Err(format!(
            "url gateway CA missing at {} / {} and auto_generate_ca=false",
            cert_path.display(),
            key_path.display(),
        ));
    };

    Ok(CaState {
        signer: Arc::new(Mutex::new(signer)),
        leaf_cache: Arc::new(RwLock::new(HashMap::new())),
    })
}

fn load_ca_material(cert_path: &Path, key_path: &Path) -> Result<CaSigner, String> {
    let cert_pem = fs::read_to_string(cert_path)
        .map_err(|err| format!("read CA cert {}: {err}", cert_path.display()))?;
    let key_pem = fs::read_to_string(key_path)
        .map_err(|err| format!("read CA key {}: {err}", key_path.display()))?;
    let key_pair = KeyPair::from_pem(&key_pem)
        .map_err(|err| format!("parse CA key {}: {err}", key_path.display()))?;
    let params = CertificateParams::from_ca_cert_pem(&cert_pem)
        .map_err(|err| format!("parse CA cert {}: {err}", cert_path.display()))?;
    // self_signed reconstructs an in-memory Certificate matching the on-disk
    // CA's distinguished name and public key (same key_pair). Leaves we sign
    // with this signer chain to the on-disk CA that clients already trust.
    let cert = params
        .self_signed(&key_pair)
        .map_err(|err| format!("rebuild CA certificate from disk: {err}"))?;
    Ok(CaSigner { cert, key_pair })
}

fn generate_ca_material(cert_path: &Path, key_path: &Path) -> Result<CaSigner, String> {
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create CA cert dir {}: {err}", parent.display()))?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create CA key dir {}: {err}", parent.display()))?;
    }

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|err| format!("create CA certificate params: {err}"))?;
    params.distinguished_name.push(
        DnType::CommonName,
        "Mercury URL Gateway Root CA".to_string(),
    );
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let key_pair = KeyPair::generate().map_err(|err| format!("generate CA keypair: {err}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|err| format!("self-sign CA certificate: {err}"))?;

    fs::write(cert_path, cert.pem())
        .map_err(|err| format!("write CA cert {}: {err}", cert_path.display()))?;
    #[cfg(unix)]
    fs::set_permissions(cert_path, fs::Permissions::from_mode(0o644))
        .map_err(|err| format!("set permissions on CA cert {}: {err}", cert_path.display()))?;

    fs::write(key_path, key_pair.serialize_pem())
        .map_err(|err| format!("write CA key {}: {err}", key_path.display()))?;
    #[cfg(unix)]
    fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("set permissions on CA key {}: {err}", key_path.display()))?;

    Ok(CaSigner { cert, key_pair })
}

impl CaState {
    async fn server_config_for_host(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        if let Some(config) = self.leaf_cache.read().get(host).cloned() {
            return Ok(config);
        }

        let config = {
            let signer = self.signer.lock().await;
            let leaf_key =
                KeyPair::generate().map_err(|err| format!("generate leaf keypair: {err}"))?;
            let mut params = CertificateParams::new(vec![host.to_string()])
                .map_err(|err| format!("create leaf cert params for host '{}': {err}", host))?;
            params
                .distinguished_name
                .push(DnType::CommonName, host.to_string());
            let leaf_cert = params
                .signed_by(&leaf_key, &signer.cert, &signer.key_pair)
                .map_err(|err| format!("sign leaf cert for host '{}': {err}", host))?;

            let cert_chain = vec![CertificateDer::from(leaf_cert.der().to_vec())];
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
            let mut config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, key)
                .map_err(|err| format!("build TLS server config for host '{}': {err}", host))?;
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        };

        let mut cache = self.leaf_cache.write();
        if cache.len() >= 512 {
            cache.clear();
        }
        cache.insert(host.to_string(), Arc::clone(&config));
        Ok(config)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::Path;
    use tempfile::tempdir;

    use crate::{DaemonConfig, dashboard::DashboardConfig};
    use kernel_runtime::KernelRuntimeConfig;

    use super::*;

    #[test]
    fn parse_authority_handles_port_and_default() {
        assert_eq!(
            parse_authority("example.com:9443", 443),
            Some(("example.com".to_string(), 9443))
        );
        assert_eq!(
            parse_authority("example.com", 443),
            Some(("example.com".to_string(), 443))
        );
    }

    #[test]
    fn request_url_requires_host_for_relative_uri() {
        let request = Request::builder()
            .uri("/api/v1/status")
            .body(())
            .expect("build request");
        let err = request_url(&request, "http").expect_err("missing host should fail");
        assert!(err.contains("missing host"));
    }

    #[test]
    fn request_url_builds_absolute_url_from_host_header() {
        let request = Request::builder()
            .uri("/api/v1/status?verbose=1")
            .header(HOST, "example.com")
            .body(())
            .expect("build request");
        let parsed = request_url(&request, "http").expect("request url");
        assert_eq!(
            parsed.as_str(),
            "http://example.com/api/v1/status?verbose=1"
        );
    }

    #[test]
    fn subject_is_required_for_proxy_paths() {
        let token = parse_proxy_auth_token("Basic YWktZ3VhcmQ6dG9rZW4=");
        assert_eq!(token.as_deref(), Some("token"));
        assert!(parse_proxy_auth_token("Bearer token-2").is_some());
        assert!(parse_proxy_auth_token("Digest something").is_none());
        assert!(parse_proxy_auth_token("Basic not-base64").is_none());
    }

    #[test]
    fn hop_by_hop_headers_are_filtered() {
        assert!(should_skip_request_header(&HeaderName::from_static(
            "connection"
        )));
        assert!(should_skip_request_header(&HeaderName::from_static(
            "proxy-authorization"
        )));
        assert!(should_skip_response_header(&HeaderName::from_static(
            "transfer-encoding"
        )));
        assert!(!should_skip_request_header(&HeaderName::from_static(
            "x-request-id"
        )));
        assert!(!should_skip_response_header(&HeaderName::from_static(
            "x-response-id"
        )));
    }

    #[test]
    fn evaluate_decision_prefers_url_deny_over_allow() {
        let tmp = tempdir().expect("tempdir");
        let daemon = test_daemon(tmp.path());

        let policy = r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    url_allow:
      - id: allow_docs
        scheme: https
        host_glob: docs.example.com
        path_glob: /v1/**
    url_deny:
      - id: deny_admin
        scheme: https
        host_glob: docs.example.com
        path_glob: /v1/admin/**
"#;
        let reload = daemon.apply_policy_from_yaml(policy);
        assert!(reload.success, "policy should load: {:?}", reload.errors);

        let subject = ProxySubject {
            agent_id: "agent-1".to_string(),
            profile: "default".to_string(),
            pid: 123,
            ppid: 1,
            uid: 1000,
            cgroup_id: "ai-test".to_string(),
        };
        let evaluate = |url: &str| {
            let url = reqwest::Url::parse(url).expect("url parse");
            let resource = network_resource_from_url(&Method::GET, &url);
            daemon.evaluate_proxy_request(&subject, 123, 1, resource).0
        };
        let denied = evaluate("https://docs.example.com/v1/admin/keys");
        assert_eq!(denied.decision, Decision::Deny);
        assert_eq!(denied.rule_id.as_deref(), Some("deny_admin"));

        let allowed = evaluate("https://docs.example.com/v1/reference");
        assert_eq!(allowed.decision, Decision::Allow);
    }

    fn test_daemon(root: &Path) -> GuardDaemon {
        let config = DaemonConfig {
            socket_path: root.join("mercuryd.sock").to_string_lossy().to_string(),
            policy_path: root.join("policy.yaml").to_string_lossy().to_string(),
            audit_jsonl_path: root.join("audit.jsonl").to_string_lossy().to_string(),
            audit_integrity: false,
            enrollment_state_path: root.join("enrollments.json").to_string_lossy().to_string(),
            mirror_to_journald: false,
            cgroup_base: root.join("cgroup").to_string_lossy().to_string(),
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

        GuardDaemon::new(config).expect("create daemon")
    }

    const ALLOW_ALL_POLICY: &str =
        "version: v1\ndefaults:\n  decision: allow\nprofiles:\n  default: {}\n";

    fn test_subject() -> ProxySubject {
        ProxySubject {
            agent_id: "agent-e2e".to_string(),
            profile: "default".to_string(),
            pid: 4242,
            ppid: 1,
            uid: 1000,
            cgroup_id: "ai-e2e".to_string(),
        }
    }

    struct TestGateway {
        addr: SocketAddr,
        audit_path: std::path::PathBuf,
        runtime: GatewayRuntime,
    }

    fn test_gateway_config(root: &Path, upstream_ca_cert_file: Option<String>) -> UrlGatewayConfig {
        UrlGatewayConfig {
            ca_cert_file: root.join("ca.crt").to_string_lossy().to_string(),
            ca_key_file: root.join("ca.key").to_string_lossy().to_string(),
            request_timeout_ms: 5_000,
            body_idle_timeout_ms: 5_000,
            upstream_ca_cert_file,
            model_traffic: ModelTrafficConfig {
                hosts: vec!["127.0.0.1".to_string()],
                capture: crate::model_capture::CaptureMode::Content,
                request_timeout_ms: 5_000,
                ..ModelTrafficConfig::default()
            },
            ..UrlGatewayConfig::default()
        }
    }

    /// Serve the gateway on an ephemeral port with every connection attributed
    /// to `test_subject()`.
    async fn spawn_test_gateway(
        root: &Path,
        policy: &str,
        config: UrlGatewayConfig,
    ) -> TestGateway {
        let daemon = Arc::new(test_daemon(root));
        let reload = daemon.apply_policy_from_yaml(policy);
        assert!(reload.success, "policy should load: {:?}", reload.errors);

        let runtime = GatewayRuntime {
            daemon,
            http_client: build_http_client(&config).expect("client"),
            upstream_tls: build_upstream_tls(&config).expect("tls"),
            model: Arc::new(ModelTraffic::new(config.model_traffic.clone()).expect("model")),
            ca: prepare_ca(&config).expect("ca"),
            config,
            socket_pid_cache: Arc::new(RwLock::new(HashMap::new())),
            pinned_clients: Arc::new(RwLock::new(HashMap::new())),
            auth_limiter: Arc::new(parking_lot::Mutex::new(AuditRateLimiter::default())),
        };

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind gateway");
        let addr = listener.local_addr().expect("gateway addr");
        let serving = runtime.clone();
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let runtime = serving.clone();
                tokio::spawn(async move {
                    let ctx = ConnectionContext {
                        peer,
                        peer_pid: None,
                        subject: Some(test_subject()),
                    };
                    let _ = handle_connection(runtime, stream, ctx).await;
                });
            }
        });
        TestGateway {
            addr,
            audit_path: root.join("audit.jsonl"),
            runtime,
        }
    }

    /// Capturing model traffic to loopback at content level.
    async fn start_test_gateway(root: &Path) -> (SocketAddr, std::path::PathBuf) {
        start_test_gateway_with(root, None).await
    }

    async fn start_test_gateway_with(
        root: &Path,
        upstream_ca_cert_file: Option<String>,
    ) -> (SocketAddr, std::path::PathBuf) {
        let config = test_gateway_config(root, upstream_ca_cert_file);
        let gateway = spawn_test_gateway(root, ALLOW_ALL_POLICY, config).await;
        (gateway.addr, gateway.audit_path)
    }

    fn audit_events(audit_path: &Path) -> Vec<serde_json::Value> {
        fs::read_to_string(audit_path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .collect()
    }

    /// Wait until at least `expected` audit records match `filter`.
    async fn wait_for_events(
        audit_path: &Path,
        expected: usize,
        filter: impl Fn(&serde_json::Value) -> bool,
    ) -> Vec<serde_json::Value> {
        for _ in 0..150 {
            let events: Vec<_> = audit_events(audit_path)
                .into_iter()
                .filter(|event| filter(event))
                .collect();
            if events.len() >= expected {
                return events;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "expected {expected} matching audit records in {}: {:#?}",
            audit_path.display(),
            audit_events(audit_path)
        );
    }

    fn is_network(event: &serde_json::Value) -> bool {
        event["action_type"] == "NET_CONNECT"
    }

    /// Plain HTTP upstream answering every request with `body`.
    async fn spawn_plain_upstream(body: &'static str) -> SocketAddr {
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let addr = upstream.local_addr().expect("upstream addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = upstream.accept().await {
                tokio::spawn(async move {
                    let service = service_fn(move |_req: Request<Incoming>| async move {
                        Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(body))))
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        addr
    }

    fn proxied_client(gateway: SocketAddr) -> Client {
        Client::builder()
            .proxy(reqwest::Proxy::http(format!("http://{gateway}")).unwrap())
            .build()
            .unwrap()
    }

    async fn model_events(audit_path: &Path, expected: usize) -> Vec<serde_json::Value> {
        for _ in 0..100 {
            let events: Vec<serde_json::Value> = fs::read_to_string(audit_path)
                .unwrap_or_default()
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .filter(|event| event.get("model").is_some())
                .collect();
            if events.len() >= expected {
                return events;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "expected {expected} model audit events in {}",
            audit_path.display()
        );
    }

    #[tokio::test]
    async fn streams_sse_through_the_gateway_and_audits_the_model_call() {
        let tmp = tempdir().expect("tempdir");
        let (gateway, audit_path) = start_test_gateway(tmp.path()).await;

        // Upstream: two SSE events separated by a pause longer than the
        // client's first-chunk deadline, so buffering would fail the test.
        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream addr");
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<Option<String>>();
        let seen_tx = Arc::new(std::sync::Mutex::new(Some(seen_tx)));
        tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.expect("accept");
            let service = service_fn(move |req: Request<Incoming>| {
                let seen_tx = Arc::clone(&seen_tx);
                async move {
                    let encoding = req
                        .headers()
                        .get(ACCEPT_ENCODING)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    if let Some(tx) = seen_tx.lock().unwrap().take() {
                        let _ = tx.send(encoding);
                    }
                    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(4);
                    tokio::spawn(async move {
                        let first = "data: {\"model\":\"gpt-e2e\",\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n";
                        let second = concat!(
                            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}],",
                            "\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\n",
                            "data: [DONE]\n\n"
                        );
                        let _ = tx.send(Ok(Frame::data(Bytes::from(first)))).await;
                        tokio::time::sleep(Duration::from_millis(1_500)).await;
                        let _ = tx.send(Ok(Frame::data(Bytes::from(second)))).await;
                    });
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .header(CONTENT_TYPE, "text/event-stream")
                            .body(StreamBody::new(ReceiverStream::new(rx)))
                            .unwrap(),
                    )
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });

        let client = Client::builder()
            .proxy(reqwest::Proxy::http(format!("http://{gateway}")).unwrap())
            .build()
            .unwrap();
        let started = Instant::now();
        let mut response = client
            .post(format!("http://{upstream_addr}/v1/chat/completions"))
            .header(ACCEPT_ENCODING, "gzip, br")
            .header("authorization", "Bearer sk-live-should-never-be-logged-0123456789")
            .body(r#"{"model":"gpt-e2e","stream":true,"messages":[{"role":"user","content":"say hello"}],"tools":[{"type":"function","function":{"name":"shell"}}]}"#)
            .send()
            .await
            .expect("send through gateway");
        assert_eq!(response.status(), StatusCode::OK);

        let first = tokio::time::timeout(Duration::from_millis(1_000), response.chunk())
            .await
            .expect("first SSE chunk must arrive before the upstream finishes")
            .expect("chunk")
            .expect("some bytes");
        assert!(started.elapsed() < Duration::from_millis(1_400));
        assert!(String::from_utf8_lossy(&first).contains("Hel"));
        let mut rest = Vec::new();
        while let Some(chunk) = response.chunk().await.expect("chunk") {
            rest.extend_from_slice(&chunk);
        }
        assert!(String::from_utf8_lossy(&rest).contains("[DONE]"));
        assert_eq!(seen_rx.await.unwrap().as_deref(), Some("identity"));

        let events = model_events(&audit_path, 1).await;
        let model = &events[0]["model"];
        assert_eq!(model["api"], "openai.chat_completions");
        assert_eq!(model["transport"], "sse");
        assert_eq!(model["model"], "gpt-e2e");
        assert_eq!(model["output_text"], "Hello");
        assert_eq!(model["finish_reason"], "stop");
        assert_eq!(model["usage"]["output_tokens"], 2);
        assert_eq!(model["tools_offered"][0], "shell");
        assert_eq!(model["messages"][0]["text"], "say hello");
        assert_eq!(events[0]["agent_id"], "agent-e2e");
        let raw = fs::read_to_string(&audit_path).unwrap();
        assert!(!raw.contains("should-never-be-logged"));

        // The model call is the request's outcome record, joined to the
        // decision record by correlation id.
        assert_eq!(events[0]["outcome"]["status"], 200);
        assert_eq!(events[0]["source"], "url-gateway");
        let correlation = events[0]["correlation_id"]
            .as_str()
            .expect("correlation id");
        let decisions = wait_for_events(&audit_path, 1, |e| {
            is_network(e) && e.get("outcome").is_none()
        })
        .await;
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0]["correlation_id"], correlation);
        let outcomes = audit_events(&audit_path)
            .into_iter()
            .filter(|e| is_network(e) && e.get("outcome").is_some())
            .count();
        assert_eq!(outcomes, 1, "one record per model call");
    }

    fn masked_text_frame(payload: &[u8]) -> Vec<u8> {
        let key = [7u8, 1, 9, 3];
        let mut frame = vec![0x81];
        if payload.len() < 126 {
            frame.push(0x80 | payload.len() as u8);
        } else {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(&key);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        frame
    }

    fn text_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x81];
        if payload.len() < 126 {
            frame.push(payload.len() as u8);
        } else {
            frame.push(126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        frame
    }

    async fn read_until(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(needle.len()).any(|w| w == needle) {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
                .await
                .expect("read timeout")
                .expect("read");
            assert!(
                n > 0,
                "unexpected EOF; got {:?}",
                String::from_utf8_lossy(&buf)
            );
            buf.extend_from_slice(&chunk[..n]);
        }
        buf
    }

    #[tokio::test]
    async fn relays_websocket_and_audits_responses_calls() {
        let tmp = tempdir().expect("tempdir");
        let (gateway, audit_path) = start_test_gateway(tmp.path()).await;

        let server_events = [
            text_frame(br#"{"type":"response.output_text.delta","delta":"Hi"}"#),
            text_frame(br#"{"type":"response.completed","response":{"model":"gpt-ws","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"Hi there"}]}],"usage":{"input_tokens":4,"output_tokens":2}}}"#),
        ]
        .concat();

        let upstream = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = upstream.local_addr().expect("upstream addr");
        let (head_tx, head_rx) = tokio::sync::oneshot::channel::<String>();
        let upstream_events = server_events.clone();
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("accept");
            let head = read_until(&mut stream, b"\r\n\r\n").await;
            let _ = head_tx.send(String::from_utf8_lossy(&head).into_owned());
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n")
                .await
                .unwrap();
            // Wait for the client's response.create frame, then answer.
            let mut chunk = [0u8; 4096];
            let _ = stream.read(&mut chunk).await.unwrap();
            stream.write_all(&upstream_events).await.unwrap();
            let _ = stream.read(&mut chunk).await;
        });

        let mut client = TcpStream::connect(gateway).await.expect("connect gateway");
        let handshake = format!(
            "GET http://{upstream_addr}/v1/responses HTTP/1.1\r\nHost: {upstream_addr}\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        );
        client.write_all(handshake.as_bytes()).await.unwrap();
        let head = read_until(&mut client, b"\r\n\r\n").await;
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"));

        let upstream_head = head_rx.await.unwrap().to_ascii_lowercase();
        assert!(upstream_head.starts_with("get /v1/responses http/1.1"));
        assert!(upstream_head.contains("sec-websocket-key: dghlihnhbxbszsbub25jzq=="));
        assert!(!upstream_head.contains("permessage-deflate"));

        let request_frame = masked_text_frame(
            br#"{"type":"response.create","model":"gpt-ws","instructions":"be kind","input":"hello ws"}"#,
        );
        client.write_all(&request_frame).await.unwrap();
        let mut received = Vec::new();
        let mut chunk = [0u8; 4096];
        while received.len() < server_events.len() {
            let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut chunk))
                .await
                .expect("read timeout")
                .expect("read");
            assert!(n > 0);
            received.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(received, server_events, "frames must be relayed unchanged");

        let events = model_events(&audit_path, 1).await;
        let model = &events[0]["model"];
        assert_eq!(model["transport"], "websocket");
        assert_eq!(model["api"], "openai.responses");
        assert_eq!(model["model"], "gpt-ws");
        assert_eq!(model["system"], "be kind");
        assert_eq!(model["messages"][0]["text"], "hello ws");
        assert_eq!(model["output_text"], "Hi there");
        assert_eq!(model["usage"]["input_tokens"], 4);

        // Closing the socket writes the connection's outcome, with the bytes
        // relayed in each direction.
        drop(client);
        let outcome = wait_for_events(&audit_path, 1, |e| {
            is_network(e) && e["outcome"]["status"] == 101
        })
        .await;
        assert_eq!(
            outcome[0]["outcome"]["bytes_sent"],
            request_frame.len() as u64
        );
        assert_eq!(
            outcome[0]["outcome"]["bytes_received"],
            server_events.len() as u64
        );
        assert_eq!(outcome[0]["correlation_id"], events[0]["correlation_id"]);
        assert!(outcome[0].get("model").is_none());
    }

    #[tokio::test]
    async fn relays_websocket_inside_intercepted_tls() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tmp = tempdir().expect("tempdir");

        // Upstream TLS origin with its own self-signed cert, trusted by the
        // gateway through upstream_ca_cert_file.
        let upstream_key = KeyPair::generate().unwrap();
        let upstream_cert = CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .self_signed(&upstream_key)
            .unwrap();
        let upstream_ca = tmp.path().join("upstream.crt");
        fs::write(&upstream_ca, upstream_cert.pem()).unwrap();
        let mut server_tls = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(upstream_cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(upstream_key.serialize_der())),
            )
            .unwrap();
        server_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_tls));

        let (gateway, audit_path) =
            start_test_gateway_with(tmp.path(), Some(upstream_ca.to_string_lossy().to_string()))
                .await;

        let completed = text_frame(br#"{"type":"response.completed","response":{"model":"gpt-tls","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1}}}"#);
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_events = completed.clone();
        tokio::spawn(async move {
            let (tcp, _) = upstream.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tls.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                buf.extend_from_slice(&chunk[..n]);
            }
            tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                .await
                .unwrap();
            let _ = tls.read(&mut chunk).await.unwrap();
            tls.write_all(&upstream_events).await.unwrap();
            let _ = tls.read(&mut chunk).await;
        });

        // Client: CONNECT, then TLS to the gateway's minted leaf.
        let mut tcp = TcpStream::connect(gateway).await.unwrap();
        tcp.write_all(format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let head = read_until(&mut tcp, b"\r\n\r\n").await;
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));

        let mut roots = rustls::RootCertStore::empty();
        let gateway_ca = fs::read(tmp.path().join("ca.crt")).unwrap();
        for cert in rustls_pemfile::certs(&mut gateway_ca.as_slice()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut tls = TlsConnector::from(Arc::new(client_tls))
            .connect(
                rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
                tcp,
            )
            .await
            .expect("client trusts the gateway CA");

        tls.write_all(format!(
            "GET /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: a2V5a2V5a2V5a2V5a2V5a2V5\r\n\r\n"
        ).as_bytes())
        .await
        .unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tls.read(&mut chunk).await.unwrap();
            assert!(
                n > 0,
                "EOF during handshake: {:?}",
                String::from_utf8_lossy(&buf)
            );
            buf.extend_from_slice(&chunk[..n]);
        }
        assert!(
            String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 101"),
            "{}",
            String::from_utf8_lossy(&buf)
        );

        tls.write_all(&masked_text_frame(
            br#"{"type":"response.create","model":"gpt-tls","input":"over tls"}"#,
        ))
        .await
        .unwrap();
        let mut received = Vec::new();
        while received.len() < completed.len() {
            let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk))
                .await
                .expect("read timeout")
                .unwrap();
            assert!(n > 0);
            received.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(received, completed);

        let events = model_events(&audit_path, 1).await;
        assert_eq!(events[0]["model"]["transport"], "websocket");
        assert_eq!(events[0]["model"]["model"], "gpt-tls");
        assert_eq!(events[0]["resource"]["scheme"], "https");
    }

    #[test]
    fn stale_proxy_token_is_rejected_when_cgroup_is_empty() {
        let tmp = tempdir().expect("tempdir");
        let daemon = test_daemon(tmp.path());
        let cgroup_id = "ai-token";
        let cgroup_dir = tmp.path().join("cgroup").join(cgroup_id);
        fs::create_dir_all(&cgroup_dir).expect("create cgroup dir");
        fs::write(cgroup_dir.join("cgroup.procs"), "").expect("write empty cgroup");

        daemon.proxy_auth_tokens.write().insert(
            "token-1".to_string(),
            ProxySubject {
                agent_id: "agent-1".to_string(),
                profile: "default".to_string(),
                pid: 123,
                ppid: 1,
                uid: 1000,
                cgroup_id: cgroup_id.to_string(),
            },
        );

        assert!(daemon.resolve_proxy_subject_for_token("token-1").is_none());
        assert!(!daemon.proxy_auth_tokens.read().contains_key("token-1"));
    }

    #[test]
    fn prepare_ca_reuses_existing_pair_across_calls() {
        let tmp = tempdir().expect("tempdir");
        let cert_path = tmp.path().join("ca.crt");
        let key_path = tmp.path().join("ca.key");

        let config = UrlGatewayConfig {
            ca_cert_file: cert_path.to_string_lossy().to_string(),
            ca_key_file: key_path.to_string_lossy().to_string(),
            auto_generate_ca: true,
            ..UrlGatewayConfig::default()
        };

        // First call generates the CA on disk.
        prepare_ca(&config).expect("first prepare_ca");
        let cert_after_first = fs::read_to_string(&cert_path).expect("read cert");
        let key_after_first = fs::read_to_string(&key_path).expect("read key");
        assert!(cert_after_first.contains("BEGIN CERTIFICATE"));
        assert!(key_after_first.contains("PRIVATE KEY"));

        // Second call must NOT rotate the on-disk pair — clients that already
        // trust this CA need it to survive daemon restarts.
        prepare_ca(&config).expect("second prepare_ca");
        let cert_after_second = fs::read_to_string(&cert_path).expect("read cert");
        let key_after_second = fs::read_to_string(&key_path).expect("read key");
        assert_eq!(cert_after_first, cert_after_second, "CA cert was rotated");
        assert_eq!(key_after_first, key_after_second, "CA key was rotated");
    }

    #[test]
    fn prepare_ca_errors_when_pair_missing_and_autogen_disabled() {
        let tmp = tempdir().expect("tempdir");
        let config = UrlGatewayConfig {
            ca_cert_file: tmp.path().join("missing.crt").to_string_lossy().to_string(),
            ca_key_file: tmp.path().join("missing.key").to_string_lossy().to_string(),
            auto_generate_ca: false,
            ..UrlGatewayConfig::default()
        };

        let err = match prepare_ca(&config) {
            Ok(_) => panic!("should fail without autogen"),
            Err(err) => err,
        };
        assert!(
            err.contains("auto_generate_ca=false"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn plain_request_writes_decision_and_outcome_records() {
        let tmp = tempdir().expect("tempdir");
        let (gateway, audit_path) = start_test_gateway(tmp.path()).await;
        let upstream = spawn_plain_upstream("hello world").await;

        let response = proxied_client(gateway)
            .get(format!(
                "http://{upstream}/plain?token=secret-value-123&page=2"
            ))
            .send()
            .await
            .expect("send through gateway");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "hello world");

        let events = wait_for_events(&audit_path, 2, is_network).await;
        let decision = events
            .iter()
            .find(|e| e.get("outcome").is_none())
            .expect("decision record");
        let outcome = events
            .iter()
            .find(|e| e.get("outcome").is_some())
            .expect("outcome record");

        let correlation = decision["correlation_id"].as_str().expect("correlation");
        assert!(!correlation.is_empty());
        assert_eq!(outcome["correlation_id"], correlation);
        assert_eq!(outcome["outcome"]["status"], 200);
        assert_eq!(outcome["outcome"]["bytes_sent"], 0);
        assert_eq!(outcome["outcome"]["bytes_received"], 11);
        assert_eq!(outcome["decision"], decision["decision"]);
        for event in [decision, outcome] {
            assert_eq!(event["source"], "url-gateway");
            assert_eq!(event["pid"], 4242);
            assert_eq!(event["root_pid"], serde_json::Value::Null);
            assert_eq!(event["resource"]["dest_ip"], "127.0.0.1");
            assert_eq!(
                event["resource"]["full_url"],
                format!("http://{upstream}/plain?token=[REDACTED]&page=2")
            );
            assert_eq!(event["resource"]["query"], "token=[REDACTED]&page=2");
        }
        let raw = fs::read_to_string(&audit_path).unwrap();
        assert!(!raw.contains("secret-value-123"));
    }

    #[tokio::test]
    async fn upstream_failure_writes_bad_gateway_outcome() {
        let tmp = tempdir().expect("tempdir");
        let (gateway, audit_path) = start_test_gateway(tmp.path()).await;
        // Nothing listens on the closed port.
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();

        let response = proxied_client(gateway)
            .get(format!("http://{closed}/down"))
            .send()
            .await
            .expect("send through gateway");
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let outcome = wait_for_events(&audit_path, 1, |e| {
            is_network(e) && e.get("outcome").is_some()
        })
        .await;
        assert_eq!(outcome[0]["outcome"]["status"], 502);
        let error = outcome[0]["outcome"]["error"].as_str().expect("error");
        assert!(error.contains("upstream request failed"), "{error}");
        assert_eq!(outcome[0]["decision"], "ALLOW");
    }

    const LOCALHOST_POLICY: &str = r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    url_allow:
      - id: allow_localhost
        host_glob: localhost
        path_glob: /**
    network_deny:
      - id: deny_loopback_v6
        cidr: ::1/128
__EXTRA__
"#;

    #[tokio::test]
    async fn cidr_deny_applies_to_the_resolved_address_of_an_allowed_host() {
        let upstream = spawn_plain_upstream("local").await;
        let url = format!("http://localhost:{}/data", upstream.port());

        // 127.0.0.0/8 denied as well: every address of `localhost` is
        // blocked even though a URL rule allows the host.
        let tmp = tempdir().expect("tempdir");
        let policy = LOCALHOST_POLICY.replace(
            "__EXTRA__",
            "      - id: deny_loopback_v4\n        cidr: 127.0.0.0/8",
        );
        let gateway =
            spawn_test_gateway(tmp.path(), &policy, test_gateway_config(tmp.path(), None)).await;
        let response = proxied_client(gateway.addr).get(&url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let decision = wait_for_events(&gateway.audit_path, 1, is_network).await;
        assert_eq!(decision[0]["decision"], "DENY");
        assert_eq!(decision[0]["reason"], "DENY_BY_RULE");
        let rule = decision[0]["rule_id"].as_str().unwrap();
        assert!(rule.starts_with("deny_loopback"), "{rule}");
        assert!(decision[0]["resource"]["dest_ip"].is_string());
        assert!(
            audit_events(&gateway.audit_path)
                .iter()
                .all(|e| e.get("outcome").is_none()),
            "a denied request has no outcome"
        );

        // Only ::1 denied: the gateway pins the request to 127.0.0.1.
        let tmp = tempdir().expect("tempdir");
        let policy = LOCALHOST_POLICY.replace("__EXTRA__", "");
        let gateway =
            spawn_test_gateway(tmp.path(), &policy, test_gateway_config(tmp.path(), None)).await;
        let response = proxied_client(gateway.addr).get(&url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let decision = wait_for_events(&gateway.audit_path, 1, |e| {
            is_network(e) && e.get("outcome").is_none()
        })
        .await;
        assert_eq!(decision[0]["decision"], "ALLOW");
        assert_eq!(decision[0]["rule_id"], "allow_localhost");
        assert_eq!(decision[0]["resource"]["dest_ip"], "127.0.0.1");
    }

    #[test]
    fn check_upstream_addrs_skips_denied_addresses_and_honours_observe_mode() {
        let tmp = tempdir().expect("tempdir");
        let daemon = test_daemon(tmp.path());
        let policy = |mode: &str| {
            format!(
                "version: v1\ndefaults:\n  decision: allow\nprofiles:\n  default:\n    enforcement:\n      network: {mode}\n    network_deny:\n      - id: deny_metadata\n        cidr: 169.254.0.0/16\n      - id: deny_private_https\n        cidr: 10.0.0.0/8\n        port: 443\n"
            )
        };
        let reload = daemon.apply_policy_from_yaml(&policy("enforce"));
        assert!(reload.success, "{:?}", reload.errors);

        let url = reqwest::Url::parse("https://rebind.example/latest").unwrap();
        let resource = network_resource_from_url(&Method::GET, &url);
        let metadata: SocketAddr = "169.254.169.254:443".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:169.254.169.254]:443".parse().unwrap();
        let public: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let private: SocketAddr = "10.1.2.3:443".parse().unwrap();

        let checked = check_upstream_addrs(&daemon, "default", &resource, &[metadata, public]);
        assert_eq!(checked.addrs, vec![public]);
        assert!(checked.decision.is_none());

        for denied in [metadata, mapped] {
            let checked = check_upstream_addrs(&daemon, "default", &resource, &[denied]);
            assert_eq!(checked.addrs, vec![denied]);
            let decision = checked.decision.expect("denied");
            assert_eq!(decision.decision, Decision::Deny);
            assert_eq!(decision.rule_id.as_deref(), Some("deny_metadata"));
        }

        // Port-scoped rule: only matches the request's port.
        let checked = check_upstream_addrs(&daemon, "default", &resource, &[private]);
        assert_eq!(
            checked.decision.unwrap().rule_id.as_deref(),
            Some("deny_private_https")
        );
        let http = network_resource_from_url(
            &Method::GET,
            &reqwest::Url::parse("http://rebind.example/").unwrap(),
        );
        assert!(
            check_upstream_addrs(&daemon, "default", &http, &[private])
                .decision
                .is_none()
        );

        let reload = daemon.apply_policy_from_yaml(&policy("observe"));
        assert!(reload.success, "{:?}", reload.errors);
        let checked = check_upstream_addrs(&daemon, "default", &resource, &[metadata, public]);
        assert_eq!(
            checked.addrs,
            vec![public],
            "denied addresses are still skipped"
        );
        assert!(checked.decision.is_none());
        let checked = check_upstream_addrs(&daemon, "default", &resource, &[metadata]);
        assert_eq!(checked.addrs, vec![metadata]);
        let decision = checked.decision.unwrap();
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.reason, DecisionReason::AllowByObserveMode);
        assert_eq!(decision.rule_id.as_deref(), Some("deny_metadata"));
    }

    #[tokio::test]
    async fn pinned_upstreams_fall_back_across_permitted_addresses() {
        let tmp = tempdir().expect("tempdir");
        let gateway = spawn_test_gateway(
            tmp.path(),
            ALLOW_ALL_POLICY,
            test_gateway_config(tmp.path(), None),
        )
        .await;
        let live = spawn_plain_upstream("pinned").await;
        let port = live.port();
        // Nothing listens on 127.0.0.2: connecting is refused.
        let dead: SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();

        let client =
            pinned_client(&gateway.runtime, "fallback.test", &[dead, live]).expect("client");
        let body = client
            .get(format!("http://fallback.test:{port}/"))
            .send()
            .await
            .expect("falls back to the live address")
            .text()
            .await
            .unwrap();
        assert_eq!(body, "pinned");
        // The same set in another order reuses the client and its pool.
        pinned_client(&gateway.runtime, "fallback.test", &[live, dead]).expect("client");
        assert_eq!(gateway.runtime.pinned_clients.read().len(), 1);

        let url = reqwest::Url::parse(&format!("http://fallback.test:{port}/")).unwrap();
        assert!(
            connect_upstream(&gateway.runtime, &url, &[dead, live])
                .await
                .is_ok()
        );
        match connect_upstream(&gateway.runtime, &url, &[dead]).await {
            Ok(_) => panic!("nothing listens on {dead}"),
            Err(err) => assert!(err.contains("127.0.0.2"), "{err}"),
        }
    }

    #[tokio::test]
    async fn invalid_proxy_token_is_audited_and_rate_limited() {
        let tmp = tempdir().expect("tempdir");
        let gateway = spawn_test_gateway(
            tmp.path(),
            ALLOW_ALL_POLICY,
            test_gateway_config(tmp.path(), None),
        )
        .await;
        *gateway.runtime.auth_limiter.lock() = AuditRateLimiter::new(2, Duration::from_secs(60));
        let upstream = spawn_plain_upstream("never").await;

        let client = Client::builder()
            .proxy(
                reqwest::Proxy::http(format!("http://{}", gateway.addr))
                    .unwrap()
                    .basic_auth("mercury", "bogus-token-value"),
            )
            .build()
            .unwrap();
        for _ in 0..3 {
            let response = client
                .get(format!("http://{upstream}/x?api_key=leak-me-please"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }

        let is_auth_failure =
            |e: &serde_json::Value| e["resource"]["event"] == "gateway_auth_failure";
        let failures = wait_for_events(&gateway.audit_path, 2, is_auth_failure).await;
        assert_eq!(failures.len(), 2, "third failure is rate-limited");
        let failure = &failures[0];
        assert_eq!(failure["action_type"], "SYSTEM_EVENT");
        assert_eq!(failure["decision"], "DENY");
        assert_eq!(failure["reason"], "DENY_FAIL_CLOSED");
        assert_eq!(failure["source"], "url-gateway");
        assert_eq!(
            failure["resource"]["attributes"]["failure"],
            "invalid_proxy_token"
        );
        assert_eq!(failure["resource"]["attributes"]["token_present"], true);
        assert_eq!(failure["agent_id"], "agent-e2e");

        let closed = gateway
            .runtime
            .auth_limiter
            .lock()
            .flush(Instant::now() + Duration::from_secs(61));
        gateway.runtime.daemon.record_suppressed(closed);
        let summary = wait_for_events(&gateway.audit_path, 3, is_auth_failure).await;
        let summary = summary
            .iter()
            .find(|e| e["resource"]["detail"] == "rate_limited")
            .expect("summary record");
        assert_eq!(summary["resource"]["attributes"]["suppressed"], 1);

        let raw = fs::read_to_string(&gateway.audit_path).unwrap();
        assert!(!raw.contains("bogus-token-value"));
        assert!(!raw.contains("leak-me-please"));
    }

    async fn send_connect(gateway: SocketAddr, authority: &str) -> (TcpStream, String) {
        let mut tcp = TcpStream::connect(gateway).await.unwrap();
        tcp.write_all(
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let head = read_until(&mut tcp, b"\r\n\r\n").await;
        (tcp, String::from_utf8_lossy(&head).into_owned())
    }

    #[tokio::test]
    async fn connect_is_refused_and_audited_when_interception_is_disabled() {
        let tmp = tempdir().expect("tempdir");
        let config = UrlGatewayConfig {
            tls_intercept_enabled: false,
            ..test_gateway_config(tmp.path(), None)
        };
        let gateway = spawn_test_gateway(tmp.path(), ALLOW_ALL_POLICY, config).await;
        let (_tcp, head) = send_connect(gateway.addr, "pinned.example:8443").await;
        assert!(head.starts_with("HTTP/1.1 403"), "{head}");

        let events = wait_for_events(&gateway.audit_path, 1, is_network).await;
        let event = &events[0];
        assert_eq!(event["decision"], "DENY");
        assert_eq!(event["reason"], "DENY_FAIL_CLOSED");
        assert_eq!(event["rule_id"], TLS_INTERCEPT_DISABLED_RULE);
        assert_eq!(event["resource"]["dest_host"], "pinned.example");
        assert_eq!(event["resource"]["dest_port"], 8443);
        assert_eq!(event["resource"]["method"], "CONNECT");
        assert_eq!(event["agent_id"], "agent-e2e");
    }

    #[tokio::test]
    async fn failed_tls_interception_is_audited() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tmp = tempdir().expect("tempdir");
        let gateway = spawn_test_gateway(
            tmp.path(),
            ALLOW_ALL_POLICY,
            test_gateway_config(tmp.path(), None),
        )
        .await;
        let (mut tcp, head) = send_connect(gateway.addr, "127.0.0.1:9").await;
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        // A client that refuses the minted certificate never completes the
        // handshake; plain text fails it just the same.
        tcp.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        drop(tcp);

        let events = wait_for_events(&gateway.audit_path, 1, |e| {
            e["resource"]["event"] == "tls_intercept_failed"
        })
        .await;
        let event = &events[0];
        assert_eq!(event["decision"], "DENY");
        assert_eq!(event["resource"]["attributes"]["host"], "127.0.0.1");
        assert_eq!(event["resource"]["attributes"]["port"], 9);
        assert_eq!(event["resource"]["attributes"]["stage"], "handshake");
        assert_eq!(event["agent_id"], "agent-e2e");
        assert_eq!(event["pid"], 4242);
    }

    #[test]
    fn token_requests_are_attributed_to_the_socket_owner() {
        let tmp = tempdir().expect("tempdir");
        let daemon = test_daemon(tmp.path());
        let agent_id = Uuid::new_v4();
        let parent = Uuid::new_v4();
        daemon.registrations.write().insert(
            100,
            core_types::AgentRegistration {
                agent_id,
                profile: "default".to_string(),
                pid: 100,
                proc_start_time: 0,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                cgroup_id: "ai-test".to_string(),
                cmdline: Vec::new(),
                cwd: "/".to_string(),
                mcp_session_id: None,
                server_id: Some("fs".to_string()),
                client_name: None,
                parent_agent_id: Some(parent),
                resolved_exec_path: None,
            },
        );
        let subject = ProxySubject {
            agent_id: agent_id.to_string(),
            profile: "default".to_string(),
            pid: 100,
            ppid: 1,
            uid: 1000,
            cgroup_id: "ai-test".to_string(),
        };

        let me = std::process::id();
        let identity = RequestIdentity::resolve(&daemon, subject.clone(), Some(me), true);
        assert_eq!(identity.pid, me);
        assert_eq!(Some(identity.ppid), crate::parent_pid_for(me));
        assert_eq!(identity.root_pid, Some(100));
        assert_eq!(identity.parent_agent_id, Some(parent.to_string()));

        // Without a socket owner the registration pid stands in.
        let identity = RequestIdentity::resolve(&daemon, subject.clone(), None, true);
        assert_eq!((identity.pid, identity.ppid), (100, 1));

        // Unregistered token subject: the token's pid is the root.
        let stranger = ProxySubject {
            agent_id: "unregistered".to_string(),
            pid: 200,
            ..subject
        };
        let identity = RequestIdentity::resolve(&daemon, stranger, None, true);
        assert_eq!(identity.root_pid, Some(200));
        assert_eq!(identity.parent_agent_id, None);
    }

    #[test]
    fn socket_owner_pid_finds_this_process_over_ipv4_and_ipv6() {
        let me = std::process::id();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _server = listener.accept().unwrap();
        assert_eq!(
            socket_owner_pid(client.local_addr().unwrap(), listener.local_addr().unwrap()),
            Some(me)
        );

        // IPv6 may be disabled on the host.
        if let Ok(listener) = std::net::TcpListener::bind("[::1]:0") {
            let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let _server = listener.accept().unwrap();
            assert_eq!(
                socket_owner_pid(client.local_addr().unwrap(), listener.local_addr().unwrap()),
                Some(me)
            );
        }

        let remote: SocketAddr = "192.0.2.1:5555".parse().unwrap();
        assert_eq!(
            socket_owner_pid(remote, listener.local_addr().unwrap()),
            None
        );
        assert_eq!(
            ipv6_to_proc_hex(Ipv6Addr::LOCALHOST),
            "00000000000000000000000001000000"
        );
    }
}
