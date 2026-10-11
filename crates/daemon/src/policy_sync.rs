use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::info;

/// Default poll interval: 5 minutes.
fn default_policy_sync_interval() -> u64 {
    300
}

fn default_true_bool() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicySyncConfig {
    /// URL to fetch policy from (https:// required)
    pub url: String,
    /// Poll interval in seconds. Default: 300 (5 minutes)
    #[serde(default = "default_policy_sync_interval")]
    pub interval_secs: u64,
    /// Optional bearer token for authentication
    #[serde(default)]
    pub bearer_token: Option<String>,
    /// Path to bearer token file (alternative to inline token)
    #[serde(default)]
    pub bearer_token_file: Option<String>,
    /// Optional CA cert path for custom TLS
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    /// If true, verify HMAC signature on fetched policy (uses daemon's signing key)
    #[serde(default = "default_true_bool")]
    pub verify_signature: bool,
}

#[derive(Debug, Error)]
pub enum PolicySyncError {
    #[error("http request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url must use https scheme: {0}")]
    InsecureUrl(String),
    #[error("server returned {0}: {1}")]
    ServerError(u16, String),
    #[error("failed to write policy file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to read bearer token file: {0}")]
    TokenFileRead(String),
    #[error("failed to load CA certificate: {0}")]
    CaCert(String),
}

/// Tracks the last check time and error for health reporting.
#[derive(Debug, Clone, Default)]
pub struct PolicySyncStatus {
    pub enabled: bool,
    pub last_check: Option<String>,
    pub last_error: Option<String>,
}

pub struct PolicySyncWorker {
    config: PolicySyncConfig,
    policy_path: PathBuf,
    last_etag: Mutex<Option<String>>,
    last_hash: Mutex<Option<String>>,
    status: Arc<Mutex<PolicySyncStatus>>,
}

impl PolicySyncWorker {
    pub fn new(
        config: PolicySyncConfig,
        policy_path: PathBuf,
        status: Arc<Mutex<PolicySyncStatus>>,
    ) -> Self {
        Self {
            config,
            policy_path,
            last_etag: Mutex::new(None),
            last_hash: Mutex::new(None),
            status,
        }
    }

    /// Check for policy updates. Returns Ok(true) if policy was updated.
    pub async fn check_and_update(&self) -> Result<bool, PolicySyncError> {
        if !self.config.url.starts_with("https://") {
            return Err(PolicySyncError::InsecureUrl(self.config.url.clone()));
        }

        let mut client_builder = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(std::time::Duration::from_secs(30));

        if let Some(ref ca_path) = self.config.ca_cert_path {
            let pem = std::fs::read(ca_path)
                .map_err(|e| PolicySyncError::CaCert(format!("{ca_path}: {e}")))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| PolicySyncError::CaCert(format!("parse {ca_path}: {e}")))?;
            client_builder = client_builder.add_root_certificate(cert);
        }

        let client = client_builder.build()?;

        let mut request = client.get(&self.config.url);

        // Add bearer token if configured
        let token = self.resolve_bearer_token()?;
        if let Some(ref token) = token {
            request = request.bearer_auth(token);
        }

        // Add If-None-Match header if we have a previous ETag
        {
            let etag = self.last_etag.lock();
            if let Some(ref etag_value) = *etag {
                request = request.header("If-None-Match", etag_value.as_str());
            }
        }

        let response = request.send().await?;
        let status_code = response.status().as_u16();

        // Update check timestamp
        {
            let now = chrono::Utc::now().to_rfc3339();
            self.status.lock().last_check = Some(now);
        }

        if status_code == 304 {
            info!("policy sync: remote policy unchanged (304 Not Modified)");
            return Ok(false);
        }

        if !response.status().is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_string());
            return Err(PolicySyncError::ServerError(status_code, body));
        }

        // Store ETag from response if present
        let new_etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let body = response.bytes().await?;

        // Compare SHA-256 hash
        let new_hash = hex::encode(Sha256::digest(&body));
        {
            let last_hash = self.last_hash.lock();
            if last_hash.as_deref() == Some(new_hash.as_str()) {
                info!("policy sync: remote policy content unchanged (same hash)");
                if let Some(etag) = new_etag {
                    *self.last_etag.lock() = Some(etag);
                }
                return Ok(false);
            }
        }

        // Content has changed — write atomically via tmp + rename
        let tmp_path = self.policy_path.with_extension("sync.tmp");
        std::fs::write(&tmp_path, &body)?;
        std::fs::rename(&tmp_path, &self.policy_path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            PolicySyncError::Io(e)
        })?;

        info!(
            hash = %new_hash,
            "policy sync: fetched updated policy from remote"
        );

        // Update cached state
        *self.last_hash.lock() = Some(new_hash);
        if let Some(etag) = new_etag {
            *self.last_etag.lock() = Some(etag);
        }

        Ok(true)
    }

    fn resolve_bearer_token(&self) -> Result<Option<String>, PolicySyncError> {
        if let Some(ref token) = self.config.bearer_token {
            return Ok(Some(token.clone()));
        }
        if let Some(ref path) = self.config.bearer_token_file {
            let token = std::fs::read_to_string(path)
                .map_err(|e| PolicySyncError::TokenFileRead(format!("{path}: {e}")))?;
            return Ok(Some(token.trim().to_string()));
        }
        Ok(None)
    }
}
