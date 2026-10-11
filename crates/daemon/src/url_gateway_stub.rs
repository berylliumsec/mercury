//! Stub url_gateway module for non-Linux builds.

use serde::Deserialize;

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
        "/etc/mercury/gateway-ca.crt".to_string()
    }
    #[cfg(not(unix))]
    {
        "gateway-ca.crt".to_string()
    }
}
fn default_url_gateway_ca_key_file() -> String {
    #[cfg(unix)]
    {
        "/etc/mercury/gateway-ca.key".to_string()
    }
    #[cfg(not(unix))]
    {
        "gateway-ca.key".to_string()
    }
}
fn default_url_gateway_connect_timeout_ms() -> u64 {
    5000
}
fn default_url_gateway_request_timeout_ms() -> u64 {
    30000
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
    #[serde(default = "default_url_gateway_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default)]
    pub upstream_ca_cert_file: Option<String>,
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
            upstream_ca_cert_file: None,
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
            ca_cert_path: None,
            error: None,
        }
    }
}

pub async fn spawn_url_gateway(_daemon: std::sync::Arc<()>) -> Result<(), String> {
    Err("url gateway is not supported on this platform".to_string())
}
