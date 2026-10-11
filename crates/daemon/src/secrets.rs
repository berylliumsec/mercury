use std::fs;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("systemd-creds failed: {0}")]
    SystemdCreds(String),
    #[error("invalid secret format: {0}")]
    InvalidFormat(String),
}

/// Resolve a secret reference to its value.
///
/// Format in config YAML:
///   - Plain path: "/etc/mercury/policy-signing-key"
///   - Environment variable: "env:MERCURY_SIGNING_KEY"
///   - systemd-creds: "creds:signing-key"
///   - Literal value (for testing): "literal:deadbeef..."
pub fn resolve_secret(reference: &str) -> Result<String, SecretError> {
    if let Some(env_name) = reference.strip_prefix("env:") {
        std::env::var(env_name)
            .map_err(|_| SecretError::NotFound(format!("environment variable {env_name} not set")))
    } else if let Some(cred_name) = reference.strip_prefix("creds:") {
        resolve_systemd_creds(cred_name)
    } else if let Some(literal) = reference.strip_prefix("literal:") {
        Ok(literal.to_string())
    } else {
        // Treat as file path (existing behavior)
        fs::read_to_string(reference)
            .map(|s| s.trim().to_string())
            .map_err(SecretError::Io)
    }
}

fn resolve_systemd_creds(name: &str) -> Result<String, SecretError> {
    // Reject path traversal: credential names must not contain '/', '..', or null bytes.
    if name.contains('/') || name.contains("..") || name.contains('\0') || name.is_empty() {
        return Err(SecretError::InvalidFormat(format!(
            "credential name must not contain '/', '..', or null bytes: {name:?}"
        )));
    }

    let creds_dir = std::env::var("CREDENTIALS_DIRECTORY").map_err(|_| {
        SecretError::NotFound(
            "CREDENTIALS_DIRECTORY not set; not running under systemd with credentials".to_string(),
        )
    })?;

    let path = format!("{creds_dir}/{name}");
    fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .map_err(|e| {
            SecretError::SystemdCreds(format!("failed to read credential {name} from {path}: {e}"))
        })
}

/// Resolve a secret that should be a hex-encoded 32-byte key.
pub fn resolve_hex_key(reference: &str) -> Result<Vec<u8>, SecretError> {
    let raw = resolve_secret(reference)?;
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return Err(SecretError::InvalidFormat(format!(
            "expected 64 hex characters, got {}",
            trimmed.len()
        )));
    }
    hex::decode(trimmed).map_err(|e| SecretError::InvalidFormat(format!("invalid hex: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_literal() {
        let result = resolve_secret("literal:test-value").unwrap();
        assert_eq!(result, "test-value");
    }

    #[test]
    fn resolve_env() {
        // SAFETY: test-only; no concurrent threads depend on this variable.
        unsafe { std::env::set_var("MERCURY_TEST_SECRET_9283", "env-value") };
        let result = resolve_secret("env:MERCURY_TEST_SECRET_9283").unwrap();
        assert_eq!(result, "env-value");
        unsafe { std::env::remove_var("MERCURY_TEST_SECRET_9283") };
    }

    #[test]
    fn resolve_missing_env() {
        let result = resolve_secret("env:MERCURY_NONEXISTENT_SECRET_12345");
        assert!(result.is_err());
    }

    #[test]
    fn resolve_hex_key_valid() {
        let hex_key = "ab".repeat(32);
        let result = resolve_hex_key(&format!("literal:{hex_key}")).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn resolve_hex_key_wrong_length() {
        let result = resolve_hex_key("literal:deadbeef");
        assert!(result.is_err());
    }

    #[test]
    fn creds_rejects_path_traversal() {
        let result = resolve_secret("creds:../../etc/shadow");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("must not contain"),
            "expected path traversal rejection, got: {err}"
        );
    }

    #[test]
    fn creds_rejects_slash() {
        let result = resolve_secret("creds:sub/dir");
        assert!(result.is_err());
    }

    #[test]
    fn creds_rejects_empty() {
        let result = resolve_secret("creds:");
        assert!(result.is_err());
    }
}
