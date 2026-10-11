use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, anyhow};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use control_api::{
    ControlRequest, ControlResponse, PolicyReloadRequest, SOCKET_PATH, TestDecisionRequest,
};
use core_types::{
    Action, ActionContext, ActionType, ExecResource, FileOp, FileResource, McpToolResource,
    McpTransport, NetworkProtocol, NetworkResource, Resource,
};
use hmac::{Hmac, Mac};
use policy_engine::{SignatureVerification, load_policy_from_path};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
#[command(name = "mercury-policy")]
#[command(about = "Policy management CLI for mercury")]
struct Args {
    #[arg(long, default_value = SOCKET_PATH, global = true)]
    socket: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Validate {
        #[arg(long)]
        file: String,
        #[arg(long, default_value = "warn")]
        signature: SignatureMode,
        /// Path to hex-encoded HMAC-SHA256 signing key (required when --signature=require)
        #[arg(long)]
        key_file: Option<String>,
    },
    /// Sign a policy file and write a `signature:` block to it (or stdout)
    Sign {
        #[arg(long)]
        file: String,
        #[arg(long)]
        key_file: String,
        /// Identifier recorded in the signature block (e.g. "prod-key-2025")
        #[arg(long, default_value = "default")]
        key_id: String,
        /// Write signed YAML to this path instead of modifying the input file in-place
        #[arg(long)]
        output: Option<String>,
    },
    /// Generate a new 32-byte random HMAC-SHA256 key and write it (hex) to a file
    GenerateSigningKey {
        #[arg(long, default_value = "/etc/mercury/policy-signing-key")]
        key_file: String,
    },
    Reload {
        #[arg(long)]
        file: String,
    },
    Test {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        action: ActionArg,
        #[arg(long)]
        path: Option<String>,
        #[arg(long, default_value = "/")]
        cwd: String,
        #[arg(long)]
        dest_host: Option<String>,
        #[arg(long)]
        dest_ip: Option<String>,
        #[arg(long)]
        dest_port: Option<u16>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        protocol: Option<ProtocolArg>,
        #[arg(long)]
        mcp_server: Option<String>,
        #[arg(long)]
        mcp_tool: Option<String>,
        #[arg(long)]
        mcp_tool_call_id: Option<String>,
        #[arg(long)]
        mcp_session_id: Option<String>,
        #[arg(long)]
        arguments_json: Option<String>,
    },
    DashboardToken {
        #[command(subcommand)]
        command: DashboardTokenCommand,
    },
    DashboardPassword {
        #[command(subcommand)]
        command: DashboardPasswordCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DashboardTokenCommand {
    Rotate {
        #[arg(long, default_value = "/etc/mercury/dashboard.password")]
        file: String,
        #[arg(long, default_value = "admin")]
        username: String,
        #[arg(long, default_value_t = 32)]
        bytes: usize,
    },
}

#[derive(Debug, Subcommand)]
enum DashboardPasswordCommand {
    Rotate {
        #[arg(long, default_value = "/etc/mercury/dashboard.password")]
        file: String,
        #[arg(long, default_value = "admin")]
        username: String,
        #[arg(long, default_value_t = 32)]
        bytes: usize,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SignatureMode {
    Disabled,
    Warn,
    Require,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ActionArg {
    FileRead,
    FileWrite,
    FileDelete,
    ProcExec,
    NetConnect,
    McpToolCall,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProtocolArg {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
struct ActionBuildInput {
    action: ActionArg,
    path: Option<String>,
    cwd: String,
    dest_host: Option<String>,
    dest_ip: Option<String>,
    dest_port: Option<u16>,
    url: Option<String>,
    method: Option<String>,
    protocol: Option<ProtocolArg>,
    mcp_server: Option<String>,
    mcp_tool: Option<String>,
    mcp_tool_call_id: Option<String>,
    mcp_session_id: Option<String>,
    arguments_json: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(err) = run(args).await {
        eprintln!("mercury-policy failed: {err:#}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Validate {
            file,
            signature,
            key_file,
        } => {
            let mode = match signature {
                SignatureMode::Disabled => SignatureVerification::Disabled,
                SignatureMode::Warn => SignatureVerification::WarnOnInvalid,
                SignatureMode::Require => {
                    let path = key_file.ok_or_else(|| {
                        anyhow!("--key-file is required when --signature=require")
                    })?;
                    let hex = fs::read_to_string(&path)
                        .with_context(|| format!("read key file {path}"))?;
                    let hmac_key = hex::decode(hex.trim())
                        .with_context(|| "key file must contain hex-encoded bytes")?;
                    SignatureVerification::RequireValid { hmac_key }
                }
            };

            let loaded = load_policy_from_path(&file, mode)
                .with_context(|| format!("validate policy file {file}"))?;
            println!("policy valid: version={}", loaded.compiled.version);
            if !loaded.warnings.is_empty() {
                for warning in loaded.warnings {
                    println!("warning: {warning}");
                }
            }
            Ok(())
        }
        Command::Sign {
            file,
            key_file,
            key_id,
            output,
        } => {
            let raw =
                fs::read_to_string(&file).with_context(|| format!("read policy file {file}"))?;
            let key_hex = fs::read_to_string(&key_file)
                .with_context(|| format!("read key file {key_file}"))?;
            let hmac_key = hex::decode(key_hex.trim())
                .with_context(|| "key file must contain hex-encoded bytes")?;
            // Strip any existing signature block, compute HMAC over canonical YAML
            let mut doc: serde_yaml::Value =
                serde_yaml::from_str(&raw).with_context(|| "parse policy YAML")?;
            if let Some(map) = doc.as_mapping_mut() {
                map.remove("signature");
            }
            let canonical =
                serde_yaml::to_string(&doc).with_context(|| "serialize canonical YAML")?;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
                .map_err(|e| anyhow!("invalid key: {e}"))?;
            mac.update(canonical.as_bytes());
            let sig_hex = hex::encode(mac.finalize().into_bytes());
            // Insert signature block into the mapping
            if let Some(map) = doc.as_mapping_mut() {
                map.insert(
                    serde_yaml::Value::String("signature".to_string()),
                    serde_yaml::Value::Mapping({
                        let mut m = serde_yaml::Mapping::new();
                        m.insert(
                            serde_yaml::Value::String("key_id".to_string()),
                            serde_yaml::Value::String(key_id.clone()),
                        );
                        m.insert(
                            serde_yaml::Value::String("alg".to_string()),
                            serde_yaml::Value::String("hmac-sha256".to_string()),
                        );
                        m.insert(
                            serde_yaml::Value::String("sig".to_string()),
                            serde_yaml::Value::String(sig_hex),
                        );
                        m
                    }),
                );
            }
            let signed_yaml =
                serde_yaml::to_string(&doc).with_context(|| "serialize signed YAML")?;
            let dest = output.as_deref().unwrap_or(&file);
            fs::write(dest, &signed_yaml)
                .with_context(|| format!("write signed policy to {dest}"))?;
            println!("signed policy written to {dest}");
            Ok(())
        }
        Command::GenerateSigningKey { key_file } => {
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            let hex_key = hex::encode(bytes);
            let path = Path::new(&key_file);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create directory {}", parent.display()))?;
            }
            fs::write(path, format!("{hex_key}\n"))
                .with_context(|| format!("write key to {key_file}"))?;
            // Restrict permissions to owner-read-only
            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .with_context(|| "set key file permissions")?;
            println!("signing key written to {key_file} (keep this secret)");
            Ok(())
        }
        Command::Reload { file } => {
            let request = ControlRequest::PolicyReload(PolicyReloadRequest { path: file });
            let response = cli::send_request(&args.socket, &request).await?;
            match response {
                ControlResponse::PolicyReload(payload) => {
                    println!(
                        "reload success={} version={} errors={}",
                        payload.success,
                        payload.version,
                        payload.errors.join(" | ")
                    );
                    if payload.success {
                        Ok(())
                    } else {
                        Err(anyhow!("policy reload failed"))
                    }
                }
                ControlResponse::Error(err) => {
                    Err(anyhow!("reload rejected: {}: {}", err.code, err.message))
                }
                other => Err(anyhow!("unexpected response: {other:?}")),
            }
        }
        Command::Test {
            profile,
            action,
            path,
            cwd,
            dest_host,
            dest_ip,
            dest_port,
            url,
            method,
            protocol,
            mcp_server,
            mcp_tool,
            mcp_tool_call_id,
            mcp_session_id,
            arguments_json,
        } => {
            let action = build_action(
                &profile,
                ActionBuildInput {
                    action,
                    path,
                    cwd,
                    dest_host,
                    dest_ip,
                    dest_port,
                    url,
                    method,
                    protocol,
                    mcp_server,
                    mcp_tool,
                    mcp_tool_call_id,
                    mcp_session_id,
                    arguments_json,
                },
            )?;

            let request = ControlRequest::TestDecision(TestDecisionRequest { profile, action });
            let response = cli::send_request(&args.socket, &request).await?;
            match response {
                ControlResponse::TestDecision(result) => {
                    println!(
                        "decision={:?} reason={:?} rule_id={:?}",
                        result.decision, result.reason, result.rule_id
                    );
                    Ok(())
                }
                ControlResponse::Error(err) => Err(anyhow!(
                    "test request failed: {}: {}",
                    err.code,
                    err.message
                )),
                other => Err(anyhow!("unexpected response: {other:?}")),
            }
        }
        Command::DashboardToken { command } => match command {
            DashboardTokenCommand::Rotate {
                file,
                username,
                bytes,
            } => rotate_dashboard_password(&file, &username, bytes),
        },
        Command::DashboardPassword { command } => match command {
            DashboardPasswordCommand::Rotate {
                file,
                username,
                bytes,
            } => rotate_dashboard_password(&file, &username, bytes),
        },
    }
}

fn build_action(profile: &str, input: ActionBuildInput) -> anyhow::Result<Action> {
    let context = ActionContext {
        timestamp: Utc::now(),
        agent_id: "cli-test-agent".to_string(),
        pid: std::process::id(),
        ppid: parent_pid(),
        uid: current_uid(),
        profile: profile.to_string(),
    };

    match input.action {
        ActionArg::FileRead => Ok(Action {
            action_type: ActionType::FileRead,
            context,
            resource: Resource::File(FileResource {
                path: required(input.path, "--path")?,
                resolved_path: None,
                op: FileOp::Read,
                source_path: None,
            }),
        }),
        ActionArg::FileWrite => Ok(Action {
            action_type: ActionType::FileWrite,
            context,
            resource: Resource::File(FileResource {
                path: required(input.path, "--path")?,
                resolved_path: None,
                op: FileOp::Write,
                source_path: None,
            }),
        }),
        ActionArg::FileDelete => Ok(Action {
            action_type: ActionType::FileDelete,
            context,
            resource: Resource::File(FileResource {
                path: required(input.path, "--path")?,
                resolved_path: None,
                op: FileOp::Delete,
                source_path: None,
            }),
        }),
        ActionArg::ProcExec => Ok(Action {
            action_type: ActionType::ProcExec,
            context,
            resource: Resource::Exec(ExecResource {
                path: required(input.path, "--path")?,
                argv_hash: None,
                cwd: input.cwd,
                argv: Vec::new(),
                argv_truncated: false,
            }),
        }),
        ActionArg::NetConnect => Ok(Action {
            action_type: ActionType::NetConnect,
            context,
            resource: Resource::Network(build_network_resource(
                input.dest_host,
                input.dest_ip,
                input.dest_port,
                input.url,
                input.method,
                input.protocol,
            )?),
        }),
        ActionArg::McpToolCall => {
            let arguments_json = input.arguments_json.unwrap_or_else(|| "{}".to_string());
            let arguments_sha256 = hex::encode(Sha256::digest(arguments_json.as_bytes()));
            Ok(Action {
                action_type: ActionType::McpToolCall,
                context,
                resource: Resource::McpTool(McpToolResource {
                    server_id: required(input.mcp_server, "--mcp-server")?,
                    transport: McpTransport::Stdio,
                    tool_name: required(input.mcp_tool, "--mcp-tool")?,
                    tool_call_id: input
                        .mcp_tool_call_id
                        .unwrap_or_else(|| "cli-test-call".to_string()),
                    mcp_session_id: input
                        .mcp_session_id
                        .unwrap_or_else(|| "cli-test-session".to_string()),
                    arguments_sha256,
                    arguments_summary: Some(arguments_json.chars().take(160).collect()),
                }),
            })
        }
    }
}

fn build_network_resource(
    dest_host: Option<String>,
    dest_ip: Option<String>,
    dest_port: Option<u16>,
    url: Option<String>,
    method: Option<String>,
    protocol: Option<ProtocolArg>,
) -> anyhow::Result<NetworkResource> {
    let proto = match protocol.unwrap_or(ProtocolArg::Tcp) {
        ProtocolArg::Tcp => NetworkProtocol::Tcp,
        ProtocolArg::Udp => NetworkProtocol::Udp,
    };

    if let Some(raw_url) = url {
        let parsed = parse_url(raw_url.as_str())?;
        return Ok(NetworkResource {
            dest_host: Some(parsed.host),
            dest_ip: None,
            dest_port: parsed.port,
            protocol: proto,
            full_url: Some(raw_url),
            scheme: Some(parsed.scheme),
            method: method.map(|m| m.trim().to_ascii_uppercase()),
            path: Some(parsed.path),
            query: parsed.query,
            socket_path: None,
            family: None,
        });
    }

    Ok(NetworkResource {
        dest_host,
        dest_ip,
        dest_port: required(dest_port, "--dest-port")?,
        protocol: proto,
        full_url: None,
        scheme: None,
        method: method.map(|m| m.trim().to_ascii_uppercase()),
        path: None,
        query: None,
        socket_path: None,
        family: None,
    })
}

#[derive(Debug)]
struct ParsedUrl {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    query: Option<String>,
}

fn parse_url(raw: &str) -> anyhow::Result<ParsedUrl> {
    let trimmed = raw.trim();
    let (scheme_raw, rest) = trimmed
        .split_once("://")
        .ok_or_else(|| anyhow!("--url must include scheme://host"))?;
    let scheme = scheme_raw.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(anyhow!("--url scheme must be http or https"));
    }

    let (authority, tail) = match rest.split_once('/') {
        Some((authority, tail)) => (authority, format!("/{}", tail)),
        None => (rest, "/".to_string()),
    };

    if authority.trim().is_empty() {
        return Err(anyhow!("--url host must not be empty"));
    }

    let (host, port) = parse_authority(authority, if scheme == "https" { 443 } else { 80 })?;
    let (path, query) = match tail.split_once('?') {
        Some((path, query)) => (path.to_string(), Some(query.to_string())),
        None => (tail, None),
    };

    Ok(ParsedUrl {
        scheme,
        host,
        port,
        path,
        query,
    })
}

fn parse_authority(authority: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    if let Some(host) = authority.strip_prefix('[') {
        let end = host
            .find(']')
            .ok_or_else(|| anyhow!("invalid bracketed host in --url"))?;
        let host = &host[..end];
        let tail = &authority[host.len() + 2..];
        let port = if let Some(value) = tail.strip_prefix(':') {
            value
                .parse::<u16>()
                .map_err(|_| anyhow!("invalid port in --url"))?
        } else {
            default_port
        };
        return Ok((host.to_string(), port));
    }

    if let Some((host, port_raw)) = authority.rsplit_once(':')
        && !host.contains(':')
    {
        let port = port_raw
            .parse::<u16>()
            .map_err(|_| anyhow!("invalid port in --url"))?;
        return Ok((host.to_string(), port));
    }

    Ok((authority.to_string(), default_port))
}

fn required<T>(value: Option<T>, arg: &str) -> anyhow::Result<T> {
    value.ok_or_else(|| anyhow!("missing required argument: {arg}"))
}

fn parent_pid() -> u32 {
    platform_traits::parent_pid()
}

fn current_uid() -> u32 {
    platform_traits::current_uid()
}

fn rotate_dashboard_password(path: &str, username: &str, bytes: usize) -> anyhow::Result<()> {
    let username = username.trim();
    if username.is_empty() {
        return Err(anyhow!("username must not be empty"));
    }

    let size = bytes.clamp(16, 128);
    let mut raw = vec![0u8; size];
    OsRng.fill_bytes(raw.as_mut_slice());
    let plaintext = URL_SAFE_NO_PAD.encode(raw);

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|err| anyhow!("hash dashboard password: {err}"))?
        .to_string();

    let file_path = Path::new(path);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create dashboard password dir {}", parent.display()))?;
    }

    fs::write(file_path, format!("{hash}\n"))
        .with_context(|| format!("write dashboard password hash to {}", file_path.display()))?;

    #[cfg(unix)]
    fs::set_permissions(file_path, fs::Permissions::from_mode(0o600)).with_context(|| {
        format!(
            "set dashboard password permissions on {}",
            file_path.display()
        )
    })?;

    println!("dashboard_password_file={}", file_path.display());
    println!("dashboard_username={username}");
    println!("dashboard_password={plaintext}");
    println!("note=store_password_securely_it_is_not_recoverable");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_extracts_components() {
        let parsed = parse_url("https://example.com:8443/api/v1?q=1").expect("parse url");
        assert_eq!(parsed.scheme, "https");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 8443);
        assert_eq!(parsed.path, "/api/v1");
        assert_eq!(parsed.query.as_deref(), Some("q=1"));
    }

    #[test]
    fn parse_url_defaults_path_and_port() {
        let parsed = parse_url("http://example.com").expect("parse url");
        assert_eq!(parsed.scheme, "http");
        assert_eq!(parsed.port, 80);
        assert_eq!(parsed.path, "/");
        assert!(parsed.query.is_none());
    }

    #[test]
    fn parse_url_rejects_missing_scheme() {
        let err = parse_url("example.com/path").expect_err("should reject");
        assert!(err.to_string().contains("scheme://host"));
    }

    #[test]
    fn parse_authority_supports_ipv6_brackets() {
        let parsed = parse_authority("[2001:db8::1]:8443", 443).expect("parse authority");
        assert_eq!(parsed.0, "2001:db8::1");
        assert_eq!(parsed.1, 8443);
    }

    #[test]
    fn parse_authority_rejects_invalid_port() {
        let err = parse_authority("example.com:not-a-port", 443).expect_err("invalid port");
        assert!(err.to_string().contains("invalid port"));
    }

    #[test]
    fn build_network_resource_from_url_sets_url_fields() {
        let resource = build_network_resource(
            None,
            None,
            None,
            Some("https://api.example.com/reports?id=7".to_string()),
            Some("post".to_string()),
            Some(ProtocolArg::Tcp),
        )
        .expect("build network resource");

        assert_eq!(resource.dest_host.as_deref(), Some("api.example.com"));
        assert_eq!(resource.dest_port, 443);
        assert_eq!(
            resource.full_url.as_deref(),
            Some("https://api.example.com/reports?id=7")
        );
        assert_eq!(resource.scheme.as_deref(), Some("https"));
        assert_eq!(resource.method.as_deref(), Some("POST"));
        assert_eq!(resource.path.as_deref(), Some("/reports"));
        assert_eq!(resource.query.as_deref(), Some("id=7"));
    }

    #[test]
    fn build_network_resource_requires_dest_port_without_url() {
        let err = build_network_resource(
            Some("example.com".to_string()),
            None,
            None,
            None,
            None,
            Some(ProtocolArg::Udp),
        )
        .expect_err("missing --dest-port should fail");
        assert!(err.to_string().contains("--dest-port"));
    }

    #[test]
    fn build_action_net_connect_uses_profile_context() {
        let action = build_action(
            "default",
            ActionBuildInput {
                action: ActionArg::NetConnect,
                path: None,
                cwd: "/tmp".to_string(),
                dest_host: Some("example.com".to_string()),
                dest_ip: None,
                dest_port: Some(443),
                url: None,
                method: Some("get".to_string()),
                protocol: Some(ProtocolArg::Tcp),
                mcp_server: None,
                mcp_tool: None,
                mcp_tool_call_id: None,
                mcp_session_id: None,
                arguments_json: None,
            },
        )
        .expect("build action");

        assert_eq!(action.context.profile, "default");
        assert_eq!(action.action_type, ActionType::NetConnect);
        match action.resource {
            Resource::Network(network) => {
                assert_eq!(network.dest_host.as_deref(), Some("example.com"));
                assert_eq!(network.dest_port, 443);
                assert_eq!(network.method.as_deref(), Some("GET"));
            }
            _ => panic!("expected network resource"),
        }
    }
}
