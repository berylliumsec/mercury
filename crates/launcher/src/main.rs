use std::env;
use std::ffi::OsStr;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Stdio};

use anyhow::{Context, anyhow};
use clap::Parser;
use control_api::{
    ControlRequest, ControlResponse, RegisterAgentRequest, RegisterAgentResponse, decode_response,
    encode_request,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::{Duration, timeout};

const REGISTER_IO_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Parser)]
#[command(name = "mercury-run")]
#[command(about = "Launch an AI agent process under mercury policy")]
struct Args {
    #[arg(long, default_value = "default")]
    profile: String,
    #[arg(long, default_value = control_api::SOCKET_PATH)]
    socket: String,
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if let Err(err) = run(args).await {
        eprintln!("mercury-run failed: {err:#}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    if args.command.is_empty() {
        return Err(anyhow!("missing command to execute"));
    }

    // H2: Narrow ptrace permission to the daemon PID rather than granting
    // PR_SET_PTRACER_ANY (which allows *any* process to attach).
    #[cfg(all(feature = "unix-ipc", unix))]
    set_ptracer_for_daemon(&args.socket).context("configure ptrace opt-in for mercuryd")?;

    let requested_argv = args.command.clone();
    let exec_path = resolve_executable(requested_argv[0].as_str())?;

    let cwd = env::current_dir()
        .context("resolve cwd")?
        .to_string_lossy()
        .to_string();
    let pid = std::process::id();

    let request = ControlRequest::RegisterAgent(RegisterAgentRequest {
        pid,
        ppid: parent_pid(),
        uid: current_uid(),
        gid: current_gid(),
        profile: args.profile.clone(),
        cmdline: requested_argv.clone(),
        cwd,
    });

    let registration = register_with_daemon(&args.socket, &request).await?;

    let mut command = StdCommand::new(&exec_path);
    apply_command_argv(&mut command, requested_argv.as_slice());
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    apply_registration_environment(&mut command, &args.profile, &registration)?;
    #[cfg(unix)]
    apply_filesystem_label(&registration)?;

    #[cfg(unix)]
    {
        let err = command.exec();
        return Err(anyhow!("exec command {}: {err}", exec_path));
    }

    #[allow(unreachable_code)]
    {
        let status = command
            .status()
            .with_context(|| format!("run command {}", exec_path))?;

        if let Some(code) = status.code() {
            std::process::exit(code);
        }

        std::process::exit(1);
    }
}

/// Send a registration request to the daemon and return the parsed response.
///
/// Connects via the daemon's Unix domain socket.
#[cfg(unix)]
async fn register_with_daemon(
    socket: &str,
    request: &ControlRequest,
) -> anyhow::Result<RegisterAgentResponse> {
    let mut stream = timeout(REGISTER_IO_TIMEOUT, UnixStream::connect(socket))
        .await
        .context("timed out connecting to daemon control socket")?
        .with_context(|| format!("connect to daemon socket {socket}"))?;

    let frame = encode_request(request).context("encode register request")?;
    timeout(REGISTER_IO_TIMEOUT, stream.write_all(&frame))
        .await
        .context("timed out sending register request")?
        .context("send register request")?;
    timeout(REGISTER_IO_TIMEOUT, stream.flush())
        .await
        .context("timed out flushing register request")?
        .context("flush register request")?;

    let (read_half, _) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut response_frame = Vec::new();
    let bytes = timeout(
        REGISTER_IO_TIMEOUT,
        reader.read_until(b'\n', &mut response_frame),
    )
    .await
    .context("timed out waiting for register response")?
    .context("read register response")?;
    if bytes == 0 {
        return Err(anyhow!(
            "daemon closed control socket without a register response frame"
        ));
    }

    let response = decode_response(&response_frame).context("decode register response")?;
    match response {
        ControlResponse::RegisterAgent(payload) => Ok(payload),
        ControlResponse::Error(err) => Err(anyhow!(
            "registration rejected: {}: {}",
            err.code,
            err.message
        )),
        unexpected => Err(anyhow!(
            "unexpected daemon response to RegisterAgent: {unexpected:?}"
        )),
    }
}

fn apply_command_argv(command: &mut StdCommand, command_argv: &[String]) {
    if command_argv.len() > 1 {
        command.args(&command_argv[1..]);
    }

    #[cfg(unix)]
    {
        // Preserve caller-provided argv[0] because some binaries inspect it for mode selection
        // or self-validation and may abort if it is rewritten to an absolute path.
        if let Some(arg0) = command_argv.first() {
            command.arg0(arg0.as_str());
        }
    }
}

fn resolve_executable(program: &str) -> anyhow::Result<String> {
    Ok(resolve_executable_in_path(
        program,
        env::var_os("PATH").as_deref(),
    ))
}

fn resolve_executable_in_path(program: &str, path_env: Option<&OsStr>) -> String {
    if program.contains('/') || program.contains('\\') {
        return program.to_string();
    }

    let Some(path_env) = path_env else {
        return program.to_string();
    };

    for dir in env::split_paths(path_env) {
        let candidate = dir.join(program);
        if is_executable_file(candidate.as_path()) {
            return candidate.to_string_lossy().to_string();
        }
    }

    program.to_string()
}

fn apply_registration_environment(
    command: &mut StdCommand,
    profile: &str,
    registration: &RegisterAgentResponse,
) -> anyhow::Result<()> {
    command
        .env("MERCURY_AGENT_ID", registration.agent_id.to_string())
        .env("MERCURY_PROFILE", profile)
        .env("MERCURY_CGROUP_ID", &registration.cgroup_id);

    if let Some(proxy) = registration.url_proxy_http.as_deref() {
        let proxy = proxy_url_with_auth(proxy, registration.url_proxy_auth_token.as_deref())?;
        command
            .env("HTTP_PROXY", proxy.as_str())
            .env("http_proxy", proxy.as_str());
    }
    if let Some(proxy) = registration.url_proxy_https.as_deref() {
        let proxy = proxy_url_with_auth(proxy, registration.url_proxy_auth_token.as_deref())?;
        command
            .env("HTTPS_PROXY", proxy.as_str())
            .env("https_proxy", proxy.as_str());
    }
    if let Some(no_proxy) = registration.url_proxy_no_proxy.as_deref() {
        command.env("NO_PROXY", no_proxy).env("no_proxy", no_proxy);
    }
    if let Some(ca_path) = resolve_registration_ca_path(registration)? {
        command
            .env("SSL_CERT_FILE", &ca_path)
            .env("REQUESTS_CA_BUNDLE", &ca_path)
            .env("NODE_EXTRA_CA_CERTS", &ca_path)
            .env("CURL_CA_BUNDLE", &ca_path)
            .env("GIT_SSL_CAINFO", &ca_path);
    }

    Ok(())
}

#[cfg(unix)]
fn apply_filesystem_label(registration: &RegisterAgentResponse) -> anyhow::Result<()> {
    let Some(label) = registration.filesystem_label.as_deref() else {
        return Ok(());
    };

    // Prefer "exec" which works on all AppArmor kernels.  Fall back to
    // "stackexec" when running inside a stacked AppArmor namespace (Ubuntu 24.04+
    // with namespace stacking enabled).
    let exec_path = Path::new("/proc/self/attr/exec");
    fs::write(exec_path, format!("exec {label}"))
        .or_else(|_| fs::write(exec_path, format!("stackexec {label}")))
        .with_context(|| format!("apply AppArmor on-exec profile {label}"))?;
    Ok(())
}

fn proxy_url_with_auth(proxy: &str, auth_token: Option<&str>) -> anyhow::Result<String> {
    let Some(auth_token) = auth_token else {
        return Ok(proxy.to_string());
    };
    if auth_token.trim().is_empty() {
        return Err(anyhow!(
            "registration returned an empty URL proxy authentication token"
        ));
    }

    let Some(target) = proxy.strip_prefix("http://") else {
        return Err(anyhow!(
            "URL proxy endpoint must use http:// scheme, got '{}'",
            proxy
        ));
    };

    if target.contains('@') {
        return Ok(proxy.to_string());
    }

    Ok(format!("http://mercury:{auth_token}@{target}"))
}

fn resolve_registration_ca_path(
    registration: &RegisterAgentResponse,
) -> anyhow::Result<Option<String>> {
    if let Some(ca_pem) = registration.url_proxy_ca_cert_pem.as_deref() {
        if ca_pem.trim().is_empty() {
            return Err(anyhow!(
                "registration returned an empty URL gateway CA certificate payload"
            ));
        }

        let path = materialize_registration_ca_file(ca_pem)?;
        return Ok(Some(path.to_string_lossy().to_string()));
    }

    if let Some(ca_path) = registration.url_proxy_ca_cert_path.as_deref()
        && fs::read_to_string(ca_path).is_ok()
    {
        return Ok(Some(ca_path.to_string()));
    }

    Ok(registration.url_proxy_ca_cert_path.clone())
}

fn materialize_registration_ca_file(ca_pem: &str) -> anyhow::Result<PathBuf> {
    let digest = hex_digest(ca_pem.as_bytes());
    // UID-scope the cache dir so a `sudo mercury-run` invocation can't leave
    // a root-owned file in /tmp/mercury-ca/ that blocks subsequent calls from
    // other users. Each UID gets its own 0o700 cache dir.
    #[cfg(all(feature = "unix-ipc", unix))]
    let dir = {
        // Safety: getuid() is always-defined and has no failure mode.
        let uid = unsafe { libc::getuid() };
        env::temp_dir().join(format!("mercury-ca-{uid}"))
    };
    #[cfg(not(all(feature = "unix-ipc", unix)))]
    let dir = env::temp_dir().join("mercury-ca");
    fs::create_dir_all(&dir)
        .with_context(|| format!("create URL gateway CA certificate cache {}", dir.display()))?;
    #[cfg(unix)]
    {
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "set URL gateway CA certificate cache permissions on {}",
                dir.display()
            )
        })?;
    }
    let path = dir.join(format!("mercury-ca-{digest}.crt"));

    match fs::read_to_string(&path) {
        Ok(existing) => {
            if existing != ca_pem {
                return Err(anyhow!(
                    "existing URL gateway CA certificate cache at {} does not match expected contents",
                    path.display()
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| {
                    format!(
                        "create URL gateway CA certificate cache file {}",
                        path.display()
                    )
                })?;
            std::io::Write::write_all(&mut file, ca_pem.as_bytes()).with_context(|| {
                format!(
                    "write URL gateway CA certificate bundle to {}",
                    path.display()
                )
            })?;
        }
        Err(err) => {
            return Err(anyhow!(
                "read URL gateway CA certificate cache {}: {}",
                path.display(),
                err
            ));
        }
    }

    #[cfg(unix)]
    {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).with_context(|| {
            format!(
                "set URL gateway CA certificate permissions on {}",
                path.display()
            )
        })?;
    }
    Ok(path)
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn parent_pid() -> u32 {
    platform_traits::parent_pid()
}

fn current_uid() -> u32 {
    platform_traits::current_uid()
}

fn current_gid() -> u32 {
    platform_traits::current_gid()
}

#[cfg(all(feature = "unix-ipc", unix))]
fn set_ptracer_for_daemon(socket_path: &str) -> anyhow::Result<()> {
    // Derive pidfile path: same directory as the control socket, file "mercuryd.pid".
    let pid_path = std::path::Path::new(socket_path)
        .parent()
        .ok_or_else(|| anyhow!("could not derive pidfile dir from socket path {socket_path}"))
        .map(|dir| dir.join("mercuryd.pid"));

    let daemon_pid: libc::pid_t = match pid_path {
        Ok(ref path) => fs::read_to_string(path)
            .with_context(|| format!("read daemon pidfile {}", path.display()))?
            .trim()
            .parse()
            .context("parse daemon pid from pidfile")?,
        Err(err) => {
            // If we can't derive the path fall back to the broad permission.
            eprintln!("mercury-run: {err:#}; falling back to PR_SET_PTRACER_ANY");
            return set_ptracer_any();
        }
    };

    // SAFETY: prctl with PR_SET_PTRACER and a valid pid is documented and safe.
    let rc = unsafe { libc::prctl(libc::PR_SET_PTRACER, daemon_pid as libc::c_long, 0, 0, 0) };
    if rc != 0 {
        // PR_SET_PTRACER may not be supported on all kernels/configs (e.g. when
        // Yama is disabled). Treat this as a non-fatal warning.
        let os_err = std::io::Error::last_os_error();
        eprintln!(
            "mercury-run: prctl(PR_SET_PTRACER, {daemon_pid}) failed: {os_err}; tracing may be restricted"
        );
    }
    Ok(())
}

#[cfg(all(feature = "unix-ipc", unix))]
fn set_ptracer_any() -> anyhow::Result<()> {
    // SAFETY: prctl is called with PR_SET_PTRACER and a documented magic value to allow tracing.
    let rc = unsafe { libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(anyhow!(
            "prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) failed with errno {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    fn dummy_command() -> StdCommand {
        StdCommand::new("/bin/echo")
    }

    #[test]
    fn resolve_executable_in_path_finds_executable() {
        let dir = tempdir().expect("tempdir");
        let binary = dir.path().join("agent-tool");
        fs::write(&binary, "#!/bin/sh\nexit 0\n").expect("write executable");
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&binary).expect("metadata").permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&binary, perms).expect("chmod");
        }

        let resolved = resolve_executable_in_path("agent-tool", Some(dir.path().as_os_str()));
        assert_eq!(resolved, binary.to_string_lossy());
    }

    #[test]
    fn resolve_executable_in_path_keeps_explicit_path() {
        let resolved = resolve_executable_in_path("/usr/bin/env", None);
        assert_eq!(resolved, "/usr/bin/env");
    }

    #[test]
    fn apply_registration_environment_sets_proxy_variables() {
        let registration = RegisterAgentResponse {
            agent_id: "123e4567-e89b-12d3-a456-426614174000"
                .parse()
                .expect("uuid"),
            cgroup_id: "ai-test".to_string(),
            filesystem_label: None,
            url_proxy_http: Some("http://127.0.0.1:19080".to_string()),
            url_proxy_https: Some("http://127.0.0.1:19080".to_string()),
            url_proxy_no_proxy: Some("localhost,127.0.0.1".to_string()),
            url_proxy_auth_token: None,
            url_proxy_ca_cert_path: Some("/tmp/mercury-ca.crt".to_string()),
            url_proxy_ca_cert_pem: None,
        };

        let mut command = dummy_command();
        apply_registration_environment(&mut command, "default", &registration).expect("env setup");
        let envs: HashMap<String, String> = command
            .get_envs()
            .filter_map(|(key, value)| {
                Some((
                    key.to_string_lossy().to_string(),
                    value?.to_string_lossy().to_string(),
                ))
            })
            .collect();

        assert_eq!(
            envs.get("MERCURY_AGENT_ID"),
            Some(&registration.agent_id.to_string())
        );
        assert_eq!(envs.get("MERCURY_PROFILE"), Some(&"default".to_string()));
        assert_eq!(envs.get("MERCURY_CGROUP_ID"), Some(&"ai-test".to_string()));
        assert_eq!(
            envs.get("HTTP_PROXY"),
            Some(&"http://127.0.0.1:19080".to_string())
        );
        assert_eq!(
            envs.get("HTTPS_PROXY"),
            Some(&"http://127.0.0.1:19080".to_string())
        );
        assert_eq!(
            envs.get("NODE_EXTRA_CA_CERTS"),
            Some(&"/tmp/mercury-ca.crt".to_string())
        );
    }

    #[test]
    fn apply_registration_environment_embeds_proxy_auth_token() {
        let registration = RegisterAgentResponse {
            agent_id: "123e4567-e89b-12d3-a456-42661417400a"
                .parse()
                .expect("uuid"),
            cgroup_id: "ai-test".to_string(),
            filesystem_label: None,
            url_proxy_http: Some("http://127.0.0.1:19080".to_string()),
            url_proxy_https: Some("http://127.0.0.1:19080".to_string()),
            url_proxy_no_proxy: Some("localhost,127.0.0.1".to_string()),
            url_proxy_auth_token: Some("token-123".to_string()),
            url_proxy_ca_cert_path: None,
            url_proxy_ca_cert_pem: None,
        };

        let mut command = dummy_command();
        apply_registration_environment(&mut command, "default", &registration).expect("env setup");
        let envs: HashMap<String, String> = command
            .get_envs()
            .filter_map(|(key, value)| {
                Some((
                    key.to_string_lossy().to_string(),
                    value?.to_string_lossy().to_string(),
                ))
            })
            .collect();

        assert_eq!(
            envs.get("HTTP_PROXY"),
            Some(&"http://mercury:token-123@127.0.0.1:19080".to_string())
        );
        assert_eq!(
            envs.get("HTTPS_PROXY"),
            Some(&"http://mercury:token-123@127.0.0.1:19080".to_string())
        );
    }

    #[test]
    fn apply_registration_environment_materializes_ca_from_pem() {
        let dir = tempdir().expect("tempdir");
        let missing_ca_path = dir.path().join("missing-gateway-ca.crt");

        let registration = RegisterAgentResponse {
            agent_id: "123e4567-e89b-12d3-a456-426614174001"
                .parse()
                .expect("uuid"),
            cgroup_id: "ai-test".to_string(),
            filesystem_label: None,
            url_proxy_http: Some("http://127.0.0.1:19080".to_string()),
            url_proxy_https: Some("http://127.0.0.1:19080".to_string()),
            url_proxy_no_proxy: Some("localhost,127.0.0.1".to_string()),
            url_proxy_auth_token: None,
            url_proxy_ca_cert_path: Some(missing_ca_path.to_string_lossy().to_string()),
            url_proxy_ca_cert_pem: Some(
                "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_string(),
            ),
        };

        let mut command = dummy_command();
        apply_registration_environment(&mut command, "default", &registration).expect("env setup");
        let envs: HashMap<String, String> = command
            .get_envs()
            .filter_map(|(key, value)| {
                Some((
                    key.to_string_lossy().to_string(),
                    value?.to_string_lossy().to_string(),
                ))
            })
            .collect();

        let ca_path = envs.get("SSL_CERT_FILE").expect("SSL_CERT_FILE");
        // Use platform-agnostic separator check
        let ca_path_normalized = ca_path.replace('\\', "/");
        assert!(ca_path_normalized.contains("/mercury-ca-"));
        assert_eq!(
            fs::read_to_string(ca_path).expect("read generated CA bundle"),
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        );
        fs::remove_file(ca_path).expect("cleanup generated CA bundle");
    }

    #[test]
    fn apply_registration_environment_prefers_pem_ca_bundle_over_host_path() {
        let dir = tempdir().expect("tempdir");
        let ca_path = dir.path().join("gateway-ca.crt");
        fs::write(
            &ca_path,
            "-----BEGIN CERTIFICATE-----\nPATH\n-----END CERTIFICATE-----\n",
        )
        .expect("write CA cert");

        let registration = RegisterAgentResponse {
            agent_id: "123e4567-e89b-12d3-a456-426614174002"
                .parse()
                .expect("uuid"),
            cgroup_id: "ai-test".to_string(),
            filesystem_label: None,
            url_proxy_http: Some("http://127.0.0.1:19080".to_string()),
            url_proxy_https: Some("http://127.0.0.1:19080".to_string()),
            url_proxy_no_proxy: Some("localhost,127.0.0.1".to_string()),
            url_proxy_auth_token: None,
            url_proxy_ca_cert_path: Some(ca_path.to_string_lossy().to_string()),
            url_proxy_ca_cert_pem: Some(
                "-----BEGIN CERTIFICATE-----\nPEM\n-----END CERTIFICATE-----\n".to_string(),
            ),
        };

        let mut command = dummy_command();
        apply_registration_environment(&mut command, "default", &registration).expect("env setup");
        let envs: HashMap<String, String> = command
            .get_envs()
            .filter_map(|(key, value)| {
                Some((
                    key.to_string_lossy().to_string(),
                    value?.to_string_lossy().to_string(),
                ))
            })
            .collect();

        let generated_path = envs.get("SSL_CERT_FILE").expect("SSL_CERT_FILE");
        assert_ne!(generated_path, &ca_path.to_string_lossy().to_string());
        let generated_path_normalized = generated_path.replace('\\', "/");
        assert!(generated_path_normalized.contains("/mercury-ca-"));
        assert_eq!(
            fs::read_to_string(generated_path).expect("read generated CA bundle"),
            "-----BEGIN CERTIFICATE-----\nPEM\n-----END CERTIFICATE-----\n"
        );
        fs::remove_file(generated_path).expect("cleanup generated CA bundle");
    }

    #[test]
    fn apply_registration_environment_falls_back_to_readable_ca_path_without_pem() {
        let dir = tempdir().expect("tempdir");
        let ca_path = dir.path().join("gateway-ca.crt");
        fs::write(
            &ca_path,
            "-----BEGIN CERTIFICATE-----\nPATH\n-----END CERTIFICATE-----\n",
        )
        .expect("write CA cert");

        let registration = RegisterAgentResponse {
            agent_id: "123e4567-e89b-12d3-a456-426614174002"
                .parse()
                .expect("uuid"),
            cgroup_id: "ai-test".to_string(),
            filesystem_label: None,
            url_proxy_http: Some("http://127.0.0.1:19080".to_string()),
            url_proxy_https: Some("http://127.0.0.1:19080".to_string()),
            url_proxy_no_proxy: Some("localhost,127.0.0.1".to_string()),
            url_proxy_auth_token: None,
            url_proxy_ca_cert_path: Some(ca_path.to_string_lossy().to_string()),
            url_proxy_ca_cert_pem: None,
        };

        let mut command = dummy_command();
        apply_registration_environment(&mut command, "default", &registration).expect("env setup");
        let envs: HashMap<String, String> = command
            .get_envs()
            .filter_map(|(key, value)| {
                Some((
                    key.to_string_lossy().to_string(),
                    value?.to_string_lossy().to_string(),
                ))
            })
            .collect();

        assert_eq!(
            envs.get("SSL_CERT_FILE"),
            Some(&ca_path.to_string_lossy().to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn args_default_profile_when_omitted() {
        let args = Args::try_parse_from(["mercury-run", "example-agent"]).expect("parse args");
        assert_eq!(args.profile, "default");
        assert_eq!(args.command, vec!["example-agent".to_string()]);
    }

    #[test]
    fn args_accept_explicit_profile_override() {
        let args = Args::try_parse_from(["mercury-run", "--profile", "sandbox", "example-agent"])
            .expect("parse args");
        assert_eq!(args.profile, "sandbox");
        assert_eq!(args.command, vec!["example-agent".to_string()]);
    }

    #[test]
    fn apply_command_argv_preserves_original_arg0() {
        let mut command = StdCommand::new("/bin/sh");
        let argv = vec![
            "agent-alias".to_string(),
            "-c".to_string(),
            "printf '%s' \"$0\"".to_string(),
        ];
        apply_command_argv(&mut command, argv.as_slice());

        let output = command.output().expect("run shell command");
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "agent-alias");
    }

    // SAFETY: env::set_var is process-global; this test reads TMPDIR after
    // setting it. Rust 2024 marks env::set_var unsafe — we hold no other
    // threads that would race on it during the cargo test harness.
    #[cfg(all(feature = "unix-ipc", unix))]
    #[test]
    fn materialize_registration_ca_file_uses_uid_scoped_dir() {
        let tmp = tempdir().expect("tempdir");
        // Force env::temp_dir() to point at our tempdir for this process.
        let prev = env::var_os("TMPDIR");
        unsafe {
            env::set_var("TMPDIR", tmp.path());
        }

        let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        let path = materialize_registration_ca_file(pem).expect("materialize ca");

        // Restore TMPDIR before any further env-sensitive code runs.
        unsafe {
            match prev {
                Some(v) => env::set_var("TMPDIR", v),
                None => env::remove_var("TMPDIR"),
            }
        }

        let uid = unsafe { libc::getuid() };
        let parent = path.parent().expect("cache file has a parent");
        let parent_name = parent.file_name().and_then(|n| n.to_str()).unwrap_or("");
        assert_eq!(
            parent_name,
            format!("mercury-ca-{uid}"),
            "cache dir is not UID-scoped: {}",
            parent.display()
        );
        assert!(parent.starts_with(tmp.path()), "cache dir not under TMPDIR");
    }
}
