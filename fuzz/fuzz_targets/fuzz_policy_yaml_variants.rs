#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use policy_engine::{SignatureVerification, load_policy_from_str};

#[derive(Debug, Arbitrary)]
struct FuzzPolicyInput {
    version: u8,
    default_decision: bool,
    profile_name: String,
    file_allow_pattern: String,
    file_deny_pattern: String,
    exec_pattern: String,
    net_cidr: String,
    net_port: u16,
    url_host: String,
    url_path: String,
}

fn yaml_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fuzz_target!(|input: FuzzPolicyInput| {
    let decision = if input.default_decision {
        "allow"
    } else {
        "deny"
    };
    let version = format!("{}.{}", input.version / 16, input.version % 16);
    let yaml = format!(
        r#"version: "{version}"
defaults:
  decision: {decision}
  fail_mode: fail_closed
profiles:
  "{name}":
    file_allow:
      - id: fa1
        pattern: "{fa}"
    file_deny:
      - id: fd1
        pattern: "{fd}"
    exec_allow:
      - id: ea1
        pattern: "{ea}"
    network_deny:
      - id: nd1
        cidr: "{cidr}"
        port: {port}
        protocol: tcp
    url_deny:
      - id: ud1
        host: "{host}"
        path: "{path}"
"#,
        name = yaml_escape(&input.profile_name),
        fa = yaml_escape(&input.file_allow_pattern),
        fd = yaml_escape(&input.file_deny_pattern),
        ea = yaml_escape(&input.exec_pattern),
        cidr = yaml_escape(&input.net_cidr),
        port = input.net_port,
        host = yaml_escape(&input.url_host),
        path = yaml_escape(&input.url_path),
    );

    // Must never panic regardless of input content.
    let _ = load_policy_from_str(&yaml, SignatureVerification::Disabled);
});
