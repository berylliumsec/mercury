use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use core_types::{
    API_VERSION, Action, ActionClass, ActionType, CoreError, Decision, DecisionReason,
    DecisionResult, DefaultDecision, EnforcementMode, ExecRule, FailMode, FileResource, McpPolicy,
    McpResourcePolicy, McpResourceReadResource, McpServerPolicy, McpToolAction, McpToolPolicy,
    McpToolResource, McpTransport, NetworkRule, PolicyDefaults, PolicyDocument, ProfilePolicy,
    Resource, UrlRule,
};
use globset::{Glob, GlobMatcher};

// When compiled with the "linux" feature (default), pull limits from the kernel
// crates.  Without it, use equivalent defaults so policy evaluation logic
// compiles on every platform.
#[cfg(feature = "linux")]
use kernel_matcher::{MAX_PATH_BYTES, MAX_PROFILES};
#[cfg(not(feature = "linux"))]
const MAX_PATH_BYTES: usize = 1024;
#[cfg(not(feature = "linux"))]
const MAX_PROFILES: usize = 128;

#[cfg(feature = "linux")]
const MAX_KERNEL_RULES_PER_CLASS: usize = kernel_ebpf::MAX_RULES_PER_CLASS;
#[cfg(not(feature = "linux"))]
const MAX_KERNEL_RULES_PER_CLASS: usize = 32;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureVerification {
    Disabled,
    WarnOnInvalid,
    /// Verify the policy's HMAC-SHA256 signature using the provided key.
    /// The signature is computed over the policy YAML with the `signature:` block removed,
    /// and stored as 64 lowercase hex characters in `signature.sig`.
    RequireValid {
        hmac_key: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub compiled: CompiledPolicy,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub version: String,
    pub defaults: PolicyDefaults,
    pub profiles: HashMap<String, CompiledProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelPolicyIr {
    pub version: String,
    pub defaults: PolicyDefaults,
    pub profile_count: u32,
    pub max_path_bytes: u32,
    pub max_rules_per_class: u32,
    pub profiles: HashMap<String, KernelProfileIr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelProfileIr {
    pub workspace_roots: Vec<String>,
    pub file_allow: Vec<KernelPathRuleIr>,
    pub file_deny: Vec<KernelPathRuleIr>,
    pub exec_allow: Vec<KernelExecRuleIr>,
    pub exec_deny: Vec<KernelExecRuleIr>,
    pub network_allow: Vec<NetworkRule>,
    pub network_deny: Vec<NetworkRule>,
    pub url_allow: Vec<UrlRule>,
    pub url_deny: Vec<UrlRule>,
    pub enforcement: core_types::EnforcementSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelPathRuleIr {
    pub id: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelExecRuleIr {
    pub id: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemPolicyBackend {
    EbpfLsm,
    AppArmor,
}

#[derive(Debug, Clone)]
pub struct CompiledProfile {
    pub workspace_roots: Vec<String>,
    pub file_allow: Vec<CompiledPathRule>,
    pub file_deny: Vec<CompiledPathRule>,
    pub exec_allow: Vec<CompiledExecRule>,
    pub exec_deny: Vec<CompiledExecRule>,
    pub network_allow: Vec<NetworkRule>,
    pub network_deny: Vec<NetworkRule>,
    pub url_allow: Vec<CompiledUrlRule>,
    pub url_deny: Vec<CompiledUrlRule>,
    pub mcp: Option<CompiledMcpPolicy>,
    pub enforcement: core_types::EnforcementSettings,
}

#[derive(Debug, Clone)]
pub struct CompiledMcpPolicy {
    pub default_tool_action: McpToolAction,
    pub default_rule_id: String,
    pub default_resource_action: McpToolAction,
    pub default_resource_rule_id: String,
    pub servers: Vec<CompiledMcpServer>,
}

#[derive(Debug, Clone)]
pub struct CompiledMcpServer {
    pub id: String,
    pub transport: McpTransport,
    pub exec_path_glob: Option<String>,
    pub exec_path_matcher: Option<GlobMatcher>,
    pub base_url: Option<String>,
    pub default_tool_action: Option<McpToolAction>,
    pub default_rule_id: Option<String>,
    pub default_resource_action: Option<McpToolAction>,
    pub default_resource_rule_id: Option<String>,
    pub tool_rules: HashMap<String, CompiledMcpToolRule>,
    pub resource_rules: Vec<CompiledMcpResourceRule>,
}

#[derive(Debug, Clone)]
pub struct CompiledMcpToolRule {
    pub action: McpToolAction,
    pub rule_id: String,
}

#[derive(Debug, Clone)]
pub struct CompiledMcpResourceRule {
    pub pattern: String,
    pub matcher: GlobMatcher,
    pub action: McpToolAction,
    pub rule_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpEvaluationDecision {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpEvaluationResult {
    pub decision: McpEvaluationDecision,
    pub rule_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CompiledPathRule {
    pub id: String,
    pub pattern: String,
    pub matcher: GlobMatcher,
    /// When the source pattern ends in `/**`, this holds the directory
    /// portion (without the trailing `/**`). The rule then also matches
    /// the directory itself, so `ls <dir>` and `stat <dir>` are blocked
    /// — otherwise `<dir>/**` would let you enumerate names even though
    /// every entry's contents are denied.
    pub dir_self_match: Option<String>,
}

impl CompiledPathRule {
    pub fn is_match(&self, path: &str) -> bool {
        if self.matcher.is_match(path) {
            return true;
        }
        if let Some(dir) = self.dir_self_match.as_deref() {
            // Match both `/foo/bar` and `/foo/bar/` so getattr/readdir on
            // the directory itself is covered regardless of how the
            // kernel renders the path.
            let trimmed = path.strip_suffix('/').unwrap_or(path);
            if trimmed == dir {
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone)]
pub struct CompiledExecRule {
    pub id: String,
    pub path: String,
    pub matcher: GlobMatcher,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledUrlScheme {
    Http,
    Https,
    Any,
}

#[derive(Debug, Clone)]
pub struct CompiledUrlRule {
    pub id: String,
    pub scheme: Option<CompiledUrlScheme>,
    pub host_glob: String,
    pub host_matcher: GlobMatcher,
    pub port: Option<u16>,
    pub method: Option<String>,
    pub path_glob: String,
    pub path_matcher: GlobMatcher,
    pub query_glob: Option<String>,
    pub query_matcher: Option<GlobMatcher>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineOptions {
    pub policy_unavailable_mode: FailMode,
    /// Maximum number of rules per class (file_allow, file_deny, etc.).
    pub max_rules_per_class: usize,
    /// Maximum number of profiles the eBPF kernel can hold.
    pub max_profiles: usize,
    /// Maximum number of workspace roots per profile.
    pub max_workspace_roots: usize,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            policy_unavailable_mode: FailMode::FailClosed,
            #[cfg(feature = "linux")]
            max_rules_per_class: kernel_ebpf::MAX_RULES_PER_CLASS,
            #[cfg(not(feature = "linux"))]
            max_rules_per_class: MAX_KERNEL_RULES_PER_CLASS,
            #[cfg(feature = "linux")]
            max_profiles: kernel_ebpf::MAX_PROFILES as usize,
            #[cfg(not(feature = "linux"))]
            max_profiles: MAX_PROFILES,
            #[cfg(feature = "linux")]
            max_workspace_roots: kernel_ebpf::MAX_WORKSPACE_ROOTS,
            #[cfg(not(feature = "linux"))]
            max_workspace_roots: 64,
        }
    }
}

#[derive(Debug)]
pub struct PolicyEngine {
    policy: Option<CompiledPolicy>,
    options: EngineOptions,
}

impl PolicyEngine {
    pub fn new(options: EngineOptions) -> Self {
        Self {
            policy: None,
            options,
        }
    }

    pub fn with_policy(policy: CompiledPolicy, options: EngineOptions) -> Self {
        Self {
            policy: Some(policy),
            options,
        }
    }

    pub fn set_policy(&mut self, policy: CompiledPolicy) {
        self.policy = Some(policy);
    }

    /// Return the configured kernel limits from this engine's options.
    pub fn kernel_limits(&self) -> (usize, usize, usize) {
        (
            self.options.max_rules_per_class,
            self.options.max_profiles,
            self.options.max_workspace_roots,
        )
    }

    pub fn policy_version(&self) -> Option<&str> {
        self.policy.as_ref().map(|p| p.version.as_str())
    }

    pub fn evaluate(&self, profile: &str, action: &Action) -> DecisionResult {
        let Some(policy) = self.policy.as_ref() else {
            return match self.options.policy_unavailable_mode {
                FailMode::FailOpen => DecisionResult {
                    decision: Decision::Allow,
                    reason: DecisionReason::AllowFailOpen,
                    rule_id: None,
                },
                FailMode::FailClosed => DecisionResult {
                    decision: Decision::Deny,
                    reason: DecisionReason::DenyFailClosed,
                    rule_id: None,
                },
            };
        };

        let Some(compiled_profile) = policy.profiles.get(profile) else {
            return DecisionResult {
                decision: Decision::Deny,
                reason: DecisionReason::DenyByDefault,
                rule_id: None,
            };
        };

        let evaluated = evaluate_profile(policy, compiled_profile, action);

        if evaluated.decision == Decision::Deny {
            let mode = match action.action_type.class() {
                ActionClass::File => compiled_profile.enforcement.file,
                ActionClass::Process => compiled_profile.enforcement.process,
                ActionClass::Network => compiled_profile.enforcement.network,
                ActionClass::Mcp | ActionClass::System => return evaluated,
            };

            if mode == EnforcementMode::Observe {
                return DecisionResult {
                    decision: Decision::Allow,
                    reason: DecisionReason::AllowByObserveMode,
                    rule_id: evaluated.rule_id,
                };
            }
        }

        evaluated
    }

    pub fn evaluate_mcp_tool_call(
        &self,
        profile: &str,
        resource: &McpToolResource,
    ) -> McpEvaluationResult {
        let Some(policy) = self.policy.as_ref() else {
            return match self.options.policy_unavailable_mode {
                FailMode::FailOpen => McpEvaluationResult {
                    decision: McpEvaluationDecision::Allow,
                    rule_id: None,
                },
                FailMode::FailClosed => McpEvaluationResult {
                    decision: McpEvaluationDecision::Deny,
                    rule_id: None,
                },
            };
        };

        let Some(compiled_profile) = policy.profiles.get(profile) else {
            return McpEvaluationResult {
                decision: McpEvaluationDecision::Deny,
                rule_id: None,
            };
        };

        evaluate_mcp(compiled_profile, resource)
    }

    pub fn evaluate_mcp_resource_read(
        &self,
        profile: &str,
        resource: &McpResourceReadResource,
    ) -> McpEvaluationResult {
        let Some(policy) = self.policy.as_ref() else {
            return match self.options.policy_unavailable_mode {
                FailMode::FailOpen => McpEvaluationResult {
                    decision: McpEvaluationDecision::Allow,
                    rule_id: None,
                },
                FailMode::FailClosed => McpEvaluationResult {
                    decision: McpEvaluationDecision::Deny,
                    rule_id: None,
                },
            };
        };

        let Some(compiled_profile) = policy.profiles.get(profile) else {
            return McpEvaluationResult {
                decision: McpEvaluationDecision::Deny,
                rule_id: None,
            };
        };

        evaluate_mcp_resource(compiled_profile, resource)
    }
}

fn evaluate_profile(
    policy: &CompiledPolicy,
    profile: &CompiledProfile,
    action: &Action,
) -> DecisionResult {
    match (&action.action_type, &action.resource) {
        (
            ActionType::FileRead
            | ActionType::FileWrite
            | ActionType::FileDelete
            | ActionType::FileMmap
            | ActionType::FileRename
            | ActionType::FileLink
            | ActionType::FileSymlink
            | ActionType::FileMkdir
            | ActionType::FileRmdir
            | ActionType::FileCreate
            | ActionType::FileChmod
            | ActionType::FileChown
            | ActionType::FileTruncate,
            Resource::File(file),
        ) => evaluate_file(policy, profile, file),
        (
            ActionType::ProcExec
            | ActionType::ProcPtrace
            | ActionType::ProcKill
            | ActionType::ProcCapable
            | ActionType::ProcBpf
            | ActionType::ProcModuleLoad
            | ActionType::ProcMount
            | ActionType::ProcUserns,
            Resource::Exec(exec_resource),
        ) => evaluate_exec(policy, profile, &exec_resource.path),
        (
            ActionType::NetConnect
            | ActionType::NetSendmsg
            | ActionType::NetBind
            | ActionType::NetListen
            | ActionType::NetAccept
            | ActionType::NetCreate,
            Resource::Network(network_resource),
        ) => evaluate_network(policy, profile, network_resource),
        (ActionType::McpToolCall, Resource::McpTool(resource)) => {
            let mcp_result = evaluate_mcp(profile, resource);
            match mcp_result.decision {
                McpEvaluationDecision::Allow => DecisionResult {
                    decision: Decision::Allow,
                    reason: DecisionReason::AllowByRule,
                    rule_id: mcp_result.rule_id,
                },
                McpEvaluationDecision::Deny => DecisionResult {
                    decision: Decision::Deny,
                    reason: DecisionReason::DenyByRule,
                    rule_id: mcp_result.rule_id,
                },
                McpEvaluationDecision::RequireApproval => DecisionResult {
                    decision: Decision::Deny,
                    reason: DecisionReason::DenyByRule,
                    rule_id: mcp_result.rule_id,
                },
            }
        }
        (ActionType::McpResourceRead, Resource::McpResource(resource)) => {
            let mcp_result = evaluate_mcp_resource(profile, resource);
            match mcp_result.decision {
                McpEvaluationDecision::Allow => DecisionResult {
                    decision: Decision::Allow,
                    reason: DecisionReason::AllowByRule,
                    rule_id: mcp_result.rule_id,
                },
                McpEvaluationDecision::Deny => DecisionResult {
                    decision: Decision::Deny,
                    reason: DecisionReason::DenyByRule,
                    rule_id: mcp_result.rule_id,
                },
                McpEvaluationDecision::RequireApproval => DecisionResult {
                    decision: Decision::Deny,
                    reason: DecisionReason::DenyByRule,
                    rule_id: mcp_result.rule_id,
                },
            }
        }
        _ => DecisionResult {
            decision: Decision::Deny,
            reason: DecisionReason::ErrorInvalidAction,
            rule_id: None,
        },
    }
}

fn evaluate_mcp(profile: &CompiledProfile, resource: &McpToolResource) -> McpEvaluationResult {
    let Some(mcp_policy) = profile.mcp.as_ref() else {
        return McpEvaluationResult {
            decision: McpEvaluationDecision::Allow,
            rule_id: None,
        };
    };

    if let Some(server) = mcp_policy
        .servers
        .iter()
        .find(|server| server.id == resource.server_id && server.transport == resource.transport)
    {
        if let Some(rule) = server.tool_rules.get(resource.tool_name.as_str()) {
            return McpEvaluationResult {
                decision: map_mcp_tool_action(rule.action),
                rule_id: Some(rule.rule_id.clone()),
            };
        }

        if let Some(action) = server.default_tool_action {
            return McpEvaluationResult {
                decision: map_mcp_tool_action(action),
                rule_id: server.default_rule_id.clone(),
            };
        }
    }

    McpEvaluationResult {
        decision: map_mcp_tool_action(mcp_policy.default_tool_action),
        rule_id: Some(mcp_policy.default_rule_id.clone()),
    }
}

fn evaluate_mcp_resource(
    profile: &CompiledProfile,
    resource: &McpResourceReadResource,
) -> McpEvaluationResult {
    let Some(mcp_policy) = profile.mcp.as_ref() else {
        return McpEvaluationResult {
            decision: McpEvaluationDecision::Allow,
            rule_id: None,
        };
    };

    if let Some(server) = mcp_policy
        .servers
        .iter()
        .find(|server| server.id == resource.server_id && server.transport == resource.transport)
    {
        for rule in &server.resource_rules {
            if rule.matcher.is_match(resource.uri.as_str()) {
                return McpEvaluationResult {
                    decision: map_mcp_tool_action(rule.action),
                    rule_id: Some(rule.rule_id.clone()),
                };
            }
        }

        if let Some(action) = server.default_resource_action {
            return McpEvaluationResult {
                decision: map_mcp_tool_action(action),
                rule_id: server.default_resource_rule_id.clone(),
            };
        }
    }

    McpEvaluationResult {
        decision: map_mcp_tool_action(mcp_policy.default_resource_action),
        rule_id: Some(mcp_policy.default_resource_rule_id.clone()),
    }
}

fn map_mcp_tool_action(action: McpToolAction) -> McpEvaluationDecision {
    match action {
        McpToolAction::Allow => McpEvaluationDecision::Allow,
        McpToolAction::Deny => McpEvaluationDecision::Deny,
        McpToolAction::RequireApproval => McpEvaluationDecision::RequireApproval,
    }
}

fn evaluate_file(
    policy: &CompiledPolicy,
    profile: &CompiledProfile,
    file: &FileResource,
) -> DecisionResult {
    let path = file.resolved_path.as_deref().unwrap_or(file.path.as_str());
    let normalized = normalize_path(path);

    for rule in &profile.file_deny {
        if rule.is_match(&normalized) {
            return DecisionResult {
                decision: Decision::Deny,
                reason: DecisionReason::DenyByRule,
                rule_id: Some(rule.id.clone()),
            };
        }
    }

    for rule in &profile.file_allow {
        if rule.is_match(&normalized) {
            return DecisionResult {
                decision: Decision::Allow,
                reason: DecisionReason::AllowByRule,
                rule_id: Some(rule.id.clone()),
            };
        }
    }

    if !profile.workspace_roots.is_empty() {
        let in_workspace = profile
            .workspace_roots
            .iter()
            .any(|root| is_path_within_root(&normalized, root));

        if in_workspace {
            return DecisionResult {
                decision: Decision::Allow,
                reason: DecisionReason::AllowByRule,
                rule_id: Some("workspace_root".to_string()),
            };
        }
    }

    default_decision(&policy.defaults)
}

fn evaluate_exec(
    policy: &CompiledPolicy,
    profile: &CompiledProfile,
    executable_path: &str,
) -> DecisionResult {
    let normalized = normalize_path(executable_path);

    for rule in &profile.exec_deny {
        if rule.matcher.is_match(&normalized) {
            return DecisionResult {
                decision: Decision::Deny,
                reason: DecisionReason::DenyByRule,
                rule_id: Some(rule.id.clone()),
            };
        }
    }

    for rule in &profile.exec_allow {
        if rule.matcher.is_match(&normalized) {
            return DecisionResult {
                decision: Decision::Allow,
                reason: DecisionReason::AllowByRule,
                rule_id: Some(rule.id.clone()),
            };
        }
    }

    default_decision(&policy.defaults)
}

fn evaluate_network(
    policy: &CompiledPolicy,
    profile: &CompiledProfile,
    resource: &core_types::NetworkResource,
) -> DecisionResult {
    if has_url_context(resource) {
        for rule in &profile.url_deny {
            if url_rule_matches(rule, resource) {
                return DecisionResult {
                    decision: Decision::Deny,
                    reason: DecisionReason::DenyByRule,
                    rule_id: Some(rule.id.clone()),
                };
            }
        }

        for rule in &profile.url_allow {
            if url_rule_matches(rule, resource) {
                return DecisionResult {
                    decision: Decision::Allow,
                    reason: DecisionReason::AllowByRule,
                    rule_id: Some(rule.id.clone()),
                };
            }
        }
    }

    for rule in &profile.network_deny {
        if network_rule_matches(rule, resource) {
            return DecisionResult {
                decision: Decision::Deny,
                reason: DecisionReason::DenyByRule,
                rule_id: Some(rule.id.clone()),
            };
        }
    }

    for rule in &profile.network_allow {
        if network_rule_matches(rule, resource) {
            return DecisionResult {
                decision: Decision::Allow,
                reason: DecisionReason::AllowByRule,
                rule_id: Some(rule.id.clone()),
            };
        }
    }

    default_decision(&policy.defaults)
}

fn network_rule_matches(rule: &NetworkRule, resource: &core_types::NetworkResource) -> bool {
    if let Some(protocol) = rule.protocol
        && protocol != resource.protocol
    {
        return false;
    }

    if let Some(port) = rule.port
        && port != resource.dest_port
    {
        return false;
    }

    if let Some(cidr) = &rule.cidr {
        let Some(dest_ip) = &resource.dest_ip else {
            return false;
        };
        let Ok(parsed): Result<std::net::IpAddr, _> = dest_ip.parse() else {
            return false;
        };
        if !cidr.contains(&parsed) {
            return false;
        }
    }

    if let Some(host_glob) = &rule.host_glob {
        let Some(host) = resource.dest_host.as_deref() else {
            return false;
        };

        let Ok(glob) = Glob::new(host_glob) else {
            return false;
        };
        if !glob.compile_matcher().is_match(host) {
            return false;
        }
    }

    true
}

fn has_url_context(resource: &core_types::NetworkResource) -> bool {
    resource.full_url.is_some()
        || resource.scheme.is_some()
        || resource.method.is_some()
        || resource.path.is_some()
        || resource.query.is_some()
}

fn url_rule_matches(rule: &CompiledUrlRule, resource: &core_types::NetworkResource) -> bool {
    let Some(host) = resource.dest_host.as_deref() else {
        return false;
    };

    if !rule.host_matcher.is_match(host) {
        return false;
    }

    if let Some(port) = rule.port
        && port != resource.dest_port
    {
        return false;
    }

    if let Some(expected_method) = rule.method.as_deref() {
        let Some(method) = resource.method.as_deref() else {
            return false;
        };
        if !method.eq_ignore_ascii_case(expected_method) {
            return false;
        }
    }

    if let Some(expected_scheme) = rule.scheme {
        let Some(actual_scheme) = resource.scheme.as_deref() else {
            return false;
        };
        let normalized = normalize_url_scheme(actual_scheme);
        let Some(normalized) = normalized else {
            return false;
        };
        match expected_scheme {
            CompiledUrlScheme::Any => {}
            CompiledUrlScheme::Http if normalized != CompiledUrlScheme::Http => return false,
            CompiledUrlScheme::Https if normalized != CompiledUrlScheme::Https => return false,
            _ => {}
        }
    }

    let path = resource.path.as_deref().unwrap_or("/");
    if !rule.path_matcher.is_match(path) {
        return false;
    }

    if let Some(query_matcher) = rule.query_matcher.as_ref() {
        let query = resource.query.as_deref().unwrap_or("");
        if !query_matcher.is_match(query) {
            return false;
        }
    }

    true
}

fn default_decision(defaults: &PolicyDefaults) -> DecisionResult {
    match defaults.decision {
        DefaultDecision::Allow => DecisionResult {
            decision: Decision::Allow,
            reason: DecisionReason::AllowByDefault,
            rule_id: None,
        },
        DefaultDecision::Deny => DecisionResult {
            decision: Decision::Deny,
            reason: DecisionReason::DenyByDefault,
            rule_id: None,
        },
    }
}

pub fn load_policy_from_path(
    path: impl AsRef<Path>,
    signature_verification: SignatureVerification,
) -> Result<LoadedPolicy, PolicyError> {
    let raw = fs::read_to_string(path).map_err(PolicyError::Io)?;
    load_policy_from_str(&raw, signature_verification)
}

pub fn load_policy_from_str(
    raw: &str,
    signature_verification: SignatureVerification,
) -> Result<LoadedPolicy, PolicyError> {
    let mut document_value: serde_yaml::Value =
        serde_yaml::from_str(raw).map_err(PolicyError::Deserialize)?;
    reject_unsupported_top_level_rules(&document_value)?;

    // Verify HMAC-SHA256 before full parsing so tampered content never reaches compile_policy.
    if let SignatureVerification::RequireValid { hmac_key } = &signature_verification {
        let sig_hex = document_value
            .get("signature")
            .and_then(|s| s.get("sig"))
            .and_then(|s| s.as_str())
            .map(|s| s.trim().to_string())
            .ok_or_else(|| {
                PolicyError::Signature(
                    "signature verification required but signature.sig is missing".to_string(),
                )
            })?;

        let sig_bytes = hex::decode(&sig_hex).map_err(|_| {
            PolicyError::Signature("signature.sig is not valid lowercase hex".to_string())
        })?;
        if sig_bytes.len() != 32 {
            return Err(PolicyError::Signature(
                "signature.sig must be 64 hex characters (HMAC-SHA256 output)".to_string(),
            ));
        }

        // Canonical signed content: policy YAML with the `signature:` block removed.
        if let serde_yaml::Value::Mapping(ref mut map) = document_value {
            map.remove(serde_yaml::Value::String("signature".to_string()));
        }
        let canonical = serde_yaml::to_string(&document_value)
            .map_err(|e| PolicyError::Signature(format!("canonicalize policy content: {e}")))?;

        {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            use subtle::ConstantTimeEq;
            let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key.as_slice())
                .map_err(|_| PolicyError::Signature("signing key must not be empty".to_string()))?;
            mac.update(canonical.as_bytes());
            let expected: [u8; 32] = mac.finalize().into_bytes().into();
            let sig_array: [u8; 32] = sig_bytes.as_slice().try_into().unwrap();
            if sig_array.ct_eq(&expected).unwrap_u8() != 1 {
                return Err(PolicyError::Signature(
                    "HMAC-SHA256 signature verification failed: signature does not match policy content".to_string(),
                ));
            }
        }

        // Re-parse so the signature block is available for validate_document().
        document_value = serde_yaml::from_str(raw).map_err(PolicyError::Deserialize)?;
    }

    let document: PolicyDocument =
        serde_yaml::from_value(document_value).map_err(PolicyError::Deserialize)?;
    validate_document(&document)?;

    let mut warnings = Vec::new();

    match (&signature_verification, &document.signature) {
        (SignatureVerification::Disabled, _) => {}
        (SignatureVerification::WarnOnInvalid, Some(signature)) => {
            if signature.sig.trim().is_empty() {
                warnings.push("policy signature is present but empty".to_string());
            }
        }
        (SignatureVerification::WarnOnInvalid, None) => {
            warnings.push("policy signature is missing (allowed by configuration)".to_string());
        }
        (SignatureVerification::RequireValid { .. }, _) => {
            // Already verified above.
        }
    }

    let compiled = compile_policy(document)?;
    Ok(LoadedPolicy { compiled, warnings })
}

fn reject_unsupported_top_level_rules(document: &serde_yaml::Value) -> Result<(), PolicyError> {
    let serde_yaml::Value::Mapping(mapping) = document else {
        return Ok(());
    };

    if mapping
        .keys()
        .any(|key| matches!(key, serde_yaml::Value::String(value) if value == "rules"))
    {
        return Err(PolicyError::Validation(
            "top-level 'rules' is no longer supported; define rules directly under profiles"
                .to_string(),
        ));
    }

    Ok(())
}

/// Validate that a compiled policy does not exceed the configured kernel limits.
pub fn validate_policy_limits(
    policy: &CompiledPolicy,
    options: &EngineOptions,
) -> Result<(), PolicyError> {
    if policy.profiles.len() > options.max_profiles {
        return Err(PolicyError::Compile(format!(
            "policy has {} profiles but the configured kernel limit is {} (max_profiles);              reduce the number of profiles or recompile the eBPF kernel with a larger limit",
            policy.profiles.len(),
            options.max_profiles
        )));
    }
    for (name, profile) in &policy.profiles {
        let max_rpc = options.max_rules_per_class;
        let checks = [
            ("file_allow", profile.file_allow.len()),
            ("file_deny", profile.file_deny.len()),
            ("exec_allow", profile.exec_allow.len()),
            ("exec_deny", profile.exec_deny.len()),
            ("network_allow", profile.network_allow.len()),
            ("network_deny", profile.network_deny.len()),
        ];
        for (class, count) in checks {
            if count > max_rpc {
                return Err(PolicyError::Compile(format!(
                    "profile '{name}': {class} has {count} rules but the configured kernel limit                      is {max_rpc} (max_rules_per_class); reduce rules or recompile the eBPF kernel",
                )));
            }
        }
        let max_ws = options.max_workspace_roots;
        if profile.workspace_roots.len() > max_ws {
            return Err(PolicyError::Compile(format!(
                "profile '{name}': has {} workspace roots but the configured kernel limit                  is {max_ws} (max_workspace_roots); reduce workspace roots or recompile the eBPF kernel",
                profile.workspace_roots.len(),
            )));
        }
    }
    Ok(())
}

pub fn compile_kernel_ir(policy: &CompiledPolicy) -> Result<KernelPolicyIr, PolicyError> {
    compile_kernel_ir_for_backend(policy, FilesystemPolicyBackend::EbpfLsm)
}

pub fn compile_kernel_ir_for_backend(
    policy: &CompiledPolicy,
    filesystem_backend: FilesystemPolicyBackend,
) -> Result<KernelPolicyIr, PolicyError> {
    if policy.profiles.len() > MAX_PROFILES {
        return Err(PolicyError::Compile(format!(
            "kernel profile count {} exceeds MAX_PROFILES={MAX_PROFILES}",
            policy.profiles.len()
        )));
    }

    let mut profiles = HashMap::with_capacity(policy.profiles.len());
    for (name, profile) in &policy.profiles {
        enforce_rule_limits(name, profile, filesystem_backend)?;
        enforce_path_limits(name, profile, filesystem_backend)?;

        let compiled = KernelProfileIr {
            workspace_roots: profile.workspace_roots.clone(),
            file_allow: profile
                .file_allow
                .iter()
                .map(|r| KernelPathRuleIr {
                    id: r.id.clone(),
                    pattern: r.pattern.clone(),
                })
                .collect(),
            file_deny: profile
                .file_deny
                .iter()
                .map(|r| KernelPathRuleIr {
                    id: r.id.clone(),
                    pattern: r.pattern.clone(),
                })
                .collect(),
            exec_allow: profile
                .exec_allow
                .iter()
                .map(|r| KernelExecRuleIr {
                    id: r.id.clone(),
                    path: r.path.clone(),
                })
                .collect(),
            exec_deny: profile
                .exec_deny
                .iter()
                .map(|r| KernelExecRuleIr {
                    id: r.id.clone(),
                    path: r.path.clone(),
                })
                .collect(),
            network_allow: profile.network_allow.clone(),
            network_deny: profile.network_deny.clone(),
            url_allow: profile
                .url_allow
                .iter()
                .map(|rule| UrlRule {
                    id: rule.id.clone(),
                    scheme: rule.scheme.map(|s| match s {
                        CompiledUrlScheme::Http => "http".to_string(),
                        CompiledUrlScheme::Https => "https".to_string(),
                        CompiledUrlScheme::Any => "*".to_string(),
                    }),
                    host_glob: rule.host_glob.clone(),
                    port: rule.port,
                    method: rule.method.clone(),
                    path_glob: rule.path_glob.clone(),
                    query_glob: rule.query_glob.clone(),
                })
                .collect(),
            url_deny: profile
                .url_deny
                .iter()
                .map(|rule| UrlRule {
                    id: rule.id.clone(),
                    scheme: rule.scheme.map(|s| match s {
                        CompiledUrlScheme::Http => "http".to_string(),
                        CompiledUrlScheme::Https => "https".to_string(),
                        CompiledUrlScheme::Any => "*".to_string(),
                    }),
                    host_glob: rule.host_glob.clone(),
                    port: rule.port,
                    method: rule.method.clone(),
                    path_glob: rule.path_glob.clone(),
                    query_glob: rule.query_glob.clone(),
                })
                .collect(),
            enforcement: profile.enforcement.clone(),
        };
        profiles.insert(name.clone(), compiled);
    }

    Ok(KernelPolicyIr {
        version: policy.version.clone(),
        defaults: policy.defaults.clone(),
        profile_count: policy.profiles.len() as u32,
        max_path_bytes: MAX_PATH_BYTES as u32,
        max_rules_per_class: MAX_KERNEL_RULES_PER_CLASS as u32,
        profiles,
    })
}

fn enforce_rule_limits(
    profile_name: &str,
    profile: &CompiledProfile,
    filesystem_backend: FilesystemPolicyBackend,
) -> Result<(), PolicyError> {
    // These rule classes are enforced by the BPF kernel and stored in fixed-size maps.
    // url_allow / url_deny are enforced by the URL proxy (userspace-only), not the BPF program,
    // so they are NOT checked here — they get a separate, much higher limit from kernel-matcher.
    let mut kernel_checks = vec![
        ("network_allow", profile.network_allow.len()),
        ("network_deny", profile.network_deny.len()),
    ];
    if filesystem_backend == FilesystemPolicyBackend::EbpfLsm {
        kernel_checks.push(("exec_allow", profile.exec_allow.len()));
        kernel_checks.push(("exec_deny", profile.exec_deny.len()));
        kernel_checks.push(("file_allow", profile.file_allow.len()));
        kernel_checks.push(("file_deny", profile.file_deny.len()));
    }

    for (class, count) in kernel_checks {
        if count > MAX_KERNEL_RULES_PER_CLASS {
            return Err(PolicyError::Compile(format!(
                "profile {profile_name}: {class} count {count} exceeds kernel limit MAX_KERNEL_RULES_PER_CLASS={MAX_KERNEL_RULES_PER_CLASS}"
            )));
        }
    }

    // URL rules live in the URL proxy only — enforce against the soft limit.
    #[cfg(feature = "linux")]
    const MAX_URL_RULES: usize = kernel_matcher::MAX_RULES_PER_CLASS;
    #[cfg(not(feature = "linux"))]
    const MAX_URL_RULES: usize = 1024;
    let url_checks = [
        ("url_allow", profile.url_allow.len()),
        ("url_deny", profile.url_deny.len()),
    ];
    for (class, count) in url_checks {
        if count > MAX_URL_RULES {
            return Err(PolicyError::Compile(format!(
                "profile {profile_name}: {class} count {count} exceeds url proxy limit MAX_URL_RULES={MAX_URL_RULES}"
            )));
        }
    }

    Ok(())
}

fn enforce_path_limits(
    profile_name: &str,
    profile: &CompiledProfile,
    filesystem_backend: FilesystemPolicyBackend,
) -> Result<(), PolicyError> {
    if filesystem_backend == FilesystemPolicyBackend::EbpfLsm {
        for root in &profile.workspace_roots {
            if root.len() > MAX_PATH_BYTES {
                return Err(PolicyError::Compile(format!(
                    "profile {profile_name}: workspace root length exceeds MAX_PATH_BYTES={MAX_PATH_BYTES}"
                )));
            }
        }

        for rule in &profile.file_allow {
            if rule.pattern.len() > MAX_PATH_BYTES {
                return Err(PolicyError::Compile(format!(
                    "profile {profile_name}: file_allow rule '{}' length exceeds MAX_PATH_BYTES={MAX_PATH_BYTES}",
                    rule.id
                )));
            }
        }
        for rule in &profile.file_deny {
            if rule.pattern.len() > MAX_PATH_BYTES {
                return Err(PolicyError::Compile(format!(
                    "profile {profile_name}: file_deny rule '{}' length exceeds MAX_PATH_BYTES={MAX_PATH_BYTES}",
                    rule.id
                )));
            }
        }
        for rule in &profile.exec_allow {
            if rule.path.len() > MAX_PATH_BYTES {
                return Err(PolicyError::Compile(format!(
                    "profile {profile_name}: exec_allow rule '{}' length exceeds MAX_PATH_BYTES={MAX_PATH_BYTES}",
                    rule.id
                )));
            }
        }
        for rule in &profile.exec_deny {
            if rule.path.len() > MAX_PATH_BYTES {
                return Err(PolicyError::Compile(format!(
                    "profile {profile_name}: exec_deny rule '{}' length exceeds MAX_PATH_BYTES={MAX_PATH_BYTES}",
                    rule.id
                )));
            }
        }
    }

    Ok(())
}

fn compile_policy(document: PolicyDocument) -> Result<CompiledPolicy, PolicyError> {
    let mut profiles = HashMap::new();

    for (name, profile) in document.profiles {
        let compiled_profile = compile_profile(name.as_str(), &document.defaults, profile)?;
        profiles.insert(name, compiled_profile);
    }

    Ok(CompiledPolicy {
        version: document.version,
        defaults: document.defaults,
        profiles,
    })
}

fn compile_profile(
    profile_name: &str,
    defaults: &PolicyDefaults,
    profile: ProfilePolicy,
) -> Result<CompiledProfile, PolicyError> {
    let file_allow = compile_path_rules(&profile.file_allow)
        .map_err(|e| PolicyError::Compile(format!("profile {profile_name}: {e}")))?;
    let file_deny = compile_path_rules(&profile.file_deny)
        .map_err(|e| PolicyError::Compile(format!("profile {profile_name}: {e}")))?;
    let exec_allow = compile_exec_rules(&profile.exec_allow)
        .map_err(|e| PolicyError::Compile(format!("profile {profile_name}: {e}")))?;
    let exec_deny = compile_exec_rules(&profile.exec_deny)
        .map_err(|e| PolicyError::Compile(format!("profile {profile_name}: {e}")))?;
    let url_allow = compile_url_rules(&profile.url_allow)
        .map_err(|e| PolicyError::Compile(format!("profile {profile_name}: {e}")))?;
    let url_deny = compile_url_rules(&profile.url_deny)
        .map_err(|e| PolicyError::Compile(format!("profile {profile_name}: {e}")))?;
    let mcp = profile
        .mcp
        .map(|mcp| compile_mcp_policy(profile_name, mcp))
        .transpose()?;

    let enforcement = profile
        .enforcement
        .unwrap_or_else(|| defaults.enforcement.clone());
    validate_enforcement_settings(profile_name, &enforcement)?;

    Ok(CompiledProfile {
        workspace_roots: profile
            .workspace_roots
            .into_iter()
            .map(|r| normalize_path(&r))
            .collect(),
        file_allow,
        file_deny,
        exec_allow,
        exec_deny,
        network_allow: profile.network_allow,
        network_deny: profile.network_deny,
        url_allow,
        url_deny,
        mcp,
        enforcement,
    })
}

fn validate_enforcement_settings(
    profile_name: &str,
    enforcement: &core_types::EnforcementSettings,
) -> Result<(), PolicyError> {
    if enforcement.file != enforcement.process {
        return Err(PolicyError::Compile(format!(
            "profile {profile_name}: enforcement.file and enforcement.process must match"
        )));
    }

    Ok(())
}

fn compile_mcp_policy(
    profile_name: &str,
    policy: McpPolicy,
) -> Result<CompiledMcpPolicy, PolicyError> {
    let default_tool_action = policy.default_tool_action.unwrap_or(McpToolAction::Deny);
    let default_resource_action = policy
        .default_resource_action
        .unwrap_or(McpToolAction::Deny);
    let mut servers = Vec::with_capacity(policy.servers.len());
    for server in policy.servers {
        servers.push(compile_mcp_server(profile_name, server)?);
    }

    Ok(CompiledMcpPolicy {
        default_tool_action,
        default_rule_id: "mcp_default_tool_action".to_string(),
        default_resource_action,
        default_resource_rule_id: "mcp_default_resource_action".to_string(),
        servers,
    })
}

fn compile_mcp_server(
    profile_name: &str,
    server: McpServerPolicy,
) -> Result<CompiledMcpServer, PolicyError> {
    let exec_path_matcher = match server.exec_path_glob.as_ref() {
        Some(exec_path_glob) => Some(
            Glob::new(exec_path_glob.as_str())
                .map_err(|err| {
                    PolicyError::Compile(format!(
                        "profile {profile_name}: invalid MCP exec_path_glob '{}' for server '{}': {err}",
                        exec_path_glob, server.id
                    ))
                })?
                .compile_matcher(),
        ),
        None => None,
    };

    let tool_rules = compile_mcp_tool_rules(server.id.as_str(), &server.tools);
    let resource_rules = compile_mcp_resource_rules(server.id.as_str(), &server.resources)?;

    Ok(CompiledMcpServer {
        id: server.id.clone(),
        transport: server.transport,
        exec_path_glob: server.exec_path_glob,
        exec_path_matcher,
        base_url: server.base_url,
        default_tool_action: server.default_tool_action,
        default_rule_id: server
            .default_tool_action
            .map(|_| format!("mcp_server_{}_default_tool_action", server.id)),
        default_resource_action: server.default_resource_action,
        default_resource_rule_id: server
            .default_resource_action
            .map(|_| format!("mcp_server_{}_default_resource_action", server.id)),
        tool_rules,
        resource_rules,
    })
}

fn compile_mcp_tool_rules(
    server_id: &str,
    tools: &McpToolPolicy,
) -> HashMap<String, CompiledMcpToolRule> {
    let mut compiled = HashMap::new();

    for tool_name in &tools.allow {
        compiled.insert(
            tool_name.clone(),
            CompiledMcpToolRule {
                action: McpToolAction::Allow,
                rule_id: format!("mcp_server_{server_id}_tool_allow_{tool_name}"),
            },
        );
    }
    for tool_name in &tools.deny {
        compiled.insert(
            tool_name.clone(),
            CompiledMcpToolRule {
                action: McpToolAction::Deny,
                rule_id: format!("mcp_server_{server_id}_tool_deny_{tool_name}"),
            },
        );
    }
    for tool_name in &tools.require_approval {
        compiled.insert(
            tool_name.clone(),
            CompiledMcpToolRule {
                action: McpToolAction::RequireApproval,
                rule_id: format!("mcp_server_{server_id}_tool_require_approval_{tool_name}"),
            },
        );
    }

    compiled
}

fn compile_mcp_resource_rules(
    server_id: &str,
    resources: &McpResourcePolicy,
) -> Result<Vec<CompiledMcpResourceRule>, PolicyError> {
    let mut compiled = Vec::new();

    for (action, values, action_name) in [
        (McpToolAction::Allow, &resources.allow, "allow"),
        (McpToolAction::Deny, &resources.deny, "deny"),
        (
            McpToolAction::RequireApproval,
            &resources.require_approval,
            "require_approval",
        ),
    ] {
        for pattern in values {
            let matcher = Glob::new(pattern.as_str())
                .map_err(|err| {
                    PolicyError::Compile(format!(
                        "invalid MCP resource glob '{}' for server '{}': {err}",
                        pattern, server_id
                    ))
                })?
                .compile_matcher();
            compiled.push(CompiledMcpResourceRule {
                pattern: pattern.clone(),
                matcher,
                action,
                rule_id: format!(
                    "mcp_server_{server_id}_resource_{action_name}_{}",
                    sanitize_rule_component(pattern)
                ),
            });
        }
    }

    Ok(compiled)
}

fn compile_path_rules(rules: &[core_types::PathRule]) -> Result<Vec<CompiledPathRule>, String> {
    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules {
        let glob = Glob::new(&rule.pattern)
            .map_err(|e| format!("invalid path glob '{}': {e}", rule.pattern))?;
        let dir_self_match = rule
            .pattern
            .strip_suffix("/**")
            .filter(|dir| !dir.is_empty() && !dir.contains(['*', '?', '[']))
            .map(str::to_string);
        compiled.push(CompiledPathRule {
            id: rule.id.clone(),
            pattern: rule.pattern.clone(),
            matcher: glob.compile_matcher(),
            dir_self_match,
        });
    }
    Ok(compiled)
}

fn compile_exec_rules(rules: &[ExecRule]) -> Result<Vec<CompiledExecRule>, String> {
    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules {
        let glob =
            Glob::new(&rule.path).map_err(|e| format!("invalid exec glob '{}': {e}", rule.path))?;
        compiled.push(CompiledExecRule {
            id: rule.id.clone(),
            path: rule.path.clone(),
            matcher: glob.compile_matcher(),
        });
    }
    Ok(compiled)
}

fn compile_url_rules(rules: &[UrlRule]) -> Result<Vec<CompiledUrlRule>, String> {
    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules {
        let host_glob = rule.host_glob.trim();
        if host_glob.is_empty() {
            return Err(format!("url rule '{}' has an empty host_glob", rule.id));
        }
        let host_matcher = Glob::new(host_glob)
            .map_err(|e| format!("invalid url host glob '{}': {e}", rule.host_glob))?
            .compile_matcher();

        let path_glob = rule.path_glob.trim();
        if path_glob.is_empty() {
            return Err(format!("url rule '{}' has an empty path_glob", rule.id));
        }
        let path_matcher = Glob::new(path_glob)
            .map_err(|e| format!("invalid url path glob '{}': {e}", rule.path_glob))?
            .compile_matcher();

        let query_matcher = match rule.query_glob.as_ref() {
            Some(query_glob) => Some(
                Glob::new(query_glob)
                    .map_err(|e| format!("invalid url query glob '{}': {e}", query_glob))?
                    .compile_matcher(),
            ),
            None => None,
        };

        let scheme = match rule.scheme.as_deref() {
            Some(raw) => Some(normalize_url_scheme(raw).ok_or_else(|| {
                format!(
                    "url rule '{}' has unsupported scheme '{}'; expected http, https, or *",
                    rule.id, raw
                )
            })?),
            None => None,
        };

        let method = rule
            .method
            .as_ref()
            .map(|method| method.trim().to_ascii_uppercase())
            .filter(|method| !method.is_empty());

        compiled.push(CompiledUrlRule {
            id: rule.id.clone(),
            scheme,
            host_glob: rule.host_glob.clone(),
            host_matcher,
            port: rule.port,
            method,
            path_glob: rule.path_glob.clone(),
            path_matcher,
            query_glob: rule.query_glob.clone(),
            query_matcher,
        });
    }
    Ok(compiled)
}

fn normalize_url_scheme(raw: &str) -> Option<CompiledUrlScheme> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "http" => Some(CompiledUrlScheme::Http),
        "https" => Some(CompiledUrlScheme::Https),
        "*" | "any" => Some(CompiledUrlScheme::Any),
        _ => None,
    }
}

fn validate_document(document: &PolicyDocument) -> Result<(), PolicyError> {
    if document.version != API_VERSION {
        return Err(PolicyError::Core(CoreError::PolicyVersionMismatch {
            expected: API_VERSION,
            got: document.version.clone(),
        }));
    }

    if document.profiles.is_empty() {
        return Err(PolicyError::Validation(
            "at least one profile is required".to_string(),
        ));
    }

    for (profile_name, profile) in &document.profiles {
        validate_profile(profile_name, profile)?;
    }

    Ok(())
}

fn validate_profile(profile_name: &str, profile: &ProfilePolicy) -> Result<(), PolicyError> {
    for root in &profile.workspace_roots {
        // Accept both platform-native absolute paths and Unix-style absolute paths
        // (policies may be authored on one platform and applied on another).
        let is_abs = std::path::Path::new(root).is_absolute() || root.starts_with('/');
        if !is_abs {
            return Err(PolicyError::Validation(format!(
                "profile {profile_name}: workspace root '{root}' must be absolute"
            )));
        }
    }

    let mut ids = HashSet::new();
    for rule in &profile.file_allow {
        validate_unique_id(profile_name, &mut ids, &rule.id)?;
    }
    for rule in &profile.file_deny {
        validate_unique_id(profile_name, &mut ids, &rule.id)?;
    }
    for rule in &profile.exec_allow {
        validate_unique_id(profile_name, &mut ids, &rule.id)?;
    }
    for rule in &profile.exec_deny {
        validate_unique_id(profile_name, &mut ids, &rule.id)?;
    }
    for rule in &profile.network_allow {
        validate_unique_id(profile_name, &mut ids, &rule.id)?;
        validate_network_rule(profile_name, rule)?;
    }
    for rule in &profile.network_deny {
        validate_unique_id(profile_name, &mut ids, &rule.id)?;
        validate_network_rule(profile_name, rule)?;
    }
    for rule in &profile.url_allow {
        validate_unique_id(profile_name, &mut ids, &rule.id)?;
        validate_url_rule(profile_name, rule)?;
    }
    for rule in &profile.url_deny {
        validate_unique_id(profile_name, &mut ids, &rule.id)?;
        validate_url_rule(profile_name, rule)?;
    }
    if let Some(mcp) = profile.mcp.as_ref() {
        validate_mcp_policy(profile_name, mcp)?;
    }

    // Network rules that match on host_glob are only evaluated by the URL gateway
    // (url_enforce=true). If the profile has no url_allow/url_deny rules, url_enforce will be
    // false and every host_glob network rule is silently unenforced at the kernel level.
    let has_host_glob_net_rule = profile
        .network_allow
        .iter()
        .chain(profile.network_deny.iter())
        .any(|r| r.host_glob.is_some());
    let has_url_rules = !profile.url_allow.is_empty() || !profile.url_deny.is_empty();
    if has_host_glob_net_rule && !has_url_rules {
        return Err(PolicyError::Validation(format!(
            "profile {profile_name}: network rules with `host_glob` are only enforced by \
             the URL gateway. Add at least one url_allow or url_deny rule to activate URL \
             enforcement, or replace `host_glob` with a `cidr` rule."
        )));
    }

    Ok(())
}

fn validate_mcp_policy(profile_name: &str, policy: &McpPolicy) -> Result<(), PolicyError> {
    let mut server_ids = HashSet::new();

    for server in &policy.servers {
        let server_id = server.id.trim();
        if server_id.is_empty() {
            return Err(PolicyError::Validation(format!(
                "profile {profile_name}: MCP server id cannot be empty"
            )));
        }
        if !server_ids.insert(server_id.to_string()) {
            return Err(PolicyError::Validation(format!(
                "profile {profile_name}: duplicate MCP server id '{server_id}'"
            )));
        }
        match server.transport {
            McpTransport::Stdio => {
                let Some(exec_path_glob) = server.exec_path_glob.as_ref() else {
                    return Err(PolicyError::Validation(format!(
                        "profile {profile_name}: MCP server '{}' with transport 'stdio' requires exec_path_glob",
                        server.id
                    )));
                };
                if !exec_path_glob.starts_with('/')
                    && !std::path::Path::new(exec_path_glob).is_absolute()
                {
                    return Err(PolicyError::Validation(format!(
                        "profile {profile_name}: MCP server '{}' exec_path_glob '{}' must be absolute",
                        server.id, exec_path_glob
                    )));
                }
                Glob::new(exec_path_glob.as_str()).map_err(|err| {
                    PolicyError::Validation(format!(
                        "profile {profile_name}: invalid MCP exec_path_glob '{}' for server '{}': {err}",
                        exec_path_glob, server.id
                    ))
                })?;
            }
            McpTransport::Http => {
                let Some(base_url) = server.base_url.as_ref() else {
                    return Err(PolicyError::Validation(format!(
                        "profile {profile_name}: MCP server '{}' with transport 'http' requires base_url",
                        server.id
                    )));
                };
                let normalized = base_url.trim().to_ascii_lowercase();
                if !(normalized.starts_with("http://") || normalized.starts_with("https://")) {
                    return Err(PolicyError::Validation(format!(
                        "profile {profile_name}: MCP server '{}' base_url '{}' must start with http:// or https://",
                        server.id, base_url
                    )));
                }
            }
        }
        validate_mcp_tools(profile_name, server.id.as_str(), &server.tools)?;
        validate_mcp_resources(profile_name, server.id.as_str(), &server.resources)?;
    }

    Ok(())
}

fn validate_mcp_tools(
    profile_name: &str,
    server_id: &str,
    tools: &McpToolPolicy,
) -> Result<(), PolicyError> {
    let mut seen = HashMap::new();
    for (action_name, values) in [
        ("allow", &tools.allow),
        ("deny", &tools.deny),
        ("require_approval", &tools.require_approval),
    ] {
        for tool_name in values {
            let trimmed = tool_name.trim();
            if trimmed.is_empty() {
                return Err(PolicyError::Validation(format!(
                    "profile {profile_name}: MCP server '{server_id}' has an empty tool name in '{action_name}'"
                )));
            }
            if let Some(previous) = seen.insert(trimmed.to_string(), action_name) {
                return Err(PolicyError::Validation(format!(
                    "profile {profile_name}: MCP server '{server_id}' tool '{trimmed}' overlaps between '{previous}' and '{action_name}'"
                )));
            }
        }
    }

    Ok(())
}

fn validate_mcp_resources(
    profile_name: &str,
    server_id: &str,
    resources: &McpResourcePolicy,
) -> Result<(), PolicyError> {
    let mut seen = HashMap::new();
    for (action_name, values) in [
        ("allow", &resources.allow),
        ("deny", &resources.deny),
        ("require_approval", &resources.require_approval),
    ] {
        for resource_uri in values {
            let trimmed = resource_uri.trim();
            if trimmed.is_empty() {
                return Err(PolicyError::Validation(format!(
                    "profile {profile_name}: MCP server '{server_id}' has an empty resource uri glob in '{action_name}'"
                )));
            }
            Glob::new(trimmed).map_err(|err| {
                PolicyError::Validation(format!(
                    "profile {profile_name}: invalid MCP resource glob '{}' for server '{}': {err}",
                    trimmed, server_id
                ))
            })?;
            if let Some(previous) = seen.insert(trimmed.to_string(), action_name) {
                return Err(PolicyError::Validation(format!(
                    "profile {profile_name}: MCP server '{server_id}' resource glob '{trimmed}' overlaps between '{previous}' and '{action_name}'"
                )));
            }
        }
    }

    Ok(())
}

fn validate_unique_id(
    profile_name: &str,
    ids: &mut HashSet<String>,
    id: &str,
) -> Result<(), PolicyError> {
    if id.trim().is_empty() {
        return Err(PolicyError::Validation(format!(
            "profile {profile_name}: rule id cannot be empty"
        )));
    }

    if !ids.insert(id.to_string()) {
        return Err(PolicyError::Validation(format!(
            "profile {profile_name}: duplicate rule id '{id}'"
        )));
    }

    Ok(())
}

fn validate_network_rule(profile_name: &str, rule: &NetworkRule) -> Result<(), PolicyError> {
    if rule.host_glob.is_none() && rule.cidr.is_none() {
        return Err(PolicyError::Validation(format!(
            "profile {profile_name}: network rule '{}' must set host_glob or cidr",
            rule.id
        )));
    }

    if let Some(host_glob) = &rule.host_glob {
        Glob::new(host_glob).map_err(|e| {
            PolicyError::Validation(format!(
                "profile {profile_name}: invalid host glob '{}' for rule '{}': {e}",
                host_glob, rule.id
            ))
        })?;
    }

    Ok(())
}

fn validate_url_rule(profile_name: &str, rule: &UrlRule) -> Result<(), PolicyError> {
    if rule.host_glob.trim().is_empty() {
        return Err(PolicyError::Validation(format!(
            "profile {profile_name}: url rule '{}' must set host_glob",
            rule.id
        )));
    }
    if rule.path_glob.trim().is_empty() {
        return Err(PolicyError::Validation(format!(
            "profile {profile_name}: url rule '{}' must set path_glob",
            rule.id
        )));
    }

    Glob::new(rule.host_glob.as_str()).map_err(|e| {
        PolicyError::Validation(format!(
            "profile {profile_name}: invalid url host_glob '{}' for rule '{}': {e}",
            rule.host_glob, rule.id
        ))
    })?;

    Glob::new(rule.path_glob.as_str()).map_err(|e| {
        PolicyError::Validation(format!(
            "profile {profile_name}: invalid url path_glob '{}' for rule '{}': {e}",
            rule.path_glob, rule.id
        ))
    })?;

    if let Some(query_glob) = rule.query_glob.as_ref() {
        Glob::new(query_glob).map_err(|e| {
            PolicyError::Validation(format!(
                "profile {profile_name}: invalid url query_glob '{}' for rule '{}': {e}",
                query_glob, rule.id
            ))
        })?;
    }

    if let Some(scheme) = rule.scheme.as_deref()
        && normalize_url_scheme(scheme).is_none()
    {
        return Err(PolicyError::Validation(format!(
            "profile {profile_name}: invalid url scheme '{}' for rule '{}'; expected http, https, or *",
            scheme, rule.id
        )));
    }

    if let Some(method) = rule.method.as_ref() {
        let valid = method
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_');
        if method.trim().is_empty() || !valid {
            return Err(PolicyError::Validation(format!(
                "profile {profile_name}: invalid url method '{}' for rule '{}'",
                method, rule.id
            )));
        }
    }

    Ok(())
}

fn normalize_path(path: &str) -> String {
    let mut parts = Vec::new();
    let absolute = path.starts_with('/');

    for component in Path::new(path).components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                if !parts.is_empty() {
                    parts.pop();
                }
            }
            Component::Normal(segment) => {
                parts.push(segment.to_string_lossy().to_string());
            }
            Component::Prefix(_) => {}
        }
    }

    if absolute {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    }
}

fn sanitize_rule_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    out.trim_matches('_').to_string()
}

fn is_path_within_root(path: &str, root: &str) -> bool {
    let root = normalize_path(root);
    let path = normalize_path(path);
    if root == "/" {
        return path.starts_with('/');
    }
    path == root || path.starts_with(&(root + "/"))
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("io: {0}")]
    Io(std::io::Error),
    #[error("yaml parse: {0}")]
    Deserialize(serde_yaml::Error),
    #[error("core: {0}")]
    Core(#[from] CoreError),
    #[error("validation: {0}")]
    Validation(String),
    #[error("compile: {0}")]
    Compile(String),
    #[error("signature: {0}")]
    Signature(String),
}

pub fn canonicalize_for_enforcement(path: &Path) -> std::io::Result<PathBuf> {
    path.canonicalize()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use core_types::{
        ActionContext, EnforcementSettings, ExecResource, FileOp, FileResource,
        McpResourceReadResource, McpToolResource, McpTransport, NetworkProtocol, NetworkResource,
        Resource,
    };

    use super::*;

    const POLICY: &str = r#"
version: v1
defaults:
  decision: deny
  fail_mode: fail_closed
  audit_level: all
  enforcement:
    file: enforce
    process: enforce
    network: enforce
profiles:
  default:
    workspace_roots:
      - /workspace
    file_allow:
      - id: file_allow_workspace
        pattern: /workspace/**
    file_deny:
      - id: file_deny_secret
        pattern: /workspace/secret/**
    exec_allow:
      - id: exec_allow_echo
        path: /usr/bin/echo
    exec_deny:
      - id: exec_deny_rm
        path: /bin/rm
    network_allow:
      - id: net_allow_local
        cidr: 127.0.0.1/32
        protocol: TCP
    network_deny:
      - id: net_deny_bad
        host_glob: "*.evil.example"
    url_deny:
      - id: url_deny_evil_domain
        host_glob: "*.evil.example"
        path_glob: "/**"
"#;

    fn context() -> ActionContext {
        ActionContext {
            timestamp: Utc::now(),
            agent_id: "agent-1".to_string(),
            pid: 100,
            ppid: 1,
            uid: 1000,
            profile: "default".to_string(),
        }
    }

    #[test]
    fn deny_overrides_allow_for_files() {
        let loaded = load_policy_from_str(POLICY, SignatureVerification::Disabled).expect("load");
        let engine = PolicyEngine::with_policy(loaded.compiled, EngineOptions::default());

        let action = Action {
            action_type: ActionType::FileRead,
            context: context(),
            resource: Resource::File(FileResource {
                path: "/workspace/secret/data.txt".to_string(),
                resolved_path: None,
                op: FileOp::Read,
                source_path: None,
            }),
        };

        let result = engine.evaluate("default", &action);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.reason, DecisionReason::DenyByRule);
        assert_eq!(result.rule_id.as_deref(), Some("file_deny_secret"));
    }

    #[test]
    fn dir_self_is_denied_when_pattern_ends_in_double_star() {
        // `<dir>/**` must also block accessing the dir itself, otherwise
        // `ls /workspace/secret/` (readdir) leaks every entry name.
        let loaded = load_policy_from_str(POLICY, SignatureVerification::Disabled).expect("load");
        let engine = PolicyEngine::with_policy(loaded.compiled, EngineOptions::default());

        for path in ["/workspace/secret", "/workspace/secret/"] {
            let action = Action {
                action_type: ActionType::FileRead,
                context: context(),
                resource: Resource::File(FileResource {
                    path: path.to_string(),
                    resolved_path: None,
                    op: FileOp::Read,
                    source_path: None,
                }),
            };
            let result = engine.evaluate("default", &action);
            assert_eq!(result.decision, Decision::Deny, "path={path}");
            assert_eq!(result.rule_id.as_deref(), Some("file_deny_secret"));
        }
    }

    #[test]
    fn dir_self_match_is_not_synthesized_for_bare_or_non_recursive_patterns() {
        // A bare path or a non-recursive glob must NOT silently extend to
        // the parent dir — only `/**` triggers the directory expansion.
        let policy_yaml = r#"
version: v1
defaults:
  decision: allow
profiles:
  default:
    file_deny:
      - id: deny_bare
        pattern: /etc/shadow
      - id: deny_one_level
        pattern: /etc/secrets/*
"#;
        let loaded = load_policy_from_str(policy_yaml, SignatureVerification::Disabled)
            .expect("load policy");
        let profile = &loaded.compiled.profiles["default"];

        let bare = profile
            .file_deny
            .iter()
            .find(|r| r.id == "deny_bare")
            .expect("rule");
        assert!(
            bare.dir_self_match.is_none(),
            "bare-path rule should not expand"
        );

        let one_level = profile
            .file_deny
            .iter()
            .find(|r| r.id == "deny_one_level")
            .expect("rule");
        assert!(
            one_level.dir_self_match.is_none(),
            "/* (single-level) should not expand to parent dir"
        );
    }

    #[test]
    fn default_deny_for_unmatched_action() {
        let loaded = load_policy_from_str(POLICY, SignatureVerification::Disabled).expect("load");
        let engine = PolicyEngine::with_policy(loaded.compiled, EngineOptions::default());

        let action = Action {
            action_type: ActionType::ProcExec,
            context: context(),
            resource: Resource::Exec(ExecResource {
                path: "/usr/bin/python3".to_string(),
                argv_hash: None,
                cwd: "/workspace".to_string(),
                argv: Vec::new(),
                argv_truncated: false,
            }),
        };

        let result = engine.evaluate("default", &action);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.reason, DecisionReason::DenyByDefault);
    }

    #[test]
    fn observe_mode_allows_with_reason() {
        let loaded = load_policy_from_str(POLICY, SignatureVerification::Disabled).expect("load");
        let mut policy = loaded.compiled;
        let profile = policy
            .profiles
            .get_mut("default")
            .expect("default profile exists");
        profile.enforcement = EnforcementSettings {
            file: EnforcementMode::Observe,
            process: EnforcementMode::Observe,
            network: EnforcementMode::Enforce,
        };

        let engine = PolicyEngine::with_policy(policy, EngineOptions::default());

        let action = Action {
            action_type: ActionType::FileRead,
            context: context(),
            resource: Resource::File(FileResource {
                path: "/etc/shadow".to_string(),
                resolved_path: None,
                op: FileOp::Read,
                source_path: None,
            }),
        };

        let result = engine.evaluate("default", &action);
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.reason, DecisionReason::AllowByObserveMode);
    }

    #[test]
    fn policy_rejects_mismatched_file_and_process_enforcement() {
        let err = load_policy_from_str(
            r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    enforcement:
      file: enforce
      process: observe
      network: enforce
"#,
            SignatureVerification::Disabled,
        )
        .expect_err("mixed enforcement should be rejected");

        assert!(
            err.to_string()
                .contains("enforcement.file and enforcement.process must match")
        );
    }

    #[test]
    fn default_allow_uses_allow_by_default_reason() {
        let policy = r#"
version: v1
defaults:
  decision: allow
profiles:
  default:
    workspace_roots:
      - /workspace
"#;

        let loaded = load_policy_from_str(policy, SignatureVerification::Disabled).expect("load");
        let engine = PolicyEngine::with_policy(loaded.compiled, EngineOptions::default());

        let action = Action {
            action_type: ActionType::ProcExec,
            context: context(),
            resource: Resource::Exec(ExecResource {
                path: "/usr/bin/python3".to_string(),
                argv_hash: None,
                cwd: "/workspace".to_string(),
                argv: Vec::new(),
                argv_truncated: false,
            }),
        };

        let result = engine.evaluate("default", &action);
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.reason, DecisionReason::AllowByDefault);
        assert!(result.rule_id.is_none());
    }

    #[test]
    fn network_allow_and_deny() {
        let loaded = load_policy_from_str(POLICY, SignatureVerification::Disabled).expect("load");
        let engine = PolicyEngine::with_policy(loaded.compiled, EngineOptions::default());

        let deny_action = Action {
            action_type: ActionType::NetConnect,
            context: context(),
            resource: Resource::Network(NetworkResource {
                dest_host: Some("api.evil.example".to_string()),
                dest_ip: Some("203.0.113.10".to_string()),
                dest_port: 443,
                protocol: NetworkProtocol::Tcp,
                full_url: None,
                scheme: None,
                method: None,
                path: None,
                query: None,
                socket_path: None,
                family: None,
            }),
        };
        let deny_result = engine.evaluate("default", &deny_action);
        assert_eq!(deny_result.decision, Decision::Deny);
        assert_eq!(deny_result.rule_id.as_deref(), Some("net_deny_bad"));

        let allow_action = Action {
            action_type: ActionType::NetConnect,
            context: context(),
            resource: Resource::Network(NetworkResource {
                dest_host: Some("localhost".to_string()),
                dest_ip: Some("127.0.0.1".to_string()),
                dest_port: 8080,
                protocol: NetworkProtocol::Tcp,
                full_url: None,
                scheme: None,
                method: None,
                path: None,
                query: None,
                socket_path: None,
                family: None,
            }),
        };
        let allow_result = engine.evaluate("default", &allow_action);
        assert_eq!(allow_result.decision, Decision::Allow);
        assert_eq!(allow_result.rule_id.as_deref(), Some("net_allow_local"));
    }

    #[test]
    fn url_rules_apply_with_deny_precedence() {
        let policy = r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    network_allow:
      - id: net_allow_proxy
        cidr: 127.0.0.1/32
        protocol: TCP
    url_allow:
      - id: allow_docs
        scheme: https
        host_glob: docs.example.com
        method: GET
        path_glob: /v1/**
    url_deny:
      - id: deny_admin
        scheme: https
        host_glob: docs.example.com
        path_glob: /v1/admin/**
"#;

        let loaded = load_policy_from_str(policy, SignatureVerification::Disabled).expect("load");
        let engine = PolicyEngine::with_policy(loaded.compiled, EngineOptions::default());

        let denied = Action {
            action_type: ActionType::NetConnect,
            context: context(),
            resource: Resource::Network(NetworkResource {
                dest_host: Some("docs.example.com".to_string()),
                dest_ip: None,
                dest_port: 443,
                protocol: NetworkProtocol::Tcp,
                full_url: Some("https://docs.example.com/v1/admin/keys".to_string()),
                scheme: Some("https".to_string()),
                method: Some("GET".to_string()),
                path: Some("/v1/admin/keys".to_string()),
                query: None,
                socket_path: None,
                family: None,
            }),
        };
        let denied_result = engine.evaluate("default", &denied);
        assert_eq!(denied_result.decision, Decision::Deny);
        assert_eq!(denied_result.rule_id.as_deref(), Some("deny_admin"));

        let allowed = Action {
            action_type: ActionType::NetConnect,
            context: context(),
            resource: Resource::Network(NetworkResource {
                dest_host: Some("docs.example.com".to_string()),
                dest_ip: None,
                dest_port: 443,
                protocol: NetworkProtocol::Tcp,
                full_url: Some("https://docs.example.com/v1/reference".to_string()),
                scheme: Some("https".to_string()),
                method: Some("GET".to_string()),
                path: Some("/v1/reference".to_string()),
                query: None,
                socket_path: None,
                family: None,
            }),
        };
        let allowed_result = engine.evaluate("default", &allowed);
        assert_eq!(allowed_result.decision, Decision::Allow);
        assert_eq!(allowed_result.rule_id.as_deref(), Some("allow_docs"));
    }

    #[test]
    fn url_rules_support_query_and_method_matching() {
        let policy = r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    url_allow:
      - id: allow_reports
        scheme: https
        host_glob: api.example.com
        method: POST
        path_glob: /reports/**
        query_glob: token=*
"#;

        let loaded = load_policy_from_str(policy, SignatureVerification::Disabled).expect("load");
        let engine = PolicyEngine::with_policy(loaded.compiled, EngineOptions::default());

        let allow_action = Action {
            action_type: ActionType::NetConnect,
            context: context(),
            resource: Resource::Network(NetworkResource {
                dest_host: Some("api.example.com".to_string()),
                dest_ip: None,
                dest_port: 443,
                protocol: NetworkProtocol::Tcp,
                full_url: Some("https://api.example.com/reports/generate?token=abc".to_string()),
                scheme: Some("https".to_string()),
                method: Some("POST".to_string()),
                path: Some("/reports/generate".to_string()),
                query: Some("token=abc".to_string()),
                socket_path: None,
                family: None,
            }),
        };
        let allow_result = engine.evaluate("default", &allow_action);
        assert_eq!(allow_result.decision, Decision::Allow);
        assert_eq!(allow_result.rule_id.as_deref(), Some("allow_reports"));

        let deny_action = Action {
            action_type: ActionType::NetConnect,
            context: context(),
            resource: Resource::Network(NetworkResource {
                dest_host: Some("api.example.com".to_string()),
                dest_ip: None,
                dest_port: 443,
                protocol: NetworkProtocol::Tcp,
                full_url: Some("https://api.example.com/reports/generate?missing=1".to_string()),
                scheme: Some("https".to_string()),
                method: Some("POST".to_string()),
                path: Some("/reports/generate".to_string()),
                query: Some("missing=1".to_string()),
                socket_path: None,
                family: None,
            }),
        };
        let deny_result = engine.evaluate("default", &deny_action);
        assert_eq!(deny_result.decision, Decision::Deny);
        assert_eq!(deny_result.reason, DecisionReason::DenyByDefault);
    }

    #[test]
    fn host_glob_network_rule_without_url_rules_is_rejected() {
        let bad = r#"
version: v1
profiles:
  default:
    network_deny:
      - id: deny_hosts
        host_glob: "*.corp.internal"
"#;
        let err =
            load_policy_from_str(bad, SignatureVerification::Disabled).expect_err("should reject");
        assert!(
            err.to_string().contains("host_glob"),
            "error should mention host_glob: {err}"
        );
    }

    #[test]
    fn policy_signature_hmac_verified() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let raw = r#"
version: v1
profiles:
  default:
    workspace_roots:
      - /workspace
"#;

        // Parse the policy, remove signature block (none here — just test the signing logic)
        let key = b"test-key-32-bytes-padded-to-size!!";
        let mut value: serde_yaml::Value = serde_yaml::from_str(raw).unwrap();
        let canonical = serde_yaml::to_string(&value).unwrap();

        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(canonical.as_bytes());
        let sig_bytes: [u8; 32] = mac.finalize().into_bytes().into();
        let sig_hex = hex::encode(sig_bytes);

        // Inject signature block into value
        let mut sig_map = serde_yaml::Mapping::new();
        sig_map.insert(
            serde_yaml::Value::String("key_id".to_string()),
            serde_yaml::Value::String("test-key".to_string()),
        );
        sig_map.insert(
            serde_yaml::Value::String("alg".to_string()),
            serde_yaml::Value::String("hmac-sha256".to_string()),
        );
        sig_map.insert(
            serde_yaml::Value::String("sig".to_string()),
            serde_yaml::Value::String(sig_hex.clone()),
        );
        if let serde_yaml::Value::Mapping(ref mut m) = value {
            m.insert(
                serde_yaml::Value::String("signature".to_string()),
                serde_yaml::Value::Mapping(sig_map),
            );
        }
        let signed_yaml = serde_yaml::to_string(&value).unwrap();

        // Valid key → accepted
        let result = load_policy_from_str(
            &signed_yaml,
            SignatureVerification::RequireValid {
                hmac_key: key.to_vec(),
            },
        );
        assert!(
            result.is_ok(),
            "valid signature should be accepted: {:?}",
            result
        );

        // Wrong key → rejected
        let result = load_policy_from_str(
            &signed_yaml,
            SignatureVerification::RequireValid {
                hmac_key: b"wrong-key".to_vec(),
            },
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HMAC"));
    }

    #[test]
    fn invalid_policy_rejected() {
        let bad = r#"
version: v1
profiles:
  default:
    network_allow:
      - id: bad
"#;

        let result = load_policy_from_str(bad, SignatureVerification::Disabled);
        assert!(result.is_err());
    }

    #[test]
    fn top_level_rules_are_rejected() {
        let bad = r#"
version: v1
rules:
  - id: shared
    description: no longer supported
profiles:
  default:
    workspace_roots:
      - /workspace
"#;

        let err = load_policy_from_str(bad, SignatureVerification::Disabled).expect_err("reject");
        assert!(
            err.to_string()
                .contains("top-level 'rules' is no longer supported")
        );
    }

    #[test]
    fn policy_unavailable_uses_fail_mode() {
        let engine_closed = PolicyEngine::new(EngineOptions {
            policy_unavailable_mode: FailMode::FailClosed,
            ..EngineOptions::default()
        });
        let action = Action {
            action_type: ActionType::FileRead,
            context: context(),
            resource: Resource::File(FileResource {
                path: "/tmp/test".to_string(),
                resolved_path: None,
                op: FileOp::Read,
                source_path: None,
            }),
        };
        let deny = engine_closed.evaluate("default", &action);
        assert_eq!(deny.decision, Decision::Deny);
        assert_eq!(deny.reason, DecisionReason::DenyFailClosed);

        let engine_open = PolicyEngine::new(EngineOptions {
            policy_unavailable_mode: FailMode::FailOpen,
            ..EngineOptions::default()
        });
        let allow = engine_open.evaluate("default", &action);
        assert_eq!(allow.decision, Decision::Allow);
        assert_eq!(allow.reason, DecisionReason::AllowFailOpen);
    }

    #[test]
    fn workspace_boundary_and_escape_checks() {
        assert!(is_path_within_root("/workspace/app/file.txt", "/workspace"));
        assert!(!is_path_within_root(
            "/workspace-other/file.txt",
            "/workspace"
        ));

        let normalized = normalize_path("/workspace/../etc/passwd");
        assert_eq!(normalized, "/etc/passwd");
    }

    #[test]
    fn compile_kernel_ir_success() {
        let loaded = load_policy_from_str(POLICY, SignatureVerification::Disabled).expect("load");
        let ir = compile_kernel_ir(&loaded.compiled).expect("compile kernel ir");
        assert_eq!(ir.version, "v1");
        assert_eq!(ir.profile_count, 1);
        assert!(ir.profiles.contains_key("default"));
    }

    #[test]
    fn compile_kernel_ir_rejects_oversized_path_rule() {
        let mut policy = load_policy_from_str(POLICY, SignatureVerification::Disabled)
            .expect("load")
            .compiled;
        let profile = policy.profiles.get_mut("default").expect("default profile");

        profile.file_allow[0].pattern = format!("/workspace/{}", "a".repeat(MAX_PATH_BYTES));

        let err = compile_kernel_ir(&policy).expect_err("should reject oversized path");
        assert!(err.to_string().contains("MAX_PATH_BYTES"));
    }

    #[test]
    fn compile_kernel_ir_apparmor_backend_skips_file_path_limit() {
        let mut policy = load_policy_from_str(POLICY, SignatureVerification::Disabled)
            .expect("load")
            .compiled;
        let profile = policy.profiles.get_mut("default").expect("default profile");
        profile.file_allow[0].pattern = format!("/workspace/{}", "a".repeat(MAX_PATH_BYTES));

        let ir = compile_kernel_ir_for_backend(&policy, FilesystemPolicyBackend::AppArmor)
            .expect("compile AppArmor backend IR");
        assert_eq!(ir.version, "v1");
    }

    #[test]
    fn compile_kernel_ir_apparmor_backend_skips_exec_path_limit() {
        let mut policy = load_policy_from_str(POLICY, SignatureVerification::Disabled)
            .expect("load")
            .compiled;
        let profile = policy.profiles.get_mut("default").expect("default profile");
        profile.exec_allow[0].path = format!("/usr/bin/{}", "a".repeat(MAX_PATH_BYTES));

        let ir = compile_kernel_ir_for_backend(&policy, FilesystemPolicyBackend::AppArmor)
            .expect("compile AppArmor backend IR");
        assert_eq!(ir.version, "v1");
    }

    #[test]
    fn mcp_policy_evaluates_allow_require_approval_and_default_deny() {
        let policy = r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    mcp:
      default_tool_action: deny
      servers:
        - id: github
          transport: stdio
          exec_path_glob: /usr/local/bin/github-mcp*
          default_tool_action: require_approval
          tools:
            allow: [list_repos]
            deny: [delete_repo]
"#;

        let loaded = load_policy_from_str(policy, SignatureVerification::Disabled).expect("load");
        let engine = PolicyEngine::with_policy(loaded.compiled, EngineOptions::default());

        let allow = engine.evaluate_mcp_tool_call(
            "default",
            &McpToolResource {
                server_id: "github".to_string(),
                transport: McpTransport::Stdio,
                tool_name: "list_repos".to_string(),
                tool_call_id: "call-1".to_string(),
                mcp_session_id: "session-1".to_string(),
                arguments_sha256: "abc".to_string(),
                arguments_summary: None,
            },
        );
        assert_eq!(allow.decision, McpEvaluationDecision::Allow);
        assert_eq!(
            allow.rule_id.as_deref(),
            Some("mcp_server_github_tool_allow_list_repos")
        );

        let approval = engine.evaluate_mcp_tool_call(
            "default",
            &McpToolResource {
                server_id: "github".to_string(),
                transport: McpTransport::Stdio,
                tool_name: "create_pull_request".to_string(),
                tool_call_id: "call-2".to_string(),
                mcp_session_id: "session-1".to_string(),
                arguments_sha256: "def".to_string(),
                arguments_summary: None,
            },
        );
        assert_eq!(approval.decision, McpEvaluationDecision::RequireApproval);
        assert_eq!(
            approval.rule_id.as_deref(),
            Some("mcp_server_github_default_tool_action")
        );

        let deny = engine.evaluate_mcp_tool_call(
            "default",
            &McpToolResource {
                server_id: "unknown".to_string(),
                transport: McpTransport::Stdio,
                tool_name: "anything".to_string(),
                tool_call_id: "call-3".to_string(),
                mcp_session_id: "session-1".to_string(),
                arguments_sha256: "ghi".to_string(),
                arguments_summary: None,
            },
        );
        assert_eq!(deny.decision, McpEvaluationDecision::Deny);
        assert_eq!(deny.rule_id.as_deref(), Some("mcp_default_tool_action"));
    }

    #[test]
    fn mcp_http_resource_policy_evaluates_resource_rules() {
        let policy = r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    mcp:
      default_tool_action: deny
      default_resource_action: deny
      servers:
        - id: docs
          transport: http
          base_url: https://mcp.example.test
          default_resource_action: require_approval
          resources:
            allow: [repo://openai/mercury/issues/**]
            deny: [repo://openai/mercury/secrets/**]
"#;

        let loaded = load_policy_from_str(policy, SignatureVerification::Disabled).expect("load");
        let engine = PolicyEngine::with_policy(loaded.compiled, EngineOptions::default());

        let allow = engine.evaluate_mcp_resource_read(
            "default",
            &McpResourceReadResource {
                server_id: "docs".to_string(),
                transport: McpTransport::Http,
                uri: "repo://openai/mercury/issues/42".to_string(),
                mcp_session_id: "session-1".to_string(),
                request_id: Some("req-1".to_string()),
                resource_call_id: Some("resource-1".to_string()),
            },
        );
        assert_eq!(allow.decision, McpEvaluationDecision::Allow);

        let deny = engine.evaluate_mcp_resource_read(
            "default",
            &McpResourceReadResource {
                server_id: "docs".to_string(),
                transport: McpTransport::Http,
                uri: "repo://openai/mercury/secrets/api-key".to_string(),
                mcp_session_id: "session-1".to_string(),
                request_id: Some("req-2".to_string()),
                resource_call_id: Some("resource-2".to_string()),
            },
        );
        assert_eq!(deny.decision, McpEvaluationDecision::Deny);

        let approval = engine.evaluate_mcp_resource_read(
            "default",
            &McpResourceReadResource {
                server_id: "docs".to_string(),
                transport: McpTransport::Http,
                uri: "repo://openai/mercury/pulls/5".to_string(),
                mcp_session_id: "session-1".to_string(),
                request_id: Some("req-3".to_string()),
                resource_call_id: Some("resource-3".to_string()),
            },
        );
        assert_eq!(approval.decision, McpEvaluationDecision::RequireApproval);
        assert_eq!(
            approval.rule_id.as_deref(),
            Some("mcp_server_docs_default_resource_action")
        );
    }

    #[test]
    fn mcp_http_server_requires_base_url() {
        let policy = r#"
version: v1
profiles:
  default:
    mcp:
      servers:
        - id: docs
          transport: http
"#;

        let err =
            load_policy_from_str(policy, SignatureVerification::Disabled).expect_err("reject");
        assert!(err.to_string().contains("base_url"));
    }

    #[test]
    fn mcp_policy_rejects_overlapping_tool_lists() {
        let policy = r#"
version: v1
defaults:
  decision: deny
profiles:
  default:
    mcp:
      servers:
        - id: github
          transport: stdio
          exec_path_glob: /usr/local/bin/github-mcp*
          tools:
            allow: [list_repos]
            deny: [list_repos]
"#;

        let err =
            load_policy_from_str(policy, SignatureVerification::Disabled).expect_err("reject");
        assert!(
            err.to_string()
                .contains("tool 'list_repos' overlaps between 'allow' and 'deny'")
        );
    }
}
