use std::collections::{BTreeMap, HashSet};

use anyhow::{Context, anyhow, bail};
use core_types::{
    EnforcementMode, EnforcementSettings, ExecRule, NetworkProtocol, NetworkRule, PathRule,
    PolicyDefaults, PolicyDocument, PolicySignature, ProfilePolicy, UrlRule,
};
use ipnet::IpNet;
use policy_engine::{SignatureVerification, load_policy_from_str};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "mercury-policy-patch/v1";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiPolicyPatchDocument {
    pub schema_version: String,
    #[serde(default)]
    pub needs_clarification: bool,
    #[serde(default)]
    pub questions: Vec<String>,
    #[serde(default)]
    pub assumptions: Vec<String>,
    #[serde(alias = "profile")]
    pub target_profile: String,
    #[serde(alias = "patch")]
    pub policy_patch: ProfilePatch,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProfilePatch {
    pub workspace_roots: Option<StringListPatch>,
    pub file_allow: Option<CollectionPatch<PathRuleInput>>,
    pub file_deny: Option<CollectionPatch<PathRuleInput>>,
    pub exec_allow: Option<CollectionPatch<ExecRuleInput>>,
    pub exec_deny: Option<CollectionPatch<ExecRuleInput>>,
    pub network_allow: Option<CollectionPatch<NetworkRuleInput>>,
    pub network_deny: Option<CollectionPatch<NetworkRuleInput>>,
    pub url_allow: Option<CollectionPatch<UrlRuleInput>>,
    pub url_deny: Option<CollectionPatch<UrlRuleInput>>,
    pub enforcement: Option<EnforcementSettingsPatch>,
}

impl ProfilePatch {
    fn is_empty(&self) -> bool {
        self.workspace_roots.is_none()
            && self.file_allow.is_none()
            && self.file_deny.is_none()
            && self.exec_allow.is_none()
            && self.exec_deny.is_none()
            && self.network_allow.is_none()
            && self.network_deny.is_none()
            && self.url_allow.is_none()
            && self.url_deny.is_none()
            && self.enforcement.is_none()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StringListPatch {
    #[serde(default)]
    pub action: CollectionAction,
    #[serde(default)]
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionPatch<T> {
    #[serde(default)]
    pub action: CollectionAction,
    #[serde(default)]
    pub items: Vec<T>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionAction {
    #[default]
    Append,
    Replace,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRuleInput {
    #[serde(default)]
    pub id: Option<String>,
    pub pattern: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecRuleInput {
    #[serde(default)]
    pub id: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRuleInput {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub host_glob: Option<String>,
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlRuleInput {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub scheme: Option<String>,
    pub host_glob: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub method: Option<String>,
    pub path_glob: String,
    #[serde(default)]
    pub query_glob: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementSettingsPatch {
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub process: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RenderResult {
    pub yaml: String,
    pub assumptions: Vec<String>,
    pub target_profile: String,
    pub signature_removed: bool,
}

pub fn render_policy_from_strings(
    policy_raw: &str,
    patch_raw: &str,
    create_profile: bool,
) -> anyhow::Result<RenderResult> {
    load_policy_from_str(policy_raw, SignatureVerification::Disabled)
        .context("validate input Mercury policy")?;
    let mut document: PolicyDocument =
        serde_yaml::from_str(policy_raw).context("parse Mercury policy YAML")?;
    let patch: AiPolicyPatchDocument =
        serde_json::from_str(patch_raw).context("parse AI patch JSON")?;
    validate_patch_document(&patch)?;

    let AiPolicyPatchDocument {
        schema_version: _,
        needs_clarification,
        questions,
        assumptions,
        target_profile,
        policy_patch,
    } = patch;

    if needs_clarification {
        bail!(
            "AI response needs clarification before rendering: {}",
            questions.join(" | ")
        );
    }

    let target_profile = target_profile.trim().to_string();
    {
        let profile = if create_profile {
            document.profiles.entry(target_profile.clone()).or_default()
        } else {
            document
                .profiles
                .get_mut(&target_profile)
                .ok_or_else(|| anyhow!("profile '{}' not found in input policy", target_profile))?
        };

        apply_profile_patch(profile, &document.defaults, policy_patch)?;
    }

    let signature_removed = document.signature.take().is_some();
    let output = OutputPolicyDocument::from(document);
    let yaml = serde_yaml::to_string(&output).context("serialize rendered Mercury policy")?;
    load_policy_from_str(&yaml, SignatureVerification::Disabled)
        .context("validate rendered Mercury policy")?;

    Ok(RenderResult {
        yaml,
        assumptions,
        target_profile,
        signature_removed,
    })
}

fn validate_patch_document(patch: &AiPolicyPatchDocument) -> anyhow::Result<()> {
    if patch.schema_version != SCHEMA_VERSION {
        bail!(
            "unsupported patch schema_version '{}'; expected '{}'",
            patch.schema_version,
            SCHEMA_VERSION
        );
    }

    if patch.target_profile.trim().is_empty() {
        bail!("target_profile must not be empty");
    }

    if patch.needs_clarification {
        if patch.questions.is_empty() {
            bail!("clarification responses must include at least one question");
        }
        if !patch.policy_patch.is_empty() {
            bail!("clarification responses must not include policy_patch changes");
        }
    } else {
        if !patch.questions.is_empty() {
            bail!("non-clarification responses must leave questions empty");
        }
        if patch.policy_patch.is_empty() {
            bail!("policy_patch must include at least one changed section");
        }
    }

    Ok(())
}

fn apply_profile_patch(
    profile: &mut ProfilePolicy,
    defaults: &PolicyDefaults,
    patch: ProfilePatch,
) -> anyhow::Result<()> {
    let mut used_ids = collect_rule_ids(profile);

    apply_workspace_roots(&mut profile.workspace_roots, patch.workspace_roots)?;
    apply_path_rules(
        "file_allow",
        &mut profile.file_allow,
        patch.file_allow,
        &mut used_ids,
    )?;
    apply_path_rules(
        "file_deny",
        &mut profile.file_deny,
        patch.file_deny,
        &mut used_ids,
    )?;
    apply_exec_rules(
        "exec_allow",
        &mut profile.exec_allow,
        patch.exec_allow,
        &mut used_ids,
    )?;
    apply_exec_rules(
        "exec_deny",
        &mut profile.exec_deny,
        patch.exec_deny,
        &mut used_ids,
    )?;
    apply_network_rules(
        "network_allow",
        &mut profile.network_allow,
        patch.network_allow,
        &mut used_ids,
    )?;
    apply_network_rules(
        "network_deny",
        &mut profile.network_deny,
        patch.network_deny,
        &mut used_ids,
    )?;
    apply_url_rules(
        "url_allow",
        &mut profile.url_allow,
        patch.url_allow,
        &mut used_ids,
    )?;
    apply_url_rules(
        "url_deny",
        &mut profile.url_deny,
        patch.url_deny,
        &mut used_ids,
    )?;
    apply_enforcement(&mut profile.enforcement, defaults, patch.enforcement)?;

    Ok(())
}

fn collect_rule_ids(profile: &ProfilePolicy) -> HashSet<String> {
    profile
        .file_allow
        .iter()
        .map(|rule| rule.id.clone())
        .chain(profile.file_deny.iter().map(|rule| rule.id.clone()))
        .chain(profile.exec_allow.iter().map(|rule| rule.id.clone()))
        .chain(profile.exec_deny.iter().map(|rule| rule.id.clone()))
        .chain(profile.network_allow.iter().map(|rule| rule.id.clone()))
        .chain(profile.network_deny.iter().map(|rule| rule.id.clone()))
        .chain(profile.url_allow.iter().map(|rule| rule.id.clone()))
        .chain(profile.url_deny.iter().map(|rule| rule.id.clone()))
        .collect()
}

fn apply_workspace_roots(
    current: &mut Vec<String>,
    patch: Option<StringListPatch>,
) -> anyhow::Result<()> {
    let Some(patch) = patch else {
        return Ok(());
    };

    if patch.action == CollectionAction::Replace {
        current.clear();
    }

    let mut seen: HashSet<String> = current.iter().cloned().collect();
    for root in patch.items {
        let normalized = normalize_workspace_root(&root)?;
        if seen.insert(normalized.clone()) {
            current.push(normalized);
        }
    }

    Ok(())
}

fn apply_path_rules(
    section_name: &'static str,
    current: &mut Vec<PathRule>,
    patch: Option<CollectionPatch<PathRuleInput>>,
    used_ids: &mut HashSet<String>,
) -> anyhow::Result<()> {
    let Some(patch) = patch else {
        return Ok(());
    };

    if patch.action == CollectionAction::Replace {
        release_path_rule_ids(current, used_ids);
        current.clear();
    }

    let mut seen: HashSet<String> = current.iter().map(|rule| rule.pattern.clone()).collect();
    for input in patch.items {
        let pattern = normalize_non_empty(&input.pattern, "path pattern")?;
        if seen.contains(&pattern) {
            continue;
        }
        let id = assign_rule_id(input.id.as_deref(), section_name, &pattern, used_ids);
        current.push(PathRule {
            id,
            pattern: pattern.clone(),
        });
        seen.insert(pattern);
    }

    Ok(())
}

fn apply_exec_rules(
    section_name: &'static str,
    current: &mut Vec<ExecRule>,
    patch: Option<CollectionPatch<ExecRuleInput>>,
    used_ids: &mut HashSet<String>,
) -> anyhow::Result<()> {
    let Some(patch) = patch else {
        return Ok(());
    };

    if patch.action == CollectionAction::Replace {
        release_exec_rule_ids(current, used_ids);
        current.clear();
    }

    let mut seen: HashSet<String> = current.iter().map(|rule| rule.path.clone()).collect();
    for input in patch.items {
        let path = normalize_non_empty(&input.path, "exec path")?;
        if seen.contains(&path) {
            continue;
        }
        let id = assign_rule_id(input.id.as_deref(), section_name, &path, used_ids);
        current.push(ExecRule {
            id,
            path: path.clone(),
        });
        seen.insert(path);
    }

    Ok(())
}

fn apply_network_rules(
    section_name: &'static str,
    current: &mut Vec<NetworkRule>,
    patch: Option<CollectionPatch<NetworkRuleInput>>,
    used_ids: &mut HashSet<String>,
) -> anyhow::Result<()> {
    let Some(patch) = patch else {
        return Ok(());
    };

    if patch.action == CollectionAction::Replace {
        release_network_rule_ids(current, used_ids);
        current.clear();
    }

    let mut seen: HashSet<String> = current.iter().map(network_rule_key).collect();
    for input in patch.items {
        let mut rule = normalize_network_rule(input)?;
        let key = network_rule_key(&rule);
        if seen.contains(&key) {
            continue;
        }
        let provided_id = if rule.id.is_empty() {
            None
        } else {
            Some(rule.id.as_str())
        };
        rule.id = assign_rule_id(
            provided_id,
            section_name,
            &network_rule_slug_hint(&rule),
            used_ids,
        );
        current.push(rule);
        seen.insert(key);
    }

    Ok(())
}

fn apply_url_rules(
    section_name: &'static str,
    current: &mut Vec<UrlRule>,
    patch: Option<CollectionPatch<UrlRuleInput>>,
    used_ids: &mut HashSet<String>,
) -> anyhow::Result<()> {
    let Some(patch) = patch else {
        return Ok(());
    };

    if patch.action == CollectionAction::Replace {
        release_url_rule_ids(current, used_ids);
        current.clear();
    }

    let mut seen: HashSet<String> = current.iter().map(url_rule_key).collect();
    for input in patch.items {
        let mut rule = normalize_url_rule(input)?;
        let key = url_rule_key(&rule);
        if seen.contains(&key) {
            continue;
        }
        let provided_id = if rule.id.is_empty() {
            None
        } else {
            Some(rule.id.as_str())
        };
        rule.id = assign_rule_id(
            provided_id,
            section_name,
            &url_rule_slug_hint(&rule),
            used_ids,
        );
        current.push(rule);
        seen.insert(key);
    }

    Ok(())
}

fn apply_enforcement(
    current: &mut Option<EnforcementSettings>,
    defaults: &PolicyDefaults,
    patch: Option<EnforcementSettingsPatch>,
) -> anyhow::Result<()> {
    let Some(patch) = patch else {
        return Ok(());
    };

    let mut next = current
        .clone()
        .unwrap_or_else(|| defaults.enforcement.clone());

    if let Some(file) = patch.file.as_deref() {
        next.file = parse_enforcement_mode(file)?;
    }
    if let Some(process) = patch.process.as_deref() {
        next.process = parse_enforcement_mode(process)?;
    }
    if let Some(network) = patch.network.as_deref() {
        next.network = parse_enforcement_mode(network)?;
    }

    *current = Some(next);
    Ok(())
}

fn normalize_workspace_root(raw: &str) -> anyhow::Result<String> {
    let mut root = normalize_non_empty(raw, "workspace root")?;
    while root.len() > 1 && root.ends_with('/') {
        root.pop();
    }
    if !root.starts_with('/') {
        bail!("workspace root '{}' must be absolute", root);
    }
    Ok(root)
}

fn normalize_non_empty(raw: &str, field_name: &str) -> anyhow::Result<String> {
    let value = raw.trim();
    if value.is_empty() {
        bail!("{field_name} must not be empty");
    }
    Ok(value.to_string())
}

fn normalize_optional_string(raw: Option<String>) -> Option<String> {
    raw.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn normalize_network_rule(input: NetworkRuleInput) -> anyhow::Result<NetworkRule> {
    let host_glob = normalize_optional_string(input.host_glob);
    let cidr = match normalize_optional_string(input.cidr) {
        Some(cidr) => Some(
            cidr.parse::<IpNet>()
                .with_context(|| format!("invalid CIDR '{}'", cidr))?,
        ),
        None => None,
    };

    if host_glob.is_none() && cidr.is_none() {
        bail!("network rules must set host_glob or cidr");
    }

    let protocol = match normalize_optional_string(input.protocol) {
        Some(protocol) => Some(parse_network_protocol(&protocol)?),
        None => None,
    };

    Ok(NetworkRule {
        id: normalize_optional_string(input.id).unwrap_or_default(),
        host_glob,
        cidr,
        port: input.port,
        protocol,
    })
}

fn normalize_url_rule(input: UrlRuleInput) -> anyhow::Result<UrlRule> {
    let scheme = match normalize_optional_string(input.scheme) {
        Some(scheme) => Some(normalize_scheme(&scheme)?),
        None => None,
    };
    let method = normalize_optional_string(input.method).map(|method| method.to_ascii_uppercase());

    Ok(UrlRule {
        id: normalize_optional_string(input.id).unwrap_or_default(),
        scheme,
        host_glob: normalize_non_empty(&input.host_glob, "url host_glob")?,
        port: input.port,
        method,
        path_glob: normalize_non_empty(&input.path_glob, "url path_glob")?,
        query_glob: normalize_optional_string(input.query_glob),
    })
}

fn parse_network_protocol(raw: &str) -> anyhow::Result<NetworkProtocol> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tcp" => Ok(NetworkProtocol::Tcp),
        "udp" => Ok(NetworkProtocol::Udp),
        other => bail!("unsupported network protocol '{}'", other),
    }
}

fn normalize_scheme(raw: &str) -> anyhow::Result<String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "http" => Ok("http".to_string()),
        "https" => Ok("https".to_string()),
        "*" => Ok("*".to_string()),
        other => bail!("unsupported url scheme '{}'", other),
    }
}

fn parse_enforcement_mode(raw: &str) -> anyhow::Result<EnforcementMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "observe" => Ok(EnforcementMode::Observe),
        "enforce" => Ok(EnforcementMode::Enforce),
        other => bail!("unsupported enforcement mode '{}'", other),
    }
}

fn assign_rule_id(
    provided: Option<&str>,
    section_name: &str,
    slug_hint: &str,
    used_ids: &mut HashSet<String>,
) -> String {
    let normalized_provided = provided
        .map(normalize_rule_id)
        .filter(|value| !value.is_empty());

    let base = normalized_provided
        .unwrap_or_else(|| format!("{}_{}", section_id_prefix(section_name), slugify(slug_hint)));

    let mut candidate = base.clone();
    let mut suffix = 2usize;
    while used_ids.contains(&candidate) {
        candidate = format!("{base}_{suffix}");
        suffix += 1;
    }
    used_ids.insert(candidate.clone());
    candidate
}

fn normalize_rule_id(raw: &str) -> String {
    slugify(raw)
}

fn slugify(raw: &str) -> String {
    let mut slug = String::new();
    let mut last_was_sep = false;

    for ch in raw.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            slug.push(lower);
            last_was_sep = false;
            continue;
        }

        if !last_was_sep && !slug.is_empty() {
            slug.push('_');
            last_was_sep = true;
        }
    }

    while slug.ends_with('_') {
        slug.pop();
    }

    if slug.is_empty() {
        return "rule".to_string();
    }

    const MAX_LEN: usize = 48;
    if slug.len() > MAX_LEN {
        slug.truncate(MAX_LEN);
        while slug.ends_with('_') {
            slug.pop();
        }
    }

    slug
}

fn section_id_prefix(section_name: &str) -> &'static str {
    match section_name {
        "file_allow" => "allow_file",
        "file_deny" => "deny_file",
        "exec_allow" => "allow_exec",
        "exec_deny" => "deny_exec",
        "network_allow" => "allow_net",
        "network_deny" => "deny_net",
        "url_allow" => "allow_url",
        "url_deny" => "deny_url",
        _ => "rule",
    }
}

fn network_rule_key(rule: &NetworkRule) -> String {
    format!(
        "host={:?}|cidr={:?}|port={:?}|protocol={:?}",
        rule.host_glob, rule.cidr, rule.port, rule.protocol
    )
}

fn network_rule_slug_hint(rule: &NetworkRule) -> String {
    let mut parts = Vec::new();
    if let Some(host_glob) = &rule.host_glob {
        parts.push(host_glob.clone());
    }
    if let Some(cidr) = &rule.cidr {
        parts.push(cidr.to_string());
    }
    if let Some(port) = rule.port {
        parts.push(format!("port_{}", port));
    }
    if let Some(protocol) = rule.protocol {
        parts.push(match protocol {
            NetworkProtocol::Tcp => "tcp".to_string(),
            NetworkProtocol::Udp => "udp".to_string(),
        });
    }
    parts.join("_")
}

fn url_rule_key(rule: &UrlRule) -> String {
    format!(
        "scheme={:?}|host={}|port={:?}|method={:?}|path={}|query={:?}",
        rule.scheme, rule.host_glob, rule.port, rule.method, rule.path_glob, rule.query_glob
    )
}

fn url_rule_slug_hint(rule: &UrlRule) -> String {
    let mut parts = Vec::new();
    if let Some(method) = &rule.method {
        parts.push(method.clone());
    }
    parts.push(rule.host_glob.clone());
    parts.push(rule.path_glob.clone());
    parts.join("_")
}

fn release_path_rule_ids(rules: &[PathRule], used_ids: &mut HashSet<String>) {
    for rule in rules {
        used_ids.remove(&rule.id);
    }
}

fn release_exec_rule_ids(rules: &[ExecRule], used_ids: &mut HashSet<String>) {
    for rule in rules {
        used_ids.remove(&rule.id);
    }
}

fn release_network_rule_ids(rules: &[NetworkRule], used_ids: &mut HashSet<String>) {
    for rule in rules {
        used_ids.remove(&rule.id);
    }
}

fn release_url_rule_ids(rules: &[UrlRule], used_ids: &mut HashSet<String>) {
    for rule in rules {
        used_ids.remove(&rule.id);
    }
}

#[derive(Debug, Clone, Serialize)]
struct OutputPolicyDocument {
    version: String,
    defaults: PolicyDefaults,
    profiles: BTreeMap<String, OutputProfilePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<PolicySignature>,
}

impl From<PolicyDocument> for OutputPolicyDocument {
    fn from(document: PolicyDocument) -> Self {
        let profiles = document
            .profiles
            .into_iter()
            .map(|(name, profile)| (name, OutputProfilePolicy::from(profile)))
            .collect();

        Self {
            version: document.version,
            defaults: document.defaults,
            profiles,
            signature: document.signature,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct OutputProfilePolicy {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    workspace_roots: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    file_allow: Vec<PathRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    file_deny: Vec<PathRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exec_allow: Vec<ExecRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exec_deny: Vec<ExecRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    network_allow: Vec<OutputNetworkRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    network_deny: Vec<OutputNetworkRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    url_allow: Vec<OutputUrlRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    url_deny: Vec<OutputUrlRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enforcement: Option<EnforcementSettings>,
}

impl From<ProfilePolicy> for OutputProfilePolicy {
    fn from(profile: ProfilePolicy) -> Self {
        Self {
            workspace_roots: profile.workspace_roots,
            file_allow: profile.file_allow,
            file_deny: profile.file_deny,
            exec_allow: profile.exec_allow,
            exec_deny: profile.exec_deny,
            network_allow: profile
                .network_allow
                .into_iter()
                .map(OutputNetworkRule::from)
                .collect(),
            network_deny: profile
                .network_deny
                .into_iter()
                .map(OutputNetworkRule::from)
                .collect(),
            url_allow: profile
                .url_allow
                .into_iter()
                .map(OutputUrlRule::from)
                .collect(),
            url_deny: profile
                .url_deny
                .into_iter()
                .map(OutputUrlRule::from)
                .collect(),
            enforcement: profile.enforcement,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct OutputNetworkRule {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_glob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cidr: Option<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<NetworkProtocol>,
}

impl From<NetworkRule> for OutputNetworkRule {
    fn from(rule: NetworkRule) -> Self {
        Self {
            id: rule.id,
            host_glob: rule.host_glob,
            cidr: rule.cidr,
            port: rule.port,
            protocol: rule.protocol,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct OutputUrlRule {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scheme: Option<String>,
    host_glob: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    path_glob: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_glob: Option<String>,
}

impl From<UrlRule> for OutputUrlRule {
    fn from(rule: UrlRule) -> Self {
        Self {
            id: rule.id,
            scheme: rule.scheme,
            host_glob: rule.host_glob,
            port: rule.port,
            method: rule.method,
            path_glob: rule.path_glob,
            query_glob: rule.query_glob,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_policy() -> &'static str {
        r#"version: v1
defaults:
  decision: deny
  fail_mode: fail_closed
  audit_level: all
  enforcement:
    file: enforce
    process: enforce
    network: enforce
profiles:
  default: {}
signature:
  key_id: local-dev
  alg: hmac-sha256
  sig: ""
"#
    }

    #[test]
    fn render_appends_rules_and_generates_ids() {
        let patch = json!({
            "schema_version": SCHEMA_VERSION,
            "needs_clarification": false,
            "questions": [],
            "assumptions": ["Git is required to fetch project sources."],
            "target_profile": "default",
            "policy_patch": {
                "file_allow": {
                    "items": [
                        { "pattern": "/workspace/docs/**" }
                    ]
                },
                "exec_allow": {
                    "items": [
                        { "path": "/usr/bin/git" }
                    ]
                }
            }
        })
        .to_string();

        let rendered = render_policy_from_strings(base_policy(), &patch, false).unwrap();
        assert!(rendered.signature_removed);
        assert!(!rendered.yaml.contains("signature:"));

        let parsed: PolicyDocument = serde_yaml::from_str(&rendered.yaml).unwrap();
        let profile = parsed.profiles.get("default").unwrap();
        assert_eq!(profile.file_allow.len(), 1);
        assert_eq!(profile.exec_allow.len(), 1);
        assert_eq!(profile.file_allow[0].id, "allow_file_workspace_docs");
        assert_eq!(profile.exec_allow[0].id, "allow_exec_usr_bin_git");
    }

    #[test]
    fn render_refuses_clarification_responses() {
        let patch = json!({
            "schema_version": SCHEMA_VERSION,
            "needs_clarification": true,
            "questions": ["Which directory should be writable?"],
            "assumptions": [],
            "target_profile": "default",
            "policy_patch": {}
        })
        .to_string();

        let error = render_policy_from_strings(base_policy(), &patch, false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Which directory should be writable?")
        );
    }

    #[test]
    fn render_can_create_profiles() {
        let patch = json!({
            "schema_version": SCHEMA_VERSION,
            "needs_clarification": false,
            "questions": [],
            "assumptions": ["Only HTTPS GET access is needed."],
            "target_profile": "ops",
            "policy_patch": {
                "url_allow": {
                    "items": [
                        {
                            "host_glob": "api.github.com",
                            "path_glob": "/repos/**",
                            "method": "get",
                            "scheme": "https"
                        }
                    ]
                }
            }
        })
        .to_string();

        let rendered = render_policy_from_strings(base_policy(), &patch, true).unwrap();
        assert!(!rendered.yaml.contains("null"));
        let parsed: PolicyDocument = serde_yaml::from_str(&rendered.yaml).unwrap();
        let profile = parsed.profiles.get("ops").unwrap();
        assert_eq!(profile.url_allow.len(), 1);
        assert_eq!(profile.url_allow[0].method.as_deref(), Some("GET"));
        assert_eq!(profile.url_allow[0].scheme.as_deref(), Some("https"));
    }

    #[test]
    fn render_skips_duplicate_rules() {
        let policy = r#"version: v1
defaults:
  decision: deny
profiles:
  default:
    file_allow:
      - id: allow_file_workspace_docs
        pattern: /workspace/docs/**
"#;
        let patch = json!({
            "schema_version": SCHEMA_VERSION,
            "needs_clarification": false,
            "questions": [],
            "assumptions": [],
            "target_profile": "default",
            "policy_patch": {
                "file_allow": {
                    "items": [
                        { "pattern": "/workspace/docs/**" }
                    ]
                }
            }
        })
        .to_string();

        let rendered = render_policy_from_strings(policy, &patch, false).unwrap();
        let parsed: PolicyDocument = serde_yaml::from_str(&rendered.yaml).unwrap();
        let profile = parsed.profiles.get("default").unwrap();
        assert_eq!(profile.file_allow.len(), 1);
    }
}
