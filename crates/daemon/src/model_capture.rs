//! Model API visibility for the URL gateway.
//!
//! The gateway already decrypts and forwards every HTTPS exchange from an
//! enrolled agent. This module recognises the ones that are model API calls
//! (OpenAI chat/responses, Anthropic messages, Gemini, Vertex, Bedrock and
//! OpenAI-compatible routers) and turns the request plus the streamed response
//! into a [`ModelCallAuditContext`] without holding back any bytes from the
//! client: response chunks are observed as they are forwarded.
//!
//! Nothing here reads HTTP headers, so API keys in `Authorization`,
//! `x-api-key`, or `x-goog-api-key` are never recorded. Body text is passed
//! through [`redact_secrets`] and truncated before it reaches the audit log.
//! Embedding calls are recorded as metadata only, whatever the capture mode.

use std::collections::BTreeMap;
use std::time::Instant;

use core_types::{ModelCallAuditContext, ModelMessage, ModelToolCall, ModelUsage};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::gateway_audit::{redact_secrets, truncate_chars};

const DEFAULT_MODEL_HOSTS: &[&str] = &[
    "api.openai.com",
    "chatgpt.com",
    "api.anthropic.com",
    "openrouter.ai",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "*-aiplatform.googleapis.com",
    "bedrock-runtime.*.amazonaws.com",
    "api.x.ai",
    "api.mistral.ai",
    "api.groq.com",
    "api.deepseek.com",
    "api.together.xyz",
    "api.fireworks.ai",
    "*.openai.azure.com",
];

/// `url_gateway.model_traffic` config section.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ModelTrafficConfig {
    /// Host globs treated as model APIs. Applies the model timeouts even when
    /// capture is off. Setting it replaces the built-in list.
    pub hosts: Vec<String>,
    /// Host globs added to `hosts` (self-hosted OpenAI-compatible servers,
    /// Ollama, LiteLLM, vLLM) without restating the built-in list.
    pub extra_hosts: Vec<String>,
    /// Time allowed for a model API to return response headers. Non-streaming
    /// completions only send headers once generation is finished.
    pub request_timeout_ms: u64,
    pub capture: CaptureMode,
    /// Bytes of a non-streaming response body (or of one SSE event /
    /// WebSocket message) buffered for parsing. Forwarding is never limited.
    pub max_capture_bytes: usize,
    /// Characters kept per captured text field.
    pub max_text_chars: usize,
    /// Most recent conversation messages kept per call at `capture: content`.
    pub max_messages: usize,
}

impl Default for ModelTrafficConfig {
    fn default() -> Self {
        Self {
            hosts: DEFAULT_MODEL_HOSTS.iter().map(|h| h.to_string()).collect(),
            extra_hosts: Vec::new(),
            request_timeout_ms: 600_000,
            capture: CaptureMode::Off,
            max_capture_bytes: 4 * 1024 * 1024,
            max_text_chars: 16_384,
            max_messages: 50,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Only the gateway's URL-level network events are recorded.
    #[default]
    Off,
    /// Model, tools offered, tool call names, usage, finish reason, sizes.
    Metadata,
    /// Metadata plus redacted prompt, output, reasoning and tool arguments.
    Content,
}

#[derive(Debug, Clone, Copy)]
pub struct CaptureSettings {
    pub mode: CaptureMode,
    pub max_capture_bytes: usize,
    pub max_text_chars: usize,
    pub max_messages: usize,
}

impl CaptureSettings {
    fn content(&self) -> bool {
        self.mode == CaptureMode::Content
    }
}

#[derive(Debug, Clone)]
pub struct ModelTraffic {
    hosts: GlobSet,
    config: ModelTrafficConfig,
}

impl ModelTraffic {
    pub fn new(config: ModelTrafficConfig) -> Result<Self, String> {
        let mut builder = GlobSetBuilder::new();
        for pattern in config.hosts.iter().chain(&config.extra_hosts) {
            let glob = Glob::new(pattern.to_ascii_lowercase().as_str())
                .map_err(|err| format!("invalid model_traffic host glob '{pattern}': {err}"))?;
            builder.add(glob);
        }
        let hosts = builder
            .build()
            .map_err(|err| format!("build model_traffic host globs: {err}"))?;
        Ok(Self { hosts, config })
    }

    pub fn is_model_host(&self, host: &str) -> bool {
        self.hosts.is_match(host.to_ascii_lowercase().as_str())
    }

    pub fn request_timeout_ms(&self) -> u64 {
        self.config.request_timeout_ms
    }

    pub fn capture_enabled(&self) -> bool {
        self.config.capture != CaptureMode::Off
    }

    pub fn settings(&self) -> CaptureSettings {
        CaptureSettings {
            mode: self.config.capture,
            max_capture_bytes: self.config.max_capture_bytes,
            max_text_chars: self.config.max_text_chars,
            max_messages: self.config.max_messages,
        }
    }

    /// The model API a request targets, when capture is on and the host and
    /// path are recognised.
    pub fn target_for(&self, host: &str, path: &str) -> Option<ModelTarget> {
        if !self.capture_enabled() || !self.is_model_host(host) {
            return None;
        }
        detect_target(host, path)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelApi {
    OpenAiChat,
    OpenAiResponses,
    AnthropicMessages,
    GeminiGenerate,
    BedrockConverse,
    BedrockInvoke,
    OllamaChat,
    OllamaGenerate,
    /// Any provider's embeddings endpoint: recorded as metadata only.
    Embeddings,
}

impl ModelApi {
    fn name(self) -> &'static str {
        match self {
            Self::OpenAiChat => "openai.chat_completions",
            Self::OpenAiResponses => "openai.responses",
            Self::AnthropicMessages => "anthropic.messages",
            Self::GeminiGenerate => "gemini.generate_content",
            Self::BedrockConverse => "bedrock.converse",
            Self::BedrockInvoke => "bedrock.invoke_model",
            Self::OllamaChat => "ollama.chat",
            Self::OllamaGenerate => "ollama.generate",
            Self::Embeddings => "embeddings",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelTarget {
    pub provider: String,
    pub api: ModelApi,
    pub model_from_path: Option<String>,
    pub stream_from_path: bool,
}

fn provider_for_host(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    let known = [
        ("api.openai.com", "openai"),
        ("chatgpt.com", "openai-chatgpt"),
        ("api.anthropic.com", "anthropic"),
        ("openrouter.ai", "openrouter"),
        ("generativelanguage.googleapis.com", "gemini"),
        ("api.x.ai", "xai"),
        ("api.mistral.ai", "mistral"),
        ("api.groq.com", "groq"),
        ("api.deepseek.com", "deepseek"),
        ("api.together.xyz", "together"),
        ("api.fireworks.ai", "fireworks"),
    ];
    if let Some((_, name)) = known.iter().find(|(h, _)| *h == host) {
        return (*name).to_string();
    }
    if host.ends_with("aiplatform.googleapis.com") {
        return "vertex".to_string();
    }
    if host.starts_with("bedrock-runtime.") && host.ends_with(".amazonaws.com") {
        return "bedrock".to_string();
    }
    if host.ends_with(".openai.azure.com") {
        return "azure-openai".to_string();
    }
    host
}

pub fn detect_target(host: &str, path: &str) -> Option<ModelTarget> {
    let provider = provider_for_host(host);
    let target = |api, model_from_path, stream_from_path| {
        Some(ModelTarget {
            provider: provider.clone(),
            api,
            model_from_path,
            stream_from_path,
        })
    };

    // Azure OpenAI names the deployment, not the model, in the path:
    // /openai/deployments/{deployment}/chat/completions.
    let deployment = path
        .split_once("/openai/deployments/")
        .and_then(|(_, rest)| rest.split('/').next())
        .filter(|name| !name.is_empty())
        .map(percent_decode);

    if path.ends_with("/chat/completions") {
        return target(ModelApi::OpenAiChat, deployment, false);
    }
    if path.ends_with("/responses") {
        return target(ModelApi::OpenAiResponses, deployment, false);
    }
    if path.ends_with("/v1/messages") {
        return target(ModelApi::AnthropicMessages, None, false);
    }
    if path.ends_with("/embeddings") {
        return target(ModelApi::Embeddings, deployment, false);
    }
    // Ollama.
    match path {
        "/api/chat" => return target(ModelApi::OllamaChat, None, false),
        "/api/generate" => return target(ModelApi::OllamaGenerate, None, false),
        "/api/embed" | "/api/embeddings" => return target(ModelApi::Embeddings, None, false),
        _ => {}
    }

    // Google: .../models/{model}:{method}; Vertex also serves Anthropic models
    // under publishers/anthropic with rawPredict.
    if let Some((prefix, method)) = path.rsplit_once(':') {
        let model = prefix
            .rsplit_once("/models/")
            .map(|(_, model)| percent_decode(model));
        match method {
            "generateContent" => return target(ModelApi::GeminiGenerate, model, false),
            "streamGenerateContent" => return target(ModelApi::GeminiGenerate, model, true),
            "rawPredict" if path.contains("/publishers/anthropic/") => {
                return target(ModelApi::AnthropicMessages, model, false);
            }
            "streamRawPredict" if path.contains("/publishers/anthropic/") => {
                return target(ModelApi::AnthropicMessages, model, true);
            }
            "embedContent" | "batchEmbedContents" => {
                return target(ModelApi::Embeddings, model, false);
            }
            _ => {}
        }
    }

    // Bedrock runtime: /model/{modelId}/{operation}
    if let Some(rest) = path.strip_prefix("/model/")
        && let Some((model, operation)) = rest.rsplit_once('/')
    {
        let model = Some(percent_decode(model));
        return match operation {
            "converse" => target(ModelApi::BedrockConverse, model, false),
            "converse-stream" => target(ModelApi::BedrockConverse, model, true),
            "invoke" => target(ModelApi::BedrockInvoke, model, false),
            "invoke-with-response-stream" => target(ModelApi::BedrockInvoke, model, true),
            _ => None,
        };
    }

    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── JSON helpers ────────────────────────────────────────────────────────────

fn str_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn u64_at(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn arr_at<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// Text of a content field that may be a string or an array of typed parts.
fn content_text(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(parts) => {
            let texts: Vec<String> = parts.iter().filter_map(part_text).collect();
            texts.join("\n")
        }
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn part_text(part: &Value) -> Option<String> {
    if let Some(text) = part.as_str() {
        return Some(text.to_string());
    }
    let kind = str_at(part, "type").unwrap_or("");
    match kind {
        "text" | "input_text" | "output_text" => str_at(part, "text").map(str::to_string),
        "tool_use" | "server_tool_use" => Some(format!(
            "[tool_use {}] {}",
            str_at(part, "name").unwrap_or("?"),
            part.get("input").map(Value::to_string).unwrap_or_default()
        )),
        "tool_result" => Some(format!(
            "[tool_result] {}",
            part.get("content").map(content_text).unwrap_or_default()
        )),
        "image" | "image_url" | "input_image" => Some("[image]".to_string()),
        "document" | "input_file" | "file" => Some("[file]".to_string()),
        "thinking" | "redacted_thinking" => None,
        _ => {
            // Bedrock / Gemini parts are keyed by field rather than `type`.
            if let Some(text) = str_at(part, "text") {
                return Some(text.to_string());
            }
            if let Some(tool) = part.get("toolUse").or_else(|| part.get("functionCall")) {
                return Some(format!(
                    "[tool_use {}] {}",
                    str_at(tool, "name").unwrap_or("?"),
                    tool.get("input")
                        .or_else(|| tool.get("args"))
                        .map(Value::to_string)
                        .unwrap_or_default()
                ));
            }
            if let Some(result) = part
                .get("toolResult")
                .or_else(|| part.get("functionResponse"))
            {
                return Some(format!("[tool_result] {result}"));
            }
            None
        }
    }
}

// ── request parsing ─────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct RequestSummary {
    model: Option<String>,
    stream: bool,
    system: Option<String>,
    messages: Vec<ModelMessage>,
    tools: Vec<String>,
    /// Number of inputs of an embeddings request (its content is never kept).
    input_count: Option<u32>,
}

fn parse_request(api: ModelApi, body: &Value) -> RequestSummary {
    // Ollama streams unless told not to.
    let stream_default = matches!(api, ModelApi::OllamaChat | ModelApi::OllamaGenerate);
    let mut summary = RequestSummary {
        model: str_at(body, "model").map(str::to_string),
        stream: body
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(stream_default),
        ..RequestSummary::default()
    };

    let push = |summary: &mut RequestSummary, role: &str, text: String| {
        summary.messages.push(ModelMessage {
            role: role.to_string(),
            text,
        });
    };

    match api {
        ModelApi::OpenAiChat => {
            for message in arr_at(body, "messages") {
                let role = str_at(message, "role").unwrap_or("unknown");
                let mut text = message.get("content").map(content_text).unwrap_or_default();
                for call in arr_at(message, "tool_calls") {
                    let function = call.get("function").unwrap_or(call);
                    text.push_str(&format!(
                        "\n[tool_call {}] {}",
                        str_at(function, "name").unwrap_or("?"),
                        str_at(function, "arguments").unwrap_or("")
                    ));
                }
                if (role == "system" || role == "developer") && summary.system.is_none() {
                    summary.system = Some(text.clone());
                }
                push(&mut summary, role, text);
            }
            summary.tools = tool_names(arr_at(body, "tools"));
        }
        ModelApi::OpenAiResponses => {
            summary.system = str_at(body, "instructions").map(str::to_string);
            match body.get("input") {
                Some(Value::String(text)) => push(&mut summary, "user", text.clone()),
                Some(Value::Array(items)) => {
                    for item in items {
                        let kind = str_at(item, "type").unwrap_or("message");
                        match kind {
                            "function_call" | "custom_tool_call" => push(
                                &mut summary,
                                "assistant",
                                format!(
                                    "[tool_call {}] {}",
                                    str_at(item, "name").unwrap_or("?"),
                                    str_at(item, "arguments")
                                        .or_else(|| str_at(item, "input"))
                                        .unwrap_or("")
                                ),
                            ),
                            "function_call_output" | "custom_tool_call_output" => push(
                                &mut summary,
                                "tool",
                                item.get("output").map(content_text).unwrap_or_default(),
                            ),
                            "reasoning" => {}
                            _ => {
                                let role = str_at(item, "role").unwrap_or("user");
                                let text =
                                    item.get("content").map(content_text).unwrap_or_default();
                                push(&mut summary, role, text);
                            }
                        }
                    }
                }
                _ => {}
            }
            summary.tools = tool_names(arr_at(body, "tools"));
        }
        ModelApi::AnthropicMessages | ModelApi::BedrockInvoke => {
            summary.system = body.get("system").map(content_text);
            for message in arr_at(body, "messages") {
                let role = str_at(message, "role").unwrap_or("unknown");
                let text = message.get("content").map(content_text).unwrap_or_default();
                push(&mut summary, role, text);
            }
            summary.tools = tool_names(arr_at(body, "tools"));
        }
        ModelApi::GeminiGenerate => {
            let system = body
                .get("systemInstruction")
                .or_else(|| body.get("system_instruction"));
            summary.system = system.map(|s| content_text(s.get("parts").unwrap_or(s)));
            for content in arr_at(body, "contents") {
                let role = str_at(content, "role").unwrap_or("user");
                let text = content.get("parts").map(content_text).unwrap_or_default();
                push(&mut summary, role, text);
            }
            for tool in arr_at(body, "tools") {
                let declarations = tool
                    .get("functionDeclarations")
                    .or_else(|| tool.get("function_declarations"));
                match declarations.and_then(Value::as_array) {
                    Some(list) => summary.tools.extend(
                        list.iter()
                            .filter_map(|d| str_at(d, "name"))
                            .map(str::to_string),
                    ),
                    None => {
                        if let Some(obj) = tool.as_object() {
                            summary.tools.extend(obj.keys().cloned());
                        }
                    }
                }
            }
        }
        ModelApi::BedrockConverse => {
            let system: Vec<String> = arr_at(body, "system")
                .iter()
                .filter_map(part_text)
                .collect();
            if !system.is_empty() {
                summary.system = Some(system.join("\n"));
            }
            for message in arr_at(body, "messages") {
                let role = str_at(message, "role").unwrap_or("unknown");
                let text = message.get("content").map(content_text).unwrap_or_default();
                push(&mut summary, role, text);
            }
            if let Some(config) = body.get("toolConfig") {
                summary.tools = arr_at(config, "tools")
                    .iter()
                    .filter_map(|t| t.get("toolSpec").and_then(|s| str_at(s, "name")))
                    .map(str::to_string)
                    .collect();
            }
        }
        ModelApi::OllamaChat => {
            for message in arr_at(body, "messages") {
                let role = str_at(message, "role").unwrap_or("unknown");
                let mut text = message.get("content").map(content_text).unwrap_or_default();
                for call in arr_at(message, "tool_calls") {
                    let function = call.get("function").unwrap_or(call);
                    text.push_str(&format!(
                        "\n[tool_call {}] {}",
                        str_at(function, "name").unwrap_or("?"),
                        function.get("arguments").map(json_text).unwrap_or_default()
                    ));
                }
                if role == "system" && summary.system.is_none() {
                    summary.system = Some(text.clone());
                }
                push(&mut summary, role, text);
            }
            summary.tools = tool_names(arr_at(body, "tools"));
        }
        ModelApi::OllamaGenerate => {
            summary.system = str_at(body, "system").map(str::to_string);
            if let Some(prompt) = str_at(body, "prompt") {
                push(&mut summary, "user", prompt.to_string());
            }
        }
        ModelApi::Embeddings => {
            // OpenAI/Azure `input`, Ollama `input`/`prompt`, Gemini
            // `content`/`requests`.
            let inputs = ["input", "prompt", "content", "requests"]
                .iter()
                .find_map(|key| body.get(*key));
            summary.input_count = Some(match inputs {
                Some(Value::Array(items)) => items.len() as u32,
                Some(Value::Null) | None => 0,
                Some(_) => 1,
            });
        }
    }
    summary
}

/// A JSON value as text: strings as-is, anything else serialized.
fn json_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn tool_names(tools: &[Value]) -> Vec<String> {
    tools
        .iter()
        .filter_map(|tool| {
            tool.get("function")
                .and_then(|f| str_at(f, "name"))
                .or_else(|| str_at(tool, "name"))
                .or_else(|| str_at(tool, "type"))
                .map(str::to_string)
        })
        .collect()
}

// ── response accumulation ───────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
struct PendingToolCall {
    id: Option<String>,
    name: String,
    arguments: String,
}

#[derive(Debug, Default)]
struct ResponseAccumulator {
    model: Option<String>,
    output_text: String,
    reasoning_text: String,
    /// Keyed by stream index (or insertion order when the API has none).
    tool_calls: BTreeMap<u64, PendingToolCall>,
    finish_reason: Option<String>,
    usage: ModelUsage,
    usage_seen: bool,
    error: Option<String>,
    /// Responses API: a terminal event carried the authoritative response.
    completed: bool,
}

impl ResponseAccumulator {
    fn next_index(&self) -> u64 {
        self.tool_calls
            .keys()
            .next_back()
            .map(|k| k + 1)
            .unwrap_or(0)
    }

    fn add_tool_call(&mut self, id: Option<String>, name: &str, arguments: String) {
        let index = self.next_index();
        self.tool_calls.insert(
            index,
            PendingToolCall {
                id,
                name: name.to_string(),
                arguments,
            },
        );
    }

    fn set_usage(&mut self, update: impl FnOnce(&mut ModelUsage)) {
        update(&mut self.usage);
        self.usage_seen = true;
    }

    fn apply(&mut self, api: ModelApi, event: &Value) {
        if let Some(message) = error_message(event) {
            self.error = Some(message);
        }
        match api {
            ModelApi::OpenAiChat => self.apply_openai_chat(event),
            ModelApi::OpenAiResponses => self.apply_responses_event(event),
            ModelApi::AnthropicMessages | ModelApi::BedrockInvoke => self.apply_anthropic(event),
            ModelApi::GeminiGenerate => self.apply_gemini(event),
            ModelApi::BedrockConverse => self.apply_bedrock_converse(event),
            ModelApi::OllamaChat | ModelApi::OllamaGenerate => self.apply_ollama(event),
            ModelApi::Embeddings => self.apply_embeddings(event),
        }
    }

    fn apply_openai_chat(&mut self, event: &Value) {
        if let Some(model) = str_at(event, "model") {
            self.model = Some(model.to_string());
        }
        for choice in arr_at(event, "choices") {
            // Streaming chunks carry `delta`; complete responses carry `message`.
            let (body, streaming) = match choice.get("delta") {
                Some(delta) => (delta, true),
                None => (choice.get("message").unwrap_or(&Value::Null), false),
            };
            if let Some(text) = body.get("content").filter(|v| !v.is_null()) {
                self.output_text.push_str(&content_text(text));
            }
            for key in ["reasoning", "reasoning_content"] {
                if let Some(text) = str_at(body, key) {
                    self.reasoning_text.push_str(text);
                }
            }
            for (position, call) in arr_at(body, "tool_calls").iter().enumerate() {
                let index = if streaming {
                    u64_at(call, "index").unwrap_or(position as u64)
                } else {
                    self.next_index()
                };
                let entry = self.tool_calls.entry(index).or_default();
                if let Some(id) = str_at(call, "id") {
                    entry.id = Some(id.to_string());
                }
                if let Some(function) = call.get("function") {
                    if let Some(name) = str_at(function, "name") {
                        entry.name.push_str(name);
                    }
                    if let Some(arguments) = str_at(function, "arguments") {
                        entry.arguments.push_str(arguments);
                    }
                }
            }
            if let Some(reason) = str_at(choice, "finish_reason") {
                self.finish_reason = Some(reason.to_string());
            }
        }
        if let Some(usage) = event.get("usage").filter(|u| u.is_object()) {
            self.set_usage(|u| {
                u.input_tokens = u64_at(usage, "prompt_tokens").or(u.input_tokens);
                u.output_tokens = u64_at(usage, "completion_tokens").or(u.output_tokens);
                u.total_tokens = u64_at(usage, "total_tokens").or(u.total_tokens);
                u.cache_read_tokens = usage
                    .get("prompt_tokens_details")
                    .and_then(|d| u64_at(d, "cached_tokens"))
                    .or(u.cache_read_tokens);
                u.reasoning_tokens = usage
                    .get("completion_tokens_details")
                    .and_then(|d| u64_at(d, "reasoning_tokens"))
                    .or(u.reasoning_tokens);
            });
        }
    }

    fn apply_responses_event(&mut self, event: &Value) {
        let kind = str_at(event, "type").unwrap_or("");
        match kind {
            "response.output_text.delta" if !self.completed => {
                if let Some(delta) = str_at(event, "delta") {
                    self.output_text.push_str(delta);
                }
            }
            "response.reasoning_summary_text.delta" | "response.reasoning_text.delta"
                if !self.completed =>
            {
                if let Some(delta) = str_at(event, "delta") {
                    self.reasoning_text.push_str(delta);
                }
            }
            "response.output_item.done" if !self.completed => {
                if let Some(item) = event.get("item") {
                    self.apply_responses_tool_item(item);
                }
            }
            "response.created" | "response.in_progress" => {
                if let Some(model) = event.get("response").and_then(|r| str_at(r, "model")) {
                    self.model = Some(model.to_string());
                }
            }
            "response.completed" | "response.incomplete" | "response.failed" | "response.done" => {
                if let Some(response) = event.get("response") {
                    self.apply_responses_object(response);
                }
            }
            _ => {
                // Non-streaming responses are the response object itself.
                if str_at(event, "object") == Some("response") {
                    self.apply_responses_object(event);
                }
            }
        }
    }

    fn apply_responses_tool_item(&mut self, item: &Value) {
        match str_at(item, "type").unwrap_or("") {
            "function_call" | "custom_tool_call" => self.add_tool_call(
                str_at(item, "call_id").map(str::to_string),
                str_at(item, "name").unwrap_or("?"),
                str_at(item, "arguments")
                    .or_else(|| str_at(item, "input"))
                    .unwrap_or("")
                    .to_string(),
            ),
            kind if kind.ends_with("_call") => self.add_tool_call(
                str_at(item, "id").map(str::to_string),
                kind.trim_end_matches("_call"),
                item.get("action").map(Value::to_string).unwrap_or_default(),
            ),
            _ => {}
        }
    }

    fn apply_responses_object(&mut self, response: &Value) {
        if let Some(model) = str_at(response, "model") {
            self.model = Some(model.to_string());
        }
        let status = str_at(response, "status");
        let incomplete = response
            .get("incomplete_details")
            .and_then(|d| str_at(d, "reason"));
        self.finish_reason = match (status, incomplete) {
            (Some(status), Some(reason)) => Some(format!("{status}:{reason}")),
            (Some(status), None) => Some(status.to_string()),
            (None, reason) => reason.map(str::to_string).or(self.finish_reason.take()),
        };

        let output = arr_at(response, "output");
        if !output.is_empty() {
            // The terminal object is authoritative; replace streamed partials.
            self.output_text.clear();
            self.reasoning_text.clear();
            self.tool_calls.clear();
            for item in output {
                match str_at(item, "type").unwrap_or("") {
                    "message" => {
                        let text = item.get("content").map(content_text).unwrap_or_default();
                        self.output_text.push_str(&text);
                    }
                    "reasoning" => {
                        let summary: Vec<String> = arr_at(item, "summary")
                            .iter()
                            .filter_map(|s| str_at(s, "text").map(str::to_string))
                            .collect();
                        self.reasoning_text.push_str(&summary.join("\n"));
                    }
                    _ => self.apply_responses_tool_item(item),
                }
            }
        }
        if let Some(usage) = response.get("usage").filter(|u| u.is_object()) {
            self.set_usage(|u| {
                u.input_tokens = u64_at(usage, "input_tokens");
                u.output_tokens = u64_at(usage, "output_tokens");
                u.total_tokens = u64_at(usage, "total_tokens");
                u.cache_read_tokens = usage
                    .get("input_tokens_details")
                    .and_then(|d| u64_at(d, "cached_tokens"));
                u.reasoning_tokens = usage
                    .get("output_tokens_details")
                    .and_then(|d| u64_at(d, "reasoning_tokens"));
            });
        }
        if let Some(message) = response.get("error").and_then(|e| str_at(e, "message")) {
            self.error = Some(message.to_string());
        }
        self.completed = true;
    }

    fn apply_anthropic_usage(&mut self, usage: &Value) {
        self.set_usage(|u| {
            u.input_tokens = u64_at(usage, "input_tokens").or(u.input_tokens);
            u.output_tokens = u64_at(usage, "output_tokens").or(u.output_tokens);
            u.cache_read_tokens = u64_at(usage, "cache_read_input_tokens").or(u.cache_read_tokens);
            u.cache_write_tokens =
                u64_at(usage, "cache_creation_input_tokens").or(u.cache_write_tokens);
        });
    }

    fn apply_anthropic(&mut self, event: &Value) {
        match str_at(event, "type").unwrap_or("") {
            "message_start" => {
                if let Some(message) = event.get("message") {
                    if let Some(model) = str_at(message, "model") {
                        self.model = Some(model.to_string());
                    }
                    if let Some(usage) = message.get("usage") {
                        self.apply_anthropic_usage(usage);
                    }
                }
            }
            "content_block_start" => {
                let index = u64_at(event, "index").unwrap_or_else(|| self.next_index());
                if let Some(block) = event.get("content_block") {
                    let kind = str_at(block, "type").unwrap_or("");
                    if kind == "tool_use" || kind == "server_tool_use" {
                        self.tool_calls.insert(
                            index,
                            PendingToolCall {
                                id: str_at(block, "id").map(str::to_string),
                                name: str_at(block, "name").unwrap_or("?").to_string(),
                                arguments: String::new(),
                            },
                        );
                    }
                }
            }
            "content_block_delta" => {
                let index = u64_at(event, "index").unwrap_or(0);
                if let Some(delta) = event.get("delta") {
                    match str_at(delta, "type").unwrap_or("") {
                        "text_delta" => self
                            .output_text
                            .push_str(str_at(delta, "text").unwrap_or("")),
                        "thinking_delta" => self
                            .reasoning_text
                            .push_str(str_at(delta, "thinking").unwrap_or("")),
                        "input_json_delta" => {
                            if let Some(call) = self.tool_calls.get_mut(&index) {
                                call.arguments
                                    .push_str(str_at(delta, "partial_json").unwrap_or(""));
                            }
                        }
                        _ => {}
                    }
                }
            }
            "message_delta" => {
                if let Some(reason) = event.get("delta").and_then(|d| str_at(d, "stop_reason")) {
                    self.finish_reason = Some(reason.to_string());
                }
                if let Some(usage) = event.get("usage") {
                    self.apply_anthropic_usage(usage);
                }
            }
            "message" => {
                if let Some(model) = str_at(event, "model") {
                    self.model = Some(model.to_string());
                }
                for block in arr_at(event, "content") {
                    match str_at(block, "type").unwrap_or("") {
                        "text" => self
                            .output_text
                            .push_str(str_at(block, "text").unwrap_or("")),
                        "thinking" => self
                            .reasoning_text
                            .push_str(str_at(block, "thinking").unwrap_or("")),
                        "tool_use" | "server_tool_use" => self.add_tool_call(
                            str_at(block, "id").map(str::to_string),
                            str_at(block, "name").unwrap_or("?"),
                            block.get("input").map(Value::to_string).unwrap_or_default(),
                        ),
                        _ => {}
                    }
                }
                if let Some(reason) = str_at(event, "stop_reason") {
                    self.finish_reason = Some(reason.to_string());
                }
                if let Some(usage) = event.get("usage") {
                    self.apply_anthropic_usage(usage);
                }
            }
            _ => {}
        }
    }

    fn apply_gemini(&mut self, event: &Value) {
        if let Value::Array(chunks) = event {
            // streamGenerateContent without alt=sse returns a JSON array.
            for chunk in chunks {
                self.apply_gemini(chunk);
            }
            return;
        }
        if let Some(model) = str_at(event, "modelVersion") {
            self.model = Some(model.to_string());
        }
        for candidate in arr_at(event, "candidates") {
            if let Some(content) = candidate.get("content") {
                for part in arr_at(content, "parts") {
                    if let Some(text) = str_at(part, "text") {
                        if part.get("thought").and_then(Value::as_bool) == Some(true) {
                            self.reasoning_text.push_str(text);
                        } else {
                            self.output_text.push_str(text);
                        }
                    }
                    if let Some(call) = part.get("functionCall") {
                        self.add_tool_call(
                            str_at(call, "id").map(str::to_string),
                            str_at(call, "name").unwrap_or("?"),
                            call.get("args").map(Value::to_string).unwrap_or_default(),
                        );
                    }
                }
            }
            if let Some(reason) = str_at(candidate, "finishReason") {
                self.finish_reason = Some(reason.to_string());
            }
        }
        if let Some(usage) = event.get("usageMetadata") {
            self.set_usage(|u| {
                u.input_tokens = u64_at(usage, "promptTokenCount").or(u.input_tokens);
                u.output_tokens = u64_at(usage, "candidatesTokenCount").or(u.output_tokens);
                u.cache_read_tokens =
                    u64_at(usage, "cachedContentTokenCount").or(u.cache_read_tokens);
                u.reasoning_tokens = u64_at(usage, "thoughtsTokenCount").or(u.reasoning_tokens);
                u.total_tokens = u64_at(usage, "totalTokenCount").or(u.total_tokens);
            });
        }
    }

    fn apply_bedrock_converse(&mut self, event: &Value) {
        if let Some(message) = event.get("output").and_then(|o| o.get("message")) {
            for block in arr_at(message, "content") {
                if let Some(text) = str_at(block, "text") {
                    self.output_text.push_str(text);
                }
                if let Some(tool) = block.get("toolUse") {
                    self.add_tool_call(
                        str_at(tool, "toolUseId").map(str::to_string),
                        str_at(tool, "name").unwrap_or("?"),
                        tool.get("input").map(Value::to_string).unwrap_or_default(),
                    );
                }
                if let Some(text) = block
                    .get("reasoningContent")
                    .and_then(|r| r.get("reasoningText"))
                    .and_then(|r| str_at(r, "text"))
                {
                    self.reasoning_text.push_str(text);
                }
            }
        }
        if let Some(reason) = str_at(event, "stopReason") {
            self.finish_reason = Some(reason.to_string());
        }
        if let Some(usage) = event.get("usage") {
            self.set_usage(|u| {
                u.input_tokens = u64_at(usage, "inputTokens");
                u.output_tokens = u64_at(usage, "outputTokens");
                u.total_tokens = u64_at(usage, "totalTokens");
                u.cache_read_tokens = u64_at(usage, "cacheReadInputTokens");
                u.cache_write_tokens = u64_at(usage, "cacheWriteInputTokens");
            });
        }
    }
}

impl ResponseAccumulator {
    /// Ollama `/api/chat` and `/api/generate`: one object, or one per NDJSON
    /// line when streaming; the last has `done: true` and the token counts.
    fn apply_ollama(&mut self, event: &Value) {
        if let Some(model) = str_at(event, "model") {
            self.model = Some(model.to_string());
        }
        if let Some(message) = event.get("message") {
            if let Some(text) = str_at(message, "content") {
                self.output_text.push_str(text);
            }
            if let Some(text) = str_at(message, "thinking") {
                self.reasoning_text.push_str(text);
            }
            for call in arr_at(message, "tool_calls") {
                let function = call.get("function").unwrap_or(call);
                self.add_tool_call(
                    str_at(call, "id").map(str::to_string),
                    str_at(function, "name").unwrap_or("?"),
                    function.get("arguments").map(json_text).unwrap_or_default(),
                );
            }
        }
        if let Some(text) = str_at(event, "response") {
            self.output_text.push_str(text);
        }
        if let Some(text) = str_at(event, "thinking") {
            self.reasoning_text.push_str(text);
        }
        if event.get("done").and_then(Value::as_bool) == Some(true) {
            if let Some(reason) = str_at(event, "done_reason") {
                self.finish_reason = Some(reason.to_string());
            }
            let input = u64_at(event, "prompt_eval_count");
            let output = u64_at(event, "eval_count");
            if input.is_some() || output.is_some() {
                self.set_usage(|u| {
                    u.input_tokens = input.or(u.input_tokens);
                    u.output_tokens = output.or(u.output_tokens);
                });
            }
        }
    }

    /// Embeddings: only the model and token usage are kept, never vectors.
    fn apply_embeddings(&mut self, event: &Value) {
        if let Some(model) = str_at(event, "model") {
            self.model = Some(model.to_string());
        }
        if let Some(usage) = event.get("usage").filter(|u| u.is_object()) {
            self.set_usage(|u| {
                u.input_tokens = u64_at(usage, "prompt_tokens").or(u.input_tokens);
                u.total_tokens = u64_at(usage, "total_tokens").or(u.total_tokens);
            });
        }
        if let Some(count) = u64_at(event, "prompt_eval_count") {
            self.set_usage(|u| u.input_tokens = Some(count));
        }
    }
}

fn error_message(event: &Value) -> Option<String> {
    if str_at(event, "type") == Some("error") {
        let message = event
            .get("error")
            .and_then(|e| str_at(e, "message"))
            .or_else(|| str_at(event, "message"));
        return Some(message.unwrap_or("error event").to_string());
    }
    let error = event.get("error")?;
    match error {
        Value::String(text) => Some(text.clone()),
        Value::Object(_) => Some(
            str_at(error, "message")
                .map(str::to_string)
                .unwrap_or_else(|| error.to_string()),
        ),
        _ => None,
    }
}

// ── SSE framing ─────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct SseParser {
    line: Vec<u8>,
    data: Vec<u8>,
    overflow: bool,
}

impl SseParser {
    /// Feed bytes; returns complete `data:` payloads.
    fn feed(&mut self, bytes: &[u8], limit: usize) -> Vec<Vec<u8>> {
        let mut events = Vec::new();
        for &byte in bytes {
            if byte != b'\n' {
                if self.line.len() < limit {
                    self.line.push(byte);
                } else {
                    self.overflow = true;
                }
                continue;
            }
            if self.line.last() == Some(&b'\r') {
                self.line.pop();
            }
            if self.line.is_empty() {
                if !self.data.is_empty() {
                    events.push(std::mem::take(&mut self.data));
                }
            } else if let Some(rest) = self.line.strip_prefix(b"data:") {
                let rest = rest.strip_prefix(b" ").unwrap_or(rest);
                if !self.data.is_empty() {
                    self.data.push(b'\n');
                }
                if self.data.len() + rest.len() <= limit {
                    self.data.extend_from_slice(rest);
                } else {
                    self.overflow = true;
                }
            }
            self.line.clear();
        }
        events
    }

    fn finish(&mut self) -> Option<Vec<u8>> {
        if !self.line.is_empty() {
            self.feed(b"\n", usize::MAX);
        }
        (!self.data.is_empty()).then(|| std::mem::take(&mut self.data))
    }
}

// ── call recorder ───────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum ResponseKind {
    Pending,
    Json,
    Sse,
    /// Newline-delimited JSON (Ollama streaming).
    Ndjson,
    /// Delivered as parsed events by the caller (WebSocket).
    Events,
    Opaque,
}

/// Observes one model API exchange and produces its audit context.
#[derive(Debug)]
pub struct ModelCallRecorder {
    settings: CaptureSettings,
    api: ModelApi,
    started: Instant,
    ctx: ModelCallAuditContext,
    request: RequestSummary,
    response_kind: ResponseKind,
    json_body: Vec<u8>,
    sse: SseParser,
    /// Partial NDJSON line.
    line: Vec<u8>,
    acc: ResponseAccumulator,
    truncated: bool,
    /// Streamed events (SSE data, NDJSON lines, WebSocket messages) that
    /// were not valid JSON and so were skipped.
    unparsed_events: u32,
    notes: Vec<String>,
}

impl ModelCallRecorder {
    fn new(settings: CaptureSettings, target: &ModelTarget, transport: &str) -> Self {
        let ctx = ModelCallAuditContext {
            call_id: uuid::Uuid::new_v4().to_string(),
            provider: target.provider.clone(),
            api: target.api.name().to_string(),
            transport: transport.to_string(),
            model: target.model_from_path.clone(),
            stream: target.stream_from_path,
            ..ModelCallAuditContext::default()
        };
        Self {
            settings,
            api: target.api,
            started: Instant::now(),
            ctx,
            request: RequestSummary::default(),
            response_kind: ResponseKind::Pending,
            json_body: Vec::new(),
            sse: SseParser::default(),
            line: Vec::new(),
            acc: ResponseAccumulator::default(),
            truncated: false,
            unparsed_events: 0,
            notes: Vec::new(),
        }
    }

    /// Start recording an HTTP exchange from its (already buffered) request body.
    pub fn for_http(
        settings: CaptureSettings,
        target: &ModelTarget,
        body: &[u8],
        content_encoding: Option<&str>,
    ) -> Self {
        let mut recorder = Self::new(settings, target, "http");
        recorder.ctx.request_bytes = body.len() as u64;
        recorder.ctx.request_sha256 = Some(hex::encode(Sha256::digest(body)));
        match content_encoding.map(str::trim).filter(|e| !e.is_empty()) {
            Some(encoding) if !encoding.eq_ignore_ascii_case("identity") => recorder.notes.push(
                format!("request body is {encoding}-encoded; prompt not parsed"),
            ),
            _ => match serde_json::from_slice::<Value>(body) {
                Ok(value) => recorder.set_request(&value),
                Err(_) if body.is_empty() => {}
                Err(err) => recorder
                    .notes
                    .push(format!("request body is not JSON: {err}")),
            },
        }
        recorder
    }

    /// Start recording a call sent as a WebSocket message (Responses API
    /// `response.create`).
    pub fn for_websocket(settings: CaptureSettings, target: &ModelTarget, message: &[u8]) -> Self {
        let mut recorder = Self::new(settings, target, "websocket");
        recorder.ctx.stream = true;
        recorder.ctx.request_bytes = message.len() as u64;
        recorder.ctx.request_sha256 = Some(hex::encode(Sha256::digest(message)));
        recorder.response_kind = ResponseKind::Events;
        if let Ok(value) = serde_json::from_slice::<Value>(message) {
            let request = value
                .get("response")
                .filter(|r| r.is_object())
                .unwrap_or(&value);
            recorder.set_request(request);
        }
        recorder
    }

    fn set_request(&mut self, body: &Value) {
        let summary = parse_request(self.api, body);
        if summary.model.is_some() {
            self.ctx.model = summary.model.clone();
        }
        self.ctx.stream |= summary.stream;
        self.request = summary;
    }

    pub fn on_response_head(
        &mut self,
        status: u16,
        content_type: Option<&str>,
        content_encoding: Option<&str>,
    ) {
        self.ctx.status = Some(status);
        let content_type = content_type.unwrap_or("").to_ascii_lowercase();
        let encoded = content_encoding
            .map(str::trim)
            .filter(|e| !e.is_empty() && !e.eq_ignore_ascii_case("identity"));
        self.response_kind = if let Some(encoding) = encoded {
            self.notes.push(format!(
                "response body is {encoding}-encoded; output not parsed"
            ));
            ResponseKind::Opaque
        } else if content_type.starts_with("text/event-stream") {
            self.ctx.transport = "sse".to_string();
            ResponseKind::Sse
        } else if content_type.contains("ndjson") || content_type.contains("jsonl") {
            ResponseKind::Ndjson
        } else if content_type.contains("json") || content_type.is_empty() {
            ResponseKind::Json
        } else {
            self.notes.push(format!(
                "response content-type {content_type} is not decoded"
            ));
            ResponseKind::Opaque
        };
    }

    pub fn on_body_chunk(&mut self, chunk: &[u8]) {
        self.ctx.response_bytes += chunk.len() as u64;
        let limit = self.settings.max_capture_bytes;
        match self.response_kind {
            ResponseKind::Json | ResponseKind::Pending => {
                let room = limit.saturating_sub(self.json_body.len());
                if chunk.len() > room {
                    self.truncated = true;
                }
                self.json_body
                    .extend_from_slice(&chunk[..chunk.len().min(room)]);
            }
            ResponseKind::Sse => {
                for data in self.sse.feed(chunk, limit) {
                    self.apply_sse_data(&data);
                }
                if self.sse.overflow {
                    self.truncated = true;
                }
            }
            ResponseKind::Ndjson => {
                for &byte in chunk {
                    if byte == b'\n' {
                        let line = std::mem::take(&mut self.line);
                        self.apply_json_event(&line);
                    } else if self.line.len() < limit {
                        self.line.push(byte);
                    } else {
                        self.truncated = true;
                    }
                }
            }
            ResponseKind::Events | ResponseKind::Opaque => {}
        }
    }

    /// Feed one already-framed event (a WebSocket text message).
    pub fn on_event(&mut self, raw: &[u8]) {
        self.ctx.response_bytes += raw.len() as u64;
        self.apply_json_event(raw);
    }

    fn apply_json_event(&mut self, raw: &[u8]) {
        let raw = raw.trim_ascii();
        if raw.is_empty() {
            return;
        }
        match serde_json::from_slice::<Value>(raw) {
            Ok(value) => self.acc.apply(self.api, &value),
            Err(_) => self.unparsed_events += 1,
        }
    }

    fn note_once(&mut self, note: &str) {
        if !self.notes.iter().any(|existing| existing == note) {
            self.notes.push(note.to_string());
        }
    }

    /// Whether the last event ended the response (WebSocket framing has no
    /// end-of-body marker per call).
    pub fn is_complete(&self) -> bool {
        self.acc.completed || self.acc.error.is_some()
    }

    fn apply_sse_data(&mut self, data: &[u8]) {
        if data == b"[DONE]" {
            return;
        }
        self.apply_json_event(data);
    }

    pub fn finish(mut self, note: Option<String>) -> ModelCallAuditContext {
        if let Some(note) = note {
            self.notes.push(note);
        }
        match self.response_kind {
            ResponseKind::Json | ResponseKind::Pending if !self.json_body.is_empty() => {
                match serde_json::from_slice::<Value>(&self.json_body) {
                    Ok(value) => self.acc.apply(self.api, &value),
                    Err(_) if self.truncated => self
                        .notes
                        .push("response body exceeded max_capture_bytes".to_string()),
                    Err(_) => {
                        let text = String::from_utf8_lossy(&self.json_body).into_owned();
                        if self.ctx.status.is_some_and(|s| s >= 400) {
                            self.acc.error = Some(text);
                        }
                    }
                }
            }
            ResponseKind::Sse => {
                if let Some(data) = self.sse.finish() {
                    self.apply_sse_data(&data);
                }
            }
            ResponseKind::Ndjson => {
                let line = std::mem::take(&mut self.line);
                self.apply_json_event(&line);
            }
            _ => {}
        }
        if self.unparsed_events > 0 {
            self.notes.push(format!(
                "{} streamed events were not valid JSON and were skipped",
                self.unparsed_events
            ));
        }

        let settings = self.settings;
        let mut truncated = self.truncated;
        let mut clip = |text: &str| -> String {
            let (text, cut) = truncate_chars(&redact_secrets(text), settings.max_text_chars);
            truncated |= cut;
            text
        };

        let mut ctx = self.ctx;
        ctx.duration_ms = self.started.elapsed().as_millis() as u64;
        ctx.message_count = Some(
            self.request
                .input_count
                .unwrap_or(self.request.messages.len() as u32),
        );
        ctx.tools_offered = self.request.tools;
        if let Some(model) = self.acc.model.take() {
            ctx.model = Some(model);
        }
        ctx.finish_reason = self.acc.finish_reason.take();
        ctx.usage = self.acc.usage_seen.then_some(self.acc.usage.clone());
        ctx.error = self.acc.error.take().map(|e| clip(&e));

        ctx.tool_calls = self
            .acc
            .tool_calls
            .into_values()
            .map(|call| ModelToolCall {
                name: call.name,
                id: call.id,
                arguments: settings.content().then(|| clip(&call.arguments)),
            })
            .collect();

        // Embedding inputs are often whole documents: metadata only.
        if settings.content() && self.api != ModelApi::Embeddings {
            ctx.system = self.request.system.as_deref().map(&mut clip);
            let messages = &self.request.messages;
            let skip = messages.len().saturating_sub(settings.max_messages);
            ctx.messages = messages[skip..]
                .iter()
                .map(|m| ModelMessage {
                    role: m.role.clone(),
                    text: clip(&m.text),
                })
                .collect();
            if skip > 0 {
                self.notes
                    .push(format!("{skip} earlier messages omitted (max_messages)"));
            }
            ctx.output_text =
                (!self.acc.output_text.is_empty()).then(|| clip(&self.acc.output_text));
            ctx.reasoning_text =
                (!self.acc.reasoning_text.is_empty()).then(|| clip(&self.acc.reasoning_text));
        }

        ctx.truncated = truncated;
        ctx.capture_note = (!self.notes.is_empty()).then(|| self.notes.join("; "));
        ctx
    }
}

// ── WebSocket observation ───────────────────────────────────────────────────

/// A complete WebSocket message seen on the wire.
#[derive(Debug, PartialEq, Eq)]
pub enum WsMessage {
    Text(Vec<u8>),
    /// A text message larger than the decoder's limit; its content was not
    /// kept.
    Oversized,
    Binary,
    Close,
}

/// Incremental RFC 6455 frame decoder that only observes: it never alters or
/// holds back the bytes it is fed.
#[derive(Debug)]
pub struct WsFrameDecoder {
    limit: usize,
    header: Vec<u8>,
    payload_remaining: u64,
    mask: Option<[u8; 4]>,
    mask_pos: usize,
    frame_opcode: u8,
    frame_fin: bool,
    message_opcode: u8,
    message: Vec<u8>,
    control: Vec<u8>,
    pub overflow: bool,
}

impl WsFrameDecoder {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            header: Vec::with_capacity(14),
            payload_remaining: 0,
            mask: None,
            mask_pos: 0,
            frame_opcode: 0,
            frame_fin: false,
            message_opcode: 0,
            message: Vec::new(),
            control: Vec::new(),
            overflow: false,
        }
    }

    fn header_len(header: &[u8]) -> Option<usize> {
        if header.len() < 2 {
            return None;
        }
        let masked = header[1] & 0x80 != 0;
        let extended = match header[1] & 0x7f {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        Some(2 + extended + if masked { 4 } else { 0 })
    }

    pub fn feed(&mut self, mut data: &[u8], out: &mut Vec<WsMessage>) {
        while !data.is_empty() {
            if self.payload_remaining == 0 && self.header_in_progress() {
                let needed = Self::header_len(&self.header).unwrap_or(2);
                let take = (needed - self.header.len()).min(data.len());
                self.header.extend_from_slice(&data[..take]);
                data = &data[take..];
                if Self::header_len(&self.header) == Some(self.header.len()) {
                    self.start_frame(out);
                }
                continue;
            }

            let take = (self.payload_remaining.min(data.len() as u64)) as usize;
            let chunk = &data[..take];
            data = &data[take..];
            self.payload_remaining -= take as u64;

            let target = if self.frame_opcode >= 0x8 {
                &mut self.control
            } else {
                &mut self.message
            };
            let room = self.limit.saturating_sub(target.len()).min(chunk.len());
            let start = target.len();
            target.extend_from_slice(&chunk[..room]);
            if let Some(mask) = self.mask {
                for (offset, byte) in target[start..].iter_mut().enumerate() {
                    *byte ^= mask[(self.mask_pos + offset) % 4];
                }
            }
            self.mask_pos += chunk.len();
            if room < chunk.len() && self.frame_opcode < 0x8 {
                self.overflow = true;
            }

            if self.payload_remaining == 0 {
                self.end_frame(out);
            }
        }
    }

    /// True while waiting for (the rest of) a frame header.
    fn header_in_progress(&self) -> bool {
        Self::header_len(&self.header) != Some(self.header.len()) || self.header.is_empty()
    }

    fn start_frame(&mut self, out: &mut Vec<WsMessage>) {
        let header = std::mem::take(&mut self.header);
        self.frame_fin = header[0] & 0x80 != 0;
        self.frame_opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let (len, offset) = match header[1] & 0x7f {
            126 => (u16::from_be_bytes([header[2], header[3]]) as u64, 4),
            127 => {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&header[2..10]);
                (u64::from_be_bytes(raw), 10)
            }
            len => (len as u64, 2),
        };
        self.mask = masked.then(|| {
            let mut key = [0u8; 4];
            key.copy_from_slice(&header[offset..offset + 4]);
            key
        });
        self.mask_pos = 0;
        self.payload_remaining = len;
        if self.frame_opcode >= 0x8 {
            self.control.clear();
        } else if self.frame_opcode != 0 {
            self.message_opcode = self.frame_opcode;
            self.message.clear();
            self.overflow = false;
        }
        if len == 0 {
            self.end_frame(out);
        }
    }

    fn end_frame(&mut self, out: &mut Vec<WsMessage>) {
        match self.frame_opcode {
            0x8 => out.push(WsMessage::Close),
            0x9 | 0xA => {}
            _ if self.frame_fin => {
                let message = std::mem::take(&mut self.message);
                match self.message_opcode {
                    0x1 if !self.overflow => out.push(WsMessage::Text(message)),
                    0x1 => out.push(WsMessage::Oversized),
                    _ => out.push(WsMessage::Binary),
                }
            }
            _ => {}
        }
    }
}

/// Tracks Responses-API calls multiplexed over one WebSocket.
#[derive(Debug)]
pub struct WsModelSession {
    settings: CaptureSettings,
    target: ModelTarget,
    current: Option<ModelCallRecorder>,
}

impl WsModelSession {
    pub fn new(settings: CaptureSettings, target: ModelTarget) -> Self {
        Self {
            settings,
            target,
            current: None,
        }
    }

    /// A message from the client. Returns a call that was still open and got
    /// superseded by a new request.
    pub fn on_client_text(&mut self, text: &[u8]) -> Option<ModelCallAuditContext> {
        let value: Value = serde_json::from_slice(text).ok()?;
        let kind = str_at(&value, "type").unwrap_or("");
        if kind != "response.create" {
            return None;
        }
        let previous = self
            .current
            .take()
            .map(|call| call.finish(Some("superseded by a new response.create".to_string())));
        self.current = Some(ModelCallRecorder::for_websocket(
            self.settings,
            &self.target,
            text,
        ));
        previous
    }

    /// A client message too large to decode. It is most likely the next
    /// request, so the open call is closed and a new, unparsed one begins.
    pub fn on_client_oversized(&mut self) -> Option<ModelCallAuditContext> {
        let previous = self
            .current
            .take()
            .map(|call| call.finish(Some("superseded by a new request message".to_string())));
        let mut call = ModelCallRecorder::for_websocket(self.settings, &self.target, b"");
        call.ctx.request_sha256 = None;
        call.truncated = true;
        call.note_once("request message exceeded max_capture_bytes and was not parsed");
        self.current = Some(call);
        previous
    }

    /// A server message too large to decode: the open call's output is
    /// incomplete.
    pub fn on_server_oversized(&mut self) {
        if let Some(call) = self.current.as_mut() {
            call.truncated = true;
            call.note_once("a server message exceeded max_capture_bytes and was not parsed");
        }
    }

    /// A message from the server. Returns the call once it completes.
    pub fn on_server_text(&mut self, text: &[u8]) -> Option<ModelCallAuditContext> {
        let call = self.current.as_mut()?;
        call.on_event(text);
        if call.is_complete() {
            return self.current.take().map(|call| call.finish(None));
        }
        None
    }

    pub fn close(&mut self, note: &str) -> Option<ModelCallAuditContext> {
        self.current
            .take()
            .map(|call| call.finish(Some(note.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(mode: CaptureMode) -> CaptureSettings {
        CaptureSettings {
            mode,
            max_capture_bytes: 1 << 20,
            max_text_chars: 1000,
            max_messages: 10,
        }
    }

    fn target(host: &str, path: &str) -> ModelTarget {
        detect_target(host, path).expect("model target")
    }

    #[test]
    fn detects_provider_apis_from_paths() {
        let t = target("api.openai.com", "/v1/chat/completions");
        assert_eq!(
            (t.provider.as_str(), t.api),
            ("openai", ModelApi::OpenAiChat)
        );
        let t = target("chatgpt.com", "/backend-api/codex/responses");
        assert_eq!(t.api, ModelApi::OpenAiResponses);
        let t = target("openrouter.ai", "/api/v1/chat/completions");
        assert_eq!(t.provider, "openrouter");
        let t = target("api.anthropic.com", "/v1/messages");
        assert_eq!(t.api, ModelApi::AnthropicMessages);
        assert!(detect_target("api.anthropic.com", "/v1/messages/count_tokens").is_none());
        assert!(detect_target("api.openai.com", "/v1/models").is_none());

        let t = target(
            "generativelanguage.googleapis.com",
            "/v1beta/models/gemini-2.5-pro:streamGenerateContent",
        );
        assert_eq!(t.api, ModelApi::GeminiGenerate);
        assert_eq!(t.model_from_path.as_deref(), Some("gemini-2.5-pro"));
        assert!(t.stream_from_path);

        let t = target(
            "us-east5-aiplatform.googleapis.com",
            "/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-opus-5:streamRawPredict",
        );
        assert_eq!(
            (t.provider.as_str(), t.api),
            ("vertex", ModelApi::AnthropicMessages)
        );
        assert_eq!(t.model_from_path.as_deref(), Some("claude-opus-5"));

        let t = target(
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/us.anthropic.claude-sonnet-5-v1%3A0/converse-stream",
        );
        assert_eq!(t.api, ModelApi::BedrockConverse);
        assert_eq!(
            t.model_from_path.as_deref(),
            Some("us.anthropic.claude-sonnet-5-v1:0")
        );
        assert!(t.stream_from_path);
    }

    #[test]
    fn host_globs_gate_capture() {
        let traffic = ModelTraffic::new(ModelTrafficConfig {
            capture: CaptureMode::Metadata,
            ..ModelTrafficConfig::default()
        })
        .expect("traffic");
        assert!(traffic.is_model_host("bedrock-runtime.eu-west-1.amazonaws.com"));
        assert!(traffic.is_model_host("API.OpenAI.com"));
        assert!(!traffic.is_model_host("github.com"));
        assert!(
            traffic
                .target_for("github.com", "/v1/chat/completions")
                .is_none()
        );

        let off = ModelTraffic::new(ModelTrafficConfig::default()).expect("traffic");
        assert!(off.is_model_host("api.openai.com"));
        assert!(
            off.target_for("api.openai.com", "/v1/chat/completions")
                .is_none()
        );
    }

    #[test]
    fn redacts_common_credentials() {
        let text = "key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123 and AKIAABCDEFGHIJKLMNOP \
                    with Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig ok";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("abcdefghijklmnop"), "{redacted}");
        assert!(!redacted.contains("AKIAABCD"), "{redacted}");
        assert!(!redacted.contains("eyJhbGci"), "{redacted}");
        assert!(redacted.contains("Bearer [REDACTED]"), "{redacted}");
        // Short or embedded prefixes are left alone.
        assert_eq!(
            redact_secrets("task-sk-1 and sk-short"),
            "task-sk-1 and sk-short"
        );
    }

    #[test]
    fn openai_chat_stream_accumulates_text_tools_and_usage() {
        let body = serde_json::json!({
            "model": "gpt-5",
            "stream": true,
            "messages": [
                {"role": "system", "content": "You are Nebula. token sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA"},
                {"role": "user", "content": [{"type": "text", "text": "scan the host"}]}
            ],
            "tools": [{"type": "function", "function": {"name": "run_nmap"}}]
        });
        let body = serde_json::to_vec(&body).unwrap();
        let t = target("api.openai.com", "/v1/chat/completions");
        let mut rec = ModelCallRecorder::for_http(settings(CaptureMode::Content), &t, &body, None);
        rec.on_response_head(200, Some("text/event-stream; charset=utf-8"), None);

        let stream = concat!(
            "data: {\"model\":\"gpt-5-2026\",\"choices\":[{\"delta\":{\"content\":\"Run\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"ning\",\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"run_nmap\",\"arguments\":\"{\\\"t\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"1}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":7,\"total_tokens\":19}}\n\n",
            "data: [DONE]\n\n"
        );
        // Split mid-event to exercise incremental framing.
        let (a, b) = stream.as_bytes().split_at(37);
        rec.on_body_chunk(a);
        rec.on_body_chunk(b);
        let ctx = rec.finish(None);

        assert_eq!(ctx.transport, "sse");
        assert_eq!(ctx.model.as_deref(), Some("gpt-5-2026"));
        assert!(ctx.stream);
        assert_eq!(ctx.message_count, Some(2));
        assert_eq!(ctx.tools_offered, vec!["run_nmap"]);
        assert_eq!(ctx.output_text.as_deref(), Some("Running"));
        assert_eq!(ctx.finish_reason.as_deref(), Some("tool_calls"));
        assert_eq!(ctx.tool_calls.len(), 1);
        assert_eq!(ctx.tool_calls[0].name, "run_nmap");
        assert_eq!(ctx.tool_calls[0].arguments.as_deref(), Some("{\"t\":1}"));
        let usage = ctx.usage.expect("usage");
        assert_eq!(
            (usage.input_tokens, usage.output_tokens),
            (Some(12), Some(7))
        );
        let system = ctx.system.expect("system");
        assert!(system.contains("[REDACTED]") && !system.contains("AAAAAAAA"));
    }

    #[test]
    fn metadata_mode_omits_content() {
        let body = br#"{"model":"claude-opus-5","system":"secret plan","messages":[{"role":"user","content":"hi"}],"tools":[{"name":"bash"}]}"#;
        let t = target("api.anthropic.com", "/v1/messages");
        let mut rec = ModelCallRecorder::for_http(settings(CaptureMode::Metadata), &t, body, None);
        rec.on_response_head(200, Some("application/json"), None);
        rec.on_body_chunk(
            br#"{"type":"message","model":"claude-opus-5","content":[{"type":"text","text":"hello"},{"type":"tool_use","id":"t1","name":"bash","input":{"cmd":"id"}}],"stop_reason":"tool_use","usage":{"input_tokens":5,"output_tokens":3,"cache_read_input_tokens":100}}"#,
        );
        let ctx = rec.finish(None);
        assert_eq!(ctx.transport, "http");
        assert_eq!(ctx.finish_reason.as_deref(), Some("tool_use"));
        assert_eq!(ctx.tool_calls[0].name, "bash");
        assert!(ctx.tool_calls[0].arguments.is_none());
        assert!(ctx.system.is_none() && ctx.messages.is_empty() && ctx.output_text.is_none());
        assert_eq!(ctx.usage.unwrap().cache_read_tokens, Some(100));
        assert!(ctx.request_sha256.is_some());
    }

    #[test]
    fn anthropic_stream_collects_thinking_and_tool_input() {
        let t = target("api.anthropic.com", "/v1/messages");
        let body = br#"{"model":"claude-opus-5","stream":true,"messages":[]}"#;
        let mut rec = ModelCallRecorder::for_http(settings(CaptureMode::Content), &t, body, None);
        rec.on_response_head(200, Some("text/event-stream"), None);
        rec.on_body_chunk(concat!(
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-5\",\"usage\":{\"input_tokens\":9}}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"plan\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu\",\"name\":\"Bash\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"ls\\\"}\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":4}}\n\n",
        ).as_bytes());
        let ctx = rec.finish(None);
        assert_eq!(ctx.reasoning_text.as_deref(), Some("plan"));
        assert_eq!(ctx.tool_calls[0].name, "Bash");
        assert_eq!(
            ctx.tool_calls[0].arguments.as_deref(),
            Some("{\"command\":\"ls\"}")
        );
        let usage = ctx.usage.unwrap();
        assert_eq!(
            (usage.input_tokens, usage.output_tokens),
            (Some(9), Some(4))
        );
    }

    #[test]
    fn gemini_and_bedrock_responses_parse() {
        let t = target(
            "generativelanguage.googleapis.com",
            "/v1beta/models/gemini-2.5-flash:generateContent",
        );
        let body = br#"{"systemInstruction":{"parts":[{"text":"be brief"}]},"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"lookup"}]},{"googleSearch":{}}]}"#;
        let mut rec = ModelCallRecorder::for_http(settings(CaptureMode::Content), &t, body, None);
        rec.on_response_head(200, Some("application/json"), None);
        rec.on_body_chunk(br#"{"candidates":[{"content":{"parts":[{"text":"hmm","thought":true},{"text":"hello"},{"functionCall":{"name":"lookup","args":{"q":1}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":2,"thoughtsTokenCount":1},"modelVersion":"gemini-2.5-flash-001"}"#);
        let ctx = rec.finish(None);
        assert_eq!(ctx.model.as_deref(), Some("gemini-2.5-flash-001"));
        assert_eq!(ctx.system.as_deref(), Some("be brief"));
        assert_eq!(ctx.tools_offered, vec!["lookup", "googleSearch"]);
        assert_eq!(ctx.output_text.as_deref(), Some("hello"));
        assert_eq!(ctx.reasoning_text.as_deref(), Some("hmm"));
        assert_eq!(ctx.tool_calls[0].name, "lookup");

        let t = target(
            "bedrock-runtime.us-east-1.amazonaws.com",
            "/model/anthropic.claude-v5/converse",
        );
        let body = br#"{"system":[{"text":"sys"}],"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"calc"}}]}}"#;
        let mut rec = ModelCallRecorder::for_http(settings(CaptureMode::Content), &t, body, None);
        rec.on_response_head(200, Some("application/json"), None);
        rec.on_body_chunk(br#"{"output":{"message":{"role":"assistant","content":[{"text":"4"},{"toolUse":{"toolUseId":"x","name":"calc","input":{"a":2}}}]}},"stopReason":"tool_use","usage":{"inputTokens":8,"outputTokens":2,"totalTokens":10}}"#);
        let ctx = rec.finish(None);
        assert_eq!(ctx.model.as_deref(), Some("anthropic.claude-v5"));
        assert_eq!(ctx.tools_offered, vec!["calc"]);
        assert_eq!(ctx.output_text.as_deref(), Some("4"));
        assert_eq!(ctx.usage.unwrap().total_tokens, Some(10));
    }

    #[test]
    fn encoded_or_error_responses_are_noted() {
        let t = target("api.openai.com", "/v1/responses");
        let mut rec = ModelCallRecorder::for_http(
            settings(CaptureMode::Content),
            &t,
            b"\x28\xb5",
            Some("zstd"),
        );
        rec.on_response_head(429, Some("application/json"), None);
        rec.on_body_chunk(br#"{"error":{"message":"Rate limit reached","type":"rate_limit"}}"#);
        let ctx = rec.finish(None);
        assert_eq!(ctx.status, Some(429));
        assert_eq!(ctx.error.as_deref(), Some("Rate limit reached"));
        assert!(ctx.capture_note.unwrap().contains("zstd"));
    }

    #[test]
    fn truncates_text_and_limits_messages() {
        let mut s = settings(CaptureMode::Content);
        s.max_text_chars = 5;
        s.max_messages = 1;
        let t = target("api.openai.com", "/v1/chat/completions");
        let body = br#"{"model":"m","messages":[{"role":"user","content":"first"},{"role":"user","content":"second message"}]}"#;
        let rec = ModelCallRecorder::for_http(s, &t, body, None);
        let ctx = rec.finish(None);
        assert_eq!(ctx.message_count, Some(2));
        assert_eq!(ctx.messages.len(), 1);
        assert_eq!(ctx.messages[0].text, "secon…");
        assert!(ctx.truncated);
        assert!(
            ctx.capture_note
                .unwrap()
                .contains("1 earlier messages omitted")
        );
    }

    fn ws_frame(opcode: u8, fin: bool, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut frame = vec![(if fin { 0x80 } else { 0 }) | opcode];
        let mask_bit = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            len if len < 126 => frame.push(mask_bit | len as u8),
            len if len <= u16::MAX as usize => {
                frame.push(mask_bit | 126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            }
            len => {
                frame.push(mask_bit | 127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
        }
        match mask {
            Some(key) => {
                frame.extend_from_slice(&key);
                frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
            }
            None => frame.extend_from_slice(payload),
        }
        frame
    }

    #[test]
    fn ws_decoder_handles_masking_fragmentation_and_control_frames() {
        let mut wire = ws_frame(0x1, false, b"hel", Some([1, 2, 3, 4]));
        wire.extend(ws_frame(0x9, true, b"ping", Some([9, 9, 9, 9])));
        wire.extend(ws_frame(0x0, true, b"lo", Some([5, 6, 7, 8])));
        let big = vec![b'x'; 70_000];
        wire.extend(ws_frame(0x1, true, &big, None));
        wire.extend(ws_frame(0x2, true, b"\x00\x01", None));
        wire.extend(ws_frame(0x8, true, b"", None));

        let mut decoder = WsFrameDecoder::new(1 << 20);
        let mut out = Vec::new();
        // One byte at a time exercises every header/payload boundary.
        for byte in &wire {
            decoder.feed(std::slice::from_ref(byte), &mut out);
        }
        assert_eq!(out.len(), 4);
        assert_eq!(out[0], WsMessage::Text(b"hello".to_vec()));
        assert_eq!(out[1], WsMessage::Text(big));
        assert_eq!(out[2], WsMessage::Binary);
        assert_eq!(out[3], WsMessage::Close);
    }

    #[test]
    fn ws_session_records_responses_calls() {
        let t = target("chatgpt.com", "/backend-api/codex/responses");
        let mut session = WsModelSession::new(settings(CaptureMode::Content), t);
        assert!(session
            .on_client_text(br#"{"type":"response.create","model":"gpt-5-codex","instructions":"You are Codex","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"fix bug"}]}],"tools":[{"type":"function","name":"shell"}]}"#)
            .is_none());
        assert!(
            session
                .on_server_text(br#"{"type":"response.output_text.delta","delta":"On it"}"#)
                .is_none()
        );
        let ctx = session
            .on_server_text(br#"{"type":"response.completed","response":{"model":"gpt-5-codex","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"On it."}]},{"type":"function_call","call_id":"c","name":"shell","arguments":"{\"cmd\":[\"ls\"]}"}],"usage":{"input_tokens":20,"output_tokens":5,"output_tokens_details":{"reasoning_tokens":2}}}}"#)
            .expect("completed call");
        assert_eq!(ctx.transport, "websocket");
        assert_eq!(ctx.api, "openai.responses");
        assert_eq!(ctx.system.as_deref(), Some("You are Codex"));
        assert_eq!(ctx.messages[0].text, "fix bug");
        assert_eq!(ctx.output_text.as_deref(), Some("On it."));
        assert_eq!(ctx.tool_calls[0].name, "shell");
        assert_eq!(ctx.finish_reason.as_deref(), Some("completed"));
        assert_eq!(ctx.usage.unwrap().reasoning_tokens, Some(2));

        session
            .on_client_text(br#"{"type":"response.create","model":"gpt-5-codex","input":"again"}"#);
        let open = session.close("websocket closed").expect("open call");
        assert!(open.capture_note.unwrap().contains("websocket closed"));
    }

    #[test]
    fn detects_azure_ollama_and_embedding_endpoints() {
        let t = target(
            "contoso.openai.azure.com",
            "/openai/deployments/gpt-5-prod/chat/completions",
        );
        assert_eq!(
            (t.provider.as_str(), t.api),
            ("azure-openai", ModelApi::OpenAiChat)
        );
        assert_eq!(t.model_from_path.as_deref(), Some("gpt-5-prod"));
        let t = target("contoso.openai.azure.com", "/openai/v1/responses");
        assert_eq!(t.api, ModelApi::OpenAiResponses);
        let t = target(
            "contoso.openai.azure.com",
            "/openai/deployments/embed-small/embeddings",
        );
        assert_eq!(t.api, ModelApi::Embeddings);
        assert_eq!(t.model_from_path.as_deref(), Some("embed-small"));

        assert_eq!(target("gpu-box", "/api/chat").api, ModelApi::OllamaChat);
        assert_eq!(
            target("gpu-box", "/api/generate").api,
            ModelApi::OllamaGenerate
        );
        assert_eq!(target("gpu-box", "/api/embed").api, ModelApi::Embeddings);
        assert_eq!(
            target("vllm.lan", "/v1/embeddings").api,
            ModelApi::Embeddings
        );
        let t = target(
            "generativelanguage.googleapis.com",
            "/v1beta/models/text-embedding-004:embedContent",
        );
        assert_eq!(t.api, ModelApi::Embeddings);
        assert!(detect_target("gpu-box", "/api/tags").is_none());

        let traffic = ModelTraffic::new(ModelTrafficConfig {
            capture: CaptureMode::Metadata,
            extra_hosts: vec!["*.lan".to_string()],
            ..ModelTrafficConfig::default()
        })
        .expect("traffic");
        assert!(traffic.is_model_host("contoso.openai.azure.com"));
        assert!(traffic.is_model_host("api.openai.com"), "defaults are kept");
        assert_eq!(
            traffic
                .target_for("vllm.lan", "/v1/chat/completions")
                .map(|t| t.api),
            Some(ModelApi::OpenAiChat)
        );
    }

    #[test]
    fn ollama_ndjson_stream_accumulates_output_tools_and_usage() {
        let t = target("gpu-box", "/api/chat");
        let body = br#"{"model":"qwen3","messages":[{"role":"system","content":"be terse"},{"role":"user","content":"list files"}],"tools":[{"type":"function","function":{"name":"ls"}}]}"#;
        let mut rec = ModelCallRecorder::for_http(settings(CaptureMode::Content), &t, body, None);
        rec.on_response_head(200, Some("application/x-ndjson"), None);
        let stream = concat!(
            "{\"model\":\"qwen3\",\"message\":{\"role\":\"assistant\",\"content\":\"Let\"}}\n",
            "{\"model\":\"qwen3\",\"message\":{\"role\":\"assistant\",\"content\":\" me\",\"thinking\":\"hmm\"}}\n",
            "not json\n",
            "{\"model\":\"qwen3\",\"message\":{\"role\":\"assistant\",\"content\":\"\",\"tool_calls\":[{\"function\":{\"name\":\"ls\",\"arguments\":{\"path\":\"/tmp\"}}}]},",
            "\"done\":true,\"done_reason\":\"stop\",\"prompt_eval_count\":11,\"eval_count\":4}\n"
        );
        let (a, b) = stream.as_bytes().split_at(50);
        rec.on_body_chunk(a);
        rec.on_body_chunk(b);
        let ctx = rec.finish(None);
        assert_eq!(ctx.api, "ollama.chat");
        assert!(ctx.stream, "Ollama streams unless told otherwise");
        assert_eq!(ctx.system.as_deref(), Some("be terse"));
        assert_eq!(ctx.tools_offered, vec!["ls"]);
        assert_eq!(ctx.output_text.as_deref(), Some("Let me"));
        assert_eq!(ctx.reasoning_text.as_deref(), Some("hmm"));
        assert_eq!(ctx.tool_calls[0].name, "ls");
        assert_eq!(
            ctx.tool_calls[0].arguments.as_deref(),
            Some("{\"path\":\"/tmp\"}")
        );
        assert_eq!(ctx.finish_reason.as_deref(), Some("stop"));
        let usage = ctx.usage.expect("usage");
        assert_eq!(
            (usage.input_tokens, usage.output_tokens),
            (Some(11), Some(4))
        );
        assert!(
            ctx.capture_note
                .expect("note")
                .contains("1 streamed events were not valid JSON")
        );

        let t = target("gpu-box", "/api/generate");
        let body = br#"{"model":"llama3","prompt":"why is the sky blue","system":"physicist","stream":false}"#;
        let mut rec = ModelCallRecorder::for_http(settings(CaptureMode::Content), &t, body, None);
        rec.on_response_head(200, Some("application/json; charset=utf-8"), None);
        rec.on_body_chunk(br#"{"model":"llama3","response":"Rayleigh scattering.","done":true,"done_reason":"stop","prompt_eval_count":6,"eval_count":3}"#);
        let ctx = rec.finish(None);
        assert!(!ctx.stream);
        assert_eq!(ctx.messages[0].text, "why is the sky blue");
        assert_eq!(ctx.output_text.as_deref(), Some("Rayleigh scattering."));
    }

    #[test]
    fn embeddings_are_metadata_only_even_in_content_mode() {
        let t = target("api.openai.com", "/v1/embeddings");
        let body = br#"{"model":"text-embedding-3-small","input":["secret document one","secret document two"]}"#;
        let mut rec = ModelCallRecorder::for_http(settings(CaptureMode::Content), &t, body, None);
        rec.on_response_head(200, Some("application/json"), None);
        rec.on_body_chunk(br#"{"object":"list","data":[{"embedding":[0.1,0.2]},{"embedding":[0.3,0.4]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":8,"total_tokens":8}}"#);
        let ctx = rec.finish(None);
        assert_eq!(ctx.api, "embeddings");
        assert_eq!(ctx.message_count, Some(2));
        assert_eq!(ctx.usage.unwrap().input_tokens, Some(8));
        assert!(ctx.messages.is_empty() && ctx.system.is_none() && ctx.output_text.is_none());
    }

    #[test]
    fn unparsed_sse_events_are_noted() {
        let t = target("api.openai.com", "/v1/chat/completions");
        let mut rec = ModelCallRecorder::for_http(
            settings(CaptureMode::Metadata),
            &t,
            br#"{"model":"m","stream":true,"messages":[]}"#,
            None,
        );
        rec.on_response_head(200, Some("text/event-stream"), None);
        rec.on_body_chunk(b"data: {\"choices\":[]}\n\ndata: {broken\n\ndata: [DONE]\n\n");
        let ctx = rec.finish(None);
        assert!(
            ctx.capture_note
                .unwrap()
                .contains("1 streamed events were not valid JSON")
        );
    }

    #[test]
    fn oversized_websocket_messages_mark_the_call_truncated() {
        let mut decoder = WsFrameDecoder::new(8);
        let mut out = Vec::new();
        decoder.feed(
            &ws_frame(0x1, true, b"far too long for the limit", None),
            &mut out,
        );
        decoder.feed(&ws_frame(0x1, true, b"short", None), &mut out);
        assert_eq!(
            out,
            vec![WsMessage::Oversized, WsMessage::Text(b"short".to_vec())]
        );

        let t = target("chatgpt.com", "/backend-api/codex/responses");
        let mut session = WsModelSession::new(settings(CaptureMode::Metadata), t);
        session.on_client_text(br#"{"type":"response.create","model":"gpt-5-codex","input":"a"}"#);
        // A huge follow-up request closes the open call and starts an unparsed one.
        let superseded = session.on_client_oversized().expect("previous call");
        assert!(superseded.capture_note.unwrap().contains("superseded"));
        session.on_server_oversized();
        let ctx = session
            .on_server_text(
                br#"{"type":"response.completed","response":{"status":"completed","output":[]}}"#,
            )
            .expect("completed call");
        assert!(ctx.truncated);
        let note = ctx.capture_note.unwrap();
        assert!(
            note.contains("request message exceeded max_capture_bytes"),
            "{note}"
        );
        assert!(
            note.contains("a server message exceeded max_capture_bytes"),
            "{note}"
        );
        assert!(ctx.request_sha256.is_none());
    }
}
