# URL gateway, MCP and model capture audit records

This page describes what the URL gateway (`url-gateway`) and MCP governance
(`mcp`) write to the audit log, how related records are joined, and what is
redacted. All fields named here are schema v2 fields from
`core_types::AuditEvent` / `EventContext`; `context.*` fields are serialized
at the top level of each JSON record.

## Record kinds

| Record | `action_type` | `source` | Key fields |
| --- | --- | --- | --- |
| Proxied request decision | `NET_CONNECT` | `url-gateway` | `resource` (redacted URL, `dest_ip`), `decision`, `rule_id`, `correlation_id`, `pid`, `root_pid`, `parent_agent_id` |
| Proxied request outcome | `NET_CONNECT` | `url-gateway` | same as the decision plus `outcome {status, bytes_sent, bytes_received, duration_ms, error}`; `model` when the request was a model API call |
| Model call on a WebSocket | `NET_CONNECT` | `url-gateway` | `model`, `correlation_id` of the connection (no `outcome`) |
| CONNECT refused (interception off) | `NET_CONNECT` | `url-gateway` | `decision: DENY`, `reason: DENY_FAIL_CLOSED`, `rule_id: url_gateway.tls_intercept_disabled`, `resource.dest_host/dest_port`, `resource.method: CONNECT` |
| Proxy authentication failure | `SYSTEM_EVENT` `gateway_auth_failure` | `url-gateway` | `decision: DENY`, `reason: DENY_FAIL_CLOSED`, attributes `failure` (`invalid_proxy_token`, `unresolved_subject`), `peer`, `peer_pid`, `method`, `target` (redacted), `token_present` |
| TLS interception failure | `SYSTEM_EVENT` `tls_intercept_failed` | `url-gateway` | `decision: DENY`, `reason: DENY_FAIL_CLOSED`, attributes `host`, `port`, `stage` (`certificate`, `handshake`, `upgrade`), `error`; agent attribution |
| Rate-limit summary | `SYSTEM_EVENT` (same event name, `detail: rate_limited`) | as the suppressed records | attributes `key`, `suppressed`, `window_seconds` |
| MCP gateway authentication failure | `SYSTEM_EVENT` `gateway_auth_failure` | `mcp` | `decision: DENY`, attributes `failure` (`missing_token`, `invalid_token`, `unknown_session`, `wrong_transport`), `gateway: mcp_http`, `mcp_session_id`, `session_agent_id` |
| Observed MCP JSON-RPC traffic | `MCP_REQUEST`, `resource.kind: SYSTEM`, `event: mcp_request` | `mcp` | attributes `method`, `request_id`, `notification`, `server_id`, `mcp_session_id`, `transport`; `initialize` adds `server_name`, `server_version`, `protocol_version`; `tools/list` adds `tools [{name, sha256}]`, `tool_count`, `next_cursor`; `outcome`, `correlation_id` |
| MCP tool result | `MCP_REQUEST`, `event: mcp_tool_result` | `mcp` | attributes `tool_name`, `tool_call_id`, `is_error`, `content_types`, `content_items`, `structured_content`, `result_bytes`, `result_sha256`, `jsonrpc_error_code`, `approval_request_id`, `content` (content capture only); `mcp`, `outcome`, `correlation_id` |
| MCP tool definition changed | `SYSTEM_EVENT` `mcp_tool_definition_changed` | `mcp` | attributes `server_id`, `tool_name`, `previous_sha256`, `sha256`, `mcp_session_id`, `previous_mcp_session_id` |
| MCP approval requested | `SYSTEM_EVENT` `mcp_approval_requested` | `mcp` | attributes `kind` (`tool`, `resource`, `prompt`), `request_id`, `tool_name` / `resource_uri`, `call_id`, `arguments_sha256`, `arguments_summary`, `expires_at`; `rule_id`, `mcp`, `correlation_id` = request id |
| MCP approval resolution | `MCP_TOOL_CALL` / `MCP_RESOURCE_READ` | `mcp` | `reason` (`ALLOW_BY_APPROVAL`, `DENY_BY_APPROVAL`, `DENY_APPROVAL_EXPIRED`), `actor` (approver), `correlation_id` = request id; message carries `request_id=`, `approver=`, `requested_at=`, `latency_ms=` |
| MCP approvals unavailable | `MCP_TOOL_CALL` / `MCP_RESOURCE_READ` | `mcp` | `decision: DENY`, `reason: DENY_FAIL_CLOSED`, `rule_id` of the approval rule |
| MCP authorization (existing) | `MCP_TOOL_CALL` / `MCP_RESOURCE_READ` | `mcp` | now also `root_pid`, `parent_agent_id`; a repeated `tool_call_id` for a call still in flight is audited too |

`MCP_REQUEST` and informational `SYSTEM_EVENT` records carry
`decision: ALLOW, reason: INFORMATIONAL`: they are observations, not policy
decisions.

## Correlation

* Every allowed proxied request gets one `correlation_id` (a UUID) shared by
  its decision record and its outcome record. A plain HTTP request has
  exactly one outcome record; for a model API call that outcome record also
  carries `model`, so each call is one record (the decision is the other).
* A WebSocket connection has one decision, one model-call record per
  Responses API call, and one outcome record when the socket closes
  (`outcome.status: 101`, bytes per direction), all sharing the id.
* Upstream failures are outcome records too: 502 (connect, DNS, TLS, client
  build), 504 (header timeout), 400 (unreadable request body), with
  `outcome.error`.
* MCP calls that needed approval: `mcp_approval_requested`, the resolution
  record and the `mcp_tool_result` share the approval request id.
* MCP calls that did not: `mcp_tool_result` and `mcp_request` use
  `<mcp_session_id>:<JSON-RPC id>`; the authorization record can be joined
  through `mcp.mcp_session_id` + `mcp.tool_call_id`.

## Attribution

* `pid` of a proxied request is the process that owns the client socket
  (found through `/proc/net/tcp{,6}`), even when the request authenticated
  with the proxy token the launcher puts in `HTTP_PROXY`. The token still
  decides which agent the request belongs to. `ppid` is that process's
  parent. When the owner cannot be found, the registration pid is used.
* `root_pid` is the agent's registration pid; `parent_agent_id` is set for
  MCP server agents registered with a parent (proxied requests and all MCP
  records).
* The socket-owner cache is keyed by the full peer socket address (IPv6
  peers no longer share one slot), and IPv6/v4-mapped loopback peers are
  resolved through `/proc/net/tcp6`.

## Upstream address pinning (`network_deny` CIDR rules)

After URL policy allows a request, the gateway resolves the host once, and
checks every `network_deny` rule that has a `cidr` (with its `port`,
`protocol` and `host_glob`, as the policy engine applies them) against each
resolved address. Denied addresses are dropped; the request is sent only to
the remaining ones and the host is never resolved again (HTTP clients are
pinned per host and address set and still fall back between those addresses,
IPv6 to IPv4, as after a normal lookup; WebSockets try them in order).
`resource.dest_ip` records the first permitted address. If every address is
denied the request is refused with `DENY_BY_RULE` and that rule's id, or
recorded as `ALLOW_BY_OBSERVE_MODE` when the profile's network enforcement is
`observe`. This closes the
DNS-rebinding / SSRF gap where an allowed hostname resolving to
`169.254.169.254` or an RFC 1918 address was reachable because URL rules take
precedence over network rules.

Behavior change: a profile that allows a hostname with `url_allow` while
denying its address range with a CIDR `network_deny` rule is now blocked for
that host through the gateway, consistently with the kernel hooks.

Hosts denied by URL policy are never resolved.

## Redaction

Policy is evaluated on the original request; only logged copies are
redacted.

* URLs (`resource.full_url`, `resource.query`, `target` attributes): values of
  query and fragment keys `key`, `api_key`/`apikey`, `token`,
  `access_token`, `refresh_token`, `id_token`, `auth_token`,
  `session_token`, `sig`, `signature`, `password`, `passwd`, `pwd`,
  `secret`, `client_secret`, `auth`, `code`, `X-Amz-Signature`,
  `X-Amz-Credential`, `X-Amz-Security-Token`, `X-Goog-Signature`,
  `X-Goog-Credential`, and any key ending in `token`, `secret`, `password`,
  `apikey`, `signature` or `secretkey` (case, `-`, `_` and `.` ignored).
  Userinfo passwords become `user:[REDACTED]@`. Azure SAS `sig` is redacted;
  `sv` (a version date) is kept.
* Text (model prompts/outputs/tool arguments, MCP argument summaries, MCP
  tool result content, error messages): PEM private key blocks, `key=value` /
  `key: value` / `"key": "value"` for the keys above plus
  `aws_secret_access_key`, `private_key`, `AccountKey`, `SharedAccessKey`,
  `Authorization:` / `Proxy-Authorization:` (scheme kept), `Cookie:`,
  `user:pass@` in URLs, bearer tokens, JWTs, standalone 40-character AWS
  secret keys, and the formats `sk-` (OpenAI, `sk-proj-`, Anthropic
  `sk-ant-`), `sk_live_`/`rk_live_` (Stripe), `AKIA`/`ASIA`, `AIza`,
  `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`/`github_pat_`, `xox[abprs]-`, `glpat-`.
* MCP argument summaries are redacted, then cut to 160 characters on a
  character boundary (a multibyte character at byte 160 used to panic the
  daemon).

Not redacted: `arguments_json` stored in the dashboard's SQLite approval
table (needed for the approver to see the call).

## Rate limiting

Records that a peer can trigger before authenticating (`gateway_auth_failure`
from either gateway, `tls_intercept_failed`) are limited to 20 per peer per
60-second window. The URL gateway keys peers by socket-owner pid (else IP);
the MCP gateway by session path. At most 64 peers are tracked per window;
further peers share one `other` bucket. When a window that dropped records
closes, one summary record reports the count: the URL gateway checks every
30 s, the MCP gateway on its next request.

## MCP HTTP gateway traffic

Every JSON-RPC method other than the four policy-evaluated ones
(`tools/call`, `resources/read`, `prompts/list`, `prompts/get`) now produces
an `mcp_request` record after the upstream answers. For `tools/list` the
digest of each tool covers `title`, `description`, `inputSchema`,
`outputSchema` and `annotations` (keys sorted, so reordering is not a
change). The gateway remembers the last digest per (profile, server id, tool)
for the daemon's lifetime and writes `mcp_tool_definition_changed` when a
later listing differs, whether in the same session or a later one. Tools
first seen in a later page or listing are not flagged (paginated lists would
otherwise look like additions); they are listed in the `mcp_request` record.

`tools/call` results are recorded as `mcp_tool_result`. Raw content is only
included when `url_gateway.model_traffic.capture: content`, redacted and cut
to `model_traffic.max_text_chars`.

Stdio MCP servers report only completion status to the daemon, so they have
no `mcp_tool_result` record.

## Model capture

* New APIs: Azure OpenAI (`*.openai.azure.com`, now a default model host;
  `/openai/deployments/{deployment}/chat/completions|responses|embeddings`,
  deployment recorded as the model until the response names one), Ollama
  (`/api/chat`, `/api/generate`, NDJSON streaming, `stream` defaults to true),
  and embeddings (`/embeddings`, Ollama `/api/embed`, Gemini
  `:embedContent`/`:batchEmbedContents`), which are always metadata only:
  model, input count (`message_count`) and token usage, never inputs or
  vectors.
* SSE, NDJSON and WebSocket events that are not valid JSON are counted in
  `capture_note` instead of being dropped silently.
* A WebSocket text message larger than `max_capture_bytes` marks the call
  `truncated` with a note; an oversized client message starts a new
  (unparsed) call so later server events are not attributed to the previous
  one.

### Config keys

| Key | Default | Meaning |
| --- | --- | --- |
| `url_gateway.model_traffic.extra_hosts` | `[]` | Host globs added to `model_traffic.hosts` without restating the built-in list (self-hosted OpenAI-compatible servers, Ollama, vLLM, LiteLLM). OpenAI-compatible paths (`/chat/completions`, `/responses`, `/embeddings`) are recognised on any model host. |

Note that `localhost`, `127.0.0.1` and `::1` are in the default `no_proxy`,
so a local Ollama is only observed if it is reached through another name or
`no_proxy` is changed.

## Known limits

* The gateway and model capture only run for profiles with URL rules; there
  is no `proxy_all_profiles` switch yet.
* When one MCP server runs several tool calls at once, kernel events of its
  processes are attributed to the most recent call (calls carry no per-call
  process information to disambiguate).
