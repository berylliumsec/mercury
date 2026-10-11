# AI Policy Authoring for Mercury

The safest workflow is:

1. Ask the model for a `mercury-policy-patch/v1` JSON document, not YAML.
2. Merge that patch into a real Mercury policy with `mercury-policy-patch`.
3. Validate the rendered YAML with Mercury.
4. Sign the rendered policy before reload if your environment requires signatures.

## Files

- Prompt template: `docs/ai/mercury-policy-patch.prompt.md`
- JSON schema: `docs/ai/mercury-policy-patch.schema.json`
- Example patch: `docs/ai/example-policy-patch.json`
- Renderer: `tools/mercury-policy-patch`

## Why this shape

- It keeps the model inside Mercury's actual profile schema instead of free-form YAML.
- It avoids unsupported output like top-level `rules`.
- It lets the renderer generate or repair rule IDs deterministically.
- It preserves validation in the existing Rust `policy-engine`.
- It removes stale signatures automatically so the final file can be re-signed cleanly.

## Suggested model flow

Use the prompt in `docs/ai/mercury-policy-patch.prompt.md` and attach the schema in
`docs/ai/mercury-policy-patch.schema.json` as the response contract.

Pass the model:

- The current Mercury profile or policy snippet
- The target profile name
- The plain-English request

If the model is uncertain, it should return `needs_clarification: true` and one or more short
questions instead of guessing.

## Render and validate

Build the helper:

```bash
cargo build -p mercury-policy-patch
```

Render a patch into an existing policy:

```bash
cargo run -p mercury-policy-patch -- render \
  --policy policy.nebula.yaml \
  --patch docs/ai/example-policy-patch.json \
  --output /tmp/policy.rendered.yaml
```

Create a missing profile while rendering:

```bash
cargo run -p mercury-policy-patch -- render \
  --policy policy.nebula.yaml \
  --patch docs/ai/example-policy-patch.json \
  --output /tmp/policy.rendered.yaml \
  --create-profile
```

Validate the result with the existing Mercury validator:

```bash
cargo run -p cli --bin mercury-policy -- validate --file /tmp/policy.rendered.yaml
```

Sign afterward if needed:

```bash
cargo run -p cli --bin mercury-policy -- sign \
  --file /tmp/policy.rendered.yaml \
  --key-file /etc/mercury/policy-signing-key
```

## Operational rules

- Keep policy defaults human-managed unless the request explicitly asks to change enforcement.
- Prefer URL rules for HTTP(S) access and CIDR rules for raw network access.
- If a network rule uses `host_glob`, make sure the profile also has at least one URL rule.
- Treat the renderer output as the source of truth, not the raw model response.
