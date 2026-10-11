# Audit log: integrity, rotation, durability and journald

`mercuryd` writes every audit record to `audit_jsonl_path`
(`/var/log/mercury/audit.jsonl`), one JSON object per line, and mirrors it to
journald. This page covers the writer in `crates/audit` and the
`mercury-audit` verification tool.

## Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `audit_integrity` | `true` | Sign every record with a chained HMAC. `false` opts out. |
| `audit_integrity_key_path` | unset → `/var/lib/mercury/audit-integrity.key` | Key file (64 hex chars) or a secret reference `env:VAR`, `creds:NAME`, `literal:HEX`. |
| `audit_fsync` | `interval` | `none`, `interval` or `always` (see Durability). |
| `audit_max_file_bytes` | `104857600` (100 MiB) | Rotate the active file at this size. |
| `audit_max_files` | `10` | Rotated files kept (`audit.jsonl.1` … `.10`) besides the active file. |
| `mirror_to_journald` | `true` | Mirror records to journald. |
| `journald_mirror_mode` | `native` | `native` (journald native protocol) or `syslog` (pre-v2 behavior). |

## Record stamping

Before a record is written, missing context is filled in: `event_id` (UUID
v4), `schema_version` (`core_types::AUDIT_SCHEMA_VERSION`) and `host` (the
hostname, read once at startup). Values already set by the caller are kept, so
a daemon that pre-stamps `event_id` gets the same id in the file, journald and
the dashboard.

## Integrity chain (v2)

A signed record carries one extra trailing member, so every line stays valid
JSON for `jq` and log shippers:

```json
{"timestamp":"…","agent_id":"…",…,"integrity":{"v":2,"seq":1042,"mac":"<64 hex>"}}
```

- `mac = HMAC-SHA256(key, prev_mac ‖ seq as 8-byte big-endian ‖ json)`, where
  `json` is the line without the `integrity` member (the text before
  `,"integrity":` followed by `}`) and `prev_mac` is the previous record's MAC.
- `seq` grows by one per record for the life of the chain — across daemon
  restarts, rotation and reopen — so removed records and removed files show
  up as gaps.

The writer keeps the chain continuous and records every discontinuity as a
signed `SYSTEM_EVENT` with `source: "audit"`:

| Event | Written when | Attributes |
| --- | --- | --- |
| `audit_chain_start` | A new chain begins; signed with an all-zero `prev_mac`. | `reason`: `new_log`, `unsigned_tail`, `legacy_v1_tail`, `tail_mac_mismatch` (key changed or tail edited), `unrecognized_tail`, `unreadable_tail`; `prev_seq` when known (seq keeps counting). |
| `audit_chain_link` | First record of a new file that continues the chain. | `reason`: `rotation`, `reopen` (SIGHUP after an external rename), `file_replaced` / `file_missing` (path changed under the writer), `open` (empty active file at startup, continuing from `audit.jsonl.1`); `prev_seq`, `prev_mac`, `prev_file`. |
| `audit_file_expired` | Written into the active file just before the oldest rotated file is deleted. | `file`, `size_bytes`, `first_seq`, `last_seq`, `final_mac`. |
| `audit_integrity_unavailable` | Unsigned. The default key could not be read or created; the log continues without integrity. | `detail`: the error. |

On startup the writer reads the last two lines of the active file, verifies
the last record's MAC against its predecessor and resumes from its `seq` and
MAC. A record cut off by a crash is terminated with a newline and the chain
continues from the last complete record. Before every write the writer checks
that the configured path still names the open file; if it was renamed or
deleted, the writer reopens and links to the previous file.

### Key management

- Unset `audit_integrity_key_path`: `/var/lib/mercury/audit-integrity.key` is
  created on first start (0600, directory 0700 if created). If it cannot be
  read or created, the daemon still starts: the error is logged, recorded in
  the audit stats, and written to the log as `audit_integrity_unavailable`.
- A configured file path must exist and hold a valid key, or the daemon fails
  to start (unchanged behavior).
- Secret references are resolved in memory. Earlier versions wrote the
  resolved key to `/var/log/mercury/.audit-integrity-key`; that no longer
  happens. Verify with the same secret (`--key -` reads it from stdin).
- A different key on restart starts a new chain (`tail_mac_mismatch`), which
  verification reports as a restart.

## Verifying

```sh
mercury-audit verify                                # key and files at their defaults
mercury-audit verify --key /path/key audit.jsonl*   # any order; .N suffixes are sorted
printf %s "$KEY_HEX" | mercury-audit verify --key - --json /archive/audit.jsonl.3
```

Files are checked oldest first (`.N` highest first, the unnumbered file
last). Exit status: `0` intact, `1` any integrity error, `2` usage or I/O
error. `--partial` downgrades a missing predecessor of the first file to a
warning when checking a subset. `--json` prints the full `ChainReport`.

| Issue | Severity | Meaning |
| --- | --- | --- |
| `mac_mismatch` | error | Record edited, or wrong key. Verification resynchronizes and continues. |
| `sequence_gap` | error | Records removed (or reordered) inside the set. |
| `broken_link` | error | A link record does not point at the record before it: a file is missing or was replaced. |
| `chain_restart` | error | A new chain starts after signed records. |
| `missing_predecessor` | error | The set starts mid-chain and no `audit_file_expired` record explains the predecessor (oldest file deleted or moved away). |
| `unsigned_record` | error | A record without a v2 integrity member after the chain began (integrity was turned off, or a line was inserted). |
| `malformed_line` | error | Not a JSON record (torn write or edit). |
| `truncated_tail` | error | The last line has no newline: the final record was cut off. |
| `no_signed_records` | error | Nothing could be verified. |
| `expired_predecessor` | info | The set starts with a link to a file whose expiry is recorded. |
| `legacy_records` | warning | Unsigned or v1 records written before the chain began. |

Legacy v1 files (`<json>\t|integrity=sha256:<hex>`) still verify. v1 chains
restarted from zero on every daemon start and rotation, so v1 restarts are
counted and reported as a warning: removals at those points are not
detectable.

### What is and is not detectable

Detected: edited records, removed records, removed or replaced rotated files,
truncation or deletion of the active file while the daemon runs, deletion of
the oldest file without an expiry record, key changes, integrity being turned
off. Not detectable from the files alone: removing the newest records (or the
whole active file) while the daemon is stopped. The journald mirror carries
`MERCURY_AUDIT_SEQ` on every entry, so comparing the last journald sequence
with the file detects that; shipping records off-host does too. The key lives
on the same host: root can re-sign a forged log, so treat the chain as tamper
evidence against everyone else and ship logs off-host for protection against
root.

## Rotation

When the active file reaches `audit_max_file_bytes`, files shift
(`.9` → `.10`, …, active → `.1`) and the new active file starts with an
`audit_chain_link`. Before a file past `audit_max_files` is deleted, an
`audit_file_expired` record describing it is written, so expiry is never
silent and a verifier can tell expiry from deletion. Files left over from a
larger `audit_max_files` are expired the same way.

External `logrotate` still works: send SIGHUP (or just let the writer notice
the rename on its next write). Prefer the built-in rotation; with `dateext`
naming, pass the files to `mercury-audit verify` explicitly in order.

## Durability

- `interval` (default): fdatasync at most once per second while the file is
  dirty, and within ~100 ms after a DENY or SYSTEM_EVENT record. Syncs run on
  a background thread on a duplicated descriptor, so writers never wait for
  the disk.
- `always`: fdatasync after every record.
- `none`: never fdatasync.

With `interval` and `always` the file is also synced before rotation or
reopen switches files, the directory is synced after rotation, and the file
is synced on close. `AuditLogger::sync()` forces a sync (the daemon should
call it on shutdown).

## journald mirror

`native` mode sends each record to `/run/systemd/journal/socket` in the
journald native protocol:

| Field | Value |
| --- | --- |
| `MESSAGE` | `mercury <decision> <ACTION> <resource> agent=<id>` |
| `PRIORITY` | 3 for `ERROR_*` reasons, 4 for denies and `telemetry_loss` / `audit_integrity_unavailable`, 5 for other system events, 6 for allows |
| `SYSLOG_IDENTIFIER` | `mercury` |
| `MERCURY_EVENT_ID`, `MERCURY_DECISION`, `MERCURY_REASON`, `MERCURY_ACTION`, `MERCURY_RULE_ID`, `MERCURY_AGENT_ID`, `MERCURY_PID`, `MERCURY_PROFILE`, `MERCURY_SOURCE` | Record fields (unset ones omitted) |
| `MERCURY_AUDIT_SEQ` | Chain sequence number (integrity on) |
| `MERCURY_JSON` | The full record (without the `integrity` member) |
| `MERCURY_TRUNCATED` | `1` when the record did not fit (below) |

```sh
journalctl -t mercury MERCURY_DECISION=deny
journalctl -t mercury -p warning -o json | jq -r .MERCURY_JSON
```

Records over 200 KiB (or any that fail with `EMSGSIZE`) are written to a
sealed memfd passed with `SCM_RIGHTS`, as `sd_journal_sendv()` does. If that
fails, the record is resent without captured model content (`system`,
`messages`, `output_text`, `reasoning_text`, tool call `arguments`) and with
`MERCURY_TRUNCATED=1`, then without `MERCURY_JSON` at all. Sends time out
after 250 ms so a stalled journald cannot block enforcement. Every truncation
and failure is counted.

`syslog` mode keeps the pre-v2 behavior: an RFC 3164 line
(`<pri>mercury decision=… data=<json>`, facility local0) on
`/run/systemd/journal/syslog`. That socket is journald's forwarding socket to
a local syslog daemon; journald itself does not store these messages. The
priority now follows the table above instead of a fixed `<134>`.

## Monitoring

`AuditLogger::stats()` returns `AuditStats` (serde-serializable):
`records_written`, `write_failures` (writes, rotations, reopens, fdatasyncs),
`mirror_failures`, `mirror_truncated`, `rotations`, `files_expired`,
`last_error`, `last_error_at`, `integrity_enabled`, `chain_seq`. When a file
write fails the record is still mirrored to journald.

## Upgrading

- Hosts that ran with integrity off get an `audit_chain_start`
  (`unsigned_tail`) on first start; `mercury-audit verify` reports the older
  records as a `legacy_records` warning.
- Hosts with a v1 chain get `audit_chain_start` (`legacy_v1_tail`); the v1
  part still verifies with the same key.
- Signed lines are now valid JSON. Tools that parsed the v1 tab suffix
  (`\t|integrity=sha256:`) need to read the `integrity` member instead.
