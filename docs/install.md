# Install and Hardening Notes (Linux)

## Files

- Daemon config: `/etc/mercury/config.yaml`
- Policy file: `/etc/mercury/policy.yaml`
- Socket: `/run/mercury/mercuryd.sock`
- Audit log: `/var/log/mercury/audit.jsonl`

## Systemd

- Service file: `deploy/systemd/mercuryd.service`
- Tmpfiles: `deploy/systemd/mercuryd.tmpfiles.conf`

Install:

```bash
cargo build --workspace --release
npm --prefix dashboard/linux-ui ci
npm --prefix dashboard/linux-ui run build
sudo ./scripts/install_mercury_system.sh --preflight-only
sudo ./scripts/install_mercury_system.sh
```

The dashboard now defaults to loopback-only `127.0.0.1:7480`. To expose it intentionally, pass
an explicit bind address:

```bash
sudo ./scripts/install_mercury_system.sh --dashboard-expose
sudo ./scripts/install_mercury_system.sh --dashboard-bind-addr 192.0.2.10:7480
```

Non-loopback dashboard binds now require a trusted TLS certificate. Use `--acme-domain` /
`--acme-email` or `--tls-cert-file` / `--tls-key-file`. If you want TLS termination elsewhere,
keep Mercury bound to localhost and put it behind a reverse proxy.

If you explicitly want Mercury's self-signed certificate on a non-loopback bind, opt in:

```bash
sudo ./scripts/install_mercury_system.sh --dashboard-expose --no-tls --dashboard-allow-self-signed
```

Log out/in (or start a new login shell) after `usermod` so `mercury-run` can access `/run/mercury/mercuryd.sock` without `sudo`.

The installer also seeds `dashboard.launch.user` to the invoking non-root user when possible. If you
start the daemon manually from source, set `dashboard.launch.user` to a non-root Linux username
before using the Agents tab.

Fresh installs also generate `/etc/mercury/dashboard.password`, `/etc/mercury/policy-signing-key`,
and re-sign `/etc/mercury/policy.yaml` so the shipped config can use `signature_verification: require_valid`
without exposing first-login bootstrap signup.

The repo-local installer mirrors the release installer's preflight behavior. Use `--force` only
when you have already reviewed the host prerequisites and intentionally want to continue anyway.

Uninstall while preserving config and data:

```bash
sudo ./scripts/uninstall_mercury_system.sh
```

Purge config and runtime data too:

```bash
sudo ./scripts/uninstall_mercury_system.sh --purge
```

## Hardening checklist

- Restrict `/etc/mercury` ownership to root.
- Restrict policy write access to trusted admins.
- Keep `dashboard.bind_addr` on loopback unless you intentionally front it with a reverse proxy or firewall.
- Keep `signature_verification: require_valid` and protect `/etc/mercury/policy-signing-key`.
- Use `policy_unavailable_mode: fail_closed` for strict environments.
- Start rollout with observe mode in policy per action class.
- Forward journald + JSONL logs to centralized SIEM.
- Build hosts need `clang` with BPF target support to compile the embedded kernel object.
- Keep `backend_mode: kernel_strict` in production to fail closed when kernel hooks are unavailable.
- Use `backend_mode: linux_compat` only on Linux hosts where AppArmor is available but full eBPF
  LSM prerequisites are not.
- Ensure Linux 6.1+, bpffs mounted (`/sys/fs/bpf`), BPF LSM enabled, and cgroup v2 mounted for
  `kernel_strict`.
- Run agent commands via `mercury-run` for explicit profile registration; use `kernel.auto_enroll_rules` for systemd/cgroup profile enrollment.
- For support tiers, backups, rollback, and operational alerts, see [`docs/public-prod.md`](public-prod.md).
