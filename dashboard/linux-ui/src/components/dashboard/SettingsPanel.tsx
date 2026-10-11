import { FormEvent, useState } from "react";
import { api } from "../../apiClient";
import { AppIcon } from "./AppIcon";
import type { TlsCertInfo } from "../../dashboardTypes";

// ── helpers ──────────────────────────────────────────────────────────────────

function certExpiryTone(expiresAt: string): "ok" | "warn" | "error" {
  const now = Date.now();
  const expiry = new Date(expiresAt).getTime();
  const daysLeft = (expiry - now) / (1000 * 60 * 60 * 24);
  if (daysLeft < 0) return "error";
  if (daysLeft < 14) return "warn";
  return "ok";
}

function friendlyExpiry(expiresAt: string): string {
  const now = Date.now();
  const expiry = new Date(expiresAt).getTime();
  const daysLeft = Math.round((expiry - now) / (1000 * 60 * 60 * 24));
  if (daysLeft < 0) return `Expired ${Math.abs(daysLeft)}d ago`;
  if (daysLeft === 0) return "Expires today";
  return `Expires in ${daysLeft}d`;
}

// ── TLS panel ─────────────────────────────────────────────────────────────────

type TlsPanelProps = {
  certInfo?: TlsCertInfo | null;
  csrfToken: string;
  onReloaded: (info: TlsCertInfo) => void;
};

function TlsPanel({ certInfo, csrfToken, onReloaded }: TlsPanelProps) {
  const [certFile, setCertFile] = useState(certInfo?.cert_file ?? "");
  const [keyFile, setKeyFile] = useState(certInfo?.key_file ?? "");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const result = await api<TlsCertInfo>("/settings/tls", {
        method: "PUT",
        body: JSON.stringify({
          cert_file: certFile.trim(),
          key_file: keyFile.trim()
        }),
        headers: { "x-csrf-token": csrfToken }
      });
      onReloaded(result);
      setMessage({ ok: true, text: "Certificate reloaded successfully." });
    } catch (err: unknown) {
      const text = err instanceof Error ? err.message : "Failed to reload certificate.";
      setMessage({ ok: false, text });
    } finally {
      setBusy(false);
    }
  }

  const tone = certInfo ? certExpiryTone(certInfo.expires_at) : null;

  return (
    <div className="settings-tls-panel">
      <h2 className="settings-section-title">TLS Certificate</h2>

      {certInfo ? (
        <div className={`tls-cert-status tls-cert-status--${tone}`}>
          <div className="tls-cert-status-row">
            <AppIcon name={tone === "ok" ? "shield" : "warning"} className="app-icon-sm" />
            <span className="tls-cert-status-label">
              {certInfo.is_self_signed
                ? "Self-signed certificate"
                : `Issued by: ${certInfo.issuer}`}
            </span>
            <span className={`tls-cert-expiry tls-cert-expiry--${tone}`}>
              {friendlyExpiry(certInfo.expires_at)}
            </span>
          </div>
          {certInfo.is_self_signed && (
            <p className="tls-cert-selfsg-hint">
              Browsers will show a security warning for self-signed certificates. Use Let&rsquo;s
              Encrypt or a trusted CA certificate for production.
            </p>
          )}
          <div className="tls-cert-paths">
            <span className="tls-cert-path-label">Certificate:</span>
            <code>{certInfo.cert_file}</code>
          </div>
          <div className="tls-cert-paths">
            <span className="tls-cert-path-label">Key:</span>
            <code>{certInfo.key_file}</code>
          </div>
        </div>
      ) : (
        <div className="tls-cert-status tls-cert-status--unknown">
          <AppIcon name="info" className="app-icon-sm" />
          <span>TLS status unavailable (daemon may be starting).</span>
        </div>
      )}

      <form className="settings-tls-form" onSubmit={(e) => void handleSubmit(e)}>
        <h3 className="settings-sub-title">Hot-swap Certificate</h3>
        <p className="settings-hint">
          Provide PEM file paths already present on the server. The daemon will reload without
          restarting. You can also send <code>SIGHUP</code> to the daemon to reload the current
          certificate from disk.
        </p>

        <label className="settings-field-label">
          Certificate file (PEM)
          <input
            data-testid="tls-cert-file-input"
            className="settings-input"
            type="text"
            value={certFile}
            onChange={(e) => setCertFile(e.target.value)}
            placeholder="/etc/mercury/dashboard.crt"
            required
          />
        </label>

        <label className="settings-field-label">
          Private key file (PEM)
          <input
            data-testid="tls-key-file-input"
            className="settings-input"
            type="text"
            value={keyFile}
            onChange={(e) => setKeyFile(e.target.value)}
            placeholder="/etc/mercury/dashboard.key"
            required
          />
        </label>

        {message && (
          <div
            data-testid="tls-status-message"
            className={`settings-message ${message.ok ? "settings-message--ok" : "settings-message--error"}`}
          >
            {message.text}
          </div>
        )}

        <div className="settings-tls-actions">
          <button data-testid="tls-submit-button" type="submit" className="primary" disabled={busy}>
            {busy ? "Reloading…" : "Save & Reload"}
          </button>
        </div>
      </form>

      <div className="settings-tls-guide">
        <h3 className="settings-sub-title">Obtaining a Trusted Certificate</h3>
        <p className="settings-hint">
          <strong>Let&rsquo;s Encrypt</strong> — run on the server while port 80 is free:
        </p>
        <pre className="settings-code-block">{`certbot certonly --standalone \\
  --non-interactive --agree-tos \\
  -m you@example.com \\
  -d guard.example.com`}</pre>
        <p className="settings-hint">
          Then set the paths above to{" "}
          <code>/etc/letsencrypt/live/&lt;domain&gt;/fullchain.pem</code> and{" "}
          <code>/etc/letsencrypt/live/&lt;domain&gt;/privkey.pem</code>. Add a deploy hook at{" "}
          <code>/etc/letsencrypt/renewal-hooks/deploy/mercuryd.sh</code> to send <code>SIGHUP</code>{" "}
          after each renewal.
        </p>
      </div>
    </div>
  );
}

// ── Settings page root ────────────────────────────────────────────────────────

type SettingsPanelProps = {
  certInfo?: TlsCertInfo | null;
  csrfToken: string;
  onCertInfoUpdate: (info: TlsCertInfo) => void;
};

export function SettingsPanel({ certInfo, csrfToken, onCertInfoUpdate }: SettingsPanelProps) {
  return (
    <div className="settings-panel" data-testid="settings-panel">
      <TlsPanel certInfo={certInfo} csrfToken={csrfToken} onReloaded={onCertInfoUpdate} />
    </div>
  );
}
