import { useEffect, useState } from "react";

import {
  captureNotices,
  formatBytes,
  formatDurationMs,
  formatTokens,
  hasCapturedContent,
  modelCallLabel,
  roleLabel,
  transportLabel,
  type ModelCall
} from "../../modelCall";
import { fmt } from "../../dashboardUi";
import type { EventItem } from "../../eventHelpers";
import { AppIcon } from "./AppIcon";

type ModelCallModalProps = {
  item: EventItem;
  call: ModelCall;
  onClose: () => void;
};

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="model-call-meta-row">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function TextBlock({ text }: { text: string }) {
  return <p className="model-call-text">{text}</p>;
}

export function ModelCallModal({ item, call, onClose }: ModelCallModalProps) {
  const [copied, setCopied] = useState(false);
  const notices = captureNotices(call);
  const contentCaptured = hasCapturedContent(call);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        onClose();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  useEffect(() => {
    if (!copied) {
      return;
    }
    const timer = window.setTimeout(() => setCopied(false), 2000);
    return () => window.clearTimeout(timer);
  }, [copied]);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(call, null, 2));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="modal-overlay" data-testid="model-call-modal">
      <div
        className="modal-card model-call-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="model-call-title"
      >
        <div className="modal-header">
          <h3 id="model-call-title">
            <span className="button-with-icon">
              <AppIcon name="transcript" className="app-icon-sm" />
              <span>Model call</span>
            </span>
            <span className="pill pill-model">{modelCallLabel(call)}</span>
          </h3>
          <button
            className="ghost icon-only-button"
            onClick={onClose}
            aria-label="Close"
            title="Close"
          >
            <AppIcon name="close" className="app-icon-sm" />
            <span className="sr-only">Close</span>
          </button>
        </div>

        <div className="modal-body">
          <dl className="model-call-meta">
            <MetaRow label="API" value={call.api || "unknown"} />
            <MetaRow label="Transport" value={transportLabel(call)} />
            <MetaRow label="Status" value={call.status != null ? String(call.status) : "none"} />
            <MetaRow label="Duration" value={formatDurationMs(call.duration_ms)} />
            <MetaRow label="Tokens" value={formatTokens(call.usage)} />
            <MetaRow label="Finish reason" value={call.finish_reason ?? "not reported"} />
            <MetaRow
              label="Bytes"
              value={`${formatBytes(call.request_bytes)} up · ${formatBytes(call.response_bytes)} down`}
            />
            <MetaRow
              label="Messages"
              value={call.message_count != null ? String(call.message_count) : "not reported"}
            />
            <MetaRow label="Agent" value={item.agent_id || "unknown"} />
            <MetaRow label="Observed" value={fmt(item.timestamp)} />
          </dl>

          {call.tools_offered.length ? (
            <section className="model-call-section">
              <h4>Tools offered</h4>
              <div className="model-call-chips">
                {call.tools_offered.map((tool) => (
                  <span key={tool} className="pill pill-neutral mono" title={tool}>
                    {tool}
                  </span>
                ))}
              </div>
            </section>
          ) : null}

          {notices.length ? (
            <ul className="model-call-notices" data-testid="model-call-notices">
              {notices.map((notice) => (
                <li key={notice}>
                  <AppIcon name="info" className="app-icon-sm" />
                  <span>{notice}</span>
                </li>
              ))}
            </ul>
          ) : null}

          {call.system ? (
            <section className="model-call-section">
              <h4>System prompt</h4>
              <TextBlock text={call.system} />
            </section>
          ) : null}

          {call.messages.length ? (
            <section className="model-call-section">
              <h4>Transcript</h4>
              <ol className="model-call-transcript" data-testid="model-call-transcript">
                {call.messages.map((message, index) => (
                  <li
                    key={`${message.role}-${index}`}
                    className={`model-call-message model-call-message-${message.role.toLowerCase()}`}
                  >
                    <span className="model-call-role">{roleLabel(message.role)}</span>
                    <TextBlock text={message.text} />
                  </li>
                ))}
              </ol>
            </section>
          ) : null}

          {call.output_text ? (
            <section className="model-call-section">
              <h4>Model output</h4>
              <TextBlock text={call.output_text} />
            </section>
          ) : null}

          {call.reasoning_text ? (
            <section className="model-call-section">
              <h4>Reasoning</h4>
              <TextBlock text={call.reasoning_text} />
            </section>
          ) : null}

          {call.tool_calls.length ? (
            <section className="model-call-section">
              <h4>Tool calls</h4>
              <ul className="model-call-tool-calls">
                {call.tool_calls.map((toolCall, index) => (
                  <li key={toolCall.id ?? `${toolCall.name}-${index}`}>
                    <span className="model-call-role mono">{toolCall.name}</span>
                    {toolCall.arguments ? (
                      <TextBlock text={toolCall.arguments} />
                    ) : (
                      <p className="model-call-text model-call-muted">
                        Arguments are captured at content level only.
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          <p className="model-call-footnote">
            {contentCaptured
              ? "The gateway redacts credential-shaped strings, clips long fields, drops thinking blocks and keeps only the most recent messages, so this is not a verbatim copy of the exchange. Request headers are never recorded."
              : "Request headers are never recorded, and no prompt or output text was captured for this call."}
          </p>
        </div>

        <div className="modal-footer">
          <button className="ghost" onClick={() => void handleCopy()} data-testid="model-call-copy">
            <span className="button-with-icon">
              <AppIcon name={copied ? "check" : "copy"} className="app-icon-sm" />
              <span>{copied ? "Copied" : "Copy JSON"}</span>
            </span>
          </button>
          <button className="primary" onClick={onClose}>
            <span className="button-with-icon">
              <AppIcon name="close" className="app-icon-sm" />
              <span>Close</span>
            </span>
          </button>
        </div>
      </div>
    </div>
  );
}
