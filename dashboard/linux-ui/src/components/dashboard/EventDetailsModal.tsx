import { useEffect, useMemo, useState } from "react";

import { decisionLabel, isInformational } from "../../actionTypes";
import { fmt, statusBadge } from "../../dashboardUi";
import { eventDetailFields, eventRecord } from "../../eventDetails";
import type { EventItem } from "../../eventHelpers";
import { AppIcon } from "./AppIcon";

type EventDetailsModalProps = {
  item: EventItem;
  onClose: () => void;
};

export function EventDetailsModal({ item, onClose }: EventDetailsModalProps) {
  const [copied, setCopied] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  const fields = useMemo(() => eventDetailFields(item), [item]);
  const record = useMemo(() => eventRecord(item), [item]);
  const informational = isInformational(item);

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
      await navigator.clipboard.writeText(JSON.stringify(record, null, 2));
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="modal-overlay" data-testid="event-details-modal">
      <div
        className="modal-card event-details-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="event-details-title"
      >
        <div className="modal-header">
          <h3 id="event-details-title">
            <span className="button-with-icon">
              <AppIcon name="event" className="app-icon-sm" />
              <span>Event #{item.id}</span>
            </span>
            <span
              className={informational ? "pill pill-info" : statusBadge(item.effective_decision)}
            >
              {decisionLabel(item)}
            </span>
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
          <p className="meta">
            {fmt(item.timestamp)} · <span className="mono">{item.resource}</span>
          </p>
          <dl className="event-details-grid" data-testid="event-details-fields">
            {fields.map((field) => (
              <div
                key={field.key}
                className="event-details-row"
                data-testid={`event-field-${field.key}`}
              >
                <dt>{field.label}</dt>
                <dd className={field.mono ? "mono" : undefined}>{field.value}</dd>
              </div>
            ))}
          </dl>
          {showRaw ? (
            <pre className="event-details-raw" data-testid="event-details-raw">
              {JSON.stringify(record, null, 2)}
            </pre>
          ) : null}
        </div>

        <div className="modal-footer">
          <button className="ghost" onClick={() => setShowRaw((value) => !value)}>
            <span className="button-with-icon">
              <AppIcon name="eye" className="app-icon-sm" />
              <span>{showRaw ? "Hide raw record" : "Show raw record"}</span>
            </span>
          </button>
          <button
            className="ghost"
            onClick={() => void handleCopy()}
            data-testid="event-details-copy"
          >
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
