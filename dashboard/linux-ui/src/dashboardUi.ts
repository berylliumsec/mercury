import type { StreamStatus } from "./dashboardTypes";

export function fmt(ts: string): string {
  return new Date(ts).toLocaleString();
}

/** Compact event time: time only for today, short date + time otherwise. */
export function fmtTime(ts: string): string {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) {
    return ts;
  }
  const sameDay = date.toDateString() === new Date().toDateString();
  const time = date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
  return sameDay
    ? time
    : `${date.toLocaleDateString([], { month: "short", day: "numeric" })} ${time}`;
}

export function statusBadge(value: string): string {
  switch (value) {
    case "deny":
      return "pill pill-deny";
    case "allow":
      return "pill pill-allow";
    case "observe":
      return "pill pill-observe";
    default:
      return "pill";
  }
}

export function streamBadgeClass(value: StreamStatus): string {
  switch (value) {
    case "connected":
      return "pill pill-stream-ok";
    case "reconnecting":
      return "pill pill-stream-warn";
    case "connecting":
      return "pill";
    case "disconnected":
      return "pill pill-stream-off";
    default:
      return "pill";
  }
}

export function csvEscape(value: string | number | null | undefined): string {
  const text = String(value ?? "");
  if (!/[",\n]/.test(text)) {
    return text;
  }
  return `"${text.replace(/"/g, '""')}"`;
}
