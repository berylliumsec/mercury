import { request } from "./apiClient";

/** Filename from a Content-Disposition header, or `fallback`. */
export function filenameFromDisposition(header: string | null, fallback: string): string {
  const match = header ? /filename="?([^";]+)"?/i.exec(header) : null;
  return match?.[1]?.trim() || fallback;
}

/** Fetches an authenticated export endpoint and saves the response as a file. */
export async function downloadExport(path: string, fallbackName: string): Promise<void> {
  const response = await request(path);
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(text || `export failed: ${response.status}`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filenameFromDisposition(
    response.headers.get("content-disposition"),
    fallbackName
  );
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** RFC 3339 lower bound for a relative export range; null means everything. */
export function rangeStart(range: string, now = Date.now()): string | null {
  const hours: Record<string, number> = { "24h": 24, "7d": 24 * 7, "30d": 24 * 30 };
  const span = hours[range];
  return span ? new Date(now - span * 60 * 60 * 1000).toISOString() : null;
}

/** `/actions/export` URL for a relative range ("24h", "7d", "30d", or "all"). */
export function actionsExportPath(range: string, now = Date.now()): string {
  const start = rangeStart(range, now);
  return start ? `/actions/export?${new URLSearchParams({ start }).toString()}` : "/actions/export";
}
