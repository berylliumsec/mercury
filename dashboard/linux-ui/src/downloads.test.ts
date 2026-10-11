import { describe, expect, it } from "vitest";

import { actionsExportPath, filenameFromDisposition, rangeStart } from "./downloads";

describe("filenameFromDisposition", () => {
  it("uses the server-provided filename when present", () => {
    expect(
      filenameFromDisposition('attachment; filename="mercury-events-20260929T101500Z.jsonl"', "x")
    ).toBe("mercury-events-20260929T101500Z.jsonl");
    expect(filenameFromDisposition(null, "fallback.csv")).toBe("fallback.csv");
    expect(filenameFromDisposition("inline", "fallback.csv")).toBe("fallback.csv");
  });
});

describe("export ranges", () => {
  const now = Date.parse("2026-09-29T12:00:00Z");

  it("computes RFC 3339 lower bounds for relative ranges", () => {
    expect(rangeStart("24h", now)).toBe("2026-09-28T12:00:00.000Z");
    expect(rangeStart("7d", now)).toBe("2026-09-22T12:00:00.000Z");
    expect(rangeStart("all", now)).toBeNull();
  });

  it("builds the action export URL for a range", () => {
    expect(actionsExportPath("24h", now)).toBe(
      "/actions/export?start=2026-09-28T12%3A00%3A00.000Z"
    );
    expect(actionsExportPath("all", now)).toBe("/actions/export");
  });
});
