import { describe, expect, it } from "vitest";

import { parseShellArgs } from "./components/dashboard/parseShellArgs";

describe("parseShellArgs", () => {
  it("splits simple whitespace-separated arguments", () => {
    expect(parseShellArgs("-m pytest -q")).toEqual(["-m", "pytest", "-q"]);
  });

  it("preserves quoted segments", () => {
    expect(parseShellArgs("-c \"print('hello world')\" --name 'demo user'")).toEqual([
      "-c",
      "print('hello world')",
      "--name",
      "demo user"
    ]);
  });

  it("throws on unterminated quotes", () => {
    expect(() => parseShellArgs('-c "unterminated')).toThrow(/unterminated quote/i);
  });
});
