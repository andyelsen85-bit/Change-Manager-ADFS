import { describe, expect, it } from "vitest";
import { sanitizeAdfsReturnPath } from "./adfs";

describe("sanitizeAdfsReturnPath", () => {
  it("preserves local change links including query strings and fragments", () => {
    expect(sanitizeAdfsReturnPath("/changes/123?tab=planning#tasks")).toBe(
      "/changes/123?tab=planning#tasks",
    );
  });

  it.each([
    "https://attacker.example/change",
    "//attacker.example/change",
    "/\\attacker.example/change",
    "javascript:alert(1)",
    "/changes/1\nLocation: https://attacker.example",
    null,
  ])("rejects unsafe return target %s", (value) => {
    expect(sanitizeAdfsReturnPath(value)).toBe("/");
  });
});