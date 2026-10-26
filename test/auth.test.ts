import { describe, expect, it } from "vitest";
import { keysMatch } from "../src/auth.js";

describe("keysMatch", () => {
  it("matches only the exact key", () => {
    expect(keysMatch("abc", "abc")).toBe(true);
    expect(keysMatch("abd", "abc")).toBe(false);
    expect(keysMatch("abcd", "abc")).toBe(false);
    expect(keysMatch(undefined, "abc")).toBe(false);
    expect(keysMatch("", "abc")).toBe(false);
  });
});
