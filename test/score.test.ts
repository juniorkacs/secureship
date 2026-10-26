import { describe, expect, it } from "vitest";
import { CvssError, parseVector, roundup, score, severity } from "../src/cvss/score.js";

// Reference values computed with the formulas in the FIRST CVSS v3.1 specification.
const CASES: [string, number, string][] = [
  ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"],
  ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"],
  ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "High"],
  ["CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Medium"],
  ["CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "High"],
  ["CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "High"],
  ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, "Critical"],
  ["CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "Low"],
  ["CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2, "High"],
  ["CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.5, "Medium"],
  ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"],
];

describe("base score", () => {
  it.each(CASES)("%s scores %d (%s)", (vector, expected, sev) => {
    const r = score(vector);
    expect(r.baseScore).toBe(expected);
    expect(r.baseSeverity).toBe(sev);
  });

  it("uses the higher Privileges Required weights when scope is changed", () => {
    // PR:L is 0.62 when unchanged and 0.68 when changed.
    const unchanged = score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
    const changed = score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N");
    expect(unchanged.exploitabilitySubscore).toBe(2.8);
    expect(changed.exploitabilitySubscore).toBe(3.1);
  });

  it("accepts metrics in any order", () => {
    expect(score("CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N").baseScore).toBe(9.8);
  });

  it("reports subscores", () => {
    const r = score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(r.impactSubscore).toBe(5.9);
    expect(r.exploitabilitySubscore).toBe(3.9);
  });
});

describe("temporal score", () => {
  it("equals the base score when temporal metrics are not defined", () => {
    const r = score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(r.temporalScore).toBe(9.8);
  });

  it("applies exploit maturity, remediation level and report confidence", () => {
    // 9.8 x 0.94 x 0.95 x 0.96 = 8.401... rounds up to 8.5
    const r = score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:R");
    expect(r.temporalScore).toBe(8.5);
    expect(r.temporalSeverity).toBe("High");
    expect(r.metrics.map((m) => m.key)).toEqual(["AV", "AC", "PR", "UI", "S", "C", "I", "A", "E", "RL", "RC"]);
  });
});

describe("roundup", () => {
  it("rounds up to one decimal", () => {
    expect(roundup(4.02)).toBe(4.1);
    expect(roundup(4.0)).toBe(4.0);
  });
  it("is not fooled by floating-point noise", () => {
    expect(roundup(4.000000001)).toBe(4.0);
    expect(roundup(0.1 + 0.2)).toBe(0.3);
  });
});

describe("severity bands", () => {
  it.each([
    [0, "None"], [0.1, "Low"], [3.9, "Low"], [4.0, "Medium"], [6.9, "Medium"],
    [7.0, "High"], [8.9, "High"], [9.0, "Critical"], [10, "Critical"],
  ])("%d is %s", (s, expected) => expect(severity(s)).toBe(expected));
});

describe("parseVector rejects bad input with specific messages", () => {
  const bad: [string, RegExp][] = [
    ["AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", /must start with "CVSS:3.1\/"/],
    ["CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", /Only CVSS v3.1/],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", /Missing base metric: A/],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:Q", /Q is not a valid value for Availability/],
    ["CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", /appears more than once/],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1", /Unknown or unsupported metric "ZZ"/],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/", /is not a metric:value pair/],
    ["CVSS:3.1/AV:N:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", /is not a metric:value pair/],
    [`CVSS:3.1/${"AV:N/".repeat(50)}`, /longer than 200/],
  ];
  it.each(bad)("%s", (v, msg) => {
    expect(() => parseVector(v)).toThrow(CvssError);
    expect(() => parseVector(v)).toThrow(msg);
  });

  it("does not treat inherited object properties as metrics", () => {
    expect(() => parseVector("CVSS:3.1/toString:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toThrow(/Unknown/);
    expect(() => parseVector("CVSS:3.1/__proto__:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toThrow(/Unknown/);
    expect(() => parseVector("CVSS:3.1/AV:constructor/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toThrow(/not a valid value/);
  });
});
