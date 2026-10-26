/**
 * CVSS v3.1 metric definitions and numeric weights, as published in the
 * FIRST CVSS v3.1 specification (section 7.4, "Metric Values").
 */

export type MetricDef = {
  name: string;
  values: Record<string, { label: string; weight: number }>;
  /** Weight to use when Scope is Changed, if different (Privileges Required only). */
  changedScope?: Record<string, number>;
};

export const BASE_METRICS = {
  AV: {
    name: "Attack Vector",
    values: {
      N: { label: "Network", weight: 0.85 },
      A: { label: "Adjacent", weight: 0.62 },
      L: { label: "Local", weight: 0.55 },
      P: { label: "Physical", weight: 0.2 },
    },
  },
  AC: {
    name: "Attack Complexity",
    values: {
      L: { label: "Low", weight: 0.77 },
      H: { label: "High", weight: 0.44 },
    },
  },
  PR: {
    name: "Privileges Required",
    values: {
      N: { label: "None", weight: 0.85 },
      L: { label: "Low", weight: 0.62 },
      H: { label: "High", weight: 0.27 },
    },
    changedScope: { N: 0.85, L: 0.68, H: 0.5 },
  },
  UI: {
    name: "User Interaction",
    values: {
      N: { label: "None", weight: 0.85 },
      R: { label: "Required", weight: 0.62 },
    },
  },
  S: {
    name: "Scope",
    values: {
      U: { label: "Unchanged", weight: 0 },
      C: { label: "Changed", weight: 0 },
    },
  },
  C: {
    name: "Confidentiality",
    values: {
      H: { label: "High", weight: 0.56 },
      L: { label: "Low", weight: 0.22 },
      N: { label: "None", weight: 0 },
    },
  },
  I: {
    name: "Integrity",
    values: {
      H: { label: "High", weight: 0.56 },
      L: { label: "Low", weight: 0.22 },
      N: { label: "None", weight: 0 },
    },
  },
  A: {
    name: "Availability",
    values: {
      H: { label: "High", weight: 0.56 },
      L: { label: "Low", weight: 0.22 },
      N: { label: "None", weight: 0 },
    },
  },
} as const satisfies Record<string, MetricDef>;

export const TEMPORAL_METRICS = {
  E: {
    name: "Exploit Code Maturity",
    values: {
      X: { label: "Not Defined", weight: 1 },
      H: { label: "High", weight: 1 },
      F: { label: "Functional", weight: 0.97 },
      P: { label: "Proof-of-Concept", weight: 0.94 },
      U: { label: "Unproven", weight: 0.91 },
    },
  },
  RL: {
    name: "Remediation Level",
    values: {
      X: { label: "Not Defined", weight: 1 },
      U: { label: "Unavailable", weight: 1 },
      W: { label: "Workaround", weight: 0.97 },
      T: { label: "Temporary Fix", weight: 0.96 },
      O: { label: "Official Fix", weight: 0.95 },
    },
  },
  RC: {
    name: "Report Confidence",
    values: {
      X: { label: "Not Defined", weight: 1 },
      C: { label: "Confirmed", weight: 1 },
      R: { label: "Reasonable", weight: 0.96 },
      U: { label: "Unknown", weight: 0.92 },
    },
  },
} as const satisfies Record<string, MetricDef>;

export type BaseKey = keyof typeof BASE_METRICS;
export type TemporalKey = keyof typeof TEMPORAL_METRICS;
export const BASE_ORDER: BaseKey[] = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
export const TEMPORAL_ORDER: TemporalKey[] = ["E", "RL", "RC"];
