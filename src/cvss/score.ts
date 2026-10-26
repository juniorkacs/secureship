/**
 * CVSS v3.1 vector parsing and scoring, following the FIRST specification
 * (sections 7.1 to 7.3 and Appendix A for Roundup).
 */
import { BASE_METRICS, BASE_ORDER, TEMPORAL_METRICS, TEMPORAL_ORDER, type BaseKey, type TemporalKey } from "./metrics.js";

export type Severity = "None" | "Low" | "Medium" | "High" | "Critical";

export class CvssError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CvssError";
  }
}

export type ParsedVector = {
  base: Record<BaseKey, string>;
  temporal: Record<TemporalKey, string>;
};

export type CvssResult = {
  vector: string;
  version: "3.1";
  baseScore: number;
  baseSeverity: Severity;
  impactSubscore: number;
  exploitabilitySubscore: number;
  temporalScore: number;
  temporalSeverity: Severity;
  metrics: { key: string; name: string; value: string; label: string }[];
};

const PREFIX = "CVSS:3.1/";
const MAX_VECTOR_LENGTH = 200;

/** Parse a CVSS v3.1 vector string. Throws CvssError with a specific message on any problem. */
export function parseVector(vector: string): ParsedVector {
  if (typeof vector !== "string") throw new CvssError("Vector must be a string.");
  if (vector.length > MAX_VECTOR_LENGTH) throw new CvssError(`Vector is longer than ${MAX_VECTOR_LENGTH} characters.`);
  if (!vector.startsWith(PREFIX)) {
    throw new CvssError(vector.startsWith("CVSS:3.0/") ? "Only CVSS v3.1 vectors are supported." : 'Vector must start with "CVSS:3.1/".');
  }
  const base = {} as Record<BaseKey, string>;
  const temporal = { E: "X", RL: "X", RC: "X" } as Record<TemporalKey, string>;
  const seen = new Set<string>();

  // Object.hasOwn (not `in`) so names like "toString" or "__proto__" are rejected.
  for (const part of vector.slice(PREFIX.length).split("/")) {
    const [key, value, extra] = part.split(":");
    if (!key || value === undefined || extra !== undefined) throw new CvssError(`"${part}" is not a metric:value pair.`);
    if (seen.has(key)) throw new CvssError(`Metric ${key} appears more than once.`);
    seen.add(key);
    if (Object.hasOwn(BASE_METRICS, key)) {
      const def = BASE_METRICS[key as BaseKey];
      if (!Object.hasOwn(def.values, value)) throw new CvssError(`${value} is not a valid value for ${def.name} (${key}).`);
      base[key as BaseKey] = value;
    } else if (Object.hasOwn(TEMPORAL_METRICS, key)) {
      const def = TEMPORAL_METRICS[key as TemporalKey];
      if (!Object.hasOwn(def.values, value)) throw new CvssError(`${value} is not a valid value for ${def.name} (${key}).`);
      temporal[key as TemporalKey] = value;
    } else {
      throw new CvssError(`Unknown or unsupported metric "${key}".`);
    }
  }
  const missing = BASE_ORDER.filter((k) => !Object.hasOwn(base, k));
  if (missing.length) throw new CvssError(`Missing base metric${missing.length > 1 ? "s" : ""}: ${missing.join(", ")}.`);
  return { base, temporal };
}

/**
 * Roundup as defined in CVSS v3.1 Appendix A: the smallest number, to one
 * decimal place, that is equal to or higher than its input. Implemented with
 * integer arithmetic to avoid floating-point surprises such as 4.000000001.
 */
export function roundup(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function severity(score: number): Severity {
  if (score === 0) return "None";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}

const w = (key: BaseKey, value: string): number =>
  (BASE_METRICS[key].values as Record<string, { weight: number }>)[value].weight;

export function score(vector: string): CvssResult {
  const { base, temporal } = parseVector(vector);
  const changed = base.S === "C";

  const iss = 1 - (1 - w("C", base.C)) * (1 - w("I", base.I)) * (1 - w("A", base.A));
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const pr = changed ? BASE_METRICS.PR.changedScope[base.PR as "N" | "L" | "H"] : w("PR", base.PR);
  const exploitability = 8.22 * w("AV", base.AV) * w("AC", base.AC) * pr * w("UI", base.UI);

  let baseScore: number;
  if (impact <= 0) baseScore = 0;
  else if (changed) baseScore = roundup(Math.min(1.08 * (impact + exploitability), 10));
  else baseScore = roundup(Math.min(impact + exploitability, 10));

  const tw = (k: TemporalKey) => (TEMPORAL_METRICS[k].values as Record<string, { weight: number }>)[temporal[k]].weight;
  const temporalScore = roundup(baseScore * tw("E") * tw("RL") * tw("RC"));

  const metrics = [
    ...BASE_ORDER.map((k) => ({
      key: k,
      name: BASE_METRICS[k].name,
      value: base[k],
      label: (BASE_METRICS[k].values as Record<string, { label: string }>)[base[k]].label,
    })),
    ...TEMPORAL_ORDER.filter((k) => temporal[k] !== "X").map((k) => ({
      key: k,
      name: TEMPORAL_METRICS[k].name,
      value: temporal[k],
      label: (TEMPORAL_METRICS[k].values as Record<string, { label: string }>)[temporal[k]].label,
    })),
  ];

  return {
    vector,
    version: "3.1",
    baseScore,
    baseSeverity: severity(baseScore),
    // Subscores are reported to one decimal, as calculators conventionally display them.
    impactSubscore: Math.round(Math.max(impact, 0) * 10) / 10,
    exploitabilitySubscore: Math.round(exploitability * 10) / 10,
    temporalScore,
    temporalSeverity: severity(temporalScore),
    metrics,
  };
}
