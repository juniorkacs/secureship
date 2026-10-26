import { createHash, timingSafeEqual } from "node:crypto";

/** Constant-time comparison. Hashing first makes both inputs the same length. */
export function keysMatch(provided: string | undefined, expected: string): boolean {
  if (!provided) return false;
  const a = createHash("sha256").update(provided).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}
