/**
 * Configuration from environment variables. Invalid values stop start-up
 * with a clear message, rather than running with a surprising setting.
 */
export type Config = {
  port: number;
  host: string;
  logLevel: "fatal" | "error" | "warn" | "info" | "debug" | "trace" | "silent";
  /** If set, POST /v1/* requires the header `x-api-key` with this value. */
  apiKey: string | null;
  rateLimitPerMinute: number;
};

const LEVELS = ["fatal", "error", "warn", "info", "debug", "trace", "silent"] as const;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const port = Number(env.PORT ?? 8080);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`PORT must be 1-65535, got "${env.PORT}".`);
  const logLevel = (env.LOG_LEVEL ?? "info") as Config["logLevel"];
  if (!LEVELS.includes(logLevel)) throw new Error(`LOG_LEVEL must be one of ${LEVELS.join(", ")}.`);
  const apiKey = env.API_KEY?.trim() || null;
  if (apiKey !== null && apiKey.length < 24) throw new Error("API_KEY must be at least 24 characters when set.");
  const rateLimitPerMinute = Number(env.RATE_LIMIT_PER_MINUTE ?? 120);
  if (!Number.isInteger(rateLimitPerMinute) || rateLimitPerMinute < 1) throw new Error("RATE_LIMIT_PER_MINUTE must be a positive integer.");
  return { port, host: env.HOST ?? "0.0.0.0", logLevel, apiKey, rateLimitPerMinute };
}
