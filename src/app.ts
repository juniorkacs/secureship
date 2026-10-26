import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import Fastify, { type FastifyServerOptions } from "fastify";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import fastifyStatic from "@fastify/static";
import type { Config } from "./config.js";
import { keysMatch } from "./auth.js";
import { cvssRoutes } from "./routes/cvss.js";

export const VERSION = process.env.APP_VERSION ?? "1.0.0";
const publicDir = join(dirname(fileURLToPath(import.meta.url)), "..", "public");

export async function buildApp(config: Config, opts: FastifyServerOptions = {}) {
  const app = Fastify({
    bodyLimit: 16 * 1024,
    // Strict validation: never coerce types or silently drop unknown fields.
    ajv: { customOptions: { coerceTypes: false, removeAdditional: false, allErrors: false } },
    logger: {
      level: config.logLevel,
      // Never write credentials to logs.
      redact: { paths: ["req.headers['x-api-key']", "req.headers.authorization"], censor: "[redacted]" },
    },
    ...opts,
  });

  app.setErrorHandler((err: Error & { statusCode?: number; validation?: unknown }, req, reply) => {
    if (err.validation) return reply.code(400).send({ error: `Invalid request: ${err.message}` });
    const status = err.statusCode && err.statusCode >= 400 && err.statusCode < 500 ? err.statusCode : 500;
    if (status === 500) req.log.error(err);
    // 4xx messages are safe to show; 5xx details stay in the logs.
    return reply.code(status).send({ error: status === 500 ? "Unexpected server error." : err.message });
  });

  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'self'"],
      },
    },
  });
  await app.register(rateLimit, { max: config.rateLimitPerMinute, timeWindow: "1 minute" });
  await app.register(fastifyStatic, { root: publicDir, index: "index.html" });

  // Optional API key for write-style endpoints. Read-only routes stay open.
  app.addHook("onRequest", async (req, reply) => {
    if (config.apiKey && req.method === "POST" && req.url.startsWith("/v1/")) {
      if (!keysMatch(req.headers["x-api-key"] as string | undefined, config.apiKey)) {
        return reply.code(401).send({ error: "Missing or invalid API key." });
      }
    }
  });

  app.get("/healthz", async () => ({ status: "ok", version: VERSION }));
  await app.register(cvssRoutes);

  app.setNotFoundHandler((req, reply) => reply.code(404).send({ error: `No route for ${req.method} ${req.url}.` }));

  return app;
}
