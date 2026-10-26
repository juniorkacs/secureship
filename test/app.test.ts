import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { loadConfig, type Config } from "../src/config.js";

let app: FastifyInstance;
const base: Config = { port: 0, host: "127.0.0.1", logLevel: "silent", apiKey: null, rateLimitPerMinute: 1000 };
const make = async (overrides: Partial<Config> = {}) => (app = await buildApp({ ...base, ...overrides }));
afterEach(async () => app?.close());

const VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

describe("HTTP API", () => {
  it("serves a health check", async () => {
    await make();
    const r = await app.inject({ method: "GET", url: "/healthz" });
    expect(r.statusCode).toBe(200);
    expect(r.json().status).toBe("ok");
  });

  it("scores a vector", async () => {
    await make();
    const r = await app.inject({ method: "POST", url: "/v1/score", payload: { vector: VECTOR } });
    expect(r.statusCode).toBe(200);
    expect(r.json()).toMatchObject({ baseScore: 9.8, baseSeverity: "Critical", version: "3.1" });
  });

  it("returns 422 with a reason for an invalid vector", async () => {
    await make();
    const r = await app.inject({ method: "POST", url: "/v1/score", payload: { vector: "CVSS:3.1/AV:N" } });
    expect(r.statusCode).toBe(422);
    expect(r.json().error).toMatch(/Missing base metrics/);
  });

  it("validates the request body shape", async () => {
    await make();
    for (const payload of [{}, { vector: 7 }, { vector: VECTOR, extra: 1 }, { vector: "" }]) {
      const r = await app.inject({ method: "POST", url: "/v1/score", payload });
      expect(r.statusCode).toBe(400);
      expect(r.json().error).toMatch(/Invalid request/);
    }
  });

  it("rejects bodies over 16 KB", async () => {
    await make();
    const r = await app.inject({
      method: "POST",
      url: "/v1/score/batch",
      payload: { vectors: Array(100).fill("x".repeat(200)) },
    });
    expect(r.statusCode).toBe(413);
  });

  it("scores a batch and reports per-item errors", async () => {
    await make();
    const r = await app.inject({ method: "POST", url: "/v1/score/batch", payload: { vectors: [VECTOR, "nope"] } });
    expect(r.statusCode).toBe(200);
    const [ok, bad] = r.json().results;
    expect(ok.ok).toBe(true);
    expect(ok.result.baseScore).toBe(9.8);
    expect(bad).toMatchObject({ ok: false, vector: "nope" });
  });

  it("limits batch size", async () => {
    await make();
    const r = await app.inject({ method: "POST", url: "/v1/score/batch", payload: { vectors: Array(101).fill("a") } });
    expect(r.statusCode).toBe(400);
  });

  it("publishes metric definitions", async () => {
    await make();
    const r = await app.inject({ method: "GET", url: "/v1/metrics" });
    expect(r.json().base.AV.values.N.weight).toBe(0.85);
  });

  it("returns JSON 404s", async () => {
    await make();
    const r = await app.inject({ method: "GET", url: "/nope" });
    expect(r.statusCode).toBe(404);
    expect(r.json().error).toMatch(/No route/);
  });

  it("serves the calculator page with security headers", async () => {
    await make();
    const r = await app.inject({ method: "GET", url: "/" });
    expect(r.statusCode).toBe(200);
    expect(r.body).toContain("CVSS v3.1 calculator");
    expect(r.headers["content-security-policy"]).toContain("script-src 'self'");
    expect(r.headers["x-content-type-options"]).toBe("nosniff");
  });
});

describe("API key", () => {
  const key = "k".repeat(32);

  it("is required for scoring when configured", async () => {
    await make({ apiKey: key });
    const none = await app.inject({ method: "POST", url: "/v1/score", payload: { vector: VECTOR } });
    expect(none.statusCode).toBe(401);
    const wrong = await app.inject({ method: "POST", url: "/v1/score", payload: { vector: VECTOR }, headers: { "x-api-key": "wrong" } });
    expect(wrong.statusCode).toBe(401);
    const right = await app.inject({ method: "POST", url: "/v1/score", payload: { vector: VECTOR }, headers: { "x-api-key": key } });
    expect(right.statusCode).toBe(200);
  });

  it("is not required for read-only routes", async () => {
    await make({ apiKey: key });
    expect((await app.inject({ method: "GET", url: "/healthz" })).statusCode).toBe(200);
  });
});

describe("rate limiting", () => {
  it("returns 429 after the limit", async () => {
    await make({ rateLimitPerMinute: 3 });
    const codes = [];
    for (let i = 0; i < 4; i++) codes.push((await app.inject({ method: "GET", url: "/healthz" })).statusCode);
    expect(codes).toEqual([200, 200, 200, 429]);
  });
});

describe("configuration", () => {
  it("uses safe defaults", () => {
    expect(loadConfig({})).toMatchObject({ port: 8080, apiKey: null, logLevel: "info", rateLimitPerMinute: 120 });
  });
  it.each([
    [{ PORT: "abc" }, /PORT/],
    [{ PORT: "70000" }, /PORT/],
    [{ LOG_LEVEL: "loud" }, /LOG_LEVEL/],
    [{ API_KEY: "short" }, /at least 24/],
    [{ RATE_LIMIT_PER_MINUTE: "0" }, /RATE_LIMIT/],
  ])("rejects %o", (env, msg) => {
    expect(() => loadConfig(env)).toThrow(msg);
  });
});
