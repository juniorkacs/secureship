import type { FastifyInstance } from "fastify";
import { BASE_METRICS, TEMPORAL_METRICS } from "../cvss/metrics.js";
import { CvssError, score } from "../cvss/score.js";

const vectorSchema = { type: "string", minLength: 1, maxLength: 200 } as const;

export async function cvssRoutes(app: FastifyInstance) {
  app.get("/v1/metrics", async () => ({ version: "3.1", base: BASE_METRICS, temporal: TEMPORAL_METRICS }));

  app.post<{ Body: { vector: string } }>(
    "/v1/score",
    {
      schema: {
        body: {
          type: "object",
          required: ["vector"],
          additionalProperties: false,
          properties: { vector: vectorSchema },
        },
      },
    },
    async (req, reply) => {
      try {
        return score(req.body.vector.trim());
      } catch (e) {
        if (e instanceof CvssError) return reply.code(422).send({ error: e.message });
        throw e;
      }
    },
  );

  app.post<{ Body: { vectors: string[] } }>(
    "/v1/score/batch",
    {
      schema: {
        body: {
          type: "object",
          required: ["vectors"],
          additionalProperties: false,
          properties: { vectors: { type: "array", minItems: 1, maxItems: 100, items: vectorSchema } },
        },
      },
    },
    async (req) => ({
      results: req.body.vectors.map((v) => {
        try {
          return { ok: true, result: score(v.trim()) };
        } catch (e) {
          if (e instanceof CvssError) return { ok: false, vector: v, error: e.message };
          throw e;
        }
      }),
    }),
  );
}
