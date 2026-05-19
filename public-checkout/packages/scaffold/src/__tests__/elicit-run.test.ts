import { describe, it, expect, vi, afterEach } from "vitest";
import { runElicitation } from "../elicit";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReviewEntry, ElicitRenderer } from "@local/shared";

const SPEC = {
  openapi: "3.0.0",
  info: { title: "T", version: "1" },
  servers: [{ url: "https://x" }],
  paths: {
    "/items": {
      post: {
        operationId: "createItem",
        requestBody: { content: { "application/json": { schema: { type: "object", properties: { name: { type: "string" } } } } } },
        responses: { "200": { description: "OK" } },
      },
    },
  },
  components: { schemas: {} },
} as unknown as OpenApiSpec;

const ENTRY: SurfaceReviewEntry = { decision: "elicit" };
const FIXED_RENDERER: ElicitRenderer = () => ({
  message: "Confirm",
  fields: { name: "alpha" },
});

interface CapturedAudit {
  decision: "allow" | "elicit" | "deny";
  elicitationOutcome?: string;
  elicitFields?: Record<string, unknown>;
}

function makeArgs(opts: {
  elicitInput: (params: unknown) => Promise<unknown>;
  capability?: { elicitation?: object };
  renderer?: ElicitRenderer;
  category?: string;
  inspectorSummary?: Record<string, string | number | boolean>;
}) {
  const audits: CapturedAudit[] = [];
  return {
    audits,
    args: {
      spec: SPEC,
      operationId: "createItem",
      method: "POST",
      path: "/items",
      body: { name: "alpha" },
      entry: ENTRY,
      ...(opts.category !== undefined ? { category: opts.category } : {}),
      ...(opts.inspectorSummary !== undefined ? { inspectorSummary: opts.inspectorSummary } : {}),
      ...(opts.renderer ? { elicitRenderers: { external_data_flow: opts.renderer } } : {}),
      server: {
        server: {
          getClientCapabilities: () => (opts.capability !== undefined ? opts.capability : { elicitation: {} }),
          elicitInput: opts.elicitInput,
        },
      },
      emitAudit: (e: CapturedAudit) => audits.push(e),
      elicitTimeoutMs: 50,
      env: {},
    } as import("../elicit").RunElicitationArgs,
  };
}

describe("runElicitation", () => {
  afterEach(() => vi.useRealTimers());

  it("accept + valid content -> resolves; audit accepted with elicitFields", async () => {
    const { args, audits } = makeArgs({
      elicitInput: async () => ({ action: "accept", content: { name: "alpha" } }),
      renderer: FIXED_RENDERER,
      category: "external_data_flow",
    });
    await expect(runElicitation(args)).resolves.toBeUndefined();
    expect(audits[0]).toMatchObject({
      decision: "elicit",
      elicitationOutcome: "accepted",
      elicitFields: { name: "alpha" },
    });
  });

  it("accept + invalid content -> throws; audit declined with elicitFields", async () => {
    const { args, audits } = makeArgs({
      elicitInput: async () => ({ action: "accept", content: { name: 123 } }),
      renderer: FIXED_RENDERER,
      category: "external_data_flow",
    });
    await expect(runElicitation(args)).rejects.toThrow(/declined/);
    expect(audits[0]).toMatchObject({ elicitationOutcome: "declined" });
    expect(audits[0]!.elicitFields).toEqual({ name: "alpha" });
  });

  it("decline -> throws; audit declined", async () => {
    const { args, audits } = makeArgs({
      elicitInput: async () => ({ action: "decline" }),
      renderer: FIXED_RENDERER,
      category: "external_data_flow",
    });
    await expect(runElicitation(args)).rejects.toThrow();
    expect(audits[0]).toMatchObject({ elicitationOutcome: "declined" });
  });

  it("cancel -> throws; audit cancelled", async () => {
    const { args, audits } = makeArgs({
      elicitInput: async () => ({ action: "cancel" }),
      renderer: FIXED_RENDERER,
      category: "external_data_flow",
    });
    await expect(runElicitation(args)).rejects.toThrow();
    expect(audits[0]).toMatchObject({ elicitationOutcome: "cancelled" });
  });

  it("timeout -> throws; audit timeout", async () => {
    vi.useFakeTimers();
    const { args, audits } = makeArgs({
      elicitInput: () => new Promise(() => {}),
      renderer: FIXED_RENDERER,
      category: "external_data_flow",
    });
    const promise = runElicitation(args);
    // Suppress unhandled-rejection warning while we advance time; we check it below.
    promise.catch(() => {});
    await vi.advanceTimersByTimeAsync(60);
    await expect(promise).rejects.toThrow();
    expect(audits[0]).toMatchObject({ elicitationOutcome: "timeout" });
  });

  it("transport error -> throws; audit transport-error", async () => {
    const { args, audits } = makeArgs({
      elicitInput: async () => { throw new Error("ws closed"); },
      renderer: FIXED_RENDERER,
      category: "external_data_flow",
    });
    await expect(runElicitation(args)).rejects.toThrow();
    expect(audits[0]).toMatchObject({ elicitationOutcome: "transport-error" });
  });

  it("capability missing -> throws; audit unsupported; elicitInput not called", async () => {
    const elicitSpy = vi.fn();
    const { args, audits } = makeArgs({
      elicitInput: elicitSpy,
      capability: {},
      renderer: FIXED_RENDERER,
      category: "external_data_flow",
    });
    await expect(runElicitation(args)).rejects.toThrow();
    expect(audits[0]).toMatchObject({ elicitationOutcome: "unsupported" });
    expect(audits[0]!.elicitFields).toBeUndefined();
    expect(elicitSpy).not.toHaveBeenCalled();
  });

  it("falls back to genericWalker when no renderer resolves", async () => {
    const { args, audits } = makeArgs({
      elicitInput: async () => ({ action: "accept", content: { name: "alpha" } }),
      category: "external_data_flow",
    });
    await runElicitation(args);
    expect(audits[0]).toMatchObject({
      elicitationOutcome: "accepted",
      elicitFields: { name: "alpha" },
    });
  });
});
