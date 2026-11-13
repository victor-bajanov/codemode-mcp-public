import { describe, it, expect, vi, afterEach } from "vitest";
import { runElicitation, type RunElicitationArgs } from "../elicit";
import type { OpenApiSpec } from "@local/spec-loaders-google-discovery";
import type { SurfaceReviewEntry, ElicitRenderer, ElicitRendererInput } from "@local/shared";

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
  headline: "Confirm",
  facts: { name: "alpha" },
});

interface CapturedAudit {
  decision: "allow" | "elicit" | "deny";
  elicitationOutcome?: string;
  elicitFields?: Record<string, unknown>;
}

function makeArgs(opts: {
  elicitInput: (params: unknown, options?: unknown) => Promise<unknown>;
  capability?: { elicitation?: object };
  renderer?: ElicitRenderer;
  category?: string;
  inspectorSummary?: Record<string, string | number | boolean>;
  query?: Record<string, string | number | boolean | undefined>;
  relatedRequestId?: string;
}) {
  const audits: CapturedAudit[] = [];
  return {
    audits,
    args: {
      spec: SPEC,
      operationId: "createItem",
      method: "POST",
      path: "/items",
      pathParams: {},
      body: { name: "alpha" },
      entry: ENTRY,
      ...(opts.category !== undefined ? { category: opts.category } : {}),
      ...(opts.inspectorSummary !== undefined ? { inspectorSummary: opts.inspectorSummary } : {}),
      ...(opts.query !== undefined ? { query: opts.query } : {}),
      ...(opts.relatedRequestId !== undefined ? { relatedRequestId: opts.relatedRequestId } : {}),
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
    } as RunElicitationArgs,
  };
}

describe("runElicitation", () => {
  afterEach(() => vi.useRealTimers());

  it("accept + { confirm: true } -> resolves; audit accepted with elicitFields = facts", async () => {
    const { args, audits } = makeArgs({
      elicitInput: async () => ({ action: "accept", content: { confirm: true } }),
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

  for (const content of [{ confirm: false }, { confirm: true, extra: 1 }, { name: "alpha" }]) {
    it(`FIXED (D-1): accept + ${JSON.stringify(content)} -> throws declined; audit declined with elicitFields`, async () => {
      const { args, audits } = makeArgs({
        elicitInput: async () => ({ action: "accept", content }),
        renderer: FIXED_RENDERER,
        category: "external_data_flow",
      });
      await expect(runElicitation(args)).rejects.toThrow(/outcome: declined/);
      expect(audits[0]).toMatchObject({ elicitationOutcome: "declined" });
      expect(audits[0]!.elicitFields).toEqual({ name: "alpha" });
    });
  }

  it("sends the composed message with the confirm-only schema; facts are never inputs", async () => {
    const elicitInput = vi.fn(async (_p: unknown, _o?: unknown) => ({ action: "accept", content: { confirm: true } }));
    const { args } = makeArgs({
      elicitInput,
      renderer: FIXED_RENDERER,
      category: "external_data_flow",
      query: { mode: "all", skipped: undefined },
      relatedRequestId: "req-7",
    });
    await runElicitation(args);
    expect(elicitInput).toHaveBeenCalledTimes(1);
    const [params, options] = elicitInput.mock.calls[0]!;
    expect(options).toEqual({ relatedRequestId: "req-7" });
    expect(params).toEqual({
      message: [
        "Confirm",
        "Request: POST /items",
        'Query: mode="all"',
        'name: "alpha"',
        "Approve only if this is exactly the request you intended.",
      ].join("\n"),
      requestedSchema: {
        type: "object",
        properties: { confirm: { type: "boolean" } },
        required: ["confirm"],
        additionalProperties: false,
      },
    });
    // A fresh, mutable copy is handed to the transport (not the frozen constant).
    expect(Object.isFrozen((params as { requestedSchema: object }).requestedSchema)).toBe(false);
  });

  it("FIXED (D-1): audit elicitFields records the shown (sanitised, truncated) facts, so its size is bounded", async () => {
    const sep = String.fromCodePoint(0x2028);
    const rlo = String.fromCodePoint(0x202e);
    const renderer: ElicitRenderer = () => ({
      headline: "H",
      facts: { note: "n".repeat(5000), [`label${sep}x`]: `a${rlo}b`, count: 3, ok: true, ["k".repeat(60)]: "v" },
    });
    const { args, audits } = makeArgs({
      elicitInput: async () => ({ action: "accept", content: { confirm: true } }),
      renderer,
      category: "external_data_flow",
    });
    await runElicitation(args);
    expect(audits[0]!.elicitFields).toEqual({
      note: "n".repeat(200) + "…",
      "label x": "a b",
      count: 3,
      ok: true,
      ["k".repeat(40) + "…"]: "v",
    });
  });

  it("hands renderers the method, the matched path and the decoded path params", async () => {
    const seen: ElicitRendererInput[] = [];
    const renderer: ElicitRenderer = (input) => {
      seen.push(input);
      return { headline: "H", facts: {} };
    };
    const { args } = makeArgs({
      elicitInput: async () => ({ action: "accept", content: { confirm: true } }),
      renderer,
      category: "external_data_flow",
      query: { a: 1 },
    });
    await runElicitation({ ...args, path: "/items/x%2Fy", pathParams: { id: "x/y" } });
    expect(seen[0]).toMatchObject({
      operationId: "createItem",
      method: "POST",
      path: "/items/x%2Fy",
      pathParams: { id: "x/y" },
      query: { a: 1 },
      body: { name: "alpha" },
    });
  });

  it("FIXED (D-1): an opaque (composed) payload keeps the full scaffold warning even with a long operation id", async () => {
    const elicitInput = vi.fn(async (_p: unknown) => ({ action: "accept", content: { confirm: true } }));
    const { args } = makeArgs({ elicitInput });
    const operationId = "x".repeat(250);
    await runElicitation({
      ...args,
      operationId,
      opaquePayload: "composed, 3 segments, 1 staged file, 1234 bytes",
      attachments: "q.pdf (1000 bytes)",
    });
    const { message } = elicitInput.mock.calls[0]![0] as { message: string };
    const lines = message.split("\n");
    expect(lines[0]).toBe(`Confirm operation: ${operationId}`.slice(0, 200) + "…");
    expect(lines[1]).toBe(
      "Its request body (composed, 3 segments, 1 staged file, 1234 bytes) cannot be shown here; approve only if you expected this upload.",
    );
    expect(lines).toContain("Attachments: q.pdf (1000 bytes)");
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

  it("FIXED (D-1): no getClientCapabilities accessor -> unsupported before any renderer runs; elicitInput not called", async () => {
    const elicitSpy = vi.fn();
    const renderer = vi.fn(FIXED_RENDERER);
    const { args, audits } = makeArgs({ elicitInput: elicitSpy, renderer, category: "external_data_flow" });
    const noAccessor = { ...args, server: { server: { elicitInput: elicitSpy } } } as RunElicitationArgs;
    await expect(runElicitation(noAccessor)).rejects.toThrow(
      "Operation createItem requires user approval; outcome: unsupported",
    );
    expect(audits).toEqual([expect.objectContaining({ elicitationOutcome: "unsupported" })]);
    expect(renderer).not.toHaveBeenCalled();
    expect(elicitSpy).not.toHaveBeenCalled();
  });

  it("falls back to genericWalker when no renderer resolves", async () => {
    const { args, audits } = makeArgs({
      elicitInput: async () => ({ action: "accept", content: { confirm: true } }),
      category: "external_data_flow",
    });
    await runElicitation(args);
    expect(audits[0]).toMatchObject({
      elicitationOutcome: "accepted",
      elicitFields: { name: "alpha" },
    });
  });
});
