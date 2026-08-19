import { defineConfig } from "vitest/config";

// Stub for cloudflare: built-in protocols. Importing @local/scaffold (main
// entry — buildExecuteAddendum in the executeHint tests) transitively pulls in
// token-broker.ts which imports cloudflare:workers at module evaluation; Node's
// loader rejects the protocol, so vitest needs a stub.
// DurableObject's constructor assigns ctx/env on the instance so subclasses
// that don't override it can be unit-tested directly with host-supplied values.
// WorkerEntrypoint mirrors that shape: codemode 0.4.x's CodemodeConnector
// extends it, so it must be a defined class or module load throws.
const STUBS: Record<string, string> = {
  "cloudflare:workers": `
    export class DurableObject {
      constructor(ctx, env) { this.ctx = ctx; this.env = env; }
    }
    export class WorkerEntrypoint {
      constructor(ctx, env) { this.ctx = ctx; this.env = env; }
    }
    export class RpcTarget {}
    export class WorkflowEntrypoint {}
    export const env = {};
    export class DurableObjectStub {}
    export class DurableObjectNamespace {}
    export default {};
  `,
  "cloudflare:email": `
    export class EmailMessage {}
    export default {};
  `,
};

export default defineConfig({
  plugins: [
    {
      name: "cloudflare-stub",
      enforce: "pre" as const,
      resolveId(id: string) {
        if (id in STUBS) return `\0${id}`;
        return null;
      },
      load(id: string) {
        const key = id.startsWith("\0") ? id.slice(1) : id;
        if (key in STUBS) return STUBS[key];
        return null;
      },
    },
  ],
  ssr: {
    noExternal: true,
  },
  test: {},
});
