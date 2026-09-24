import { defineConfig } from "vitest/config";

// Comprehensive stub for cloudflare: built-in protocols.
// `agents`, `@cloudflare/codemode`, and `partyserver` transitively import
// these at module evaluation time; none of our test cases exercise them.
// WorkerEntrypoint must be a defined class — codemode 0.4.x's CodemodeConnector
// extends it, so its absence throws at module load.
const STUBS: Record<string, string> = {
  "cloudflare:workers": `
    export class DurableObject {}
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
    // Inline all node_modules through Vite's transform so the cloudflare-stub
    // plugin can intercept `cloudflare:` protocol imports before Node's ESM
    // loader rejects them (Node 25 doesn't support `cloudflare:` protocol).
    noExternal: true,
  },
  test: {},
});
