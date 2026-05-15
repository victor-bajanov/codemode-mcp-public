/**
 * NOTE: this file is documentation-only; it is NOT bundled with `wrangler dev`.
 *
 * The host (src/host.ts) injects the child Worker via `env.LOADER.get(...)` by
 * passing a literal source string (`CHILD_MODULE_SOURCE`). That string mirrors
 * exactly the code below. We keep this file in TypeScript form so it's easy to
 * read and review without staring at an embedded string.
 *
 * If you want to edit the child, change BOTH this file and CHILD_MODULE_SOURCE
 * in src/host.ts (the embedded string is the source of truth at runtime).
 */
import { WorkerEntrypoint } from "cloudflare:workers";

interface Bridge {
  runCallback(): Promise<unknown>;
}

export default class Child extends WorkerEntrypoint {
  /**
   * Invokes the host-side callback via Workers RPC.
   *
   * This is the moment that severs the AsyncLocalStorage chain: the host
   * receives `runCallback()` as a fresh entrypoint invocation, and any
   * AsyncLocalStorage frame that was active where the host originally
   * created `bridge` is NOT inherited.
   */
  async run(bridge: Bridge): Promise<unknown> {
    return await bridge.runCallback();
  }
}
