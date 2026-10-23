// Two-level transfer gate (D8): per execution run at most one transfer in
// flight and one waiting; per isolate a bounded FIFO semaphore.

import { describe, it, expect } from "vitest";
import { TransferGate, PER_RUN_MESSAGE, RETRY_MESSAGE } from "../compose/gate";
import { ToolError } from "../elicit";

const live = () => new AbortController().signal;
const tick = () => new Promise((r) => setTimeout(r, 0));

function gate(maxConcurrent = 2, maxWaiting = 4) {
  return new TransferGate({ maxConcurrent, maxWaiting, perRunInFlight: 1, perRunWaiting: 1 });
}

function track(p: Promise<() => void>) {
  const s: { release?: () => void; error?: unknown } = {};
  p.then((r) => (s.release = r), (e) => (s.error = e));
  return s;
}

describe("TransferGate — per-run cap", () => {
  it("a run's third concurrent acquire rejects with the per-execution message; another run is admitted", async () => {
    const g = gate(4, 4);
    const run = {};
    const a = track(g.acquire(run, live()));
    const b = track(g.acquire(run, live()));
    await expect(g.acquire(run, live())).rejects.toThrow(PER_RUN_MESSAGE);
    await tick();
    expect(a.release).toBeTypeOf("function");
    expect(b.release).toBeUndefined(); // waits for its own run's first transfer
    const other = track(g.acquire({}, live()));
    await tick();
    expect(other.release).toBeTypeOf("function");
    a.release!();
    await tick();
    expect(b.release).toBeTypeOf("function");
  });

  it("the per-run error is a ToolError", async () => {
    const g = gate();
    const run = {};
    void g.acquire(run, live());
    void g.acquire(run, live());
    await expect(g.acquire(run, live())).rejects.toBeInstanceOf(ToolError);
  });

  it("a second run is admitted while a first run holds its two slots", async () => {
    const g = gate(2, 4);
    const r1 = {};
    const a = track(g.acquire(r1, live()));
    track(g.acquire(r1, live()));
    const c = track(g.acquire({}, live()));
    await tick();
    expect(a.release).toBeTypeOf("function");
    expect(c.release).toBeTypeOf("function");
  });
});

describe("TransferGate — isolate semaphore", () => {
  it("honours maxConcurrent and admits waiters in FIFO order", async () => {
    const g = gate(2, 4);
    const a = track(g.acquire({}, live()));
    const b = track(g.acquire({}, live()));
    const c = track(g.acquire({}, live()));
    const d = track(g.acquire({}, live()));
    await tick();
    expect([a, b, c, d].map((x) => typeof x.release)).toEqual(["function", "function", "undefined", "undefined"]);
    b.release!();
    await tick();
    expect(c.release).toBeTypeOf("function");
    expect(d.release).toBeUndefined();
    a.release!();
    await tick();
    expect(d.release).toBeTypeOf("function");
  });

  it("a full queue rejects immediately with the retry message", async () => {
    const g = gate(1, 2);
    track(g.acquire({}, live()));
    track(g.acquire({}, live()));
    track(g.acquire({}, live()));
    await expect(g.acquire({}, live())).rejects.toThrow(RETRY_MESSAGE);
  });

  it("an aborted signal while waiting rejects and frees the queue slot", async () => {
    const g = gate(1, 1);
    const a = track(g.acquire({}, live()));
    const ctl = new AbortController();
    const waiting = g.acquire({}, ctl.signal);
    await expect(g.acquire({}, live())).rejects.toThrow(RETRY_MESSAGE);
    ctl.abort(new Error("deadline"));
    await expect(waiting).rejects.toThrow();
    const next = track(g.acquire({}, live()));
    await tick();
    expect(next.error).toBeUndefined();
    a.release!();
    await tick();
    expect(next.release).toBeTypeOf("function");
  });

  it("an already-aborted signal rejects without taking a slot", async () => {
    const g = gate(1, 0);
    const ctl = new AbortController();
    ctl.abort();
    await expect(g.acquire({}, ctl.signal)).rejects.toThrow();
    const a = track(g.acquire({}, live()));
    await tick();
    expect(a.release).toBeTypeOf("function");
  });

  it("an aborted per-run waiter frees its run's waiting slot", async () => {
    const g = gate(4, 4);
    const run = {};
    const a = track(g.acquire(run, live()));
    const ctl = new AbortController();
    const w = g.acquire(run, ctl.signal);
    ctl.abort();
    await expect(w).rejects.toThrow();
    const again = track(g.acquire(run, live()));
    await tick();
    expect(again.error).toBeUndefined();
    a.release!();
    await tick();
    expect(again.release).toBeTypeOf("function");
  });

  it("release is idempotent", async () => {
    const g = gate(1, 4);
    const a = track(g.acquire({}, live()));
    const b = track(g.acquire({}, live()));
    const c = track(g.acquire({}, live()));
    await tick();
    a.release!();
    a.release!();
    await tick();
    expect(b.release).toBeTypeOf("function");
    expect(c.release).toBeUndefined();
  });

  it("release in finally on throw frees the slot", async () => {
    const g = gate(1, 4);
    const work = async () => {
      const release = await g.acquire({}, live());
      try {
        throw new Error("boom");
      } finally {
        release();
      }
    };
    await expect(work()).rejects.toThrow("boom");
    const a = track(g.acquire({}, live()));
    await tick();
    expect(a.release).toBeTypeOf("function");
  });
});
