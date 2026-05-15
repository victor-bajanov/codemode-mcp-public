import { describe, it, expect, vi, afterEach } from "vitest";
import { clientSupportsElicitation, raceTimeout } from "../elicit";

describe("clientSupportsElicitation", () => {
  it("true when getClientCapabilities returns an object with .elicitation", () => {
    const server = { server: { getClientCapabilities: () => ({ elicitation: {} }) } };
    expect(clientSupportsElicitation(server)).toBe(true);
  });

  it("false when getClientCapabilities returns no .elicitation", () => {
    const server = { server: { getClientCapabilities: () => ({ tools: {} }) } };
    expect(clientSupportsElicitation(server)).toBe(false);
  });

  it("false when getClientCapabilities returns undefined", () => {
    const server = { server: { getClientCapabilities: () => undefined } };
    expect(clientSupportsElicitation(server)).toBe(false);
  });

  it("true (fail-open) when accessor missing — let elicitInput itself reject", () => {
    const server = { server: {} };
    expect(clientSupportsElicitation(server)).toBe(true);
  });

  it("preserves `this` binding when calling getClientCapabilities (regression: detached method)", () => {
    // Simulate a class instance whose method depends on `this`.
    class FakeServer {
      private _caps = { elicitation: {} };
      getClientCapabilities() {
        return this._caps;
      }
    }
    const server = { server: new FakeServer() };
    expect(clientSupportsElicitation(server)).toBe(true);
  });
});

describe("raceTimeout", () => {
  afterEach(() => vi.useRealTimers());

  it("resolves with the inner promise when it wins", async () => {
    const r = raceTimeout(Promise.resolve("ok"), 1000);
    await expect(r).resolves.toBe("ok");
  });

  it("rejects with TimeoutError when timer fires first", async () => {
    vi.useFakeTimers();
    const inner = new Promise<string>(() => {/* never */});
    const r = raceTimeout(inner, 1000);
    vi.advanceTimersByTime(1001);
    await expect(r).rejects.toMatchObject({ name: "TimeoutError" });
  });

  it("propagates inner rejection (not a timeout)", async () => {
    const r = raceTimeout(Promise.reject(new Error("net")), 1000);
    await expect(r).rejects.toThrow("net");
  });
});
