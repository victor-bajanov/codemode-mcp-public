import { describe, it, expect } from "vitest";
import { encryptSlot, decryptSlot } from "../encrypt-slot";

describe("encryptSlot / decryptSlot", () => {
  it("round-trips a JSON-serialisable value under the same wrapping token", async () => {
    const value = { currentRefreshToken: "RT-3", accessToken: "AT-3", lastUsedAt: 42 };
    const sealed = await encryptSlot("WRAP-TOKEN", value);
    const decoded = await decryptSlot<typeof value>("WRAP-TOKEN", sealed);
    expect(decoded).toEqual(value);
  });

  it("generates a fresh per-call data key (two encrypts produce different ciphertexts)", async () => {
    const a = await encryptSlot("WRAP-TOKEN", { x: 1 });
    const b = await encryptSlot("WRAP-TOKEN", { x: 1 });
    expect(a.encryptedData).not.toBe(b.encryptedData);
    expect(a.wrappedKey).not.toBe(b.wrappedKey);
  });

  it("returns undefined when the wrapping token doesn't match (AES-KW unwrap fails)", async () => {
    const sealed = await encryptSlot("WRAP-TOKEN-A", { x: 1 });
    const decoded = await decryptSlot("WRAP-TOKEN-B", sealed);
    expect(decoded).toBeUndefined();
  });

  it("returns undefined when the encrypted blob is corrupted", async () => {
    const sealed = await encryptSlot("WRAP-TOKEN", { x: 1 });
    const corrupted = { ...sealed, encryptedData: sealed.encryptedData.slice(0, -4) + "AAAA" };
    const decoded = await decryptSlot("WRAP-TOKEN", corrupted);
    expect(decoded).toBeUndefined();
  });
});
