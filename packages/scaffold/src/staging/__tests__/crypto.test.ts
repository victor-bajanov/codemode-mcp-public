import { describe, it, expect } from "vitest";
import {
  sha256Bearer,
  deriveContentKey,
} from "../crypto";
import { HKDF_INFO_V2 } from "../block-format";
import { mintToken, mintFileHandle, decodeTokenSecret, decodeHandleBytes } from "../tokens";

describe("sha256Bearer", () => {
  it("hashes the full bearer string (prefix included), returns 32 bytes", async () => {
    const t = mintToken();
    const h = await sha256Bearer(t);
    expect(h.byteLength).toBe(32);
  });

  it("is deterministic for the same input", async () => {
    const a = await sha256Bearer("stg_test");
    const b = await sha256Bearer("stg_test");
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
  });

  it("differs across different inputs", async () => {
    const a = await sha256Bearer("stg_a");
    const b = await sha256Bearer("stg_b");
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("deriveContentKey", () => {
  it("has no default HKDF info, so no caller can derive the retired v1 key by omission", () => {
    // A parameter with a default is not counted by Function.length.
    expect(deriveContentKey.length).toBe(3);
    const ts = decodeTokenSecret(mintToken());
    const hb = decodeHandleBytes(mintFileHandle());
    // @ts-expect-error `info` is required
    void deriveContentKey(ts, hb).catch(() => {});
  });

  it("returns a 32-byte AES-256 CryptoKey usable with AES-GCM", async () => {
    const token = mintToken();
    const handle = mintFileHandle();
    const key = await deriveContentKey(decodeTokenSecret(token), decodeHandleBytes(handle), HKDF_INFO_V2);
    expect(key).toBeInstanceOf(CryptoKey);
    // Round-trip a small payload to prove usability:
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode("hi")),
    );
    const pt = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct),
    );
    expect(new TextDecoder().decode(pt)).toBe("hi");
  });

  it("is deterministic: same (token, handle) → same key material", async () => {
    const t = mintToken();
    const h = mintFileHandle();
    const ts = decodeTokenSecret(t);
    const hb = decodeHandleBytes(h);
    const k1 = await deriveContentKey(ts, hb, HKDF_INFO_V2);
    const k2 = await deriveContentKey(ts, hb, HKDF_INFO_V2);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct1 = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k1, new TextEncoder().encode("x")),
    );
    const pt2 = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, k2, ct1),
    );
    expect(new TextDecoder().decode(pt2)).toBe("x");
  });

  it("different handles → different keys (same token)", async () => {
    const t = decodeTokenSecret(mintToken());
    const h1 = decodeHandleBytes(mintFileHandle());
    const h2 = decodeHandleBytes(mintFileHandle());
    const k1 = await deriveContentKey(t, h1, HKDF_INFO_V2);
    const k2 = await deriveContentKey(t, h2, HKDF_INFO_V2);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct1 = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k1, new TextEncoder().encode("x")),
    );
    await expect(crypto.subtle.decrypt({ name: "AES-GCM", iv }, k2, ct1))
      .rejects.toThrow();
  });
});
