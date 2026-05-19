import { describe, it, expect } from "vitest";
import {
  sha256Bearer,
  deriveContentKey,
  encryptForStorage,
  decryptFromStorage,
} from "../crypto";
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
  it("returns a 32-byte AES-256 CryptoKey usable with AES-GCM", async () => {
    const token = mintToken();
    const handle = mintFileHandle();
    const key = await deriveContentKey(decodeTokenSecret(token), decodeHandleBytes(handle));
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
    const k1 = await deriveContentKey(ts, hb);
    const k2 = await deriveContentKey(ts, hb);
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
    const k1 = await deriveContentKey(t, h1);
    const k2 = await deriveContentKey(t, h2);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct1 = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k1, new TextEncoder().encode("x")),
    );
    await expect(crypto.subtle.decrypt({ name: "AES-GCM", iv }, k2, ct1))
      .rejects.toThrow();
  });
});

describe("encryptForStorage / decryptFromStorage", () => {
  it("round-trips plaintext under matching (token, handle)", async () => {
    const token = mintToken();
    const handle = mintFileHandle();
    const plain = new Uint8Array(1024);
    crypto.getRandomValues(plain);
    const { ciphertext, iv } = await encryptForStorage(token, handle, plain);
    const out = await decryptFromStorage(token, handle, ciphertext, iv);
    expect(Buffer.from(out).equals(Buffer.from(plain))).toBe(true);
  });

  it("rejects when AAD (file_handle) doesn't match", async () => {
    const token = mintToken();
    const handle = mintFileHandle();
    const wrongHandle = mintFileHandle();
    const plain = new TextEncoder().encode("hello");
    const { ciphertext, iv } = await encryptForStorage(token, handle, plain);
    await expect(decryptFromStorage(token, wrongHandle, ciphertext, iv)).rejects.toThrow();
  });

  it("rejects when token doesn't match", async () => {
    const handle = mintFileHandle();
    const plain = new TextEncoder().encode("hello");
    const { ciphertext, iv } = await encryptForStorage(mintToken(), handle, plain);
    await expect(decryptFromStorage(mintToken(), handle, ciphertext, iv)).rejects.toThrow();
  });

  it("rejects when ciphertext is tampered (last byte flipped)", async () => {
    const token = mintToken();
    const handle = mintFileHandle();
    const plain = new TextEncoder().encode("hello world");
    const { ciphertext, iv } = await encryptForStorage(token, handle, plain);
    ciphertext[ciphertext.byteLength - 1] = (ciphertext[ciphertext.byteLength - 1] ?? 0) ^ 0x01;
    await expect(decryptFromStorage(token, handle, ciphertext, iv)).rejects.toThrow();
  });

  it("produces unique IVs across calls", async () => {
    const token = mintToken();
    const handle = mintFileHandle();
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const { iv } = await encryptForStorage(token, handle, new Uint8Array([0]));
      seen.add(Buffer.from(iv).toString("hex"));
    }
    expect(seen.size).toBe(50);
  });
});
