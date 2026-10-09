// A4 — encrypt-slot.ts: hardcoded HMAC constant, fixed zero IV, JSON.parse on
// decrypted bytes, decrypt-failure oracle.
//
// STATUS: REFUTED (controls hold). Observations against the real module:
//   - Fresh AES-GCM data key per encrypt → same plaintext/same token gives a
//     different ciphertext AND wrapped key each time; the zero IV is never
//     reused with the same key, so GCM's nonce rule is honoured.
//   - The hardcoded WRAPPING_KEY_HMAC_KEY is a domain separator, not a secret:
//     security rests entirely on the wrapping token (the grant's original
//     upstream refresh token). A KV-dump reader without that token gets
//     nothing; a wrong token yields `undefined`, never a throw or a partial.
//   - AES-KW unwrap and AES-GCM decrypt are both authenticated, so JSON.parse
//     only ever runs on bytes that passed a MAC — tampering yields `undefined`.
//   - No oracle: wrong-token, tampered-wrappedKey and tampered-ciphertext all
//     collapse to the same `undefined` result.

import { describe, it, expect } from "vitest";
import { encryptSlot, decryptSlot, type SealedSlot } from "../../encrypt-slot";

const SLOT = { seedKey: "abc", currentRefreshToken: "RT-live", accessToken: "AT", accessExpiresAt: 1, lastUsedAt: 0 };

function flipByte(b64: string, idx: number): string {
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  bytes[idx] = bytes[idx]! ^ 0x01;
  return btoa(String.fromCharCode(...bytes));
}

describe("A4 encrypt-slot properties", () => {
  it("REFUTED: fresh data key per call — identical inputs never produce identical ciphertext", async () => {
    const a = await encryptSlot("RT-wrap", SLOT);
    const b = await encryptSlot("RT-wrap", SLOT);
    expect(a.encryptedData).not.toBe(b.encryptedData);
    expect(a.wrappedKey).not.toBe(b.wrappedKey);
    expect(await decryptSlot("RT-wrap", a)).toEqual(SLOT);
    expect(await decryptSlot("RT-wrap", b)).toEqual(SLOT);
  });

  it("REFUTED: wrong wrapping token, tampered key, tampered ciphertext all yield undefined (no oracle, no throw)", async () => {
    const sealed = await encryptSlot("RT-wrap", SLOT);
    expect(await decryptSlot("RT-other", sealed)).toBeUndefined();
    const badKey: SealedSlot = { ...sealed, wrappedKey: flipByte(sealed.wrappedKey, 3) };
    expect(await decryptSlot("RT-wrap", badKey)).toBeUndefined();
    const badData: SealedSlot = { ...sealed, encryptedData: flipByte(sealed.encryptedData, 0) };
    expect(await decryptSlot("RT-wrap", badData)).toBeUndefined();
    const garbage: SealedSlot = { encryptedData: "!!!", wrappedKey: "???" };
    expect(await decryptSlot("RT-wrap", garbage)).toBeUndefined();
  });

  it("REFUTED: sealed blob carries no plaintext from the slot", async () => {
    const sealed = await encryptSlot("RT-wrap", SLOT);
    const json = JSON.stringify(sealed);
    expect(json).not.toContain("RT-live");
    expect(json).not.toContain("RT-wrap");
    expect(json).not.toContain("accessToken");
  });
});
