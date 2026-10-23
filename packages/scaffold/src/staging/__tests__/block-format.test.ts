import { describe, it, expect } from "vitest";
import {
  BLOCK_BYTES,
  ENC_VERSION_V2,
  HKDF_INFO_V2,
  blockAad,
  blockCount,
  blockNonce,
  ciphertextLength,
  decryptBlock,
  encryptBlock,
} from "../block-format";
import { deriveContentKey, deriveV2Key } from "../crypto";
import { HKDF_INFO } from "./__fixtures__/v1-row";
import { decodeHandleBytes, decodeTokenSecret, mintFileHandle, mintToken } from "../tokens";

const HANDLE = "fh_AAAAAAAAAAAAAAAAAAAAAA";
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("blockCount / ciphertextLength", () => {
  it("counts at least one block, then ceil(len / BLOCK_BYTES)", () => {
    expect(blockCount(0)).toBe(1);
    expect(blockCount(1)).toBe(1);
    expect(blockCount(BLOCK_BYTES)).toBe(1);
    expect(blockCount(BLOCK_BYTES + 1)).toBe(2);
    expect(blockCount(3 * BLOCK_BYTES + 5)).toBe(4);
  });

  it("adds one 16-byte tag per block", () => {
    expect(ciphertextLength(0)).toBe(16);
    expect(ciphertextLength(BLOCK_BYTES)).toBe(BLOCK_BYTES + 16);
    expect(ciphertextLength(BLOCK_BYTES + 1)).toBe(BLOCK_BYTES + 1 + 32);
    expect(ciphertextLength(50 * BLOCK_BYTES)).toBe(50 * BLOCK_BYTES + 50 * 16);
  });

  it("rejects negative or non-integer lengths", () => {
    expect(() => blockCount(-1)).toThrow();
    expect(() => blockCount(1.5)).toThrow();
  });
});

describe("blockNonce", () => {
  it("is the 8-byte prefix followed by BE32(index)", () => {
    const base = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(hex(blockNonce(base, 0))).toBe("010203040506070800000000");
    expect(hex(blockNonce(base, 0x01020304))).toBe("010203040506070801020304");
  });

  it("is distinct for every index in 0..n", () => {
    const base = crypto.getRandomValues(new Uint8Array(8));
    const seen = new Set<string>();
    for (let i = 0; i <= 64; i++) seen.add(hex(blockNonce(base, i)));
    expect(seen.size).toBe(65);
  });

  it("rejects a prefix that is not 8 bytes, or an out-of-range index", () => {
    expect(() => blockNonce(new Uint8Array(12), 0)).toThrow();
    expect(() => blockNonce(new Uint8Array(8), -1)).toThrow();
    expect(() => blockNonce(new Uint8Array(8), 2 ** 32)).toThrow();
  });
});

describe("blockAad", () => {
  it("pins the byte layout: BE16(len) ‖ handle ‖ version ‖ BE32(index) ‖ BE32(n) ‖ BE64(byteLen)", () => {
    const aad = blockAad(HANDLE, 2, 3, 2 * BLOCK_BYTES + 5);
    expect(hex(aad)).toBe(
      "0019" +
        Buffer.from(HANDLE, "utf8").toString("hex") +
        "02" +
        "00000002" +
        "00000003" +
        "0000000000200005",
    );
    expect(aad[2 + HANDLE.length]).toBe(ENC_VERSION_V2);
  });
});

async function v2Key(): Promise<{ key: CryptoKey; handle: string }> {
  const token = mintToken();
  const handle = mintFileHandle();
  return { key: await deriveV2Key(token, handle), handle };
}

function filled(n: number): Uint8Array {
  const a = new Uint8Array(n);
  for (let i = 0; i < n; i++) a[i] = (i * 31 + 7) & 0xff;
  return a;
}

describe("encryptBlock / decryptBlock round-trip", () => {
  for (const size of [0, 1, BLOCK_BYTES - 1, BLOCK_BYTES, BLOCK_BYTES + 1, 3 * BLOCK_BYTES + 5]) {
    it(`round-trips a ${size}-byte file block by block`, async () => {
      const { key, handle } = await v2Key();
      const ivBase = crypto.getRandomValues(new Uint8Array(8));
      const plain = filled(size);
      const n = blockCount(size);
      const blocks: Uint8Array[] = [];
      for (let i = 0; i < n; i++) {
        const chunk = plain.subarray(i * BLOCK_BYTES, Math.min(size, (i + 1) * BLOCK_BYTES));
        const ct = await encryptBlock(key, ivBase, handle, i, n, size, chunk);
        expect(ct.byteLength).toBe(chunk.byteLength + 16);
        blocks.push(ct);
      }
      expect(blocks.reduce((s, b) => s + b.byteLength, 0)).toBe(ciphertextLength(size));
      let off = 0;
      for (let i = 0; i < n; i++) {
        const pt = await decryptBlock(key, ivBase, handle, i, n, size, blocks[i]!);
        expect(Buffer.from(pt).equals(Buffer.from(plain.subarray(off, off + pt.byteLength)))).toBe(true);
        off += pt.byteLength;
      }
      expect(off).toBe(size);
    });
  }
});

describe("tamper matrix", () => {
  const size = 2 * BLOCK_BYTES + 3;
  const n = 3;

  async function setup() {
    const { key, handle } = await v2Key();
    const ivBase = crypto.getRandomValues(new Uint8Array(8));
    const plain = filled(BLOCK_BYTES);
    const ct = await encryptBlock(key, ivBase, handle, 1, n, size, plain);
    return { key, handle, ivBase, ct };
  }

  it("decrypts the untampered block (control)", async () => {
    const { key, handle, ivBase, ct } = await setup();
    await expect(decryptBlock(key, ivBase, handle, 1, n, size, ct)).resolves.toBeInstanceOf(Uint8Array);
  });

  it("fails with the wrong index", async () => {
    const { key, handle, ivBase, ct } = await setup();
    await expect(decryptBlock(key, ivBase, handle, 0, n, size, ct)).rejects.toThrow();
  });

  it("fails with the wrong block count", async () => {
    const { key, handle, ivBase, ct } = await setup();
    await expect(decryptBlock(key, ivBase, handle, 1, n + 1, size, ct)).rejects.toThrow();
  });

  it("fails with the wrong total length", async () => {
    const { key, handle, ivBase, ct } = await setup();
    await expect(decryptBlock(key, ivBase, handle, 1, n, size + 1, ct)).rejects.toThrow();
  });

  it("fails with the wrong handle", async () => {
    const { key, ivBase, ct } = await setup();
    await expect(decryptBlock(key, ivBase, mintFileHandle(), 1, n, size, ct)).rejects.toThrow();
  });

  it("fails with a flipped ciphertext byte", async () => {
    const { key, handle, ivBase, ct } = await setup();
    const bad = ct.slice();
    bad[100] = bad[100]! ^ 1;
    await expect(decryptBlock(key, ivBase, handle, 1, n, size, bad)).rejects.toThrow();
  });

  it("fails with a flipped tag byte", async () => {
    const { key, handle, ivBase, ct } = await setup();
    const bad = ct.slice();
    bad[bad.length - 1] = bad[bad.length - 1]! ^ 1;
    await expect(decryptBlock(key, ivBase, handle, 1, n, size, bad)).rejects.toThrow();
  });

  it("fails when the block was sealed under another index's nonce (moved block)", async () => {
    const { key, handle, ivBase } = await setup();
    const plain = filled(BLOCK_BYTES);
    const sealedAt0 = await encryptBlock(key, ivBase, handle, 0, n, size, plain);
    await expect(decryptBlock(key, ivBase, handle, 1, n, size, sealedAt0)).rejects.toThrow();
  });

  it("fails with a different ivBase", async () => {
    const { key, handle, ct } = await setup();
    await expect(
      decryptBlock(key, crypto.getRandomValues(new Uint8Array(8)), handle, 1, n, size, ct),
    ).rejects.toThrow();
  });
});

describe("v2 key derivation", () => {
  it("uses a distinct HKDF info from v1, so v1 and v2 keys differ", async () => {
    expect(HKDF_INFO_V2).not.toBe(HKDF_INFO);
    const token = mintToken();
    const handle = mintFileHandle();
    const iv = new Uint8Array(12);
    const pt = new Uint8Array([1, 2, 3]);
    const k1 = await deriveContentKey(decodeTokenSecret(token), decodeHandleBytes(handle), HKDF_INFO);
    const k2 = await deriveContentKey(decodeTokenSecret(token), decodeHandleBytes(handle), HKDF_INFO_V2);
    const k2b = await deriveV2Key(token, handle);
    const ct1 = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k1, pt));
    const ct2 = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k2, pt));
    const ct2b = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k2b, pt));
    expect(hex(ct1)).not.toBe(hex(ct2));
    expect(hex(ct2)).toBe(hex(ct2b));
  });
});
