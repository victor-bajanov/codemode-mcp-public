import { describe, it, expect } from "vitest";
import { Base64Encoder, base64Length, decodeBase64Into, decodedLength, type Base64Mode } from "../codec";
import { BLOCK_BYTES } from "../block-format";

const NATIVE = typeof (Uint8Array.prototype as unknown as { toBase64?: unknown }).toBase64 === "function";

function pattern(n: number, seed = 1): Uint8Array {
  const a = new Uint8Array(n);
  let x = seed >>> 0 || 1;
  for (let i = 0; i < n; i++) {
    x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0;
    a[i] = x & 0xff;
  }
  return a;
}

function reference(bytes: Uint8Array, mode: Base64Mode): string {
  const b64 = Buffer.from(bytes).toString("base64");
  if (mode === "plain") return b64;
  let out = "";
  for (let i = 0; i < b64.length; i += 76) out += b64.slice(i, i + 76) + "\r\n";
  return out;
}

async function encodeAll(
  bytes: Uint8Array, mode: Base64Mode, blockSize: number, forceJs: boolean,
): Promise<{ text: string; chunks: number[] }> {
  const enc = new Base64Encoder(mode, "std", { forceJs });
  const parts: Buffer[] = [];
  const chunks: number[] = [];
  const emit = async (ascii: Uint8Array) => {
    parts.push(Buffer.from(ascii));
    chunks.push(ascii.byteLength);
  };
  for (let off = 0; off < bytes.byteLength; off += blockSize) {
    await enc.push(bytes.subarray(off, Math.min(bytes.byteLength, off + blockSize)), emit);
  }
  await enc.finish(emit);
  return { text: Buffer.concat(parts).toString("latin1"), chunks };
}

const PATHS: Array<[string, boolean]> = [["js", true], ...(NATIVE ? [["native", false] as [string, boolean]] : [])];

describe("base64Length", () => {
  it("is exact for both modes", () => {
    for (let n = 0; n <= 300; n++) {
      const x = pattern(n);
      expect(base64Length(n, "plain")).toBe(reference(x, "plain").length);
      expect(base64Length(n, "lines")).toBe(reference(x, "lines").length);
    }
    const big = 50 * BLOCK_BYTES;
    expect(base64Length(big, "plain")).toBe(Math.ceil(big / 3) * 4);
  });
});

describe.each(PATHS)("Base64Encoder (%s path)", (_name, forceJs) => {
  it("matches Buffer for every length 0..300 in both modes, pushed whole and byte by byte", async () => {
    for (let n = 0; n <= 300; n++) {
      const x = pattern(n, n + 1);
      for (const mode of ["plain", "lines"] as const) {
        expect((await encodeAll(x, mode, Math.max(1, n), forceJs)).text).toBe(reference(x, mode));
      }
    }
    const x = pattern(200, 9);
    for (const mode of ["plain", "lines"] as const) {
      for (const step of [1, 2, 5, 56, 57, 58]) {
        expect((await encodeAll(x, mode, step, forceJs)).text).toBe(reference(x, mode));
      }
    }
  });

  it("carries the remainder across 1 MiB blocks (k·MiB + r inputs)", async () => {
    for (const len of [BLOCK_BYTES + 1, 2 * BLOCK_BYTES + 2, 3 * BLOCK_BYTES + 5]) {
      const x = pattern(len, len);
      for (const mode of ["plain", "lines"] as const) {
        const { text, chunks } = await encodeAll(x, mode, BLOCK_BYTES, forceJs);
        expect(text.length).toBe(base64Length(len, mode));
        expect(text).toBe(reference(x, mode));
        // No emitted chunk is bigger than one encoded block (plus a line).
        for (const c of chunks) expect(c).toBeLessThanOrEqual(base64Length(BLOCK_BYTES + 57, "lines"));
      }
    }
  });
});

describe.each(PATHS)("decodeBase64Into (%s path)", (_name, forceJs) => {
  const opts = { forceJs };
  function decode(s: string, alphabet: "std" | "url"): Uint8Array {
    const n = decodedLength(s, 0, s.length, alphabet);
    const out = new Uint8Array(n);
    const w = decodeBase64Into(s, 0, s.length, out, 0, alphabet, opts);
    expect(w).toBe(n);
    return out;
  }

  it("round-trips Buffer's encoding for 0..300 bytes (std, padded and unpadded)", () => {
    for (let n = 0; n <= 300; n++) {
      const x = pattern(n, n + 3);
      const b64 = Buffer.from(x).toString("base64");
      expect(Buffer.from(decode(b64, "std")).equals(Buffer.from(x))).toBe(true);
      expect(Buffer.from(decode(b64.replace(/=+$/, ""), "std")).equals(Buffer.from(x))).toBe(true);
    }
  });

  it("decodes the url alphabet with and without padding", () => {
    for (let n = 0; n <= 100; n++) {
      const x = pattern(n, n + 5);
      const url = Buffer.from(x).toString("base64url");
      const padded = url + "=".repeat((4 - (url.length % 4)) % 4);
      expect(Buffer.from(decode(url, "url")).equals(Buffer.from(x))).toBe(true);
      expect(Buffer.from(decode(padded, "url")).equals(Buffer.from(x))).toBe(true);
    }
  });

  it("decodes a sub-range into an offset in the destination", () => {
    const x = pattern(30);
    const s = "!!!!" + Buffer.from(x).toString("base64") + "????";
    const dst = new Uint8Array(35);
    const w = decodeBase64Into(s, 4, s.length - 4, dst, 5, "std", opts);
    expect(w).toBe(30);
    expect(Buffer.from(dst.subarray(5)).equals(Buffer.from(x))).toBe(true);
  });

  it.each([
    ["whitespace", "AAAA AAA", "std"],
    ["newline", "AAAA\nAAAA", "std"],
    ["= in the middle", "AA==AAAA", "std"],
    ["url chars in std", "AA-_", "std"],
    ["std chars in url", "AA+/", "url"],
    ["length ≡ 1 mod 4", "AAAAA", "std"],
    ["non-ascii", "AAAé", "std"],
    ["three pads", "A===", "std"],
    ["pad without full quantum", "AA=", "std"],
  ] as const)("rejects %s", (_label, input, alphabet) => {
    expect(() => {
      const n = decodedLength(input, 0, input.length, alphabet);
      decodeBase64Into(input, 0, input.length, new Uint8Array(n + 8), 0, alphabet, opts);
    }).toThrow();
  });
});

describe("decodedLength", () => {
  it("is exact for padded and unpadded input", () => {
    for (let n = 0; n <= 50; n++) {
      const b64 = Buffer.from(pattern(n)).toString("base64");
      expect(decodedLength(b64, 0, b64.length, "std")).toBe(n);
      const bare = b64.replace(/=+$/, "");
      expect(decodedLength(bare, 0, bare.length, "std")).toBe(n);
    }
  });

  it("throws for a length ≡ 1 mod 4", () => {
    expect(() => decodedLength("AAAAA", 0, 5, "std")).toThrow();
  });
});

describe("native detection", () => {
  it.runIf(process.env.REQUIRE_NATIVE_B64 === "1")(
    "REQUIRE_NATIVE_B64=1: the native toBase64/setFromBase64 path is present, so it cannot be silently skipped",
    () => {
      const proto = Uint8Array.prototype as unknown as { toBase64?: unknown; setFromBase64?: unknown };
      expect(typeof proto.toBase64).toBe("function");
      expect(typeof proto.setFromBase64).toBe("function");
      expect(PATHS.map(([n]) => n)).toContain("native");
    },
  );

  it("reports whether the platform has Uint8Array.prototype.toBase64", () => {
    // Informational: under Node 22 the JS path is the only one exercised.
    expect(typeof NATIVE).toBe("boolean");
  });
});
