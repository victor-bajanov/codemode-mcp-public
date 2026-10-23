import { describe, it, expect } from "vitest";
import {
  mintToken,
  mintFileHandle,
  decodeTokenSecret,
  decodeHandleBytes,
} from "../tokens";
import { TOKEN_PREFIX, HANDLE_PREFIX, TOKEN_SECRET_BYTES, HANDLE_BYTES } from "../types";

describe("mintToken", () => {
  it("returns a string with the stg_ prefix", () => {
    const t = mintToken();
    expect(t.startsWith(TOKEN_PREFIX)).toBe(true);
  });

  it("decodes to exactly 32 random bytes", () => {
    const t = mintToken();
    expect(decodeTokenSecret(t).byteLength).toBe(TOKEN_SECRET_BYTES);
  });

  it("produces different tokens on each call", () => {
    const s = new Set(Array.from({ length: 100 }, () => mintToken()));
    expect(s.size).toBe(100);
  });

  it("uses base64url (no + / =)", () => {
    const t = mintToken();
    expect(t).not.toMatch(/[+/=]/);
  });
});

describe("mintFileHandle", () => {
  it("returns a string with the fh_ prefix", () => {
    expect(mintFileHandle().startsWith(HANDLE_PREFIX)).toBe(true);
  });

  it("decodes to exactly 16 random bytes", () => {
    expect(decodeHandleBytes(mintFileHandle()).byteLength).toBe(HANDLE_BYTES);
  });

  it("produces different handles on each call", () => {
    const s = new Set(Array.from({ length: 100 }, () => mintFileHandle()));
    expect(s.size).toBe(100);
  });
});

describe("decodeTokenSecret", () => {
  it("throws when prefix is missing", () => {
    expect(() => decodeTokenSecret("xx_abcd")).toThrow();
  });

  it("throws when the body is the wrong length", () => {
    expect(() => decodeTokenSecret("stg_short")).toThrow();
  });
});

describe("decodeHandleBytes", () => {
  it("throws when prefix is missing", () => {
    expect(() => decodeHandleBytes("xx_abcd")).toThrow();
  });

  it("throws when the body is the wrong length", () => {
    expect(() => decodeHandleBytes("fh_short")).toThrow();
  });
});

describe("strict decoding (codec-backed)", () => {
  it("rejects a token or handle with embedded whitespace or padding", () => {
    const t = mintToken();
    const h = mintFileHandle();
    expect(() => decodeTokenSecret(t.slice(0, 10) + " " + t.slice(10))).toThrow();
    expect(() => decodeHandleBytes(h + "==")).toThrow();
    expect(() => decodeHandleBytes(h.slice(0, 8) + "\n" + h.slice(8))).toThrow();
  });

  it("rejects standard-alphabet characters", () => {
    const h = mintFileHandle();
    expect(() => decodeHandleBytes(h.slice(0, -1) + "+")).toThrow();
  });

  it("round-trips minted values", () => {
    for (let i = 0; i < 50; i++) {
      expect(decodeTokenSecret(mintToken()).byteLength).toBe(32);
      expect(decodeHandleBytes(mintFileHandle()).byteLength).toBe(16);
    }
  });
});

describe("timingSafeEqualStrings", () => {
  it("compares strings for equality", async () => {
    const { timingSafeEqualStrings } = await import("../tokens");
    expect(timingSafeEqualStrings("fh_abc", "fh_abc")).toBe(true);
    expect(timingSafeEqualStrings("fh_abc", "fh_abd")).toBe(false);
    expect(timingSafeEqualStrings("fh_abc", "fh_ab")).toBe(false);
  });
});
