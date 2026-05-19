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
