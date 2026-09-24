// Regression tests for the send-path Subject normalizer. The trigger: the
// 2026-08-25 "Codemode MCP-v2 watch" routine email arrived with the subject
// "Codemode MCP-v2 watch Ã¢Â€Â” ... Ã¢Â€Â” CHANGES" — each em dash (U+2014)
// shipped as the bytes C3 83 C2 A2 C3 82 C2 80 C3 82 C2 94, i.e. the UTF-8
// encoding run through "read as Latin-1, re-encode as UTF-8" twice, dumped
// raw into the header with no RFC 2047 encoding. The executeHint documents
// the correct idiom (since PR #14) but cannot stop sandbox code from
// improvising a double-wrapped encoder, so the provider repairs the Subject
// host-side via SurfaceReviewEntry.normalizeBody.

import { describe, it, expect } from "vitest";
import {
  normalizeOutboundMessage,
  repairRawSubject,
  repairMojibake,
  encodeHeaderWord,
} from "../inspectors/normalize-subject";

const CLEAN_SUBJECT = "Codemode MCP-v2 watch — 2026-08-25 — CHANGES";

/** One "UTF-8 bytes read back as Latin-1" layer. */
function mangle(s: string): string {
  return Buffer.from(s, "utf8").toString("latin1");
}

function toBase64Url(s: string): string {
  return Buffer.from(s, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(s: string): Buffer {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return Buffer.from(b64, "base64");
}

function rfc822(subjectValue: string, body = "hello", eol = "\r\n"): string {
  return [
    "From: me",
    "To: you@example.com",
    `Subject: ${subjectValue}`,
    "MIME-Version: 1.0",
    'Content-Type: text/plain; charset="UTF-8"',
    "",
    body,
  ].join(eol);
}

/** Decoded subject the receiving client renders, from a normalized raw. */
function deliveredSubject(raw: string): string {
  const text = fromBase64Url(raw).toString("utf8");
  const headerEnd = text.indexOf("\r\n\r\n") >= 0 ? text.indexOf("\r\n\r\n") : text.indexOf("\n\n");
  const lines = text.slice(0, headerEnd).split(/\r?\n/);
  const i = lines.findIndex((l) => /^subject:/i.test(l));
  expect(i).toBeGreaterThanOrEqual(0);
  const parts = [lines[i]!.slice(lines[i]!.indexOf(":") + 1).trim()];
  for (let j = i + 1; j < lines.length && /^[ \t]/.test(lines[j]!); j++) parts.push(lines[j]!.trim());
  const value = parts.join(" ").replace(/(\?=)\s+(=\?)/g, "$1$2");
  return value.replace(/=\?UTF-8\?B\?([^?]*)\?=/gi, (_, b64: string) =>
    Buffer.from(b64, "base64").toString("utf8"),
  );
}

describe("repairMojibake", () => {
  it("unwinds the routine email's double-encoding to the real em dash", () => {
    expect(repairMojibake(mangle(mangle(CLEAN_SUBJECT)))).toBe(CLEAN_SUBJECT);
  });

  it("unwinds a single layer", () => {
    expect(repairMojibake(mangle(CLEAN_SUBJECT))).toBe(CLEAN_SUBJECT);
  });

  it("leaves already-clean Unicode text alone", () => {
    expect(repairMojibake(CLEAN_SUBJECT)).toBe(CLEAN_SUBJECT);
  });

  it("leaves genuine Latin-1-looking text alone (strict-decode guard)", () => {
    expect(repairMojibake("café")).toBe("café");
    expect(repairMojibake("Ã la carte")).toBe("Ã la carte");
  });

  it("leaves pure ASCII alone", () => {
    expect(repairMojibake("Plain subject")).toBe("Plain subject");
  });
});

describe("encodeHeaderWord", () => {
  it("passes ASCII through unchanged", () => {
    expect(encodeHeaderWord("Plain subject")).toBe("Plain subject");
  });

  it("emits RFC 2047 UTF-8 B words that decode back to the input", () => {
    const encoded = encodeHeaderWord(CLEAN_SUBJECT);
    expect(encoded).toMatch(/^=\?UTF-8\?B\?/);
    const decoded = encoded
      .split("\r\n ")
      .join("")
      .replace(/=\?UTF-8\?B\?([^?]*)\?=/gi, (_, b64: string) =>
        Buffer.from(b64, "base64").toString("utf8"),
      );
    expect(decoded).toBe(CLEAN_SUBJECT);
  });

  it("keeps every encoded-word line within the RFC 2047 75-char limit", () => {
    const long = "— très long sujet avec beaucoup de caractères non-ASCII — ".repeat(4);
    for (const line of encodeHeaderWord(long).split("\r\n ")) {
      expect(line.length).toBeLessThanOrEqual(75);
    }
  });
});

describe("repairRawSubject / normalizeOutboundMessage", () => {
  it("repairs the exact double-mojibake the 2026-08-25 routine email shipped", () => {
    const wire = rfc822(mangle(mangle(CLEAN_SUBJECT)));
    // Sanity: the wire header carries the observed byte fingerprint.
    expect(Buffer.from(wire, "utf8").toString("hex")).toContain("c383c2a2c382c280c382c294");
    const out = normalizeOutboundMessage({ raw: toBase64Url(wire) }) as { raw: string };
    expect(out).toBeDefined();
    expect(deliveredSubject(out.raw)).toBe(CLEAN_SUBJECT);
  });

  it("converts a correct-but-raw UTF-8 subject into an encoded word", () => {
    const out = normalizeOutboundMessage({ raw: toBase64Url(rfc822(CLEAN_SUBJECT)) }) as {
      raw: string;
    };
    expect(out).toBeDefined();
    const text = fromBase64Url(out.raw).toString("utf8");
    // Header section is now pure ASCII (encoded-words), body untouched.
    const headerEnd = text.indexOf("\r\n\r\n");
    expect(/^[\x00-\x7F]*$/.test(text.slice(0, headerEnd))).toBe(true);
    expect(deliveredSubject(out.raw)).toBe(CLEAN_SUBJECT);
  });

  it("repairs a mojibake'd subject hiding inside an encoded word", () => {
    const b64 = Buffer.from(mangle(CLEAN_SUBJECT), "utf8").toString("base64");
    const out = normalizeOutboundMessage({
      raw: toBase64Url(rfc822(`=?UTF-8?B?${b64}?=`)),
    }) as { raw: string };
    expect(out).toBeDefined();
    expect(deliveredSubject(out.raw)).toBe(CLEAN_SUBJECT);
  });

  it("returns undefined for a plain ASCII subject (no change)", () => {
    expect(normalizeOutboundMessage({ raw: toBase64Url(rfc822("Plain subject")) })).toBeUndefined();
  });

  it("returns undefined when the subject is already a canonical encoded word", () => {
    const canonical = encodeHeaderWord(CLEAN_SUBJECT);
    const raw = toBase64Url(rfc822(canonical));
    expect(normalizeOutboundMessage({ raw })).toBeUndefined();
  });

  it("preserves the message body byte-for-byte across a repair", () => {
    const body = "line one\r\n\r\nbinary-ish: " + mangle("—…—") + "\r\n--boundary--";
    const wire = rfc822(mangle(mangle(CLEAN_SUBJECT)), body);
    const out = normalizeOutboundMessage({ raw: toBase64Url(wire) }) as { raw: string };
    const text = fromBase64Url(out.raw).toString("utf8");
    expect(text.slice(text.indexOf("\r\n\r\n"))).toBe("\r\n\r\n" + body);
  });

  it("handles LF-only line endings", () => {
    const wire = rfc822(mangle(mangle(CLEAN_SUBJECT)), "hello", "\n");
    const out = normalizeOutboundMessage({ raw: toBase64Url(wire) }) as { raw: string };
    expect(out).toBeDefined();
    expect(deliveredSubject(out.raw)).toBe(CLEAN_SUBJECT);
  });

  it("repairs the draft wrapper shape { message: { raw } }", () => {
    const raw = toBase64Url(rfc822(mangle(mangle(CLEAN_SUBJECT))));
    const out = normalizeOutboundMessage({ id: "r-123", message: { raw } }) as {
      id: string;
      message: { raw: string };
    };
    expect(out.id).toBe("r-123");
    expect(deliveredSubject(out.message.raw)).toBe(CLEAN_SUBJECT);
  });

  it("neutralizes CR/LF smuggled through an encoded word (no header injection)", () => {
    const b64 = Buffer.from("evil\r\nBcc: attacker@example.com", "utf8").toString("base64");
    const out = normalizeOutboundMessage({
      raw: toBase64Url(rfc822(`=?UTF-8?B?${b64}?= —`)),
    }) as { raw: string };
    expect(out).toBeDefined();
    const text = fromBase64Url(out.raw).toString("utf8");
    expect(text).not.toContain("Bcc: attacker@example.com");
    expect(deliveredSubject(out.raw)).toBe("evil Bcc: attacker@example.com —");
  });

  it("bails to undefined on inputs it cannot confidently interpret", () => {
    expect(normalizeOutboundMessage("not an object")).toBeUndefined();
    expect(normalizeOutboundMessage({})).toBeUndefined();
    expect(normalizeOutboundMessage({ raw: "!!!not-base64!!!" })).toBeUndefined();
    // No header/body separator.
    expect(normalizeOutboundMessage({ raw: toBase64Url("Subject: x") })).toBeUndefined();
    // Header section that is not valid UTF-8 (true Latin-1 é byte).
    const latin1 = Buffer.concat([
      Buffer.from("Subject: caf", "utf8"),
      Buffer.from([0xe9]),
      Buffer.from("\r\n\r\nbody", "utf8"),
    ]);
    const rawLatin1 = latin1.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(normalizeOutboundMessage({ raw: rawLatin1 })).toBeUndefined();
    // No Subject header at all.
    expect(
      normalizeOutboundMessage({ raw: toBase64Url("To: a@b.com\r\n\r\nbody") }),
    ).toBeUndefined();
  });

  it("exposes repairRawSubject returning undefined for an untouched message", () => {
    expect(repairRawSubject(toBase64Url(rfc822("nothing to do")))).toBeUndefined();
  });
});
