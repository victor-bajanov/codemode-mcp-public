// The composed-channel Subject normaliser (issue #59, Task C3). A media-upload
// send carries the RFC 822 header block as plain text in the first composed
// segment rather than as base64url `raw`, so the Subject repair has a text
// entry point, `repairRfc822Text`, and `repairRawSubject` is its base64url
// wrapper. Every fixture below must come out of both entry points identically.

import { describe, it, expect } from "vitest";
import { repairRfc822Text, repairRawSubject } from "../inspectors/normalize-subject";

const CLEAN_SUBJECT = "Codemode MCP-v2 watch — 2026-08-25 — CHANGES";

/** One "UTF-8 bytes read back as Latin-1" layer. */
function mangle(s: string): string {
  return Buffer.from(s, "utf8").toString("latin1");
}

function toBase64Url(s: string): string {
  return Buffer.from(s, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s: string): string {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return Buffer.from(b64, "base64").toString("utf8");
}

/** A composed send's leading text segment: headers, then the opening of a
 *  multipart body up to where the staged attachment bytes are spliced in. */
function composedPrefix(subjectValue: string, eol = "\r\n"): string {
  return [
    "From: me",
    "To: you@example.com",
    `Subject: ${subjectValue}`,
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="b1"',
    "",
    "--b1",
    'Content-Type: text/plain; charset="UTF-8"',
    "",
    "hello — body text is never touched",
    "",
    "--b1",
    'Content-Type: application/pdf; name="q.pdf"',
    'Content-Disposition: attachment; filename="q.pdf"',
    "Content-Transfer-Encoding: base64",
    "",
    "",
  ].join(eol);
}

/** The shared fixture: inputs both entry points must treat identically. */
const FIXTURES: Array<{ name: string; text: string; changes: boolean }> = [
  { name: "double mojibake (the 2026-08-25 routine email)", text: composedPrefix(mangle(mangle(CLEAN_SUBJECT))), changes: true },
  { name: "single mojibake layer", text: composedPrefix(mangle(CLEAN_SUBJECT)), changes: true },
  { name: "correct but raw UTF-8 subject", text: composedPrefix(CLEAN_SUBJECT), changes: true },
  {
    name: "mojibake hiding inside an encoded word",
    text: composedPrefix(`=?UTF-8?B?${Buffer.from(mangle(CLEAN_SUBJECT), "utf8").toString("base64")}?=`),
    changes: true,
  },
  { name: "LF-only line endings", text: composedPrefix(mangle(mangle(CLEAN_SUBJECT)), "\n"), changes: true },
  {
    name: "CR/LF smuggled through an encoded word",
    text: composedPrefix(`=?UTF-8?B?${Buffer.from("hi\r\nBcc: evil@x.com", "utf8").toString("base64")}?=`),
    changes: true,
  },
  { name: "plain ASCII subject", text: composedPrefix("Quarterly report"), changes: false },
  { name: "already-canonical encoded word", text: composedPrefix("=?UTF-8?B?w6k=?="), changes: false },
  { name: "no Subject header", text: composedPrefix("x").replace(/^Subject: x\r\n/m, ""), changes: false },
  { name: "no header terminator", text: "From: me\r\nSubject: " + CLEAN_SUBJECT, changes: false },
];

describe("repairRfc822Text", () => {
  for (const f of FIXTURES) {
    it(`${f.name}: matches repairRawSubject on the base64url form`, () => {
      const viaText = repairRfc822Text(f.text);
      const viaRaw = repairRawSubject(toBase64Url(f.text));
      expect(viaText === undefined).toBe(!f.changes);
      expect(viaText).toBe(viaRaw === undefined ? undefined : fromBase64Url(viaRaw));
    });
  }

  it("rewrites only the Subject line; every other header and the body survive verbatim", () => {
    const input = composedPrefix(mangle(mangle(CLEAN_SUBJECT)));
    const out = repairRfc822Text(input);
    expect(out).toBeDefined();
    const before = input.split("\r\n");
    const after = out!.split("\r\n");
    const subjectAt = before.findIndex((l) => l.startsWith("Subject:"));
    expect(after.slice(0, subjectAt)).toEqual(before.slice(0, subjectAt));
    // The repaired subject may fold onto continuation lines; skip them.
    let j = subjectAt + 1;
    while (/^[ \t]/.test(after[j]!)) j++;
    expect(after.slice(j)).toEqual(before.slice(subjectAt + 1));
    expect(after[subjectAt]).toMatch(/^Subject: =\?UTF-8\?B\?/);
  });

  it("re-emits the subject as RFC 2047 words that decode to the intended text", () => {
    const out = repairRfc822Text(composedPrefix(mangle(mangle(CLEAN_SUBJECT))))!;
    const header = out.slice(0, out.indexOf("\r\n\r\n")).split("\r\n");
    const i = header.findIndex((l) => l.startsWith("Subject:"));
    const parts = [header[i]!.slice("Subject:".length).trim()];
    for (let j = i + 1; j < header.length && /^[ \t]/.test(header[j]!); j++) parts.push(header[j]!.trim());
    const decoded = parts
      .join("")
      .replace(/=\?UTF-8\?B\?([^?]*)\?=/g, (_, b: string) => Buffer.from(b, "base64").toString("utf8"));
    expect(decoded).toBe(CLEAN_SUBJECT);
  });

  it("never lets smuggled CR/LF become a header line", () => {
    const out = repairRfc822Text(
      composedPrefix(`=?UTF-8?B?${Buffer.from("hi\r\nBcc: evil@x.com", "utf8").toString("base64")}?=`),
    )!;
    const header = out.slice(0, out.indexOf("\r\n\r\n"));
    expect(header).not.toMatch(/^Bcc:/im);
  });
});
