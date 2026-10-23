// Shape validation for the host-assembled `composed` body channel (plan §2,
// D5/D6). Every rule returns a stable `reason` and a message that never
// echoes a token, a handle or text content.

import { describe, it, expect } from "vitest";
import { validateComposed, COMPOSED_MAX_SEGMENTS, COMPOSED_MAX_TEXT_BYTES } from "../compose/validate";
import { mintFileHandle, mintToken } from "../staging/tokens";

const REF = { file_handle: mintFileHandle(), token: mintToken() };

function staged(encoding: string, ref: unknown = REF) {
  return { staged: ref, encoding };
}

function expectReason(r: ReturnType<typeof validateComposed>, reason: string) {
  expect(r.ok).toBe(false);
  if (r.ok) return;
  expect(r.reason).toBe(reason);
  expect(r.message).not.toContain(REF.token);
  expect(r.message).not.toContain(REF.file_handle);
}

describe("validateComposed — accepted shapes", () => {
  it("text + staged(base64-lines) + text → segments in order, text as UTF-8 bytes", () => {
    const r = validateComposed({
      composed: { segments: [{ text: "Subject: é\r\n\r\n" }, staged("base64-lines"), { text: "--b1--\r\n" }] },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.segments).toHaveLength(3);
    const [a, b, c] = r.segments;
    expect(a).toEqual({ kind: "text", bytes: new TextEncoder().encode("Subject: é\r\n\r\n") });
    expect(b).toEqual({ kind: "staged", ref: REF, encoding: "base64-lines", index: 1 });
    expect(c!.kind).toBe("text");
  });

  it("a sole identity segment is accepted", () => {
    const r = validateComposed({ composed: { segments: [staged("identity")] } });
    expect(r.ok).toBe(true);
  });

  it("plain base64 among text is accepted; the same file twice is two segments", () => {
    const r = validateComposed({ composed: { segments: [staged("base64"), { text: "x" }, staged("base64")] } });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.segments.filter((s) => s.kind === "staged")).toHaveLength(2);
  });

  it("copies the ref (a later mutation of the input does not change the segment)", () => {
    const ref = { ...REF };
    const r = validateComposed({ composed: { segments: [{ staged: ref, encoding: "identity" }] } });
    ref.token = "changed";
    expect(r.ok && r.segments[0]!.kind === "staged" && r.segments[0]!.ref.token).toBe(REF.token);
  });
});

describe("validateComposed — malformed", () => {
  const bad: Array<[string, unknown]> = [
    ["composed null", null],
    ["composed array", []],
    ["composed string", "x"],
    ["segments missing", {}],
    ["segments not array", { segments: {} }],
    ["segments empty", { segments: [] }],
    ["extra key on composed", { segments: [{ text: "a" }], extra: 1 }],
    ["__proto__ own key on composed", JSON.parse('{"segments":[{"text":"a"}],"__proto__":{"x":1}}')],
    ["segment null", { segments: [null] }],
    ["segment array", { segments: [["text"]] }],
    ["segment with both text and staged", { segments: [{ text: "a", staged: REF, encoding: "base64" }] }],
    ["segment with neither", { segments: [{ encoding: "base64" }] }],
    ["text not a string", { segments: [{ text: 5 }] }],
    ["text segment with an extra key", { segments: [{ text: "a", encoding: "base64" }] }],
    ["staged without encoding", { segments: [{ staged: REF }] }],
    ["staged with extra key", { segments: [{ staged: REF, encoding: "base64", x: 1 }] }],
    ["unknown encoding", { segments: [staged("quoted-printable")] }],
    ["encoding not a string", { segments: [staged(7 as unknown as string)] }],
    ["staged ref not an object", { segments: [staged("base64", "fh_x")] }],
    ["staged ref an array", { segments: [staged("base64", [REF.file_handle, REF.token])] }],
    ["staged ref missing token", { segments: [staged("base64", { file_handle: REF.file_handle })] }],
    ["staged ref with extra key", { segments: [staged("base64", { ...REF, x: 1 })] }],
    ["staged ref wrong prefixes", { segments: [staged("base64", { file_handle: REF.token, token: REF.file_handle })] }],
    ["staged ref short handle", { segments: [staged("base64", { file_handle: "fh_abc", token: REF.token })] }],
    ["segment with a prototype other than Object", { segments: [Object.create({ text: "a" })] }],
    ["__proto__ own key on a segment", { segments: [JSON.parse('{"text":"a","__proto__":{}}')] }],
  ];
  for (const [name, composed] of bad) {
    it(`${name} → composed-malformed`, () => {
      expectReason(validateComposed({ composed }), "composed-malformed");
    });
  }

  it(`more than ${COMPOSED_MAX_SEGMENTS} segments → composed-malformed`, () => {
    const segments = Array.from({ length: COMPOSED_MAX_SEGMENTS + 1 }, () => ({ text: "a" }));
    expectReason(validateComposed({ composed: { segments } }), "composed-malformed");
    const ok = validateComposed({ composed: { segments: segments.slice(1) } });
    expect(ok.ok).toBe(true);
  });

  it("total text over the cap → composed-malformed (counted in UTF-8 bytes)", () => {
    const half = "a".repeat(COMPOSED_MAX_TEXT_BYTES / 2);
    expect(validateComposed({ composed: { segments: [{ text: half }, { text: half }] } }).ok).toBe(true);
    expectReason(
      validateComposed({ composed: { segments: [{ text: half }, { text: half + "a" }] } }),
      "composed-malformed",
    );
    // 2-byte characters: under the cap in UTF-16 units, over it in bytes.
    const wide = "é".repeat(COMPOSED_MAX_TEXT_BYTES / 2 + 1);
    expectReason(validateComposed({ composed: { segments: [{ text: wide }] } }), "composed-malformed");
  });

  it("U+FFFC in text → composed-text-reserved-char (literal and JSON-escaped)", () => {
    expectReason(validateComposed({ composed: { segments: [{ text: "a￼b" }] } }), "composed-text-reserved-char");
    const parsed = JSON.parse('{"segments":[{"text":"a\\ufffcb"}]}');
    expectReason(validateComposed({ composed: parsed }), "composed-text-reserved-char");
  });

  it("a lone surrogate in text → composed-text-not-well-formed", () => {
    expectReason(validateComposed({ composed: { segments: [{ text: "a\uD800b" }] } }), "composed-text-not-well-formed");
    expectReason(validateComposed({ composed: { segments: [{ text: "\uDC00" }] } }), "composed-text-not-well-formed");
    expect(validateComposed({ composed: { segments: [{ text: "😀" }] } }).ok).toBe(true);
  });

  it("identity with any other segment → composed-identity-not-sole", () => {
    expectReason(
      validateComposed({ composed: { segments: [{ text: "a" }, staged("identity")] } }),
      "composed-identity-not-sole",
    );
    expectReason(
      validateComposed({ composed: { segments: [staged("identity"), staged("identity")] } }),
      "composed-identity-not-sole",
    );
  });
});

describe("validateComposed — exclusivity", () => {
  const segs = { segments: [{ text: "a" }] };
  for (const [name, extra] of [
    ["body", { body: { a: 1 } }],
    ["body string", { body: "x" }],
    ["bodyBase64", { bodyBase64: "AAAA" }],
    ["rawBody", { rawBody: true }],
    ["rawBody false", { rawBody: false }],
    ["multipart", { multipart: [] }],
  ] as const) {
    it(`composed + ${name} → multiple-body-channels`, () => {
      expectReason(validateComposed({ composed: segs, ...extra }), "multiple-body-channels");
    });
  }

  it("body: null alongside composed is treated as absent", () => {
    expect(validateComposed({ composed: segs, body: null }).ok).toBe(true);
  });
});
