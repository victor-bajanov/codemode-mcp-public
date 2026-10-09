// Unit tests for the shared outbound recipient matcher, in particular the
// addr-spec shape check that runs before any allowlist entry is compared
// (F-18).

import { describe, it, expect } from "vitest";
import { isAllowedRecipient, isPlainAddrSpec } from "../inspectors/allowlist";

const LIST = ["*@allowed.example", "exact@partner.example"];

describe("isAllowedRecipient", () => {
  it("matches wildcard-domain and exact entries case-insensitively", () => {
    expect(isAllowedRecipient("staff@allowed.example", LIST)).toBe(true);
    expect(isAllowedRecipient("  Staff@Allowed.Example  ", LIST)).toBe(true);
    expect(isAllowedRecipient("first.last+tag@allowed.example", LIST)).toBe(true);
    expect(isAllowedRecipient("exact@partner.example", LIST)).toBe(true);
    expect(isAllowedRecipient("o'brien@allowed.example", LIST)).toBe(true);
  });

  it("keeps the existing strictness: no subdomains, no plus-address widening, empty list matches nothing", () => {
    expect(isAllowedRecipient("a@sub.allowed.example", LIST)).toBe(false);
    expect(isAllowedRecipient("exact+tag@partner.example", LIST)).toBe(false);
    expect(isAllowedRecipient("staff@allowed.example", [])).toBe(false);
  });

  it("refuses an address with two '@' even when the trailing domain is allowed (F-18)", () => {
    expect(isAllowedRecipient("outsider@evil.example@allowed.example", LIST)).toBe(false);
    expect(isAllowedRecipient("exact@partner.example@partner.example", LIST)).toBe(false);
  });

  it.each([
    ["empty", ""],
    ["blank", "   "],
    ["no @", "allowed.example"],
    ["empty local part", "@allowed.example"],
    ["empty domain", "staff@"],
    ["inner whitespace", "sta ff@allowed.example"],
    ["tab", "staff\t@allowed.example"],
    ["quoted local part", '"a b"@allowed.example'],
    ["quoted local part without space", '"ab"@allowed.example'],
    ["angle brackets", "<staff@allowed.example>"],
    ["display name", "Staff <staff@allowed.example>"],
    ["comma", "a,b@allowed.example"],
    ["semicolon", "a;b@allowed.example"],
    ["colon (group syntax)", "group:staff@allowed.example"],
    ["parenthesised comment", "staff(comment)@allowed.example"],
    ["domain literal", "staff@[allowed.example]"],
    ["backslash", "st\\aff@allowed.example"],
    ["NUL", "staff\u0000@allowed.example"],
    ["DEL", "staff\u007f@allowed.example"],
    ["embedded newline", "staff@allowed.example\nBcc: x@evil.example"],
  ])("refuses a malformed address (%s)", (_label, address) => {
    expect(isAllowedRecipient(address, LIST)).toBe(false);
  });
});

describe("isPlainAddrSpec", () => {
  it("accepts a plain local@domain and refuses everything with a second @ or forbidden character", () => {
    expect(isPlainAddrSpec("room-101@resource.calendar.google.com")).toBe(true);
    expect(isPlainAddrSpec("a@b@resource.calendar.google.com")).toBe(false);
    expect(isPlainAddrSpec('"x"@resource.calendar.google.com')).toBe(false);
  });
});
