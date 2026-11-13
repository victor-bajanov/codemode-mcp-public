// Unit tests for the deploy-time calendar write allow-list
// (CALENDAR_WRITE_ALLOWLIST): which calendars the agent may write events to.
// Fail closed: unset/blank means an empty list, and an empty list matches
// nothing, so every Calendar event write is denied until the operator lists
// `primary` (or an owned calendar id) explicitly.

import { describe, it, expect } from "vitest";
import {
  CALENDAR_WRITE_ALLOWLIST_VAR,
  calendarWriteAllowlistFromEnv,
  isAllowedCalendar,
} from "../inspectors/calendar-allowlist";

const env = (raw: unknown) => ({ [CALENDAR_WRITE_ALLOWLIST_VAR]: raw });

describe("calendarWriteAllowlistFromEnv", () => {
  it("names the wrangler var", () => {
    expect(CALENDAR_WRITE_ALLOWLIST_VAR).toBe("CALENDAR_WRITE_ALLOWLIST");
  });

  it.each([
    ["no env", undefined],
    ["var unset", {}],
    ["empty string", env("")],
    ["blank string", env("   ")],
    ["only commas and spaces", env(" , ,, ")],
    ["number", env(1)],
    ["array", env(["primary"])],
    ["null", env(null)],
  ])("returns an empty list when the var is missing or not a usable string (%s)", (_label, e) => {
    expect(calendarWriteAllowlistFromEnv(e as Readonly<Record<string, unknown>> | undefined)).toEqual([]);
  });

  it("splits on commas, trims and lower-cases each entry", () => {
    expect(
      calendarWriteAllowlistFromEnv(
        env(" primary , Owner@Example.com,C_ABC123@group.calendar.google.com ,"),
      ),
    ).toEqual(["primary", "owner@example.com", "c_abc123@group.calendar.google.com"]);
  });

  it("accepts `PRIMARY` in any case as the literal primary", () => {
    expect(calendarWriteAllowlistFromEnv(env("Primary"))).toEqual(["primary"]);
  });

  it("returns a frozen list", () => {
    const list = calendarWriteAllowlistFromEnv(env("primary,frozen@example.com"));
    expect(Object.isFrozen(list)).toBe(true);
  });

  it("memoises on the raw string and re-parses when it changes", () => {
    const a = calendarWriteAllowlistFromEnv(env("primary,memo@example.com"));
    const b = calendarWriteAllowlistFromEnv(env("primary,memo@example.com"));
    expect(b).toBe(a);
    const c = calendarWriteAllowlistFromEnv(env("other@example.com"));
    expect(c).toEqual(["other@example.com"]);
    // A later bad value still throws even after a good one was cached.
    expect(() => calendarWriteAllowlistFromEnv(env("primary,bad entry"))).toThrow();
    expect(calendarWriteAllowlistFromEnv(env("primary,memo@example.com"))).toEqual([
      "primary",
      "memo@example.com",
    ]);
  });

  it.each([
    ["bare word other than primary", "secondary"],
    ["no @", "example.com"],
    ["empty local part", "@example.com"],
    ["empty domain", "owner@"],
    ["two @", "a@b@example.com"],
    ["inner whitespace", "own er@example.com"],
    ["angle brackets", "<owner@example.com>"],
    ["display name", "Owner <owner@example.com>"],
    ["quoted local part", '"owner"@example.com'],
    ["semicolon", "owner;x@example.com"],
    ["wildcard local part", "*@example.com"],
    ["control character", "owner\u0000@example.com"],
    ["Kelvin sign (non-ASCII folding to k)", "\u212Aim@x.com"],
    ["non-ASCII local part", "\u00f6wner@example.com"],
    ["dotted capital I in primary", "pr\u0130mary"],
  ])("throws on a malformed entry (%s), naming the var", (_label, entry) => {
    expect(() => calendarWriteAllowlistFromEnv(env(`primary,${entry}`))).toThrow(
      /CALENDAR_WRITE_ALLOWLIST/,
    );
  });
});

describe("isAllowedCalendar", () => {
  const LIST = ["primary", "owner@example.com", "c_abc123@group.calendar.google.com"];

  it("matches an entry exactly after lower-casing the calendar id", () => {
    expect(isAllowedCalendar("primary", LIST)).toBe(true);
    expect(isAllowedCalendar("PRIMARY", LIST)).toBe(true);
    expect(isAllowedCalendar("Owner@Example.com", LIST)).toBe(true);
    expect(isAllowedCalendar("c_ABC123@group.calendar.google.com", LIST)).toBe(true);
  });

  it("does not widen: no domain wildcarding, no plus-address, no substring", () => {
    expect(isAllowedCalendar("other@example.com", LIST)).toBe(false);
    expect(isAllowedCalendar("owner+tag@example.com", LIST)).toBe(false);
    expect(isAllowedCalendar("primaryx", LIST)).toBe(false);
    expect(isAllowedCalendar("owner@example.com.evil", LIST)).toBe(false);
    expect(isAllowedCalendar("", LIST)).toBe(false);
  });

  it("denies an id with edge whitespace instead of trimming it (the path would carry it)", () => {
    expect(isAllowedCalendar(" primary", LIST)).toBe(false);
    expect(isAllowedCalendar("primary ", LIST)).toBe(false);
    expect(isAllowedCalendar("\tprimary", LIST)).toBe(false);
    expect(isAllowedCalendar("owner@example.com\n", LIST)).toBe(false);
  });

  it("denies an id with characters outside printable ASCII before lower-casing", () => {
    // U+212A KELVIN SIGN lower-cases to ASCII "k" under toLowerCase().
    expect(isAllowedCalendar("\u212Aim@x.com", ["kim@x.com"])).toBe(false);
    expect(isAllowedCalendar("pr\u0130mary", LIST)).toBe(false);
    expect(isAllowedCalendar("owner@exam\u00a0ple.com", LIST)).toBe(false);
    expect(isAllowedCalendar("prim ary", LIST)).toBe(false);
  });

  it("an empty list matches nothing, not even primary", () => {
    expect(isAllowedCalendar("primary", [])).toBe(false);
    expect(isAllowedCalendar("owner@example.com", [])).toBe(false);
  });

  it("a non-string calendar id is never allowed", () => {
    expect(isAllowedCalendar(undefined as unknown as string, LIST)).toBe(false);
    expect(isAllowedCalendar(42 as unknown as string, LIST)).toBe(false);
  });
});
