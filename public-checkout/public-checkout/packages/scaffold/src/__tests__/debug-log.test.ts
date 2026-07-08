import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { debugLog } from "../config";

describe("debugLog", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it("DEBUG_ELICIT absent -> console.log not called", () => {
    debugLog({}, "wrap-pre", { method: "POST", path: "/x" }, { containsPii: true });
    debugLog({}, "elicit-branch", { operationId: "op" }, { containsPii: false });
    expect(logSpy).not.toHaveBeenCalled();
  });

  it("DEBUG_ELICIT=true, containsPii=false -> full payload logged", () => {
    debugLog(
      { DEBUG_ELICIT: "true" },
      "elicit-branch",
      { operationId: "op", decision: "elicit" },
      { containsPii: false },
    );
    expect(logSpy).toHaveBeenCalledTimes(1);
    const arg = logSpy.mock.calls[0]![0] as string;
    expect(arg.startsWith("DEBUG-ELICIT ")).toBe(true);
    const json = JSON.parse(arg.slice("DEBUG-ELICIT ".length));
    expect(json.stage).toBe("elicit-branch");
    expect(json.operationId).toBe("op");
    expect(json.decision).toBe("elicit");
    expect(typeof json.ts).toBe("string");
  });

  it("DEBUG_ELICIT=true, containsPii=true, ALLOW_PII_IN_LOGS=false -> redaction marker line", () => {
    debugLog(
      { DEBUG_ELICIT: "true", ALLOW_PII_IN_LOGS: "false" },
      "wrap-pre",
      { method: "POST", path: "/secret" },
      { containsPii: true },
    );
    expect(logSpy).toHaveBeenCalledTimes(1);
    const arg = logSpy.mock.calls[0]![0] as string;
    expect(arg).toBe(
      "DEBUG-ELICIT wrap-pre <REDACTED: ALLOW_PII_IN_LOGS=false required to log this site>",
    );
  });

  it("DEBUG_ELICIT=true, containsPii=true, ALLOW_PII_IN_LOGS=true -> full payload logged", () => {
    debugLog(
      { DEBUG_ELICIT: "true", ALLOW_PII_IN_LOGS: "true" },
      "wrap-pre",
      { method: "POST", path: "/secret" },
      { containsPii: true },
    );
    expect(logSpy).toHaveBeenCalledTimes(1);
    const arg = logSpy.mock.calls[0]![0] as string;
    expect(arg.startsWith("DEBUG-ELICIT ")).toBe(true);
    const json = JSON.parse(arg.slice("DEBUG-ELICIT ".length));
    expect(json.stage).toBe("wrap-pre");
    expect(json.method).toBe("POST");
    expect(json.path).toBe("/secret");
    expect(typeof json.ts).toBe("string");
  });
});
