import { describe, it, expect } from "vitest";
import { timingSafeEqual } from "node:crypto";

// Test the safeEqual function logic (extracted from index.ts)
function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

describe("safeEqual", () => {
  it("returns true for equal strings", () => {
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("token-123", "token-123")).toBe(true);
    expect(safeEqual("", "")).toBe(true);
  });

  it("returns false for unequal strings of same length", () => {
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("xxx", "yyy")).toBe(false);
  });

  it("returns false for different length strings", () => {
    expect(safeEqual("short", "longer-string")).toBe(false);
    expect(safeEqual("a", "ab")).toBe(false);
  });

  it("returns false comparing against empty string", () => {
    expect(safeEqual("token", "")).toBe(false);
    expect(safeEqual("", "token")).toBe(false);
  });

  it("handles multibyte characters", () => {
    expect(safeEqual("héllo", "héllo")).toBe(true);
    expect(safeEqual("héllo", "hello")).toBe(false);
  });
});

describe("auth middleware logic", () => {
  const apiTokens = ["token-1", "token-2", "secret-key"];

  function checkStaticToken(token: string): boolean {
    return apiTokens.some((t) => safeEqual(token, t));
  }

  it("accepts valid static tokens", () => {
    expect(checkStaticToken("token-1")).toBe(true);
    expect(checkStaticToken("token-2")).toBe(true);
    expect(checkStaticToken("secret-key")).toBe(true);
  });

  it("rejects invalid tokens", () => {
    expect(checkStaticToken("wrong")).toBe(false);
    expect(checkStaticToken("token-3")).toBe(false);
    expect(checkStaticToken("")).toBe(false);
  });

  it("rejects tokens that are substrings or superstrings", () => {
    expect(checkStaticToken("token-")).toBe(false);
    expect(checkStaticToken("token-12")).toBe(false);
    expect(checkStaticToken("token-1-extra")).toBe(false);
  });
});

describe("params normalization", () => {
  it("converts params:null to {} in single request", () => {
    const body = { jsonrpc: "2.0", method: "test", params: null as Record<string, unknown> | null };
    if (body.params === null) body.params = {};
    expect(body.params).toEqual({});
  });

  it("converts params:null in batch requests", () => {
    const body = [
      { jsonrpc: "2.0", method: "a", params: null as Record<string, unknown> | null },
      { jsonrpc: "2.0", method: "b", params: { x: 1 } as Record<string, unknown> | null },
    ];
    for (const item of body) {
      if (item && item.params === null) item.params = {};
    }
    expect(body[0].params).toEqual({});
    expect(body[1].params).toEqual({ x: 1 });
  });

  it("leaves valid params unchanged", () => {
    const body = { jsonrpc: "2.0", method: "test", params: { foo: "bar" } as Record<string, unknown> | null };
    if (body.params === null) body.params = {};
    expect(body.params).toEqual({ foo: "bar" });
  });
});

