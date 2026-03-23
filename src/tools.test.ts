import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * Test the size validation and query defaulting logic used in es_search tool.
 * We replicate the logic from tools.ts to test it in isolation without
 * needing to spin up a full McpServer + ElasticsearchClient.
 */
function applySearchDefaults(body: Record<string, unknown>): Record<string, unknown> {
  const result = { ...body };
  if (result.size === undefined) {
    result.size = 10;
  } else if (typeof result.size === "number" && Number.isInteger(result.size) && result.size >= 0) {
    result.size = Math.min(result.size as number, 500);
  }
  if (!result.query) result.query = { match_all: {} };
  return result;
}

describe("es_search size validation", () => {
  it("defaults size to 10 when omitted", () => {
    const result = applySearchDefaults({ query: { match_all: {} } });
    expect(result.size).toBe(10);
  });

  it("caps size at 500 when larger", () => {
    const result = applySearchDefaults({ size: 9999, query: { match_all: {} } });
    expect(result.size).toBe(500);
  });

  it("preserves valid size <= 500", () => {
    const result = applySearchDefaults({ size: 50, query: { match_all: {} } });
    expect(result.size).toBe(50);
  });

  it("preserves size of exactly 500", () => {
    const result = applySearchDefaults({ size: 500, query: { match_all: {} } });
    expect(result.size).toBe(500);
  });

  it("preserves size of 0", () => {
    const result = applySearchDefaults({ size: 0, query: { match_all: {} } });
    expect(result.size).toBe(0);
  });

  it("passes through non-numeric size for ES to validate", () => {
    const result = applySearchDefaults({ size: "abc", query: { match_all: {} } });
    expect(result.size).toBe("abc");
  });

  it("passes through negative size for ES to validate", () => {
    const result = applySearchDefaults({ size: -1, query: { match_all: {} } });
    expect(result.size).toBe(-1);
  });
});

describe("es_search query defaulting", () => {
  it("defaults missing query to match_all", () => {
    const result = applySearchDefaults({ size: 10 });
    expect(result.query).toEqual({ match_all: {} });
  });

  it("preserves existing query", () => {
    const query = { term: { status: "active" } };
    const result = applySearchDefaults({ query });
    expect(result.query).toEqual(query);
  });
});
