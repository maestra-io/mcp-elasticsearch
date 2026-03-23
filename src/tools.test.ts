import { describe, it, expect } from "vitest";
import { applySearchDefaults } from "./tools.js";

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
