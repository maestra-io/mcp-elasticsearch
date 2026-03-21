import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("./config.js", () => ({
  config: {
    esAddresses: ["http://es-host-1:9200", "http://es-host-2:9200", "http://es-host-3:9200"],
    esTimeout: 5000,
    esMaxRetries: 2,
    port: 8080,
    maxSessions: 1000,
    bodyLimit: "1mb",
    apiTokens: ["token1"],
    publicUrl: "https://mta-logs-elasticsearch-mcp.maestra.io",
    googleClientId: "",
    googleClientSecret: "",
  },
}));

const { ElasticsearchClient } = await import("./elasticsearch.js");

describe("ElasticsearchClient", () => {
  let client: InstanceType<typeof ElasticsearchClient>;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    client = new ElasticsearchClient();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function mockFetchOk(body: unknown) {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => body,
    });
  }

  function mockFetchError(status: number, body: unknown) {
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status,
      json: async () => body,
    });
  }

  describe("info", () => {
    it("returns cluster info", async () => {
      const expected = { name: "node-1", cluster_name: "es-cluster", version: { number: "7.10.2" } };
      mockFetchOk(expected);

      const result = await client.info();
      expect(result).toEqual(expected);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls[0][0]).toMatch(/\/$/);
    });
  });

  describe("clusterHealth", () => {
    it("returns cluster health", async () => {
      const expected = { cluster_name: "es-cluster", status: "green", number_of_nodes: 3 };
      mockFetchOk(expected);

      const result = await client.clusterHealth();
      expect(result).toEqual(expected);
      expect(fetchMock.mock.calls[0][0]).toMatch(/\/_cluster\/health$/);
    });
  });

  describe("listIndices", () => {
    it("returns indices list", async () => {
      const expected = [
        { index: "logs-2024", health: "green", "docs.count": "1000" },
        { index: "logs-2025", health: "yellow", "docs.count": "500" },
      ];
      mockFetchOk(expected);

      const result = await client.listIndices();
      expect(result).toEqual(expected);
      expect(fetchMock.mock.calls[0][0]).toMatch(/\/_cat\/indices\?format=json$/);
    });
  });

  describe("search", () => {
    it("sends search request with index", async () => {
      const expected = { hits: { total: { value: 1 }, hits: [{ _source: { msg: "hello" } }] } };
      mockFetchOk(expected);

      const result = await client.search("my-index", { match: { msg: "hello" } }, 10, 0);
      expect(result).toEqual(expected);
      expect(fetchMock.mock.calls[0][0]).toContain("/my-index/_search");
      expect(fetchMock.mock.calls[0][0]).toContain("size=10");
      expect(fetchMock.mock.calls[0][0]).toContain("from=0");
    });

    it("sends search request without index", async () => {
      mockFetchOk({ hits: { total: { value: 0 }, hits: [] } });

      await client.search(undefined, { match_all: {} }, 5, 0);
      expect(fetchMock.mock.calls[0][0]).toContain("/_search?size=5&from=0");
      expect(fetchMock.mock.calls[0][0]).not.toContain("/undefined/");
    });

    it("includes sort and _source in body", async () => {
      mockFetchOk({ hits: { total: { value: 0 }, hits: [] } });

      await client.search("idx", { match_all: {} }, 10, 0, [{ "@timestamp": "desc" }], ["field1"]);

      const body = JSON.parse(fetchMock.mock.calls[0][1].body);
      expect(body.sort).toEqual([{ "@timestamp": "desc" }]);
      expect(body._source).toEqual(["field1"]);
    });
  });

  describe("round-robin", () => {
    it("cycles through addresses", async () => {
      mockFetchOk({ name: "node-1" });
      mockFetchOk({ name: "node-2" });
      mockFetchOk({ name: "node-3" });
      mockFetchOk({ name: "node-1" });

      await client.info();
      await client.info();
      await client.info();
      await client.info();

      expect(fetchMock.mock.calls[0][0]).toContain("es-host-1");
      expect(fetchMock.mock.calls[1][0]).toContain("es-host-2");
      expect(fetchMock.mock.calls[2][0]).toContain("es-host-3");
      expect(fetchMock.mock.calls[3][0]).toContain("es-host-1");
    });
  });

  describe("retry", () => {
    it("retries on 503 and succeeds", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: async () => ({ error: "unavailable" }),
      });
      mockFetchOk({ name: "node-2" });

      const result = await client.info();
      expect(result).toEqual({ name: "node-2" });
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    it("throws after exhausting retries on 503", async () => {
      for (let i = 0; i <= 2; i++) {
        fetchMock.mockResolvedValueOnce({
          ok: false,
          status: 503,
          json: async () => ({ error: "unavailable" }),
        });
      }

      await expect(client.info()).rejects.toThrow("ES returned 503 after 3 attempts");
    });

    it("throws immediately on non-retryable error status", async () => {
      mockFetchError(400, { error: { type: "parsing_exception", reason: "bad query" } });

      await expect(client.search("idx", { bad: "query" }, 10, 0)).rejects.toThrow("Elasticsearch error (400)");
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("error handling", () => {
    it("throws on network error after retries", async () => {
      fetchMock.mockRejectedValue(new Error("ECONNREFUSED"));

      await expect(client.info()).rejects.toThrow("ECONNREFUSED");
    });
  });
});
