import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { ElasticsearchClient } from "./elasticsearch.js";

export function registerTools(server: McpServer, esClient: ElasticsearchClient): void {
  server.tool(
    "es_cluster_info",
    "Get Elasticsearch cluster information including version, name, and tagline",
    {},
    async () => {
      try {
        const info = await esClient.info();
        return {
          content: [{ type: "text" as const, text: JSON.stringify(info, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Failed to get cluster info: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "es_cluster_health",
    "Get Elasticsearch cluster health status, number of nodes, shards, and indices",
    {},
    async () => {
      try {
        const health = await esClient.clusterHealth();
        return {
          content: [{ type: "text" as const, text: JSON.stringify(health, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Failed to get cluster health: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "es_index_list",
    "List all Elasticsearch indices with their health, status, document count, and storage size",
    {},
    async () => {
      try {
        const indices = await esClient.listIndices();
        return {
          content: [{ type: "text" as const, text: JSON.stringify(indices, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Failed to list indices: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "es_search",
    `Execute an Elasticsearch search query using Query DSL.
Supports full Query DSL (match, bool, range, term, etc.), pagination, sorting, and source filtering.
The index parameter is optional — omit it to search across all indices.`,
    {
      index: z.string().optional().describe("Index name to search (optional, searches all if omitted)"),
      query: z.record(z.unknown()).optional().describe("Elasticsearch Query DSL object (e.g. {\"match\": {\"message\": \"error\"}}). Defaults to match_all"),
      size: z.number().min(0).max(10000).default(10).describe("Number of results to return (default: 10)"),
      from: z.number().min(0).default(0).describe("Offset for pagination (default: 0)"),
      sort: z.array(z.record(z.unknown())).optional().describe("Sort specification (array of sort objects, e.g. [{\"@timestamp\": \"desc\"}])"),
      _source: z.union([
        z.boolean(),
        z.array(z.string()),
        z.record(z.unknown()),
      ]).optional().describe("Source filtering: boolean, array of field names, or object with includes/excludes"),
    },
    async (params) => {
      try {
        const query = params.query ?? { match_all: {} };
        const result = await esClient.search(params.index, query, params.size, params.from, params.sort, params._source);
        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Search failed: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}
