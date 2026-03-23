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
    `Execute an Elasticsearch search query using the full Search API body.
Pass the complete request body as you would to POST /<index>/_search.
Supports query, aggs, size, from, sort, _source, highlight, track_total_hits, and all other Search API parameters.
The index parameter is optional — omit it to search across all indices.`,
    {
      index: z.string().optional().describe("Index name or pattern to search (optional, searches all if omitted). Supports comma-separated names and wildcards."),
      body: z.record(z.unknown()).describe("Full Elasticsearch Search API request body. Supports all fields: query, aggs, size, from, sort, _source, highlight, track_total_hits, etc."),
    },
    async (params) => {
      try {
        const body = { ...params.body };
        if (body.size !== undefined && (body.size as number) > 500) {
          body.size = 500;
        }
        if (body.size === undefined) {
          body.size = 10;
        }
        if (!body.query) body.query = { match_all: {} };
        const result = await esClient.search(params.index, body);
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
