import { requireEnv, parseIntSafe, parseServerConfig } from "@maestra-io/mcp-framework";

export const config = {
  ...parseServerConfig({ publicUrl: "https://mta-logs-elasticsearch-mcp.maestra.io" }),

  // Elasticsearch
  esAddresses: requireEnv("ES_ADDRESSES").split(",").map((a) => a.trim()).filter(Boolean),
  esTimeout: parseIntSafe(process.env.ES_TIMEOUT, 30000),
  esMaxRetries: parseIntSafe(process.env.ES_MAX_RETRIES, 3),
} as const;
