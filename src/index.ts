#!/usr/bin/env node
import { startMcpServer } from "@maestra-io/mcp-framework";
import { config } from "./config.js";
import { ElasticsearchClient } from "./elasticsearch.js";
import { registerTools } from "./tools.js";

const esClient = new ElasticsearchClient();

startMcpServer({
  name: "mcp-elasticsearch",
  version: "1.0.0",
  config,
  setupServer: (server) => registerTools(server, esClient),
});
