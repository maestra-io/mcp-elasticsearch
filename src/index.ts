#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID } from "node:crypto";
import express from "express";
import { config } from "./config.js";
import { timingSafeEqual } from "node:crypto";
import { mountOAuthRoutes, validateOAuthToken } from "./oauth.js";
import { ElasticsearchClient } from "./elasticsearch.js";
import { registerTools } from "./tools.js";

const app = express();
app.use(express.json({ limit: config.bodyLimit }));
app.use(express.urlencoded({ extended: false }));

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  const { method, path } = req;
  const auth = req.headers.authorization;
  const authType = auth ? auth.split(" ")[0] : "none";
  const sessionId = req.headers["mcp-session-id"] ?? "-";

  res.on("finish", () => {
    const duration = Date.now() - start;
    console.log(`${method} ${path} ${res.statusCode} ${duration}ms auth=${authType} session=${sessionId}`);
  });
  next();
});

// Mount OAuth discovery + flow routes (before auth middleware)
if (config.googleClientId) {
  mountOAuthRoutes(app);
}

// Auth middleware: Bearer token validation (static API tokens + OAuth tokens)
app.use("/mcp", (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    console.warn(`Auth rejected: missing or non-Bearer auth header (got: ${auth ? auth.split(" ")[0] : "none"})`);
    res.status(401).json({ error: "Bearer token required" });
    return;
  }

  const token = auth.slice(7);

  // Check static API tokens
  if (config.apiTokens.some((t) => safeEqual(token, t))) {
    next();
    return;
  }

  // Check OAuth-issued tokens
  const email = validateOAuthToken(token);
  if (email) {
    console.log(`Auth: OAuth token for ${email}`);
    next();
    return;
  }

  console.warn(`Auth rejected: invalid token (length=${token.length}, prefix=${token.slice(0, 4)}...)`);
  res.status(401).json({ error: "Invalid token" });
});

function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

const esClient = new ElasticsearchClient();

function createServer(): McpServer {
  const server = new McpServer({
    name: "mcp-elasticsearch",
    version: "1.0.0",
  });
  registerTools(server, esClient);
  return server;
}

// Stateful sessions: each client gets its own server+transport pair.
const SESSION_TTL_MS = 30 * 60 * 1000;
const sessions = new Map<string, {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  lastAccess: number;
}>();

// Cleanup expired sessions every 5 minutes
const cleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.lastAccess > SESSION_TTL_MS) {
      session.transport.close().catch(() => {});
      session.server.close().catch(() => {});
      sessions.delete(id);
    }
  }
}, 5 * 60 * 1000);
cleanupInterval.unref();

/** Wrap async route handlers to forward errors to Express error handler. */
function asyncHandler(fn: (req: express.Request, res: express.Response) => Promise<void>) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    fn(req, res).catch(next);
  };
}

app.post("/mcp", asyncHandler(async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  // Existing session
  if (sessionId && sessions.has(sessionId)) {
    const session = sessions.get(sessionId)!;
    session.lastAccess = Date.now();
    await session.transport.handleRequest(req, res, req.body);
    return;
  }

  // Reject non-init requests without valid session
  if (sessionId && !sessions.has(sessionId)) {
    res.status(404).json({ error: "Session not found" });
    return;
  }

  // Enforce session limit
  if (sessions.size >= config.maxSessions) {
    res.status(503).json({ error: "Too many active sessions" });
    return;
  }

  // New session
  const newSessionId = randomUUID();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => newSessionId,
  });
  const server = createServer();

  transport.onclose = () => {
    sessions.delete(newSessionId);
  };

  try {
    await server.connect(transport);
    sessions.set(newSessionId, {
      transport,
      server,
      lastAccess: Date.now(),
    });
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    sessions.delete(newSessionId);
    transport.close().catch(() => {});
    server.close().catch(() => {});
    throw error;
  }
}));

app.get("/mcp", asyncHandler(async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId) {
    res.status(400).json({ error: "Missing session ID" });
    return;
  }
  if (!sessions.has(sessionId)) {
    res.status(404).json({ error: "Session not found or expired" });
    return;
  }
  const session = sessions.get(sessionId)!;
  session.lastAccess = Date.now();
  await session.transport.handleRequest(req, res);
}));

app.delete("/mcp", asyncHandler(async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (sessionId && sessions.has(sessionId)) {
    const session = sessions.get(sessionId)!;
    await session.transport.close();
    session.server.close().catch(() => {});
    sessions.delete(sessionId);
  }
  res.status(200).end();
}));

app.get("/healthz", (_req, res) => {
  res.status(200).json({ status: "ok", sessions: sessions.size });
});

const port = config.port;
const server = app.listen(port, () => {
  console.log(`Elasticsearch MCP server listening on port ${port}`);
});

// Graceful shutdown
function shutdown(signal: string) {
  console.log(`Received ${signal}, shutting down gracefully...`);
  clearInterval(cleanupInterval);

  for (const [id, session] of sessions) {
    session.transport.close().catch(() => {});
    session.server.close().catch(() => {});
    sessions.delete(id);
  }

  server.close(() => {
    console.log("HTTP server closed.");
    process.exit(0);
  });

  setTimeout(() => {
    console.error("Graceful shutdown timed out, forcing exit.");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
