function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Required environment variable ${name} is not set`);
  }
  return value;
}

function parseIntSafe(raw: string | undefined, fallback: number, min = 0): number {
  if (!raw) return fallback;
  const trimmed = raw.trim();
  if (trimmed === "") return fallback;
  const n = Number(trimmed);
  if (!Number.isInteger(n) || n < min) {
    throw new Error(`Invalid integer value: "${raw}" (min: ${min})`);
  }
  return n;
}

export const config = {
  // Elasticsearch
  esAddresses: requireEnv("ES_ADDRESSES").split(",").map((a) => a.trim()).filter(Boolean),
  esTimeout: parseIntSafe(process.env.ES_TIMEOUT, 30000),
  esMaxRetries: parseIntSafe(process.env.ES_MAX_RETRIES, 3),

  // Server
  port: parseIntSafe(process.env.PORT, 8080, 1),
  maxSessions: parseIntSafe(process.env.MAX_SESSIONS, 1000, 1),
  bodyLimit: process.env.BODY_LIMIT ?? "1mb",

  // Auth
  apiTokens: requireEnv("API_TOKENS").split(",").map((t) => t.trim()).filter(Boolean),

  // OAuth (Google)
  publicUrl: process.env.PUBLIC_URL ?? "https://mta-logs-elasticsearch-mcp.maestra.io",
  googleClientId: process.env.GOOGLE_CLIENT_ID ?? "",
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET ?? "",
} as const;

if (config.googleClientId && !config.googleClientSecret) {
  throw new Error("GOOGLE_CLIENT_SECRET is required when GOOGLE_CLIENT_ID is set");
}
