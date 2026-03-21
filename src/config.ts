function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Required environment variable ${name} is not set`);
  }
  return value;
}

function parseIntSafe(value: string, name: string): number {
  const trimmed = value.trim();
  const n = Number(trimmed);
  if (!Number.isInteger(n)) {
    throw new Error(`Environment variable ${name} must be a valid integer, got: "${value}"`);
  }
  return n;
}

export const config = {
  // Elasticsearch
  esAddresses: requireEnv("ES_ADDRESSES").split(",").map((a) => a.trim()).filter(Boolean),
  esTimeout: parseIntSafe(process.env.ES_TIMEOUT ?? "30000", "ES_TIMEOUT"),
  esMaxRetries: parseIntSafe(process.env.ES_MAX_RETRIES ?? "3", "ES_MAX_RETRIES"),

  // Server
  port: parseIntSafe(process.env.PORT ?? "8080", "PORT"),
  maxSessions: parseIntSafe(process.env.MAX_SESSIONS ?? "1000", "MAX_SESSIONS"),
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
