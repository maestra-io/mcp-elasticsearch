# Elasticsearch MCP Server

A read-only MCP (Model Context Protocol) server for Elasticsearch, providing secure access to ES 7.10 clusters via Streamable HTTP transport with Google OAuth + static Bearer token authentication.

## Tools

- `es_cluster_info` — cluster name, version, tagline
- `es_cluster_health` — cluster status, nodes, shards
- `es_index_list` — all indices with health, doc count, storage size
- `es_search` — full Query DSL search with pagination, sorting, source filtering

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ES_ADDRESSES` | yes | — | Comma-separated ES node URLs |
| `API_TOKENS` | yes | — | Comma-separated static Bearer tokens |
| `PORT` | no | `8080` | HTTP listen port |
| `PUBLIC_URL` | no | `https://mta-logs-elasticsearch-mcp.maestra.io` | Public URL for OAuth redirects |
| `GOOGLE_CLIENT_ID` | no | — | Enables Google OAuth when set |
| `GOOGLE_CLIENT_SECRET` | no | — | Required with GOOGLE_CLIENT_ID |
| `ES_TIMEOUT` | no | `30000` | ES request timeout (ms) |
| `ES_MAX_RETRIES` | no | `3` | Max retries on 502/503/504/429 |
| `MAX_SESSIONS` | no | `1000` | Max concurrent MCP sessions |

## Development

```bash
npm install
npm run build
npm run dev    # tsx watch mode
npm test       # vitest
```

## Docker

```bash
docker build -t mcp-elasticsearch .
docker run -e ES_ADDRESSES=http://es:9200 -e API_TOKENS=my-token -p 8080:8080 mcp-elasticsearch
```

## Authentication

1. **Static Bearer tokens** — for programmatic access and Teleport
2. **Google OAuth + PKCE** — for interactive access via Claude Code (restricted to `@maestra.io`)

Auth is handled entirely in the application; no Traefik middleware required.
