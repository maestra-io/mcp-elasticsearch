import { config } from "./config.js";

export interface ElasticsearchResponse {
  status: number;
  body: unknown;
}

export class ElasticsearchClient {
  private addresses: string[];
  private timeout: number;
  private maxRetries: number;
  private currentIndex = 0;

  constructor(
    addresses: string[] = config.esAddresses,
    timeout: number = config.esTimeout,
    maxRetries: number = config.esMaxRetries,
  ) {
    this.addresses = addresses;
    this.timeout = timeout;
    this.maxRetries = maxRetries;
  }

  private nextAddress(): string {
    const addr = this.addresses[this.currentIndex % this.addresses.length];
    this.currentIndex = (this.currentIndex + 1) % this.addresses.length;
    return addr;
  }

  async request(method: string, path: string, body?: unknown): Promise<unknown> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const address = this.nextAddress();
      const url = `${address}${path}`;

      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        const init: RequestInit = {
          method,
          signal: controller.signal,
          headers: { "Content-Type": "application/json" },
        };

        if (body !== undefined) {
          init.body = JSON.stringify(body);
        }

        const response = await fetch(url, init);
        clearTimeout(timeoutId);

        if ([502, 503, 504, 429].includes(response.status)) {
          if (attempt < this.maxRetries) {
            lastError = new Error(`ES returned ${response.status}`);
            const backoffMs = Math.min(1000 * Math.pow(2, attempt), 10_000) * (0.5 + Math.random() * 0.5);
            await new Promise(resolve => setTimeout(resolve, backoffMs));
            continue;
          }
          throw new Error(`ES returned ${response.status} after ${this.maxRetries + 1} attempts`);
        }

        const responseBody = await response.json();

        if (!response.ok) {
          const errorMsg = typeof responseBody === "object" && responseBody !== null && "error" in responseBody
            ? JSON.stringify((responseBody as Record<string, unknown>).error)
            : JSON.stringify(responseBody);
          throw new Error(`Elasticsearch error (${response.status}): ${errorMsg}`);
        }

        return responseBody;
      } catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
          lastError = new Error(`Request to ${url} timed out after ${this.timeout}ms`);
        } else if (error instanceof Error && error.message.startsWith("Elasticsearch error")) {
          throw error;
        } else {
          lastError = error instanceof Error ? error : new Error(String(error));
        }

        if (attempt >= this.maxRetries) break;
        const backoffMs = Math.min(1000 * Math.pow(2, attempt), 10_000) * (0.5 + Math.random() * 0.5);
        await new Promise(resolve => setTimeout(resolve, backoffMs));
      }
    }

    throw lastError ?? new Error("All retry attempts failed");
  }

  async info(): Promise<unknown> {
    return this.request("GET", "/");
  }

  async clusterHealth(): Promise<unknown> {
    return this.request("GET", "/_cluster/health");
  }

  async listIndices(): Promise<unknown> {
    return this.request("GET", "/_cat/indices?format=json");
  }

  async search(index: string | undefined, body: Record<string, unknown>): Promise<unknown> {
    const path = index ? `/${encodeURIComponent(index)}/_search` : `/_search`;
    return this.request("POST", path, body);
  }
}
