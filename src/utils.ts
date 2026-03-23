import { timingSafeEqual } from "node:crypto";

export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export function normalizeJsonRpcParams(body: unknown): void {
  if (Array.isArray(body)) {
    for (const item of body) {
      if (item && item.params === null) {
        item.params = {};
      }
    }
  } else if (body && typeof body === "object" && (body as any).params === null) {
    (body as any).params = {};
  }
}
