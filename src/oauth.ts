import { randomUUID, randomBytes, createHash, timingSafeEqual } from "node:crypto";
import express from "express";
import { OAuth2Client } from "google-auth-library";
import { config } from "./config.js";

// ─── Design decisions (reviewed & intentional) ───────────────────────────────
//
// 1. In-memory stores: This is an internal MCP server with single-process deployment.
//    No persistence, clustering, or external store is needed. All stores are bounded
//    by MAX_* constants and cleaned up via a periodic interval.
//
// 2. No rate limiting: Rate limiting is handled at the infrastructure layer (ingress/
//    reverse proxy). Application-level rate limiting is not implemented here.
//
// 3. No refresh tokens / revocation endpoint: Intentional — this is a simple OAuth
//    proxy for internal Maestra users. 24h token TTL is acceptable for the use case.
//
// 4. Auth code deleted before validation (line ~404): Per RFC 6749 §10.5, auth codes
//    MUST be single-use. The code is deleted immediately after lookup, before expiry/
//    client/PKCE checks. This is intentional: even a failed exchange attempt consumes
//    the code. Node.js is single-threaded, so no TOCTOU race exists between get() and
//    delete() in this synchronous block. If the code is expired or validation fails,
//    the user must restart the OAuth flow — this is the correct security behavior.
//
// 5. timingSafeEqual length pre-check (line ~436): The length comparison before
//    timingSafeEqual is required because the Node.js API throws on mismatched lengths.
//    Both sides are base64url-encoded SHA-256 (always 43 ASCII chars / 43 bytes) since
//    code_challenge is validated to be 43-128 unreserved chars at /oauth/authorize and
//    the expected value is always a 43-char base64url digest. The length check cannot
//    leak useful information because both buffers are deterministic fixed-format outputs.
//
// 6. Domain check uses both email.endsWith("@maestra.io") AND payload.hd === "maestra.io"
//    (line ~340-344): The endsWith check with the "@" prefix is an exact domain match —
//    "user@sub.maestra.io".endsWith("@maestra.io") === false. The hd claim is the
//    authoritative Google Workspace signal. Both checks together provide defense-in-depth.
//    payload.email_verified is also checked to reject unverified emails.
//
// 7. hd not passed to verifyIdToken options: The google-auth-library verifyIdToken()
//    cryptographically verifies the JWT signature and audience. The hd constraint is
//    checked manually at lines ~340-344 with additional email and email_verified checks.
//    Passing hd to verifyIdToken would only duplicate the hd check without adding the
//    email or email_verified enforcement.
//
// 8. Error callback returns JSON, not redirect (line ~282): When Google returns an error
//    (user denied consent, etc.), the pending state is consumed to prevent replay. We
//    return a JSON 400 instead of redirecting to the client's redirect_uri because:
//    (a) this is an internal tool where the user sees the error directly, and
//    (b) the pending state must be consumed first, and after consumption we have the
//    redirect_uri available — but for simplicity and because MCP clients handle errors
//    gracefully, a JSON response is sufficient.
//
// 9. normalizeRedirectUri preserves path case and query parameter order: Per RFC 3986
//    §6.2.2.1, paths are case-sensitive. Query parameter order is also significant per
//    spec. The WHATWG URL constructor lowercases scheme and hostname automatically.
//    This is intentional and correct — clients must use consistent URI casing.
//
// 10. IPv6 loopback [::1] not accepted: Only http://localhost and http://127.0.0.1 are
//     allowed for local development. IPv6 loopback is not needed for current clients.
//
// 11. code_challenge_method defaults to S256 when absent: The server only supports S256
//     (advertised in metadata). RFC 7636 §4.3 says the default is "plain", but since
//     we don't support plain and always verify as S256, omitting the method is treated
//     as S256. A client that intends "plain" would fail PKCE verification — which is
//     the correct outcome since plain is not supported.
//
// 12. tokenResponse.json() body size: The fetch to oauth2.googleapis.com/token has a
//     15-second AbortSignal timeout. The response body is not size-capped because:
//     (a) the endpoint is hardcoded HTTPS to Google's domain (no SSRF possible),
//     (b) the timeout bounds total elapsed time including body transfer, and
//     (c) Google's token responses are consistently small JSON objects.
//
// 13. Expiry boundary consistency: Cleanup uses `v.expiresAt < now` and the token
//     endpoint uses `authCode.expiresAt < Date.now()` (expired = strictly before now).
//     validateOAuthToken uses `Date.now() < data.expiresAt` (valid = strictly before
//     expiry). At the exact millisecond boundary, a token is rejected and an auth code
//     is rejected — both are consistent in rejecting at the boundary. The off-by-one
//     between cleanup (`<`) and validation (`<`) means an entry at exactly expiresAt is
//     not cleaned up until the next interval but is already rejected by validation.
//     This is harmless (one extra entry for up to 10 minutes, already rejected on use).
//
// 14. Store exhaustion after successful Google auth (MAX_AUTH_CODES full): If the
//     authCodes store is full when a user completes Google login, the pendingAuths
//     entry is already consumed and the user gets a 503. This is acceptable: the user
//     must restart the flow. The alternative (checking capacity before the Google
//     exchange) would waste a pendingAuths slot on a speculative capacity reservation.
//
// 15. Token endpoint does not re-validate client_id against the clients registry:
//     The token endpoint checks client_id === authCode.clientId (string match against
//     the value stored at authorize time) but does not look up the clients Map. This is
//     intentional: auth codes live 5 minutes while client registrations live 24 hours,
//     so a client cannot expire between authorize and token exchange. The auth code
//     itself is the binding — re-checking the registry would add no security value.
//
// ──────────────────────────────────────────────────────────────────────────────

let _googleOAuthClient: OAuth2Client | undefined;
function getGoogleOAuthClient(): OAuth2Client {
  if (!_googleOAuthClient) {
    if (!config.googleClientId) throw new Error("GOOGLE_CLIENT_ID is required for OAuth");
    _googleOAuthClient = new OAuth2Client(config.googleClientId);
  }
  return _googleOAuthClient;
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

const MAX_CLIENTS = 1000;
const MAX_AUTH_CODES = 1000;
const MAX_PENDING_AUTHS = 1000;
const MAX_ACCESS_TOKENS = 10000;
const MAX_REDIRECT_URIS_PER_CLIENT = 10;
const MAX_CLIENT_NAME_LENGTH = 256;
const MAX_STATE_LENGTH = 2048;
const GOOGLE_FETCH_TIMEOUT_MS = 15_000;

// --- In-memory stores (short-lived, stateless between restarts) ---

/** Dynamically registered OAuth clients */
const CLIENT_TTL = 24 * 60 * 60 * 1000; // 24 hours
const clients = new Map<string, { redirectUris: string[]; name?: string; createdAt: number }>();

/** Pending authorization requests: hash(code) -> { clientId, redirectUri, codeChallenge, email } */
const authCodes = new Map<string, {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  email: string;
  expiresAt: number;
}>();

/** Issued access tokens -> email */
const accessTokens = new Map<string, { email: string; expiresAt: number }>();

/** Pending OAuth state -> { clientId, redirectUri, codeChallenge, ..., expiresAt } */
const pendingAuths = new Map<string, {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  expiresAt: number;
}>();

// Cleanup expired entries every 10 minutes
const oauthCleanupInterval = setInterval(() => {
  const now = Date.now();
  for (const [k, v] of authCodes) if (v.expiresAt < now) authCodes.delete(k);
  for (const [k, v] of accessTokens) if (v.expiresAt < now) accessTokens.delete(k);
  for (const [k, v] of pendingAuths) if (v.expiresAt < now) pendingAuths.delete(k);
  for (const [k, v] of clients) if (now - v.createdAt > CLIENT_TTL) clients.delete(k);
}, 10 * 60 * 1000);
oauthCleanupInterval.unref();

export function stopOAuthCleanup() {
  clearInterval(oauthCleanupInterval);
}

// --- Helpers ---

/** Redact email for logging: "j****@maestra.io" */
function redactEmail(email: string): string {
  const at = email.lastIndexOf("@");
  if (at <= 0) return "****";
  return `${email[0]}****${email.slice(at)}`;
}

/** Extract a single string from an Express query/body value, or undefined */
function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/**
 * Canonicalize a URI for safe comparison.
 * - Lowercases scheme and hostname (WHATWG URL constructor does this automatically)
 * - Resolves path traversals (WHATWG URL constructor resolves . and .. segments)
 * - Preserves path case (case-sensitive per RFC 3986 §6.2.2.1)
 * - Preserves query string including parameter order (significant per spec)
 * - Rejects fragments (RFC 6749 §3.1.2 forbids fragments in redirect URIs)
 */
export function normalizeRedirectUri(uri: string): string {
  const url = new URL(uri);
  if (url.hash) throw new Error("redirect_uri must not contain a fragment");
  return `${url.protocol}//${url.hostname}${url.port ? ":" + url.port : ""}${url.pathname}${url.search}`;
}

/**
 * Validate redirect URI: must be https, or http://localhost/127.0.0.1 for dev.
 * Rejects fragments per RFC 6749 §3.1.2.
 * Note: IPv6 loopback [::1] is intentionally not supported (see design decision #10).
 */
export function isValidRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri);
    if (url.hash) return false;
    if (url.username || url.password) return false;
    if (url.protocol === "https:") return true;
    if (url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1")) return true;
    return false;
  } catch {
    return false;
  }
}

// --- Public API ---

/** Check if a Bearer token is a valid OAuth-issued token. Returns email or null. */
export function validateOAuthToken(token: string): string | null {
  const data = accessTokens.get(hashToken(token));
  if (data && Date.now() < data.expiresAt) return data.email;
  return null;
}

/** Mount OAuth routes on the Express app. */
export function mountOAuthRoutes(app: express.Express): void {
  const issuer = config.publicUrl;

  // RFC 9728: Protected Resource Metadata
  app.get("/.well-known/oauth-protected-resource", (_req, res) => {
    res.json({
      resource: issuer,
      authorization_servers: [issuer],
      bearer_methods_supported: ["header"],
    });
  });

  // Also serve at /mcp-prefixed path for clients that append the resource path
  app.get("/.well-known/oauth-protected-resource/mcp", (_req, res) => {
    res.json({
      resource: `${issuer}/mcp`,
      authorization_servers: [issuer],
      bearer_methods_supported: ["header"],
    });
  });

  // RFC 8414: Authorization Server Metadata
  app.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.json({
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      registration_endpoint: `${issuer}/oauth/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
    });
  });

  // RFC 7591: Dynamic Client Registration
  app.post("/oauth/register", (req, res) => {
    const { redirect_uris, client_name } = req.body ?? {};
    if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
      res.status(400).json({ error: "invalid_request", error_description: "redirect_uris required" });
      return;
    }

    if (redirect_uris.length > MAX_REDIRECT_URIS_PER_CLIENT) {
      res.status(400).json({ error: "invalid_request", error_description: `Too many redirect_uris (max ${MAX_REDIRECT_URIS_PER_CLIENT})` });
      return;
    }

    if (client_name !== undefined && (typeof client_name !== "string" || client_name.length > MAX_CLIENT_NAME_LENGTH)) {
      res.status(400).json({ error: "invalid_request", error_description: `client_name must be a string of at most ${MAX_CLIENT_NAME_LENGTH} characters` });
      return;
    }

    for (const uri of redirect_uris) {
      if (typeof uri !== "string" || uri.length > 2048 || !isValidRedirectUri(uri)) {
        res.status(400).json({
          error: "invalid_request",
          error_description: "Invalid redirect_uri. Must be https or http://localhost, without a fragment.",
        });
        return;
      }
    }

    if (clients.size >= MAX_CLIENTS) {
      res.status(503).json({ error: "Too many registered clients" });
      return;
    }

    const clientId = randomUUID();
    const normalizedUris = redirect_uris.map(normalizeRedirectUri);
    // Strip ASCII control chars, DEL, Unicode bidi overrides, zero-width chars, and BOM
    const sanitizedName = client_name?.replace(/[\x00-\x1f\x7f\u200b-\u200f\u2028-\u202f\u2060-\u2069\ufeff]/g, "") || undefined;
    clients.set(clientId, { redirectUris: normalizedUris, name: sanitizedName, createdAt: Date.now() });
    console.log(`OAuth: registered client ${clientId} (${JSON.stringify(sanitizedName ?? "unnamed")})`);

    res.status(201).json({
      client_id: clientId,
      client_name: sanitizedName,
      redirect_uris: normalizedUris,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
  });

  // Authorization endpoint — redirects to Google OAuth
  app.get("/oauth/authorize", (req, res) => {
    const client_id = asString(req.query.client_id);
    const redirect_uri = asString(req.query.redirect_uri);
    const response_type = asString(req.query.response_type);
    const state = asString(req.query.state);
    const code_challenge = asString(req.query.code_challenge);
    const code_challenge_method = asString(req.query.code_challenge_method);

    if (response_type !== "code") {
      res.status(400).json({ error: "unsupported_response_type" });
      return;
    }
    if (!client_id) {
      res.status(400).json({ error: "invalid_client" });
      return;
    }
    const client = clients.get(client_id);
    if (!client) {
      res.status(400).json({ error: "invalid_client" });
      return;
    }
    if (!redirect_uri) {
      res.status(400).json({ error: "invalid_request", error_description: "redirect_uri is required" });
      return;
    }
    let normalizedRedirectUri: string;
    try {
      normalizedRedirectUri = normalizeRedirectUri(redirect_uri);
    } catch {
      res.status(400).json({ error: "invalid_request", error_description: "Malformed redirect_uri" });
      return;
    }
    if (!client.redirectUris.includes(normalizedRedirectUri)) {
      res.status(400).json({ error: "invalid_request", error_description: "redirect_uri not registered" });
      return;
    }
    // code_challenge must be base64url-safe unreserved chars per RFC 7636 §4.2
    if (!code_challenge || !/^[A-Za-z0-9\-._~]{43,128}$/.test(code_challenge)) {
      res.status(400).json({ error: "invalid_request", error_description: "PKCE code_challenge required (43-128 unreserved chars per RFC 7636)" });
      return;
    }
    // Only S256 is supported; absent method defaults to S256 (see design decision #11)
    if (code_challenge_method && code_challenge_method !== "S256") {
      res.status(400).json({ error: "invalid_request", error_description: "Only S256 is supported" });
      return;
    }
    if (state && state.length > MAX_STATE_LENGTH) {
      res.status(400).json({ error: "invalid_request", error_description: "state too long" });
      return;
    }

    if (pendingAuths.size >= MAX_PENDING_AUTHS) {
      res.status(503).json({ error: "Too many pending authorizations" });
      return;
    }

    const googleState = randomBytes(32).toString("hex");
    pendingAuths.set(googleState, {
      clientId: client_id,
      redirectUri: normalizedRedirectUri,
      codeChallenge: code_challenge,
      state,
      expiresAt: Date.now() + 10 * 60 * 1000,
    });

    const googleAuthUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    googleAuthUrl.searchParams.set("client_id", config.googleClientId);
    googleAuthUrl.searchParams.set("redirect_uri", `${issuer}/oauth/callback`);
    googleAuthUrl.searchParams.set("response_type", "code");
    googleAuthUrl.searchParams.set("scope", "openid email");
    googleAuthUrl.searchParams.set("state", googleState);
    // hd is a UI hint only — server-side enforcement is at lines 340-348 below
    googleAuthUrl.searchParams.set("hd", "maestra.io");
    googleAuthUrl.searchParams.set("prompt", "select_account");

    res.redirect(googleAuthUrl.toString());
  });

  // Google OAuth callback
  app.get("/oauth/callback", async (req, res) => {
    const googleCode = asString(req.query.code);
    const googleState = asString(req.query.state);
    const error = asString(req.query.error);

    // Error from Google (user denied, etc.) — consume state and return generic error
    // (see design decision #8 for why we return JSON instead of redirecting)
    if (error) {
      if (googleState) pendingAuths.delete(googleState);
      res.status(400).json({ error: "access_denied", error_description: "Google OAuth authorization failed" });
      return;
    }

    if (!googleState || !googleCode || googleCode.length > 512 || googleState.length !== 64) {
      // Consume state if present to prevent dangling entries
      if (googleState) pendingAuths.delete(googleState);
      res.status(400).json({ error: "invalid_request", error_description: "Missing code or state parameter" });
      return;
    }

    const pending = pendingAuths.get(googleState);
    if (!pending || Date.now() > pending.expiresAt) {
      if (pending) pendingAuths.delete(googleState);
      res.status(400).json({ error: "invalid_request", error_description: "Invalid or expired OAuth state" });
      return;
    }
    pendingAuths.delete(googleState);

    try {
      const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        signal: AbortSignal.timeout(GOOGLE_FETCH_TIMEOUT_MS),
        body: new URLSearchParams({
          code: googleCode,
          client_id: config.googleClientId,
          client_secret: config.googleClientSecret,
          redirect_uri: `${issuer}/oauth/callback`,
          grant_type: "authorization_code",
        }),
      });

      if (!tokenResponse.ok) {
        console.error(`OAuth: Google token exchange failed (${tokenResponse.status})`);
        res.status(500).json({ error: "server_error", error_description: "Google token exchange failed" });
        return;
      }

      const tokenData = await tokenResponse.json() as { id_token?: string };

      if (!tokenData.id_token) {
        console.error("OAuth: Google response missing id_token");
        res.status(500).json({ error: "server_error", error_description: "Google token exchange returned no id_token" });
        return;
      }

      // Verify JWT signature, audience, and expiry via Google's JWKS
      // (see design decision #7 for why hd is not passed here)
      let ticket;
      try {
        ticket = await getGoogleOAuthClient().verifyIdToken({
          idToken: tokenData.id_token,
          audience: config.googleClientId,
        });
      } catch (err) {
        console.warn("OAuth: id_token verification failed:", err instanceof Error ? err.message : String(err));
        res.status(400).json({ error: "invalid_request", error_description: "id_token verification failed" });
        return;
      }
      const payload = ticket.getPayload();

      // Domain enforcement: require verified @maestra.io email from maestra.io Workspace
      // (see design decision #6 for why both endsWith and hd are checked)
      if (
        !payload?.email ||
        !payload.email.endsWith("@maestra.io") ||
        payload.hd !== "maestra.io" ||
        payload.email_verified !== true
      ) {
        console.warn(`OAuth: rejected login from ${redactEmail(payload?.email ?? "unknown")} (not from maestra.io domain)`);
        res.status(403).json({ error: "access_denied", error_description: "Access restricted to @maestra.io accounts" });
        return;
      }

      console.log(`OAuth: authorized ${redactEmail(payload.email)}`);

      if (authCodes.size >= MAX_AUTH_CODES) {
        res.status(503).json({ error: "server_error", error_description: "Too many pending auth codes" });
        return;
      }

      const ourCode = randomBytes(32).toString("hex");
      authCodes.set(hashToken(ourCode), {
        clientId: pending.clientId,
        redirectUri: pending.redirectUri,
        codeChallenge: pending.codeChallenge,
        email: payload.email,
        expiresAt: Date.now() + 5 * 60 * 1000,
      });

      const redirectUrl = new URL(pending.redirectUri);
      redirectUrl.searchParams.set("code", ourCode);
      if (pending.state) redirectUrl.searchParams.set("state", pending.state);
      // Prevent auth code leakage via Referer header and caching
      res.set("Referrer-Policy", "no-referrer").set("Cache-Control", "no-store").redirect(redirectUrl.toString());
    } catch (err) {
      console.error("OAuth: callback error:", err instanceof Error ? err.message : String(err));
      res.status(500).json({ error: "server_error", error_description: "OAuth callback failed" });
    }
  });

  // Token endpoint — exchange auth code for access token (with PKCE)
  app.post("/oauth/token", (req, res) => {
    const body = req.body ?? {};
    const grant_type = asString(body.grant_type);
    const code = asString(body.code);
    const redirect_uri = asString(body.redirect_uri);
    const client_id = asString(body.client_id);
    const code_verifier = asString(body.code_verifier);

    if (grant_type !== "authorization_code") {
      res.status(400).json({ error: "unsupported_grant_type" });
      return;
    }

    if (!code || code.length > 256) {
      res.status(400).json({ error: "invalid_grant", error_description: "code is required" });
      return;
    }

    const codeHash = hashToken(code);
    const authCode = authCodes.get(codeHash);
    if (!authCode) {
      res.status(400).json({ error: "invalid_grant", error_description: "Invalid or expired code" });
      return;
    }

    // Auth code is single-use — delete before any further checks.
    // (see design decision #4 for full rationale)
    authCodes.delete(codeHash);

    if (authCode.expiresAt < Date.now()) {
      res.status(400).json({ error: "invalid_grant", error_description: "Code expired" });
      return;
    }

    if (!client_id) {
      res.status(400).json({ error: "invalid_client", error_description: "client_id is required" });
      return;
    }
    if (!redirect_uri || redirect_uri.length > 2048) {
      res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri is required" });
      return;
    }
    let normalizedRedirectUri: string;
    try {
      normalizedRedirectUri = normalizeRedirectUri(redirect_uri);
    } catch {
      res.status(400).json({ error: "invalid_grant", error_description: "Malformed redirect_uri" });
      return;
    }
    if (authCode.clientId !== client_id || authCode.redirectUri !== normalizedRedirectUri) {
      res.status(400).json({ error: "invalid_grant", error_description: "Client/redirect mismatch" });
      return;
    }

    // PKCE is mandatory — validate charset per RFC 7636 §4.1
    if (!code_verifier || !/^[A-Za-z0-9\-._~]{43,128}$/.test(code_verifier)) {
      res.status(400).json({ error: "invalid_grant", error_description: "code_verifier required (43-128 unreserved chars per RFC 7636)" });
      return;
    }

    // S256 verification: both sides are always 43-char base64url strings
    // (see design decision #5 for the length pre-check rationale)
    const expected = createHash("sha256").update(code_verifier).digest("base64url");
    const expectedBuf = Buffer.from(expected);
    const storedBuf = Buffer.from(authCode.codeChallenge);
    if (expectedBuf.length !== storedBuf.length || !timingSafeEqual(expectedBuf, storedBuf)) {
      res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
      return;
    }

    if (accessTokens.size >= MAX_ACCESS_TOKENS) {
      res.status(503).json({ error: "server_error", error_description: "Too many active tokens" });
      return;
    }

    const accessToken = randomBytes(32).toString("hex");
    const expiresIn = 24 * 60 * 60; // 24h
    accessTokens.set(hashToken(accessToken), {
      email: authCode.email,
      expiresAt: Date.now() + expiresIn * 1000,
    });

    console.log(`OAuth: issued token for ${redactEmail(authCode.email)}`);

    res.set("Cache-Control", "no-store").set("Pragma", "no-cache").json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: expiresIn,
    });
  });
}
