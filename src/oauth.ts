import { randomUUID, randomBytes, createHash, timingSafeEqual } from "node:crypto";
import express from "express";
import { OAuth2Client } from "google-auth-library";
import { config } from "./config.js";

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

/** Canonicalize a URI for safe comparison (lowercases scheme+host, resolves path) */
export function normalizeRedirectUri(uri: string): string {
  const url = new URL(uri);
  if (url.hash) throw new Error("redirect_uri must not contain a fragment");
  return `${url.protocol}//${url.hostname}${url.port ? ":" + url.port : ""}${url.pathname}${url.search}`;
}

/** Validate redirect URI: must be https, or http://localhost for dev */
export function isValidRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri);
    if (url.hash) return false;
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
      if (typeof uri !== "string" || !isValidRedirectUri(uri)) {
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
    const sanitizedName = client_name?.replace(/[\x00-\x1f\x7f\u200b-\u200f\u2028-\u202f\u2060-\u2069\ufeff]/g, "") ?? undefined;
    clients.set(clientId, { redirectUris: normalizedUris, name: sanitizedName, createdAt: Date.now() });
    console.log(`OAuth: registered client ${clientId} (${sanitizedName ?? "unnamed"})`);

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
    if (!code_challenge || !/^[A-Za-z0-9\-._~]{43,128}$/.test(code_challenge)) {
      res.status(400).json({ error: "invalid_request", error_description: "PKCE code_challenge required (43-128 unreserved chars per RFC 7636)" });
      return;
    }
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
    googleAuthUrl.searchParams.set("hd", "maestra.io");
    googleAuthUrl.searchParams.set("prompt", "select_account");

    res.redirect(googleAuthUrl.toString());
  });

  // Google OAuth callback
  app.get("/oauth/callback", async (req, res) => {
    const googleCode = asString(req.query.code);
    const googleState = asString(req.query.state);
    const error = asString(req.query.error);

    if (error) {
      // Consume the pending state to prevent replay
      if (googleState) pendingAuths.delete(googleState);
      res.status(400).json({ error: "access_denied", error_description: "Google OAuth authorization failed" });
      return;
    }

    if (!googleState || !googleCode) {
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

      let ticket;
      try {
        ticket = await getGoogleOAuthClient().verifyIdToken({
          idToken: tokenData.id_token,
          audience: config.googleClientId,
        });
      } catch (err) {
        console.warn("OAuth: id_token verification failed", err);
        res.status(400).json({ error: "invalid_request", error_description: "id_token verification failed" });
        return;
      }
      const payload = ticket.getPayload();

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
      res.redirect(redirectUrl.toString());
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

    if (!code) {
      res.status(400).json({ error: "invalid_grant", error_description: "code is required" });
      return;
    }

    const codeHash = hashToken(code);
    const authCode = authCodes.get(codeHash);
    if (!authCode) {
      res.status(400).json({ error: "invalid_grant", error_description: "Invalid or expired code" });
      return;
    }

    // Auth code is single-use per RFC 6749 §10.5 — delete immediately
    authCodes.delete(codeHash);

    if (authCode.expiresAt < Date.now()) {
      res.status(400).json({ error: "invalid_grant", error_description: "Code expired" });
      return;
    }

    if (!redirect_uri) {
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
