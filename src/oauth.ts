import { randomUUID, randomBytes, createHash } from "node:crypto";
import express from "express";
import { config } from "./config.js";

// --- In-memory stores (short-lived, stateless between restarts) ---

/** Dynamically registered OAuth clients */
const clients = new Map<string, { redirectUris: string[]; name?: string }>();

/** Pending authorization requests: code -> { clientId, redirectUri, codeChallenge, email } */
const authCodes = new Map<string, {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
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
  codeChallengeMethod: string;
  state?: string;
  expiresAt: number;
}>();

// Cleanup expired entries every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of authCodes) if (v.expiresAt < now) authCodes.delete(k);
  for (const [k, v] of accessTokens) if (v.expiresAt < now) accessTokens.delete(k);
  for (const [k, v] of pendingAuths) if (v.expiresAt < now) pendingAuths.delete(k);
}, 10 * 60 * 1000).unref();

// --- Helpers ---

/** Validate redirect URI: must be https, or http://localhost for dev */
export function isValidRedirectUri(uri: string): boolean {
  try {
    const url = new URL(uri);
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
  const entry = accessTokens.get(token);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    accessTokens.delete(token);
    return null;
  }
  return entry.email;
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

    for (const uri of redirect_uris) {
      if (typeof uri !== "string" || !isValidRedirectUri(uri)) {
        res.status(400).json({
          error: "invalid_request",
          error_description: `Invalid redirect_uri: ${uri}. Must be https or http://localhost`,
        });
        return;
      }
    }

    const clientId = randomUUID();
    clients.set(clientId, { redirectUris: redirect_uris, name: client_name });
    console.log(`OAuth: registered client ${clientId} (${client_name ?? "unnamed"})`);

    res.status(201).json({
      client_id: clientId,
      client_name,
      redirect_uris,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });
  });

  // Authorization endpoint — redirects to Google OAuth
  app.get("/oauth/authorize", (req, res) => {
    const {
      client_id, redirect_uri, response_type, state,
      code_challenge, code_challenge_method,
    } = req.query as Record<string, string>;

    if (response_type !== "code") {
      res.status(400).json({ error: "unsupported_response_type" });
      return;
    }
    const client = clients.get(client_id);
    if (!client) {
      res.status(400).json({ error: "invalid_client" });
      return;
    }
    if (!client.redirectUris.includes(redirect_uri)) {
      res.status(400).json({ error: "invalid_request", error_description: "redirect_uri not registered" });
      return;
    }
    if (!code_challenge) {
      res.status(400).json({ error: "invalid_request", error_description: "PKCE required" });
      return;
    }

    const googleState = randomBytes(32).toString("hex");
    pendingAuths.set(googleState, {
      clientId: client_id,
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method ?? "S256",
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
    const { code: googleCode, state: googleState, error } = req.query as Record<string, string>;

    if (error) {
      res.status(400).send(`Google OAuth error: ${error}`);
      return;
    }

    const pending = pendingAuths.get(googleState);
    if (!pending) {
      res.status(400).send("Invalid or expired OAuth state");
      return;
    }
    pendingAuths.delete(googleState);

    try {
      const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code: googleCode,
          client_id: config.googleClientId,
          client_secret: config.googleClientSecret,
          redirect_uri: `${issuer}/oauth/callback`,
          grant_type: "authorization_code",
        }),
      });

      if (!tokenResponse.ok) {
        const err = await tokenResponse.text();
        console.error(`OAuth: Google token exchange failed (${tokenResponse.status}): ${err}`);
        res.status(500).send("Google token exchange failed");
        return;
      }

      const tokenData = await tokenResponse.json() as { id_token?: string };

      if (!tokenData.id_token) {
        console.error("OAuth: Google response missing id_token");
        res.status(500).send("Google token exchange returned no id_token");
        return;
      }

      const payload = JSON.parse(
        Buffer.from(tokenData.id_token.split(".")[1], "base64url").toString(),
      ) as { email?: string; hd?: string };

      if (!payload.email || !payload.email.endsWith("@maestra.io")) {
        console.warn(`OAuth: rejected login from ${payload.email} (not @maestra.io)`);
        res.status(403).send("Access restricted to @maestra.io accounts");
        return;
      }

      console.log(`OAuth: authorized ${payload.email}`);

      const ourCode = randomBytes(32).toString("hex");
      authCodes.set(ourCode, {
        clientId: pending.clientId,
        redirectUri: pending.redirectUri,
        codeChallenge: pending.codeChallenge,
        codeChallengeMethod: pending.codeChallengeMethod,
        email: payload.email,
        expiresAt: Date.now() + 5 * 60 * 1000,
      });

      const redirectUrl = new URL(pending.redirectUri);
      redirectUrl.searchParams.set("code", ourCode);
      if (pending.state) redirectUrl.searchParams.set("state", pending.state);
      res.redirect(redirectUrl.toString());
    } catch (err) {
      console.error(`OAuth: callback error: ${err}`);
      res.status(500).send("OAuth callback failed");
    }
  });

  // Token endpoint — exchange auth code for access token (with PKCE)
  app.post("/oauth/token", (req, res) => {
    const { grant_type, code, redirect_uri, client_id, code_verifier } = req.body ?? {};

    console.log(`OAuth /token: grant_type=${grant_type} has_code=${typeof code === "string"} has_client_id=${typeof client_id === "string"}`);

    if (grant_type !== "authorization_code") {
      console.warn("OAuth /token: rejected unsupported grant_type");
      res.status(400).json({ error: "unsupported_grant_type" });
      return;
    }

    const authCode = typeof code === "string" ? authCodes.get(code) : undefined;
    if (!authCode) {
      console.warn("OAuth /token: invalid or expired code");
      res.status(400).json({ error: "invalid_grant", error_description: "Invalid or expired code" });
      return;
    }

    if (authCode.clientId !== client_id || authCode.redirectUri !== redirect_uri) {
      console.warn("OAuth /token: client/redirect mismatch");
      res.status(400).json({ error: "invalid_grant", error_description: "Client/redirect mismatch" });
      return;
    }

    if (authCode.expiresAt < Date.now()) {
      authCodes.delete(code);
      res.status(400).json({ error: "invalid_grant", error_description: "Code expired" });
      return;
    }

    if (authCode.codeChallenge && !code_verifier) {
      res.status(400).json({ error: "invalid_grant", error_description: "code_verifier required (PKCE)" });
      return;
    }

    if (code_verifier) {
      const expected = createHash("sha256").update(code_verifier).digest("base64url");
      if (expected !== authCode.codeChallenge) {
        res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
        return;
      }
    }

    authCodes.delete(code);

    const accessToken = randomBytes(32).toString("hex");
    const expiresIn = 24 * 60 * 60; // 24h
    accessTokens.set(accessToken, {
      email: authCode.email,
      expiresAt: Date.now() + expiresIn * 1000,
    });

    console.log(`OAuth: issued token for ${authCode.email}`);

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: expiresIn,
    });
  });
}
