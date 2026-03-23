import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("./config.js", () => ({
  config: {
    esAddresses: ["http://localhost:9200"],
    esTimeout: 30000,
    esMaxRetries: 3,
    port: 8080,
    maxSessions: 1000,
    bodyLimit: "1mb",
    apiTokens: ["token1"],
    publicUrl: "https://mta-logs-elasticsearch-mcp.maestra.io",
    googleClientId: "test-client-id",
    googleClientSecret: "test-client-secret",
  },
}));

const { isValidRedirectUri, validateOAuthToken, mountOAuthRoutes } = await import("./oauth.js");

describe("isValidRedirectUri", () => {
  it("accepts https URIs", () => {
    expect(isValidRedirectUri("https://example.com/callback")).toBe(true);
    expect(isValidRedirectUri("https://app.example.com:8443/auth")).toBe(true);
  });

  it("accepts http://localhost", () => {
    expect(isValidRedirectUri("http://localhost/callback")).toBe(true);
    expect(isValidRedirectUri("http://localhost:3000/callback")).toBe(true);
  });

  it("accepts http://127.0.0.1", () => {
    expect(isValidRedirectUri("http://127.0.0.1/callback")).toBe(true);
    expect(isValidRedirectUri("http://127.0.0.1:8080/auth")).toBe(true);
  });

  it("rejects http with non-localhost hosts", () => {
    expect(isValidRedirectUri("http://example.com/callback")).toBe(false);
    expect(isValidRedirectUri("http://evil.com/auth")).toBe(false);
  });

  it("rejects malformed URIs", () => {
    expect(isValidRedirectUri("not-a-url")).toBe(false);
    expect(isValidRedirectUri("")).toBe(false);
    expect(isValidRedirectUri("ftp://example.com/file")).toBe(false);
  });
});

describe("validateOAuthToken", () => {
  it("returns null for unknown token", () => {
    expect(validateOAuthToken("nonexistent-token")).toBeNull();
  });
});

describe("mountOAuthRoutes", () => {
  let routes: Record<string, Record<string, Function>>;
  let mockApp: any;

  beforeEach(() => {
    routes = {};
    mockApp = {
      get: vi.fn((path: string, handler: Function) => {
        routes[`GET:${path}`] = { handler };
      }),
      post: vi.fn((path: string, handler: Function) => {
        routes[`POST:${path}`] = { handler };
      }),
    };
    mountOAuthRoutes(mockApp);
  });

  it("registers all required OAuth routes", () => {
    expect(mockApp.get).toHaveBeenCalledWith("/.well-known/oauth-protected-resource", expect.any(Function));
    expect(mockApp.get).toHaveBeenCalledWith("/.well-known/oauth-protected-resource/mcp", expect.any(Function));
    expect(mockApp.get).toHaveBeenCalledWith("/.well-known/oauth-authorization-server", expect.any(Function));
    expect(mockApp.post).toHaveBeenCalledWith("/oauth/register", expect.any(Function));
    expect(mockApp.get).toHaveBeenCalledWith("/oauth/authorize", expect.any(Function));
    expect(mockApp.get).toHaveBeenCalledWith("/oauth/callback", expect.any(Function));
    expect(mockApp.post).toHaveBeenCalledWith("/oauth/token", expect.any(Function));
  });

  function mockRes() {
    const res: any = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
      send: vi.fn().mockReturnThis(),
      redirect: vi.fn(),
    };
    return res;
  }

  describe("/.well-known/oauth-protected-resource", () => {
    it("returns correct metadata", () => {
      const res = mockRes();
      routes["GET:/.well-known/oauth-protected-resource"].handler({}, res);
      expect(res.json).toHaveBeenCalledWith({
        resource: "https://mta-logs-elasticsearch-mcp.maestra.io",
        authorization_servers: ["https://mta-logs-elasticsearch-mcp.maestra.io"],
        bearer_methods_supported: ["header"],
      });
    });
  });

  describe("/.well-known/oauth-authorization-server", () => {
    it("returns correct server metadata", () => {
      const res = mockRes();
      routes["GET:/.well-known/oauth-authorization-server"].handler({}, res);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          issuer: "https://mta-logs-elasticsearch-mcp.maestra.io",
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code"],
          code_challenge_methods_supported: ["S256"],
        }),
      );
    });
  });

  describe("/oauth/register", () => {
    it("rejects missing redirect_uris", () => {
      const res = mockRes();
      routes["POST:/oauth/register"].handler({ body: {} }, res);
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: "invalid_request" }),
      );
    });

    it("rejects empty redirect_uris array", () => {
      const res = mockRes();
      routes["POST:/oauth/register"].handler({ body: { redirect_uris: [] } }, res);
      expect(res.status).toHaveBeenCalledWith(400);
    });

    it("rejects invalid redirect URIs", () => {
      const res = mockRes();
      routes["POST:/oauth/register"].handler(
        { body: { redirect_uris: ["http://evil.com/callback"] } },
        res,
      );
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error_description: expect.stringContaining("Invalid redirect_uri") }),
      );
    });

    it("returns client_id on success", () => {
      const res = mockRes();
      routes["POST:/oauth/register"].handler(
        { body: { redirect_uris: ["https://app.example.com/callback"], client_name: "Test App" } },
        res,
      );
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          client_id: expect.any(String),
          client_name: "Test App",
          redirect_uris: ["https://app.example.com/callback"],
        }),
      );
    });
  });

  describe("/oauth/authorize", () => {
    function registerClient(): string {
      const res = mockRes();
      routes["POST:/oauth/register"].handler(
        { body: { redirect_uris: ["https://app.example.com/callback"] } },
        res,
      );
      return res.json.mock.calls[0][0].client_id;
    }

    it("rejects non-code response_type", () => {
      const res = mockRes();
      routes["GET:/oauth/authorize"].handler(
        { query: { response_type: "token", client_id: "x", redirect_uri: "y" } },
        res,
      );
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: "unsupported_response_type" });
    });

    it("rejects unknown client_id", () => {
      const res = mockRes();
      routes["GET:/oauth/authorize"].handler(
        { query: { response_type: "code", client_id: "unknown", redirect_uri: "y" } },
        res,
      );
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: "invalid_client" });
    });

    it("rejects unregistered redirect_uri", () => {
      const clientId = registerClient();
      const res = mockRes();
      routes["GET:/oauth/authorize"].handler(
        {
          query: {
            response_type: "code",
            client_id: clientId,
            redirect_uri: "https://other.com/callback",
            code_challenge: "challenge",
          },
        },
        res,
      );
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error_description: "redirect_uri not registered" }),
      );
    });

    it("requires PKCE (code_challenge)", () => {
      const clientId = registerClient();
      const res = mockRes();
      routes["GET:/oauth/authorize"].handler(
        {
          query: {
            response_type: "code",
            client_id: clientId,
            redirect_uri: "https://app.example.com/callback",
          },
        },
        res,
      );
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error_description: "PKCE required" }),
      );
    });

    it("redirects to Google with correct params on success", () => {
      const clientId = registerClient();
      const res = mockRes();
      routes["GET:/oauth/authorize"].handler(
        {
          query: {
            response_type: "code",
            client_id: clientId,
            redirect_uri: "https://app.example.com/callback",
            code_challenge: "test-challenge",
            code_challenge_method: "S256",
            state: "client-state",
          },
        },
        res,
      );
      expect(res.redirect).toHaveBeenCalledTimes(1);
      const redirectUrl = new URL(res.redirect.mock.calls[0][0]);
      expect(redirectUrl.origin).toBe("https://accounts.google.com");
      expect(redirectUrl.searchParams.get("client_id")).toBe("test-client-id");
      expect(redirectUrl.searchParams.get("response_type")).toBe("code");
      expect(redirectUrl.searchParams.get("scope")).toBe("openid email");
      expect(redirectUrl.searchParams.get("hd")).toBe("maestra.io");
    });
  });

  describe("/oauth/callback", () => {
    it("returns error when Google returns an error", async () => {
      const res = mockRes();
      await routes["GET:/oauth/callback"].handler(
        { query: { error: "access_denied", state: "x" } },
        res,
      );
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: "Google OAuth error", details: "access_denied" });
    });

    it("returns error for invalid/expired state", async () => {
      const res = mockRes();
      await routes["GET:/oauth/callback"].handler(
        { query: { code: "google-code", state: "invalid-state" } },
        res,
      );
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: "invalid_request", error_description: "Invalid or expired OAuth state" });
    });
  });

  describe("/oauth/token", () => {
    it("rejects non-authorization_code grant_type", () => {
      const res = mockRes();
      routes["POST:/oauth/token"].handler(
        { body: { grant_type: "client_credentials" } },
        res,
      );
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({ error: "unsupported_grant_type" });
    });

    it("rejects invalid/expired code", () => {
      const res = mockRes();
      routes["POST:/oauth/token"].handler(
        { body: { grant_type: "authorization_code", code: "invalid" } },
        res,
      );
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: "invalid_grant" }),
      );
    });

    it("rejects missing code", () => {
      const res = mockRes();
      routes["POST:/oauth/token"].handler(
        { body: { grant_type: "authorization_code" } },
        res,
      );
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: "invalid_grant" }),
      );
    });
  });
});
