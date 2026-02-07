# Copilot Instructions for mock-mcp-server

## Build & Run

```bash
dotnet restore
dotnet build
func start          # Run locally (requires Azure Functions Core Tools v4)
```

There are no tests or linting configured in this project.

## Architecture

This is a mock MCP (Model Context Protocol) server built as a .NET 8 Azure Functions app using the **isolated worker model** (`dotnet-isolated`). It implements the MCP JSON-RPC protocol over HTTP (not SSE/stdio), with OAuth-based authentication and a consent flow for tool authorization.

**Request flow:** All requests hit `Functions/McpFunctions.cs`, the single function class containing all endpoints. The POST `/mcp` endpoint validates a Bearer JWT (audience: `https://apihub.azure.com`), parses the JSON-RPC method, and dispatches via a `switch` expression. Token validation is intentionally relaxed — it checks JWT structure and audience but skips signature verification for local testing.

**Consent flow:** On first `tools/call`, the server returns an elicitation response with a consent URL. The user visits `/consent` in a browser to grant access (stored in an in-memory `ConcurrentDictionary`). After consent, `tools/list` returns the full tool set (`echo`, `get_weather`, `calculate`); before consent, only `discover_tools` is exposed.

**Endpoints:**
- `GET/POST /mcp` — MCP protocol (auth-protected)
- `GET /.well-known/oauth-protected-resource/mcp` — OAuth Protected Resource Metadata
- `GET /.well-known/oauth-authorization-server` — OAuth Authorization Server Metadata
- `GET /consent` — Consent page (HTML form + grant action)
- `GET /consent/status` — Check consent status (JSON)

## Conventions

- All endpoints are in a single class (`McpFunctions`) with no route prefix (`host.json` sets `routePrefix: ""`).
- Responses use anonymous objects serialized with `System.Text.Json` and `WriteIndented = true`. No DTO classes.
- Logging uses ANSI-colored `Console.WriteLine` for structured terminal output. Verbose logging (headers, args, response bodies) is toggled by the `MCP_VERBOSE_LOGGING` environment variable.
- The `AZURE_TENANT_ID` environment variable controls the OAuth tenant (defaults to `"common"` for multi-tenant).
- Session tokens are deterministic SHA256 hashes of `{toolName}:{arguments}`, truncated to 16 chars.
