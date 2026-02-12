# Copilot Instructions for mock-mcp-server

## Build & Run

```bash
dotnet restore
dotnet build
dotnet run          # Run locally (server listens on http://localhost:7071)
```

There are no tests or linting configured in this project.

## Architecture

This is a mock MCP (Model Context Protocol) server built as a .NET 8 **ASP.NET Core minimal API** application. It implements the MCP JSON-RPC protocol over HTTP with SSE support, OAuth-based authentication (CIMD), and a two-part authentication flow.

**Request flow:** All MCP logic is in `McpServer.cs`, with routes mapped in `Program.cs`. Requests to GET or POST `/mcp` are handled by `McpServer.HandleMcpGet()` and `McpServer.HandleMcpPost()`. Token validation is intentionally relaxed for local testing — it checks JWT structure and audience (`https://apihub.azure.com`) but skips signature verification.

**SSE support:** The GET `/mcp` endpoint supports Server-Sent Events (SSE) for the Streamable HTTP transport. Clients send `Accept: text/event-stream` and receive MCP messages as SSE events. The server sends `tools/list_changed` notifications when backend auth completes.

**Two-part auth flow:**
1. **Proxy auth (CIMD + AAD App #1):** Client authenticates via CIMD OAuth flow (`/oauth/authorize` → `/oauth/token`) to get a proxy token. With proxy token only, `tools/list` returns just `discover_tools`.
2. **Backend auth (AAD App #2):** Client calls `discover_tools` → receives elicitation URL → user authenticates in browser → backend tokens stored server-side keyed by proxy token. Now `tools/list` returns full tools (`echo`, `get_weather`, `calculate`).

**Endpoints:**
- `GET/POST /mcp` — MCP JSON-RPC protocol (auth-protected, SSE support on GET)
- `GET /.well-known/oauth-protected-resource` — OAuth Protected Resource Metadata (PRM)
- `GET /.well-known/oauth-authorization-server` — OAuth Authorization Server Metadata
- `GET /oauth/authorize` — OAuth authorization endpoint (CIMD)
- `GET /oauth/callback` — Entra ID callback (proxy auth)
- `POST /oauth/token` — OAuth token endpoint (proxy auth)
- `GET /backend-auth/login` — Start backend auth (AAD App #2)
- `GET /backend-auth/callback` — Backend auth callback
- `GET /backend-auth/status` — Check backend auth status
- `GET /cimd-policy` — Current CIMD policy configuration

## Conventions

- All MCP server logic is in `McpServer.cs`, with endpoint routing configured in `Program.cs`.
- Responses use anonymous objects serialized with `System.Text.Json` and `WriteIndented = true`. No DTO classes.
- Logging uses ANSI-colored `Console.WriteLine` for structured terminal output. Verbose logging (headers, args, response bodies) is toggled by the `MCP_VERBOSE_LOGGING` environment variable.
- Configuration is loaded from `local.settings.json` ("Values" section) and environment variables in `Program.cs`.
- Auth mode (`MCP_AUTH_MODE`) can be `mock` (default, no external calls) or `entra` (real Azure AD).
- Auth strategy (`MCP_AUTH_STRATEGY`) can be `cimd` (default, proxy is OAuth AS) or `entra-direct` (PRM points to Entra ID for WAM silent auth).
