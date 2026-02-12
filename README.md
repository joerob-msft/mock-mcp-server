# Mock MCP Server

A mock MCP (Model Context Protocol) proxy server with two-part authentication, SSE notifications, and CIMD-based client identity. Built as a .NET 8 ASP.NET Core app. Models a real-world architecture where an MCP proxy authenticates clients via CIMD (AAD App #1) and internally authenticates to a backend MCP server via a separate AAD app (App #2).

## Two-Part Authentication Flow

```
VS Code (MCP Client)
  │
  ├─ CIMD OAuth ──→ AAD App #1 ──→ proxy token
  │
  ├─ tools/list ──→ [discover_tools only]
  │
  ├─ tools/call discover_tools ──→ elicitation URL
  │       │
  │       └─ User opens browser → /backend-auth/login
  │             → Entra login (AAD App #2)
  │             → Backend tokens stored server-side
  │             → "Success, close window"
  │
  ├─ tools/list ──→ [full tools list]
  │
  └─ tools/call echo ──→ proxy uses stored backend token internally
```

### Part 1: Proxy Auth (CIMD + AAD App #1)
1. Client discovers PRM at `/.well-known/oauth-protected-resource`
2. Client authenticates via CIMD OAuth flow (`/oauth/authorize` → `/oauth/token`)
3. Client receives a **proxy token** — this is the only token the client ever sees
4. With proxy token, `tools/list` returns only `discover_tools`

### Part 2: Backend Auth (AAD App #2, server-side)
5. Client calls `discover_tools` → receives elicitation URL
6. User opens URL in browser → authenticates against AAD App #2
7. Backend tokens (access + refresh) stored **server-side**, keyed by proxy token
8. Now `tools/list` returns full tools and `tools/call` works
9. Client continues using the same proxy token — backend tokens are never exposed

## Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/.well-known/oauth-protected-resource` | Protected Resource Metadata (PRM) |
| GET | `/.well-known/oauth-authorization-server` | OAuth Authorization Server Metadata |
| GET | `/oauth/authorize` | OAuth authorization endpoint (CIMD) |
| GET | `/oauth/callback` | Entra ID callback (proxy auth) |
| POST | `/oauth/token` | OAuth token endpoint (proxy auth) |
| GET/POST | `/mcp` | MCP JSON-RPC endpoint |
| GET | `/backend-auth/login` | Start backend auth (AAD App #2) |
| GET | `/backend-auth/callback` | Backend auth callback |
| GET | `/backend-auth/status` | Check backend auth status |
| GET | `/cimd-policy` | Current CIMD policy configuration |

## Supported MCP Methods

- `initialize` - Returns server capabilities
- `tools/list` - Returns available tools (expands after consent)
- `tools/call` - Executes a tool call (echo, get_weather, calculate)
- `resources/list` - Returns available resources (empty)
- `prompts/list` - Returns available prompts (empty)

## Configuration

### Auth Modes

Set `MCP_AUTH_MODE` in `local.settings.json`:

| Mode | Description |
|------|-------------|
| `mock` (default) | No external calls. Auth codes and tokens generated locally. Good for offline testing. |
| `entra` | Real Azure AD integration. Redirects to Entra ID for user authentication. Requires AAD app registration. |

### Auth Strategy

Set `MCP_AUTH_STRATEGY` in `local.settings.json`:

| Strategy | Description |
|----------|-------------|
| `cimd` (default) | Proxy acts as its own OAuth Authorization Server. Clients authenticate via CIMD. Works with any MCP client. |
| `entra-direct` | PRM points directly to Entra ID. VS Code uses WAM for silent auth (no browser popup). Only works with Entra-registered clients. |

### Environment Variables

#### Proxy Auth (AAD App #1)
| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_AUTH_MODE` | `mock` | Auth mode: `mock` or `entra` |
| `MCP_AUTH_STRATEGY` | `cimd` | Auth strategy: `cimd` (proxy is OAuth AS) or `entra-direct` (Entra ID is AS) |
| `MCP_EXPOSED_SCOPE` | `Runtime.All` | Exposed scope name on AAD app (used in entra-direct PRM) |
| `AZURE_TENANT_ID` | `common` | Entra tenant ID |
| `AZURE_CLIENT_ID` | — | AAD App #1 client ID (proxy) |
| `AZURE_CLIENT_SECRET` | — | AAD App #1 client secret (only needed for CIMD strategy) |

#### Backend Auth (AAD App #2 — real MCP server)
| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND_CLIENT_ID` | — | AAD App #2 client ID (backend) |
| `BACKEND_CLIENT_SECRET` | — | AAD App #2 client secret |
| `BACKEND_TENANT_ID` | `AZURE_TENANT_ID` | Backend tenant (defaults to proxy tenant) |
| `BACKEND_SCOPES` | `openid profile offline_access` | Scopes for App #2 |

#### Other
| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_VERBOSE_LOGGING` | `false` | Enable verbose request/response logging |
| `CIMD_POLICY_MODE` | `open` | CIMD client policy: `open`, `allowlist`, or `denylist` |
| `CIMD_ALLOWED_CLIENTS` | — | Semicolon-delimited list of allowed CIMD client patterns (used when mode=`allowlist`) |
| `CIMD_DENIED_CLIENTS` | — | Semicolon-delimited list of denied CIMD client patterns (used when mode=`denylist`) |

### CIMD Client Policy

Controls which MCP clients are permitted to authenticate via CIMD. The policy is evaluated **before** fetching the CIMD document (prevents SSRF from untrusted `client_id` URLs).

| Mode | Behavior |
|------|----------|
| `open` (default) | All CIMD clients allowed |
| `allowlist` | Only explicitly listed clients/domains permitted |
| `denylist` | All clients allowed except explicitly blocked ones |

**Pattern types** (semicolon-delimited in `CIMD_ALLOWED_CLIENTS` / `CIMD_DENIED_CLIENTS`):
- **Exact URL:** `https://vscode.dev/oauth/client-metadata.json`
- **Exact domain:** `vscode.dev` (matches any CIMD on that host)
- **Wildcard domain:** `*.microsoft.com` (matches subdomains only)

**Example — allowlist only VS Code and GitHub clients:**
```json
{
  "Values": {
    "CIMD_POLICY_MODE": "allowlist",
    "CIMD_ALLOWED_CLIENTS": "https://vscode.dev/oauth/client-metadata.json;*.github.com"
  }
}
```

**Example — block a specific client:**
```json
{
  "Values": {
    "CIMD_POLICY_MODE": "denylist",
    "CIMD_DENIED_CLIENTS": "*.untrusted.dev"
  }
}
```

**Check current policy:** `curl http://localhost:7071/cimd-policy`

### Entra Mode Setup (CIMD Strategy)

1. **App #1 (Proxy):** Register in Azure Portal, add redirect URI `http://localhost:7071/oauth/callback`
2. **App #2 (Backend):** Register separately, add redirect URI `http://localhost:7071/backend-auth/callback`
3. Set environment variables in `local.settings.json`:
   ```json
   {
     "Values": {
       "MCP_AUTH_MODE": "entra",
       "MCP_AUTH_STRATEGY": "cimd",
       "AZURE_TENANT_ID": "your-tenant-id",
       "AZURE_CLIENT_ID": "app1-client-id",
       "AZURE_CLIENT_SECRET": "app1-secret",
       "BACKEND_CLIENT_ID": "app2-client-id",
       "BACKEND_CLIENT_SECRET": "app2-secret",
       "BACKEND_SCOPES": "api://app2-client-id/.default"
     }
   }
   ```

### Entra-Direct Setup (Silent Auth via WAM)

In this mode, VS Code authenticates silently using the user's existing Microsoft session — no browser popup needed. The PRM points directly to Entra ID as the authorization server.

1. **App #1 (Proxy):** Register in Azure Portal
2. **Expose an API** on App #1:
   - Add a scope (e.g., `Runtime.All`)
   - Pre-authorize VS Code's client ID: `aebc6443-996d-45c2-90f0-388ff96faa56`
3. **App #2 (Backend):** Register separately, add redirect URI `http://localhost:7071/backend-auth/callback`
4. Set environment variables in `local.settings.json`:
   ```json
   {
     "Values": {
       "MCP_AUTH_MODE": "entra",
       "MCP_AUTH_STRATEGY": "entra-direct",
       "MCP_EXPOSED_SCOPE": "Runtime.All",
       "AZURE_TENANT_ID": "your-tenant-id",
       "AZURE_CLIENT_ID": "app1-client-id",
       "BACKEND_CLIENT_ID": "app2-client-id",
       "BACKEND_CLIENT_SECRET": "app2-secret",
       "BACKEND_SCOPES": "api://app2-client-id/.default"
     }
   }
   ```
   Note: `AZURE_CLIENT_SECRET` is not needed for entra-direct (the proxy is just a resource server, not an OAuth AS).

## Local Development

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Running Locally

```bash
dotnet run
# Server starts on http://localhost:7071
```

### Testing the CIMD Flow

```bash
# 1. Check Protected Resource Metadata
curl http://localhost:7071/.well-known/oauth-protected-resource

# 2. Check OAuth Authorization Server Metadata
curl http://localhost:7071/.well-known/oauth-authorization-server

# 3. Start authorization (opens redirect)
curl -v "http://localhost:7071/oauth/authorize?response_type=code&client_id=https://client.example.dev/oauth/metadata.json&redirect_uri=https://client.example.dev/oauth/callback&scope=mcp.tools.execute&state=test123"

# 4. Exchange code for token
curl -X POST http://localhost:7071/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=<AUTH_CODE>&client_id=https://client.example.dev/oauth/metadata.json"

# 5. Use token for MCP calls
curl -X POST http://localhost:7071/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}'
```

## Project Structure

```
mock-mcp-server/
├── McpServer.cs               # All server logic (MCP, OAuth/CIMD, SSE, backend auth)
├── Program.cs                 # ASP.NET Core host, route mapping, config loading
├── MockMcpServer.csproj       # Project file (.NET 8 Web SDK)
├── local.settings.json        # Local dev settings (auth mode, credentials)
├── samplecalls.http           # HTTP test file for VS Code REST Client
├── APIHUB_MCP_INTEGRATION.md  # Architecture, requirements, and demo script
└── README.md
```

## License

MIT
