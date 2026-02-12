# MCP Integration for APIHub Runtime — Architecture, Requirements & Demo Script

## Executive Summary

This document captures the architecture, requirements, design decisions, and tradeoffs for integrating MCP (Model Context Protocol) support into APIHub runtime using APIM as a proxy for backend connectors. It is based on a working proof-of-concept that demonstrates CIMD-based client authentication, two-part OAuth flows, SSE notifications, and progressive tool discovery — all patterns needed for production deployment.

The POC is a .NET 8 ASP.NET Core server that models the exact HTTP interactions an MCP client (VS Code) performs against an MCP proxy. It validates real Entra ID integration with two separate AAD apps.

---

## 1. Architecture Overview

### Current Architecture (POC)

```
┌─────────────────┐                    ┌──────────────────────────────────────┐
│   MCP Client    │                    │         MCP Proxy (APIHub)           │
│   (VS Code)     │                    │                                      │
│                 │   ① CIMD OAuth     │  ┌─────────────────────┐             │
│  ┌───────────┐  │ ──────────────────→│  │  AAD App #1 (Proxy) │             │
│  │  OAuth    │  │   proxy token      │  │  - CIMD validation  │             │
│  │  Client   │  │ ←──────────────────│  │  - Token issuance   │             │
│  └───────────┘  │                    │  └─────────────────────┘             │
│                 │                    │                                      │
│  ┌───────────┐  │   ② tools/list     │  ┌─────────────────────┐             │
│  │  MCP      │  │ ──────────────────→│  │  Tool Gateway       │             │
│  │  Protocol │  │   [discover_tools] │  │  - Progressive list │             │
│  │  Client   │  │ ←──────────────────│  │  - Auth gating      │             │
│  └───────────┘  │                    │  └─────────────────────┘             │
│                 │                    │                                      │
│  ┌───────────┐  │   ③ Backend Auth   │  ┌─────────────────────┐             │
│  │  Browser  │  │ ──── (user) ──────→│  │  AAD App #2 (Backend)│            │
│  │  (Entra)  │  │   (server-side)    │  │  - Per-connector auth│            │
│  └───────────┘  │                    │  │  - Token stored      │            │
│                 │                    │  └─────────────────────┘             │
│                 │   ④ SSE stream     │                                      │
│  ┌───────────┐  │ ←─── keepalive ────│  tools/list_changed notification    │
│  │  SSE      │  │ ←─── event ────────│  (after backend auth completes)     │
│  │  Listener │  │                    │                                      │
│  └───────────┘  │                    │                                      │
└─────────────────┘                    └──────────────────────────────────────┘
```

### Target Architecture (APIHub + APIM)

```
┌─────────────────┐     ┌──────────┐     ┌────────────────────┐     ┌─────────────┐
│   MCP Client    │────→│   APIM   │────→│   APIHub Runtime   │────→│  Backend    │
│   (VS Code,     │     │  Gateway │     │   (MCP Proxy)      │     │  Connectors │
│    Copilot,     │     │          │     │                    │     │  (REST APIs)│
│    CLI tools)   │←────│  SSE:    │←────│  - CIMD validation │←────│             │
│                 │     │  buffer- │     │  - OAuth proxy     │     │             │
│                 │     │  response│     │  - Tool registry   │     │             │
│                 │     │  =false  │     │  - Token vault     │     │             │
└─────────────────┘     └──────────┘     └────────────────────┘     └─────────────┘
```

---

## 2. Key Requirements

### 2.1 Client Authentication (CIMD)

**Requirement**: MCP clients authenticate to the proxy without pre-registration.

| Item | Detail |
|------|--------|
| **Protocol** | CIMD (Client ID Metadata Document) per [client.dev spec](https://client.dev/) |
| **client_id format** | A URL (e.g., `https://vscode.dev/oauth/client-metadata.json`) |
| **Discovery flag** | `client_id_metadata_document_supported: true` in OAuth AS metadata |
| **Validation** | Fetch CIMD from `client_id` URL, verify `client_id` match, check `redirect_uris` contains requested `redirect_uri` |
| **Loopback handling** | Per RFC 8252 §7.3, ignore port when matching loopback redirect URIs (`127.0.0.1`, `localhost`, `::1`) — VS Code uses dynamic ports |
| **Confidential client** | Proxy AAD app uses `client_secret` for Entra token exchange (proxy holds secret, client never sees it) |

**POC finding**: VS Code checks the `client_id_metadata_document_supported` flag in the Authorization Server Metadata to decide whether to use CIMD. Without it, VS Code falls through to DCR → manual client_id prompt.

**POC finding**: VS Code's CIMD document at `https://vscode.dev/oauth/client-metadata.json` lists loopback redirect URIs with a specific port. VS Code actually uses a *different* dynamic port at runtime. Strict URI matching fails — port-agnostic matching for loopback addresses is required.

### 2.2 Two-Part Authentication Model

**Requirement**: Separate proxy auth from backend connector auth.

| Phase | Purpose | Token | Visibility |
|-------|---------|-------|------------|
| **Part 1: Proxy Auth** | Authenticate the MCP client to the proxy | Proxy token (opaque, 64-char hex) | Client holds this token |
| **Part 2: Backend Auth** | Authenticate the user to backend connectors | Backend access + refresh tokens | Server-side only, never exposed to client |

**Why two parts?**
- Different AAD apps may have different audiences, scopes, and consent requirements
- Backend connectors may require per-connector consent that shouldn't block initial tool discovery
- Proxy token lifetime is independent of backend token lifetime
- Backend tokens can be refreshed server-side without client interaction

### 2.3 Progressive Tool Discovery

**Requirement**: Tools list expands after backend authentication.

| State | `tools/list` returns | `tools/call` behavior |
|-------|---------------------|----------------------|
| **Before backend auth** | `discover_tools` only | `discover_tools` returns auth URL; other tools return error |
| **After backend auth** | Full tools list (`echo`, `get_weather`, `calculate`, etc.) | Tools execute normally |

**POC finding**: VS Code caches `tools/list` results and does NOT automatically re-query after auth changes. The server must push a `notifications/tools/list_changed` event via SSE to trigger a refresh.

### 2.4 SSE Notifications (Streamable HTTP Transport)

**Requirement**: Server pushes notifications to connected MCP clients.

| Item | Detail |
|------|--------|
| **Transport** | MCP Streamable HTTP — `GET /mcp` with `Accept: text/event-stream` |
| **Connection** | Long-lived, held open by server with 30s keepalive comments |
| **Key event** | `notifications/tools/list_changed` — triggers client to re-call `tools/list` |
| **Trigger** | Sent after backend auth completes (via Entra callback or mock approval) |
| **APIM support** | ✅ APIM supports SSE on Classic/v2 tiers with `buffer-response="false"` policy |

**POC finding**: Azure Functions isolated worker model CANNOT support SSE — gRPC buffering between host and worker prevents streaming. This required migrating to plain ASP.NET Core.

**APIM requirement**: The `<forward-request>` policy must set `buffer-response="false"` for the SSE endpoint. Response logging/validation policies must also be disabled for this route.

### 2.5 Well-Known Endpoints (RFC 9728)

**Requirement**: Serve OAuth discovery metadata.

| Endpoint | Purpose | Key fields |
|----------|---------|------------|
| `GET /.well-known/oauth-protected-resource` | Protected Resource Metadata (PRM) | `resource` (MUST match the MCP endpoint URL), `authorization_servers`, `scopes_supported` |
| `GET /.well-known/oauth-authorization-server` | Authorization Server Metadata | `authorization_endpoint`, `token_endpoint`, `client_id_metadata_document_supported` |

**POC finding**: The PRM `resource` property MUST exactly match the URL the client uses to access the protected resource. For an MCP server at `https://host/mcp`, the resource must be `https://host/mcp` (not just `https://host/`). VS Code validates this per RFC 9728.

**POC finding**: Some MCP clients request PRM at both `/.well-known/oauth-protected-resource` AND `/.well-known/oauth-protected-resource/mcp` (appending the resource path). The server should serve the same metadata on both routes.

### 2.6 Token Management

**Requirement**: Manage proxy and backend tokens independently.

| Token | Storage | Lifetime | Refresh |
|-------|---------|----------|---------|
| **Proxy token** | In-memory map (token → client metadata) | Configurable (default: 3600s) | Client re-authenticates via OAuth |
| **Backend access token** | In-memory map (proxy token → backend tokens) | Per-connector, typically 3600s | Server-side refresh using stored refresh token |
| **Backend refresh token** | In-memory map (server-side) | Long-lived | Entra ID manages rotation |

**Production requirement**: Replace in-memory `ConcurrentDictionary` stores with a persistent, distributed token vault (Redis, Cosmos DB, or Azure Key Vault). In-memory stores are lost on process restart.

---

## 3. Design Decisions & Tradeoffs

### 3.1 CIMD vs. Dynamic Client Registration (DCR)

| Factor | CIMD | DCR |
|--------|------|-----|
| **Registration** | None — stateless, based on fetching a URL | Requires `POST /register` endpoint and client storage |
| **Identity verification** | URL ownership (DNS-based trust) | Registration secret |
| **Open ecosystem** | ✅ Any client can connect | ❌ Requires pre-registration |
| **MCP spec support** | ✅ Primary recommendation | ✅ Fallback option |
| **Revocation** | Domain/URL allowlists | Revoke registration |

**Decision**: Use CIMD as the primary client identity mechanism. It enables the open MCP ecosystem model where any client can connect without prior registration.

**Tradeoff**: CIMD relies on DNS/URL trust — a compromised domain could impersonate a client. Mitigate with domain allowlists in production.

### 3.2 Confidential vs. Public Client Flow

| Factor | Confidential (chosen) | Public (PKCE-only) |
|--------|----------------------|-------------------|
| **Secret** | Proxy holds `client_secret` | No secret, uses PKCE code_verifier |
| **AAD app type** | Web platform redirect URI | SPA or Mobile platform |
| **Security** | Higher — secret is server-side | Lower — relies on PKCE alone |
| **Entra support** | ✅ Standard | ⚠️ Requires specific platform config in Azure Portal |

**Decision**: Proxy uses confidential client flow. The `client_secret` is held server-side, never exposed to the MCP client.

**POC finding**: Attempting PKCE-only with an AAD app configured with a "Web" platform redirect URI results in `AADSTS7000218: client_assertion or client_secret required`. The Azure Portal app platform type matters.

### 3.3 Token Architecture: Proxy vs. Pass-Through

| Factor | Proxy tokens (chosen) | Pass-through Entra tokens |
|--------|----------------------|--------------------------|
| **Token format** | Opaque hex string | JWT from Entra ID |
| **Validation** | Server-side lookup | JWT signature verification |
| **Client coupling** | Low — client unaware of Entra | High — client sees Entra details |
| **Backend auth** | Decoupled via server-side token mapping | Tightly coupled |
| **Scalability** | Requires shared token store | Stateless (JWT self-contained) |

**Decision**: Issue opaque proxy tokens. This decouples the client from Entra details and allows the proxy to independently manage backend tokens.

**Tradeoff**: Requires a shared, persistent token store in a multi-instance deployment. Consider JWT-based proxy tokens for stateless validation if horizontal scaling is a priority.

### 3.4 Auth Strategy: CIMD vs. Entra-Direct

| Factor | CIMD (proxy is OAuth AS) | Entra-Direct (PRM → Entra ID) |
|--------|-------------------------|-------------------------------|
| **Auth server** | Proxy acts as OAuth AS | Entra ID is the AS |
| **Client identity** | CIMD URL (any client) | VS Code's Entra client ID |
| **User experience** | Browser popup (Entra login) | Silent via WAM (no popup) |
| **Client compatibility** | Any MCP client | Only Entra-registered clients (VS Code) |
| **Client secret needed** | Yes (proxy exchanges code for token) | No (proxy is just a resource server) |
| **CIMD allowlist** | Proxy controls it | N/A (Entra pre-auth controls it) |

**Decision**: Support both via `MCP_AUTH_STRATEGY` toggle. CIMD for universal client compatibility; entra-direct for best UX with VS Code.

**Production recommendation**: A hybrid approach where the proxy accepts tokens from both sources — Entra JWTs (for VS Code/WAM) and proxy-issued tokens (for CIMD clients).

### 3.5 Progressive vs. Full Tool Listing

| Factor | Progressive (chosen) | Full listing |
|--------|---------------------|-------------|
| **Initial response** | Only `discover_tools` | All tools visible |
| **Backend auth trigger** | Calling `discover_tools` | Calling any tool |
| **Client UX** | Clear auth intent | May confuse users seeing tools they can't use |
| **SSE dependency** | Required — must notify to refresh list | Not needed |

**Decision**: Progressive tool discovery with SSE notifications. This models the real-world APIHub pattern where different connectors require different auth.

**Tradeoff**: Requires SSE support, which adds complexity. Without SSE, VS Code does NOT refresh `tools/list` after auth changes — the tools panel stays stale.

### 3.6 Hosting: Azure Functions vs. ASP.NET Core

| Factor | Azure Functions | ASP.NET Core (chosen) |
|--------|----------------|----------------------|
| **SSE support** | ❌ Buffered via gRPC | ✅ Native Kestrel streaming |
| **Deployment** | Serverless, auto-scale | Requires hosting (App Service, Container) |
| **Local dev** | `func start` | `dotnet run` |
| **APIM compatibility** | Backend can be Functions | Backend can be anything |

**Decision**: Migrated to ASP.NET Core for SSE support. In production, the backend behind APIM can be any technology — APIM handles SSE passthrough with `buffer-response="false"`.

---

## 4. Impact on Customer Usage

### 4.1 Customer Experience: What Changes

**Before (no MCP)**:
- Customer configures connectors via portal
- Authentication flows happen at connection creation time
- Tools are fixed per connector

**After (with MCP)**:
- Customer adds MCP server URL in their client (VS Code, CLI tool)
- First tool invocation triggers automatic authentication (browser popup, once)
- Tools discovered dynamically, expand after consent
- No manual registration, no client_id configuration needed (CIMD handles this)

### 4.2 Customer Configuration

Customers need to configure **only one thing**: the MCP server URL.

```json
// VS Code settings.json
{
  "mcp": {
    "servers": {
      "apihub": {
        "url": "https://mcp.contoso.com/mcp"
      }
    }
  }
}
```

Everything else is automatic:
1. Client discovers auth endpoints via PRM (`.well-known/oauth-protected-resource`)
2. Client uses CIMD — no client_id to configure
3. Browser opens for Entra login — SSO with existing Microsoft account
4. After consent, tools appear automatically (SSE notification refreshes the list)

### 4.3 Authentication UX Flow (What the Customer Sees)

```
1. Customer adds MCP server URL
2. VS Code shows "Signing in..." → browser opens → Entra login page
3. Customer signs in with Microsoft account (SSO if already signed in)
4. Browser shows "Authorization Complete, close this window"
5. VS Code shows 1 tool: discover_tools
6. Customer (or AI) calls discover_tools → browser opens → backend consent
7. Customer approves → browser shows success → close window
8. VS Code automatically refreshes → shows all tools (echo, get_weather, etc.)
9. Tools work seamlessly from this point forward
```

### 4.4 Failure Modes & Error Handling

| Scenario | Customer sees | Server behavior |
|----------|--------------|-----------------|
| Invalid/expired proxy token | "Signing in..." (auto re-auth) | 401 with `WWW-Authenticate` header triggers OAuth flow |
| Backend auth expired | Error message suggesting to call `discover_tools` | Proxy can server-side refresh using stored refresh token |
| Server restart (POC) | Tools list resets, must re-auth | In-memory stores cleared (mitigated by persistent storage in production) |
| CIMD fetch failure | Auth fails, client prompts for manual client_id | Server returns OAuth error, client falls back to DCR/manual |
| SSE disconnection | Tools list may become stale | Client automatically reconnects SSE stream |

---

## 5. APIM-Specific Requirements

### 5.1 APIM Policy Configuration

```xml
<!-- SSE endpoint: disable buffering -->
<policies>
  <inbound>
    <base />
  </inbound>
  <backend>
    <forward-request timeout="240" buffer-response="false" />
  </backend>
  <outbound>
    <base />
    <!-- Do NOT use validate-content or log-to-eventhub for SSE routes -->
  </outbound>
</policies>
```

### 5.2 APIM Route Mapping

| Route | APIM operation | Backend | Notes |
|-------|---------------|---------|-------|
| `GET /.well-known/oauth-protected-resource` | Passthrough | APIHub | Public, no auth |
| `GET /.well-known/oauth-authorization-server` | Passthrough | APIHub | Public, no auth |
| `GET /oauth/authorize` | Passthrough | APIHub | Initiates OAuth, returns 302 |
| `GET /oauth/callback` | Passthrough | APIHub | Receives Entra redirect |
| `POST /oauth/token` | Passthrough | APIHub | Token exchange |
| `GET /mcp` | **SSE passthrough** | APIHub | `buffer-response="false"`, long-lived |
| `POST /mcp` | Passthrough | APIHub | MCP JSON-RPC (initialize, tools/list, tools/call) |
| `GET /backend-auth/*` | Passthrough | APIHub | Backend connector auth flows |

### 5.3 APIM Tier Requirement

- **Consumption tier**: ❌ Does NOT support SSE / long-lived connections
- **Classic / v2 tier**: ✅ Supports SSE with `buffer-response="false"`
- **Idle timeout**: Azure load balancer enforces 4-minute idle timeout → keepalive comments every 30s mitigates this

---

## 6. Demo Script

### Prerequisites
- .NET 8 SDK
- Two AAD app registrations (App #1 for proxy, App #2 for backend)
- VS Code with MCP support

### Setup

```bash
# Clone and configure
git clone <repo-url>
cd mock-mcp-server

# Edit local.settings.json with your AAD app credentials
# See "Configuration" section in README.md

# Start the server
dotnet run
# Server starts on http://localhost:7071
```

### Demo Flow

#### Step 1: Show the Well-Known Endpoints

```bash
# Protected Resource Metadata
curl -s http://localhost:7071/.well-known/oauth-protected-resource | jq .

# OAuth Authorization Server Metadata — note client_id_metadata_document_supported: true
curl -s http://localhost:7071/.well-known/oauth-authorization-server | jq .
```

**Talking point**: "These are standard OAuth discovery endpoints. The key field is `client_id_metadata_document_supported: true` — this tells MCP clients they can use CIMD for authentication without pre-registration."

#### Step 2: Add MCP Server in VS Code

Add to VS Code `settings.json`:
```json
{
  "mcp": {
    "servers": {
      "demo-mcp": {
        "url": "http://localhost:7071/mcp"
      }
    }
  }
}
```

**What happens automatically**:
1. VS Code discovers PRM at `/.well-known/oauth-protected-resource`
2. VS Code discovers auth server at `/.well-known/oauth-authorization-server`
3. VS Code sees `client_id_metadata_document_supported: true` → uses CIMD
4. VS Code fetches its CIMD from `https://vscode.dev/oauth/client-metadata.json`
5. Browser opens → Entra login → proxy token issued
6. VS Code opens SSE connection on `GET /mcp`
7. VS Code calls `initialize`, `tools/list` → sees `discover_tools`

**Talking point**: "The customer only configured a URL. No client_id, no secret, no registration. CIMD handled the client identity automatically."

#### Step 3: Show Progressive Tool Discovery

In VS Code chat, ask to use the `discover_tools` tool.

**What happens**:
1. VS Code calls `tools/call` with `discover_tools`
2. Server returns elicitation with backend auth URL
3. VS Code shows the auth URL to the user
4. User clicks link → browser opens → Entra login for App #2
5. Server stores backend tokens server-side
6. Server pushes `notifications/tools/list_changed` via SSE
7. VS Code automatically re-calls `tools/list`
8. Tools panel now shows `echo`, `get_weather`, `calculate`

**Talking point**: "Backend authentication is completely separate from proxy auth. The client never sees the backend tokens. After consent, the SSE notification automatically refreshes the tools list — no manual refresh needed."

#### Step 4: Use a Tool

Ask the AI to use the `echo` tool or `get_weather` tool.

**Talking point**: "From this point forward, tool calls work seamlessly. The proxy resolves the backend token server-side and forwards the request. The client only ever uses the proxy token."

#### Step 5: Demo CIMD Client Policy

```bash
# Show current policy (open by default)
curl -s http://localhost:7071/cimd-policy | jq .

# Switch to allowlist mode (edit local.settings.json):
# "CIMD_POLICY_MODE": "allowlist"
# "CIMD_ALLOWED_CLIENTS": "https://vscode.dev/oauth/client-metadata.json;*.github.com"
# Restart server

# Verify policy is active
curl -s http://localhost:7071/cimd-policy | jq .

# Test with a blocked client — returns 400 access_denied without fetching CIMD
curl -v "http://localhost:7071/oauth/authorize?response_type=code&client_id=https://evil.example.com/cimd.json&redirect_uri=http://127.0.0.1:50705/&state=test"

# VS Code still works because vscode.dev is in the allowlist
```

**Talking point**: "Environment admins can control which MCP clients are permitted. The policy check happens *before* the CIMD document is fetched — an untrusted client_id URL never triggers an outbound HTTP request. This is critical for SSRF prevention in a multi-tenant proxy."

#### Step 6: Show Server Logs

Show the terminal with colored server logs demonstrating:
- CIMD policy evaluation (allowed/denied with matched rule)
- CIMD fetch and validation
- Entra token exchange (confidential client)
- SSE connection registration
- Backend auth flow (separate AAD app)
- SSE notification push
- Tool execution with backend token resolution

---

## 7. Open Questions for Production

| # | Question | Options | Recommendation |
|---|----------|---------|----------------|
| 1 | **Token persistence** | Redis, Cosmos DB, SQL | Redis for low-latency token lookup; Cosmos DB for global distribution |
| 2 | **Multi-instance SSE** | Redis Pub/Sub, Azure SignalR, Service Bus | Redis Pub/Sub for SSE event fan-out across instances |
| 3 | **Per-connector auth** | Single backend AAD app vs. per-connector apps | Per-connector apps for granular consent; single app with scopes for simplicity |
| 4 | **Token refresh** | Proactive (background) vs. reactive (on failure) | Proactive refresh 5 min before expiry to avoid tool call failures |
| 5 | **CIMD allowlisting** | Open (any client) vs. allowlist (known clients only) | ✅ **Implemented** — `CIMD_POLICY_MODE` supports `open`/`allowlist`/`denylist` with exact URL, domain, and wildcard matching. Policy checked before CIMD fetch (SSRF prevention). |
| 6 | **Scope mapping** | `api://{app}/.default` vs. granular scopes | Granular scopes per connector for least-privilege access |
| 7 | **Rate limiting** | APIM policies vs. application-level | APIM rate limiting per subscription + per-user throttling at app level |
| 8 | **SSE reconnection** | Client-managed vs. session resume | Clients manage reconnection; server maintains token state across reconnects |
| 9 | **Proxy token format** | Opaque (current) vs. JWT | JWT for stateless validation at APIM layer; opaque for backend flexibility |
| 10 | **MCP protocol version** | `2024-11-05` vs. `2025-03-26` | Upgrade to `2025-03-26` for Streamable HTTP transport support |

---

## 8. Files Reference

| File | Purpose |
|------|---------|
| `McpServer.cs` | All server logic — MCP protocol, OAuth/CIMD, backend auth, SSE, tool execution |
| `Program.cs` | ASP.NET Core minimal API host, route mapping, config loading |
| `MockMcpServer.csproj` | Project file (ASP.NET Core Web SDK, .NET 8) |
| `local.settings.json` | Configuration (auth mode, AAD app credentials, scopes) |
| `samplecalls.http` | HTTP test file for manual testing with VS Code REST Client |
| `README.md` | Project documentation |
| `APIHUB_MCP_INTEGRATION.md` | This document |
