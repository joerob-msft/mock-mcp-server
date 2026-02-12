using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace MockMcpServer;

public class McpServer
{
    private readonly ILogger<McpServer> _logger;

    // ANSI color codes for terminal output
    private const string CYAN = "\u001b[36m";
    private const string GREEN = "\u001b[32m";
    private const string YELLOW = "\u001b[33m";
    private const string MAGENTA = "\u001b[35m";
    private const string RED = "\u001b[31m";
    private const string BOLD = "\u001b[1m";
    private const string RESET = "\u001b[0m";
    
    // Set to true for verbose logging (all headers), false for concise
    private static readonly bool VerboseLogging = 
        Environment.GetEnvironmentVariable("MCP_VERBOSE_LOGGING")?.ToLower() == "true";

    public McpServer(ILogger<McpServer> logger)
    {
        _logger = logger;
    }

    private record AuthSession(
        string ClientId, string RedirectUri, string Scope, string State,
        string? EntraState, string? CodeVerifier,
        string? AuthCode, string? EntraAccessToken, DateTime CreatedAt, bool IsRedeemed);

    // In-memory auth session store - maps state/code to auth sessions
    private static readonly ConcurrentDictionary<string, AuthSession> _authSessions = new();
    // In-memory token store - maps access tokens to their metadata
    private static readonly ConcurrentDictionary<string, TokenRecord> _tokenStore = new();
    private record TokenRecord(string AccessToken, string ClientId, string Scope, DateTime IssuedAt, int ExpiresIn);

    private static readonly HttpClient _httpClient = new();

    // Auth mode: "mock" (default) or "entra"
    private static readonly string AuthMode =
        Environment.GetEnvironmentVariable("MCP_AUTH_MODE")?.ToLower() ?? "mock";

    // Auth strategy: "cimd" (default, proxy is OAuth AS) or "entra-direct" (PRM points to Entra ID)
    private static readonly string AuthStrategy =
        Environment.GetEnvironmentVariable("MCP_AUTH_STRATEGY")?.ToLower() ?? "cimd";

    // Exposed scope name on the AAD app (used in entra-direct mode PRM)
    private static readonly string ExposedScope =
        Environment.GetEnvironmentVariable("MCP_EXPOSED_SCOPE") ?? "Runtime.All";

    private static readonly string TenantId = Environment.GetEnvironmentVariable("AZURE_TENANT_ID") ?? "common";
    private static readonly string? AzureClientId = Environment.GetEnvironmentVariable("AZURE_CLIENT_ID");
    private static readonly string? AzureClientSecret = Environment.GetEnvironmentVariable("AZURE_CLIENT_SECRET");

    // Backend AAD App #2 config (the "real" MCP backend server's app)
    private static readonly string? BackendClientId = Environment.GetEnvironmentVariable("BACKEND_CLIENT_ID");
    private static readonly string? BackendClientSecret = Environment.GetEnvironmentVariable("BACKEND_CLIENT_SECRET");
    private static readonly string BackendTenantId = Environment.GetEnvironmentVariable("BACKEND_TENANT_ID") 
        ?? Environment.GetEnvironmentVariable("AZURE_TENANT_ID") ?? "common";
    private static readonly string BackendScopes = string.IsNullOrEmpty(Environment.GetEnvironmentVariable("BACKEND_SCOPES")) 
        ? "openid profile offline_access" : Environment.GetEnvironmentVariable("BACKEND_SCOPES")!;

    // CIMD policy configuration
    private static readonly string CimdPolicyMode =
        Environment.GetEnvironmentVariable("CIMD_POLICY_MODE")?.ToLower() ?? "open";
    private static readonly string[] CimdAllowedClients =
        (Environment.GetEnvironmentVariable("CIMD_ALLOWED_CLIENTS") ?? "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    private static readonly string[] CimdDeniedClients =
        (Environment.GetEnvironmentVariable("CIMD_DENIED_CLIENTS") ?? "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    // Static reference for sidecar manager (set after DI build)
    internal static BackendSseManager? SseManager;

    // Backend auth store - maps proxy tokens to backend auth state
    internal static readonly ConcurrentDictionary<string, BackendAuthRecord> _backendAuthStore = new();
    // Pending backend auth sessions - maps state param to pending session
    private static readonly ConcurrentDictionary<string, BackendAuthPending> _backendAuthPending = new();

    internal record BackendAuthRecord(
        string ProxyToken, string BackendAccessToken, string? BackendRefreshToken,
        DateTime IssuedAt, int ExpiresIn);

    private record BackendAuthPending(
        string ProxyToken, string State, DateTime CreatedAt);

    // SSE connections - maps proxy tokens to active SSE connections
    private static readonly ConcurrentDictionary<string, SseConnection> _sseConnections = new();

    private class SseConnection
    {
        public HttpResponse Response { get; init; } = null!;
        public CancellationToken RequestAborted { get; init; }
    }

    // In Entra mode, scopes must reference the AAD app's resource URI
    private static string GetScopesSupported() =>
        AuthStrategy == "entra-direct" && !string.IsNullOrEmpty(AzureClientId)
            ? $"api://{AzureClientId}/{ExposedScope}"
            : AuthMode == "entra" && !string.IsNullOrEmpty(AzureClientId)
                ? $"api://{AzureClientId}/.default"
                : "mcp.tools.execute";

    /// <summary>
    /// Sends SSE notification for tools/list_changed to a connected client.
    /// </summary>
    public static async Task NotifyToolsChanged(string proxyToken)
    {
        var data = JsonSerializer.Serialize(new { jsonrpc = "2.0", method = "notifications/tools/list_changed" });
        await NotifyClient(proxyToken, data);
    }

    /// <summary>
    /// Sends an arbitrary SSE notification to a connected client.
    /// Used by BackendSseManager to relay backend notifications.
    /// </summary>
    public static async Task NotifyClient(string proxyToken, string notificationJson)
    {
        if (_sseConnections.TryGetValue(proxyToken, out var conn))
        {
            try
            {
                if (!conn.RequestAborted.IsCancellationRequested)
                {
                    await conn.Response.WriteAsync($"event: message\ndata: {notificationJson}\n\n", conn.RequestAborted);
                    await conn.Response.Body.FlushAsync(conn.RequestAborted);
                    Console.WriteLine($"{GREEN}   ✓ SSE notification relayed to client{RESET}");
                }
            }
            catch (OperationCanceledException)
            {
                // Client disconnected
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{RED}   ✗ SSE notification relay error: {ex.Message}{RESET}");
            }
        }
    }

    /// <summary>
    /// Checks if a token is a valid backend access token.
    /// </summary>
    internal static bool IsValidBackendToken(string token)
    {
        return _backendAuthStore.Values.Any(r => r.BackendAccessToken == token);
    }

    /// <summary>
    /// Finds the proxy token associated with a backend access token.
    /// </summary>
    internal static string? FindProxyTokenByBackendToken(string backendToken)
    {
        var record = _backendAuthStore.Values.FirstOrDefault(r => r.BackendAccessToken == backendToken);
        return record?.ProxyToken;
    }

    /// <summary>
    /// GET /mcp - MCP root endpoint
    /// Returns 200 if valid bearer token with correct audience is provided.
    /// Returns 401 with PRM pointer if no token or invalid token.
    /// Supports SSE when Accept: text/event-stream is present.
    /// </summary>
    public async Task HandleMcpGet(HttpContext context)
    {
        await LogRequestDetails(context, "GET");

        // Validate bearer token
        var (isValid, tokenError) = ValidateBearerToken(context);
        
        if (!isValid)
        {
            // Return 401 with WWW-Authenticate header pointing to PRM
            Console.WriteLine($"{RED}   ✗ Token validation failed: {tokenError}{RESET}");
            
            context.Response.StatusCode = 401;
            context.Response.Headers["Content-Type"] = "application/json";
            
            var baseUrl = GetBaseUrl(context);
            context.Response.Headers["WWW-Authenticate"] = $"Bearer resource_metadata=\"{baseUrl}/.well-known/oauth-protected-resource\"";

            var errorBody = new
            {
                error = "unauthorized",
                error_description = tokenError ?? "Authentication required"
            };

            await context.Response.WriteAsync(JsonSerializer.Serialize(errorBody, new JsonSerializerOptions 
            { 
                WriteIndented = true 
            }));

            LogResponse("GET /mcp", 401, tokenError ?? "Auth required - see WWW-Authenticate header");
            return;
        }

        Console.WriteLine($"{GREEN}   ✓ Bearer token validated{RESET}");

        // Check if client wants SSE stream (Streamable HTTP transport)
        var acceptHeader = context.Request.Headers.TryGetValue("Accept", out var acceptValues) 
            ? string.Join(",", acceptValues.ToArray()) : "";
        
        if (acceptHeader.Contains("text/event-stream"))
        {
            // SSE notification stream
            Console.WriteLine($"{CYAN}   ℹ SSE stream requested — opening persistent connection{RESET}");

            var proxyToken = ExtractBearerToken(context);
            if (proxyToken == null)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Missing bearer token for SSE");
                return;
            }

            context.Response.StatusCode = 200;
            context.Response.Headers["Content-Type"] = "text/event-stream";
            context.Response.Headers["Cache-Control"] = "no-cache";
            context.Response.Headers["Connection"] = "keep-alive";
            await context.Response.Body.FlushAsync();

            // Register the SSE connection
            var conn = new SseConnection
            {
                Response = context.Response,
                RequestAborted = context.RequestAborted
            };
            _sseConnections[proxyToken] = conn;
            Console.WriteLine($"{GREEN}   ✓ SSE connection registered for token: {proxyToken[..Math.Min(8, proxyToken.Length)]}...{RESET}");

            try
            {
                // Send keepalive comments every 30 seconds until client disconnects
                while (!context.RequestAborted.IsCancellationRequested)
                {
                    await Task.Delay(30_000, context.RequestAborted);
                    await context.Response.WriteAsync(": keepalive\n\n", context.RequestAborted);
                    await context.Response.Body.FlushAsync(context.RequestAborted);
                }
            }
            catch (OperationCanceledException)
            {
                // Client disconnected — expected
            }
            finally
            {
                _sseConnections.TryRemove(proxyToken, out _);
                Console.WriteLine($"{YELLOW}   ⚠ SSE connection closed for token: {proxyToken[..Math.Min(8, proxyToken.Length)]}...{RESET}");
            }
            return;
        }

        context.Response.StatusCode = 200;
        context.Response.Headers["Content-Type"] = "application/json";

        var responseBody = new
        {
            status = "ok",
            message = "MCP server ready",
            serverInfo = new
            {
                name = "mock-mcp-server",
                version = "1.0.0"
            }
        };

        await context.Response.WriteAsync(JsonSerializer.Serialize(responseBody, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        }));

        LogResponse("GET /mcp", 200, "Authenticated");
    }

    /// <summary>
    /// GET /.well-known/oauth-protected-resource[/mcp] - Protected Resource Metadata
    /// </summary>
    public async Task HandlePRM(HttpContext context)
    {
        await LogRequestDetails(context, "GET");

        var baseUrl = GetBaseUrl(context);
        var resourceUrl = $"{baseUrl}/mcp";
        context.Response.StatusCode = 200;
        context.Response.Headers["Content-Type"] = "application/json";

        // In entra-direct mode, point to Entra ID as the authorization server
        var authServers = AuthStrategy == "entra-direct"
            ? new[] { $"https://login.microsoftonline.com/{TenantId}/v2.0" }
            : new[] { baseUrl };

        var metadata = new
        {
            resource = resourceUrl,
            authorization_servers = authServers,
            scopes_supported = new[] { GetScopesSupported() }
        };

        await context.Response.WriteAsync(JsonSerializer.Serialize(metadata, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        }));

        LogResponse("GET /.well-known/oauth-protected-resource", 200, $"resource={resourceUrl}");
    }

    /// <summary>
    /// GET /.well-known/oauth-authorization-server - OAuth Authorization Server Metadata
    /// </summary>
    public async Task HandleAuthServerMetadata(HttpContext context)
    {
        await LogRequestDetails(context, "GET");

        var baseUrl = GetBaseUrl(context);
        context.Response.StatusCode = 200;
        context.Response.Headers["Content-Type"] = "application/json";

        var metadata = new
        {
            issuer = baseUrl,
            authorization_endpoint = $"{baseUrl}/oauth/authorize",
            token_endpoint = $"{baseUrl}/oauth/token",
            response_types_supported = new[] { "code" },
            grant_types_supported = new[] { "authorization_code" },
            code_challenge_methods_supported = new[] { "S256" },
            token_endpoint_auth_methods_supported = new[] { "none" },
            scopes_supported = new[] { GetScopesSupported() },
            client_id_metadata_document_supported = true
        };

        await context.Response.WriteAsync(JsonSerializer.Serialize(metadata, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        }));

        LogResponse("GET /.well-known/oauth-authorization-server", 200, $"issuer={baseUrl}");
    }

    /// <summary>
    /// POST /mcp - Main MCP API endpoint
    /// </summary>
    public async Task HandleMcpPost(HttpContext context)
    {
        await LogRequestDetails(context, "POST");

        // Read and parse the request body first to determine the method
        string requestBody = await new StreamReader(context.Request.Body).ReadToEndAsync();

        string method = "unknown";
        int? requestId = null;
        string? toolName = null;
        JsonElement? toolArguments = null;

        try
        {
            using var jsonDoc = JsonDocument.Parse(requestBody);
            if (jsonDoc.RootElement.TryGetProperty("method", out var methodElement))
                method = methodElement.GetString() ?? "unknown";
            if (jsonDoc.RootElement.TryGetProperty("id", out var idElement))
            {
                if (idElement.ValueKind == JsonValueKind.Number)
                    requestId = idElement.GetInt32();
                else if (idElement.ValueKind == JsonValueKind.String && int.TryParse(idElement.GetString(), out var parsedId))
                    requestId = parsedId;
            }
            if (method == "tools/call" && jsonDoc.RootElement.TryGetProperty("params", out var paramsElement))
            {
                if (paramsElement.TryGetProperty("name", out var nameElement))
                    toolName = nameElement.GetString();
                if (paramsElement.TryGetProperty("arguments", out var argsElement))
                    toolArguments = argsElement.Clone();
            }
            LogMcpMethod(method, requestId, toolName);
            if (VerboseLogging && toolArguments.HasValue)
                Console.WriteLine($"{MAGENTA}   Args: {toolArguments.Value}{RESET}");
        }
        catch (JsonException ex)
        {
            Console.WriteLine($"{YELLOW}   ⚠ JSON parse error: {ex.Message}{RESET}");
        }

        // Methods that require authentication
        var requiresAuth = method is "tools/call";

        if (requiresAuth)
        {
            var (isValid, tokenError) = ValidateBearerToken(context);
            if (!isValid)
            {
                Console.WriteLine($"{RED}   ✗ Token validation failed: {tokenError}{RESET}");
                await WriteUnauthorizedResponse(context, tokenError ?? "Invalid or missing token");
                return;
            }
            Console.WriteLine($"{GREEN}   ✓ Bearer token validated{RESET}");
        }
        else
        {
            Console.WriteLine($"{CYAN}   ℹ Method '{method}' does not require auth{RESET}");
        }

        context.Response.StatusCode = 200;
        context.Response.Headers["Content-Type"] = "application/json";

        // Generate response based on the method
        object responseBody = method switch
        {
            "initialize" => new
            {
                jsonrpc = "2.0",
                result = new
                {
                    protocolVersion = "2024-11-05",
                    capabilities = new
                    {
                        tools = new { listChanged = true },
                        resources = new { subscribe = false, listChanged = false },
                        prompts = new { listChanged = false }
                    },
                    serverInfo = new
                    {
                        name = "mock-mcp-server",
                        version = "1.0.0"
                    }
                },
                id = requestId ?? 1
            },
            "tools/list" => await GenerateToolsListResponseAsync(requestId, context),
            "tools/call" => await GenerateToolCallResponseAsync(toolName, toolArguments, requestId, context),
            "resources/list" => new
            {
                jsonrpc = "2.0",
                result = new
                {
                    resources = Array.Empty<object>()
                },
                id = requestId ?? 1
            },
            "prompts/list" => new
            {
                jsonrpc = "2.0",
                result = new
                {
                    prompts = Array.Empty<object>()
                },
                id = requestId ?? 1
            },
            _ => new
            {
                jsonrpc = "2.0",
                result = new
                {
                    message = $"Mock response for method: {method}"
                },
                id = requestId ?? 1
            }
        };

        var jsonResponse = JsonSerializer.Serialize(responseBody, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        });
        
        if (VerboseLogging)
        {
            Console.WriteLine($"{GREEN}   Response: {jsonResponse}{RESET}");
        }
        await context.Response.WriteAsync(jsonResponse);

        LogResponse($"POST /mcp ({method})", 200, toolName != null ? $"tool={toolName}" : null);
    }

    private async Task LogRequestDetails(HttpContext context, string httpMethod)
    {
        var authHeader = context.Request.Headers.TryGetValue("Authorization", out var authVals) 
            ? (authVals.FirstOrDefault()?.StartsWith("Bearer ") == true ? "Bearer [token]" : authVals.FirstOrDefault()) 
            : "none";
        
        var path = context.Request.Path.Value;
        var fullUrl = $"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}";
        
        Console.WriteLine($"\n{CYAN}{BOLD}▶▶▶ INCOMING {httpMethod} {path}{RESET}");
        Console.WriteLine($"{CYAN}   URL: {fullUrl}{RESET}");
        Console.WriteLine($"{CYAN}   Auth: {authHeader}{RESET}");
        
        if (VerboseLogging)
        {
            Console.WriteLine($"{CYAN}   Headers:{RESET}");
            foreach (var header in context.Request.Headers)
            {
                if (header.Key.ToLower() != "authorization")
                {
                    Console.WriteLine($"{CYAN}     {header.Key}: {string.Join(", ", header.Value.ToArray())}{RESET}");
                }
            }
        }
        
        await Task.CompletedTask;
    }
    
    private void LogResponse(string method, int statusCode, string? summary = null)
    {
        var color = statusCode >= 400 ? RED : GREEN;
        var arrow = statusCode >= 400 ? "✗" : "✓";
        Console.WriteLine($"{color}{BOLD}◀◀◀ RESPONSE {method} → {statusCode} {arrow}{RESET}");
        if (!string.IsNullOrEmpty(summary))
        {
            Console.WriteLine($"{color}   {summary}{RESET}");
        }
        Console.WriteLine();
    }
    
    private void LogMcpMethod(string method, int? requestId, string? toolName = null)
    {
        Console.WriteLine($"{MAGENTA}{BOLD}   ⚡ MCP Method: {method}{RESET}");
        if (requestId.HasValue)
            Console.WriteLine($"{MAGENTA}   Request ID: {requestId}{RESET}");
        if (!string.IsNullOrEmpty(toolName))
            Console.WriteLine($"{MAGENTA}   Tool: {toolName}{RESET}");
    }

    private async Task<object> GenerateToolsListResponseAsync(int? requestId, HttpContext context)
    {
        var proxyToken = ExtractBearerToken(context);
        var hasBackendAuth = proxyToken != null && _backendAuthStore.ContainsKey(proxyToken);
        
        if (VerboseLogging)
            Console.WriteLine($"{CYAN}   tools/list: proxyToken={proxyToken?[..Math.Min(8, proxyToken.Length)]}..., hasBackendAuth={hasBackendAuth}, backendAuthStoreKeys={_backendAuthStore.Count}{RESET}");
        
        if (hasBackendAuth)
        {
            if (VerboseLogging)
                Console.WriteLine($"{GREEN}   Backend auth found - forwarding tools/list to backend{RESET}");

            var backendResult = await ForwardToBackend(proxyToken!, "tools/list", null, requestId);
            if (backendResult != null) return backendResult;

            // Fallback to local if backend unreachable
            Console.WriteLine($"{YELLOW}   ⚠ Backend unreachable, falling back to local tools list{RESET}");
            return new
            {
                jsonrpc = "2.0",
                result = new
                {
                    tools = GetFullToolsList()
                },
                id = requestId ?? 1
            };
        }
        
        if (VerboseLogging)
            Console.WriteLine($"{YELLOW}   No backend auth - returning discover_tools only{RESET}");
        return new
        {
            jsonrpc = "2.0",
            result = new
            {
                tools = new object[]
                {
                    new
                    {
                        name = "discover_tools",
                        description = "Authorizes access and discovers available tools. Call this first to unlock the full set of tools after completing the consent flow.",
                        inputSchema = new
                        {
                            type = "object",
                            properties = new Dictionary<string, object>(),
                            required = Array.Empty<string>()
                        }
                    }
                }
            },
            id = requestId ?? 1
        };
    }

    private object[] GetFullToolsList()
    {
        return new object[]
        {
            new
            {
                name = "discover_tools",
                description = "Authorizes access and discovers available tools. (Already authorized)",
                inputSchema = new
                {
                    type = "object",
                    properties = new Dictionary<string, object>(),
                    required = Array.Empty<string>()
                }
            },
            new
            {
                name = "echo",
                description = "Echoes back the input message",
                inputSchema = new
                {
                    type = "object",
                    properties = new Dictionary<string, object>
                    {
                        ["message"] = new
                        {
                            type = "string",
                            description = "The message to echo back"
                        }
                    },
                    required = new[] { "message" }
                }
            },
            new
            {
                name = "get_weather",
                description = "Gets the current weather for a location (mock data)",
                inputSchema = new
                {
                    type = "object",
                    properties = new Dictionary<string, object>
                    {
                        ["location"] = new
                        {
                            type = "string",
                            description = "The city or location to get weather for"
                        }
                    },
                    required = new[] { "location" }
                }
            },
            new
            {
                name = "calculate",
                description = "Performs a simple calculation (mock - always returns 42)",
                inputSchema = new
                {
                    type = "object",
                    properties = new Dictionary<string, object>
                    {
                        ["expression"] = new
                        {
                            type = "string",
                            description = "The mathematical expression to evaluate"
                        }
                    },
                    required = new[] { "expression" }
                }
            }
        };
    }

    private async Task<object> GenerateToolCallResponseAsync(string? toolName, JsonElement? arguments, int? requestId, HttpContext context)
    {
        var proxyToken = ExtractBearerToken(context);
        var hasBackendAuth = proxyToken != null && _backendAuthStore.TryGetValue(proxyToken, out var backendRecord);

        // discover_tools always triggers the backend auth flow if not yet authenticated
        if (toolName == "discover_tools")
        {
            if (hasBackendAuth)
            {
                Console.WriteLine($"{GREEN}   ✓ Backend already authorized - returning tools list{RESET}");
                return new
                {
                    jsonrpc = "2.0",
                    result = new
                    {
                        content = new[]
                        {
                            new
                            {
                                type = "text",
                                text = "✅ **Authorization Complete**\n\nYou now have access to the following tools:\n\n" +
                                       "1. **echo** - Echoes back the input message\n" +
                                       "2. **get_weather** - Gets the current weather for a location\n" +
                                       "3. **calculate** - Performs a simple calculation\n\n" +
                                       "The tools list has been updated. You can now use these tools directly.\n\n" +
                                       "_Note: The server has signaled `tools/list_changed` - your client should refresh the tools list._"
                            }
                        },
                        _meta = new
                        {
                            toolsDiscovered = new[] { "echo", "get_weather", "calculate" },
                            hint = "tools_list_changed"
                        }
                    },
                    id = requestId ?? 1
                };
            }

            // Return elicitation with backend auth URL
            Console.WriteLine($"{YELLOW}   ⚠ Backend auth required - returning elicitation{RESET}");
            var baseUrl = GetBaseUrl(context);
            
            var sessionId = Guid.NewGuid().ToString("N")[..16];
            _backendAuthPending[sessionId] = new BackendAuthPending(proxyToken!, sessionId, DateTime.UtcNow);
            var backendAuthUrl = $"{baseUrl}/backend-auth/login?session={Uri.EscapeDataString(sessionId)}";
            Console.WriteLine($"{CYAN}   ℹ Backend auth session created: {sessionId}{RESET}");
            
            return new
            {
                jsonrpc = "2.0",
                result = new
                {
                    content = new object[]
                    {
                        new
                        {
                            type = "text",
                            text = $"🔐 **Authorization Required**\n\nTo access the full set of tools, you need to authorize access to the backend service.\n\nPlease click the link below to sign in:\n\n👉 [{backendAuthUrl}]({backendAuthUrl})\n\nOnce you've signed in, retry the tool call or refresh the tools list."
                        }
                    },
                    _meta = new
                    {
                        elicitation = new
                        {
                            type = "backend_auth_required",
                            authUrl = backendAuthUrl,
                            message = "User must authenticate with the backend service. Please visit the auth URL to sign in."
                        }
                    }
                },
                id = requestId ?? 1
            };
        }

        // For real tools, require backend auth
        if (!hasBackendAuth)
        {
            Console.WriteLine($"{YELLOW}   ⚠ Backend auth required for tool: {toolName}{RESET}");
            var baseUrl = GetBaseUrl(context);
            var sessionId2 = Guid.NewGuid().ToString("N")[..16];
            _backendAuthPending[sessionId2] = new BackendAuthPending(proxyToken!, sessionId2, DateTime.UtcNow);
            var backendAuthUrl = $"{baseUrl}/backend-auth/login?session={Uri.EscapeDataString(sessionId2)}";

            return new
            {
                jsonrpc = "2.0",
                result = new
                {
                    content = new object[]
                    {
                        new
                        {
                            type = "text",
                            text = $"🔐 **Authorization Required**\n\nThe tool `{toolName}` requires backend authorization.\n\nPlease call `discover_tools` first or visit:\n👉 [{backendAuthUrl}]({backendAuthUrl})"
                        }
                    },
                    _meta = new
                    {
                        elicitation = new
                        {
                            type = "backend_auth_required",
                            authUrl = backendAuthUrl,
                            message = "User must authenticate with the backend service."
                        }
                    }
                },
                id = requestId ?? 1
            };
        }

        Console.WriteLine($"{GREEN}   ✓ Backend auth valid - forwarding tool call to backend: {toolName}{RESET}");

        // Forward tools/call to backend
        var paramsObj = new Dictionary<string, object?> { ["name"] = toolName };
        if (arguments.HasValue) paramsObj["arguments"] = arguments.Value;
        var backendResult = await ForwardToBackend(proxyToken!, "tools/call", paramsObj, requestId);
        if (backendResult != null) return backendResult;

        // Fallback to local execution if backend unreachable
        Console.WriteLine($"{YELLOW}   ⚠ Backend unreachable, falling back to local tool execution{RESET}");
        string responseText = toolName switch
        {
            "echo" => GenerateEchoResponse(arguments),
            "get_weather" => GenerateWeatherResponse(arguments),
            "calculate" => GenerateCalculateResponse(arguments),
            _ => $"Mock response for unknown tool '{toolName}'"
        };

        return new
        {
            jsonrpc = "2.0",
            result = new
            {
                content = new[]
                {
                    new
                    {
                        type = "text",
                        text = responseText
                    }
                }
            },
            id = requestId ?? 1
        };
    }

    private string GenerateEchoResponse(JsonElement? arguments)
    {
        if (arguments.HasValue && arguments.Value.TryGetProperty("message", out var messageElement))
        {
            var message = messageElement.GetString() ?? "No message provided";
            return $"Echo: {message}";
        }
        return "Echo: No message provided";
    }

    private string GenerateWeatherResponse(JsonElement? arguments)
    {
        string location = "Unknown";
        if (arguments.HasValue && arguments.Value.TryGetProperty("location", out var locationElement))
        {
            location = locationElement.GetString() ?? "Unknown";
        }
        
        return $"Weather for {location}: Sunny, 72°F (22°C), Humidity: 45%, Wind: 10 mph NW. (This is mock data)";
    }

    private string GenerateCalculateResponse(JsonElement? arguments)
    {
        string expression = "unknown";
        if (arguments.HasValue && arguments.Value.TryGetProperty("expression", out var exprElement))
        {
            expression = exprElement.GetString() ?? "unknown";
        }
        
        return $"The result of '{expression}' is 42. (This is mock data - the answer to everything!)";
    }

    /// <summary>
    /// Forwards a JSON-RPC request to the in-process backend MCP server via HTTP.
    /// Returns the deserialized response object, or null if the backend is unreachable.
    /// </summary>
    private async Task<object?> ForwardToBackend(string proxyToken, string method, object? @params, int? requestId)
    {
        if (!_backendAuthStore.TryGetValue(proxyToken, out var record))
            return null;

        var backendUrl = "http://localhost:7071/backend/mcp";
        var rpcRequest = new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["method"] = method,
            ["id"] = requestId ?? 1
        };
        if (@params != null) rpcRequest["params"] = @params;

        try
        {
            var json = JsonSerializer.Serialize(rpcRequest);
            using var httpRequest = new HttpRequestMessage(HttpMethod.Post, backendUrl);
            httpRequest.Content = new StringContent(json, Encoding.UTF8, "application/json");
            httpRequest.Headers.Add("Authorization", $"Bearer {record.BackendAccessToken}");

            Console.WriteLine($"{CYAN}   → Forwarding {method} to backend: {backendUrl}{RESET}");
            var httpResponse = await _httpClient.SendAsync(httpRequest);
            var responseBody = await httpResponse.Content.ReadAsStringAsync();

            if (httpResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"{GREEN}   ← Backend responded {(int)httpResponse.StatusCode}{RESET}");
                // Return as a raw JsonElement so it serializes faithfully
                using var doc = JsonDocument.Parse(responseBody);
                return doc.RootElement.Clone();
            }

            Console.WriteLine($"{RED}   ← Backend error {(int)httpResponse.StatusCode}: {responseBody}{RESET}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{RED}   ✗ Backend forward error: {ex.Message}{RESET}");
        }

        return null;
    }

    /// <summary>
    /// Validates the bearer token from the Authorization header.
    /// </summary>
    private (bool IsValid, string? Error) ValidateBearerToken(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue("Authorization", out var authValues))
            return (false, "Missing Authorization header");

        var authHeader = authValues.FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader))
            return (false, "Empty Authorization header");

        if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return (false, "Authorization header must use Bearer scheme");

        var token = authHeader.Substring(7).Trim();
        if (string.IsNullOrEmpty(token))
            return (false, "Empty bearer token");

        _logger.LogInformation("Validating bearer token (length: {Length})", token.Length);

        // Check proxy-issued token store first
        if (_tokenStore.TryGetValue(token, out var tokenRecord))
        {
            if (DateTime.UtcNow < tokenRecord.IssuedAt.AddSeconds(tokenRecord.ExpiresIn))
            {
                Console.WriteLine($"{GREEN}   ✓ Proxy-issued token validated (client: {tokenRecord.ClientId}){RESET}");
                return (true, null);
            }
            _tokenStore.TryRemove(token, out _);
            return (false, "Token has expired");
        }

        // Fall back to JWT validation (for entra-direct mode or backward compat)
        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token))
                return (false, "Token is not recognized (not in token store and not a valid JWT)");

            var jwt = handler.ReadJwtToken(token);
            if (VerboseLogging)
            {
                Console.WriteLine($"{CYAN}   JWT Issuer: {jwt.Issuer}{RESET}");
                Console.WriteLine($"{CYAN}   JWT Subject: {jwt.Subject}{RESET}");
                Console.WriteLine($"{CYAN}   JWT Audiences: {string.Join(", ", jwt.Audiences)}{RESET}");
            }

            // In entra-direct mode, enforce audience and expiry
            if (AuthStrategy == "entra-direct" && !string.IsNullOrEmpty(AzureClientId))
            {
                // Check audience matches our AAD app
                var validAudiences = new[] { $"api://{AzureClientId}", AzureClientId };
                if (!jwt.Audiences.Any(a => validAudiences.Contains(a, StringComparer.OrdinalIgnoreCase)))
                {
                    return (false, $"JWT audience '{string.Join(", ", jwt.Audiences)}' does not match expected '{AzureClientId}'");
                }

                // Check token not expired
                if (jwt.ValidTo != DateTime.MinValue && jwt.ValidTo < DateTime.UtcNow)
                {
                    return (false, "JWT has expired");
                }

                Console.WriteLine($"{GREEN}   ✓ Entra JWT validated (aud: {AzureClientId}, sub: {jwt.Subject}){RESET}");
            }

            return (true, null);
        }
        catch (Exception ex)
        {
            return (false, $"Error parsing token: {ex.Message}");
        }
    }

    /// <summary>
    /// Creates a 401 Unauthorized response with WWW-Authenticate header pointing to PRM.
    /// </summary>
    private async Task WriteUnauthorizedResponse(HttpContext context, string errorDescription)
    {
        context.Response.StatusCode = 401;
        context.Response.Headers["Content-Type"] = "application/json";
        
        var baseUrl = GetBaseUrl(context);
        context.Response.Headers["WWW-Authenticate"] = $"Bearer resource_metadata=\"{baseUrl}/.well-known/oauth-protected-resource\"";

        var responseBody = new
        {
            error = "unauthorized",
            error_description = errorDescription
        };

        await context.Response.WriteAsync(JsonSerializer.Serialize(responseBody, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        }));

        LogResponse("POST /mcp", 401, errorDescription);
    }

    private static string GetBaseUrl(HttpContext context)
    {
        var request = context.Request;
        var host = request.Host;
        // Host includes port when non-default
        return $"{request.Scheme}://{host}";
    }

    private static string? ExtractBearerToken(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue("Authorization", out var authValues))
            return null;
        var authHeader = authValues.FirstOrDefault();
        if (authHeader?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
            return authHeader.Substring(7).Trim();
        return null;
    }

    // ── Backend Auth Endpoints (AAD App #2) ─────────────────────────────

    /// <summary>
    /// GET /backend-auth/login - Starts OAuth2 flow against AAD App #2.
    /// </summary>
    public async Task HandleBackendAuthLogin(HttpContext context)
    {
        await LogRequestDetails(context, "GET");

        var query = context.Request.Query;
        
        // Accept either session ID (new) or proxy_token (legacy)
        var sessionId = query["session"].FirstOrDefault();
        string? proxyToken = null;
        
        if (!string.IsNullOrEmpty(sessionId))
        {
            if (_backendAuthPending.TryGetValue(sessionId, out var pendingSession))
            {
                proxyToken = pendingSession.ProxyToken;
                Console.WriteLine($"{CYAN}   ℹ Resolved session {sessionId} → proxy token: {proxyToken[..Math.Min(8, proxyToken.Length)]}...{RESET}");
            }
            else
            {
                context.Response.StatusCode = 400;
                context.Response.Headers["Content-Type"] = "text/html";
                await context.Response.WriteAsync("<html><body><h1>Error</h1><p>Invalid or expired session. Please retry the tool call to get a new authorization link.</p></body></html>");
                return;
            }
        }
        else
        {
            // Legacy: accept proxy_token directly
            proxyToken = query["proxy_token"].FirstOrDefault();
        }

        if (string.IsNullOrEmpty(proxyToken))
        {
            context.Response.StatusCode = 400;
            context.Response.Headers["Content-Type"] = "text/html";
            await context.Response.WriteAsync("<html><body><h1>Error</h1><p>Missing proxy_token parameter</p></body></html>");
            return;
        }

        Console.WriteLine($"{MAGENTA}   ⚡ Backend auth login for proxy token: {proxyToken[..Math.Min(8, proxyToken.Length)]}...{RESET}");

        if (AuthMode == "entra" && !string.IsNullOrEmpty(BackendClientId))
        {
            // Entra mode: redirect to Entra ID for App #2
            var state = Guid.NewGuid().ToString("N");
            var baseUrl = GetBaseUrl(context);
            var callbackUri = $"{baseUrl}/backend-auth/callback";

            _backendAuthPending[state] = new BackendAuthPending(proxyToken, state, DateTime.UtcNow);

            var entraAuthUrl = $"https://login.microsoftonline.com/{BackendTenantId}/oauth2/v2.0/authorize" +
                $"?response_type=code" +
                $"&client_id={Uri.EscapeDataString(BackendClientId)}" +
                $"&redirect_uri={Uri.EscapeDataString(callbackUri)}" +
                $"&scope={Uri.EscapeDataString(BackendScopes)}" +
                $"&state={Uri.EscapeDataString(state)}";

            Console.WriteLine($"{CYAN}   → Redirecting to Entra ID (App #2){RESET}");
            context.Response.StatusCode = 302;
            context.Response.Headers["Location"] = entraAuthUrl;
            LogResponse("GET /backend-auth/login", 302, "→ Entra ID (App #2)");
        }
        else
        {
            // Mock mode: auto-approve backend auth
            var mockToken = $"mock-backend-{Guid.NewGuid():N}";
            _backendAuthStore[proxyToken] = new BackendAuthRecord(
                proxyToken, mockToken, null, DateTime.UtcNow, 3600);

            Console.WriteLine($"{GREEN}   ✓ Mock backend auth granted{RESET}");

            // Notify SSE clients that tools have changed
            await NotifyToolsChanged(proxyToken);

            // Connect the SSE sidecar to the backend for streaming notifications
            if (SseManager != null)
            {
                var mockBaseUrl = GetBaseUrl(context);
                SseManager.ConnectToBackend(proxyToken, mockToken, $"{mockBaseUrl}/backend/mcp");
            }

            context.Response.StatusCode = 200;
            context.Response.Headers["Content-Type"] = "text/html";
            await context.Response.WriteAsync(@"
<!DOCTYPE html>
<html>
<head><title>Backend Authorization Complete</title>
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
           max-width: 600px; margin: 100px auto; padding: 20px; text-align: center; }
    .success { color: #28a745; font-size: 48px; }
    h1 { color: #333; }
    p { color: #666; line-height: 1.6; }
</style>
</head>
<body>
    <div class='success'>✓</div>
    <h1>Backend Authorization Complete</h1>
    <p>You have successfully authorized access to the backend service.</p>
    <p style='margin-top: 30px; color: #888;'>You can close this window and retry your tool call or refresh the tools list.</p>
</body>
</html>");
            LogResponse("GET /backend-auth/login", 200, "Mock backend auth granted");
        }
    }

    /// <summary>
    /// GET /backend-auth/callback - Entra ID callback for AAD App #2.
    /// </summary>
    public async Task HandleBackendAuthCallback(HttpContext context)
    {
        await LogRequestDetails(context, "GET");

        var query = context.Request.Query;
        var entraCode = query["code"].FirstOrDefault();
        var state = query["state"].FirstOrDefault();
        var error = query["error"].FirstOrDefault();

        if (!string.IsNullOrEmpty(error))
        {
            Console.WriteLine($"{RED}   ✗ Entra App #2 returned error: {error}{RESET}");
            context.Response.StatusCode = 400;
            context.Response.Headers["Content-Type"] = "text/html";
            await context.Response.WriteAsync($"<html><body><h1>Error</h1><p>{error}: {query["error_description"].FirstOrDefault()}</p></body></html>");
            return;
        }

        if (string.IsNullOrEmpty(entraCode) || string.IsNullOrEmpty(state))
        {
            context.Response.StatusCode = 400;
            context.Response.Headers["Content-Type"] = "text/html";
            await context.Response.WriteAsync("<html><body><h1>Error</h1><p>Missing code or state</p></body></html>");
            return;
        }

        if (!_backendAuthPending.TryRemove(state, out var pending))
        {
            context.Response.StatusCode = 400;
            context.Response.Headers["Content-Type"] = "text/html";
            await context.Response.WriteAsync("<html><body><h1>Error</h1><p>Unknown state — session expired or already used</p></body></html>");
            return;
        }

        Console.WriteLine($"{CYAN}   Exchanging Entra code for backend tokens (App #2)...{RESET}");

        var baseUrl = GetBaseUrl(context);
        var callbackUri = $"{baseUrl}/backend-auth/callback";

        var tokenRequestContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = BackendClientId!,
            ["client_secret"] = BackendClientSecret ?? "",
            ["code"] = entraCode,
            ["redirect_uri"] = callbackUri,
            ["scope"] = BackendScopes
        });

        try
        {
            var tokenResponse = await _httpClient.PostAsync(
                $"https://login.microsoftonline.com/{BackendTenantId}/oauth2/v2.0/token",
                tokenRequestContent);

            var tokenBody = await tokenResponse.Content.ReadAsStringAsync();

            if (!tokenResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"{RED}   ✗ Backend token exchange failed: {tokenBody}{RESET}");
                context.Response.StatusCode = 500;
                context.Response.Headers["Content-Type"] = "text/html";
                await context.Response.WriteAsync("<html><body><h1>Error</h1><p>Failed to exchange code for backend tokens.</p></body></html>");
                return;
            }

            using var tokenJson = JsonDocument.Parse(tokenBody);
            var backendAccessToken = tokenJson.RootElement.GetProperty("access_token").GetString()!;
            var backendRefreshToken = tokenJson.RootElement.TryGetProperty("refresh_token", out var rtProp) ? rtProp.GetString() : null;
            var expiresIn = tokenJson.RootElement.TryGetProperty("expires_in", out var expProp) ? expProp.GetInt32() : 3600;

            // Store backend tokens keyed by the proxy token
            _backendAuthStore[pending.ProxyToken] = new BackendAuthRecord(
                pending.ProxyToken, backendAccessToken, backendRefreshToken, DateTime.UtcNow, expiresIn);

            Console.WriteLine($"{GREEN}   ✓ Backend tokens stored for proxy token: {pending.ProxyToken[..Math.Min(8, pending.ProxyToken.Length)]}...{RESET}");

            // Notify SSE clients that tools have changed
            await NotifyToolsChanged(pending.ProxyToken);

            // Connect the SSE sidecar to the backend for streaming notifications
            if (SseManager != null)
            {
                var backendMcpUrl = $"{baseUrl}/backend/mcp";
                SseManager.ConnectToBackend(pending.ProxyToken, backendAccessToken, backendMcpUrl);
                Console.WriteLine($"{CYAN}   ℹ BackendSseManager connected for proxy→backend streaming{RESET}");
            }

            context.Response.StatusCode = 200;
            context.Response.Headers["Content-Type"] = "text/html";
            await context.Response.WriteAsync(@"
<!DOCTYPE html>
<html>
<head><title>Backend Authorization Complete</title>
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
           max-width: 600px; margin: 100px auto; padding: 20px; text-align: center; }
    .success { color: #28a745; font-size: 48px; }
    h1 { color: #333; }
    p { color: #666; line-height: 1.6; }
</style>
</head>
<body>
    <div class='success'>✓</div>
    <h1>Backend Authorization Complete</h1>
    <p>You have successfully authorized access to the backend service.</p>
    <p>Your backend credentials have been securely stored on the server.</p>
    <p style='margin-top: 30px; color: #888;'>You can close this window and retry your tool call or refresh the tools list.</p>
</body>
</html>");
            LogResponse("GET /backend-auth/callback", 200, "Backend tokens stored");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{RED}   ✗ Backend token exchange error: {ex.Message}{RESET}");
            context.Response.StatusCode = 500;
            context.Response.Headers["Content-Type"] = "text/html";
            await context.Response.WriteAsync($"<html><body><h1>Error</h1><p>Token exchange failed: {ex.Message}</p></body></html>");
        }
    }

    /// <summary>
    /// GET /backend-auth/status - Check backend auth status for a proxy token.
    /// </summary>
    public async Task HandleBackendAuthStatus(HttpContext context)
    {
        var query = context.Request.Query;
        var proxyToken = query["proxy_token"].FirstOrDefault();

        context.Response.StatusCode = 200;
        context.Response.Headers["Content-Type"] = "application/json";

        var isAuthorized = !string.IsNullOrEmpty(proxyToken) && _backendAuthStore.ContainsKey(proxyToken);

        await context.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            authorized = isAuthorized,
            proxy_token = proxyToken?[..Math.Min(8, proxyToken?.Length ?? 0)] + "..."
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    // ── CIMD Policy Endpoint ────────────────────────────────────────────

    /// <summary>
    /// GET /cimd-policy - Returns current CIMD policy configuration
    /// </summary>
    public async Task HandleCimdPolicy(HttpContext context)
    {
        context.Response.StatusCode = 200;
        context.Response.Headers["Content-Type"] = "application/json";

        await context.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            mode = CimdPolicyMode,
            allowed_clients = CimdPolicyMode == "allowlist" ? CimdAllowedClients : Array.Empty<string>(),
            denied_clients = CimdPolicyMode == "denylist" ? CimdDeniedClients : Array.Empty<string>(),
            description = CimdPolicyMode switch
            {
                "allowlist" => $"Only {CimdAllowedClients.Length} allowed client pattern(s). All others are denied.",
                "denylist" => $"{CimdDeniedClients.Length} denied client pattern(s). All others are allowed.",
                "open" => "All CIMD clients are allowed (no restrictions).",
                _ => $"Unknown mode '{CimdPolicyMode}', defaulting to open."
            }
        }, new JsonSerializerOptions { WriteIndented = true }));

        LogResponse("GET /cimd-policy", 200, $"mode={CimdPolicyMode}");
    }

    // ── OAuth / CIMD Endpoints ──────────────────────────────────────────

    /// <summary>
    /// GET /oauth/authorize - OAuth Authorization Endpoint (CIMD)
    /// </summary>
    public async Task HandleOAuthAuthorize(HttpContext context)
    {
        await LogRequestDetails(context, "GET");

        var query = context.Request.Query;
        var responseType = query["response_type"].FirstOrDefault();
        var clientId = query["client_id"].FirstOrDefault();
        var redirectUri = query["redirect_uri"].FirstOrDefault();
        var scope = query["scope"].FirstOrDefault() ?? GetScopesSupported();
        var state = query["state"].FirstOrDefault() ?? "";

        Console.WriteLine($"{MAGENTA}   ⚡ OAuth Authorize: client_id={clientId}{RESET}");

        if (responseType != "code")
        {
            await WriteOAuthErrorResponse(context, "unsupported_response_type", "Only response_type=code is supported");
            return;
        }

        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
        {
            await WriteOAuthErrorResponse(context, "invalid_request", "client_id and redirect_uri are required");
            return;
        }

        // Evaluate CIMD policy before fetching the document
        var (policyAllowed, policyReason) = EvaluateCimdPolicy(clientId);
        if (!policyAllowed)
        {
            Console.WriteLine($"{RED}   ✗ CIMD policy denied: {policyReason}{RESET}");
            await WriteOAuthErrorResponse(context, "access_denied", policyReason ?? "Client not permitted by CIMD policy");
            return;
        }
        if (policyReason != null)
            Console.WriteLine($"{GREEN}   ✓ CIMD policy: {policyReason}{RESET}");

        // Fetch and validate CIMD document
        var (cimdValid, cimdError) = await ValidateCimd(clientId, redirectUri);
        if (!cimdValid)
        {
            Console.WriteLine($"{RED}   ✗ CIMD validation failed: {cimdError}{RESET}");
            await WriteOAuthErrorResponse(context, "invalid_client", cimdError ?? "CIMD validation failed");
            return;
        }
        Console.WriteLine($"{GREEN}   ✓ CIMD validated for {clientId}{RESET}");

        if (AuthMode == "entra")
        {
            if (string.IsNullOrEmpty(AzureClientId))
            {
                await WriteOAuthErrorResponse(context, "server_error", "AZURE_CLIENT_ID not configured");
                return;
            }

            var proxyState = Guid.NewGuid().ToString("N");
            var baseUrl = GetBaseUrl(context);
            var callbackUri = $"{baseUrl}/oauth/callback";

            _authSessions[proxyState] = new AuthSession(
                clientId, redirectUri, scope, state,
                EntraState: proxyState, CodeVerifier: null,
                AuthCode: null, EntraAccessToken: null, CreatedAt: DateTime.UtcNow, IsRedeemed: false);

            var entraAuthUrl = $"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/authorize" +
                $"?response_type=code" +
                $"&client_id={Uri.EscapeDataString(AzureClientId)}" +
                $"&redirect_uri={Uri.EscapeDataString(callbackUri)}" +
                $"&scope={Uri.EscapeDataString("openid profile offline_access")}" +
                $"&state={Uri.EscapeDataString(proxyState)}";

            Console.WriteLine($"{CYAN}   → Redirecting to Entra ID{RESET}");
            context.Response.StatusCode = 302;
            context.Response.Headers["Location"] = entraAuthUrl;
            LogResponse("GET /oauth/authorize", 302, "→ Entra ID");
        }
        else
        {
            // Mock mode: generate auth code directly
            var authCode = Guid.NewGuid().ToString("N");
            _authSessions[authCode] = new AuthSession(
                clientId, redirectUri, scope, state,
                EntraState: null, CodeVerifier: null,
                AuthCode: authCode, EntraAccessToken: null, CreatedAt: DateTime.UtcNow, IsRedeemed: false);

            var location = $"{redirectUri}{(redirectUri.Contains('?') ? '&' : '?')}code={Uri.EscapeDataString(authCode)}&state={Uri.EscapeDataString(state)}";
            Console.WriteLine($"{GREEN}   ✓ Mock auth code issued: {authCode[..8]}...{RESET}");

            context.Response.StatusCode = 302;
            context.Response.Headers["Location"] = location;
            LogResponse("GET /oauth/authorize", 302, $"→ {redirectUri}");
        }
    }

    /// <summary>
    /// GET /oauth/callback - Entra ID callback (Entra mode only)
    /// </summary>
    public async Task HandleOAuthCallback(HttpContext context)
    {
        await LogRequestDetails(context, "GET");

        var query = context.Request.Query;
        var entraCode = query["code"].FirstOrDefault();
        var proxyState = query["state"].FirstOrDefault();
        var error = query["error"].FirstOrDefault();

        if (!string.IsNullOrEmpty(error))
        {
            Console.WriteLine($"{RED}   ✗ Entra returned error: {error}{RESET}");
            await WriteOAuthErrorResponse(context, "access_denied", $"Entra error: {error} - {query["error_description"].FirstOrDefault()}");
            return;
        }

        if (string.IsNullOrEmpty(entraCode) || string.IsNullOrEmpty(proxyState))
        {
            await WriteOAuthErrorResponse(context, "invalid_request", "Missing code or state from Entra callback");
            return;
        }

        if (!_authSessions.TryGetValue(proxyState, out var session))
        {
            await WriteOAuthErrorResponse(context, "invalid_request", "Unknown state — session not found");
            return;
        }

        Console.WriteLine($"{CYAN}   Exchanging Entra code for tokens...{RESET}");

        var baseUrl = GetBaseUrl(context);
        var callbackUri = $"{baseUrl}/oauth/callback";

        var tokenRequestContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = AzureClientId!,
            ["client_secret"] = AzureClientSecret ?? "",
            ["code"] = entraCode,
            ["redirect_uri"] = callbackUri,
            ["scope"] = "openid profile offline_access"
        });

        try
        {
            var tokenResponse = await _httpClient.PostAsync(
                $"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token",
                tokenRequestContent);

            var tokenBody = await tokenResponse.Content.ReadAsStringAsync();

            if (!tokenResponse.IsSuccessStatusCode)
            {
                Console.WriteLine($"{RED}   ✗ Entra token exchange failed: {tokenBody}{RESET}");
                await WriteOAuthErrorResponse(context, "server_error", "Failed to exchange Entra code for tokens");
                return;
            }

            using var tokenJson = JsonDocument.Parse(tokenBody);
            var entraAccessToken = tokenJson.RootElement.GetProperty("access_token").GetString();
            Console.WriteLine($"{GREEN}   ✓ Entra tokens received{RESET}");

            var proxyCode = Guid.NewGuid().ToString("N");
            _authSessions[proxyCode] = session with
            {
                AuthCode = proxyCode,
                EntraAccessToken = entraAccessToken
            };
            _authSessions.TryRemove(proxyState, out _);

            var location = $"{session.RedirectUri}{(session.RedirectUri.Contains('?') ? '&' : '?')}code={Uri.EscapeDataString(proxyCode)}&state={Uri.EscapeDataString(session.State)}";
            Console.WriteLine($"{GREEN}   ✓ Proxy auth code issued, redirecting to client{RESET}");

            context.Response.StatusCode = 302;
            context.Response.Headers["Location"] = location;
            LogResponse("GET /oauth/callback", 302, $"→ {session.RedirectUri}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{RED}   ✗ Entra token exchange error: {ex.Message}{RESET}");
            await WriteOAuthErrorResponse(context, "server_error", $"Token exchange failed: {ex.Message}");
        }
    }

    /// <summary>
    /// POST /oauth/token - OAuth Token Endpoint
    /// </summary>
    public async Task HandleOAuthToken(HttpContext context)
    {
        await LogRequestDetails(context, "POST");

        var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
        var form = System.Web.HttpUtility.ParseQueryString(body);
        var grantType = form["grant_type"];
        var code = form["code"];
        var clientId = form["client_id"];

        Console.WriteLine($"{MAGENTA}   ⚡ Token Exchange: grant_type={grantType}, client_id={clientId}{RESET}");

        if (grantType != "authorization_code")
        {
            await WriteOAuthTokenErrorResponse(context, "unsupported_grant_type", "Only authorization_code is supported");
            return;
        }

        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(clientId))
        {
            await WriteOAuthTokenErrorResponse(context, "invalid_request", "code and client_id are required");
            return;
        }

        if (!_authSessions.TryGetValue(code, out var session))
        {
            await WriteOAuthTokenErrorResponse(context, "invalid_grant", "Authorization code not found or expired");
            return;
        }

        if (session.IsRedeemed)
        {
            await WriteOAuthTokenErrorResponse(context, "invalid_grant", "Authorization code has already been used");
            return;
        }

        if (session.ClientId != clientId)
        {
            await WriteOAuthTokenErrorResponse(context, "invalid_grant", "client_id does not match the authorization request");
            return;
        }

        // Mark code as redeemed
        _authSessions[code] = session with { IsRedeemed = true };

        // Generate proxy access token
        var accessToken = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var expiresIn = 3600;

        _tokenStore[accessToken] = new TokenRecord(accessToken, clientId, session.Scope, DateTime.UtcNow, expiresIn);

        Console.WriteLine($"{GREEN}   ✓ Access token issued for {clientId}{RESET}");

        context.Response.StatusCode = 200;
        context.Response.Headers["Content-Type"] = "application/json";
        context.Response.Headers["Cache-Control"] = "no-store";

        var tokenResponseBody = new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = expiresIn,
            scope = session.Scope
        };

        await context.Response.WriteAsync(JsonSerializer.Serialize(tokenResponseBody, new JsonSerializerOptions
        {
            WriteIndented = true
        }));

        LogResponse("POST /oauth/token", 200, $"token issued for {clientId}");
    }

    // ── CIMD Validation ─────────────────────────────────────────────────

    /// <summary>
    /// Evaluates the CIMD policy to determine if a client_id is allowed.
    /// Called BEFORE fetching the CIMD document to prevent SSRF.
    /// </summary>
    private (bool Allowed, string? Reason) EvaluateCimdPolicy(string clientId)
    {
        if (CimdPolicyMode == "open")
            return (true, null);

        if (!Uri.TryCreate(clientId, UriKind.Absolute, out var clientUri))
            return (false, "client_id is not a valid URL");

        var host = clientUri.Host;

        if (CimdPolicyMode == "allowlist")
        {
            if (CimdAllowedClients.Length == 0)
                return (false, "CIMD allowlist is empty — no clients are permitted");

            if (MatchesAnyPattern(clientId, host, CimdAllowedClients, out var matchedRule))
                return (true, $"Allowed by rule: {matchedRule}");

            return (false, $"Client '{clientId}' (host: {host}) is not in the CIMD allowlist");
        }

        if (CimdPolicyMode == "denylist")
        {
            if (MatchesAnyPattern(clientId, host, CimdDeniedClients, out var matchedRule))
                return (false, $"Client '{clientId}' is blocked by denylist rule: {matchedRule}");

            return (true, null);
        }

        return (true, null); // Unknown mode defaults to open
    }

    /// <summary>
    /// Checks if a client_id URL or host matches any pattern in the list.
    /// Patterns can be: exact URL, exact domain, or wildcard domain (*.example.com).
    /// </summary>
    private static bool MatchesAnyPattern(string clientId, string host, string[] patterns, out string? matchedRule)
    {
        foreach (var pattern in patterns)
        {
            // Exact URL match
            if (pattern.Contains("://") && string.Equals(pattern, clientId, StringComparison.OrdinalIgnoreCase))
            {
                matchedRule = pattern;
                return true;
            }

            // Wildcard domain match: *.example.com
            if (pattern.StartsWith("*."))
            {
                var suffix = pattern[1..]; // .example.com
                if (host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) && host.Length > suffix.Length)
                {
                    matchedRule = pattern;
                    return true;
                }
                continue;
            }

            // Exact domain match (non-URL patterns without ://)
            if (!pattern.Contains("://") && string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase))
            {
                matchedRule = pattern;
                return true;
            }
        }

        matchedRule = null;
        return false;
    }

    private async Task<(bool IsValid, string? Error)> ValidateCimd(string clientId, string redirectUri)
    {
        if (!Uri.TryCreate(clientId, UriKind.Absolute, out var clientIdUri))
        {
            return (false, "client_id is not a valid URL");
        }

        var isLocalhost = clientIdUri.Host is "localhost" or "127.0.0.1" or "::1";
        if (clientIdUri.Scheme != "https" && !isLocalhost)
        {
            return (false, "client_id URL must use HTTPS (http allowed only for localhost)");
        }

        try
        {
            Console.WriteLine($"{CYAN}   Fetching CIMD document from {clientId}...{RESET}");
            var response = await _httpClient.GetAsync(clientId);

            if (!response.IsSuccessStatusCode)
            {
                return (false, $"Failed to fetch CIMD document: HTTP {(int)response.StatusCode}");
            }

            var content = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(content);
            var root = doc.RootElement;

            if (root.TryGetProperty("client_id", out var cidProp))
            {
                var docClientId = cidProp.GetString();
                if (docClientId != clientId)
                {
                    return (false, $"CIMD client_id mismatch: document says '{docClientId}', request says '{clientId}'");
                }
            }
            else
            {
                return (false, "CIMD document missing client_id field");
            }

            if (root.TryGetProperty("redirect_uris", out var redirectUrisProp) && redirectUrisProp.ValueKind == JsonValueKind.Array)
            {
                var allowedUris = redirectUrisProp.EnumerateArray()
                    .Select(e => e.GetString())
                    .Where(u => u != null)
                    .ToList();

                bool redirectMatch = false;
                if (Uri.TryCreate(redirectUri, UriKind.Absolute, out var reqRedirectUri)
                    && (reqRedirectUri.Host is "127.0.0.1" or "localhost" or "::1"))
                {
                    redirectMatch = allowedUris.Any(u =>
                    {
                        if (Uri.TryCreate(u, UriKind.Absolute, out var allowedUri))
                        {
                            return allowedUri.Scheme == reqRedirectUri.Scheme
                                && allowedUri.Host == reqRedirectUri.Host
                                && allowedUri.AbsolutePath == reqRedirectUri.AbsolutePath;
                        }
                        return false;
                    });
                }
                else
                {
                    redirectMatch = allowedUris.Contains(redirectUri);
                }

                if (!redirectMatch)
                {
                    return (false, $"redirect_uri '{redirectUri}' is not listed in CIMD document redirect_uris");
                }
            }
            else
            {
                return (false, "CIMD document missing redirect_uris array");
            }

            if (VerboseLogging)
            {
                var clientName = root.TryGetProperty("client_name", out var nameProp) ? nameProp.GetString() : "unknown";
                Console.WriteLine($"{CYAN}   CIMD client_name: {clientName}{RESET}");
            }

            return (true, null);
        }
        catch (HttpRequestException ex)
        {
            return (false, $"Failed to fetch CIMD document: {ex.Message}");
        }
        catch (JsonException ex)
        {
            return (false, $"CIMD document is not valid JSON: {ex.Message}");
        }
    }

    private async Task WriteOAuthErrorResponse(HttpContext context, string error, string description)
    {
        context.Response.StatusCode = 400;
        context.Response.Headers["Content-Type"] = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(new { error, error_description = description },
            new JsonSerializerOptions { WriteIndented = true }));
        var path = context.Request.Path.Value ?? "";
        LogResponse(path, 400, description);
    }

    private async Task WriteOAuthTokenErrorResponse(HttpContext context, string error, string description)
    {
        context.Response.StatusCode = 400;
        context.Response.Headers["Content-Type"] = "application/json";
        context.Response.Headers["Cache-Control"] = "no-store";
        await context.Response.WriteAsync(JsonSerializer.Serialize(new { error, error_description = description },
            new JsonSerializerOptions { WriteIndented = true }));
        LogResponse("POST /oauth/token", 400, description);
    }
}
