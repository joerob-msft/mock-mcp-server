using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

namespace MockMcpServer.Functions;

public class McpFunctions
{
    private readonly ILogger<McpFunctions> _logger;

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

    public McpFunctions(ILogger<McpFunctions> logger)
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

    // Backend auth store - maps proxy tokens to backend auth state
    private static readonly ConcurrentDictionary<string, BackendAuthRecord> _backendAuthStore = new();
    // Pending backend auth sessions - maps state param to pending session
    private static readonly ConcurrentDictionary<string, BackendAuthPending> _backendAuthPending = new();

    private record BackendAuthRecord(
        string ProxyToken, string BackendAccessToken, string? BackendRefreshToken,
        DateTime IssuedAt, int ExpiresIn);

    private record BackendAuthPending(
        string ProxyToken, string State, DateTime CreatedAt);

    // In Entra mode, scopes must reference the AAD app's resource URI
    private static string GetScopesSupported() =>
        AuthMode == "entra" && !string.IsNullOrEmpty(AzureClientId)
            ? $"api://{AzureClientId}/.default"
            : "mcp.tools.execute";

    /// <summary>
    /// GET /mcp - MCP root endpoint
    /// Returns 200 if valid bearer token with correct audience is provided.
    /// Returns 401 with PRM pointer if no token or invalid token.
    /// </summary>
    [Function("McpGet")]
    public async Task<HttpResponseData> GetMcp(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "mcp")] HttpRequestData req)
    {
        await LogRequestDetails(req, "GET");

        // Validate bearer token
        var (isValid, tokenError) = ValidateBearerToken(req);
        
        if (!isValid)
        {
            // Return 401 with WWW-Authenticate header pointing to PRM
            Console.WriteLine($"{RED}   ✗ Token validation failed: {tokenError}{RESET}");
            
            var unauthorizedResponse = req.CreateResponse(System.Net.HttpStatusCode.Unauthorized);
            unauthorizedResponse.Headers.Add("Content-Type", "application/json");
            
            var baseUrl = GetBaseUrl(req);
            unauthorizedResponse.Headers.Add("WWW-Authenticate", $"Bearer resource_metadata=\"{baseUrl}/.well-known/oauth-protected-resource\"");

            var errorBody = new
            {
                error = "unauthorized",
                error_description = tokenError ?? "Authentication required"
            };

            await unauthorizedResponse.WriteStringAsync(JsonSerializer.Serialize(errorBody, new JsonSerializerOptions 
            { 
                WriteIndented = true 
            }));

            LogResponse("GET /mcp", 401, tokenError ?? "Auth required - see WWW-Authenticate header");
            return unauthorizedResponse;
        }

        Console.WriteLine($"{GREEN}   ✓ Bearer token validated{RESET}");

        // Check if client wants SSE stream (Streamable HTTP transport)
        var acceptHeader = req.Headers.TryGetValues("Accept", out var acceptValues) 
            ? string.Join(",", acceptValues) : "";
        
        if (acceptHeader.Contains("text/event-stream"))
        {
            // SSE notification stream not supported — return 405 per MCP Streamable HTTP spec
            Console.WriteLine($"{CYAN}   ℹ SSE stream requested but not supported — returning 405{RESET}");
            var sseResponse = req.CreateResponse(System.Net.HttpStatusCode.MethodNotAllowed);
            LogResponse("GET /mcp", 405, "SSE not supported");
            return sseResponse;
        }

        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "application/json");

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

        await response.WriteStringAsync(JsonSerializer.Serialize(responseBody, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        }));

        LogResponse("GET /mcp", 200, "Authenticated");
        return response;
    }

    /// <summary>
    /// GET /.well-known/oauth-protected-resource - Protected Resource Metadata
    /// Tells clients which resource to request tokens for and which authorization servers to use.
    /// Per RFC 9728, `resource` must match the protected resource URL (i.e., the /mcp endpoint).
    /// </summary>
    [Function("ProtectedResourceMetadata")]
    public async Task<HttpResponseData> GetProtectedResourceMetadata(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = ".well-known/oauth-protected-resource")] HttpRequestData req)
    {
        return await ServeProtectedResourceMetadata(req);
    }

    /// <summary>
    /// GET /.well-known/oauth-protected-resource/mcp - PRM at resource-specific path
    /// Some clients append the resource path to the well-known base.
    /// </summary>
    [Function("ProtectedResourceMetadataMcp")]
    public async Task<HttpResponseData> GetProtectedResourceMetadataMcp(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = ".well-known/oauth-protected-resource/mcp")] HttpRequestData req)
    {
        return await ServeProtectedResourceMetadata(req);
    }

    private async Task<HttpResponseData> ServeProtectedResourceMetadata(HttpRequestData req)
    {
        await LogRequestDetails(req, "GET");

        var baseUrl = GetBaseUrl(req);
        var resourceUrl = $"{baseUrl}/mcp";
        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "application/json");

        var metadata = new
        {
            resource = resourceUrl,
            authorization_servers = new[] { baseUrl },
            scopes_supported = new[] { GetScopesSupported() }
        };

        await response.WriteStringAsync(JsonSerializer.Serialize(metadata, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        }));

        LogResponse("GET /.well-known/oauth-protected-resource", 200, $"resource={resourceUrl}");
        return response;
    }

    /// <summary>
    /// GET /.well-known/oauth-authorization-server - OAuth Authorization Server Metadata
    /// Advertises proxy-owned OAuth endpoints for CIMD-based auth.
    /// </summary>
    [Function("OAuthAuthorizationServerMetadata")]
    public async Task<HttpResponseData> GetOAuthAuthorizationServerMetadata(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = ".well-known/oauth-authorization-server")] HttpRequestData req)
    {
        await LogRequestDetails(req, "GET");

        var baseUrl = GetBaseUrl(req);
        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "application/json");

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

        await response.WriteStringAsync(JsonSerializer.Serialize(metadata, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        }));

        LogResponse("GET /.well-known/oauth-authorization-server", 200, $"issuer={baseUrl}");
        return response;
    }

    /// <summary>
    /// POST /mcp - Main MCP API endpoint
    /// initialize, tools/list, resources/list, prompts/list are allowed without auth.
    /// tools/call requires a valid bearer token.
    /// </summary>
    [Function("McpPost")]
    public async Task<HttpResponseData> PostMcp(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "mcp")] HttpRequestData req)
    {
        await LogRequestDetails(req, "POST");

        // Read and parse the request body first to determine the method
        string requestBody = await new StreamReader(req.Body).ReadToEndAsync();

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
            var (isValid, tokenError) = ValidateBearerToken(req);
            if (!isValid)
            {
                Console.WriteLine($"{RED}   ✗ Token validation failed: {tokenError}{RESET}");
                return await CreateUnauthorizedResponse(req, tokenError ?? "Invalid or missing token");
            }
            Console.WriteLine($"{GREEN}   ✓ Bearer token validated{RESET}");
        }
        else
        {
            Console.WriteLine($"{CYAN}   ℹ Method '{method}' does not require auth{RESET}");
        }

        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "application/json");

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
                        tools = new { listChanged = true }, // Tools list can change after consent
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
            "tools/list" => GenerateToolsListResponse(requestId, req),
            "tools/call" => GenerateToolCallResponse(toolName, toolArguments, requestId, req),
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
        await response.WriteStringAsync(jsonResponse);

        LogResponse($"POST /mcp ({method})", 200, toolName != null ? $"tool={toolName}" : null);
        return response;
    }

    private async Task LogRequestDetails(HttpRequestData req, string httpMethod)
    {
        // Concise colored output
        var authHeader = req.Headers.TryGetValues("Authorization", out var authVals) 
            ? (authVals.FirstOrDefault()?.StartsWith("Bearer ") == true ? "Bearer [token]" : authVals.FirstOrDefault()) 
            : "none";
        
        Console.WriteLine($"\n{CYAN}{BOLD}▶▶▶ INCOMING {httpMethod} {req.Url.AbsolutePath}{RESET}");
        Console.WriteLine($"{CYAN}   URL: {req.Url}{RESET}");
        Console.WriteLine($"{CYAN}   Auth: {authHeader}{RESET}");
        
        if (VerboseLogging)
        {
            Console.WriteLine($"{CYAN}   Headers:{RESET}");
            foreach (var header in req.Headers)
            {
                if (header.Key.ToLower() != "authorization") // Don't log full auth header
                {
                    Console.WriteLine($"{CYAN}     {header.Key}: {string.Join(", ", header.Value)}{RESET}");
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

    private object GenerateToolsListResponse(int? requestId, HttpRequestData req)
    {
        // Check if backend auth exists for the caller's proxy token
        var proxyToken = ExtractBearerToken(req);
        var hasBackendAuth = proxyToken != null && _backendAuthStore.ContainsKey(proxyToken);
        
        if (VerboseLogging)
            Console.WriteLine($"{CYAN}   tools/list: proxyToken={proxyToken?[..Math.Min(8, proxyToken.Length)]}..., hasBackendAuth={hasBackendAuth}, backendAuthStoreKeys={_backendAuthStore.Count}{RESET}");
        
        if (hasBackendAuth)
        {
            if (VerboseLogging)
                Console.WriteLine($"{GREEN}   Backend auth found - full tools list{RESET}");
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

    private object GenerateToolCallResponse(string? toolName, JsonElement? arguments, int? requestId, HttpRequestData req)
    {
        var proxyToken = ExtractBearerToken(req);
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
            var baseUrl = GetBaseUrl(req);
            
            // Generate a short-lived session ID instead of putting the raw proxy token in the URL
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
            var baseUrl = GetBaseUrl(req);
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

        Console.WriteLine($"{GREEN}   ✓ Backend auth valid - executing tool: {toolName}{RESET}");
        
        // Execute the tool
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
        
        // Return mock weather data
        return $"Weather for {location}: Sunny, 72°F (22°C), Humidity: 45%, Wind: 10 mph NW. (This is mock data)";
    }

    private string GenerateCalculateResponse(JsonElement? arguments)
    {
        string expression = "unknown";
        if (arguments.HasValue && arguments.Value.TryGetProperty("expression", out var exprElement))
        {
            expression = exprElement.GetString() ?? "unknown";
        }
        
        // Always return 42 as a joke
        return $"The result of '{expression}' is 42. (This is mock data - the answer to everything!)";
    }

    /// <summary>
    /// Validates the bearer token from the Authorization header.
    /// First checks the in-memory token store (proxy-issued tokens),
    /// then falls back to JWT validation for backward compatibility.
    /// </summary>
    private (bool IsValid, string? Error) ValidateBearerToken(HttpRequestData req)
    {
        if (!req.Headers.TryGetValues("Authorization", out var authValues))
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

        // Fall back to JWT validation (backward compatibility)
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
    private async Task<HttpResponseData> CreateUnauthorizedResponse(HttpRequestData req, string errorDescription)
    {
        var response = req.CreateResponse(System.Net.HttpStatusCode.Unauthorized);
        response.Headers.Add("Content-Type", "application/json");
        
        var baseUrl = GetBaseUrl(req);
        response.Headers.Add("WWW-Authenticate", $"Bearer resource_metadata=\"{baseUrl}/.well-known/oauth-protected-resource\"");

        var responseBody = new
        {
            error = "unauthorized",
            error_description = errorDescription
        };

        await response.WriteStringAsync(JsonSerializer.Serialize(responseBody, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        }));

        LogResponse("POST /mcp", 401, errorDescription);
        return response;
    }

    private static string GetBaseUrl(HttpRequestData req)
    {
        var port = req.Url.Port;
        var defaultPort = req.Url.Scheme == "https" ? 443 : 80;
        return port == defaultPort
            ? $"{req.Url.Scheme}://{req.Url.Host}"
            : $"{req.Url.Scheme}://{req.Url.Host}:{port}";
    }

    private static string? ExtractBearerToken(HttpRequestData req)
    {
        if (!req.Headers.TryGetValues("Authorization", out var authValues))
            return null;
        var authHeader = authValues.FirstOrDefault();
        if (authHeader?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
            return authHeader.Substring(7).Trim();
        return null;
    }

    // ── Backend Auth Endpoints (AAD App #2) ─────────────────────────────

    /// <summary>
    /// GET /backend-auth/login - Starts OAuth2 flow against AAD App #2.
    /// The proxy_token query param links this auth to the caller's session.
    /// Mock mode: auto-approves without Entra redirect.
    /// Entra mode: redirects to Entra ID for App #2 login.
    /// </summary>
    [Function("BackendAuthLogin")]
    public async Task<HttpResponseData> BackendAuthLogin(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "backend-auth/login")] HttpRequestData req)
    {
        await LogRequestDetails(req, "GET");

        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        
        // Accept either session ID (new) or proxy_token (legacy)
        var sessionId = query["session"];
        string? proxyToken = null;
        
        if (!string.IsNullOrEmpty(sessionId))
        {
            // Look up the proxy token from the pending session
            if (_backendAuthPending.TryGetValue(sessionId, out var pendingSession))
            {
                proxyToken = pendingSession.ProxyToken;
                Console.WriteLine($"{CYAN}   ℹ Resolved session {sessionId} → proxy token: {proxyToken[..Math.Min(8, proxyToken.Length)]}...{RESET}");
            }
            else
            {
                var errorResponse = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
                errorResponse.Headers.Add("Content-Type", "text/html");
                await errorResponse.WriteStringAsync("<html><body><h1>Error</h1><p>Invalid or expired session. Please retry the tool call to get a new authorization link.</p></body></html>");
                return errorResponse;
            }
        }
        else
        {
            // Legacy: accept proxy_token directly
            proxyToken = query["proxy_token"];
        }

        if (string.IsNullOrEmpty(proxyToken))
        {
            var errorResponse = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
            errorResponse.Headers.Add("Content-Type", "text/html");
            await errorResponse.WriteStringAsync("<html><body><h1>Error</h1><p>Missing proxy_token parameter</p></body></html>");
            return errorResponse;
        }

        Console.WriteLine($"{MAGENTA}   ⚡ Backend auth login for proxy token: {proxyToken[..Math.Min(8, proxyToken.Length)]}...{RESET}");

        if (AuthMode == "entra" && !string.IsNullOrEmpty(BackendClientId))
        {
            // Entra mode: redirect to Entra ID for App #2
            var state = Guid.NewGuid().ToString("N");
            var baseUrl = GetBaseUrl(req);
            var callbackUri = $"{baseUrl}/backend-auth/callback";

            _backendAuthPending[state] = new BackendAuthPending(proxyToken, state, DateTime.UtcNow);

            var entraAuthUrl = $"https://login.microsoftonline.com/{BackendTenantId}/oauth2/v2.0/authorize" +
                $"?response_type=code" +
                $"&client_id={Uri.EscapeDataString(BackendClientId)}" +
                $"&redirect_uri={Uri.EscapeDataString(callbackUri)}" +
                $"&scope={Uri.EscapeDataString(BackendScopes)}" +
                $"&state={Uri.EscapeDataString(state)}";

            Console.WriteLine($"{CYAN}   → Redirecting to Entra ID (App #2){RESET}");
            var response = req.CreateResponse(System.Net.HttpStatusCode.Redirect);
            response.Headers.Add("Location", entraAuthUrl);
            LogResponse("GET /backend-auth/login", 302, "→ Entra ID (App #2)");
            return response;
        }
        else
        {
            // Mock mode: auto-approve backend auth
            var mockToken = $"mock-backend-{Guid.NewGuid():N}";
            _backendAuthStore[proxyToken] = new BackendAuthRecord(
                proxyToken, mockToken, null, DateTime.UtcNow, 3600);

            Console.WriteLine($"{GREEN}   ✓ Mock backend auth granted{RESET}");

            var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/html");
            await response.WriteStringAsync(@"
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
            return response;
        }
    }

    /// <summary>
    /// GET /backend-auth/callback - Entra ID callback for AAD App #2.
    /// Exchanges Entra code for backend tokens and stores them server-side.
    /// </summary>
    [Function("BackendAuthCallback")]
    public async Task<HttpResponseData> BackendAuthCallback(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "backend-auth/callback")] HttpRequestData req)
    {
        await LogRequestDetails(req, "GET");

        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        var entraCode = query["code"];
        var state = query["state"];
        var error = query["error"];

        if (!string.IsNullOrEmpty(error))
        {
            Console.WriteLine($"{RED}   ✗ Entra App #2 returned error: {error}{RESET}");
            var errorResponse = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
            errorResponse.Headers.Add("Content-Type", "text/html");
            await errorResponse.WriteStringAsync($"<html><body><h1>Error</h1><p>{error}: {query["error_description"]}</p></body></html>");
            return errorResponse;
        }

        if (string.IsNullOrEmpty(entraCode) || string.IsNullOrEmpty(state))
        {
            var errorResponse = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
            errorResponse.Headers.Add("Content-Type", "text/html");
            await errorResponse.WriteStringAsync("<html><body><h1>Error</h1><p>Missing code or state</p></body></html>");
            return errorResponse;
        }

        if (!_backendAuthPending.TryRemove(state, out var pending))
        {
            var errorResponse = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
            errorResponse.Headers.Add("Content-Type", "text/html");
            await errorResponse.WriteStringAsync("<html><body><h1>Error</h1><p>Unknown state — session expired or already used</p></body></html>");
            return errorResponse;
        }

        Console.WriteLine($"{CYAN}   Exchanging Entra code for backend tokens (App #2)...{RESET}");

        var baseUrl = GetBaseUrl(req);
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
                var errorResponse = req.CreateResponse(System.Net.HttpStatusCode.InternalServerError);
                errorResponse.Headers.Add("Content-Type", "text/html");
                await errorResponse.WriteStringAsync("<html><body><h1>Error</h1><p>Failed to exchange code for backend tokens.</p></body></html>");
                return errorResponse;
            }

            using var tokenJson = JsonDocument.Parse(tokenBody);
            var backendAccessToken = tokenJson.RootElement.GetProperty("access_token").GetString()!;
            var backendRefreshToken = tokenJson.RootElement.TryGetProperty("refresh_token", out var rtProp) ? rtProp.GetString() : null;
            var expiresIn = tokenJson.RootElement.TryGetProperty("expires_in", out var expProp) ? expProp.GetInt32() : 3600;

            // Store backend tokens keyed by the proxy token
            _backendAuthStore[pending.ProxyToken] = new BackendAuthRecord(
                pending.ProxyToken, backendAccessToken, backendRefreshToken, DateTime.UtcNow, expiresIn);

            Console.WriteLine($"{GREEN}   ✓ Backend tokens stored for proxy token: {pending.ProxyToken[..Math.Min(8, pending.ProxyToken.Length)]}...{RESET}");

            var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
            response.Headers.Add("Content-Type", "text/html");
            await response.WriteStringAsync(@"
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
            return response;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{RED}   ✗ Backend token exchange error: {ex.Message}{RESET}");
            var errorResponse = req.CreateResponse(System.Net.HttpStatusCode.InternalServerError);
            errorResponse.Headers.Add("Content-Type", "text/html");
            await errorResponse.WriteStringAsync($"<html><body><h1>Error</h1><p>Token exchange failed: {ex.Message}</p></body></html>");
            return errorResponse;
        }
    }

    /// <summary>
    /// GET /backend-auth/status - Check backend auth status for a proxy token.
    /// </summary>
    [Function("BackendAuthStatus")]
    public async Task<HttpResponseData> BackendAuthStatus(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "backend-auth/status")] HttpRequestData req)
    {
        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        var proxyToken = query["proxy_token"];

        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "application/json");

        var isAuthorized = !string.IsNullOrEmpty(proxyToken) && _backendAuthStore.ContainsKey(proxyToken);

        await response.WriteStringAsync(JsonSerializer.Serialize(new
        {
            authorized = isAuthorized,
            proxy_token = proxyToken?[..Math.Min(8, proxyToken?.Length ?? 0)] + "..."
        }, new JsonSerializerOptions { WriteIndented = true }));

        return response;
    }

    // ── OAuth / CIMD Endpoints ──────────────────────────────────────────

    /// <summary>
    /// GET /oauth/authorize - OAuth Authorization Endpoint (CIMD)
    /// Accepts client_id as a URL to a CIMD metadata document.
    /// Mock mode: generates auth code directly.
    /// Entra mode: redirects to Entra ID for user authentication.
    /// </summary>
    [Function("OAuthAuthorize")]
    public async Task<HttpResponseData> OAuthAuthorize(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oauth/authorize")] HttpRequestData req)
    {
        await LogRequestDetails(req, "GET");

        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        var responseType = query["response_type"];
        var clientId = query["client_id"];
        var redirectUri = query["redirect_uri"];
        var scope = query["scope"] ?? GetScopesSupported();
        var state = query["state"] ?? "";

        Console.WriteLine($"{MAGENTA}   ⚡ OAuth Authorize: client_id={clientId}{RESET}");

        if (responseType != "code")
        {
            return await CreateOAuthErrorResponse(req, "unsupported_response_type", "Only response_type=code is supported");
        }

        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
        {
            return await CreateOAuthErrorResponse(req, "invalid_request", "client_id and redirect_uri are required");
        }

        // Fetch and validate CIMD document
        var (cimdValid, cimdError) = await ValidateCimd(clientId, redirectUri);
        if (!cimdValid)
        {
            Console.WriteLine($"{RED}   ✗ CIMD validation failed: {cimdError}{RESET}");
            return await CreateOAuthErrorResponse(req, "invalid_client", cimdError ?? "CIMD validation failed");
        }
        Console.WriteLine($"{GREEN}   ✓ CIMD validated for {clientId}{RESET}");

        if (AuthMode == "entra")
        {
            // Entra mode: redirect to Entra ID for authentication
            if (string.IsNullOrEmpty(AzureClientId))
            {
                return await CreateOAuthErrorResponse(req, "server_error", "AZURE_CLIENT_ID not configured");
            }

            var proxyState = Guid.NewGuid().ToString("N");
            var baseUrl = GetBaseUrl(req);
            var callbackUri = $"{baseUrl}/oauth/callback";

            // Store session for callback
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
            var response = req.CreateResponse(System.Net.HttpStatusCode.Redirect);
            response.Headers.Add("Location", entraAuthUrl);
            LogResponse("GET /oauth/authorize", 302, "→ Entra ID");
            return response;
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

            var response = req.CreateResponse(System.Net.HttpStatusCode.Redirect);
            response.Headers.Add("Location", location);
            LogResponse("GET /oauth/authorize", 302, $"→ {redirectUri}");
            return response;
        }
    }

    /// <summary>
    /// GET /oauth/callback - Entra ID callback (Entra mode only)
    /// Receives Entra auth code, exchanges for tokens, then redirects to client.
    /// </summary>
    [Function("OAuthCallback")]
    public async Task<HttpResponseData> OAuthCallback(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "oauth/callback")] HttpRequestData req)
    {
        await LogRequestDetails(req, "GET");

        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        var entraCode = query["code"];
        var proxyState = query["state"];
        var error = query["error"];

        if (!string.IsNullOrEmpty(error))
        {
            Console.WriteLine($"{RED}   ✗ Entra returned error: {error}{RESET}");
            return await CreateOAuthErrorResponse(req, "access_denied", $"Entra error: {error} - {query["error_description"]}");
        }

        if (string.IsNullOrEmpty(entraCode) || string.IsNullOrEmpty(proxyState))
        {
            return await CreateOAuthErrorResponse(req, "invalid_request", "Missing code or state from Entra callback");
        }

        if (!_authSessions.TryGetValue(proxyState, out var session))
        {
            return await CreateOAuthErrorResponse(req, "invalid_request", "Unknown state — session not found");
        }

        Console.WriteLine($"{CYAN}   Exchanging Entra code for tokens...{RESET}");

        // Exchange Entra auth code for tokens
        var baseUrl = GetBaseUrl(req);
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
                return await CreateOAuthErrorResponse(req, "server_error", "Failed to exchange Entra code for tokens");
            }

            using var tokenJson = JsonDocument.Parse(tokenBody);
            var entraAccessToken = tokenJson.RootElement.GetProperty("access_token").GetString();
            Console.WriteLine($"{GREEN}   ✓ Entra tokens received{RESET}");

            // Generate proxy auth code and update session
            var proxyCode = Guid.NewGuid().ToString("N");
            _authSessions[proxyCode] = session with
            {
                AuthCode = proxyCode,
                EntraAccessToken = entraAccessToken
            };
            // Clean up the state-keyed session
            _authSessions.TryRemove(proxyState, out _);

            var location = $"{session.RedirectUri}{(session.RedirectUri.Contains('?') ? '&' : '?')}code={Uri.EscapeDataString(proxyCode)}&state={Uri.EscapeDataString(session.State)}";
            Console.WriteLine($"{GREEN}   ✓ Proxy auth code issued, redirecting to client{RESET}");

            var response = req.CreateResponse(System.Net.HttpStatusCode.Redirect);
            response.Headers.Add("Location", location);
            LogResponse("GET /oauth/callback", 302, $"→ {session.RedirectUri}");
            return response;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{RED}   ✗ Entra token exchange error: {ex.Message}{RESET}");
            return await CreateOAuthErrorResponse(req, "server_error", $"Token exchange failed: {ex.Message}");
        }
    }

    /// <summary>
    /// POST /oauth/token - OAuth Token Endpoint
    /// Exchanges proxy authorization code for an access token.
    /// </summary>
    [Function("OAuthToken")]
    public async Task<HttpResponseData> OAuthToken(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "oauth/token")] HttpRequestData req)
    {
        await LogRequestDetails(req, "POST");

        var body = await new StreamReader(req.Body).ReadToEndAsync();
        var form = System.Web.HttpUtility.ParseQueryString(body);
        var grantType = form["grant_type"];
        var code = form["code"];
        var clientId = form["client_id"];

        Console.WriteLine($"{MAGENTA}   ⚡ Token Exchange: grant_type={grantType}, client_id={clientId}{RESET}");

        if (grantType != "authorization_code")
        {
            return await CreateOAuthTokenErrorResponse(req, "unsupported_grant_type", "Only authorization_code is supported");
        }

        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(clientId))
        {
            return await CreateOAuthTokenErrorResponse(req, "invalid_request", "code and client_id are required");
        }

        if (!_authSessions.TryGetValue(code, out var session))
        {
            return await CreateOAuthTokenErrorResponse(req, "invalid_grant", "Authorization code not found or expired");
        }

        if (session.IsRedeemed)
        {
            return await CreateOAuthTokenErrorResponse(req, "invalid_grant", "Authorization code has already been used");
        }

        if (session.ClientId != clientId)
        {
            return await CreateOAuthTokenErrorResponse(req, "invalid_grant", "client_id does not match the authorization request");
        }

        // Mark code as redeemed
        _authSessions[code] = session with { IsRedeemed = true };

        // Generate proxy access token
        var accessToken = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var expiresIn = 3600;

        _tokenStore[accessToken] = new TokenRecord(accessToken, clientId, session.Scope, DateTime.UtcNow, expiresIn);

        Console.WriteLine($"{GREEN}   ✓ Access token issued for {clientId}{RESET}");

        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "application/json");
        response.Headers.Add("Cache-Control", "no-store");

        var tokenResponse = new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = expiresIn,
            scope = session.Scope
        };

        await response.WriteStringAsync(JsonSerializer.Serialize(tokenResponse, new JsonSerializerOptions
        {
            WriteIndented = true
        }));

        LogResponse("POST /oauth/token", 200, $"token issued for {clientId}");
        return response;
    }

    // ── CIMD Validation ─────────────────────────────────────────────────

    private async Task<(bool IsValid, string? Error)> ValidateCimd(string clientId, string redirectUri)
    {
        // client_id must be a valid URL
        if (!Uri.TryCreate(clientId, UriKind.Absolute, out var clientIdUri))
        {
            return (false, "client_id is not a valid URL");
        }

        // Require HTTPS unless localhost (allow http for local development)
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

            // Validate client_id matches
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

            // Validate redirect_uri is listed
            if (root.TryGetProperty("redirect_uris", out var redirectUrisProp) && redirectUrisProp.ValueKind == JsonValueKind.Array)
            {
                var allowedUris = redirectUrisProp.EnumerateArray()
                    .Select(e => e.GetString())
                    .Where(u => u != null)
                    .ToList();

                // Per RFC 8252 Section 7.3, for loopback redirects the port must be
                // excluded from the redirect_uri comparison (native apps use dynamic ports).
                bool redirectMatch = false;
                if (Uri.TryCreate(redirectUri, UriKind.Absolute, out var reqRedirectUri)
                    && (reqRedirectUri.Host is "127.0.0.1" or "localhost" or "::1"))
                {
                    // Loopback: match scheme + host + path, ignore port
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

    private async Task<HttpResponseData> CreateOAuthErrorResponse(HttpRequestData req, string error, string description)
    {
        var response = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
        response.Headers.Add("Content-Type", "application/json");
        await response.WriteStringAsync(JsonSerializer.Serialize(new { error, error_description = description },
            new JsonSerializerOptions { WriteIndented = true }));
        LogResponse(req.Url.AbsolutePath, 400, description);
        return response;
    }

    private async Task<HttpResponseData> CreateOAuthTokenErrorResponse(HttpRequestData req, string error, string description)
    {
        var response = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
        response.Headers.Add("Content-Type", "application/json");
        response.Headers.Add("Cache-Control", "no-store");
        await response.WriteStringAsync(JsonSerializer.Serialize(new { error, error_description = description },
            new JsonSerializerOptions { WriteIndented = true }));
        LogResponse("POST /oauth/token", 400, description);
        return response;
    }
}
