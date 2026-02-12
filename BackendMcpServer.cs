using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace MockMcpServer;

/// <summary>
/// Simulated backend MCP server. In production this would be a separate service.
/// Validates backend tokens, serves tools via JSON-RPC, and supports SSE notifications.
/// </summary>
public class BackendMcpServer
{
    private const string CYAN = "\u001b[36m";
    private const string GREEN = "\u001b[32m";
    private const string YELLOW = "\u001b[33m";
    private const string RED = "\u001b[31m";
    private const string MAGENTA = "\u001b[35m";
    private const string RESET = "\u001b[0m";

    private static readonly bool VerboseLogging =
        Environment.GetEnvironmentVariable("MCP_VERBOSE_LOGGING")?.ToLower() == "true";

    // Tracks initialized backend sessions by session ID (from Mcp-Session-Id header)
    private readonly ConcurrentDictionary<string, bool> _initializedSessions = new();

    // Active SSE connections keyed by session ID
    private readonly ConcurrentDictionary<string, BackendSseConnection> _sseConnections = new();

    private class BackendSseConnection
    {
        public HttpResponse Response { get; init; } = null!;
        public CancellationToken RequestAborted { get; init; }
    }

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    /// <summary>
    /// POST /backend/mcp — JSON-RPC handler for the simulated backend.
    /// </summary>
    public async Task HandleBackendMcpPost(HttpContext context)
    {
        Console.WriteLine($"{CYAN}── BACKEND POST /backend/mcp ──{RESET}");

        // Validate bearer token against backend auth store
        var token = ExtractBearer(context);
        if (token == null || !McpServer.IsValidBackendToken(token))
        {
            Console.WriteLine($"{RED}   ✗ Backend: invalid or missing backend token{RESET}");
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("{\"error\":\"unauthorized\"}");
            return;
        }

        var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
        string method = "unknown";
        int? requestId = null;
        string? toolName = null;
        JsonElement? toolArguments = null;

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("method", out var m))
                method = m.GetString() ?? "unknown";
            if (doc.RootElement.TryGetProperty("id", out var idEl))
            {
                if (idEl.ValueKind == JsonValueKind.Number) requestId = idEl.GetInt32();
                else if (idEl.ValueKind == JsonValueKind.String && int.TryParse(idEl.GetString(), out var p)) requestId = p;
            }
            if (method == "tools/call" && doc.RootElement.TryGetProperty("params", out var pars))
            {
                if (pars.TryGetProperty("name", out var n)) toolName = n.GetString();
                if (pars.TryGetProperty("arguments", out var a)) toolArguments = a.Clone();
            }
        }
        catch (JsonException ex)
        {
            Console.WriteLine($"{YELLOW}   ⚠ Backend JSON parse error: {ex.Message}{RESET}");
        }

        Console.WriteLine($"{MAGENTA}   Backend method: {method}{RESET}");

        var sessionId = context.Request.Headers["Mcp-Session-Id"].FirstOrDefault() ?? "default";

        object response = method switch
        {
            "initialize" => HandleInitialize(sessionId, requestId),
            "tools/list" => HandleToolsList(sessionId, requestId),
            "tools/call" => HandleToolCall(sessionId, toolName, toolArguments, requestId),
            _ => new { jsonrpc = "2.0", result = new { message = $"Backend: unknown method '{method}'" }, id = requestId ?? 1 }
        };

        context.Response.StatusCode = 200;
        context.Response.Headers["Content-Type"] = "application/json";
        var json = JsonSerializer.Serialize(response, JsonOpts);
        if (VerboseLogging) Console.WriteLine($"{GREEN}   Backend response: {json}{RESET}");
        await context.Response.WriteAsync(json);

        Console.WriteLine($"{GREEN}   ✓ Backend POST /backend/mcp ({method}) → 200{RESET}");
    }

    /// <summary>
    /// GET /backend/mcp — SSE endpoint for backend push notifications.
    /// </summary>
    public async Task HandleBackendMcpGet(HttpContext context)
    {
        Console.WriteLine($"{CYAN}── BACKEND GET /backend/mcp (SSE) ──{RESET}");

        var token = ExtractBearer(context);
        if (token == null || !McpServer.IsValidBackendToken(token))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("{\"error\":\"unauthorized\"}");
            return;
        }

        var accept = context.Request.Headers["Accept"].FirstOrDefault() ?? "";
        if (!accept.Contains("text/event-stream"))
        {
            context.Response.StatusCode = 200;
            context.Response.Headers["Content-Type"] = "application/json";
            await context.Response.WriteAsync("{\"status\":\"backend ok\"}");
            return;
        }

        var sessionId = context.Request.Headers["Mcp-Session-Id"].FirstOrDefault() ?? Guid.NewGuid().ToString("N")[..12];

        context.Response.StatusCode = 200;
        context.Response.Headers["Content-Type"] = "text/event-stream";
        context.Response.Headers["Cache-Control"] = "no-cache";
        context.Response.Headers["Connection"] = "keep-alive";
        await context.Response.Body.FlushAsync();

        var conn = new BackendSseConnection { Response = context.Response, RequestAborted = context.RequestAborted };
        _sseConnections[sessionId] = conn;
        Console.WriteLine($"{GREEN}   ✓ Backend SSE connection opened: session={sessionId}{RESET}");

        try
        {
            while (!context.RequestAborted.IsCancellationRequested)
            {
                await Task.Delay(30_000, context.RequestAborted);
                await context.Response.WriteAsync(": keepalive\n\n", context.RequestAborted);
                await context.Response.Body.FlushAsync(context.RequestAborted);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            _sseConnections.TryRemove(sessionId, out _);
            Console.WriteLine($"{YELLOW}   ⚠ Backend SSE connection closed: session={sessionId}{RESET}");
        }
    }

    /// <summary>
    /// Push a notification to a backend SSE session.
    /// </summary>
    public async Task TriggerNotification(string sessionId, string notificationJson)
    {
        if (_sseConnections.TryGetValue(sessionId, out var conn))
        {
            try
            {
                if (!conn.RequestAborted.IsCancellationRequested)
                {
                    await conn.Response.WriteAsync($"event: message\ndata: {notificationJson}\n\n", conn.RequestAborted);
                    await conn.Response.Body.FlushAsync(conn.RequestAborted);
                    Console.WriteLine($"{GREEN}   ✓ Backend SSE notification sent to session={sessionId}{RESET}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{RED}   ✗ Backend SSE notification error: {ex.Message}{RESET}");
            }
        }
    }

    // ── Private helpers ─────────────────────────────────────────────────

    private object HandleInitialize(string sessionId, int? requestId)
    {
        _initializedSessions[sessionId] = true;
        Console.WriteLine($"{GREEN}   ✓ Backend session initialized: {sessionId}{RESET}");
        return new
        {
            jsonrpc = "2.0",
            result = new
            {
                protocolVersion = "2024-11-05",
                capabilities = new { tools = new { listChanged = true } },
                serverInfo = new { name = "mock-backend-mcp-server", version = "1.0.0" }
            },
            id = requestId ?? 1
        };
    }

    private object HandleToolsList(string sessionId, int? requestId)
    {
        Console.WriteLine($"{CYAN}   Backend tools/list for session={sessionId}{RESET}");
        return new
        {
            jsonrpc = "2.0",
            result = new { tools = GetBackendTools() },
            id = requestId ?? 1
        };
    }

    private object HandleToolCall(string sessionId, string? toolName, JsonElement? arguments, int? requestId)
    {
        Console.WriteLine($"{MAGENTA}   Backend tools/call: {toolName} (session={sessionId}){RESET}");

        string text = toolName switch
        {
            "echo" => EchoTool(arguments),
            "get_weather" => WeatherTool(arguments),
            "calculate" => CalculateTool(arguments),
            _ => $"Backend: unknown tool '{toolName}'"
        };

        return new
        {
            jsonrpc = "2.0",
            result = new { content = new[] { new { type = "text", text } } },
            id = requestId ?? 1
        };
    }

    private static object[] GetBackendTools() => new object[]
    {
        new
        {
            name = "echo",
            description = "Echoes back the input message",
            inputSchema = new
            {
                type = "object",
                properties = new Dictionary<string, object>
                {
                    ["message"] = new { type = "string", description = "The message to echo back" }
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
                    ["location"] = new { type = "string", description = "The city or location to get weather for" }
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
                    ["expression"] = new { type = "string", description = "The mathematical expression to evaluate" }
                },
                required = new[] { "expression" }
            }
        }
    };

    private static string EchoTool(JsonElement? args)
    {
        if (args.HasValue && args.Value.TryGetProperty("message", out var m))
            return $"[Backend] Echo: {m.GetString() ?? "No message provided"}";
        return "[Backend] Echo: No message provided";
    }

    private static string WeatherTool(JsonElement? args)
    {
        var loc = "Unknown";
        if (args.HasValue && args.Value.TryGetProperty("location", out var l))
            loc = l.GetString() ?? "Unknown";
        return $"[Backend] Weather for {loc}: Sunny, 72°F (22°C), Humidity: 45%, Wind: 10 mph NW. (Mock data from backend)";
    }

    private static string CalculateTool(JsonElement? args)
    {
        var expr = "unknown";
        if (args.HasValue && args.Value.TryGetProperty("expression", out var e))
            expr = e.GetString() ?? "unknown";
        return $"[Backend] The result of '{expr}' is 42. (Mock data from backend)";
    }

    private static string? ExtractBearer(HttpContext context)
    {
        if (!context.Request.Headers.TryGetValue("Authorization", out var vals)) return null;
        var h = vals.FirstOrDefault();
        if (h?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
            return h.Substring(7).Trim();
        return null;
    }
}
