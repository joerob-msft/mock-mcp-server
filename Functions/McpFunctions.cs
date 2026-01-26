using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

namespace MockMcpServer.Functions;

public class McpFunctions
{
    private readonly ILogger<McpFunctions> _logger;
    
    // In-memory consent store - maps session tokens to consent status
    private static readonly ConcurrentDictionary<string, ConsentRecord> _consentStore = new();

    public McpFunctions(ILogger<McpFunctions> logger)
    {
        _logger = logger;
    }

    private record ConsentRecord(string SessionToken, string ToolName, DateTime GrantedAt, bool IsGranted);

    [Function("McpGet")]
    public async Task<HttpResponseData> GetMcp(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "mcp")] HttpRequestData req)
    {
        _logger.LogInformation("=== MCP GET Request Received (SSE not supported) ===");
        await LogRequestDetails(req, "GET");

        // SSE (Server-Sent Events) is not supported - return 405 Method Not Allowed
        var response = req.CreateResponse(System.Net.HttpStatusCode.MethodNotAllowed);
        response.Headers.Add("Content-Type", "application/json");

        var responseBody = new
        {
            jsonrpc = "2.0",
            error = new
            {
                code = -32601,
                message = "SSE transport is not supported. Use HTTP POST to /mcp for JSON-RPC requests."
            },
            id = (int?)null
        };

        await response.WriteStringAsync(JsonSerializer.Serialize(responseBody, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        }));

        _logger.LogInformation("=== MCP GET Response Sent (405 Method Not Allowed) ===");
        return response;
    }

    [Function("ConsentPage")]
    public async Task<HttpResponseData> ConsentPage(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "consent")] HttpRequestData req)
    {
        _logger.LogInformation("=== Consent Page Request ===");
        await LogRequestDetails(req, "GET");

        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        var sessionToken = query["session"];
        var toolName = query["tool"];
        var callbackUrl = query["callback"];

        _logger.LogInformation("Consent request - Session: {Session}, Tool: {Tool}, Callback: {Callback}", 
            sessionToken, toolName, callbackUrl);

        if (string.IsNullOrEmpty(sessionToken))
        {
            var errorResponse = req.CreateResponse(System.Net.HttpStatusCode.BadRequest);
            errorResponse.Headers.Add("Content-Type", "text/html");
            await errorResponse.WriteStringAsync("<html><body><h1>Error</h1><p>Missing session token</p></body></html>");
            return errorResponse;
        }

        // Check if this is a grant action (form submission)
        var action = query["action"];
        if (action == "grant")
        {
            // Store consent
            var consentRecord = new ConsentRecord(sessionToken, toolName ?? "all", DateTime.UtcNow, true);
            _consentStore[sessionToken] = consentRecord;
            _logger.LogInformation("Consent GRANTED for session: {Session}, tool: {Tool}", sessionToken, toolName);

            var successResponse = req.CreateResponse(System.Net.HttpStatusCode.OK);
            successResponse.Headers.Add("Content-Type", "text/html");
            
            var successHtml = $@"
<!DOCTYPE html>
<html>
<head>
    <title>Consent Granted - Mock MCP Server</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               max-width: 600px; margin: 100px auto; padding: 20px; text-align: center; }}
        .success {{ color: #28a745; font-size: 48px; }}
        h1 {{ color: #333; }}
        p {{ color: #666; line-height: 1.6; }}
        .session {{ font-family: monospace; background: #f5f5f5; padding: 10px; border-radius: 4px; 
                   word-break: break-all; }}
    </style>
</head>
<body>
    <div class='success'>✓</div>
    <h1>Consent Granted!</h1>
    <p>You have authorized the tool <strong>{toolName ?? "all tools"}</strong> to execute.</p>
    <p>Session token:</p>
    <div class='session'>{sessionToken}</div>
    <p style='margin-top: 30px; color: #888;'>You can close this window and retry your tool call.</p>
</body>
</html>";
            await successResponse.WriteStringAsync(successHtml);
            return successResponse;
        }

        // Show consent form
        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "text/html");
        
        var baseUrl = $"{req.Url.Scheme}://{req.Url.Host}:{req.Url.Port}";
        var grantUrl = $"{baseUrl}/api/consent?session={Uri.EscapeDataString(sessionToken)}&tool={Uri.EscapeDataString(toolName ?? "")}&action=grant";
        
        var html = $@"
<!DOCTYPE html>
<html>
<head>
    <title>Consent Required - Mock MCP Server</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               max-width: 600px; margin: 100px auto; padding: 20px; }}
        .warning {{ color: #856404; background: #fff3cd; border: 1px solid #ffc107; 
                   padding: 15px; border-radius: 8px; margin-bottom: 20px; }}
        h1 {{ color: #333; }}
        p {{ color: #666; line-height: 1.6; }}
        .tool-name {{ font-family: monospace; background: #e9ecef; padding: 2px 8px; 
                     border-radius: 4px; font-weight: bold; }}
        .session {{ font-family: monospace; background: #f5f5f5; padding: 10px; border-radius: 4px; 
                   font-size: 12px; word-break: break-all; margin: 15px 0; }}
        .btn {{ display: inline-block; padding: 12px 24px; margin: 10px; border-radius: 6px; 
               text-decoration: none; font-weight: bold; cursor: pointer; }}
        .btn-grant {{ background: #28a745; color: white; border: none; }}
        .btn-grant:hover {{ background: #218838; }}
        .btn-deny {{ background: #dc3545; color: white; border: none; }}
        .btn-deny:hover {{ background: #c82333; }}
        .buttons {{ margin-top: 30px; }}
    </style>
</head>
<body>
    <h1>🔐 Consent Required</h1>
    <div class='warning'>
        <strong>Authorization Request</strong><br>
        An application is requesting permission to execute a tool on your behalf.
    </div>
    <p>The <span class='tool-name'>{toolName ?? "unknown"}</span> tool is requesting permission to execute.</p>
    <p>Session token:</p>
    <div class='session'>{sessionToken}</div>
    <p>By clicking <strong>Grant Access</strong>, you authorize this tool to execute and return results.</p>
    <div class='buttons'>
        <a href='{grantUrl}' class='btn btn-grant'>✓ Grant Access</a>
        <button class='btn btn-deny' onclick='window.close()'>✗ Deny</button>
    </div>
    <p style='margin-top: 40px; font-size: 12px; color: #888;'>
        This is a mock consent flow for testing MCP elicitation responses.
    </p>
</body>
</html>";
        
        await response.WriteStringAsync(html);
        return response;
    }

    [Function("ConsentStatus")]
    public async Task<HttpResponseData> ConsentStatus(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "consent/status")] HttpRequestData req)
    {
        _logger.LogInformation("=== Consent Status Check ===");
        
        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        var sessionToken = query["session"];

        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "application/json");

        if (string.IsNullOrEmpty(sessionToken))
        {
            await response.WriteStringAsync(JsonSerializer.Serialize(new { granted = false, error = "Missing session token" }));
            return response;
        }

        var isGranted = _consentStore.TryGetValue(sessionToken, out var record) && record.IsGranted;
        _logger.LogInformation("Consent status for session {Session}: {Status}", sessionToken, isGranted ? "GRANTED" : "NOT GRANTED");

        await response.WriteStringAsync(JsonSerializer.Serialize(new 
        { 
            granted = isGranted,
            session = sessionToken,
            tool = record?.ToolName,
            grantedAt = record?.GrantedAt
        }, new JsonSerializerOptions { WriteIndented = true }));
        
        return response;
    }

    [Function("McpPost")]
    public async Task<HttpResponseData> PostMcp(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "mcp")] HttpRequestData req)
    {
        _logger.LogInformation("=== MCP POST Request Received ===");
        await LogRequestDetails(req, "POST");

        // Read and log the request body
        string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
        _logger.LogInformation("Request Body: {Body}", requestBody);

        // Parse the request to determine the method being called
        string method = "unknown";
        int? requestId = null;
        string? toolName = null;
        JsonElement? toolArguments = null;
        
        try
        {
            using var jsonDoc = JsonDocument.Parse(requestBody);
            if (jsonDoc.RootElement.TryGetProperty("method", out var methodElement))
            {
                method = methodElement.GetString() ?? "unknown";
            }
            if (jsonDoc.RootElement.TryGetProperty("id", out var idElement))
            {
                if (idElement.ValueKind == JsonValueKind.Number)
                {
                    requestId = idElement.GetInt32();
                }
                else if (idElement.ValueKind == JsonValueKind.String)
                {
                    if (int.TryParse(idElement.GetString(), out var parsedId))
                    {
                        requestId = parsedId;
                    }
                }
            }
            
            // Extract tool name and arguments for tools/call
            if (method == "tools/call" && jsonDoc.RootElement.TryGetProperty("params", out var paramsElement))
            {
                if (paramsElement.TryGetProperty("name", out var nameElement))
                {
                    toolName = nameElement.GetString();
                }
                if (paramsElement.TryGetProperty("arguments", out var argsElement))
                {
                    toolArguments = argsElement.Clone();
                }
            }
            
            _logger.LogInformation("Parsed MCP Method: {Method}, Request ID: {RequestId}, Tool: {ToolName}", 
                method, requestId, toolName ?? "N/A");
            
            if (toolArguments.HasValue)
            {
                _logger.LogInformation("Tool Arguments: {Arguments}", toolArguments.Value.ToString());
            }
        }
        catch (JsonException ex)
        {
            _logger.LogWarning("Failed to parse request body as JSON: {Error}", ex.Message);
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
                        tools = new { listChanged = false },
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
            "tools/list" => new
            {
                jsonrpc = "2.0",
                result = new
                {
                    tools = new object[]
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
                    }
                },
                id = requestId ?? 1
            },
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
        
        _logger.LogInformation("Response Body: {ResponseBody}", jsonResponse);
        await response.WriteStringAsync(jsonResponse);

        _logger.LogInformation("=== MCP POST Response Sent ===");
        return response;
    }

    private async Task LogRequestDetails(HttpRequestData req, string httpMethod)
    {
        _logger.LogInformation("HTTP Method: {Method}", httpMethod);
        _logger.LogInformation("URL: {Url}", req.Url.ToString());
        
        _logger.LogInformation("--- Request Headers ---");
        foreach (var header in req.Headers)
        {
            _logger.LogInformation("Header: {Key} = {Value}", header.Key, string.Join(", ", header.Value));
        }

        _logger.LogInformation("--- Query Parameters ---");
        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        foreach (string? key in query.AllKeys)
        {
            if (key != null)
            {
                _logger.LogInformation("Query: {Key} = {Value}", key, query[key]);
            }
        }

        _logger.LogInformation("--- Connection Info ---");
        _logger.LogInformation("Host: {Host}", req.Url.Host);
        _logger.LogInformation("Port: {Port}", req.Url.Port);
        _logger.LogInformation("Scheme: {Scheme}", req.Url.Scheme);

        await Task.CompletedTask;
    }

    private object GenerateToolCallResponse(string? toolName, JsonElement? arguments, int? requestId, HttpRequestData req)
    {
        _logger.LogInformation("Generating response for tool: {ToolName}", toolName ?? "unknown");

        // Generate a session token based on the request (in real world, this would come from auth)
        // For mock purposes, we'll use a hash of tool name + timestamp or check for existing session
        var sessionToken = GetOrCreateSessionToken(toolName, arguments);
        
        // Check if consent has been granted for this session
        if (!_consentStore.TryGetValue(sessionToken, out var consentRecord) || !consentRecord.IsGranted)
        {
            _logger.LogInformation("Consent NOT granted for session: {Session}. Returning elicitation response.", sessionToken);
            
            // Build the consent URL
            var baseUrl = $"{req.Url.Scheme}://{req.Url.Host}:{req.Url.Port}";
            var consentUrl = $"{baseUrl}/api/consent?session={Uri.EscapeDataString(sessionToken)}&tool={Uri.EscapeDataString(toolName ?? "unknown")}";
            
            // Return an elicitation response requesting consent
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
                            text = $"🔐 **Consent Required**\n\nThe tool `{toolName}` requires your authorization before it can execute.\n\nPlease click the link below to grant consent:\n\n👉 [{consentUrl}]({consentUrl})\n\nOnce you've granted consent, please retry the tool call."
                        }
                    },
                    // Include elicitation metadata
                    _meta = new
                    {
                        elicitation = new
                        {
                            type = "consent_required",
                            consentUrl = consentUrl,
                            sessionToken = sessionToken,
                            toolName = toolName,
                            message = "User consent is required to execute this tool. Please visit the consent URL to authorize.",
                            statusUrl = $"{baseUrl}/api/consent/status?session={Uri.EscapeDataString(sessionToken)}"
                        }
                    }
                },
                id = requestId ?? 1
            };
        }

        _logger.LogInformation("Consent GRANTED for session: {Session}. Executing tool: {Tool}", sessionToken, toolName);
        
        // Consent granted - execute the tool
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
                },
                _meta = new
                {
                    consentSession = sessionToken,
                    consentGrantedAt = consentRecord.GrantedAt
                }
            },
            id = requestId ?? 1
        };
    }

    private string GetOrCreateSessionToken(string? toolName, JsonElement? arguments)
    {
        // Create a deterministic session token based on tool and arguments
        // This allows the same request to get the same session token
        var input = $"{toolName}:{arguments?.ToString() ?? "no-args"}";
        using var sha = System.Security.Cryptography.SHA256.Create();
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(hash)[..16].Replace("+", "x").Replace("/", "y");
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
}
