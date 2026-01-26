using System.Text;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;

namespace MockMcpServer.Functions;

public class McpFunctions
{
    private readonly ILogger<McpFunctions> _logger;

    public McpFunctions(ILogger<McpFunctions> logger)
    {
        _logger = logger;
    }

    [Function("McpGet")]
    public async Task<HttpResponseData> GetMcp(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "mcp")] HttpRequestData req)
    {
        _logger.LogInformation("=== MCP GET Request Received ===");
        await LogRequestDetails(req, "GET");

        var response = req.CreateResponse(System.Net.HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "application/json");

        var responseBody = new
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
            id = 1
        };

        await response.WriteStringAsync(JsonSerializer.Serialize(responseBody, new JsonSerializerOptions 
        { 
            WriteIndented = true 
        }));

        _logger.LogInformation("=== MCP GET Response Sent ===");
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
        
        try
        {
            using var jsonDoc = JsonDocument.Parse(requestBody);
            if (jsonDoc.RootElement.TryGetProperty("method", out var methodElement))
            {
                method = methodElement.GetString() ?? "unknown";
            }
            if (jsonDoc.RootElement.TryGetProperty("id", out var idElement))
            {
                requestId = idElement.GetInt32();
            }
            _logger.LogInformation("Parsed MCP Method: {Method}, Request ID: {RequestId}", method, requestId);
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
                    tools = new[]
                    {
                        new
                        {
                            name = "echo",
                            description = "Echoes back the input message",
                            inputSchema = new
                            {
                                type = "object",
                                properties = new
                                {
                                    message = new
                                    {
                                        type = "string",
                                        description = "The message to echo"
                                    }
                                },
                                required = new[] { "message" }
                            }
                        }
                    }
                },
                id = requestId ?? 1
            },
            "tools/call" => new
            {
                jsonrpc = "2.0",
                result = new
                {
                    content = new[]
                    {
                        new
                        {
                            type = "text",
                            text = "Mock response from echo tool"
                        }
                    }
                },
                id = requestId ?? 1
            },
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
}
