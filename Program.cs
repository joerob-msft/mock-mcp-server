using Microsoft.Extensions.Logging;
using MockMcpServer;

var builder = WebApplication.CreateBuilder(args);

// Load local.settings.json "Values" section as configuration
builder.Configuration.AddJsonFile("local.settings.json", optional: true, reloadOnChange: false);
builder.Configuration.AddEnvironmentVariables();

// Bind the "Values" section so its keys become top-level config entries
var valuesSection = builder.Configuration.GetSection("Values");
if (valuesSection.Exists())
{
    foreach (var kvp in valuesSection.GetChildren())
    {
        if (kvp.Value != null)
        {
            builder.Configuration[kvp.Key] = kvp.Value;
            // Also set as env vars so static fields in McpServer pick them up
            Environment.SetEnvironmentVariable(kvp.Key, kvp.Value);
        }
    }
}

builder.Logging.SetMinimumLevel(LogLevel.Trace);
builder.Logging.AddConsole();

builder.Services.AddSingleton<McpServer>();
builder.Services.AddSingleton<BackendMcpServer>();
builder.Services.AddSingleton<BackendSseManager>();

// Run on port 7071 for local dev
builder.WebHost.UseUrls("http://0.0.0.0:7071");

var app = builder.Build();

var mcp = app.Services.GetRequiredService<McpServer>();
var backend = app.Services.GetRequiredService<BackendMcpServer>();
McpServer.SseManager = app.Services.GetRequiredService<BackendSseManager>();

app.MapGet("/mcp", (HttpContext ctx) => mcp.HandleMcpGet(ctx));
app.MapPost("/mcp", (HttpContext ctx) => mcp.HandleMcpPost(ctx));
app.MapGet("/.well-known/oauth-protected-resource", (HttpContext ctx) => mcp.HandlePRM(ctx));
app.MapGet("/.well-known/oauth-protected-resource/mcp", (HttpContext ctx) => mcp.HandlePRM(ctx));
app.MapGet("/.well-known/oauth-authorization-server", (HttpContext ctx) => mcp.HandleAuthServerMetadata(ctx));
app.MapGet("/oauth/authorize", (HttpContext ctx) => mcp.HandleOAuthAuthorize(ctx));
app.MapGet("/oauth/callback", (HttpContext ctx) => mcp.HandleOAuthCallback(ctx));
app.MapPost("/oauth/token", (HttpContext ctx) => mcp.HandleOAuthToken(ctx));
app.MapGet("/backend-auth/login", (HttpContext ctx) => mcp.HandleBackendAuthLogin(ctx));
app.MapGet("/backend-auth/callback", (HttpContext ctx) => mcp.HandleBackendAuthCallback(ctx));
app.MapGet("/backend-auth/status", (HttpContext ctx) => mcp.HandleBackendAuthStatus(ctx));
app.MapGet("/cimd-policy", (HttpContext ctx) => mcp.HandleCimdPolicy(ctx));
app.MapGet("/backend/mcp", (HttpContext ctx) => backend.HandleBackendMcpGet(ctx));
app.MapPost("/backend/mcp", (HttpContext ctx) => backend.HandleBackendMcpPost(ctx));

app.Run();
