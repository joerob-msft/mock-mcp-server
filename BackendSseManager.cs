using System.Collections.Concurrent;

namespace MockMcpServer;

/// <summary>
/// In-process SSE sidecar that manages persistent SSE connections to the backend MCP server.
/// When the backend pushes a notification, this relays it to the proxy client via McpServer.NotifyClient.
/// </summary>
public class BackendSseManager
{
    private const string CYAN = "\u001b[36m";
    private const string GREEN = "\u001b[32m";
    private const string YELLOW = "\u001b[33m";
    private const string RED = "\u001b[31m";
    private const string RESET = "\u001b[0m";

    private readonly HttpClient _httpClient = new();
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _connections = new();

    /// <summary>
    /// Opens a persistent SSE connection to the backend and relays notifications to the proxy client.
    /// </summary>
    public void ConnectToBackend(string proxyToken, string backendToken, string backendUrl)
    {
        // Disconnect any existing connection for this proxy token
        Disconnect(proxyToken);

        var cts = new CancellationTokenSource();
        _connections[proxyToken] = cts;

        _ = Task.Run(async () => await ReadSseLoop(proxyToken, backendToken, backendUrl, cts.Token));
        Console.WriteLine($"{GREEN}   ✓ BackendSseManager: started SSE connection for proxy token {proxyToken[..Math.Min(8, proxyToken.Length)]}...{RESET}");
    }

    /// <summary>
    /// Disconnects the SSE connection for the given proxy token.
    /// </summary>
    public void Disconnect(string proxyToken)
    {
        if (_connections.TryRemove(proxyToken, out var cts))
        {
            cts.Cancel();
            cts.Dispose();
            Console.WriteLine($"{YELLOW}   ⚠ BackendSseManager: disconnected SSE for proxy token {proxyToken[..Math.Min(8, proxyToken.Length)]}...{RESET}");
        }
    }

    private async Task ReadSseLoop(string proxyToken, string backendToken, string backendUrl, CancellationToken ct)
    {
        int retryDelay = 1000; // start at 1s, exponential backoff up to 30s
        const int maxRetryDelay = 30_000;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, backendUrl);
                request.Headers.Add("Accept", "text/event-stream");
                request.Headers.Add("Authorization", $"Bearer {backendToken}");

                using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"{RED}   ✗ BackendSseManager: backend returned {(int)response.StatusCode}{RESET}");
                    await Task.Delay(retryDelay, ct);
                    retryDelay = Math.Min(retryDelay * 2, maxRetryDelay);
                    continue;
                }

                retryDelay = 1000; // reset on successful connect
                Console.WriteLine($"{GREEN}   ✓ BackendSseManager: SSE stream connected{RESET}");

                using var stream = await response.Content.ReadAsStreamAsync(ct);
                using var reader = new StreamReader(stream);

                while (!ct.IsCancellationRequested && !reader.EndOfStream)
                {
                    var line = await reader.ReadLineAsync(ct);
                    if (line == null) break;

                    // SSE data lines start with "data: "
                    if (line.StartsWith("data: "))
                    {
                        var json = line.Substring(6);
                        Console.WriteLine($"{CYAN}   ℹ BackendSseManager: relaying notification to proxy client{RESET}");
                        await McpServer.NotifyClient(proxyToken, json);
                    }
                    // Ignore comments (":") and event type lines
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{RED}   ✗ BackendSseManager: error: {ex.Message}{RESET}");
            }

            if (!ct.IsCancellationRequested)
            {
                await Task.Delay(retryDelay, ct).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
                retryDelay = Math.Min(retryDelay * 2, maxRetryDelay);
            }
        }
    }
}
