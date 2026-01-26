using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var host = new HostBuilder()
    .ConfigureFunctionsWebApplication()
    .ConfigureServices(services =>
    {
        services.AddApplicationInsightsTelemetryWorkerService();
        services.ConfigureFunctionsApplicationInsights();
    })
    .ConfigureLogging(logging =>
    {
        // Set minimum log level to Trace to capture all logs
        logging.SetMinimumLevel(LogLevel.Trace);
        
        // Add console logging for local development
        logging.AddConsole();
    })
    .Build();

host.Run();
