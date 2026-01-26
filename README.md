# Mock MCP Server - Azure Functions

A simple MCP (Model Context Protocol) server hosted on Azure Functions using .NET 8.

## Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/mcp` | Returns server capabilities |
| POST | `/api/mcp` | Handles MCP JSON-RPC requests |

Both endpoints are unauthenticated and include comprehensive request logging.

## Supported MCP Methods

The POST endpoint handles the following MCP methods:
- `initialize` - Returns server capabilities
- `tools/list` - Returns available tools (includes an "echo" tool)
- `tools/call` - Executes a tool call
- `resources/list` - Returns available resources (empty)
- `prompts/list` - Returns available prompts (empty)

## Local Development

### Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Azure Functions Core Tools v4](https://docs.microsoft.com/azure/azure-functions/functions-run-local)
- [Azure Storage Emulator](https://docs.microsoft.com/azure/storage/common/storage-use-azurite) (Azurite) or an Azure Storage account

### Running Locally

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/mock-mcp-server.git
   cd mock-mcp-server
   ```

2. Restore dependencies:
   ```bash
   dotnet restore
   ```

3. Start the function app:
   ```bash
   func start
   ```

4. Test the endpoints:
   ```bash
   # GET request
   curl http://localhost:7071/api/mcp

   # POST request (initialize)
   curl -X POST http://localhost:7071/api/mcp \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}'
   ```

## Deploy to Azure

### Option 1: GitHub Actions (Recommended)

1. **Create Azure Resources:**
   - Create a new Function App in the [Azure Portal](https://portal.azure.com)
   - Select **.NET 8** as the runtime stack
   - Select **Windows** or **Linux** as the operating system
   - Choose a hosting plan (Consumption plan for cost-effective option)

2. **Get Publish Profile:**
   - Go to your Function App in Azure Portal
   - Click **Get publish profile** in the Overview section
   - Download the `.PublishSettings` file

3. **Configure GitHub Secrets:**
   - Go to your GitHub repository → Settings → Secrets and variables → Actions
   - Add a new secret named `AZURE_FUNCTIONAPP_PUBLISH_PROFILE`
   - Paste the entire contents of the `.PublishSettings` file

4. **Update Workflow:**
   - Edit `.github/workflows/azure-functions-deploy.yml`
   - Update `AZURE_FUNCTIONAPP_NAME` with your Function App name

5. **Deploy:**
   - Push to the `main` branch or manually trigger the workflow
   - The app will automatically build and deploy

### Option 2: Azure Portal Deployment Center

1. **Create Azure Resources** (same as Option 1)

2. **Connect to GitHub:**
   - Go to your Function App in Azure Portal
   - Navigate to **Deployment Center** (under Deployment)
   - Select **GitHub** as the source
   - Authorize Azure to access your GitHub account
   - Select your repository and branch
   - Choose **GitHub Actions** as the build provider
   - Review and save

3. **Azure will automatically:**
   - Create a GitHub Actions workflow in your repository
   - Configure the publish profile secret
   - Start the first deployment

### Option 3: Manual Deployment (Azure CLI)

```bash
# Login to Azure
az login

# Create a resource group
az group create --name rg-mock-mcp --location eastus

# Create a storage account
az storage account create \
  --name stmockmcp$(date +%s) \
  --resource-group rg-mock-mcp \
  --location eastus \
  --sku Standard_LRS

# Create a function app
az functionapp create \
  --name mock-mcp-server \
  --resource-group rg-mock-mcp \
  --consumption-plan-location eastus \
  --runtime dotnet-isolated \
  --runtime-version 8 \
  --functions-version 4 \
  --storage-account <storage-account-name>

# Deploy
func azure functionapp publish mock-mcp-server
```

## Logging

The server includes comprehensive logging for debugging:

- **Request Details:** HTTP method, URL, headers, query parameters
- **Connection Info:** Host, port, scheme
- **Request Body:** Full JSON body for POST requests
- **MCP Method Parsing:** Extracted method name and request ID
- **Response Body:** Full JSON response being sent

### Viewing Logs

**Local Development:**
- Logs appear in the terminal where `func start` is running

**Azure Portal:**
- Go to your Function App → Monitor → Log stream
- Or use Application Insights for advanced querying

**Application Insights Query:**
```kusto
traces
| where message contains "MCP"
| order by timestamp desc
| take 100
```

## Project Structure

```
mock-mcp-server/
├── .github/
│   └── workflows/
│       └── azure-functions-deploy.yml  # GitHub Actions deployment
├── Functions/
│   └── McpFunctions.cs                 # MCP endpoint handlers
├── .gitignore
├── host.json                           # Azure Functions host configuration
├── local.settings.json                 # Local development settings
├── MockMcpServer.csproj                # Project file
├── Program.cs                          # Application entry point
└── README.md
```

## Configuration

### host.json

Controls logging levels and HTTP routing:
- Route prefix: `/api` (endpoints are at `/api/mcp`)
- Logging: Set to `Trace` for detailed logs

### local.settings.json

Local development settings (not deployed):
- `AzureWebJobsStorage`: Storage connection (use Azurite locally)
- `FUNCTIONS_WORKER_RUNTIME`: `dotnet-isolated`

## License

MIT
