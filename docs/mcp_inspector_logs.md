# MCP Inspector Logs and Documentation

## Terminal Output

When running the MCP inspector using `npx @modelcontextprotocol/inspector`, the following terminal output is observed:

```powershell
PS C:\Users\User\sources\nuclei-mcp> npx @modelcontextprotocol/inspector go run nuclei_mcp.go
Need to install the following packages:
@modelcontextprotocol/inspector@0.6.0
Ok to proceed? (y) y
Starting MCP inspector...
Proxy server listening on port 3000

 MCP Inspector is up and running at http://localhost:5173 
```

## Process Details

The MCP inspector sets up several components:

1. **Web Server**: Running on `http://localhost:5173`
2. **Proxy Server**: Listening on port 3000
3. **Transport Setup**:
   - Uses stdio transport
   - Command: `C:\Program Files\Go\bin\go.exe`
   - Arguments: `run nuclei_mcp.go`

## Nuclei MCP Integration

The `nuclei_mcp.go` implements the Model Context Protocol integration with Nuclei scanner:

1. **Core Components**:
   - `ScannerService`: Manages nuclei scanning operations with caching
   - `ResultCache`: Caches scan results with configurable expiry time
   - `ScanResult`: Stores target, scan time, and vulnerability findings

2. **Key Features**:
   - Thread-safe scanning operations
   - Template filtering by severity and protocols
   - Result caching for improved performance
   - Vulnerability resource handling via MCP server

## Environment Configuration

The inspector runs with a comprehensive environment configuration including:

- Standard system paths
- Go binary path
- Python paths
- Node.js paths
- Various development tool paths

## Connection Flow

1. Creates new SSE connection
2. Spawns stdio transport
3. Connects MCP client to backing server transport
4. Creates web app transport
5. Sets up MCP proxy

## Additional Resources

For more detailed information about the Model Context Protocol, refer to the official documentation at [modelcontextprotocol.io](https://modelcontextprotocol.io)
