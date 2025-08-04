# Nuclei MCP Integration

A Model Context Protocol (MCP) server implementation that integrates Nuclei, a fast and customizable vulnerability scanner, with the MCP ecosystem. This server provides a standardized interface for performing security scans and managing vulnerability assessments programmatically.

## Features

- **Vulnerability Scanning**: Perform comprehensive security scans using Nuclei's powerful scanning engine
- **Template Management**: Add, list, and manage custom Nuclei templates
- **Result Caching**: Configurable caching system to optimize repeated scans
- **Concurrent Operations**: Thread-safe implementation for high-performance scanning
- **RESTful API**: Standardized interface for integration with other MCP-compliant tools
- **Detailed Reporting**: Structured vulnerability reports with severity levels and remediation guidance

## Tools & Endpoints

### Core Tools

- **nuclei_scan**: Perform a full Nuclei scan with advanced filtering options
- **basic_scan**: Quick scan with minimal configuration
- **vulnerability_resource**: Query and retrieve scan results
- **add_template**: Add custom Nuclei templates
- **list_templates**: View available templates
- **get_template**: Retrieve details of a specific template

## Getting Started

### Prerequisites

- Nuclei (will be automatically downloaded if not present)
- Node.js 14+ (for MCP Inspector, optional)

### Installation

#### Option 1: Download Pre-built Binary (Recommended)

1. Download the latest release for your platform from the [Releases page](https://github.com/your-org/nuclei-mcp/releases)
2. Extract the archive
3. Run the binary:

   ```bash
   # Linux/macOS
   ./nuclei-mcp
   
   # Windows
   nuclei-mcp.exe
   ```

#### Option 2: Install with Go

```bash
go install github.com/your-org/nuclei-mcp/cmd/nuclei-mcp@latest
```

#### Option 3: Build from Source

1. Clone the repository:

   ```bash
   git clone https://github.com/your-org/nuclei-mcp.git
   cd nuclei-mcp
   ```

2. Install dependencies:

   ```bash
   go mod download
   ```

3. Build and run:

   ```bash
   go build -o nuclei-mcp ./cmd/nuclei-mcp
   ./nuclei-mcp
   ```

### Running the Server

Start the MCP server:

```bash
# If using pre-built binary
./nuclei-mcp

# If built from source
go run cmd/nuclei-mcp/main.go
```

### Using the MCP Inspector

For development and testing, use the MCP Inspector:

```bash
# Install the MCP Inspector globally
npm install -g @modelcontextprotocol/inspector

# Start the inspector with the Nuclei MCP server
npx @modelcontextprotocol/inspector go run cmd/nuclei-mcp/main.go
```

The inspector UI will be available at [http://localhost:5173](http://localhost:5173)

##  Configuration

Configuration can be managed through a YAML configuration file or environment variables. The server looks for configuration in the following locations (in order of precedence):

1. File specified by `--config` flag
2. `config.yaml` in the current directory
3. `$HOME/.nuclei-mcp/config.yaml`
4. `/etc/nuclei-mcp/config.yaml`

### Configuration File Example

Create a `config.yaml` file with the following structure:

```yaml
server:
  name: "nuclei-mcp"
  version: "1.0.0"
  port: 3000
  host: "127.0.0.1"

cache:
  enabled: true
  expiry: 1h
  max_size: 1000

logging:
  level: "info"
  path: "./logs/nuclei-mcp.log"
  max_size_mb: 10
  max_backups: 5
  max_age_days: 30
  compress: true

nuclei:
  templates_directory: "nuclei-templates"
  timeout: 5m
  rate_limit: 150
  bulk_size: 25
  template_threads: 10
  headless: false
  show_browser: false
  system_resolvers: true
```

### Environment Variables

All configuration options can also be set using environment variables with the `NUCLEI_MCP_` prefix (e.g., `NUCLEI_MCP_SERVER_PORT=3000`). Nested configuration can be set using double underscores (e.g., `NUCLEI_MCP_LOGGING_LEVEL=debug`).

### MCP Client Configuration

To connect an MCP client to the Nuclei MCP server, use the following connection parameters:

- **Transport**: `stdio` (when running as a subprocess) or `http` (when running as a standalone server)
- **Command**: `go run cmd/nuclei-mcp/main.go` (for development) or the compiled binary path
- **Working Directory**: The root directory of the nuclei-mcp project

For HTTP connections, the server will be available at `http://127.0.0.1:3000` by default (configurable via the `server.port` and `server.host` configuration options).

Example MCP client configuration (JSON):

```json
{
  "mcpServers": {
    "nuclei-scanner": {
      "command": "go",
      "args": ["run", "cmd/nuclei-mcp/main.go"],
      "env": {
        "NUCLEI_MCP_SERVER_PORT": "3000",
        "NUCLEI_MCP_CACHE_ENABLED": "true"
      }
    }
  }
}
```

##  Releases

This project uses [GoReleaser](https://goreleaser.com/) for automated releases. Each release includes:

- **Cross-platform binaries** for Linux, macOS, and Windows (amd64 and arm64)
- **Checksums** for integrity verification
- **Automated changelog** generation
- **GitHub Actions** for CI/CD

### Creating a Release

To create a new release:

1. **Tag the release:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **GitHub Actions will automatically:**
   - Build binaries for all supported platforms
   - Create release archives
   - Generate checksums
   - Create a GitHub release with changelog
   - Upload all artifacts

### Manual Release (Development)

For testing releases locally:

```bash
# Test release build (no publishing)
goreleaser release --snapshot --clean

# Check configuration
goreleaser check
```

##  Important Note

This project is under active development. Breaking changes may be introduced in future releases. Please ensure you pin to a specific version when using this in production environments.

##  Documentation

- [MCP Protocol Documentation](https://modelcontextprotocol.io)
- [Nuclei Documentation](https://nuclei.projectdiscovery.io/)

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](./CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects
 Big thanks to the following projects that inspired and contributed to this implementation:
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [MCP Go](https://github.com/mark3labs/mcp-go)
