# Nuclei MCP Server

This is a Mark3 Labs MCP server implementation for Nuclei, a fast and customizable vulnerability scanner, enhanced with AI-powered security analysis using the Bifrost LLM gateway.

## 🚀 New: AI-Powered Security Analysis

This server now includes Bifrost LLM integration, providing:

- **AI Vulnerability Analysis**: Deep analysis of security findings with expert insights
- **Smart Recommendations**: Prioritized, actionable security recommendations  
- **Multi-Provider Support**: Works with OpenAI, Anthropic, Google, and Mistral
- **Security-Expert Prompts**: All AI interactions use cybersecurity expert context

## Features

### Core Nuclei Integration
- **Caching**: Scan results are cached with configurable expiry to improve performance
- **Thread-safe**: Supports concurrent scanning operations
- **Template filtering**: Allows filtering by severity, protocols, and template IDs
- **Basic & Advanced Scanning**: Provides both simple and advanced scanning options

### AI-Powered Enhancements
- **Vulnerability Analysis**: AI-powered deep analysis of security findings
- **Security Recommendations**: Generate prioritized, actionable security advice
- **General Security Chat**: Interactive AI security consultant
- **Multi-LLM Support**: Compatible with OpenAI, Anthropic, Google, and Mistral
- **Cost-Optimized**: Uses efficient models to minimize API costs

## Usage

The server provides the following tools:

1. **nuclei_scan**: Perform a full Nuclei scan with template filtering
2. **basic_scan**: Perform a simple scan without template IDs
3. **vulnerability_resource**: Query scan results as resources
4. **advanced_scan**: Perform a comprehensive scan with extensive configuration options
5. **template_sources_scan**: Perform scans using custom template sources

## Running the Server

You can run the server directly using Go:

```bash
# From the nuclei directory
go run nuclei_mcp.go
```

## Using the MCP Inspector

The MCP Inspector is a powerful tool for debugging and testing your MCP server. To use it with the Nuclei MCP server:

```bash
# Install the MCP Inspector (if not already installed)
npm install -g @modelcontextprotocol/inspector

# Run the inspector with the Nuclei MCP server
npx @modelcontextprotocol/inspector go run ./nuclei_mcp.go
```

This will:
1. Start the MCP Inspector UI (available at http://localhost:5173)
2. Launch the Nuclei MCP server
3. Connect the inspector to the server

In the inspector UI, you can:
- View available tools and their schemas
- Execute tool calls and view results
- Inspect resources provided by the server
- Monitor server notifications

## Setup

### 1. Install Dependencies

```bash
go mod tidy
```

### 2. Configure LLM Providers (Optional)

Set up API keys for the LLM providers you want to use:

```bash
# OpenAI
export OPENAI_API_KEY="your-openai-api-key"

# Anthropic
export ANTHROPIC_API_KEY="your-anthropic-api-key"

# Google
export GOOGLE_API_KEY="your-google-api-key"

# Mistral
export MISTRAL_API_KEY="your-mistral-api-key"
```

*Note: LLM features are optional. The server will work without API keys, but AI-powered tools will not be available.*

### 3. Build and Run

```bash
# Build
go build -o nuclei-mcp cmd/nuclei-mcp/main.go

# Run
./nuclei-mcp
```

## Configuration

Configure the server via environment variables:

- `CACHE_EXPIRY`: Duration for cache expiry (default: 1h)
- `LOG_LEVEL`: Logging level (default: info)
- LLM API keys (see setup section above)

## Available Tools

### Core Nuclei Tools

- **`nuclei_scan`**: Perform comprehensive vulnerability scans
- **`basic_scan`**: Quick vulnerability scanning
- **`add_template`**: Add custom Nuclei templates
- **`list_templates`**: List available templates
- **`get_template`**: Retrieve template content

### AI-Powered Tools

- **`analyze_vulnerability`**: AI analysis of specific vulnerabilities
  - Provides risk assessment, impact analysis, and remediation steps
- **`generate_recommendations`**: AI-generated security recommendations
  - Creates prioritized action plans based on scan findings
- **`llm_chat`**: General security AI consultation
  - Interactive chat with cybersecurity AI expert

### Resources

- **`vulnerabilities`**: Recent vulnerability scan reports

## Example Workflows

### 1. Enhanced Security Assessment

```bash
# 1. Run Nuclei scan
nuclei_scan(target="https://example.com", severity="medium")

# 2. Analyze critical findings with AI
analyze_vulnerability(
  vulnerability_name="SQL Injection",
  description="User input not sanitized", 
  target="https://example.com/login"
)

# 3. Generate comprehensive recommendations
generate_recommendations(
  findings="SQL injection, Weak SSL, Directory traversal"
)
```

### 2. AI Security Consultation

```bash
# Ask security questions
llm_chat(
  message="What are the OWASP Top 10 and how do I test for them?",
  provider="openai"
)
```

For detailed usage examples, see [examples/llm_integration.md](examples/llm_integration.md).

## API

The server implements the standard MCP server interface. See the [Mark3 Labs MCP documentation](https://github.com/mark3labs/mcp-go) for details.
