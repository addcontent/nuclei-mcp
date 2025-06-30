# LLM Integration with Nuclei MCP Server

This document shows how to use the new AI-powered features in the Nuclei MCP server.

## Setup

1. Set up your LLM API keys as environment variables:

```bash
# For OpenAI
export OPENAI_API_KEY="your-openai-api-key"

# For Anthropic
export ANTHROPIC_API_KEY="your-anthropic-api-key"

# For Google
export GOOGLE_API_KEY="your-google-api-key"

# For Mistral
export MISTRAL_API_KEY="your-mistral-api-key"
```

2. Run the Nuclei MCP server:

```bash
go run cmd/nuclei-mcp/main.go
```

## New AI-Powered Tools

### 1. Vulnerability Analysis (`analyze_vulnerability`)

Analyzes a specific vulnerability using AI and provides detailed insights.

**Parameters:**
- `vulnerability_name` (required): Name of the vulnerability
- `description` (required): Description of the vulnerability  
- `target` (required): Target where the vulnerability was found

**Example usage:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "analyze_vulnerability",
    "arguments": {
      "vulnerability_name": "SQL Injection",
      "description": "User input is not properly sanitized in login form",
      "target": "https://example.com/login"
    }
  }
}
```

### 2. Security Recommendations (`generate_recommendations`)

Generates prioritized security recommendations based on scan findings.

**Parameters:**
- `findings` (required): Comma-separated list of security findings

**Example usage:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "generate_recommendations",
    "arguments": {
      "findings": "SQL injection found, Weak SSL configuration, Directory traversal vulnerability, Unencrypted admin panel"
    }
  }
}
```

### 3. General AI Chat (`llm_chat`)

General purpose AI chat for security-related questions and analysis.

**Parameters:**
- `message` (required): Message to send to the AI
- `provider` (optional): LLM provider (openai, anthropic, google, mistral)
- `model` (optional): Specific model to use

**Example usage:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "llm_chat",
    "arguments": {
      "message": "What are the most common web application vulnerabilities and how can I test for them?",
      "provider": "openai",
      "model": "gpt-4o-mini"
    }
  }
}
```

## Enhanced Nuclei Workflow

### Complete Security Assessment Workflow

1. **Run a Nuclei scan:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "nuclei_scan",
    "arguments": {
      "target": "https://example.com",
      "severity": "medium"
    }
  }
}
```

2. **Analyze specific vulnerabilities found:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "analyze_vulnerability",
    "arguments": {
      "vulnerability_name": "[Name from scan results]",
      "description": "[Description from scan results]",
      "target": "https://example.com"
    }
  }
}
```

3. **Generate comprehensive recommendations:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "generate_recommendations",
    "arguments": {
      "findings": "[Comma-separated list of all findings]"
    }
  }
}
```

## Features

- **Multi-provider support**: Works with OpenAI, Anthropic, Google, and Mistral
- **Automatic fallback**: Uses the first available configured provider
- **Security-focused prompts**: All AI interactions use security-expert system prompts
- **Token usage tracking**: Reports token consumption for cost monitoring
- **Context-aware analysis**: AI understands security context and provides actionable advice

## Configuration

The LLM service will automatically detect which providers you have API keys for and use the first available one. You can specify a particular provider in the `llm_chat` tool if you prefer.

### Default Models by Provider

- **OpenAI**: `gpt-4o-mini`
- **Anthropic**: `claude-3-5-sonnet-20241022`
- **Google**: `gemini-1.5-flash`
- **Mistral**: `mistral-small-latest`

These defaults prioritize cost-effectiveness while maintaining good performance for security analysis tasks.

## Error Handling

If no LLM API keys are configured, the server will start normally but the AI-powered tools will not be available. This ensures that the core Nuclei scanning functionality remains unaffected.

## Benefits

1. **Enhanced Analysis**: AI provides detailed vulnerability analysis beyond what automated scanners can offer
2. **Prioritized Recommendations**: Get actionable, prioritized security recommendations
3. **Expert Guidance**: AI acts as a security expert, providing context and best practices
4. **Workflow Integration**: Seamlessly integrates with existing Nuclei workflows
5. **Cost-Effective**: Uses efficient models to minimize API costs while maximizing value
