package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/maximhq/bifrost/core/schemas"
	"nuclei-mcp/pkg/cache"
	"nuclei-mcp/pkg/llm"
	"nuclei-mcp/pkg/scanner"
	"nuclei-mcp/pkg/templates"
)

// NewNucleiMCPServer creates a new MCP server for Nuclei
func NewNucleiMCPServer(service *scanner.ScannerService, logger *log.Logger, tm *templates.TemplateManager, llmService *llm.Service) *server.MCPServer {
	mcpServer := server.NewMCPServer(
		"nuclei-scanner",
		"1.0.0",
		server.WithLogging(),
	)

	// Add Nuclei scan tool
	mcpServer.AddTool(mcp.NewTool("nuclei_scan",
		mcp.WithDescription("Performs a Nuclei vulnerability scan on a target"),
		mcp.WithString("target",
			mcp.Description("Target URL or IP to scan"),
			mcp.Required(),
		),
		mcp.WithString("severity",
			mcp.Description("Minimum severity level (info, low, medium, high, critical)"),
			mcp.DefaultString("info"),
		),
		mcp.WithString("protocols",
			mcp.Description("Protocols to scan (comma-separated: http,https,tcp,etc)"),
			mcp.DefaultString("http"),
		),
		mcp.WithBoolean("thread_safe",
			mcp.Description("Use thread-safe engine for scanning"),
		),
		mcp.WithString("template_ids",
			mcp.Description("Comma-separated template IDs to run (e.g. \"self-signed-ssl,nameserver-fingerprint\")"),
		),
		mcp.WithString("template_id",
			mcp.Description("Single template ID to run (alternative to template_ids)"),
		),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleNucleiScanTool(ctx, request, service, logger)
	})

	// Add Basic scan tool
	mcpServer.AddTool(mcp.NewTool("basic_scan",
		mcp.WithDescription("Performs a basic Nuclei vulnerability scan on a target without requiring template IDs"),
		mcp.WithString("target",
			mcp.Description("Target URL or IP to scan"),
			mcp.Required(),
		),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleBasicScanTool(ctx, request, service, logger)
	})

	// Add vulnerability resource
	mcpServer.AddResource(mcp.NewResource("vulnerabilities", "Recent Vulnerability Reports"), 
	func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return handleVulnerabilityResource(ctx, request, service, logger)
	})

	// Add template management tools
	mcpServer.AddTool(mcp.NewTool("add_template",
		mcp.WithDescription("Adds a new Nuclei template."),
		mcp.WithString("name", mcp.Description("The name of the template file."), mcp.Required()),
		mcp.WithString("content", mcp.Description("The content of the template file."), mcp.Required()),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleAddTemplate(ctx, request, tm)
	})

	mcpServer.AddTool(mcp.NewTool("list_templates",
		mcp.WithDescription("Lists all available Nuclei templates."),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleListTemplates(ctx, request, tm)
	})

	mcpServer.AddTool(mcp.NewTool("get_template",
		mcp.WithDescription("Gets the content of a specific Nuclei template."),
		mcp.WithString("name", mcp.Description("The name of the template file."), mcp.Required()),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleGetTemplate(ctx, request, tm)
	})

	// Add LLM-powered vulnerability analysis tool
	if llmService != nil {
		mcpServer.AddTool(mcp.NewTool("analyze_vulnerability",
			mcp.WithDescription("Uses AI to analyze a vulnerability and provide detailed insights and recommendations."),
			mcp.WithString("vulnerability_name", mcp.Description("The name of the vulnerability."), mcp.Required()),
			mcp.WithString("description", mcp.Description("Description of the vulnerability."), mcp.Required()),
			mcp.WithString("target", mcp.Description("The target where the vulnerability was found."), mcp.Required()),
		), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return handleAnalyzeVulnerability(ctx, request, llmService)
		})

		mcpServer.AddTool(mcp.NewTool("generate_recommendations",
			mcp.WithDescription("Uses AI to generate security recommendations based on scan findings."),
			mcp.WithString("findings", mcp.Description("Comma-separated list of security findings."), mcp.Required()),
		), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return handleGenerateRecommendations(ctx, request, llmService)
		})

		mcpServer.AddTool(mcp.NewTool("llm_chat",
			mcp.WithDescription("General purpose AI chat for security-related questions and analysis."),
			mcp.WithString("message", mcp.Description("The message to send to the AI."), mcp.Required()),
			mcp.WithString("provider", mcp.Description("LLM provider (openai, anthropic, google, mistral). Optional, uses first available."), mcp.DefaultString("auto")),
			mcp.WithString("model", mcp.Description("Specific model to use. Optional, uses provider default."), mcp.DefaultString("auto")),
		), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return handleLLMChat(ctx, request, llmService)
		})
	}

	return mcpServer
}

// handleNucleiScanTool handles the nuclei_scan tool requests
func handleNucleiScanTool(
	ctx context.Context,
	request mcp.CallToolRequest,
	service *scanner.ScannerService,
	_ *log.Logger,
) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid arguments format")
	}

	// Extract parameters
	target, ok := argMap["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("invalid or missing target parameter")
	}

	severity, _ := argMap["severity"].(string)
	if severity == "" {
		severity = "info"
	}

	protocols, _ := argMap["protocols"].(string)
	if protocols == "" {
		protocols = "http,https"
	}

	threadSafe, _ := argMap["thread_safe"].(bool)

	// Extract template IDs if provided
	var templateIDs []string
	if ids, ok := argMap["template_ids"].(string); ok && ids != "" {
		templateIDs = strings.Split(ids, ",")
	}

	// Also check for single template_id
	if id, ok := argMap["template_id"].(string); ok && id != "" {
		templateIDs = append(templateIDs, id)
	}

	// Perform scan
	var result cache.ScanResult
	var err error

	if threadSafe {
		result, err = service.ThreadSafeScan(ctx, target, severity, protocols, templateIDs)
	} else {
		result, err = service.Scan(target, severity, protocols, templateIDs)
	}
	
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}
	
	// Format findings
	var responseText string
	if len(result.Findings) == 0 {
		responseText = fmt.Sprintf("No vulnerabilities found for target: %s", target)
	} else {
		responseText = fmt.Sprintf("Found %d vulnerabilities for target: %s\n\n", len(result.Findings), target)
		
		for i, finding := range result.Findings {
			responseText += fmt.Sprintf("Finding #%d:\n", i+1)
			responseText += fmt.Sprintf("- Name: %s\n", finding.Info.Name)
			responseText += fmt.Sprintf("- Severity: %s\n", finding.Info.SeverityHolder.Severity.String())
			responseText += fmt.Sprintf("- Description: %s\n", finding.Info.Description)
			responseText += fmt.Sprintf("- URL: %s\n\n", finding.Host)
		}
	}
	
	return mcp.NewToolResultText(responseText), nil
}

// handleBasicScanTool handles the basic_scan tool requests
func handleBasicScanTool(
	_ context.Context,
	request mcp.CallToolRequest,
	service *scanner.ScannerService,
	logger *log.Logger,
) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid arguments format")
	}

	// Extract target parameter
	target, ok := argMap["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("invalid or missing target parameter")
	}
	
	// Perform basic scan
	result, err := service.BasicScan(target)
	if err != nil {
		logger.Printf("Basic scan failed: %v", err)
		return nil, err
	}
	
	// Convert findings to a simplified format for the response
	type SimplifiedFinding struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		URL         string `json:"url"`
	}
	
	simplifiedFindings := make([]SimplifiedFinding, 0, len(result.Findings))
	for _, finding := range result.Findings {
		simplifiedFindings = append(simplifiedFindings, SimplifiedFinding{
			Name:        finding.Info.Name,
			Severity:    finding.Info.SeverityHolder.Severity.String(),
			Description: finding.Info.Description,
			URL:         finding.Host,
		})
	}
	
	// Create response
	response := map[string]interface{}{
		"target":         result.Target,
		"scan_time":      result.ScanTime.Format(time.RFC3339),
		"findings_count": len(result.Findings),
		"findings":       simplifiedFindings,
	}
	
	// Marshal response to JSON
	responseJSON, err := json.Marshal(response)
	if err != nil {
		logger.Printf("Failed to marshal response: %v", err)
		return nil, err
	}
	
	return mcp.NewToolResultText(string(responseJSON)), nil
}

// handleVulnerabilityResource handles the vulnerability resource requests
func handleVulnerabilityResource(
	_ context.Context,
	_ mcp.ReadResourceRequest,
	service *scanner.ScannerService,
	_ *log.Logger,
) ([]mcp.ResourceContents, error) {
	results := service.Cache.GetAll()

	var recentScans []map[string]interface{}
	for _, result := range results {
		scanInfo := map[string]interface{}{
			"target":    result.Target,
			"scan_time": result.ScanTime.Format(time.RFC3339),
			"findings":  len(result.Findings),
		}
		
		// Add some sample findings
		if len(result.Findings) > 0 {
			var sampleFindings []map[string]string
			// Limit to 5 findings for brevity
			count := min(5, len(result.Findings))
			for i := 0; i < count; i++ {
				finding := result.Findings[i]
				sampleFindings = append(sampleFindings, map[string]string{
					"name":        finding.Info.Name,
					"severity":    finding.Info.SeverityHolder.Severity.String(),
					"description": finding.Info.Description,
					"url":         finding.Host,
				})
			}
			scanInfo["sample_findings"] = sampleFindings
		}
		
		recentScans = append(recentScans, scanInfo)
	}
	
	report := map[string]interface{}{
		"timestamp":     time.Now().Format(time.RFC3339),
		"recent_scans":  recentScans,
		"total_scans":   len(recentScans),
	}
	
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report: %w", err)
	}
	
	return []mcp.ResourceContents{
		mcp.TextResourceContents{
			URI:      "vulnerabilities",
			MIMEType: "application/json",
			Text:     string(reportJSON),
		},
	},
	nil
}

// min returns the smaller of x or y
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// handleAddTemplate handles the add_template tool requests
func handleAddTemplate(_ context.Context, request mcp.CallToolRequest, tm *templates.TemplateManager) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid arguments format")
	}

	name, ok := argMap["name"].(string)
	if !ok || name == "" {
		return nil, fmt.Errorf("invalid or missing name parameter")
	}

	content, ok := argMap["content"].(string)
	if !ok || content == "" {
		return nil, fmt.Errorf("invalid or missing content parameter")
	}

	if err := tm.AddTemplate(name, []byte(content)); err != nil {
		return nil, fmt.Errorf("failed to add template: %w", err)
	}

	return mcp.NewToolResultText(fmt.Sprintf("Template '%s' added successfully.", name)), nil
}

// handleListTemplates handles the list_templates tool requests
func handleListTemplates(_ context.Context, _ mcp.CallToolRequest, tm *templates.TemplateManager) (*mcp.CallToolResult, error) {
	templateFiles, err := tm.ListTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to list templates: %w", err)
	}

	if len(templateFiles) == 0 {
		return mcp.NewToolResultText("No custom templates found."), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Available templates:\n- %s", strings.Join(templateFiles, "\n- "))), nil
}

// handleGetTemplate handles the get_template tool requests
func handleGetTemplate(_ context.Context, request mcp.CallToolRequest, tm *templates.TemplateManager) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid arguments format")
	}

	name, ok := argMap["name"].(string)
	if !ok || name == "" {
		return nil, fmt.Errorf("invalid or missing name parameter")
	}

	content, err := tm.GetTemplate(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	return mcp.NewToolResultText(string(content)), nil
}

// handleAnalyzeVulnerability handles the analyze_vulnerability tool requests
func handleAnalyzeVulnerability(ctx context.Context, request mcp.CallToolRequest, llmService *llm.Service) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid arguments format")
	}

	vulnName, ok := argMap["vulnerability_name"].(string)
	if !ok || vulnName == "" {
		return nil, fmt.Errorf("invalid or missing vulnerability_name parameter")
	}

	description, ok := argMap["description"].(string)
	if !ok || description == "" {
		return nil, fmt.Errorf("invalid or missing description parameter")
	}

	target, ok := argMap["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("invalid or missing target parameter")
	}

	response, err := llmService.AnalyzeVulnerability(ctx, vulnName, description, target)
	if err != nil {
		return nil, fmt.Errorf("vulnerability analysis failed: %w", err)
	}

	// Format the response with metadata
	formattedResponse := fmt.Sprintf("# AI Vulnerability Analysis\n\n**Vulnerability:** %s\n**Target:** %s\n**Provider:** %s\n**Model:** %s\n\n---\n\n%s",
		vulnName, target, response.Provider, response.Model, response.Content)

	if response.Usage != nil {
		formattedResponse += fmt.Sprintf("\n\n---\n\n**Token Usage:** %d total (%d prompt + %d completion)",
			response.Usage.TotalTokens, response.Usage.PromptTokens, response.Usage.CompletionTokens)
	}

	return mcp.NewToolResultText(formattedResponse), nil
}

// handleGenerateRecommendations handles the generate_recommendations tool requests
func handleGenerateRecommendations(ctx context.Context, request mcp.CallToolRequest, llmService *llm.Service) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid arguments format")
	}

	findingsStr, ok := argMap["findings"].(string)
	if !ok || findingsStr == "" {
		return nil, fmt.Errorf("invalid or missing findings parameter")
	}

	// Split findings by comma
	findings := strings.Split(findingsStr, ",")
	for i, finding := range findings {
		findings[i] = strings.TrimSpace(finding)
	}

	response, err := llmService.GenerateRecommendations(ctx, findings)
	if err != nil {
		return nil, fmt.Errorf("recommendation generation failed: %w", err)
	}

	// Format the response with metadata
	formattedResponse := fmt.Sprintf("# AI Security Recommendations\n\n**Findings Analyzed:** %d\n**Provider:** %s\n**Model:** %s\n\n---\n\n%s",
		len(findings), response.Provider, response.Model, response.Content)

	if response.Usage != nil {
		formattedResponse += fmt.Sprintf("\n\n---\n\n**Token Usage:** %d total (%d prompt + %d completion)",
			response.Usage.TotalTokens, response.Usage.PromptTokens, response.Usage.CompletionTokens)
	}

	return mcp.NewToolResultText(formattedResponse), nil
}

// handleLLMChat handles the llm_chat tool requests
func handleLLMChat(ctx context.Context, request mcp.CallToolRequest, llmService *llm.Service) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid arguments format")
	}

	message, ok := argMap["message"].(string)
	if !ok || message == "" {
		return nil, fmt.Errorf("invalid or missing message parameter")
	}

	providerStr, _ := argMap["provider"].(string)
	modelStr, _ := argMap["model"].(string)

	// Get available providers
	providers, err := llmService.GetAccount().GetConfiguredProviders()
	if err != nil || len(providers) == 0 {
		return nil, fmt.Errorf("no LLM providers configured")
	}

	// Select provider
	var provider schemas.ModelProvider
	if providerStr == "auto" || providerStr == "" {
		provider = providers[0] // Use first available
	} else {
		// Parse provider string
		switch strings.ToLower(providerStr) {
		case "openai":
			provider = schemas.OpenAI
		case "anthropic":
			provider = schemas.Anthropic
		case "google":
			provider = schemas.Google
		case "mistral":
			provider = schemas.Mistral
		default:
			return nil, fmt.Errorf("unsupported provider: %s", providerStr)
		}
	}

	// Select model
	var model string
	if modelStr == "auto" || modelStr == "" {
		// Use default model for provider
		switch provider {
		case schemas.OpenAI:
			model = "gpt-4o-mini"
		case schemas.Anthropic:
			model = "claude-3-5-sonnet-20241022"
		case schemas.Google:
			model = "gemini-1.5-flash"
		case schemas.Mistral:
			model = "mistral-small-latest"
		default:
			model = "gpt-4o-mini"
		}
	} else {
		model = modelStr
	}

	// Create chat request
	req := llm.ChatRequest{
		Provider: provider,
		Model:    model,
		Messages: []llm.ChatMessage{
			{Role: "user", Content: message},
		},
		SystemPrompt: "You are a cybersecurity expert assistant. Provide helpful, accurate, and actionable security advice.",
		MaxTokens:    2000,
		Temperature:  0.3,
	}

	response, err := llmService.ChatCompletion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("chat completion failed: %w", err)
	}

	// Format the response with metadata
	formattedResponse := fmt.Sprintf("# AI Chat Response\n\n**Provider:** %s\n**Model:** %s\n\n---\n\n%s",
		response.Provider, response.Model, response.Content)

	if response.Usage != nil {
		formattedResponse += fmt.Sprintf("\n\n---\n\n**Token Usage:** %d total (%d prompt + %d completion)",
			response.Usage.TotalTokens, response.Usage.PromptTokens, response.Usage.CompletionTokens)
	}

	return mcp.NewToolResultText(formattedResponse), nil
}
