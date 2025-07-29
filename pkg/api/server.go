package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"nuclei-mcp/pkg/cache"
	"nuclei-mcp/pkg/scanner"
	"nuclei-mcp/pkg/templates"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func NewNucleiMCPServer(service scanner.ScannerService, logger *log.Logger, tm templates.TemplateManager) *server.MCPServer {
	mcpServer := server.NewMCPServer(
		"nuclei-scanner",
		"1.0.0",
		server.WithLogging(),
	)

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
		return HandleNucleiScanTool(ctx, request, service, logger)
	})

	mcpServer.AddTool(mcp.NewTool("basic_scan",
		mcp.WithDescription("Performs a basic Nuclei vulnerability scan on a target without requiring template IDs"),
		mcp.WithString("target",
			mcp.Description("Target URL or IP to scan"),
			mcp.Required(),
		),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return HandleBasicScanTool(ctx, request, service, logger)
	})


	// Add vulnerability resource
	mcpServer.AddResource(mcp.NewResource("vulnerabilities", "Recent Vulnerability Reports"),
		func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return handleVulnerabilityResource(ctx, request, service, logger)
		})

	mcpServer.AddTool(mcp.NewTool("add_template",
		mcp.WithDescription("Adds a new Nuclei template."),
		mcp.WithString("name", mcp.Description("The name of the template file."), mcp.Required()),
		mcp.WithString("content", mcp.Description("The content of the template file."), mcp.Required()),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return HandleAddTemplate(ctx, request, tm)
	})

	mcpServer.AddTool(mcp.NewTool("list_templates",
		mcp.WithDescription("Lists all available Nuclei templates."),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return HandleListTemplates(ctx, request, tm)
	})

	mcpServer.AddTool(mcp.NewTool("get_template",
		mcp.WithDescription("Gets the content of a specific Nuclei template."),
		mcp.WithString("name", mcp.Description("The name of the template file."), mcp.Required()),
	), func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return HandleGetTemplate(ctx, request, tm)
	})

	return mcpServer
}

func HandleNucleiScanTool(
	ctx context.Context,
	request mcp.CallToolRequest,
	service scanner.ScannerService,
	_ *log.Logger,
) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid arguments format")
	}

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

	var templateIDs []string
	if ids, ok := argMap["template_ids"].(string); ok && ids != "" {
		templateIDs = strings.Split(ids, ",")
	}

	if id, ok := argMap["template_id"].(string); ok && id != "" {
		templateIDs = append(templateIDs, id)
	}

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

func HandleBasicScanTool(
	_ context.Context,
	request mcp.CallToolRequest,
	service scanner.ScannerService,
	logger *log.Logger,
) (*mcp.CallToolResult, error) {
	argMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid arguments format")
	}

	target, ok := argMap["target"].(string)
	if !ok || target == "" {
		return nil, fmt.Errorf("invalid or missing target parameter")
	}


	result, err := service.BasicScan(target)
	if err != nil {
		logger.Printf("Basic scan failed: %v", err)
		return nil, err
	}


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


	response := map[string]interface{}{
		"target":         result.Target,
		"scan_time":      result.ScanTime.Format(time.RFC3339),
		"findings_count": len(result.Findings),
		"findings":       simplifiedFindings,
	}


	responseJSON, err := json.Marshal(response)
	if err != nil {
		logger.Printf("Failed to marshal response: %v", err)
		return nil, err
	}

	return mcp.NewToolResultText(string(responseJSON)), nil
}

func HandleVulnerabilityResource(
	_ context.Context,
	_ mcp.ReadResourceRequest,
	service scanner.ScannerService,
	_ *log.Logger,
) ([]mcp.ResourceContents, error) {
	results := service.GetAll()

	var recentScans []map[string]interface{}
	for _, result := range results {
		scanInfo := map[string]interface{}{
			"target":    result.Target,
			"scan_time": result.ScanTime.Format(time.RFC3339),
			"findings":  len(result.Findings),
		}



		if len(result.Findings) > 0 {
			var sampleFindings []map[string]string

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
		"timestamp":    time.Now().Format(time.RFC3339),
		"recent_scans": recentScans,
		"total_scans":  len(recentScans),
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

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func HandleAddTemplate(_ context.Context, request mcp.CallToolRequest, tm templates.TemplateManager) (*mcp.CallToolResult, error) {
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

func HandleListTemplates(_ context.Context, _ mcp.CallToolRequest, tm templates.TemplateManager) (*mcp.CallToolResult, error) {
	templateFiles, err := tm.ListTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to list templates: %w", err)
	}

	if len(templateFiles) == 0 {
		return mcp.NewToolResultText("No custom templates found."), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Available templates:\n- %s", strings.Join(templateFiles, "\n- "))), nil
}

func HandleGetTemplate(_ context.Context, request mcp.CallToolRequest, tm templates.TemplateManager) (*mcp.CallToolResult, error) {
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
