package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"nuclei-mcp/pkg/api"
	"nuclei-mcp/pkg/cache"
	"nuclei-mcp/pkg/config"
	"nuclei-mcp/pkg/llm"
	"nuclei-mcp/pkg/logging"
	"nuclei-mcp/pkg/scanner"
	"nuclei-mcp/pkg/templates"

	"github.com/mark3labs/mcp-go/server"
)

// setupSignalHandling configures graceful shutdown
func setupSignalHandling() chan os.Signal {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	return sigs
}

func main() {
	// Load configuration
	cfg, err := config.LoadConfig(".")
	if err != nil {
		log.Fatalf("cannot load config: %v", err)
	}

	// Create console logger
	consoleLogger, err := logging.NewConsoleLogger(cfg.Logging.Path)
	if err != nil {
		log.Fatalf("Failed to create console logger: %v", err)
	}
	defer consoleLogger.Close()

	// Create result cache
	resultCache := cache.NewResultCache(cfg.Cache.Expiry, log.New(os.Stdout, "[Cache] ", log.LstdFlags))

	// Create scanner service with console logger
	scannerService := scanner.NewScannerService(resultCache, consoleLogger)

	// Log startup information
	consoleLogger.Log("Starting MCP inspector...")
	consoleLogger.Log("Proxy server listening on port 3000")
	consoleLogger.Log("🔍 MCP Inspector is up and running at http://localhost:5173 🚀")

	// Create Template Manager
	templateDir := "nuclei-templates"
	tm, err := templates.NewTemplateManager(templateDir)
	if err != nil {
		log.Fatalf("Failed to create template manager: %v", err)
	}

	// Create LLM service (optional - will be nil if no API keys are configured)
	llmService, err := llm.NewService(log.New(os.Stdout, "[LLM] ", log.LstdFlags))
	if err != nil {
		consoleLogger.Log("LLM service initialization failed (this is optional): %v", err)
		llmService = nil // Continue without LLM capabilities
	} else {
		consoleLogger.Log("LLM service initialized successfully")
		defer llmService.Close()
	}

	// Create MCP server
	mcpServer := api.NewNucleiMCPServer(scannerService, log.New(os.Stdout, "[MCP] ", log.LstdFlags), tm, llmService)

	// Set up signal handling for graceful shutdown
	sigChan := setupSignalHandling()

	// Create context for graceful shutdown
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server using stdio transport
	go func() {
		if err := server.ServeStdio(mcpServer); err != nil {
			consoleLogger.Log("Failed to start MCP server: %v", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	consoleLogger.Log("Shutting down...")

	// Cancel context to stop server
	cancel()
}
