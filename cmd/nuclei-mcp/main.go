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
	cfg, err := config.LoadConfig(".")
	if err != nil {
		log.Fatalf("cannot load config: %v", err)
	}

	consoleLogger, err := logging.NewConsoleLogger(cfg.Logging.Path)
	if err != nil {
		log.Fatalf("Failed to create console logger: %v", err)
	}
	defer consoleLogger.Close()

	resultCache := cache.NewResultCache(cfg.Cache.Expiry, log.New(os.Stdout, "[Cache] ", log.LstdFlags))
	scannerService := scanner.NewScannerService(resultCache, consoleLogger)

	consoleLogger.Log("Starting MCP inspector...")
	consoleLogger.Log("Proxy server listening on port 3000")
	consoleLogger.Log("🔍 MCP Inspector is up and running at http://localhost:5173 🚀")

	templateDir := "nuclei-templates"
	tm, err := templates.NewTemplateManager(templateDir)
	if err != nil {
		log.Fatalf("Failed to create template manager: %v", err)
	}

	mcpServer := api.NewNucleiMCPServer(scannerService, log.New(os.Stdout, "[MCP] ", log.LstdFlags), tm)
	sigChan := setupSignalHandling()
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := server.ServeStdio(mcpServer); err != nil {
			consoleLogger.Log("Failed to start MCP server: %v", err)
			cancel()
		}
	}()

	<-sigChan
	consoleLogger.Log("Shutting down...")
	cancel()
}
