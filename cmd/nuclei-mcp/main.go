package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"nuclei-mcp/pkg/api"
	"nuclei-mcp/pkg/cache"
	"nuclei-mcp/pkg/config"
	"nuclei-mcp/pkg/logging"
	"nuclei-mcp/pkg/scanner"
	"nuclei-mcp/pkg/templates"

	mcp "github.com/mark3labs/mcp-go/server"
	"github.com/sirupsen/logrus"
)

// setupSignalHandling configures graceful shutdown
func setupSignalHandling() chan os.Signal {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	return sigs
}

// setupLogging initializes the application logger
func setupLogging(cfg config.LoggingConfig) (*logging.ConsoleLogger, error) {
	// Ensure log directory exists
	logDir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Initialize the logger
	logger, err := logging.NewConsoleLogger(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Set log level
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		logger.Log("Warning: Invalid log level '%s', defaulting to 'info'", cfg.Level)
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)

	return logger, nil
}

func main() {
	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	consoleLogger, err := setupLogging(cfg.Logging)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer consoleLogger.Close()

	// Log startup information
	consoleLogger.Log("Starting %s v%s", cfg.Server.Name, cfg.Server.Version)
	consoleLogger.Log("Server will listen on %s:%d", cfg.Server.Host, cfg.Server.Port)

	// Initialize cache if enabled
	var resultCache cache.ResultCacheInterface
	if cfg.Cache.Enabled {
		consoleLogger.Log("Initializing cache with expiry: %v", cfg.Cache.Expiry)
		resultCache = cache.NewResultCache(cfg.Cache.Expiry, log.New(os.Stderr, "[Cache] ", log.LstdFlags))
	} else {
		consoleLogger.Log("Cache is disabled")
		resultCache = cache.NewNoopCache()
	}

	// Resolve the absolute path for the templates directory to ensure correct file access
	templatesDir, err := filepath.Abs(cfg.Nuclei.TemplatesDirectory)
	if err != nil {
		consoleLogger.Log("Error resolving templates directory path: %v", err)
		os.Exit(1)
	}
	consoleLogger.Log("Using templates directory: %s", templatesDir)

	// Initialize scanner service with the absolute path
	scannerService := scanner.NewScannerService(resultCache, consoleLogger, templatesDir)

	// Initialize template manager with the absolute path
	templateManager, err := templates.NewTemplateManager(templatesDir)
	if err != nil {
		consoleLogger.Log("Failed to initialize template manager: %v", err)
		os.Exit(1)
	}

	// Create MCP server
	mcpServer := api.NewNucleiMCPServer(scannerService, log.New(os.Stderr, "[MCP] ", log.LstdFlags), templateManager)

	// Start the MCP server using stdio transport
	serverErr := make(chan error, 1)
	go func() {
		consoleLogger.Log("Starting MCP server with stdio transport")
		if err := mcp.ServeStdio(mcpServer); err != nil {
			serverErr <- fmt.Errorf("error starting MCP server: %w", err)
			return
		}
	}()

	// Set up signal handling
	signals := setupSignalHandling()

	// Wait for server error or interrupt signal
	select {
	case err := <-serverErr:
		consoleLogger.Log("Server error: %v", err)
		os.Exit(1)
	case sig := <-signals:
		consoleLogger.Log("Received signal: %v. Shutting down...", sig)

		// Shutdown the server
		// The stdio transport will be closed when the process exits
		consoleLogger.Log("Shutting down MCP server...")
		consoleLogger.Log("Server shutdown complete")
	}
}
