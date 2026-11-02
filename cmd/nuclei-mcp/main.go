// Command nuclei-mcp serves the Nuclei vulnerability scanner over the Model
// Context Protocol on stdin/stdout.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/addcontent/nuclei-mcp/pkg/api"
	"github.com/addcontent/nuclei-mcp/pkg/cache"
	"github.com/addcontent/nuclei-mcp/pkg/config"
	"github.com/addcontent/nuclei-mcp/pkg/logging"
	"github.com/addcontent/nuclei-mcp/pkg/scanner"
	"github.com/addcontent/nuclei-mcp/pkg/scope"
	"github.com/addcontent/nuclei-mcp/pkg/templates"

	"github.com/mark3labs/mcp-go/server"
)

// Set by the release build (see .goreleaser.yaml).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nuclei-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to a config.yaml (default: ./config.yaml, then "+config.DefaultHome()+"/config.yaml, then /etc/nuclei-mcp/config.yaml)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stderr, "nuclei-mcp %s (commit %s, built %s)\n", version, commit, date)
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "nuclei-mcp: %v\n", err)
		return 1
	}

	logger, closeLog, warn := logging.New(cfg.Logging.Path, cfg.Logging.Level)
	defer closeLog()
	if warn != nil {
		logger.Warn("log file unavailable", "error", warn)
	}
	logger.Info("starting nuclei-mcp", "version", version, "config", orNone(cfg.File),
		"templates", cfg.Nuclei.TemplatesDirectory)

	if n, err := templates.SeedBuiltins(cfg.Nuclei.TemplatesDirectory); err != nil {
		logger.Error("cannot prepare templates directory", "error", err)
		return 1
	} else if n > 0 {
		logger.Info("installed built-in templates", "count", n)
	}

	var resultCache cache.ResultCacheInterface = cache.NewNoopCache()
	if cfg.Cache.Enabled {
		resultCache = cache.NewResultCache(cfg.Cache.Expiry, slog.NewLogLogger(logger.Handler(), slog.LevelDebug))
	}
	scannerService := scanner.NewScannerService(resultCache, logger, cfg.Nuclei.TemplatesDirectory, cfg.Nuclei.BasicTemplateName)

	templateManager, err := templates.NewTemplateManager(cfg.Nuclei.TemplatesDirectory)
	if err != nil {
		logger.Error("cannot open templates directory", "error", err)
		return 1
	}
	defer templateManager.Close()

	scopeChecker, err := scope.New(cfg.Security.AllowPrivateTargets, cfg.Security.AllowedTargets, cfg.Security.DeniedTargets)
	if err != nil {
		logger.Error("invalid security settings", "error", err)
		return 1
	}
	logger.Info("security settings",
		"add_template", cfg.Security.AllowTemplateWrites,
		"private_targets", cfg.Security.AllowPrivateTargets,
		"allowed_targets", len(cfg.Security.AllowedTargets),
		"denied_targets", len(cfg.Security.DeniedTargets))

	mcpServer := api.NewNucleiMCPServer(scannerService, log.New(stderr, "[MCP] ", log.LstdFlags), templateManager, api.Options{
		AllowTemplateWrites: cfg.Security.AllowTemplateWrites,
		Scope:               scopeChecker,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stdio := server.NewStdioServer(mcpServer)
	stdio.SetErrorLogger(slog.NewLogLogger(logger.Handler(), slog.LevelError))
	err = stdio.Listen(ctx, stdin, stdout)
	switch {
	case err == nil:
		logger.Info("client disconnected, shutting down")
	case errors.Is(err, context.Canceled):
		logger.Info("signal received, shutting down")
	default:
		logger.Error("server stopped", "error", err)
		return 1
	}
	return 0
}

func orNone(s string) string {
	if s == "" {
		return "none (defaults)"
	}
	return s
}
