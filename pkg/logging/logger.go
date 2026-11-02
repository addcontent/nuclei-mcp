// Package logging builds the server's structured logger.
//
// Logs go to stderr and, optionally, to a file. Nothing is ever written to
// stdout, which carries the MCP protocol.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// ParseLevel converts debug, info, warn/warning or error to a slog level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return slog.LevelInfo, fmt.Errorf("unknown log level %q", s)
}

// New returns a logger writing to stderr and, when path is set, to that file.
// If the file cannot be opened the logger still works on stderr and the
// returned warning explains why; a log file problem never stops the server.
func New(path, level string) (logger *slog.Logger, closeFn func() error, warning error) {
	lvl, err := ParseLevel(level)
	if err != nil {
		warning = err
	}
	closeFn = func() error { return nil }

	var w io.Writer = os.Stderr
	if path != "" {
		f, ferr := openLogFile(path)
		if ferr != nil {
			warning = fmt.Errorf("logging to stderr only: %w", ferr)
		} else {
			w = io.MultiWriter(os.Stderr, f)
			closeFn = f.Close
		}
	}
	logger = slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl}))
	return logger, closeFn, warning
}

func openLogFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening log file: %w", err)
	}
	return f, nil
}

// Discard returns a logger that drops everything; useful in tests.
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
