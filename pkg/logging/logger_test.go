package logging

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewWritesToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "mcp.log")
	logger, closeFn, warn := New(path, "info")
	if warn != nil {
		t.Fatalf("unexpected warning: %v", warn)
	}
	logger.Info("hello file")
	logger.Debug("hidden at info level")
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "hello file") {
		t.Errorf("log file missing message: %q", data)
	}
	if strings.Contains(string(data), "hidden at info level") {
		t.Errorf("debug message written at info level")
	}
}

func TestNewFallsBackToStderr(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// A path under a regular file can never be created.
	logger, closeFn, warn := New(filepath.Join(blocker, "sub", "mcp.log"), "info")
	defer closeFn()
	if warn == nil {
		t.Fatal("expected a warning when the log file cannot be opened")
	}
	if logger == nil {
		t.Fatal("logger must still be usable")
	}
}

func TestNewWithoutPath(t *testing.T) {
	logger, closeFn, warn := New("", "debug")
	defer closeFn()
	if warn != nil || logger == nil {
		t.Fatalf("logger=%v warn=%v", logger, warn)
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{"debug": slog.LevelDebug, "INFO": slog.LevelInfo, "": slog.LevelInfo,
		"warn": slog.LevelWarn, "warning": slog.LevelWarn, "error": slog.LevelError}
	for in, want := range cases {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Error("expected error for unknown level")
	}
}
