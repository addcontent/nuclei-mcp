package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// isolate points the default home at a temp dir and runs the test from an
// empty working directory, so no real config.yaml is picked up.
func isolate(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv(EnvPrefix+"_HOME", home)
	t.Chdir(t.TempDir())
	return home
}

func TestLoadDefaultsWithoutConfigFile(t *testing.T) {
	home := isolate(t)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with no config file must succeed, got %v", err)
	}
	if cfg.File != "" {
		t.Errorf("File = %q, want empty", cfg.File)
	}
	if want := filepath.Join(home, "templates"); cfg.Nuclei.TemplatesDirectory != want {
		t.Errorf("templates dir = %q, want %q", cfg.Nuclei.TemplatesDirectory, want)
	}
	if want := filepath.Join(home, "logs", "nuclei-mcp.log"); cfg.Logging.Path != want {
		t.Errorf("log path = %q, want %q", cfg.Logging.Path, want)
	}
	if cfg.Security.AllowTemplateWrites || cfg.Security.Interactsh || cfg.Security.AllowPrivateTargets {
		t.Errorf("security switches must default to off: %+v", cfg.Security)
	}
	if cfg.Cache.Expiry != time.Hour || cfg.Nuclei.ScanTimeout != 10*time.Minute {
		t.Errorf("unexpected durations: expiry=%s scan_timeout=%s", cfg.Cache.Expiry, cfg.Nuclei.ScanTimeout)
	}
}

func TestLoadExplicitFileResolvesRelativePaths(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
cache:
  expiry: 10m
logging:
  level: debug
  path: logs/mcp.log
nuclei:
  templates_directory: my-templates
security:
  allowed_targets: ["example.com", "10.0.0.0/8"]
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.File != path {
		t.Errorf("File = %q, want %q", cfg.File, path)
	}
	if cfg.Cache.Expiry != 10*time.Minute {
		t.Errorf("expiry = %s, want 10m", cfg.Cache.Expiry)
	}
	if want := filepath.Join(dir, "my-templates"); cfg.Nuclei.TemplatesDirectory != want {
		t.Errorf("templates dir = %q, want %q (relative to the config file)", cfg.Nuclei.TemplatesDirectory, want)
	}
	if want := filepath.Join(dir, "logs", "mcp.log"); cfg.Logging.Path != want {
		t.Errorf("log path = %q, want %q", cfg.Logging.Path, want)
	}
	if got := strings.Join(cfg.Security.AllowedTargets, ","); got != "example.com,10.0.0.0/8" {
		t.Errorf("allowed targets = %q", got)
	}
}

func TestLoadEnvironmentOverrides(t *testing.T) {
	isolate(t)
	t.Setenv("NUCLEI_MCP_LOGGING_LEVEL", "warn")
	t.Setenv("NUCLEI_MCP_SECURITY_ALLOW_PRIVATE_TARGETS", "true")
	t.Setenv("NUCLEI_MCP_SECURITY_ALLOWED_TARGETS", "a.example,b.example")
	t.Setenv("NUCLEI_MCP_NUCLEI_RATE_LIMIT", "7")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Logging.Level != "warn" || !cfg.Security.AllowPrivateTargets || cfg.Nuclei.RateLimit != 7 {
		t.Errorf("env overrides not applied: %+v %+v %+v", cfg.Logging, cfg.Security, cfg.Nuclei)
	}
	if got := strings.Join(cfg.Security.AllowedTargets, ","); got != "a.example,b.example" {
		t.Errorf("allowed targets from env = %q", got)
	}
}

func TestLoadExplicitMissingFileFails(t *testing.T) {
	isolate(t)
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("expected an error for a missing explicit config file")
	}
}

func TestLoadRejectsDirectoryAsFile(t *testing.T) {
	isolate(t)
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("expected an error when the config path is a directory")
	}
}

func TestLoadValidation(t *testing.T) {
	isolate(t)
	path := filepath.Join(t.TempDir(), "bad.yaml")
	content := "nuclei:\n  rate_limit: 0\n  basic_template_name: ../x.yaml\nlogging:\n  level: loud\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"rate_limit", "basic_template_name", "logging.level"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestResolvePathExpandsHome(t *testing.T) {
	h, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	if got := resolvePath("~/x", "/ignored"); got != filepath.Join(h, "x") {
		t.Errorf("resolvePath(~/x) = %q", got)
	}
	if got := resolvePath("", "/base"); got != "" {
		t.Errorf("empty path must stay empty, got %q", got)
	}
}
