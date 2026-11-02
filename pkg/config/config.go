// Package config loads nuclei-mcp settings from defaults, an optional YAML
// file and NUCLEI_MCP_* environment variables, in increasing precedence.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// EnvPrefix is the prefix for environment variable overrides, for example
// NUCLEI_MCP_LOGGING_LEVEL=debug or NUCLEI_MCP_SECURITY_ALLOW_PRIVATE_TARGETS=true.
const EnvPrefix = "NUCLEI_MCP"

// Config is the complete server configuration.
type Config struct {
	Cache    CacheConfig    `mapstructure:"cache"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Nuclei   NucleiConfig   `mapstructure:"nuclei"`
	Security SecurityConfig `mapstructure:"security"`
	Output   OutputConfig   `mapstructure:"output"`

	// File is the configuration file that was read; empty when none was found.
	File string `mapstructure:"-"`
}

// CacheConfig controls how scan results are kept and reused.
type CacheConfig struct {
	// Enabled reuses a previous result for an identical scan within Expiry.
	Enabled bool          `mapstructure:"enabled"`
	Expiry  time.Duration `mapstructure:"expiry"`
	// MaxSize caps how many scan results are kept in memory.
	MaxSize int `mapstructure:"max_size"`
}

// LoggingConfig controls log output. Logs always go to stderr; Path adds a file.
type LoggingConfig struct {
	Level string `mapstructure:"level"`
	Path  string `mapstructure:"path"`
}

// NucleiConfig holds scanner settings.
type NucleiConfig struct {
	TemplatesDirectory string        `mapstructure:"templates_directory"`
	BasicTemplateName  string        `mapstructure:"basic_template_name"`
	Timeout            time.Duration `mapstructure:"timeout"`      // per request
	ScanTimeout        time.Duration `mapstructure:"scan_timeout"` // whole scan
	RateLimit          int           `mapstructure:"rate_limit"`   // requests per second
	BulkSize           int           `mapstructure:"bulk_size"`    // hosts in parallel
	TemplateThreads    int           `mapstructure:"template_threads"`
	Retries            int           `mapstructure:"retries"`
	SystemResolvers    bool          `mapstructure:"system_resolvers"`
}

// SecurityConfig limits what a model can make the server do.
type SecurityConfig struct {
	// AllowTemplateWrites exposes the add_template tool. Off by default:
	// a written template runs on every later scan.
	AllowTemplateWrites bool `mapstructure:"allow_template_writes"`
	// Interactsh enables out-of-band callbacks to interactsh servers.
	Interactsh bool `mapstructure:"interactsh"`
	// AllowPrivateTargets permits loopback, private and link-local targets.
	AllowPrivateTargets bool `mapstructure:"allow_private_targets"`
	// AllowedTargets, when set, restricts scans to these hosts, *.domains or CIDRs.
	AllowedTargets []string `mapstructure:"allowed_targets"`
	// DeniedTargets are always refused.
	DeniedTargets []string `mapstructure:"denied_targets"`
}

// OutputConfig shapes tool results.
type OutputConfig struct {
	// MaxFindings is the default page size for findings in a tool result.
	MaxFindings int `mapstructure:"max_findings"`
}

// DefaultHome returns the directory used for default config, templates and logs.
func DefaultHome() string {
	if h := os.Getenv(EnvPrefix + "_HOME"); h != "" {
		return h
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return filepath.Join(h, ".nuclei-mcp")
	}
	return filepath.Join(os.TempDir(), "nuclei-mcp")
}

func setDefaults(v *viper.Viper, home string) {
	v.SetDefault("cache.enabled", true)
	v.SetDefault("cache.expiry", "1h")
	v.SetDefault("cache.max_size", 100)

	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.path", filepath.Join(home, "logs", "nuclei-mcp.log"))

	v.SetDefault("nuclei.templates_directory", filepath.Join(home, "templates"))
	v.SetDefault("nuclei.basic_template_name", "basic-test.yaml")
	v.SetDefault("nuclei.timeout", "10s")
	v.SetDefault("nuclei.scan_timeout", "10m")
	v.SetDefault("nuclei.rate_limit", 150)
	v.SetDefault("nuclei.bulk_size", 25)
	v.SetDefault("nuclei.template_threads", 25)
	v.SetDefault("nuclei.retries", 1)
	v.SetDefault("nuclei.system_resolvers", false)

	v.SetDefault("security.allow_template_writes", false)
	v.SetDefault("security.interactsh", false)
	v.SetDefault("security.allow_private_targets", false)
	v.SetDefault("security.allowed_targets", []string{})
	v.SetDefault("security.denied_targets", []string{})

	v.SetDefault("output.max_findings", 50)
}

// Load reads configuration. With an explicit path the file must exist;
// otherwise config.yaml is searched in the working directory, the default
// home directory and /etc/nuclei-mcp, and defaults are used when none exists.
func Load(path string) (Config, error) {
	var cfg Config
	home := DefaultHome()

	v := viper.New()
	setDefaults(v, home)
	v.SetEnvPrefix(EnvPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return cfg, fmt.Errorf("reading config file %s: %w", path, err)
		}
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath(home)
		v.AddConfigPath("/etc/nuclei-mcp")
		if err := v.ReadInConfig(); err != nil {
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) {
				return cfg, fmt.Errorf("reading config file: %w", err)
			}
		}
	}

	if err := v.Unmarshal(&cfg); err != nil {
		return cfg, fmt.Errorf("parsing config: %w", err)
	}
	cfg.File = v.ConfigFileUsed()

	base := ""
	if cfg.File != "" {
		base = filepath.Dir(cfg.File)
	}
	cfg.Nuclei.TemplatesDirectory = resolvePath(cfg.Nuclei.TemplatesDirectory, base)
	cfg.Logging.Path = resolvePath(cfg.Logging.Path, base)

	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// resolvePath expands ~ and environment variables and makes a relative path
// absolute against base (the config file's directory) or the working directory.
func resolvePath(p, base string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = os.ExpandEnv(p)
	if p == "~" || strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(h, strings.TrimPrefix(p, "~"))
		}
	}
	if !filepath.IsAbs(p) {
		if base != "" {
			p = filepath.Join(base, p)
		} else if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
	}
	return filepath.Clean(p)
}

func (c *Config) validate() error {
	var errs []error
	if c.Nuclei.TemplatesDirectory == "" {
		errs = append(errs, errors.New("nuclei.templates_directory must not be empty"))
	}
	if strings.ContainsAny(c.Nuclei.BasicTemplateName, `/\`) || c.Nuclei.BasicTemplateName == "" {
		errs = append(errs, errors.New("nuclei.basic_template_name must be a plain file name"))
	}
	positive := map[string]int{
		"nuclei.rate_limit":       c.Nuclei.RateLimit,
		"nuclei.bulk_size":        c.Nuclei.BulkSize,
		"nuclei.template_threads": c.Nuclei.TemplateThreads,
		"cache.max_size":          c.Cache.MaxSize,
		"output.max_findings":     c.Output.MaxFindings,
	}
	for k, n := range positive {
		if n < 1 {
			errs = append(errs, fmt.Errorf("%s must be at least 1, got %d", k, n))
		}
	}
	if c.Nuclei.Retries < 0 {
		errs = append(errs, fmt.Errorf("nuclei.retries must not be negative"))
	}
	if c.Nuclei.Timeout < time.Second {
		errs = append(errs, fmt.Errorf("nuclei.timeout must be at least 1s, got %s", c.Nuclei.Timeout))
	}
	if c.Nuclei.ScanTimeout < time.Second {
		errs = append(errs, fmt.Errorf("nuclei.scan_timeout must be at least 1s, got %s", c.Nuclei.ScanTimeout))
	}
	if c.Cache.Expiry <= 0 {
		errs = append(errs, fmt.Errorf("cache.expiry must be positive, got %s", c.Cache.Expiry))
	}
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "warning", "error":
	default:
		errs = append(errs, fmt.Errorf("logging.level must be debug, info, warn or error, got %q", c.Logging.Level))
	}
	return errors.Join(errs...)
}
