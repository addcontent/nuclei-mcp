package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// Config stores all configuration for the application.
// The values are read by viper from a config file or environment variables.
type Config struct {
	Server  ServerConfig  `mapstructure:"server"`
	Cache   CacheConfig   `mapstructure:"cache"`
	Logging LoggingConfig `mapstructure:"logging"`
	Nuclei  NucleiConfig  `mapstructure:"nuclei"`
}

// ServerConfig stores server specific configuration.
type ServerConfig struct {
	Name    string `mapstructure:"name"`
	Version string `mapstructure:"version"`
	Port    int    `mapstructure:"port"`
	Host    string `mapstructure:"host"`
}

// CacheConfig stores cache specific configuration.
type CacheConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	Expiry  time.Duration `mapstructure:"expiry"`
	MaxSize int           `mapstructure:"max_size"`
}

// LoggingConfig stores logging specific configuration.
type LoggingConfig struct {
	Level        string `mapstructure:"level"`
	Path         string `mapstructure:"path"`
	MaxSizeMB    int    `mapstructure:"max_size_mb"`
	MaxBackups   int    `mapstructure:"max_backups"`
	MaxAgeDays   int    `mapstructure:"max_age_days"`
	Compress     bool   `mapstructure:"compress"`
}

// NucleiConfig stores Nuclei specific configuration.
type NucleiConfig struct {
	TemplatesDirectory string        `mapstructure:"templates_directory"`
	Timeout           time.Duration `mapstructure:"timeout"`
	RateLimit         int           `mapstructure:"rate_limit"`
	BulkSize          int           `mapstructure:"bulk_size"`
	TemplateThreads   int           `mapstructure:"template_threads"`
	Headless          bool          `mapstructure:"headless"`
	ShowBrowser       bool          `mapstructure:"show_browser"`
	SystemResolvers   bool          `mapstructure:"system_resolvers"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (config Config, err error) {
	// Set default values
	viper.SetDefault("server.port", 3000)
	viper.SetDefault("server.host", "127.0.0.1")
	viper.SetDefault("cache.enabled", true)
	viper.SetDefault("cache.expiry", "1h")
	viper.SetDefault("cache.max_size", 1000)
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.max_size_mb", 10)
	viper.SetDefault("logging.max_backups", 5)
	viper.SetDefault("logging.max_age_days", 30)
	viper.SetDefault("logging.compress", true)
	viper.SetDefault("nuclei.templates_directory", "nuclei-templates")

	// Set config file
	if path != "" {
		viper.SetConfigFile(path)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.nuclei-mcp")
		viper.AddConfigPath("/etc/nuclei-mcp/")
	}

	// Read config file
	err = viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return config, fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Unmarshal config
	err = viper.Unmarshal(&config)
	if err != nil {
		return config, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Ensure log directory exists
	if config.Logging.Path != "" {
		logDir := filepath.Dir(config.Logging.Path)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return config, fmt.Errorf("failed to create log directory: %w", err)
		}
	}

	// Ensure templates directory exists
	if config.Nuclei.TemplatesDirectory != "" {
		if err := os.MkdirAll(config.Nuclei.TemplatesDirectory, 0755); err != nil {
			return config, fmt.Errorf("failed to create templates directory: %w", err)
		}
	}

	return config, nil
}
