package tests

import (
	"os"
	"testing"
	"time"

	"nuclei-mcp/pkg/config"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file for testing
	configContent := []byte(`
server:
  name: "test-server"
  version: "1.0.0"
cache:
  expiry: 10m
logging:
  path: "/var/log/test.log"
`)

	tempDir := t.TempDir()
	configPath := tempDir + "/config.yaml"
	err := os.WriteFile(configPath, configContent, 0644)
	assert.NoError(t, err)

	// Load the config from tmp
	cfg, err := config.LoadConfig(tempDir)
	assert.NoError(t, err)

	assert.Equal(t, "test-server", cfg.Server.Name)
	assert.Equal(t, "1.0.0", cfg.Server.Version)
	assert.Equal(t, 10*time.Minute, cfg.Cache.Expiry)
	assert.Equal(t, "/var/log/test.log", cfg.Logging.Path)

	// Test with a non-existent path (should return an error)
	// Create a temporary directory that definitely doesn't have a config file
	emptyTempDir := t.TempDir()
	_, err = config.LoadConfig(emptyTempDir)
	assert.Error(t, err)
}
