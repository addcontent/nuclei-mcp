package config

import (
	"os"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	content := `
server:
  name: "test-server"
  version: "1.0.0"
cache:
  expiry: 10m
logging:
  path: "/tmp/test.log"
`
	tmpfile, err := os.CreateTemp("", "config.*.yaml")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write([]byte(content))
	assert.NoError(t, err)
	err = tmpfile.Close()
	assert.NoError(t, err)

	// Get the directory of the temporary file
	tmpdir := os.TempDir()

	// Create a new viper instance and set the config path
	viper.AddConfigPath(tmpdir)
	viper.SetConfigName(tmpfile.Name())
	viper.SetConfigType("yaml")

	config, err := LoadConfig(tmpdir)
	assert.NoError(t, err)

	assert.Equal(t, "test-server", config.Server.Name)
	assert.Equal(t, "1.0.0", config.Server.Version)
	assert.Equal(t, 10*time.Minute, config.Cache.Expiry)
	assert.Equal(t, "/tmp/test.log", config.Logging.Path)
}
