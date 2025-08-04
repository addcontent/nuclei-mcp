package tests

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"nuclei-mcp/pkg/logging"

	"github.com/stretchr/testify/assert"
)

func TestNewConsoleLogger(t *testing.T) {
	logPath := "./test_logs/console_logger_test.log"
	defer os.Remove(logPath)

	logger, err := logging.NewConsoleLogger(logPath)
	assert.NoError(t, err)
	assert.NotNil(t, logger)

	_, err = os.Stat(logPath)
	assert.NoError(t, err)

	_, err = logging.NewConsoleLogger("")
	assert.Error(t, err)
}

func TestConsoleLogger_Log(t *testing.T) {
	logPath := "\\invalid\\path\\to\\log.log"
	defer os.Remove(logPath)

	logger, err := logging.NewConsoleLogger(logPath)
	assert.NoError(t, err)

	logMessage := "This is a test log message"
	logger.Log("%s", logMessage)

	// Verify log file content
	content, err := ioutil.ReadFile(logPath)
	assert.NoError(t, err)
	assert.True(t, strings.Contains(string(content), logMessage))

	// Note: We're not testing console output capture as it has been deemed  complex and not essential to core functionality.
	// The main functionality (logging to file) is tested above
}

func TestConsoleLogger_Close(t *testing.T) {
	logPath := "/tmp/test_console_logger_close.log"
	defer os.Remove(logPath)

	logger, err := logging.NewConsoleLogger(logPath)
	assert.NoError(t, err)

	err = logger.Close()
	assert.NoError(t, err)

	// Attempting to log after closing should ideally not panic, but might error or be ignored

	// For now, we just ensure Close doesn't return an error.
}
