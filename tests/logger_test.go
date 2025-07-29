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
	// Create a temporary log file path
	logPath := "/tmp/test_new_console_logger.log"
	defer os.Remove(logPath)

	logger, err := logging.NewConsoleLogger(logPath)
	assert.NoError(t, err)
	assert.NotNil(t, logger)

	// Verify that the log file was created
	_, err = os.Stat(logPath)
	assert.NoError(t, err)

	// Test with an invalid path to trigger an error
	_, err = logging.NewConsoleLogger("/nonexistent/path/to/log.log")
	assert.Error(t, err)
}

func TestConsoleLogger_Log(t *testing.T) {
	logPath := "/tmp/test_console_logger_log.log"
	defer os.Remove(logPath)

	logger, err := logging.NewConsoleLogger(logPath)
	assert.NoError(t, err)

	logMessage := "This is a test log message"
	logger.Log(logMessage)

	// Verify log file content
	content, err := ioutil.ReadFile(logPath)
	assert.NoError(t, err)
	assert.True(t, strings.Contains(string(content), logMessage))

	// Note: We're not testing console output capture as it's complex and not essential
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
	// Depending on the implementation, this might need a specific check or be omitted.
	// For now, we just ensure Close doesn't return an error.
}
