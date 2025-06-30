package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// ConsoleLogger handles logging console output to a file
type ConsoleLogger struct {
	file   *os.File
	logger *log.Logger
	mu     sync.Mutex
}

// NewConsoleLogger creates a new console logger that writes to both file and stdout
func NewConsoleLogger(logPath string) (*ConsoleLogger, error) {
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	multiWriter := io.MultiWriter(file, os.Stdout)
	logger := log.New(multiWriter, "", log.LstdFlags)

	return &ConsoleLogger{
		file:   file,
		logger: logger,
		mu:     sync.Mutex{},
	}, nil
}

// Log writes a message to both the log file and stdout
func (cl *ConsoleLogger) Log(format string, v ...interface{}) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.logger.Printf(format, v...)
}

// Close closes the log file
func (cl *ConsoleLogger) Close() error {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.file.Close()
}
