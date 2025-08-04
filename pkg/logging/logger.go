package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

type Logger interface {
	Log(format string, v ...interface{})
	GetWriter() io.Writer
	Close() error
}

type ConsoleLogger struct {
	file   *os.File
	logger *log.Logger
	mu     sync.Mutex
}

func NewConsoleLogger(logPath string) (*ConsoleLogger, error) {
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %v", err)
	}

	multiWriter := io.MultiWriter(file, os.Stderr)

	logger := log.New(multiWriter, "", log.LstdFlags)

	cl := &ConsoleLogger{
		file:   file,
		logger: logger,
		mu:     sync.Mutex{},
	}

	// Set finalizer to ensure file is closed if Close() is not called
	runtime.SetFinalizer(cl, (*ConsoleLogger).finalize)

	return cl, nil
}

func (cl *ConsoleLogger) Log(format string, v ...interface{}) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.logger.Printf(format, v...)
}

func (cl *ConsoleLogger) GetWriter() io.Writer {
	return cl.logger.Writer()
}

func (cl *ConsoleLogger) Close() error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	// Clear finalizer since we're explicitly closing
	runtime.SetFinalizer(cl, nil)

	if cl.file != nil {
		err := cl.file.Close()
		cl.file = nil
		return err
	}
	return nil
}

// finalize is called by the garbage collector if Close() wasn't called
func (cl *ConsoleLogger) finalize() {
	if cl.file != nil {
		cl.file.Close()
	}
}
