package tests

import (
	"io"
	"testing"
	"time"

	"nuclei-mcp/pkg/cache"
	"nuclei-mcp/pkg/logging"
	"nuclei-mcp/pkg/scanner"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockResultCache is a mock implementation of cache.ResultCache
type MockResultCache struct {
	mock.Mock
}

func (m *MockResultCache) Get(key string) (cache.ScanResult, bool) {
	args := m.Called(key)
	return args.Get(0).(cache.ScanResult), args.Bool(1)
}

func (m *MockResultCache) Set(key string, result cache.ScanResult) {
	m.Called(key, result)
}

func (m *MockResultCache) GetAll() []cache.ScanResult {
	args := m.Called()
	return args.Get(0).([]cache.ScanResult)
}

// MockConsoleLogger is a mock implementation of logging.Logger
type MockConsoleLogger struct {
	mock.Mock
}

// Ensure MockConsoleLogger implements logging.Logger interface
var _ logging.Logger = (*MockConsoleLogger)(nil)

func (m *MockConsoleLogger) Log(format string, v ...interface{}) {
	m.Called(format, v)
}

func (m *MockConsoleLogger) GetWriter() io.Writer {
	args := m.Called()
	return args.Get(0).(io.Writer)
}

func (m *MockConsoleLogger) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewScannerService(t *testing.T) {
	mockCache := new(MockResultCache)
	mockLogger := new(MockConsoleLogger)
	service := scanner.NewScannerService(mockCache, mockLogger, "./templates", "basic-test.yaml")
	assert.NotNil(t, service)
}

func TestScannerService_CreateCacheKey(t *testing.T) {
	mockCache := new(MockResultCache)
	mockLogger := new(MockConsoleLogger)
	service := scanner.NewScannerService(mockCache, mockLogger, "./templates", "basic-test.yaml")

	key := service.CreateCacheKey("example.com", "high", "http")
	assert.Equal(t, "example.com:high:http", key)

	key = service.CreateCacheKey("test.com", "low", "tcp")
	assert.Equal(t, "test.com:low:tcp", key)
}

func TestScannerService_Scan_CacheHit(t *testing.T) {
	mockCache := new(MockResultCache)
	mockLogger := new(MockConsoleLogger)
	service := scanner.NewScannerService(mockCache, mockLogger, "./templates", "basic-test.yaml")

	expectedResult := cache.ScanResult{
		Target:   "cached.com",
		ScanTime: time.Now(),
		Findings: []*output.ResultEvent{},
	}
	mockCache.On("Get", "cached.com:info:http").Return(expectedResult, true).Once()
	mockLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Once()

	result, err := service.Scan("cached.com", "info", "http", nil)
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	mockCache.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}

func TestScannerService_Scan_CacheMiss(t *testing.T) {
	// This test case will not fully execute the nuclei scan due to mocking.
	// It primarily verifies cache interaction and initial setup.
	mockCache := new(MockResultCache)
	mockLogger := new(MockConsoleLogger)
	// Use a non-existent templates directory to force an error
	service := scanner.NewScannerService(mockCache, mockLogger, "./nonexistent-templates", "basic-test.yaml")

	mockCache.On("Get", "newscan.com:info:http").Return(cache.ScanResult{}, false).Once()
	// Expect Log calls for starting scan and error logging
	mockLogger.On("Log", mock.Anything, mock.Anything).Return().Maybe()
	// Expect Set call since the scan might succeed with empty results
	mockCache.On("Set", mock.Anything, mock.Anything).Return().Maybe()

	// Note: The actual nuclei execution is not mocked here, so this will likely fail
	// because the templates directory doesn't exist or has no templates
	result, err := service.Scan("newscan.com", "info", "http", nil)
	// The scan should fail due to missing templates directory or templates
	assert.Error(t, err, "Expected an error because templates directory doesn't exist")
	assert.Empty(t, result.Findings)
	mockCache.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}

func TestScannerService_BasicScan_CacheHit(t *testing.T) {
	mockCache := new(MockResultCache)
	mockLogger := new(MockConsoleLogger)
	service := scanner.NewScannerService(mockCache, mockLogger, "./templates", "basic-test.yaml")

	expectedResult := cache.ScanResult{
		Target:   "basiccached.com",
		ScanTime: time.Now(),
		Findings: []*output.ResultEvent{},
	}
	mockCache.On("Get", "basic:basiccached.com").Return(expectedResult, true).Once()
	mockLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Once()

	result, err := service.BasicScan("basiccached.com")
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	mockCache.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}

func TestScannerService_BasicScan_CacheMiss(t *testing.T) {
	// This test case will not fully execute the nuclei scan due to mocking.
	// It primarily verifies cache interaction and initial setup Plans are underway to mock the nuclei engine.
	mockCache := new(MockResultCache)
	mockLogger := new(MockConsoleLogger)
	// Use a non-existent templates directory to force an error
	service := scanner.NewScannerService(mockCache, mockLogger, "./nonexistent-templates", "basic-test.yaml")

	mockCache.On("Get", "basic:newbasicscan.com").Return(cache.ScanResult{}, false).Once()
	// Expect multiple Log calls for various operations (starting scan, template creation, etc.)
	mockLogger.On("Log", mock.Anything, mock.Anything).Return().Maybe()
	// Expect Set call since the scan might succeed with empty results
	mockCache.On("Set", mock.Anything, mock.Anything).Return().Maybe()

	//TODO: Mock nuclei.NewNucleiEngine initialization
	result, err := service.BasicScan("newbasicscan.com")
	// The scan should fail because the basic template file doesn't exist
	assert.Error(t, err, "Expected an error because basic template file doesn't exist")
	assert.Empty(t, result.Findings)
	mockCache.AssertExpectations(t)
	mockLogger.AssertExpectations(t)
}
