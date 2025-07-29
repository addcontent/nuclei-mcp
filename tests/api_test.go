package tests

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"nuclei-mcp/pkg/api"
	"nuclei-mcp/pkg/cache"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/assert"
)

// MockScannerService for testing purposes
type MockScannerService struct {
	MockScan           func(target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error)
	MockThreadSafeScan func(ctx context.Context, target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error)
	MockBasicScan      func(target string) (cache.ScanResult, error)
	MockGetAll         func() []cache.ScanResult
	MockCreateCacheKey func(target string, severity string, protocols string) string
}

func (m *MockScannerService) CreateCacheKey(target string, severity string, protocols string) string {
	if m.MockCreateCacheKey != nil {
		return m.MockCreateCacheKey(target, severity, protocols)
	}
	return ""
}

func (m *MockScannerService) Scan(target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error) {
	if m.MockScan != nil {
		return m.MockScan(target, severity, protocols, templateIDs)
	}
	return cache.ScanResult{}, fmt.Errorf("Scan not implemented")
}

func (m *MockScannerService) ThreadSafeScan(ctx context.Context, target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error) {
	if m.MockThreadSafeScan != nil {
		return m.MockThreadSafeScan(ctx, target, severity, protocols, templateIDs)
	}
	return cache.ScanResult{}, fmt.Errorf("ThreadSafeScan not implemented")
}

func (m *MockScannerService) BasicScan(target string) (cache.ScanResult, error) {
	if m.MockBasicScan != nil {
		return m.MockBasicScan(target)
	}
	return cache.ScanResult{}, fmt.Errorf("BasicScan not implemented")
}

func (m *MockScannerService) GetAll() []cache.ScanResult {
	if m.MockGetAll != nil {
		return m.MockGetAll()
	}
	return []cache.ScanResult{}
}

// MockTemplateManager for testing purposes
type MockTemplateManager struct {
	MockAddTemplate   func(name string, content []byte) error
	MockListTemplates func() ([]string, error)
	MockGetTemplate   func(name string) ([]byte, error)
}

func (m *MockTemplateManager) AddTemplate(name string, content []byte) error {
	if m.MockAddTemplate != nil {
		return m.MockAddTemplate(name, content)
	}
	return fmt.Errorf("AddTemplate not implemented")
}

func (m *MockTemplateManager) ListTemplates() ([]string, error) {
	if m.MockListTemplates != nil {
		return m.MockListTemplates()
	}
	return []string{}, fmt.Errorf("ListTemplates not implemented")
}

func (m *MockTemplateManager) GetTemplate(name string) ([]byte, error) {
	if m.MockGetTemplate != nil {
		return m.MockGetTemplate(name)
	}
	return []byte{}, fmt.Errorf("GetTemplate not implemented")
}

func TestNewNucleiMCPServer(t *testing.T) {
	mockScanner := &MockScannerService{}
	mockTemplateManager := &MockTemplateManager{}
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)

	mcpServer := api.NewNucleiMCPServer(mockScanner, logger, mockTemplateManager)
	assert.NotNil(t, mcpServer)
}

func TestHandleNucleiScanTool(t *testing.T) {
	ctx := context.Background()
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)

	mockScanner := &MockScannerService{
		MockScan: func(target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error) {
			// Return a simple result without trying to mock complex nuclei types
			return cache.ScanResult{
				Target:   target,
				ScanTime: time.Now(),
				Findings: []*output.ResultEvent{}, // Empty findings for simplicity
			}, nil
		},
	}

	request := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: map[string]interface{}{
				"target":    "example.com",
				"severity":  "info",
				"protocols": "http",
			},
		},
	}

	result, err := api.HandleNucleiScanTool(ctx, request, mockScanner, logger)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleBasicScanTool(t *testing.T) {
	ctx := context.Background()
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)

	mockScanner := &MockScannerService{
		MockBasicScan: func(target string) (cache.ScanResult, error) {
			return cache.ScanResult{
				Target:   target,
				ScanTime: time.Now(),
				Findings: []*output.ResultEvent{}, // Empty findings for simplicity
			}, nil
		},
	}

	request := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: map[string]interface{}{
				"target": "example.com",
			},
		},
	}

	result, err := api.HandleBasicScanTool(ctx, request, mockScanner, logger)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleVulnerabilityResource(t *testing.T) {
	ctx := context.Background()
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)

	mockScanner := &MockScannerService{
		MockGetAll: func() []cache.ScanResult {
			return []cache.ScanResult{
				{
					Target:   "example.com",
					ScanTime: time.Now(),
					Findings: []*output.ResultEvent{}, // Empty findings for simplicity
				},
			}
		},
	}

	request := mcp.ReadResourceRequest{}
	results, err := api.HandleVulnerabilityResource(ctx, request, mockScanner, logger)
	assert.NoError(t, err)
	assert.NotNil(t, results)
	assert.Len(t, results, 1)
}

func TestHandleAddTemplate(t *testing.T) {
	ctx := context.Background()
	mockTemplateManager := &MockTemplateManager{
		MockAddTemplate: func(name string, content []byte) error {
			return nil
		},
	}

	request := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: map[string]interface{}{
				"name":    "test-template.yaml",
				"content": "template content",
			},
		},
	}

	result, err := api.HandleAddTemplate(ctx, request, mockTemplateManager)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleListTemplates(t *testing.T) {
	ctx := context.Background()
	mockTemplateManager := &MockTemplateManager{
		MockListTemplates: func() ([]string, error) {
			return []string{"template1.yaml", "template2.yaml"}, nil
		},
	}

	request := mcp.CallToolRequest{}
	result, err := api.HandleListTemplates(ctx, request, mockTemplateManager)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleGetTemplate(t *testing.T) {
	ctx := context.Background()
	mockTemplateManager := &MockTemplateManager{
		MockGetTemplate: func(name string) ([]byte, error) {
			if name == "test-template.yaml" {
				return []byte("template content"), nil
			}
			return nil, fmt.Errorf("template not found")
		},
	}

	request := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: map[string]interface{}{
				"name": "test-template.yaml",
			},
		},
	}

	result, err := api.HandleGetTemplate(ctx, request, mockTemplateManager)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}
