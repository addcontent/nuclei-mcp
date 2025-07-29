package tests

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"nuclei-mcp/pkg/templates"
)

func TestNewTemplateManager(t *testing.T) {
	// Test successful creation
	tempDir := t.TempDir()
	tm, err := templates.NewTemplateManager(tempDir)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if tm == nil {
		t.Fatal("Expected TemplateManager instance, got nil")
	}

	// Verify directory was created
	if _, err := os.Stat(tempDir); os.IsNotExist(err) {
		t.Fatal("Expected templates directory to be created")
	}

	// Test creation with nested path
	nestedDir := filepath.Join(tempDir, "nested", "path")
	tm2, err := templates.NewTemplateManager(nestedDir)
	if err != nil {
		t.Fatalf("Expected no error for nested path, got %v", err)
	}
	if tm2 == nil {
		t.Fatal("Expected TemplateManager instance for nested path, got nil")
	}

	// Verify nested directory was created
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Fatal("Expected nested templates directory to be created")
	}
}

func TestAddTemplate(t *testing.T) {
	tempDir := t.TempDir()
	tm, err := templates.NewTemplateManager(tempDir)
	if err != nil {
		t.Fatalf("Failed to create TemplateManager: %v", err)
	}

	// Test adding a template
	templateName := "test-template.yaml"
	templateContent := []byte(`id: test-template
info:
  name: Test Template
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}"`)

	err = tm.AddTemplate(templateName, templateContent)
	if err != nil {
		t.Fatalf("Expected no error adding template, got %v", err)
	}

	// Verify file was created
	filePath := filepath.Join(tempDir, templateName)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatal("Expected template file to be created")
	}

	// Verify file content
	savedContent, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read saved template: %v", err)
	}
	if !bytes.Equal(savedContent, templateContent) {
		t.Fatal("Saved template content doesn't match original")
	}
}

func TestGetTemplate(t *testing.T) {
	tempDir := t.TempDir()
	tm, err := templates.NewTemplateManager(tempDir)
	if err != nil {
		t.Fatalf("Failed to create TemplateManager: %v", err)
	}

	// Add a template first
	templateName := "get-test.yaml"
	originalContent := []byte("test content for retrieval")
	err = tm.AddTemplate(templateName, originalContent)
	if err != nil {
		t.Fatalf("Failed to add template: %v", err)
	}

	// Test getting the template
	retrievedContent, err := tm.GetTemplate(templateName)
	if err != nil {
		t.Fatalf("Expected no error getting template, got %v", err)
	}
	if !bytes.Equal(retrievedContent, originalContent) {
		t.Fatal("Retrieved template content doesn't match original")
	}

	// Test getting non-existent template
	_, err = tm.GetTemplate("non-existent.yaml")
	if err == nil {
		t.Fatal("Expected error for non-existent template, got nil")
	}
}

func TestListTemplates(t *testing.T) {
	tempDir := t.TempDir()
	tm, err := templates.NewTemplateManager(tempDir)
	if err != nil {
		t.Fatalf("Failed to create TemplateManager: %v", err)
	}

	// Test empty directory
	templates, err := tm.ListTemplates()
	if err != nil {
		t.Fatalf("Expected no error listing empty templates, got %v", err)
	}
	if len(templates) != 0 {
		t.Fatalf("Expected 0 templates, got %d", len(templates))
	}

	// Add some templates
	templateNames := []string{"template1.yaml", "template2.yaml", "template3.yaml"}
	for _, name := range templateNames {
		err = tm.AddTemplate(name, []byte("content"))
		if err != nil {
			t.Fatalf("Failed to add template %s: %v", name, err)
		}
	}

	// Create a subdirectory (should be ignored)
	subDir := filepath.Join(tempDir, "subdir")
	err = os.Mkdir(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// List templates
	listedTemplates, err := tm.ListTemplates()
	if err != nil {
		t.Fatalf("Expected no error listing templates, got %v", err)
	}

	// Verify count (should ignore subdirectory)
	if len(listedTemplates) != len(templateNames) {
		t.Fatalf("Expected %d templates, got %d", len(templateNames), len(listedTemplates))
	}

	// Verify all template names are present
	templateMap := make(map[string]bool)
	for _, name := range listedTemplates {
		templateMap[name] = true
	}
	for _, expectedName := range templateNames {
		if !templateMap[expectedName] {
			t.Fatalf("Expected template %s not found in list", expectedName)
		}
	}
}

func TestTemplateManagerIntegration(t *testing.T) {
	tempDir := t.TempDir()
	tm, err := templates.NewTemplateManager(tempDir)
	if err != nil {
		t.Fatalf("Failed to create TemplateManager: %v", err)
	}

	// Integration test: Add multiple templates, list them, and retrieve each
	testTemplates := map[string][]byte{
		"sql-injection.yaml": []byte(`id: sql-injection
info:
  name: SQL Injection Test
  severity: high`),
		"xss-test.yaml": []byte(`id: xss-test
info:
  name: XSS Test
  severity: medium`),
		"info-disclosure.yaml": []byte(`id: info-disclosure
info:
  name: Information Disclosure
  severity: low`),
	}

	// Add all templates
	for name, content := range testTemplates {
		err = tm.AddTemplate(name, content)
		if err != nil {
			t.Fatalf("Failed to add template %s: %v", name, err)
		}
	}

	// List templates
	listedTemplates, err := tm.ListTemplates()
	if err != nil {
		t.Fatalf("Failed to list templates: %v", err)
	}
	if len(listedTemplates) != len(testTemplates) {
		t.Fatalf("Expected %d templates, got %d", len(testTemplates), len(listedTemplates))
	}

	// Retrieve and verify each template
	for name, expectedContent := range testTemplates {
		retrievedContent, err := tm.GetTemplate(name)
		if err != nil {
			t.Fatalf("Failed to get template %s: %v", name, err)
		}
		if !bytes.Equal(retrievedContent, expectedContent) {
			t.Fatalf("Content mismatch for template %s", name)
		}
	}
}
