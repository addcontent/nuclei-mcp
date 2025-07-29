package templates

import (
	"fmt"
	"os"
	"path/filepath"
)

// TemplateManager handles operations related to Nuclei templates.
type templateManagerImpl struct {
	Dir string
}

// TemplateManager defines the interface for managing Nuclei templates.
type TemplateManager interface {
	AddTemplate(name string, content []byte) error
	ListTemplates() ([]string, error)
	GetTemplate(name string) ([]byte, error)
}

// NewTemplateManager creates a new TemplateManager.
func NewTemplateManager(dir string) (TemplateManager, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create templates directory: %w", err)
	}
	return &templateManagerImpl{Dir: dir}, nil
}

// AddTemplate saves a new template to the templates directory.
func (tm *templateManagerImpl) AddTemplate(name string, content []byte) error {
	path := filepath.Join(tm.Dir, name)
	return os.WriteFile(path, content, 0644)
}

// ListTemplates returns a list of all available template names.

func (tm *TemplateManager) ListTemplates() ([]string, error) {
	files, err := os.ReadDir(tm.Dir)

	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	var templates []string
	for _, file := range files {
		if !file.IsDir() {
			templates = append(templates, file.Name())
		}
	}
	return templates, nil
}

// GetTemplate retrieves the content of a specific template.
func (tm *templateManagerImpl) GetTemplate(name string) ([]byte, error) {
	path := filepath.Join(tm.Dir, name)
	return os.ReadFile(path)
}
