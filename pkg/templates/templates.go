package templates

import (
	"fmt"
	"os"
	"path/filepath"
)

type templateManagerImpl struct {
	Dir string
}

type TemplateManager interface {
	AddTemplate(name string, content []byte) error
	ListTemplates() ([]string, error)
	GetTemplate(name string) ([]byte, error)
}

func NewTemplateManager(dir string) (TemplateManager, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create templates directory: %w", err)
	}
	return &templateManagerImpl{Dir: dir}, nil
}

func (tm *templateManagerImpl) AddTemplate(name string, content []byte) error {
	path := filepath.Join(tm.Dir, name)
	return os.WriteFile(path, content, 0644)
}
func (tm *templateManagerImpl) ListTemplates() ([]string, error) {
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

func (tm *templateManagerImpl) GetTemplate(name string) ([]byte, error) {
	path := filepath.Join(tm.Dir, name)
	return os.ReadFile(path)
}
