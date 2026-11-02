// Package templates manages the Nuclei templates directory.
//
// Every file operation goes through an os.Root opened on the templates
// directory, so no name a client sends (../, absolute paths, symlinks) can
// read or write outside it.
package templates

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// MaxTemplateSize caps the size of a template written through AddTemplate.
const MaxTemplateSize = 64 << 10

// ErrInvalidName is returned for names that are not safe template paths.
var ErrInvalidName = errors.New("invalid template name")

// TemplateManager reads and writes templates in one directory tree.
type TemplateManager interface {
	// AddTemplate writes a new template. name must be a plain file name
	// ending in .yaml or .yml; existing files are never overwritten.
	AddTemplate(name string, content []byte) error
	// ListTemplates returns template paths relative to the directory,
	// with forward slashes, sorted.
	ListTemplates() ([]string, error)
	// GetTemplate returns the content of a template by relative path.
	GetTemplate(name string) ([]byte, error)
}

// Manager is the os.Root-backed TemplateManager.
type Manager struct {
	dir  string
	root *os.Root
}

var _ TemplateManager = (*Manager)(nil)

// NewTemplateManager creates dir if needed and opens it as a root.
func NewTemplateManager(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating templates directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("opening templates directory: %w", err)
	}
	return &Manager{dir: dir, root: root}, nil
}

// Dir returns the templates directory.
func (m *Manager) Dir() string { return m.dir }

// Close releases the directory handle.
func (m *Manager) Close() error { return m.root.Close() }

var fileNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.ya?ml$`)

// ValidateFileName accepts plain template file names only: no directories,
// no leading dot, .yaml or .yml extension, at most 104 characters.
func ValidateFileName(name string) error {
	if !fileNameRE.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("%w %q: use a plain file name like my-check.yaml (letters, digits, '.', '_', '-')", ErrInvalidName, name)
	}
	return nil
}

// cleanRelPath validates a relative template path such as "http/cves/x.yaml".
func cleanRelPath(name string) (string, error) {
	name = strings.ReplaceAll(strings.TrimSpace(name), `\`, "/")
	if name == "" || path.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("%w %q: must be a path relative to the templates directory", ErrInvalidName, name)
	}
	clean := path.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("%w %q: must stay inside the templates directory", ErrInvalidName, name)
	}
	if ext := path.Ext(clean); ext != ".yaml" && ext != ".yml" {
		return "", fmt.Errorf("%w %q: must end in .yaml or .yml", ErrInvalidName, name)
	}
	return clean, nil
}

// AddTemplate validates and writes a new template file.
func (m *Manager) AddTemplate(name string, content []byte) error {
	if err := ValidateFileName(name); err != nil {
		return err
	}
	if len(content) > MaxTemplateSize {
		return fmt.Errorf("template is %d bytes; the limit is %d", len(content), MaxTemplateSize)
	}
	if _, err := Validate(content); err != nil {
		return err
	}
	f, err := m.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("template %q already exists; choose another name", name)
	}
	if err != nil {
		return fmt.Errorf("writing template: %w", err)
	}
	_, werr := f.Write(content)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = m.root.Remove(name)
		return fmt.Errorf("writing template: %w", errors.Join(werr, cerr))
	}
	return nil
}

// ListTemplates walks the directory tree for .yaml and .yml files.
func (m *Manager) ListTemplates() ([]string, error) {
	var out []string
	err := fs.WalkDir(m.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if ext := path.Ext(p); ext == ".yaml" || ext == ".yml" {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing templates: %w", err)
	}
	sort.Strings(out)
	return out, nil
}

// GetTemplate reads one template by relative path.
func (m *Manager) GetTemplate(name string) ([]byte, error) {
	clean, err := cleanRelPath(name)
	if err != nil {
		return nil, err
	}
	f, err := m.root.Open(clean)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("template %q not found", name)
	}
	if err != nil {
		return nil, fmt.Errorf("reading template %q: %w", name, err)
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.IsDir() {
		return nil, fmt.Errorf("template %q is a directory", name)
	}
	return io.ReadAll(io.LimitReader(f, 8*MaxTemplateSize))
}

// Fingerprint summarises the tree (paths, sizes, modification times) so that
// cached scan results can be invalidated when templates change.
func (m *Manager) Fingerprint() (string, error) {
	h := sha256.New()
	err := fs.WalkDir(m.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s\x00%d\x00%d\n", p, info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}
