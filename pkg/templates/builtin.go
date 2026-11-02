package templates

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// builtin holds the starter templates shipped inside the binary, so a fresh
// install can scan without a checkout of this repository.
//
//go:embed builtin/*.yaml
var builtin embed.FS

// SeedBuiltins copies the built-in templates into dir. Existing files are
// never overwritten, so local edits survive upgrades. It returns how many
// files were written.
func SeedBuiltins(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("creating templates directory: %w", err)
	}
	entries, err := fs.ReadDir(builtin, "builtin")
	if err != nil {
		return 0, err
	}
	written := 0
	for _, e := range entries {
		data, err := builtin.ReadFile("builtin/" + e.Name())
		if err != nil {
			return written, err
		}
		f, err := os.OpenFile(filepath.Join(dir, e.Name()), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return written, fmt.Errorf("seeding %s: %w", e.Name(), err)
		}
		_, werr := f.Write(data)
		cerr := f.Close()
		if werr != nil || cerr != nil {
			return written, fmt.Errorf("seeding %s: %w", e.Name(), errors.Join(werr, cerr))
		}
		written++
	}
	return written, nil
}

// BuiltinNames lists the embedded template file names.
func BuiltinNames() []string {
	entries, _ := fs.ReadDir(builtin, "builtin")
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
