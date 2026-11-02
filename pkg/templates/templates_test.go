package templates

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodTemplate = `id: my-check
info:
  name: My check
  author: me
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/health"
    matchers:
      - type: status
        status: [200]
`

func newManager(t *testing.T) (*Manager, string) {
	t.Helper()
	parent := t.TempDir()
	dir := filepath.Join(parent, "templates")
	m, err := NewTemplateManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m, parent
}

func TestAddListGet(t *testing.T) {
	m, _ := newManager(t)
	if err := m.AddTemplate("my-check.yaml", []byte(goodTemplate)); err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(m.Dir(), "http", "cves"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.Dir(), "http", "cves", "nested.yaml"), []byte(goodTemplate), 0o644); err != nil {
		t.Fatal(err)
	}
	list, err := m.ListTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(list, ","); got != "http/cves/nested.yaml,my-check.yaml" {
		t.Errorf("ListTemplates = %q (nested templates must be listed)", got)
	}
	data, err := m.GetTemplate("http/cves/nested.yaml")
	if err != nil || string(data) != goodTemplate {
		t.Errorf("GetTemplate nested: %v", err)
	}
}

func TestAddRefusesOverwrite(t *testing.T) {
	m, _ := newManager(t)
	if err := m.AddTemplate("my-check.yaml", []byte(goodTemplate)); err != nil {
		t.Fatal(err)
	}
	err := m.AddTemplate("my-check.yaml", []byte(strings.Replace(goodTemplate, "low", "high", 1)))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected already-exists error, got %v", err)
	}
}

// The original implementation joined the name onto the directory, so these
// names read and wrote outside it.
func TestPathTraversalIsBlocked(t *testing.T) {
	m, parent := newManager(t)
	secret := filepath.Join(parent, "secret.yaml")
	if err := os.WriteFile(secret, []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"../secret.yaml", "../../etc/passwd", "/etc/passwd", `..\secret.yaml`, "a/../../secret.yaml", "sub/x.yaml", ".hidden.yaml", "x.txt"} {
		if err := m.AddTemplate(name, []byte(goodTemplate)); !errors.Is(err, ErrInvalidName) {
			t.Errorf("AddTemplate(%q) = %v, want ErrInvalidName", name, err)
		}
	}
	for _, name := range []string{"../secret.yaml", "../../../../etc/hostname", "/etc/passwd", "a/../../secret.yaml", `..\secret.yaml`} {
		data, err := m.GetTemplate(name)
		if err == nil {
			t.Errorf("GetTemplate(%q) returned %q, want an error", name, data)
		}
	}
	if data, _ := os.ReadFile(secret); string(data) != "top secret" {
		t.Error("file outside the templates directory was modified")
	}
}

func TestSymlinkEscapeIsBlocked(t *testing.T) {
	m, parent := newManager(t)
	outside := filepath.Join(parent, "outside.yaml")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(m.Dir(), "link.yaml")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if data, err := m.GetTemplate("link.yaml"); err == nil {
		t.Errorf("symlink escape read %q", data)
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]string{
		"not yaml":        "id: [",
		"bad id":          strings.Replace(goodTemplate, "id: my-check", "id: ../x", 1),
		"no info":         "id: x\nhttp:\n  - path: ['{{BaseURL}}']\n",
		"bad severity":    strings.Replace(goodTemplate, "severity: low", "severity: extreme", 1),
		"no requests":     "id: x\ninfo:\n  name: x\n  severity: info\n",
		"code":            "id: x\ninfo:\n  name: x\n  severity: info\ncode:\n  - engine: [sh]\n    source: id\n",
		"javascript":      "id: x\ninfo:\n  name: x\n  severity: info\njavascript:\n  - code: 'x'\n",
		"flow":            goodTemplate + "flow: http()\n",
		"file":            "id: x\ninfo:\n  name: x\n  severity: info\nfile:\n  - extensions: [all]\n",
		"self-contained":  goodTemplate + "self-contained: true\n",
		"host annotation": strings.Replace(goodTemplate, `"{{BaseURL}}/health"`, `"{{BaseURL}}"`+"\n    raw:\n      - |\n        @Host: http://169.254.169.254\n        GET / HTTP/1.1", 1),
	}
	for name, content := range cases {
		if _, err := Validate([]byte(content)); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
	info, err := Validate([]byte(goodTemplate))
	if err != nil || info.ID != "my-check" || info.Severity != "low" {
		t.Errorf("good template: %+v %v", info, err)
	}
}

func TestAddRejectsLargeTemplate(t *testing.T) {
	m, _ := newManager(t)
	big := goodTemplate + "# " + strings.Repeat("x", MaxTemplateSize) + "\n"
	if err := m.AddTemplate("big.yaml", []byte(big)); err == nil {
		t.Fatal("expected size limit error")
	}
}

func TestFingerprintChanges(t *testing.T) {
	m, _ := newManager(t)
	a, err := m.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddTemplate("my-check.yaml", []byte(goodTemplate)); err != nil {
		t.Fatal(err)
	}
	b, _ := m.Fingerprint()
	if a == b {
		t.Error("fingerprint did not change after adding a template")
	}
}

func TestSeedBuiltins(t *testing.T) {
	dir := t.TempDir()
	n, err := SeedBuiltins(dir)
	if err != nil || n != len(BuiltinNames()) || n == 0 {
		t.Fatalf("first seed wrote %d of %d: %v", n, len(BuiltinNames()), err)
	}
	edited := filepath.Join(dir, "basic-test.yaml")
	if err := os.WriteFile(edited, []byte("edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err = SeedBuiltins(dir)
	if err != nil || n != 0 {
		t.Fatalf("second seed wrote %d: %v", n, err)
	}
	if data, _ := os.ReadFile(edited); string(data) != "edited" {
		t.Error("seeding overwrote a user edit")
	}
}

// Every built-in template must pass the same validation as user templates
// and use the current `http:` key.
func TestBuiltinsAreValid(t *testing.T) {
	ids := map[string]string{}
	for _, name := range BuiltinNames() {
		data, err := builtin.ReadFile("builtin/" + name)
		if err != nil {
			t.Fatal(err)
		}
		info, err := Validate(data)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if prev, dup := ids[info.ID]; dup {
			t.Errorf("%s and %s share template id %q", prev, name, info.ID)
		}
		ids[info.ID] = name
		if strings.Contains(string(data), "\nrequests:") {
			t.Errorf("%s uses the deprecated requests: key", name)
		}
	}
}
