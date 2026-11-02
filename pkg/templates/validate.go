package templates

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Protocols a template written through add_template may use. Anything that
// runs code or reads local files is refused: code, javascript, flow (which
// is JavaScript), headless (a browser), file, and workflows.
var allowedProtocols = map[string]bool{
	"http": true, "requests": true, "dns": true, "tcp": true, "network": true,
	"ssl": true, "websocket": true, "whois": true,
}

var refusedKeys = map[string]string{
	"code":       "runs commands on the host",
	"javascript": "runs JavaScript on the host",
	"flow":       "runs JavaScript on the host",
	"headless":   "drives a browser on the host",
	"file":       "reads local files",
	"workflows":  "chains other templates",
}

const errTemplate = "invalid template: "

var (
	idRE       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true, "unknown": true}
)

// Info is the subset of template metadata Validate checks and returns.
type Info struct {
	ID        string
	Name      string
	Severity  string
	Protocols []string
}

// Validate checks that content is a single, well-formed Nuclei template that
// only uses network protocols. It does not prove the template is harmless:
// it can still send any request to any target the scope rules allow.
func Validate(content []byte) (Info, error) {
	var info Info
	var doc map[string]any
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return info, fmt.Errorf(errTemplate+"not valid YAML: %w", err)
	}
	if doc == nil {
		return info, fmt.Errorf(errTemplate + "empty document")
	}

	id, _ := doc["id"].(string)
	if !idRE.MatchString(id) {
		return info, fmt.Errorf(errTemplate+"id %q must be 1-128 letters, digits, '_' or '-'", id)
	}
	info.ID = id

	meta, ok := doc["info"].(map[string]any)
	if !ok {
		return info, fmt.Errorf(errTemplate + "missing info block")
	}
	info.Name, _ = meta["name"].(string)
	if strings.TrimSpace(info.Name) == "" {
		return info, fmt.Errorf(errTemplate + "info.name is required")
	}
	info.Severity, _ = meta["severity"].(string)
	if !severities[strings.ToLower(info.Severity)] {
		return info, fmt.Errorf(errTemplate+"info.severity %q must be info, low, medium, high, critical or unknown", info.Severity)
	}

	for key := range doc {
		if why, bad := refusedKeys[key]; bad {
			return info, fmt.Errorf(errTemplate+"the %q protocol is not allowed through add_template because it %s", key, why)
		}
		if allowedProtocols[key] {
			info.Protocols = append(info.Protocols, key)
		}
	}
	if len(info.Protocols) == 0 {
		return info, fmt.Errorf(errTemplate + "no request block found (use http, dns, tcp, ssl, websocket or whois)")
	}
	if containsSelfContained(doc) {
		return info, fmt.Errorf(errTemplate + "self-contained templates are not allowed through add_template")
	}
	// "@Host:" in a raw request overrides the scanned target, which would
	// bypass the target scope checks.
	if strings.Contains(strings.ToLower(string(content)), "@host:") {
		return info, fmt.Errorf(errTemplate + "the @Host annotation is not allowed through add_template")
	}
	return info, nil
}

func containsSelfContained(doc map[string]any) bool {
	if v, ok := doc["self-contained"].(bool); ok && v {
		return true
	}
	for key := range allowedProtocols {
		reqs, _ := doc[key].([]any)
		for _, r := range reqs {
			if m, ok := r.(map[string]any); ok {
				if v, ok := m["self-contained"].(bool); ok && v {
					return true
				}
			}
		}
	}
	return false
}
