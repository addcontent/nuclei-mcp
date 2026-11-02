package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/addcontent/nuclei-mcp/pkg/cache"
	"github.com/addcontent/nuclei-mcp/pkg/logging"
	"github.com/addcontent/nuclei-mcp/pkg/scanner"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type fakeScanner struct {
	results  map[string]cache.ScanResult
	scanErr  error
	lastReq  scanner.Request
	panicNow bool
}

func (f *fakeScanner) Scan(_ context.Context, req scanner.Request) (scanner.Outcome, error) {
	if f.panicNow {
		panic("engine exploded")
	}
	f.lastReq = req
	if f.scanErr != nil {
		return scanner.Outcome{}, f.scanErr
	}
	return scanner.Outcome{Result: f.results["s1"]}, nil
}
func (f *fakeScanner) BasicScan(_ context.Context, target string) (scanner.Outcome, error) {
	if f.scanErr != nil {
		return scanner.Outcome{}, f.scanErr
	}
	return scanner.Outcome{Result: f.results["s1"], Cached: true}, nil
}
func (f *fakeScanner) Recent() []cache.ScanResult {
	var out []cache.ScanResult
	for _, r := range f.results {
		out = append(out, r)
	}
	return out
}
func (f *fakeScanner) Get(id string) (cache.ScanResult, bool) {
	r, ok := f.results[id]
	return r, ok
}

type fakeTemplates struct{ added map[string]string }

func (f *fakeTemplates) AddTemplate(name string, content []byte) error {
	if strings.Contains(name, "..") {
		return fmt.Errorf("invalid template name %q", name)
	}
	f.added[name] = string(content)
	return nil
}
func (f *fakeTemplates) ListTemplates() ([]string, error) {
	return []string{"basic-test.yaml", "dns/dmarc.yaml", "http/tech-detect.yaml"}, nil
}
func (f *fakeTemplates) GetTemplate(name string) ([]byte, error) {
	if name == "basic-test.yaml" {
		return []byte("id: basic-test"), nil
	}
	return nil, fmt.Errorf("template %q not found", name)
}

func sevFindings(sevs ...string) []cache.Finding {
	var out []cache.Finding
	for i, s := range sevs {
		out = append(out, cache.Finding{TemplateID: fmt.Sprintf("t%d", i), Name: "n", Severity: s})
	}
	return out
}

func setup(t *testing.T, allowWrites bool) (*server.MCPServer, *fakeScanner, *fakeTemplates) {
	t.Helper()
	fs := &fakeScanner{results: map[string]cache.ScanResult{
		"s1": {ID: "s1", Kind: "nuclei_scan", Target: "https://example.com", ScanTime: time.Now(),
			Findings: sevFindings("critical", "high", "high", "medium", "low", "info", "info")},
	}}
	ft := &fakeTemplates{added: map[string]string{}}
	s := NewServer(fs, ft, Config{Version: "test", AllowTemplateWrites: allowWrites, PageSize: 3, Logger: logging.Discard()})
	return s, fs, ft
}

func rpc(t *testing.T, s *server.MCPServer, method string, params any) map[string]any {
	t.Helper()
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	resp := s.HandleMessage(context.Background(), msg)
	b, _ := json.Marshal(resp)
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func callTool(t *testing.T, s *server.MCPServer, name string, args map[string]any) (text string, isError bool) {
	t.Helper()
	out := rpc(t, s, "tools/call", map[string]any{"name": name, "arguments": args})
	res, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("%s: no result: %v", name, out)
	}
	content := res["content"].([]any)[0].(map[string]any)
	isErr, _ := res["isError"].(bool)
	return content["text"].(string), isErr
}

func toolNames(t *testing.T, s *server.MCPServer) map[string]map[string]any {
	out := rpc(t, s, "tools/list", map[string]any{})
	names := map[string]map[string]any{}
	for _, tl := range out["result"].(map[string]any)["tools"].([]any) {
		m := tl.(map[string]any)
		names[m["name"].(string)] = m
	}
	return names
}

func TestToolsListed(t *testing.T) {
	s, _, _ := setup(t, false)
	tools := toolNames(t, s)
	for _, want := range []string{"nuclei_scan", "basic_scan", "get_scan_results", "list_templates", "get_template"} {
		if _, ok := tools[want]; !ok {
			t.Errorf("missing tool %s", want)
		}
	}
	if _, ok := tools["add_template"]; ok {
		t.Error("add_template must be hidden unless allow_template_writes is set")
	}
	ann := tools["get_template"]["annotations"].(map[string]any)
	if ann["readOnlyHint"] != true {
		t.Errorf("get_template annotations: %v", ann)
	}
	if tools["nuclei_scan"]["annotations"].(map[string]any)["openWorldHint"] != true {
		t.Error("nuclei_scan must be marked open-world")
	}
	if strings.Contains(fmt.Sprint(tools["nuclei_scan"]), "thread_safe") {
		t.Error("thread_safe must no longer be exposed")
	}

	s2, _, _ := setup(t, true)
	if _, ok := toolNames(t, s2)["add_template"]; !ok {
		t.Error("add_template missing when enabled")
	}
}

func TestScanPagingAndSummary(t *testing.T) {
	s, fs, _ := setup(t, false)
	text, isErr := callTool(t, s, "nuclei_scan", map[string]any{
		"target": "https://example.com", "severity": "high", "protocols": "http,https",
		"template_ids": "a,b", "template_id": "c", "tags": "cve",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	var p Page
	if err := json.Unmarshal([]byte(text), &p); err != nil {
		t.Fatal(err)
	}
	if p.ScanID != "s1" || p.TotalFindings != 7 || p.Returned != 3 || p.NextOffset == nil || *p.NextOffset != 3 {
		t.Errorf("page: %+v", p)
	}
	if p.BySeverity["high"] != 2 || p.BySeverity["info"] != 2 {
		t.Errorf("by_severity: %v", p.BySeverity)
	}
	if !strings.Contains(p.Note, "get_scan_results") {
		t.Errorf("note should point to get_scan_results: %q", p.Note)
	}
	if fs.lastReq.Severity != "high" || fs.lastReq.Protocols != "http,https" || strings.Join(fs.lastReq.TemplateIDs, "|") != "a,b|c" {
		t.Errorf("request not passed through: %+v", fs.lastReq)
	}

	text, _ = callTool(t, s, "get_scan_results", map[string]any{"scan_id": "s1", "offset": 6})
	_ = json.Unmarshal([]byte(text), &p)
	if p.Returned != 1 || p.NextOffset != nil {
		t.Errorf("last page: %+v", p)
	}

	text, _ = callTool(t, s, "get_scan_results", map[string]any{"scan_id": "s1", "severity": "high", "limit": 10})
	_ = json.Unmarshal([]byte(text), &p)
	if p.TotalFindings != 3 {
		t.Errorf("severity filter: want 3 (critical+high), got %d", p.TotalFindings)
	}
}

func TestErrorsAreToolResults(t *testing.T) {
	s, fs, _ := setup(t, false)
	fs.scanErr = &scanner.InputError{Msg: "target out of scope: 127.0.0.1"}
	text, isErr := callTool(t, s, "nuclei_scan", map[string]any{"target": "127.0.0.1"})
	if !isErr || !strings.Contains(text, "out of scope") {
		t.Errorf("want isError result, got %v %q", isErr, text)
	}
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"nuclei_scan", map[string]any{}},
		{"nuclei_scan", map[string]any{"target": "x", "limit": 0}},
		{"nuclei_scan", map[string]any{"target": "x", "limit": 501}},
		{"basic_scan", map[string]any{"target": "x", "offset": -1}},
		{"get_scan_results", map[string]any{"scan_id": "missing"}},
		{"get_scan_results", map[string]any{"scan_id": "s1", "severity": "bogus"}},
		{"get_template", map[string]any{"name": "../../etc/passwd"}},
	}
	for _, c := range cases {
		if text, isErr := callTool(t, s, c.tool, c.args); !isErr {
			t.Errorf("%s %v: want isError, got %q", c.tool, c.args, text)
		}
	}
}

func TestPanicIsRecovered(t *testing.T) {
	s, fs, _ := setup(t, false)
	fs.panicNow = true
	out := rpc(t, s, "tools/call", map[string]any{"name": "nuclei_scan", "arguments": map[string]any{"target": "x"}})
	if out["error"] == nil {
		t.Fatalf("expected an error response after a panic, got %v", out)
	}
	// The server still answers afterwards.
	if _, isErr := callTool(t, s, "list_templates", map[string]any{}); isErr {
		t.Error("server unusable after recovered panic")
	}
}

func TestTemplatesTools(t *testing.T) {
	s, _, ft := setup(t, true)
	text, _ := callTool(t, s, "list_templates", map[string]any{"filter": "DNS"})
	if !strings.Contains(text, "dns/dmarc.yaml") || strings.Contains(text, "tech-detect") {
		t.Errorf("filtered list: %s", text)
	}
	if text, isErr := callTool(t, s, "get_template", map[string]any{"name": "basic-test.yaml"}); isErr || text != "id: basic-test" {
		t.Errorf("get_template: %v %q", isErr, text)
	}
	if _, isErr := callTool(t, s, "add_template", map[string]any{"name": "x.yaml", "content": "id: x"}); isErr || ft.added["x.yaml"] != "id: x" {
		t.Error("add_template did not store the template")
	}
	if _, isErr := callTool(t, s, "add_template", map[string]any{"name": "../x.yaml", "content": "id: x"}); !isErr {
		t.Error("bad add_template must be an error result")
	}
}

func TestResources(t *testing.T) {
	s, _, _ := setup(t, false)
	out := rpc(t, s, "resources/read", map[string]any{"uri": "nuclei://scans"})
	text := out["result"].(map[string]any)["contents"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"uri":"nuclei://scans/s1"`) || !strings.Contains(text, `"total_findings":7`) {
		t.Errorf("recent scans resource: %s", text)
	}
	out = rpc(t, s, "resources/read", map[string]any{"uri": "nuclei://scans/s1"})
	text = out["result"].(map[string]any)["contents"].([]any)[0].(map[string]any)["text"].(string)
	var p Page
	if err := json.Unmarshal([]byte(text), &p); err != nil || p.Returned != 7 {
		t.Errorf("scan resource must hold every finding: %v %+v", err, p)
	}
	out = rpc(t, s, "resources/read", map[string]any{"uri": "nuclei://scans/nope"})
	if out["error"] == nil {
		t.Error("unknown scan must be an error")
	}
	out = rpc(t, s, "resources/templates/list", map[string]any{})
	if !strings.Contains(fmt.Sprint(out), "nuclei://scans/{scan_id}") {
		t.Errorf("resource template not listed: %v", out)
	}
}

func TestInitializeAdvertisesInstructions(t *testing.T) {
	s, _, _ := setup(t, false)
	out := rpc(t, s, "initialize", map[string]any{"protocolVersion": mcp.LATEST_PROTOCOL_VERSION, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t", "version": "0"}})
	res := out["result"].(map[string]any)
	if !strings.Contains(fmt.Sprint(res["instructions"]), "authorized") {
		t.Error("instructions should remind the model about authorization")
	}
	if res["serverInfo"].(map[string]any)["version"] != "test" {
		t.Errorf("version not injected: %v", res["serverInfo"])
	}
	if _, ok := res["capabilities"].(map[string]any)["logging"]; ok {
		t.Error("logging capability is advertised but never used")
	}
}
