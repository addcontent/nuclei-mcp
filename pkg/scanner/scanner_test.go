package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/addcontent/nuclei-mcp/pkg/cache"
	"github.com/addcontent/nuclei-mcp/pkg/logging"

	lib "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// fakeEngine records how the scanner drives the engine.
type fakeEngine struct {
	mu            sync.Mutex
	loadedAll     bool
	targets       []string
	probe         bool
	events        []*output.ResultEvent
	execErr       error
	blockUntilCtx bool
	closed        bool
}

func (f *fakeEngine) LoadAllTemplates() error { f.loadedAll = true; return nil }
func (f *fakeEngine) LoadTargets(t []string, probe bool) {
	f.targets, f.probe = t, probe
}
func (f *fakeEngine) ExecuteCallbackWithCtx(ctx context.Context, cbs ...func(*output.ResultEvent)) error {
	for _, ev := range f.events {
		for _, cb := range cbs {
			cb(ev)
		}
	}
	if f.blockUntilCtx {
		<-ctx.Done()
	}
	return f.execErr
}
func (f *fakeEngine) Close() { f.closed = true }

type harness struct {
	svc     *Service
	engines []*fakeEngine
	next    func() *fakeEngine
	dir     string
	fp      string
}

func newHarness(t *testing.T, scope ScopeChecker) *harness {
	t.Helper()
	h := &harness{dir: t.TempDir(), fp: "v1"}
	if err := os.WriteFile(filepath.Join(h.dir, "basic-test.yaml"), []byte("id: basic-test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.next = func() *fakeEngine { return &fakeEngine{} }
	h.svc = New(Options{
		TemplatesDir: h.dir,
		ScanTimeout:  time.Second,
		Scope:        scope,
		Fingerprint:  func() (string, error) { return h.fp, nil },
		Logger:       logging.Discard(),
		NewEngine: func(ctx context.Context, opts ...lib.NucleiSDKOptions) (Engine, error) {
			e := h.next()
			h.engines = append(h.engines, e)
			return e, nil
		},
	}, cache.New(true, time.Hour, 10))
	return h
}

func event(id, sev, matched string) *output.ResultEvent {
	ev := &output.ResultEvent{TemplateID: id, Matched: matched, Host: "example.com"}
	ev.Info = model.Info{
		Name:           id + " name",
		SeverityHolder: severity.Holder{Severity: mustSeverity(sev)},
		Tags:           stringslice.StringSlice{Value: []string{"tech"}},
		Classification: &model.Classification{CVEID: stringslice.StringSlice{Value: []string{"CVE-2024-0001"}}, CVSSScore: 9.8},
	}
	return ev
}

func mustSeverity(s string) severity.Severity {
	var h severity.Holder
	if err := h.UnmarshalYAML(func(v any) error { *(v.(*string)) = s; return nil }); err != nil {
		panic(err)
	}
	return h.Severity
}

func TestScanPipeline(t *testing.T) {
	h := newHarness(t, nil)
	h.next = func() *fakeEngine {
		return &fakeEngine{events: []*output.ResultEvent{
			event("low-one", "low", "https://example.com/a"),
			event("crit-one", "critical", "https://example.com/b"),
			nil,
		}}
	}
	out, err := h.svc.Scan(context.Background(), Request{Target: "https://example.com", Severity: "low", Protocols: "http,https"})
	if err != nil {
		t.Fatal(err)
	}
	e := h.engines[0]
	if !e.loadedAll {
		t.Error("LoadAllTemplates was not called")
	}
	if !e.closed {
		t.Error("engine not closed")
	}
	if e.probe {
		t.Error("a target with a scheme must not be probed")
	}
	r := out.Result
	if r.ID == "" || r.Kind != "nuclei_scan" || len(r.Findings) != 2 {
		t.Fatalf("unexpected result: %+v", r)
	}
	if r.Findings[0].Severity != "critical" || r.Findings[0].CVE[0] != "CVE-2024-0001" || r.Findings[0].CVSSScore != 9.8 {
		t.Errorf("findings not sorted or mapped: %+v", r.Findings[0])
	}

	again, err := h.svc.Scan(context.Background(), Request{Target: "https://example.com", Severity: "low", Protocols: "http"})
	if err != nil || !again.Cached || len(h.engines) != 1 {
		t.Fatalf("identical scan should be cached (https normalises to http): cached=%v engines=%d err=%v", again.Cached, len(h.engines), err)
	}

	h.fp = "v2" // templates changed on disk
	third, err := h.svc.Scan(context.Background(), Request{Target: "https://example.com", Severity: "low", Protocols: "http"})
	if err != nil || third.Cached || len(h.engines) != 2 {
		t.Fatalf("changed templates must bypass the cache: cached=%v engines=%d", third.Cached, len(h.engines))
	}
	if got, ok := h.svc.Get(r.ID); !ok || got.ID != r.ID {
		t.Error("result not retrievable by ID")
	}
}

func TestBareHostIsProbed(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := h.svc.BasicScan(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if !h.engines[0].probe || !h.engines[0].loadedAll {
		t.Errorf("bare host: probe=%v loadedAll=%v", h.engines[0].probe, h.engines[0].loadedAll)
	}
	if _, err := h.svc.BasicScan(context.Background(), "http://example.org"); err != nil {
		t.Fatal(err)
	}
	if h.engines[1].probe {
		t.Error("schemed target probed in basic_scan")
	}
}

type denyAll struct{}

func (denyAll) Check(context.Context, string) error { return errors.New("target out of scope: test") }

func TestScopeRefusalCreatesNoEngine(t *testing.T) {
	h := newHarness(t, denyAll{})
	_, err := h.svc.Scan(context.Background(), Request{Target: "http://10.0.0.1"})
	var ie *InputError
	if !errors.As(err, &ie) {
		t.Fatalf("want InputError, got %v", err)
	}
	if _, err := h.svc.BasicScan(context.Background(), "10.0.0.1"); !errors.As(err, &ie) {
		t.Fatalf("basic: want InputError, got %v", err)
	}
	if len(h.engines) != 0 {
		t.Error("engine created for an out-of-scope target")
	}
}

func TestTimeoutReturnsPartialResult(t *testing.T) {
	h := newHarness(t, nil)
	h.svc.opts.ScanTimeout = 50 * time.Millisecond
	h.next = func() *fakeEngine {
		return &fakeEngine{blockUntilCtx: true, events: []*output.ResultEvent{event("x", "high", "u")}}
	}
	out, err := h.svc.Scan(context.Background(), Request{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Result.Partial || out.Result.PartialReason == "" || len(out.Result.Findings) != 1 {
		t.Fatalf("want partial result with 1 finding, got %+v", out.Result)
	}
	if again, _ := h.svc.Scan(context.Background(), Request{Target: "example.com"}); again.Cached {
		t.Error("partial result must not be reused")
	}
}

func TestNoTemplatesIsInputError(t *testing.T) {
	h := newHarness(t, nil)
	h.next = func() *fakeEngine { return &fakeEngine{execErr: lib.ErrNoTemplatesAvailable} }
	_, err := h.svc.Scan(context.Background(), Request{Target: "example.com", TemplateIDs: []string{"nope"}})
	var ie *InputError
	if !errors.As(err, &ie) {
		t.Fatalf("want InputError, got %v", err)
	}
}

func TestEngineErrorPropagates(t *testing.T) {
	h := newHarness(t, nil)
	h.next = func() *fakeEngine { return &fakeEngine{execErr: errors.New("boom")} }
	if _, err := h.svc.Scan(context.Background(), Request{Target: "example.com"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestTemplateRefs(t *testing.T) {
	h := newHarness(t, nil)
	ids, files, err := h.svc.splitTemplateRefs([]string{" cve-2024-1 , tech-detect", "basic-test.yaml", "tech-detect"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "cve-2024-1" || len(files) != 1 || files[0] != filepath.Join(h.dir, "basic-test.yaml") {
		t.Errorf("ids=%v files=%v", ids, files)
	}
	for _, bad := range []string{"../../etc/passwd.yaml", "/etc/x.yaml", "missing.yaml", "bad id!"} {
		if _, _, err := h.svc.splitTemplateRefs([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBasicScanMissingTemplate(t *testing.T) {
	h := newHarness(t, nil)
	h.svc.opts.BasicTemplate = "gone.yaml"
	if _, err := h.svc.BasicScan(context.Background(), "example.com"); err == nil {
		t.Fatal("expected error for a missing basic template")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"":               "",
		"info":           "info,low,medium,high,critical",
		"HIGH":           "high,critical",
		"critical":       "critical",
		"low, high":      "low,high",
		"unknown":        "unknown",
		"medium,medium,": "medium",
	}
	for in, want := range cases {
		got, err := NormalizeSeverity(in)
		if err != nil || got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"severe", "low,extreme"} {
		if _, err := NormalizeSeverity(bad); err == nil {
			t.Errorf("NormalizeSeverity(%q) accepted", bad)
		}
	}
}

func TestNormalizeProtocols(t *testing.T) {
	cases := map[string]string{
		"":                   "",
		"http,https":         "http",
		"HTTPS":              "http",
		"dns, http , tcp":    "dns,http,tcp",
		"network,ssl":        "ssl,tcp",
		"js,whois,websocket": "javascript,websocket,whois",
	}
	for in, want := range cases {
		got, err := NormalizeProtocols(in)
		if err != nil || got != want {
			t.Errorf("NormalizeProtocols(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"ftp", "code", "file", "headless", "http,smtp"} {
		if _, err := NormalizeProtocols(bad); err == nil {
			t.Errorf("NormalizeProtocols(%q) accepted", bad)
		}
	}
}
