// Package scanner runs Nuclei scans through the Nuclei Go SDK.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/addcontent/nuclei-mcp/pkg/cache"
	"github.com/addcontent/nuclei-mcp/pkg/scope"

	lib "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
)

// Engine is the part of the Nuclei SDK engine the scanner uses. It exists so
// tests can run the scan pipeline without network access.
type Engine interface {
	LoadAllTemplates() error
	LoadTargets(targets []string, probeNonHTTP bool)
	ExecuteCallbackWithCtx(ctx context.Context, callback ...func(event *output.ResultEvent)) error
	Close()
}

// EngineFactory creates an engine from SDK options.
type EngineFactory func(ctx context.Context, opts ...lib.NucleiSDKOptions) (Engine, error)

// NucleiEngineFactory creates a real Nuclei engine.
func NucleiEngineFactory(ctx context.Context, opts ...lib.NucleiSDKOptions) (Engine, error) {
	return lib.NewNucleiEngineCtx(ctx, opts...)
}

// ScopeChecker decides whether a target may be scanned.
type ScopeChecker interface {
	Check(ctx context.Context, target string) error
}

// Options configures the scanner. Zero values get safe defaults.
type Options struct {
	TemplatesDir   string
	BasicTemplate  string
	ScanTimeout    time.Duration
	RequestTimeout time.Duration
	Retries        int
	RateLimit      int // requests per second
	// HostConcurrency and TemplateConcurrency map to Nuclei's bulk-size and
	// template-threads.
	HostConcurrency     int
	TemplateConcurrency int
	SystemResolvers     bool
	// Interactsh enables out-of-band callbacks to public interactsh servers.
	Interactsh bool
	// RestrictLocalNetwork makes Nuclei itself refuse connections to local
	// addresses, a second line of defence behind Scope.
	RestrictLocalNetwork bool
	Scope                ScopeChecker
	// Fingerprint identifies the current template set; it is part of the
	// cache key so edited templates are never answered from the cache.
	Fingerprint func() (string, error)
	NewEngine   EngineFactory
	Logger      *slog.Logger
}

// Request describes a nuclei_scan.
type Request struct {
	Target string
	// Severity is a minimum ("high" means high and critical) or an exact
	// comma-separated list ("low,high").
	Severity string
	// Protocols is a comma-separated list of Nuclei protocol types.
	Protocols   string
	TemplateIDs []string // Nuclei template IDs, or relative .yaml paths
	Tags        []string
	ExcludeTags []string
}

// Outcome is a scan result and whether it came from the cache.
type Outcome struct {
	Result cache.ScanResult
	Cached bool
}

// Service runs scans and keeps their results.
type Service struct {
	opts  Options
	store *cache.Store
}

// New returns a scanner that stores results in store.
func New(opts Options, store *cache.Store) *Service {
	if opts.BasicTemplate == "" {
		opts.BasicTemplate = "basic-test.yaml"
	}
	if opts.ScanTimeout <= 0 {
		opts.ScanTimeout = 10 * time.Minute
	}
	if opts.RequestTimeout < time.Second {
		opts.RequestTimeout = 10 * time.Second
	}
	if opts.RateLimit < 1 {
		opts.RateLimit = 150
	}
	if opts.HostConcurrency < 1 {
		opts.HostConcurrency = 25
	}
	if opts.TemplateConcurrency < 1 {
		opts.TemplateConcurrency = 25
	}
	if opts.NewEngine == nil {
		opts.NewEngine = NucleiEngineFactory
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if store == nil {
		store = cache.New(true, time.Hour, 100)
	}
	return &Service{opts: opts, store: store}
}

// InputError is a problem with the request that the caller can fix.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

func inputErrorf(format string, args ...any) error {
	return &InputError{Msg: fmt.Sprintf(format, args...)}
}

// Scan runs a filtered scan of the whole templates directory.
func (s *Service) Scan(ctx context.Context, req Request) (Outcome, error) {
	target, err := s.checkTarget(ctx, req.Target)
	if err != nil {
		return Outcome{}, err
	}
	sev, err := NormalizeSeverity(req.Severity)
	if err != nil {
		return Outcome{}, err
	}
	protocols, err := NormalizeProtocols(req.Protocols)
	if err != nil {
		return Outcome{}, err
	}
	ids, files, err := s.splitTemplateRefs(req.TemplateIDs)
	if err != nil {
		return Outcome{}, err
	}
	tags, err := normalizeTags(req.Tags)
	if err != nil {
		return Outcome{}, err
	}
	excludeTags, err := normalizeTags(req.ExcludeTags)
	if err != nil {
		return Outcome{}, err
	}

	key := strings.Join([]string{"scan", target, sev, protocols, strings.Join(ids, ","),
		strings.Join(files, ","), strings.Join(tags, ","), strings.Join(excludeTags, ","), s.fingerprint()}, "|")
	if r, ok := s.store.Lookup(key); ok {
		s.opts.Logger.Info("returning cached scan", "target", target, "scan_id", r.ID)
		return Outcome{Result: r, Cached: true}, nil
	}

	sources := []string{s.opts.TemplatesDir}
	if len(files) > 0 {
		sources = files
	}
	filters := lib.TemplateFilters{Severity: sev, ProtocolTypes: protocols, IDs: ids, Tags: tags, ExcludeTags: excludeTags}
	res, err := s.run(ctx, "nuclei_scan", target, sources, &filters)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Result: s.store.Put(key, res)}, nil
}

// BasicScan runs only the configured basic template.
func (s *Service) BasicScan(ctx context.Context, target string) (Outcome, error) {
	target, err := s.checkTarget(ctx, target)
	if err != nil {
		return Outcome{}, err
	}
	tpl := filepath.Join(s.opts.TemplatesDir, s.opts.BasicTemplate)
	if _, err := os.Stat(tpl); err != nil {
		return Outcome{}, fmt.Errorf("basic template %s is missing; restart the server to reinstall the built-in templates or set nuclei.basic_template_name", tpl)
	}
	key := strings.Join([]string{"basic", target, s.fingerprint()}, "|")
	if r, ok := s.store.Lookup(key); ok {
		return Outcome{Result: r, Cached: true}, nil
	}
	res, err := s.run(ctx, "basic_scan", target, []string{tpl}, nil)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{Result: s.store.Put(key, res)}, nil
}

// Recent returns stored scans, newest first.
func (s *Service) Recent() []cache.ScanResult { return s.store.Recent() }

// Get returns a stored scan by ID.
func (s *Service) Get(id string) (cache.ScanResult, bool) { return s.store.Get(id) }

func (s *Service) checkTarget(ctx context.Context, target string) (string, error) {
	target = strings.TrimSpace(target)
	if _, err := scope.Host(target); err != nil {
		return "", &InputError{Msg: err.Error()}
	}
	if s.opts.Scope != nil {
		if err := s.opts.Scope.Check(ctx, target); err != nil {
			return "", &InputError{Msg: err.Error()}
		}
	}
	return target, nil
}

func (s *Service) fingerprint() string {
	if s.opts.Fingerprint == nil {
		return ""
	}
	fp, err := s.opts.Fingerprint()
	if err != nil {
		// Never reuse a result when the template set cannot be identified.
		return fmt.Sprintf("unknown-%d", time.Now().UnixNano())
	}
	return fp
}

// needsProbe reports whether Nuclei should probe the target for HTTP/HTTPS.
// Probing a target that already has a scheme breaks it, so only bare hosts
// are probed.
func needsProbe(target string) bool { return !strings.Contains(target, "://") }

func (s *Service) engineOptions(ctx context.Context, sources []string, filters *lib.TemplateFilters) []lib.NucleiSDKOptions {
	opts := []lib.NucleiSDKOptions{
		lib.DisableUpdateCheck(),
		lib.WithTemplatesOrWorkflows(lib.TemplateSources{Templates: sources}),
		lib.WithConcurrency(lib.Concurrency{
			TemplateConcurrency:           s.opts.TemplateConcurrency,
			HostConcurrency:               s.opts.HostConcurrency,
			HeadlessHostConcurrency:       1,
			HeadlessTemplateConcurrency:   1,
			JavascriptTemplateConcurrency: s.opts.TemplateConcurrency,
			TemplatePayloadConcurrency:    25,
			ProbeConcurrency:              50,
		}),
		lib.WithGlobalRateLimitCtx(ctx, s.opts.RateLimit, time.Second),
		lib.WithNetworkConfig(lib.NetworkConfig{
			Timeout:         int(s.opts.RequestTimeout / time.Second),
			Retries:         s.opts.Retries,
			SystemResolvers: s.opts.SystemResolvers,
			MaxHostError:    30,
		}),
		lib.WithSandboxOptions(false, s.opts.RestrictLocalNetwork),
	}
	if filters != nil {
		opts = append(opts, lib.WithTemplateFilters(*filters))
	}
	if !s.opts.Interactsh {
		// Start from the SDK defaults: a zero-value options struct has a zero
		// cache size, which makes the engine panic. The engine fills in its
		// own output and progress writers.
		iopts := lib.InteractshOpts(*interactsh.DefaultOptions(nil, nil, nil))
		iopts.NoInteractsh = true
		opts = append(opts, lib.WithInteractshOptions(iopts))
	}
	return opts
}

func (s *Service) run(ctx context.Context, kind, target string, sources []string, filters *lib.TemplateFilters) (cache.ScanResult, error) {
	ctx, cancel := context.WithTimeout(ctx, s.opts.ScanTimeout)
	defer cancel()

	start := time.Now()
	log := s.opts.Logger.With("kind", kind, "target", target)
	log.Info("scan started")

	ne, err := s.opts.NewEngine(ctx, s.engineOptions(ctx, sources, filters)...)
	if err != nil {
		return cache.ScanResult{}, fmt.Errorf("creating scan engine: %w", err)
	}
	defer ne.Close()

	if err := ne.LoadAllTemplates(); err != nil {
		return cache.ScanResult{}, fmt.Errorf("loading templates: %w", err)
	}
	ne.LoadTargets([]string{target}, needsProbe(target))

	var mu sync.Mutex
	findings := []cache.Finding{}
	err = ne.ExecuteCallbackWithCtx(ctx, func(ev *output.ResultEvent) {
		if ev == nil {
			return
		}
		f := ToFinding(ev)
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
		log.Debug("finding", "template", f.TemplateID, "severity", f.Severity, "matched", f.MatchedAt)
	})

	mu.Lock()
	defer mu.Unlock()
	SortFindings(findings)
	res := cache.ScanResult{Kind: kind, Target: target, ScanTime: start, Duration: time.Since(start), Findings: findings}

	switch {
	case ctx.Err() != nil:
		res.Partial = true
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			res.PartialReason = fmt.Sprintf("scan stopped after %s (nuclei.scan_timeout); findings are incomplete", s.opts.ScanTimeout)
		} else {
			res.PartialReason = "scan was cancelled; findings are incomplete"
		}
	case err == nil:
	case isNoTemplates(err):
		return cache.ScanResult{}, inputErrorf("no templates match these filters%s; call list_templates to see what is installed", describeFilters(filters))
	default:
		return cache.ScanResult{}, fmt.Errorf("scan failed: %w", err)
	}
	log.Info("scan finished", "findings", len(findings), "duration", res.Duration.Round(time.Millisecond), "partial", res.Partial)
	return res, nil
}

func isNoTemplates(err error) bool {
	return errors.Is(err, lib.ErrNoTemplatesAvailable) || strings.Contains(strings.ToLower(err.Error()), "no templates available")
}

func describeFilters(f *lib.TemplateFilters) string {
	if f == nil {
		return ""
	}
	var parts []string
	add := func(name, v string) {
		if v != "" {
			parts = append(parts, name+"="+v)
		}
	}
	add("severity", f.Severity)
	add("protocols", f.ProtocolTypes)
	add("template_ids", strings.Join(f.IDs, ","))
	add("tags", strings.Join(f.Tags, ","))
	add("exclude_tags", strings.Join(f.ExcludeTags, ","))
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

var (
	idRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	tagRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// splitTemplateRefs separates Nuclei template IDs from relative template
// paths (anything ending in .yaml/.yml), validating both. Paths must stay
// inside the templates directory.
func (s *Service) splitTemplateRefs(refs []string) (ids, files []string, err error) {
	seen := map[string]bool{}
	for _, raw := range refs {
		for _, ref := range strings.Split(raw, ",") {
			ref = strings.TrimSpace(ref)
			if ref == "" || seen[ref] {
				continue
			}
			seen[ref] = true
			if ext := path.Ext(ref); ext == ".yaml" || ext == ".yml" {
				rel := path.Clean(strings.ReplaceAll(ref, `\`, "/"))
				if path.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") {
					return nil, nil, inputErrorf("template path %q must stay inside the templates directory", ref)
				}
				full := filepath.Join(s.opts.TemplatesDir, filepath.FromSlash(rel))
				if _, statErr := os.Stat(full); statErr != nil {
					return nil, nil, inputErrorf("template file %q not found; call list_templates", ref)
				}
				files = append(files, full)
				continue
			}
			if !idRE.MatchString(ref) {
				return nil, nil, inputErrorf("invalid template id %q", ref)
			}
			ids = append(ids, ref)
		}
	}
	sort.Strings(ids)
	sort.Strings(files)
	return ids, files, nil
}

func normalizeTags(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		for _, t := range strings.Split(raw, ",") {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" || seen[t] {
				continue
			}
			if !tagRE.MatchString(t) {
				return nil, inputErrorf("invalid tag %q", t)
			}
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out, nil
}

// SeverityOrder lists Nuclei severities from lowest to highest.
var SeverityOrder = []string{"info", "low", "medium", "high", "critical"}

// SeverityRank orders severities for sorting; unknown sorts lowest.
func SeverityRank(s string) int {
	for i, v := range SeverityOrder {
		if v == s {
			return i + 1
		}
	}
	return 0
}

// NormalizeSeverity turns a minimum severity into the list Nuclei expects
// ("high" -> "high,critical"). A comma-separated list is taken as an exact
// set. Nuclei itself only matches exact severities, so passing "high"
// straight through would silently skip critical templates.
func NormalizeSeverity(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil
	}
	valid := map[string]bool{"unknown": true}
	for _, v := range SeverityOrder {
		valid[v] = true
	}
	if strings.Contains(s, ",") {
		seen := map[string]bool{}
		var out []string
		for _, v := range strings.Split(s, ",") {
			v = strings.TrimSpace(v)
			if v == "" || seen[v] {
				continue
			}
			if !valid[v] {
				return "", inputErrorf("invalid severity %q: use info, low, medium, high, critical or unknown", v)
			}
			seen[v] = true
			out = append(out, v)
		}
		return strings.Join(out, ","), nil
	}
	if s == "unknown" {
		return s, nil
	}
	for i, v := range SeverityOrder {
		if v == s {
			return strings.Join(SeverityOrder[i:], ","), nil
		}
	}
	return "", inputErrorf("invalid severity %q: use info, low, medium, high or critical (a minimum), or a comma-separated list", s)
}

// Protocols the scanner accepts. code, file and headless templates are not
// enabled in this server, so asking for them would only match nothing.
var supportedProtocols = []string{"dns", "http", "javascript", "ssl", "tcp", "websocket", "whois"}

var protocolAliases = map[string]string{"https": "http", "network": "tcp", "js": "javascript"}

// NormalizeProtocols validates a comma-separated protocol list. "https" is
// accepted as an alias of "http" (Nuclei's http protocol covers both
// schemes; passing "https" through crashed every default scan, issue #9).
func NormalizeProtocols(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil
	}
	ok := map[string]bool{}
	for _, p := range supportedProtocols {
		ok[p] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if alias, isAlias := protocolAliases[p]; isAlias {
			p = alias
		}
		if p == "" || seen[p] {
			continue
		}
		if !ok[p] {
			return "", inputErrorf("unsupported protocol %q: use %s", p, strings.Join(supportedProtocols, ", "))
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Strings(out)
	return strings.Join(out, ","), nil
}

// ToFinding converts a Nuclei result event.
func ToFinding(ev *output.ResultEvent) cache.Finding {
	sev := strings.ToLower(ev.Info.SeverityHolder.Severity.String())
	if sev == "" {
		sev = "unknown"
	}
	matched := ev.Matched
	if matched == "" {
		matched = ev.URL
	}
	f := cache.Finding{
		TemplateID:       ev.TemplateID,
		Name:             ev.Info.Name,
		Severity:         sev,
		Type:             ev.Type,
		Host:             ev.Host,
		MatchedAt:        matched,
		MatcherName:      ev.MatcherName,
		ExtractorName:    ev.ExtractorName,
		ExtractedResults: limitStrings(ev.ExtractedResults, 20, 500),
		Description:      truncate(strings.TrimSpace(ev.Info.Description), 2000),
		Remediation:      truncate(strings.TrimSpace(ev.Info.Remediation), 2000),
		Tags:             ev.Info.Tags.ToSlice(),
		Timestamp:        ev.Timestamp,
	}
	if ev.Info.Reference != nil {
		f.References = limitStrings(ev.Info.Reference.ToSlice(), 20, 500)
	}
	if c := ev.Info.Classification; c != nil {
		f.CVE = c.CVEID.ToSlice()
		f.CWE = c.CWEID.ToSlice()
		f.CVSSScore = c.CVSSScore
		f.CVSSMetrics = c.CVSSMetrics
	}
	return f
}

// SortFindings orders by severity (highest first), then template and location.
func SortFindings(fs []cache.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := SeverityRank(a.Severity), SeverityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.TemplateID != b.TemplateID {
			return a.TemplateID < b.TemplateID
		}
		return a.MatchedAt < b.MatchedAt
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func limitStrings(in []string, maxItems, maxLen int) []string {
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxItems {
		in = in[:maxItems]
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = truncate(s, maxLen)
	}
	return out
}
