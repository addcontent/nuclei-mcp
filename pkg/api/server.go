// Package api exposes the scanner as MCP tools and resources.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/addcontent/nuclei-mcp/pkg/cache"
	"github.com/addcontent/nuclei-mcp/pkg/scanner"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Scanner is what the tools need from the scan service.
type Scanner interface {
	Scan(ctx context.Context, req scanner.Request) (scanner.Outcome, error)
	BasicScan(ctx context.Context, target string) (scanner.Outcome, error)
	Recent() []cache.ScanResult
	Get(id string) (cache.ScanResult, bool)
}

// Templates is what the tools need from the template store.
type Templates interface {
	AddTemplate(name string, content []byte) error
	ListTemplates() ([]string, error)
	GetTemplate(name string) ([]byte, error)
}

// Config shapes the server.
type Config struct {
	Name    string
	Version string
	// AllowTemplateWrites registers add_template.
	AllowTemplateWrites bool
	// PageSize is the default number of findings per result.
	PageSize int
	Logger   *slog.Logger
}

const (
	maxPageSize      = 500
	maxListTemplates = 1000
	scansURI         = "nuclei://scans"
	scanURIPrefix    = "nuclei://scans/"
)

const instructions = `Runs Nuclei vulnerability scans. Scans send real, sometimes intrusive, network traffic: only scan systems the user owns or is authorized to test, and confirm the target with the user first. Start with basic_scan or a narrow nuclei_scan (severity, tags, template_ids). Large results are paged: call get_scan_results with the scan_id to read more.`

// NewServer builds the MCP server.
func NewServer(sc Scanner, tm Templates, cfg Config) *server.MCPServer {
	if cfg.Name == "" {
		cfg.Name = "nuclei-mcp"
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if cfg.PageSize < 1 {
		cfg.PageSize = 50
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	h := &handlers{sc: sc, tm: tm, cfg: cfg}

	s := server.NewMCPServer(cfg.Name, cfg.Version,
		server.WithRecovery(),
		server.WithToolCapabilities(false),
		server.WithResourceCapabilities(false, false),
		server.WithInstructions(instructions),
	)

	pageOpts := []mcp.ToolOption{
		mcp.WithNumber("limit", mcp.Description(fmt.Sprintf("Findings per page (default %d, max %d)", cfg.PageSize, maxPageSize)), mcp.Min(1), mcp.Max(maxPageSize)),
		mcp.WithNumber("offset", mcp.Description("Index of the first finding to return (default 0)"), mcp.Min(0)),
	}

	scanTool := append([]mcp.ToolOption{
		mcp.WithDescription("Run a Nuclei vulnerability scan against one target using the installed templates. Only scan systems you are authorized to test. Returns a summary by severity and the first page of findings; use get_scan_results with the scan_id for more."),
		mcp.WithTitleAnnotation("Nuclei scan"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("target", mcp.Required(), mcp.Description("URL (https://example.com), host (example.com), host:port or IP to scan")),
		mcp.WithString("severity", mcp.Description("Minimum severity: info, low, medium, high or critical (\"high\" runs high and critical). A comma-separated list (\"low,high\") selects exactly those. Default: all.")),
		mcp.WithString("protocols", mcp.Description("Comma-separated protocol types: http, dns, ssl, tcp, websocket, whois, javascript (\"https\" means http). Default: all.")),
		mcp.WithString("template_ids", mcp.Description("Comma-separated Nuclei template IDs (e.g. \"tech-detect,dmarc-detect\") or template file paths from list_templates")),
		mcp.WithString("template_id", mcp.Description("A single template ID; same as template_ids")),
		mcp.WithString("tags", mcp.Description("Comma-separated template tags to include (e.g. \"cve,exposure\")")),
		mcp.WithString("exclude_tags", mcp.Description("Comma-separated template tags to skip (e.g. \"dos,fuzz\")")),
	}, pageOpts...)
	s.AddTool(mcp.NewTool("nuclei_scan", scanTool...), h.nucleiScan)

	basicTool := append([]mcp.ToolOption{
		mcp.WithDescription("Run the single built-in basic template against a target: a quick check that the target answers HTTP. Only scan systems you are authorized to test."),
		mcp.WithTitleAnnotation("Basic scan"),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("target", mcp.Required(), mcp.Description("URL, host, host:port or IP to scan")),
	}, pageOpts...)
	s.AddTool(mcp.NewTool("basic_scan", basicTool...), h.basicScan)

	resultsTool := append([]mcp.ToolOption{
		mcp.WithDescription("Read the findings of an earlier scan by scan_id, a page at a time, optionally filtered by minimum severity."),
		mcp.WithTitleAnnotation("Scan results"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("scan_id", mcp.Required(), mcp.Description("The scan_id returned by nuclei_scan or basic_scan")),
		mcp.WithString("severity", mcp.Description("Minimum severity to include, or a comma-separated list")),
	}, pageOpts...)
	s.AddTool(mcp.NewTool("get_scan_results", resultsTool...), h.getScanResults)

	s.AddTool(mcp.NewTool("list_templates",
		mcp.WithDescription("List installed Nuclei template files (paths relative to the templates directory)."),
		mcp.WithTitleAnnotation("List templates"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("filter", mcp.Description("Only list paths containing this text (case-insensitive)")),
	), h.listTemplates)

	s.AddTool(mcp.NewTool("get_template",
		mcp.WithDescription("Return the YAML of one installed template."),
		mcp.WithTitleAnnotation("Get template"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("name", mcp.Required(), mcp.Description("Template path as shown by list_templates, e.g. basic-test.yaml")),
	), h.getTemplate)

	if cfg.AllowTemplateWrites {
		s.AddTool(mcp.NewTool("add_template",
			mcp.WithDescription("Save a new Nuclei template. It runs on every later nuclei_scan that has no template_ids, so only add templates the user has reviewed. Network protocols only (http, dns, tcp, ssl, websocket, whois); existing files are never overwritten."),
			mcp.WithTitleAnnotation("Add template"),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
			mcp.WithIdempotentHintAnnotation(false),
			mcp.WithOpenWorldHintAnnotation(false),
			mcp.WithString("name", mcp.Required(), mcp.Description("New file name, e.g. my-check.yaml")),
			mcp.WithString("content", mcp.Required(), mcp.Description("The template YAML (max 64 KiB)")),
		), h.addTemplate)
	}

	s.AddResource(mcp.NewResource(scansURI, "Recent scans",
		mcp.WithResourceDescription("Summaries of recent scans, newest first"),
		mcp.WithMIMEType("application/json")), h.recentScansResource)
	s.AddResourceTemplate(mcp.NewResourceTemplate(scanURIPrefix+"{scan_id}", "Scan result",
		mcp.WithTemplateDescription("All findings of one scan"),
		mcp.WithTemplateMIMEType("application/json")), h.scanResource)

	return s
}

type handlers struct {
	sc  Scanner
	tm  Templates
	cfg Config
}

// toolError reports any failure as a tool result with isError set, so the
// model sees the message and can correct its call. Unexpected failures are
// also logged.
func (h *handlers) toolError(tool string, err error) (*mcp.CallToolResult, error) {
	var ie *scanner.InputError
	if !errors.As(err, &ie) {
		h.cfg.Logger.Error("tool failed", "tool", tool, "error", err)
	}
	return mcp.NewToolResultError(err.Error()), nil
}

func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return mcp.NewToolResultError("encoding result: " + err.Error()), nil
	}
	return mcp.NewToolResultText(string(b)), nil
}

func (h *handlers) nucleiScan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return h.toolError("nuclei_scan", err)
	}
	limit, offset, err := h.paging(req)
	if err != nil {
		return h.toolError("nuclei_scan", err)
	}
	ids := []string{req.GetString("template_ids", "")}
	if one := req.GetString("template_id", ""); one != "" {
		ids = append(ids, one)
	}
	out, err := h.sc.Scan(ctx, scanner.Request{
		Target:      target,
		Severity:    req.GetString("severity", ""),
		Protocols:   req.GetString("protocols", ""),
		TemplateIDs: ids,
		Tags:        []string{req.GetString("tags", "")},
		ExcludeTags: []string{req.GetString("exclude_tags", "")},
	})
	if err != nil {
		return h.toolError("nuclei_scan", err)
	}
	return jsonResult(buildPage(out.Result, out.Cached, nil, limit, offset))
}

func (h *handlers) basicScan(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	target, err := req.RequireString("target")
	if err != nil {
		return h.toolError("basic_scan", err)
	}
	limit, offset, err := h.paging(req)
	if err != nil {
		return h.toolError("basic_scan", err)
	}
	out, err := h.sc.BasicScan(ctx, target)
	if err != nil {
		return h.toolError("basic_scan", err)
	}
	return jsonResult(buildPage(out.Result, out.Cached, nil, limit, offset))
}

func (h *handlers) getScanResults(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id, err := req.RequireString("scan_id")
	if err != nil {
		return h.toolError("get_scan_results", err)
	}
	limit, offset, err := h.paging(req)
	if err != nil {
		return h.toolError("get_scan_results", err)
	}
	var allowed map[string]bool
	if sev := req.GetString("severity", ""); sev != "" {
		list, err := scanner.NormalizeSeverity(sev)
		if err != nil {
			return h.toolError("get_scan_results", err)
		}
		allowed = map[string]bool{}
		for _, s := range strings.Split(list, ",") {
			allowed[s] = true
		}
	}
	r, ok := h.sc.Get(strings.TrimSpace(id))
	if !ok {
		return h.toolError("get_scan_results", &scanner.InputError{Msg: fmt.Sprintf("no stored scan with id %q; it may have been evicted (cache.max_size). Read %s for recent scans", id, scansURI)})
	}
	return jsonResult(buildPage(r, true, allowed, limit, offset))
}

func (h *handlers) paging(req mcp.CallToolRequest) (limit, offset int, err error) {
	limit = req.GetInt("limit", h.cfg.PageSize)
	offset = req.GetInt("offset", 0)
	if limit < 1 || limit > maxPageSize {
		return 0, 0, &scanner.InputError{Msg: fmt.Sprintf("limit must be between 1 and %d", maxPageSize)}
	}
	if offset < 0 {
		return 0, 0, &scanner.InputError{Msg: "offset must not be negative"}
	}
	return limit, offset, nil
}

// Page is the JSON shape of a scan result page.
type Page struct {
	ScanID        string          `json:"scan_id"`
	Kind          string          `json:"kind"`
	Target        string          `json:"target"`
	ScanTime      string          `json:"scan_time"`
	DurationMS    int64           `json:"duration_ms"`
	Cached        bool            `json:"cached"`
	Partial       bool            `json:"partial"`
	PartialReason string          `json:"partial_reason,omitempty"`
	TotalFindings int             `json:"total_findings"`
	BySeverity    map[string]int  `json:"by_severity"`
	Offset        int             `json:"offset"`
	Returned      int             `json:"returned"`
	NextOffset    *int            `json:"next_offset"`
	Findings      []cache.Finding `json:"findings"`
	Note          string          `json:"note,omitempty"`
}

func buildPage(r cache.ScanResult, cached bool, allowed map[string]bool, limit, offset int) Page {
	findings := r.Findings
	if allowed != nil {
		filtered := make([]cache.Finding, 0, len(findings))
		for _, f := range findings {
			if allowed[f.Severity] {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}
	by := map[string]int{}
	for _, f := range findings {
		by[f.Severity]++
	}
	p := Page{
		ScanID: r.ID, Kind: r.Kind, Target: r.Target, ScanTime: r.ScanTime.UTC().Format(time.RFC3339),
		DurationMS: r.Duration.Milliseconds(), Cached: cached, Partial: r.Partial, PartialReason: r.PartialReason,
		TotalFindings: len(findings), BySeverity: by, Offset: offset, Findings: []cache.Finding{},
	}
	if offset < len(findings) {
		end := min(offset+limit, len(findings))
		p.Findings = findings[offset:end]
		if end < len(findings) {
			next := end
			p.NextOffset = &next
			p.Note = fmt.Sprintf("%d more findings: call get_scan_results with scan_id %q and offset %d", len(findings)-end, r.ID, end)
		}
	}
	p.Returned = len(p.Findings)
	if p.TotalFindings == 0 && !p.Partial {
		p.Note = "no findings: the selected templates did not match this target"
	}
	return p
}

func (h *handlers) listTemplates(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	all, err := h.tm.ListTemplates()
	if err != nil {
		return h.toolError("list_templates", err)
	}
	filter := strings.ToLower(strings.TrimSpace(req.GetString("filter", "")))
	matched := make([]string, 0, len(all))
	for _, t := range all {
		if filter == "" || strings.Contains(strings.ToLower(t), filter) {
			matched = append(matched, t)
		}
	}
	res := map[string]any{"total": len(matched), "templates": matched}
	if len(matched) > maxListTemplates {
		res["templates"] = matched[:maxListTemplates]
		res["note"] = fmt.Sprintf("showing the first %d; pass a filter to narrow the list", maxListTemplates)
	}
	return jsonResult(res)
}

func (h *handlers) getTemplate(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return h.toolError("get_template", err)
	}
	content, err := h.tm.GetTemplate(name)
	if err != nil {
		return h.toolError("get_template", &scanner.InputError{Msg: err.Error()})
	}
	return mcp.NewToolResultText(string(content)), nil
}

func (h *handlers) addTemplate(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return h.toolError("add_template", err)
	}
	content, err := req.RequireString("content")
	if err != nil {
		return h.toolError("add_template", err)
	}
	if err := h.tm.AddTemplate(name, []byte(content)); err != nil {
		return h.toolError("add_template", &scanner.InputError{Msg: err.Error()})
	}
	h.cfg.Logger.Warn("template added by client", "name", name)
	return mcp.NewToolResultText(fmt.Sprintf("Template %q added. It will run on later scans that do not set template_ids.", name)), nil
}

// ScanSummary is one entry of the recent-scans resource.
type ScanSummary struct {
	ScanID        string         `json:"scan_id"`
	URI           string         `json:"uri"`
	Kind          string         `json:"kind"`
	Target        string         `json:"target"`
	ScanTime      string         `json:"scan_time"`
	Partial       bool           `json:"partial"`
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
}

func (h *handlers) recentScansResource(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	recent := h.sc.Recent()
	out := make([]ScanSummary, 0, len(recent))
	for _, r := range recent {
		by := map[string]int{}
		for _, f := range r.Findings {
			by[f.Severity]++
		}
		out = append(out, ScanSummary{
			ScanID: r.ID, URI: scanURIPrefix + r.ID, Kind: r.Kind, Target: r.Target,
			ScanTime: r.ScanTime.UTC().Format(time.RFC3339), Partial: r.Partial,
			TotalFindings: len(r.Findings), BySeverity: by,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ScanTime > out[j].ScanTime })
	b, err := json.Marshal(map[string]any{"scans": out})
	if err != nil {
		return nil, err
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{URI: scansURI, MIMEType: "application/json", Text: string(b)}}, nil
}

func (h *handlers) scanResource(_ context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	uri := req.Params.URI
	id := strings.TrimPrefix(uri, scanURIPrefix)
	if id == uri || id == "" || strings.Contains(id, "/") {
		return nil, fmt.Errorf("invalid scan URI %q", uri)
	}
	r, ok := h.sc.Get(id)
	if !ok {
		return nil, fmt.Errorf("scan %q not found", id)
	}
	b, err := json.Marshal(buildPage(r, true, nil, max(len(r.Findings), 1), 0))
	if err != nil {
		return nil, err
	}
	return []mcp.ResourceContents{mcp.TextResourceContents{URI: uri, MIMEType: "application/json", Text: string(b)}}, nil
}
