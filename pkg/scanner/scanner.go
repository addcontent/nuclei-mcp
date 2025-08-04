package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"nuclei-mcp/pkg/cache"
	"nuclei-mcp/pkg/logging"

	lib "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// ScannerServiceInterface defines the interface for scanner operations
type ScannerServiceInterface interface {
	CreateCacheKey(target string, severity string, protocols string) string
	Scan(target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error)
	ThreadSafeScan(ctx context.Context, target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error)
	BasicScan(target string) (cache.ScanResult, error)
	GetAll() []cache.ScanResult
}

// ScannerService provides nuclei scanning operations
type ScannerService struct {
	cache             cache.ResultCacheInterface
	console           logging.Logger
	Cache             cache.ResultCacheInterface // Exported for testing purposes
	TemplatesDir      string
	BasicTemplateName string
}

// NewScannerService creates a new scanner service
func NewScannerService(cacheImpl cache.ResultCacheInterface, console logging.Logger, templatesDir string, basicTemplateName string) *ScannerService {
	// If cache is nil, create a no-op cache
	if cacheImpl == nil {
		cacheImpl = cache.NewNoopCache()
	}

	if basicTemplateName == "" {
		basicTemplateName = "basic-test.yaml"
	}

	return &ScannerService{
		cache:             cacheImpl,
		Cache:             cacheImpl, // Keep both fields in sync
		console:           console,
		TemplatesDir:      templatesDir,
		BasicTemplateName: basicTemplateName,
	}
}

func (s *ScannerService) CreateCacheKey(target string, severity string, protocols string) string {
	return fmt.Sprintf("%s:%s:%s", target, severity, protocols)
}

// loadTemplates loads templates based on templateIDs and returns the template sources
func (s *ScannerService) loadTemplates(templateIDs []string) (lib.TemplateSources, error) {
	templateSources := lib.TemplateSources{}

	if len(templateIDs) == 0 {
		files, err := os.ReadDir(s.TemplatesDir)
		if err != nil {
			s.console.Log("Failed to read templates directory %s: %v", s.TemplatesDir, err)
			return templateSources, err
		}
		var templatePaths []string
		for _, file := range files {
			if !file.IsDir() && (strings.HasSuffix(file.Name(), ".yaml") || strings.HasSuffix(file.Name(), ".yml")) {
				templatePaths = append(templatePaths, filepath.Join(s.TemplatesDir, file.Name()))
			}
		}
		if len(templatePaths) == 0 {
			s.console.Log("No templates found in directory: %s", s.TemplatesDir)
			return templateSources, fmt.Errorf("no templates found in %s", s.TemplatesDir)
		}
		templateSources.Templates = templatePaths
	} else {
		var fullPathTemplates []string
		for _, tpl := range templateIDs {
			fullPathTemplates = append(fullPathTemplates, filepath.Join(s.TemplatesDir, tpl))
		}
		templateSources.Templates = fullPathTemplates
	}

	return templateSources, nil
}

func (s *ScannerService) Scan(target string, severityFilter string, protocolFilter string, templateIDs []string) (cache.ScanResult, error) {
	cacheKey := s.CreateCacheKey(target, severityFilter, protocolFilter)

	if len(templateIDs) > 0 {
		cacheKey += ":" + strings.Join(templateIDs, ",")
	}

	if result, found := s.cache.Get(cacheKey); found {
		s.console.Log("Returning cached scan result for %s (%d findings)", target, len(result.Findings))
		return result, nil
	}

	s.console.Log("Starting new scan for target: %s", target)

	options := []lib.NucleiSDKOptions{
		lib.DisableUpdateCheck(),
	}

	templateSources, err := s.loadTemplates(templateIDs)
	if err != nil {
		return cache.ScanResult{}, err
	}
	options = append(options, lib.WithTemplatesOrWorkflows(templateSources))

	if severityFilter != "" || protocolFilter != "" {
		filters := lib.TemplateFilters{
			Severity:      severityFilter,
			ProtocolTypes: protocolFilter,
		}
		options = append(options, lib.WithTemplateFilters(filters))
	}

	ne, err := lib.NewNucleiEngine(options...)

	if err != nil {
		s.console.Log("Failed to create nuclei engine: %v", err)
		return cache.ScanResult{}, err
	}
	defer ne.Close()

	if err := ne.LoadAllTemplates(); err != nil {
		s.console.Log("Failed to load templates: %v", err)
		return cache.ScanResult{}, err
	}

	var findings []*output.ResultEvent
	var findingsMutex sync.Mutex

	ne.LoadTargets([]string{target}, false)

	callback := func(event *output.ResultEvent) {
		findingsMutex.Lock()
		defer findingsMutex.Unlock()
		findings = append(findings, event)
		s.console.Log("Found vulnerability: %s (%s) on %s", event.Info.Name, event.Info.SeverityHolder.Severity.String(), event.Host)
	}

	if err := ne.ExecuteWithCallback(callback); err != nil {

		s.console.Log("Scan failed: %v", err)
		return cache.ScanResult{}, err
	}

	result := cache.ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	s.cache.Set(cacheKey, result)

	s.console.Log("Scan completed for %s, found %d vulnerabilities", target, len(findings))

	return result, nil
}

func (s *ScannerService) ThreadSafeScan(ctx context.Context, target string, severity string, protocols string, templateIDs []string) (cache.ScanResult, error) {

	cacheKey := s.CreateCacheKey(target, severity, protocols)
	if len(templateIDs) > 0 {
		cacheKey += ":" + strings.Join(templateIDs, ",")
	}

	if result, found := s.cache.Get(cacheKey); found {
		s.console.Log("Returning cached scan result for %s (%d findings)", target, len(result.Findings))
		return result, nil
	}

	s.console.Log("Starting new thread-safe scan for target: %s", target)

	options := []lib.NucleiSDKOptions{
		lib.DisableUpdateCheck(),
	}

	templateSources, err := s.loadTemplates(templateIDs)
	if err != nil {
		return cache.ScanResult{}, err
	}
	options = append(options, lib.WithTemplatesOrWorkflows(templateSources))

	if severity != "" || protocols != "" {
		filters := lib.TemplateFilters{
			Severity:      severity,
			ProtocolTypes: protocols,
		}
		options = append(options, lib.WithTemplateFilters(filters))
	}

	// Create a new thread-safe nuclei engine.
	ne, err := lib.NewThreadSafeNucleiEngineCtx(ctx, options...)

	if err != nil {
		s.console.Log("Failed to create thread-safe nuclei engine: %v", err)
		return cache.ScanResult{}, err
	}
	defer ne.Close()

	var findings []*output.ResultEvent
	var findingsMutex sync.Mutex

	ne.GlobalResultCallback(func(event *output.ResultEvent) {
		findingsMutex.Lock()
		defer findingsMutex.Unlock()
		findings = append(findings, event)
		s.console.Log("Found vulnerability: %s (%s) on %s", event.Info.Name, event.Info.SeverityHolder.Severity.String(), event.Host)
	})

	// 5. Execute  babyyyy
	if err := ne.ExecuteNucleiWithOptsCtx(ctx, []string{target}, options...); err != nil {

		s.console.Log("Thread-safe scan failed: %v", err)
		return cache.ScanResult{}, err
	}

	result := cache.ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	s.cache.Set(cacheKey, result)

	s.console.Log("Thread-safe scan completed for %s, found %d vulnerabilities", target, len(findings))

	return result, nil
}

func (s *ScannerService) BasicScan(target string) (cache.ScanResult, error) {
	cacheKey := fmt.Sprintf("basic:%s", target)

	if result, found := s.cache.Get(cacheKey); found {
		s.console.Log("Returning cached basic scan result for %s (%d findings)", target, len(result.Findings))
		return result, nil
	}

	s.console.Log("Starting new basic scan for target: %s", target)

	basicTemplatePath := filepath.Join(s.TemplatesDir, s.BasicTemplateName)

	if _, err := os.Stat(basicTemplatePath); os.IsNotExist(err) {
		s.console.Log("Basic test template not found at %s", basicTemplatePath)
		return cache.ScanResult{}, fmt.Errorf("basic test template not found: %s", basicTemplatePath)
	}

	opts := []lib.NucleiSDKOptions{
		lib.WithTemplatesOrWorkflows(lib.TemplateSources{
			Templates: []string{basicTemplatePath},
		}),
		lib.DisableUpdateCheck(),
	}

	ne, err := lib.NewNucleiEngine(opts...)

	if err != nil {
		s.console.Log("Failed to create nuclei engine: %v", err)
		return cache.ScanResult{}, err
	}
	defer ne.Close()

	// Load'em targets
	ne.LoadTargets([]string{target}, true) // Probe for HTTP targets

	var findings []*output.ResultEvent
	var findingsMutex sync.Mutex

	callback := func(event *output.ResultEvent) {
		findingsMutex.Lock()
		defer findingsMutex.Unlock()
		findings = append(findings, event)
		s.console.Log("Found vulnerability: %s (%s) on %s", event.Info.Name, event.Info.SeverityHolder.Severity.String(), event.Host)
	}

	if err := ne.ExecuteWithCallback(callback); err != nil {

		s.console.Log("Basic scan failed: %v", err)
		return cache.ScanResult{}, err
	}

	result := cache.ScanResult{
		Target:   target,
		Findings: findings,
		ScanTime: time.Now(),
	}

	s.cache.Set(cacheKey, result)

	s.console.Log("Basic scan completed for %s, found %d vulnerabilities", target, len(findings))

	return result, nil
}

func (s *ScannerService) GetAll() []cache.ScanResult {
	return s.cache.GetAll()
}
