// Package cache keeps recent scan results in memory.
//
// Every completed scan is stored under a random ID so it can be paged
// through or read back as a resource. When reuse is enabled, an identical
// scan within the expiry window returns the stored result instead of
// scanning again. The store holds at most maxSize results; the oldest go
// first.
package cache

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// Finding is one Nuclei result, trimmed to what a client needs. Raw
// requests and responses are deliberately not kept.
type Finding struct {
	TemplateID       string    `json:"template_id"`
	Name             string    `json:"name"`
	Severity         string    `json:"severity"`
	Type             string    `json:"type,omitempty"`
	Host             string    `json:"host,omitempty"`
	MatchedAt        string    `json:"matched_at,omitempty"`
	MatcherName      string    `json:"matcher_name,omitempty"`
	ExtractorName    string    `json:"extractor_name,omitempty"`
	ExtractedResults []string  `json:"extracted_results,omitempty"`
	Description      string    `json:"description,omitempty"`
	Remediation      string    `json:"remediation,omitempty"`
	Tags             []string  `json:"tags,omitempty"`
	References       []string  `json:"references,omitempty"`
	CVE              []string  `json:"cve,omitempty"`
	CWE              []string  `json:"cwe,omitempty"`
	CVSSScore        float64   `json:"cvss_score,omitempty"`
	CVSSMetrics      string    `json:"cvss_metrics,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
}

// ScanResult is one completed (or timed-out) scan.
type ScanResult struct {
	ID       string        `json:"scan_id"`
	Kind     string        `json:"kind"`
	Target   string        `json:"target"`
	ScanTime time.Time     `json:"scan_time"`
	Duration time.Duration `json:"-"`
	// Partial is set when the scan stopped early (timeout or cancellation).
	Partial       bool      `json:"partial"`
	PartialReason string    `json:"partial_reason,omitempty"`
	Findings      []Finding `json:"findings"`
}

// Store is a bounded, concurrency-safe result store.
type Store struct {
	mu      sync.Mutex
	reuse   bool
	expiry  time.Duration
	maxSize int
	now     func() time.Time

	byID  map[string]ScanResult
	byKey map[string]string // reuse key -> scan ID
	keyOf map[string]string // scan ID -> reuse key
	order []string          // scan IDs, oldest first
}

// New returns a store. With reuse disabled, Lookup always misses but results
// are still kept for paging and resources.
func New(reuse bool, expiry time.Duration, maxSize int) *Store {
	if maxSize < 1 {
		maxSize = 1
	}
	return &Store{
		reuse: reuse, expiry: expiry, maxSize: maxSize, now: time.Now,
		byID: map[string]ScanResult{}, byKey: map[string]string{}, keyOf: map[string]string{},
	}
}

// Lookup returns a reusable result for key if reuse is on and it has not expired.
func (s *Store) Lookup(key string) (ScanResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.reuse {
		return ScanResult{}, false
	}
	id, ok := s.byKey[key]
	if !ok {
		return ScanResult{}, false
	}
	r := s.byID[id]
	if s.now().Sub(r.ScanTime) > s.expiry {
		delete(s.byKey, key)
		delete(s.keyOf, id)
		return ScanResult{}, false
	}
	return r, true
}

// Put stores r, assigning an ID if it has none, and returns the stored copy.
// Partial results are kept for paging but never reused.
func (s *Store) Put(key string, r ScanResult) ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.ID == "" {
		r.ID = newID()
	}
	if _, exists := s.byID[r.ID]; !exists {
		s.order = append(s.order, r.ID)
	}
	s.byID[r.ID] = r
	if key != "" && !r.Partial {
		if old, ok := s.byKey[key]; ok {
			delete(s.keyOf, old)
		}
		s.byKey[key] = r.ID
		s.keyOf[r.ID] = key
	}
	for len(s.order) > s.maxSize {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.byID, oldest)
		if k, ok := s.keyOf[oldest]; ok {
			delete(s.byKey, k)
			delete(s.keyOf, oldest)
		}
	}
	return r
}

// Get returns a stored result by scan ID.
func (s *Store) Get(id string) (ScanResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	return r, ok
}

// Recent returns stored results, newest first.
func (s *Store) Recent() []ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ScanResult, 0, len(s.byID))
	for _, r := range s.byID {
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ScanTime.After(out[j].ScanTime) })
	return out
}

// Len returns the number of stored results.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
