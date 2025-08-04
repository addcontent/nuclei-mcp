package cache

import (
	"log"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// ScanResult represents the result of a nuclei scan
type ScanResult struct {
	Target   string                `json:"target"`
	ScanTime time.Time             `json:"scan_time"`
	Findings []*output.ResultEvent `json:"findings"`
}

// ResultCacheInterface is an interface that defines the cache operations
type ResultCacheInterface interface {
	Get(key string) (ScanResult, bool)
	Set(key string, result ScanResult)
	GetAll() []ScanResult
}

// ResultCache caches scan results
type ResultCache struct {
	cache  map[string]ScanResult
	expiry time.Duration
	lock   sync.RWMutex
	logger *log.Logger
}

// NoopCache is a cache that does nothing.
type NoopCache struct{}

// Ensure ResultCache implements ResultCacheInterface
var _ ResultCacheInterface = (*ResultCache)(nil)

// Ensure NoopCache implements ResultCacheInterface
var _ ResultCacheInterface = (*NoopCache)(nil)

// NewResultCache creates a new result cache
func NewResultCache(expiry time.Duration, logger *log.Logger) *ResultCache {
	return &ResultCache{
		cache:  make(map[string]ScanResult),
		expiry: expiry,
		logger: logger,
	}
}

// Get retrieves a result from the cache
func (c *ResultCache) Get(key string) (ScanResult, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	result, found := c.cache[key]
	if !found {
		return ScanResult{}, false
	}

	// Check if result has expired
	if time.Since(result.ScanTime) > c.expiry {
		c.logger.Printf("Cache entry expired and removed: %s", key)
		delete(c.cache, key)
		return ScanResult{}, false
	}

	c.logger.Printf("Cache hit: %s", key)
	return result, true
}

// Set stores a result in the cache
func (c *ResultCache) Set(key string, result ScanResult) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.cache[key] = result
	c.logger.Printf("Cache entry set: %s", key)
}

// GetAll returns a copy of all non-expired items in the cache.
func (c *ResultCache) GetAll() []ScanResult {
	c.lock.Lock()
	defer c.lock.Unlock()

	results := make([]ScanResult, 0, len(c.cache))
	expiredKeys := make([]string, 0)

	for key, result := range c.cache {
		if time.Since(result.ScanTime) > c.expiry {
			expiredKeys = append(expiredKeys, key)
			continue
		}
		results = append(results, result)
	}

	// Clean up expired entries
	for _, key := range expiredKeys {
		c.logger.Printf("Removing expired cache entry: %s", key)
		delete(c.cache, key)
	}

	return results
}

// NewNoopCache creates a new no-op cache.
func NewNoopCache() *NoopCache {
	return &NoopCache{}
}

// Get always returns nothing for the no-op cache.
func (c *NoopCache) Get(key string) (ScanResult, bool) {
	return ScanResult{}, false
}

// Set does nothing for the no-op cache.
func (c *NoopCache) Set(key string, result ScanResult) {}

// GetAll returns an empty slice for the no-op cache.
func (c *NoopCache) GetAll() []ScanResult {
	return nil
}
