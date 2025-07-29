package tests

import (
	"log"
	"os"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/stretchr/testify/assert"
	"nuclei-mcp/pkg/cache"
)

func TestNewResultCache(t *testing.T) {
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	c := cache.NewResultCache(5*time.Minute, logger)
	assert.NotNil(t, c)
}

func TestResultCache_SetAndGet(t *testing.T) {
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	c := cache.NewResultCache(5*time.Minute, logger)

	result := cache.ScanResult{
		Target:   "example.com",
		ScanTime: time.Now(),
		Findings: []*output.ResultEvent{},
	}
	c.Set("example.com", result)

	retrievedResult, found := c.Get("example.com")
	assert.True(t, found)
	assert.Equal(t, result, retrievedResult)

	// Test getting a non-existent key
	_, found = c.Get("nonexistent.com")
	assert.False(t, found)
}

func TestResultCache_Expiration(t *testing.T) {
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	// Create a cache with a very short expiry
	c := cache.NewResultCache(1*time.Millisecond, logger)

	result := cache.ScanResult{
		Target:   "expired.com",
		ScanTime: time.Now(),
		Findings: []*output.ResultEvent{},
	}
	c.Set("expired.com", result)

	// Wait for the cache entry to expire
	time.Sleep(2 * time.Millisecond)

	_, found := c.Get("expired.com")
	assert.False(t, found, "Expected cache entry to be expired")
}

func TestResultCache_GetAll(t *testing.T) {
	logger := log.New(os.Stdout, "test: ", log.LstdFlags)
	c := cache.NewResultCache(5*time.Minute, logger)

	result1 := cache.ScanResult{
		Target:   "host1.com",
		ScanTime: time.Now(),
		Findings: []*output.ResultEvent{},
	}
	result2 := cache.ScanResult{
		Target:   "host2.com",
		ScanTime: time.Now(),
		Findings: []*output.ResultEvent{},
	}

	c.Set("host1.com", result1)
	c.Set("host2.com", result2)

	allResults := c.GetAll()
	assert.Len(t, allResults, 2)

	// Check if both results are present (order is not guaranteed for map iteration)
	found1 := false
	found2 := false
	for _, r := range allResults {
		if r.Target == "host1.com" {
			found1 = true
		}
		if r.Target == "host2.com" {
			found2 = true
		}
	}
	assert.True(t, found1)
	assert.True(t, found2)
}