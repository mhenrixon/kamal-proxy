package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/basecamp/kamal-proxy/internal/server"
)

func renderCacheStats(stats server.CacheStats) string {
	var out bytes.Buffer
	printCacheStats(&out, stats)
	return out.String()
}

func TestCacheStatsCommand_RendersTheInProcessStore(t *testing.T) {
	output := renderCacheStats(server.CacheStats{
		Store: server.CacheStoreMemory,
		Local: server.CacheLocalStats{
			Counted: true, Entries: 12481,
			Bytes: 192 * 1024 * 1024, MaxBytes: 256 * 1024 * 1024,
			EvictedFresh: 1918, EvictedStale: 3204, Oversized: 12,
		},
	})

	assert.Contains(t, output, "memory (per node)")
	assert.Contains(t, output, "12,481", "a six-figure count should be readable at a glance")
	assert.Contains(t, output, "192.0 MB of 256.0 MB (75%)")
	assert.Contains(t, output, "1,918 fresh, 3,204 stale")
	assert.Contains(t, output, "Oversized")
	assert.NotContains(t, output, "Cache server", "there is no server behind an in-process store")
}

// A shared store must not let its instance-wide numbers read as this cache's.
func TestCacheStatsCommand_SeparatesServerNumbersFromThisCaches(t *testing.T) {
	output := renderCacheStats(server.CacheStats{
		Store:  server.CacheStoreRedis,
		Shared: true,
		Local:  server.CacheLocalStats{Counted: false},
		Server: &server.CacheServerStats{
			Keys: 48201, UsedBytes: 2 * 1024 * 1024 * 1024,
			MaxBytes: 4 * 1024 * 1024 * 1024, Policy: "allkeys-lru",
		},
	})

	assert.Contains(t, output, "redis (shared)")
	assert.Contains(t, output, "not counted -- pass --count")
	assert.Contains(t, output, "Cache server -- shared with anything else using it")
	assert.Contains(t, output, "every key in the database, not only this proxy's")
	assert.Contains(t, output, "2.0 GB of 4.0 GB, policy allkeys-lru")
}

// The whole point of Unavailable: a number the server withheld must never print
// as a zero someone could size against.
func TestCacheStatsCommand_PrintsWithheldFieldsAsUnknown(t *testing.T) {
	output := renderCacheStats(server.CacheStats{
		Store:  server.CacheStoreRedis,
		Shared: true,
		Server: &server.CacheServerStats{
			Keys:        48201,
			Unavailable: []string{"used_bytes", "max_bytes", "eviction_policy"},
		},
	})

	assert.Contains(t, output, "Used memory  unknown of unknown, policy unknown")
	assert.Contains(t, output, "withheld by the server")
	assert.NotContains(t, output, "0 B of 0 B", "a withheld number must not read as zero")
}

// No limit is a different statement from an unknown limit.
func TestCacheStatsCommand_DistinguishesNoLimitFromUnknown(t *testing.T) {
	output := renderCacheStats(server.CacheStats{
		Store:  server.CacheStoreRedis,
		Shared: true,
		Server: &server.CacheServerStats{Keys: 10, UsedBytes: 1024, MaxBytes: 0, Policy: "noeviction"},
	})

	assert.Contains(t, output, "1.0 KB of no limit, policy noeviction")
}

func TestCacheStatsCommand_RendersTheServiceBreakdown(t *testing.T) {
	output := renderCacheStats(server.CacheStats{
		Store: server.CacheStoreMemory,
		Local: server.CacheLocalStats{
			Counted: true, Entries: 3,
			Services: []server.CacheServiceStats{
				{Service: "shop", Entries: 9201, Bytes: 171 * 1024 * 1024},
				{Service: "blog", Entries: 3280, Bytes: 12 * 1024 * 1024},
			},
		},
	})

	assert.Contains(t, output, "Service")
	assert.Contains(t, output, "shop")
	assert.Contains(t, output, "9,201")
	assert.Contains(t, output, "171.0 MB")
	assert.Contains(t, output, "blog")
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{bytes: 0, expected: "0 B"},
		{bytes: 512, expected: "512 B"},
		{bytes: 1024, expected: "1.0 KB"},
		{bytes: 1536, expected: "1.5 KB"},
		{bytes: 1024 * 1024, expected: "1.0 MB"},
		{bytes: 256 * 1024 * 1024, expected: "256.0 MB"},
		{bytes: 2 * 1024 * 1024 * 1024, expected: "2.0 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatBytes(tt.bytes))
		})
	}
}

func TestFormatCount(t *testing.T) {
	tests := []struct {
		count    int64
		expected string
	}{
		{count: 0, expected: "0"},
		{count: 999, expected: "999"},
		{count: 1000, expected: "1,000"},
		{count: 12481, expected: "12,481"},
		{count: 1234567, expected: "1,234,567"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatCount(tt.count))
		})
	}
}
