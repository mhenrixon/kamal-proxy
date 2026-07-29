package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheOptions_Validate(t *testing.T) {
	tests := []struct {
		name          string
		options       CacheOptions
		expectedError string
	}{
		{
			name:    "disabled and empty",
			options: CacheOptions{},
		},
		{
			name:    "enabled with defaults",
			options: CacheOptions{Enabled: true},
		},
		{
			name:    "enabled with every knob",
			options: CacheOptions{Enabled: true, MaxBodySize: 1024, MaxTTL: time.Minute, VaryHeaders: []string{"Accept-Language"}, VaryCookies: []string{"locale"}, AllowSetCookie: true},
		},
		{
			name:          "max body size requires cache",
			options:       CacheOptions{MaxBodySize: 1024},
			expectedError: "cache-max-body requires cache",
		},
		{
			name:          "max ttl requires cache",
			options:       CacheOptions{MaxTTL: time.Minute},
			expectedError: "cache-max-ttl requires cache",
		},
		{
			name:          "vary header requires cache",
			options:       CacheOptions{VaryHeaders: []string{"Accept-Language"}},
			expectedError: "cache-vary-header requires cache",
		},
		{
			name:          "vary cookie requires cache",
			options:       CacheOptions{VaryCookies: []string{"locale"}},
			expectedError: "cache-vary-cookie requires cache",
		},
		{
			name:          "allow set cookie requires cache",
			options:       CacheOptions{AllowSetCookie: true},
			expectedError: "cache-allow-set-cookie requires cache",
		},
		{
			name:          "negative body size",
			options:       CacheOptions{Enabled: true, MaxBodySize: -1},
			expectedError: "cache-max-body cannot be negative",
		},
		{
			name:          "negative ttl",
			options:       CacheOptions{Enabled: true, MaxTTL: -time.Second},
			expectedError: "cache-max-ttl cannot be negative",
		},
		{
			name:          "invalid header name",
			options:       CacheOptions{Enabled: true, VaryHeaders: []string{"Accept Language"}},
			expectedError: "cache-vary-header must be a header name",
		},
		{
			name:          "invalid cookie name",
			options:       CacheOptions{Enabled: true, VaryCookies: []string{"loc ale"}},
			expectedError: "cache-vary-cookie must be a cookie name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.options.Validate()

			if tt.expectedError == "" {
				assert.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, ErrServiceOptionsInvalid)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestCacheOptions_Normalize(t *testing.T) {
	options := CacheOptions{
		Enabled:     true,
		VaryHeaders: []string{"  Accept-Language ", "accept-language", "", "X-Tenant"},
		VaryCookies: []string{" locale ", "locale", ""},
	}
	options.Normalize()

	assert.Equal(t, []string{"accept-language", "x-tenant"}, options.VaryHeaders)
	assert.Equal(t, []string{"locale"}, options.VaryCookies)
}

// A field already in the primary key must not also be keyed per variant: that
// would cost a second lookup for a dimension the first one already carried.
func TestCacheOptions_CoversVaryField(t *testing.T) {
	assert.False(t, CacheOptions{Enabled: true}.coversVaryField(acceptEncodingHeader))

	options := CacheOptions{Enabled: true, VaryHeaders: []string{"Accept-Language"}}
	options.Normalize()
	assert.True(t, options.coversVaryField("accept-language"))
	assert.False(t, options.coversVaryField(acceptEncodingHeader))

	options = CacheOptions{Enabled: true, VaryHeaders: []string{"Accept-Encoding"}}
	options.Normalize()
	assert.True(t, options.coversVaryField(acceptEncodingHeader))
}

// A negative cap is the escape hatch back to the older behaviour, where a
// response varying on anything undeclared was refused rather than keyed.
func TestCacheOptions_AutomaticVary(t *testing.T) {
	assert.True(t, CacheOptions{Enabled: true}.automaticVary())
	assert.True(t, CacheOptions{Enabled: true, MaxVariants: 4}.automaticVary())
	assert.False(t, CacheOptions{Enabled: true, MaxVariants: -1}.automaticVary())

	assert.Equal(t, DefaultCacheMaxVariants, CacheOptions{Enabled: true}.maxVariants())
	assert.Equal(t, 4, CacheOptions{Enabled: true, MaxVariants: 4}.maxVariants())
}

func TestCacheOptions_Defaults(t *testing.T) {
	assert.Equal(t, DefaultCacheMaxBodySize, CacheOptions{Enabled: true}.maxBodySize())
	assert.Equal(t, int64(2048), CacheOptions{Enabled: true, MaxBodySize: 2048}.maxBodySize())
}

// A state file written before this option existed has no "cache" key at all,
// and must restore with the cache off rather than tripping over a zero value.
func TestCacheOptions_RoundTripsThroughServiceOptions(t *testing.T) {
	var restored ServiceOptions
	require.NoError(t, json.Unmarshal([]byte(`{"hosts":["example.com"]}`), &restored))
	assert.False(t, restored.Cache.Enabled)

	options := ServiceOptions{Cache: CacheOptions{Enabled: true, MaxTTL: time.Minute, VaryCookies: []string{"locale"}}}
	encoded, err := json.Marshal(options)
	require.NoError(t, err)

	require.NoError(t, json.Unmarshal(encoded, &restored))
	assert.Equal(t, options.Cache, restored.Cache)
}
