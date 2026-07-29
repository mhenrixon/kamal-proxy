package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHeaderRules_Parsing(t *testing.T) {
	tests := []struct {
		name          string
		flags         HeaderRuleFlags
		expected      HeaderRules
		expectedError string
	}{
		{
			name:     "no flags leaves the rules empty",
			flags:    HeaderRuleFlags{},
			expected: HeaderRules{},
		},
		{
			name:  "a set rule splits on the first colon and trims the value",
			flags: HeaderRuleFlags{Set: []string{"X-Env:  production "}},
			expected: HeaderRules{
				Set: []HeaderRule{{Name: "X-Env", Value: "production"}},
			},
		},
		{
			name:  "names are canonicalized so the state file and the wire agree",
			flags: HeaderRuleFlags{Set: []string{"x-ENV: production"}, Remove: []string{"x-powered-BY"}},
			expected: HeaderRules{
				Remove: []string{"X-Powered-By"},
				Set:    []HeaderRule{{Name: "X-Env", Value: "production"}},
			},
		},
		{
			name:  "values keep their own colons",
			flags: HeaderRuleFlags{Set: []string{"Content-Security-Policy: default-src 'self'; img-src https://cdn.example.com:8443"}},
			expected: HeaderRules{
				Set: []HeaderRule{{Name: "Content-Security-Policy", Value: "default-src 'self'; img-src https://cdn.example.com:8443"}},
			},
		},
		{
			name:  "values may contain commas, which the flag must not split",
			flags: HeaderRuleFlags{Add: []string{"Access-Control-Allow-Methods: GET, POST, OPTIONS"}},
			expected: HeaderRules{
				Add: []HeaderRule{{Name: "Access-Control-Allow-Methods", Value: "GET, POST, OPTIONS"}},
			},
		},
		{
			name:  "an empty value is allowed, as an empty header is still a header",
			flags: HeaderRuleFlags{Set: []string{"X-Env:"}},
			expected: HeaderRules{
				Set: []HeaderRule{{Name: "X-Env", Value: ""}},
			},
		},
		{
			name:  "every verb accumulates in flag order",
			flags: HeaderRuleFlags{Remove: []string{"Server", "X-Powered-By"}, Set: []string{"X-A: 1"}, Add: []string{"Vary: Accept", "Vary: Origin"}},
			expected: HeaderRules{
				Remove: []string{"Server", "X-Powered-By"},
				Set:    []HeaderRule{{Name: "X-A", Value: "1"}},
				Add:    []HeaderRule{{Name: "Vary", Value: "Accept"}, {Name: "Vary", Value: "Origin"}},
			},
		},
		{
			name:          "a rule without a colon is rejected",
			flags:         HeaderRuleFlags{Set: []string{"X-Env production"}},
			expectedError: `set-response-header must be given as "<name>: <value>"`,
		},
		{
			name:          "a rule with no name is rejected",
			flags:         HeaderRuleFlags{Add: []string{": production"}},
			expectedError: "add-response-header has an invalid header name",
		},
		{
			name:          "a name that is not a token is rejected",
			flags:         HeaderRuleFlags{Set: []string{"X Env: production"}},
			expectedError: "set-response-header has an invalid header name",
		},
		{
			name:          "a removal naming something that is not a token is rejected",
			flags:         HeaderRuleFlags{Remove: []string{"X Env"}},
			expectedError: "remove-response-header has an invalid header name",
		},
		{
			name:          "a value carrying a newline is rejected, so a rule cannot inject a header",
			flags:         HeaderRuleFlags{Set: []string{"X-Env: production\r\nX-Admin: true"}},
			expectedError: "set-response-header has an invalid value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := NewResponseHeaderRules(tt.flags)

			if tt.expectedError != "" {
				require.ErrorIs(t, err, ErrTargetOptionsInvalid)
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, rules)
		})
	}
}

func TestNewRequestHeaderRules_RejectsHost(t *testing.T) {
	tests := []struct {
		name  string
		flags HeaderRuleFlags
	}{
		{name: "set", flags: HeaderRuleFlags{Set: []string{"Host: elsewhere.example.com"}}},
		{name: "add", flags: HeaderRuleFlags{Add: []string{"host: elsewhere.example.com"}}},
		{name: "remove", flags: HeaderRuleFlags{Remove: []string{"HOST"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRequestHeaderRules(tt.flags)

			require.ErrorIs(t, err, ErrTargetOptionsInvalid)
			require.ErrorContains(t, err, "cannot rewrite the Host header")
		})
	}

	// The restriction is about how Go carries the request host, so it does not
	// apply to a response.
	_, err := NewResponseHeaderRules(HeaderRuleFlags{Set: []string{"Host: elsewhere.example.com"}})
	require.NoError(t, err)
}

func TestHeaderRules_Apply(t *testing.T) {
	tests := []struct {
		name     string
		initial  http.Header
		rules    HeaderRules
		expected http.Header
	}{
		{
			name:     "empty rules leave the headers untouched",
			initial:  http.Header{"X-Env": []string{"staging"}},
			rules:    HeaderRules{},
			expected: http.Header{"X-Env": []string{"staging"}},
		},
		{
			name:     "set replaces every existing value",
			initial:  http.Header{"X-Env": []string{"staging", "canary"}},
			rules:    HeaderRules{Set: []HeaderRule{{Name: "X-Env", Value: "production"}}},
			expected: http.Header{"X-Env": []string{"production"}},
		},
		{
			name:     "set adds a header that was not there",
			initial:  http.Header{},
			rules:    HeaderRules{Set: []HeaderRule{{Name: "Strict-Transport-Security", Value: "max-age=63072000"}}},
			expected: http.Header{"Strict-Transport-Security": []string{"max-age=63072000"}},
		},
		{
			name:     "add appends alongside what is already there",
			initial:  http.Header{"Vary": []string{"Accept"}},
			rules:    HeaderRules{Add: []HeaderRule{{Name: "Vary", Value: "Origin"}}},
			expected: http.Header{"Vary": []string{"Accept", "Origin"}},
		},
		{
			name:     "remove drops every value",
			initial:  http.Header{"Server": []string{"gunicorn"}, "X-Env": []string{"staging"}},
			rules:    HeaderRules{Remove: []string{"Server"}},
			expected: http.Header{"X-Env": []string{"staging"}},
		},
		{
			name:     "removing something absent is not an error",
			initial:  http.Header{},
			rules:    HeaderRules{Remove: []string{"Server"}},
			expected: http.Header{},
		},
		{
			name:    "remove runs first, so a name that is both removed and set keeps the set value",
			initial: http.Header{"X-Env": []string{"staging"}},
			rules: HeaderRules{
				Remove: []string{"X-Env"},
				Set:    []HeaderRule{{Name: "X-Env", Value: "production"}},
			},
			expected: http.Header{"X-Env": []string{"production"}},
		},
		{
			name:    "set runs before add, so both land on the same name",
			initial: http.Header{"Vary": []string{"Cookie"}},
			rules: HeaderRules{
				Set: []HeaderRule{{Name: "Vary", Value: "Accept"}},
				Add: []HeaderRule{{Name: "Vary", Value: "Origin"}},
			},
			expected: http.Header{"Vary": []string{"Accept", "Origin"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.rules.apply(tt.initial)

			assert.Equal(t, tt.expected, tt.initial)
		})
	}
}

func TestHeaderRules_RoundTripThroughTargetOptions(t *testing.T) {
	t.Run("configured rules survive a save and restore", func(t *testing.T) {
		options := TargetOptions{
			RequestHeaderRules: HeaderRules{
				Remove: []string{"X-Secret"},
				Set:    []HeaderRule{{Name: "X-Env", Value: "production"}},
			},
			ResponseHeaderRules: HeaderRules{
				Add: []HeaderRule{{Name: "Vary", Value: "Origin"}},
			},
		}

		encoded, err := json.Marshal(options)
		require.NoError(t, err)

		var restored TargetOptions
		require.NoError(t, json.Unmarshal(encoded, &restored))

		assert.Equal(t, options.RequestHeaderRules, restored.RequestHeaderRules)
		assert.Equal(t, options.ResponseHeaderRules, restored.ResponseHeaderRules)
	})

	t.Run("state written before header rules existed restores without any", func(t *testing.T) {
		var restored TargetOptions
		require.NoError(t, json.Unmarshal([]byte(`{"response_timeout": 1000000000}`), &restored))

		assert.Equal(t, HeaderRules{}, restored.RequestHeaderRules)
		assert.Equal(t, HeaderRules{}, restored.ResponseHeaderRules)
	})

	t.Run("unconfigured rules stay out of the state file", func(t *testing.T) {
		encoded, err := json.Marshal(TargetOptions{})
		require.NoError(t, err)

		assert.NotContains(t, string(encoded), "request_header_rules")
		assert.NotContains(t, string(encoded), "response_header_rules")
	})
}

func TestTarget_AppliesRequestHeaderRules(t *testing.T) {
	options := defaultTargetOptions
	options.RequestHeaderRules = HeaderRules{
		Remove: []string{"X-Secret"},
		Set:    []HeaderRule{{Name: "X-Env", Value: "production"}, {Name: "X-Forwarded-Proto", Value: "https"}},
		Add:    []HeaderRule{{Name: "X-Trace", Value: "proxy"}},
	}

	var received http.Header
	target := testTargetWithOptions(t, options, func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Secret", "shh")
	req.Header.Set("X-Env", "staging")
	req.Header.Set("X-Trace", "client")

	testServeRequestWithTarget(t, target, httptest.NewRecorder(), req)

	require.NotNil(t, received)
	assert.Empty(t, received.Values("X-Secret"))
	assert.Equal(t, []string{"production"}, received.Values("X-Env"))
	assert.Equal(t, []string{"client", "proxy"}, received.Values("X-Trace"))

	// The rules run after SetXForwarded, so an operator can override what the
	// proxy would otherwise have decided.
	assert.Equal(t, "https", received.Get("X-Forwarded-Proto"))
}

func TestTarget_AppliesResponseHeaderRules(t *testing.T) {
	backend := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "gunicorn")
		w.Header().Set("Vary", "Accept")
		w.Write([]byte("ok"))
	}

	t.Run("configured rules rewrite what the client sees", func(t *testing.T) {
		options := defaultTargetOptions
		options.ResponseHeaderRules = HeaderRules{
			Remove: []string{"Server"},
			Set:    []HeaderRule{{Name: "Strict-Transport-Security", Value: "max-age=63072000; includeSubDomains"}},
			Add:    []HeaderRule{{Name: "Vary", Value: "Origin"}},
		}

		target := testTargetWithOptions(t, options, backend)

		w := httptest.NewRecorder()
		testServeRequestWithTarget(t, target, w, httptest.NewRequest(http.MethodGet, "/", nil))

		result := w.Result()
		assert.Equal(t, http.StatusOK, result.StatusCode)
		assert.Empty(t, result.Header.Values("Server"))
		assert.Equal(t, "max-age=63072000; includeSubDomains", result.Header.Get("Strict-Transport-Security"))
		assert.Equal(t, []string{"Accept", "Origin"}, result.Header.Values("Vary"))
	})

	t.Run("without rules the target's headers pass through untouched", func(t *testing.T) {
		target := testTargetWithOptions(t, defaultTargetOptions, backend)

		w := httptest.NewRecorder()
		testServeRequestWithTarget(t, target, w, httptest.NewRequest(http.MethodGet, "/", nil))

		result := w.Result()
		assert.Equal(t, "gunicorn", result.Header.Get("Server"))
		assert.Equal(t, []string{"Accept"}, result.Header.Values("Vary"))
		assert.Empty(t, result.Header.Values("Strict-Transport-Security"))
	})
}
