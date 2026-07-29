package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedirectRules_Parsing(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		expected      PathRule
		expectedError string
	}{
		{
			name:     "exact path",
			value:    "/old=/new",
			expected: PathRule{Pattern: "/old", Replacement: "/new"},
		},
		{
			name:     "capture group",
			value:    "/blog/(.*)=/news/$1",
			expected: PathRule{Pattern: "/blog/(.*)", Replacement: "/news/$1"},
		},
		{
			name:     "absolute replacement",
			value:    "/old=https://other.example.com/new",
			expected: PathRule{Pattern: "/old", Replacement: "https://other.example.com/new"},
		},
		{
			name:     "explicit status",
			value:    "/old=/new;status=302",
			expected: PathRule{Pattern: "/old", Replacement: "/new", Status: http.StatusFound},
		},
		{
			name:     "query in replacement is kept",
			value:    "/old=/new?ref=old;status=307",
			expected: PathRule{Pattern: "/old", Replacement: "/new?ref=old", Status: http.StatusTemporaryRedirect},
		},
		{
			name:     "semicolon that is not a status stays in the replacement",
			value:    "/old=/new;v=2",
			expected: PathRule{Pattern: "/old", Replacement: "/new;v=2"},
		},
		{
			name:          "missing separator",
			value:         "/old",
			expectedError: `redirect must be given as "<pattern>=<replacement>"`,
		},
		{
			name:          "empty pattern",
			value:         "=/new",
			expectedError: "redirect needs a pattern",
		},
		{
			name:          "empty replacement",
			value:         "/old=",
			expectedError: "redirect needs a replacement",
		},
		{
			name:          "invalid regular expression",
			value:         "/old(=/new",
			expectedError: "redirect has an invalid pattern",
		},
		{
			name:          "relative replacement",
			value:         "/old=new",
			expectedError: "redirect replacement must be an absolute path or a full URL",
		},
		{
			name:          "unsupported scheme",
			value:         "/old=ftp://example.com/new",
			expectedError: "redirect replacement must be an absolute path or a full URL",
		},
		{
			name:          "unsupported status",
			value:         "/old=/new;status=404",
			expectedError: "redirect status must be one of 301, 302, 303, 307, 308",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := NewRedirectRules([]string{tt.value})

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				return
			}

			require.NoError(t, err)
			require.Len(t, rules, 1)
			assert.Equal(t, tt.expected, rules[0])
		})
	}
}

func TestRewriteRules_Parsing(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		expected      PathRule
		expectedError string
	}{
		{
			name:     "spa fallback",
			value:    "/[^.]*=/index.html",
			expected: PathRule{Pattern: "/[^.]*", Replacement: "/index.html"},
		},
		{
			name:          "absolute replacement",
			value:         "/old=https://other.example.com/new",
			expectedError: "rewrite replacement must be an absolute path",
		},
		{
			name:          "status suffix",
			value:         "/old=/new;status=302",
			expectedError: "rewrite cannot set a status",
		},
		{
			name:          "invalid regular expression",
			value:         "/old(=/new",
			expectedError: "rewrite has an invalid pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := NewRewriteRules([]string{tt.value})

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				return
			}

			require.NoError(t, err)
			require.Len(t, rules, 1)
			assert.Equal(t, tt.expected, rules[0])
		})
	}
}

func TestPathRuleSet_Matching(t *testing.T) {
	tests := []struct {
		name        string
		rules       []string
		path        string
		rawQuery    string
		expected    string
		expectMatch bool
	}{
		{
			name:        "exact match",
			rules:       []string{"/old=/new"},
			path:        "/old",
			expected:    "/new",
			expectMatch: true,
		},
		{
			name:        "patterns are anchored to the whole path",
			rules:       []string{"/old=/new"},
			path:        "/old/deeper",
			expectMatch: false,
		},
		{
			name:        "capture group expansion",
			rules:       []string{"/blog/(.*)=/news/$1"},
			path:        "/blog/hello-world",
			expected:    "/news/hello-world",
			expectMatch: true,
		},
		{
			name:        "original query is preserved",
			rules:       []string{"/old=/new"},
			path:        "/old",
			rawQuery:    "page=2",
			expected:    "/new?page=2",
			expectMatch: true,
		},
		{
			name:        "replacement query replaces the original",
			rules:       []string{"/old=/new?ref=old"},
			path:        "/old",
			rawQuery:    "page=2",
			expected:    "/new?ref=old",
			expectMatch: true,
		},
		{
			name:        "first matching rule wins",
			rules:       []string{"/a=/first", "/a=/second"},
			path:        "/a",
			expected:    "/first",
			expectMatch: true,
		},
		{
			name:        "later rule matches when the first does not",
			rules:       []string{"/a=/first", "/b=/second"},
			path:        "/b",
			expected:    "/second",
			expectMatch: true,
		},
		{
			name:        "no rule matches",
			rules:       []string{"/a=/first"},
			path:        "/z",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := NewRedirectRules(tt.rules)
			require.NoError(t, err)

			ruleSet, err := newPathRuleSet(rules, redirectPathRuleKind)
			require.NoError(t, err)

			result, ok := ruleSet.match(tt.path, tt.rawQuery)

			assert.Equal(t, tt.expectMatch, ok)
			if tt.expectMatch {
				assert.Equal(t, tt.expected, result.target.String())
			}
		})
	}
}

func TestPathRuleSet_EmptyRulesNeverMatch(t *testing.T) {
	ruleSet, err := newPathRuleSet(nil, redirectPathRuleKind)
	require.NoError(t, err)
	require.Nil(t, ruleSet)

	_, ok := ruleSet.match("/anything", "")
	assert.False(t, ok)
}

func TestRedirectRules_ServiceOptionValidation(t *testing.T) {
	options := defaultServiceOptions
	options.Redirects = []PathRule{{Pattern: "/old(", Replacement: "/new"}}
	assert.ErrorIs(t, options.Validate(), ErrServiceOptionsInvalid)

	options = defaultServiceOptions
	options.Rewrites = []PathRule{{Pattern: "/old", Replacement: "https://example.com/new"}}
	assert.ErrorIs(t, options.Validate(), ErrServiceOptionsInvalid)

	options = defaultServiceOptions
	options.Redirects = []PathRule{{Pattern: "/old", Replacement: "/new", Status: http.StatusFound}}
	options.Rewrites = []PathRule{{Pattern: "/[^.]*", Replacement: "/index.html"}}
	assert.NoError(t, options.Validate())
}

func TestRedirectRules_RedirectsMatchingRequests(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "target", http.StatusOK)

	options := defaultServiceOptions
	options.Hosts = []string{"example.com"}
	options.Redirects = mustRedirectRules(t, "/old=/new", "/blog/(.*)=/news/$1", "/gone=https://other.example.com/;status=302")

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	tests := []struct {
		name             string
		url              string
		expectedStatus   int
		expectedLocation string
	}{
		{
			name:             "exact path",
			url:              "http://example.com/old",
			expectedStatus:   http.StatusMovedPermanently,
			expectedLocation: "http://example.com/new",
		},
		{
			name:             "capture group with the query preserved",
			url:              "http://example.com/blog/hello?page=2",
			expectedStatus:   http.StatusMovedPermanently,
			expectedLocation: "http://example.com/news/hello?page=2",
		},
		{
			name:             "absolute replacement with an explicit status",
			url:              "http://example.com/gone",
			expectedStatus:   http.StatusFound,
			expectedLocation: "https://other.example.com/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sendRedirectRequest(router, httptest.NewRequest(http.MethodGet, tt.url, nil))

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			assert.Equal(t, tt.expectedLocation, resp.Header.Get("Location"))
		})
	}
}

func TestRedirectRules_UnmatchedRequestsReachTheTarget(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "target", http.StatusOK)

	options := defaultServiceOptions
	options.Hosts = []string{"example.com"}
	options.Redirects = mustRedirectRules(t, "/old=/new")

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	statusCode, body := sendGETRequest(router, "http://example.com/somewhere-else")

	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "target", body)
}

func TestRedirectRules_CombineWithTheCanonicalHostRedirect(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "target", http.StatusOK)

	options := defaultServiceOptions
	options.Hosts = []string{"example.com", "www.example.com"}
	options.CanonicalHost = "example.com"
	options.TLSEnabled = true
	options.TLSRedirect = true
	options.Redirects = mustRedirectRules(t, "/old=/new")

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	// A single hop, rather than one redirect for the path and another for the
	// scheme and host.
	resp := sendRedirectRequest(router, httptest.NewRequest(http.MethodGet, "http://www.example.com/old", nil))

	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
	assert.Equal(t, "https://example.com/new", resp.Header.Get("Location"))
}

func TestRedirectRules_SelfMatchingRuleDoesNotLoop(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "target", http.StatusOK)

	options := defaultServiceOptions
	options.Hosts = []string{"example.com"}
	options.Redirects = mustRedirectRules(t, "/(.*)=/$1")

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	statusCode, body := sendGETRequest(router, "http://example.com/anywhere")

	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "target", body)
}

func TestRedirectRules_CapturedPathCannotEscapeTheHost(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "target", http.StatusOK)

	options := defaultServiceOptions
	options.Hosts = []string{"example.com"}
	options.Redirects = mustRedirectRules(t, "/go/(.*)=/$1")

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	resp := sendRedirectRequest(router, httptest.NewRequest(http.MethodGet, "http://example.com/go//evil.example.com", nil))

	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
	assert.Equal(t, "http://example.com//evil.example.com", resp.Header.Get("Location"),
		"a captured path must stay on this host rather than becoming a scheme-relative URL")
}

func TestRewriteRules_ChangeThePathTheTargetSees(t *testing.T) {
	router := testRouter(t)
	receivedPath := make(chan string, 1)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		recordProxiedPath(receivedPath, r)
		w.Write([]byte("app"))
	})

	options := defaultServiceOptions
	options.Hosts = []string{"example.com"}
	options.Rewrites = mustRewriteRules(t, "/dashboard/[^.]*=/index.html")

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	statusCode, body := sendGETRequest(router, "http://example.com/dashboard/settings?tab=1")

	assert.Equal(t, http.StatusOK, statusCode)
	assert.Equal(t, "app", body)
	assert.Equal(t, "/index.html?tab=1", <-receivedPath)
}

func TestRewriteRules_LeaveUnmatchedPathsAlone(t *testing.T) {
	router := testRouter(t)
	receivedPath := make(chan string, 1)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		recordProxiedPath(receivedPath, r)
	})

	options := defaultServiceOptions
	options.Hosts = []string{"example.com"}
	options.Rewrites = mustRewriteRules(t, "/dashboard/[^.]*=/index.html")

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	sendGETRequest(router, "http://example.com/assets/app.js")

	assert.Equal(t, "/assets/app.js", <-receivedPath)
}

func TestRewriteRules_LeaveInternalRequestsAlone(t *testing.T) {
	// The TLS on-demand probe asks the backend about one specific path. A
	// catch-all rewrite pointing it at the app's index would turn every 200 into
	// an approval for whatever host was asked about.
	router := testRouter(t)
	receivedPath := make(chan string, 1)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		recordProxiedPath(receivedPath, r)
	})

	options := defaultServiceOptions
	options.Hosts = []string{"example.com"}
	options.Rewrites = mustRewriteRules(t, "/[^.]*=/index.html")

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/allow-host", nil)
	sendRedirectRequest(router, req.WithContext(markInternalRequest(req.Context())))

	assert.Equal(t, "/allow-host", <-receivedPath)
}

func TestRewriteRules_RunAfterRedirects(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "target", http.StatusOK)

	options := defaultServiceOptions
	options.Hosts = []string{"example.com"}
	options.Redirects = mustRedirectRules(t, "/old=/new")
	options.Rewrites = mustRewriteRules(t, "/old=/index.html")

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	resp := sendRedirectRequest(router, httptest.NewRequest(http.MethodGet, "http://example.com/old", nil))

	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode,
		"a redirect answers the client before any rewrite would apply")
}

func TestRedirectRules_SurviveAStateFileRoundTrip(t *testing.T) {
	router := testRouter(t)
	_, target := testBackend(t, "target", http.StatusOK)

	options := defaultServiceOptions
	options.Hosts = []string{"example.com"}
	options.Redirects = mustRedirectRules(t, "/old=/new;status=308")
	options.Rewrites = mustRewriteRules(t, "/app/[^.]*=/index.html")

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	restored := testRouter(t)
	restored.statePath = router.statePath
	require.NoError(t, restored.RestoreLastSavedState())

	resp := sendRedirectRequest(restored, httptest.NewRequest(http.MethodGet, "http://example.com/old", nil))

	assert.Equal(t, http.StatusPermanentRedirect, resp.StatusCode)
	assert.Equal(t, "http://example.com/new", resp.Header.Get("Location"))
}

// Helpers

func mustRedirectRules(t testing.TB, values ...string) []PathRule {
	t.Helper()

	rules, err := NewRedirectRules(values)
	require.NoError(t, err)
	return rules
}

func mustRewriteRules(t testing.TB, values ...string) []PathRule {
	t.Helper()

	rules, err := NewRewriteRules(values)
	require.NoError(t, err)
	return rules
}

// recordProxiedPath reports what a proxied request arrived as, ignoring the
// health checks the deploy runs against the same backend.
func recordProxiedPath(paths chan<- string, r *http.Request) {
	if r.URL.Path == DefaultHealthCheckPath {
		return
	}

	paths <- r.URL.RequestURI()
}

func sendRedirectRequest(router *Router, req *http.Request) *http.Response {
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	return w.Result()
}
