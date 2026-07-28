package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAuthUser     = "admin"
	testAuthPassword = "s3cr3t"
)

func testEncodedCredential(t testing.TB, username, password string) string {
	t.Helper()

	encoded, err := EncodeBasicAuthCredential(username, password)
	require.NoError(t, err)

	return encoded
}

// testProtectedService deploys a service behind basic auth and returns a
// handler wired the way the real server wires one.
func testProtectedService(t *testing.T, options ServiceOptions, handler http.HandlerFunc) http.Handler {
	t.Helper()

	router := testRouter(t)
	_, target := testBackendWithHandler(t, handler)

	if options.BasicAuth == "" {
		options.BasicAuth = testEncodedCredential(t, testAuthUser, testAuthPassword)
	}

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	return testRoutedHandler(t, router)
}

func testAuthRequest(handler http.Handler, req *http.Request) *http.Response {
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	return w.Result()
}

func testAuthBody(t testing.TB, resp *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return string(body)
}

func TestBasicAuthCredential_EncodeAndMatch(t *testing.T) {
	tests := []struct {
		name             string
		username         string
		password         string
		suppliedUsername string
		suppliedPassword string
		expectedMatch    bool
	}{
		{"correct credentials", testAuthUser, testAuthPassword, testAuthUser, testAuthPassword, true},
		{"wrong password", testAuthUser, testAuthPassword, testAuthUser, "nope", false},
		{"wrong username", testAuthUser, testAuthPassword, "root", testAuthPassword, false},
		{"empty supplied password", testAuthUser, testAuthPassword, testAuthUser, "", false},
		{"password containing colons", testAuthUser, "pa:ss:word", testAuthUser, "pa:ss:word", true},
		{"unicode password", testAuthUser, "hüñtér2·√", testAuthUser, "hüñtér2·√", true},
		{"username is not swappable with password", "a", "b", "b", "a", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential, err := parseBasicAuthCredential(testEncodedCredential(t, tt.username, tt.password))
			require.NoError(t, err)

			assert.Equal(t, tt.expectedMatch, credential.matches(tt.suppliedUsername, tt.suppliedPassword))
		})
	}
}

func TestBasicAuthCredential_SaltDiffersPerEncode(t *testing.T) {
	first := testEncodedCredential(t, testAuthUser, testAuthPassword)
	second := testEncodedCredential(t, testAuthUser, testAuthPassword)

	// A shared salt would let one leaked state file confirm that two services
	// use the same password.
	assert.NotEqual(t, first, second)

	for _, encoded := range []string{first, second} {
		credential, err := parseBasicAuthCredential(encoded)
		require.NoError(t, err)
		assert.True(t, credential.matches(testAuthUser, testAuthPassword))
	}
}

func TestBasicAuthCredential_EncodeRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{"empty username", "", testAuthPassword},
		{"empty password", testAuthUser, ""},
		{"username containing a colon", "ad:min", testAuthPassword},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodeBasicAuthCredential(tt.username, tt.password)
			require.Error(t, err)
		})
	}
}

func TestBasicAuthCredential_ParseRejectsMalformedValues(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{"garbage", "garbage"},
		{"too few parts", "sha256:abcd"},
		{"unknown scheme", "argon2id:aabb:ccdd"},
		{"non-hex salt", "sha256:zzzz:" + strings.Repeat("ab", 32)},
		{"short salt", "sha256:abcd:" + strings.Repeat("ab", 32)},
		{"non-hex digest", "sha256:" + strings.Repeat("ab", 16) + ":zzzz"},
		{"short digest", "sha256:" + strings.Repeat("ab", 16) + ":abcd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseBasicAuthCredential(tt.encoded)
			require.Error(t, err)
		})
	}
}

func TestServiceOptions_ValidateBasicAuth(t *testing.T) {
	tests := []struct {
		name        string
		basicAuth   string
		expectError bool
	}{
		{"absent", "", false},
		{"valid", testEncodedCredential(t, testAuthUser, testAuthPassword), false},
		{"malformed", "sha256:zz:zz", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := defaultServiceOptions
			options.BasicAuth = tt.basicAuth

			err := options.Validate()

			if tt.expectError {
				require.ErrorIs(t, err, ErrServiceOptionsInvalid)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestBasicAuth_ChallengesUnauthenticatedRequests(t *testing.T) {
	var reachedTarget atomic.Int64

	handler := testProtectedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		// Deploying runs a health check against the backend, so only count the
		// requests this test actually proxies.
		if r.URL.Path != DefaultHealthCheckPath {
			reachedTarget.Add(1)
		}
		w.Write([]byte("secret"))
	})

	resp := testAuthRequest(handler, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, basicAuthRealm, resp.Header.Get("WWW-Authenticate"))
	assert.Zero(t, reachedTarget.Load(), "the target must never see an unauthenticated request")
}

func TestBasicAuth_AllowsCorrectCredentials(t *testing.T) {
	handler := testProtectedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret"))
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.SetBasicAuth(testAuthUser, testAuthPassword)
	resp := testAuthRequest(handler, req)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "secret", testAuthBody(t, resp))
}

func TestBasicAuth_RejectsWrongCredentials(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{"wrong password", testAuthUser, "nope"},
		{"wrong username", "root", testAuthPassword},
		{"both wrong", "root", "nope"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := testProtectedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("secret"))
			})

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.SetBasicAuth(tt.username, tt.password)
			resp := testAuthRequest(handler, req)

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			assert.Equal(t, basicAuthRealm, resp.Header.Get("WWW-Authenticate"))
		})
	}
}

func TestBasicAuth_ChallengeSurvivesInterceptErrors(t *testing.T) {
	// --intercept-errors accepts 4xx, so an operator can name 401. The challenge
	// header must still reach the client, or the browser never prompts.
	options := defaultServiceOptions
	options.InterceptErrorStatuses = []int{401, 503}

	handler := testProtectedService(t, options, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secret"))
	})

	resp := testAuthRequest(handler, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, basicAuthRealm, resp.Header.Get("WWW-Authenticate"))
}

func TestBasicAuth_ChallengeRendersCustomErrorPage(t *testing.T) {
	pagesDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(pagesDir, "401.html"), []byte("<h1>go away</h1>"), 0644))

	options := defaultServiceOptions
	options.ErrorPagePath = pagesDir

	handler := testProtectedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	resp := testAuthRequest(handler, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, basicAuthRealm, resp.Header.Get("WWW-Authenticate"))
	assert.Contains(t, testAuthBody(t, resp), "go away")
}

func TestBasicAuth_ChallengeSurvivesErrorPagesWithout401Template(t *testing.T) {
	// The service-level middleware only parses the operator's directory, so a
	// dir with no 401.html falls through to the root middleware. The client must
	// still get a usable challenge.
	pagesDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(pagesDir, "404.html"), []byte("<h1>nope</h1>"), 0644))

	options := defaultServiceOptions
	options.ErrorPagePath = pagesDir

	handler := testProtectedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	resp := testAuthRequest(handler, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, basicAuthRealm, resp.Header.Get("WWW-Authenticate"))
}

func TestBasicAuth_RedirectsBeforeChallenging(t *testing.T) {
	// The core security property: a plaintext request to a TLS service must be
	// redirected, never challenged, or the browser sends the password in the
	// clear before it ever reaches https. This is the regression guard against
	// anyone later "tidying" the check into createMiddleware.
	options := defaultServiceOptions
	options.TLSEnabled = true
	options.TLSRedirect = true
	options.Hosts = []string{"example.com"}

	handler := testProtectedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	resp := testAuthRequest(handler, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))

	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
	assert.Equal(t, "https://example.com/", resp.Header.Get("Location"))
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"), "must not solicit credentials over plaintext")
}

func TestBasicAuth_RedirectsToCanonicalHostBeforeChallenging(t *testing.T) {
	options := defaultServiceOptions
	options.Hosts = []string{"example.com", "www.example.com"}
	options.CanonicalHost = "example.com"

	handler := testProtectedService(t, options, func(w http.ResponseWriter, r *http.Request) {})

	resp := testAuthRequest(handler, httptest.NewRequest(http.MethodGet, "http://www.example.com/", nil))

	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("WWW-Authenticate"))
}

func TestBasicAuth_StripsAuthorizationBeforeForwarding(t *testing.T) {
	var forwarded atomic.Value
	forwarded.Store("")

	handler := testProtectedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		forwarded.Store(r.Header.Get("Authorization"))
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.SetBasicAuth(testAuthUser, testAuthPassword)
	resp := testAuthRequest(handler, req)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, forwarded.Load(), "the proxy's credential must not reach the target")
}

func TestBasicAuth_StripsAuthorizationOnExemptPaths(t *testing.T) {
	// Browsers preemptively replay cached credentials to every path under the
	// protection space, so an exempt path must not become a forwarding hole.
	var forwarded atomic.Value
	forwarded.Store("")

	handler := testProtectedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		forwarded.Store(r.Header.Get("Authorization"))
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com"+DefaultHealthCheckPath, nil)
	req.SetBasicAuth(testAuthUser, testAuthPassword)
	resp := testAuthRequest(handler, req)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, forwarded.Load())
}

func TestBasicAuth_ExemptsHealthCheckRequests(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
	}{
		{"GET on the health check path", http.MethodGet, DefaultHealthCheckPath, http.StatusOK},
		{"HEAD on the health check path", http.MethodHead, DefaultHealthCheckPath, http.StatusOK},
		{"POST on the health check path", http.MethodPost, DefaultHealthCheckPath, http.StatusUnauthorized},
		{"any other path", http.MethodGet, "/", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := testProtectedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {})

			resp := testAuthRequest(handler, httptest.NewRequest(tt.method, "http://example.com"+tt.path, nil))

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
		})
	}
}

func TestBasicAuth_RejectsRootHealthCheckPath(t *testing.T) {
	// A health check path of "/" would exempt the protected service's index.
	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})

	options := defaultServiceOptions
	options.BasicAuth = testEncodedCredential(t, testAuthUser, testAuthPassword)

	targetOptions := defaultTargetOptions
	targetOptions.HealthCheckConfig.Path = "/"

	err := router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, targetOptions, defaultDeploymentOptions)

	require.ErrorIs(t, err, ErrServiceOptionsInvalid)
	require.ErrorContains(t, err, "health-check-path")
}

func TestBasicAuth_StateWrittenBeforeTheOptionStaysUnprotected(t *testing.T) {
	state := `
	  {
		"name": "my-app",
		"hosts": ["app.example.com"],
		"active_target": "localhost:3000",
		"rollout_target": "",
		"options": {},
		"target_options": {
		  "health_check_config": {"path": "/up", "interval": 1000000000, "timeout": 5000000000},
		  "response_timeout": 30000000000,
		  "forward_headers": true
		},
		"pause_controller": {"state": 0, "stop_message": "", "fail_after": 0},
		"rollout_controller": null
	  }
	`

	var service Service
	require.NoError(t, json.NewDecoder(strings.NewReader(state)).Decode(&service))
	t.Cleanup(service.Dispose)

	// Never accidentally locked out: a state file written before this feature
	// existed must load a service that requires no credentials.
	assert.Empty(t, service.options.BasicAuth)
	assert.Nil(t, service.basicAuth)
}

func TestBasicAuth_SurvivesStateRoundTrip(t *testing.T) {
	options := defaultServiceOptions
	options.BasicAuth = testEncodedCredential(t, testAuthUser, testAuthPassword)

	service := testCreateService(t, options, defaultTargetOptions)
	t.Cleanup(service.Dispose)

	encoded, err := json.Marshal(service)
	require.NoError(t, err)

	// The state file must never carry the plaintext credential.
	assert.NotContains(t, string(encoded), testAuthUser)
	assert.NotContains(t, string(encoded), testAuthPassword)

	var restored Service
	require.NoError(t, json.Unmarshal(encoded, &restored))
	t.Cleanup(restored.Dispose)

	require.NotNil(t, restored.basicAuth)
	assert.True(t, restored.basicAuth.matches(testAuthUser, testAuthPassword))
	assert.False(t, restored.basicAuth.matches(testAuthUser, "nope"))
}

func TestBasicAuth_UnreadableStoredCredentialFailsClosed(t *testing.T) {
	// An unparseable credential must not abort the decode of the whole state
	// file, and must deny rather than open the service it belongs to.
	state := `
	  {
		"name": "my-app",
		"hosts": ["app.example.com"],
		"active_target": "localhost:3000",
		"options": {"basic_auth": "argon2id:aa:bb"},
		"target_options": {
		  "health_check_config": {"path": "/up", "interval": 1000000000, "timeout": 5000000000},
		  "response_timeout": 30000000000
		},
		"pause_controller": {"state": 0, "stop_message": "", "fail_after": 0},
		"rollout_controller": null
	  }
	`

	var service Service
	require.NoError(t, json.NewDecoder(strings.NewReader(state)).Decode(&service))
	t.Cleanup(service.Dispose)

	require.NotNil(t, service.basicAuth)
	assert.False(t, service.basicAuth.matches(testAuthUser, testAuthPassword))
	assert.False(t, service.basicAuth.matches("", ""))
}

func TestBasicAuth_MalformedCredentialFailsTheDeploy(t *testing.T) {
	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})

	options := defaultServiceOptions
	options.BasicAuth = "sha256:zz:zz"

	err := router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions)

	require.ErrorIs(t, err, ErrServiceOptionsInvalid)
}

func TestBasicAuth_RedeployWithoutTheCredentialRemovesProtection(t *testing.T) {
	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	protected := defaultServiceOptions
	protected.BasicAuth = testEncodedCredential(t, testAuthUser, testAuthPassword)

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		protected, defaultTargetOptions, defaultDeploymentOptions))

	handler := testRoutedHandler(t, router)
	resp := testAuthRequest(handler, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		defaultServiceOptions, defaultTargetOptions, defaultDeploymentOptions))

	resp = testAuthRequest(handler, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestBasicAuth_IsNotExposedByListActiveServices(t *testing.T) {
	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})

	options := defaultServiceOptions
	options.BasicAuth = testEncodedCredential(t, testAuthUser, testAuthPassword)

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	listed, err := json.Marshal(router.ListActiveServices())
	require.NoError(t, err)

	assert.NotContains(t, string(listed), options.BasicAuth)
	assert.NotContains(t, string(listed), testAuthPassword)
}

func TestRouter_StateFileIsNotWorldReadable(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	router := NewRouter(statePath)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})

	options := defaultServiceOptions
	options.BasicAuth = testEncodedCredential(t, testAuthUser, testAuthPassword)

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	// The state file now carries a credential digest, so it must not be readable
	// by every process that can reach the config volume.
	info, err := os.Stat(statePath)
	require.NoError(t, err)
	assert.Zero(t, info.Mode().Perm()&0o077, "state file mode is %v", info.Mode().Perm())
}

func TestBasicAuth_ExemptsInternalRequests(t *testing.T) {
	// The TLS on-demand probe addresses the proxy itself. Challenging it would
	// silently refuse a certificate to every on-demand host.
	handler := testProtectedService(t, defaultServiceOptions, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(markInternalRequest(req.Context()))

	resp := testAuthRequest(handler, req)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
