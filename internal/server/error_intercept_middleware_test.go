package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/kamal-proxy/internal/pages"
)

func TestErrorInterceptMiddleware(t *testing.T) {
	tests := []struct {
		name            string
		statuses        []int
		backend         http.HandlerFunc
		expectedStatus  int
		expectedBody    string
		expectedHeaders map[string]string
	}{
		{
			name:     "intercepts a configured status",
			statuses: []int{502, 503},
			backend: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, "the app's own error page")
			},
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "Custom 503",
		},
		{
			name:     "passes through a status it was not asked to intercept",
			statuses: []int{502},
			backend: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, "the app's own error page")
			},
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "the app's own error page",
		},
		{
			name:     "passes through a successful response",
			statuses: []int{502, 503},
			backend: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "hello")
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "hello",
		},
		{
			name:     "drops entity headers describing the discarded body",
			statuses: []int{503},
			backend: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "5")
				w.Header().Set("Content-Encoding", "gzip")
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, "xxxxx")
			},
			expectedStatus:  http.StatusServiceUnavailable,
			expectedBody:    "Custom 503",
			expectedHeaders: map[string]string{"Content-Length": "", "Content-Encoding": ""},
		},
		{
			name:     "keeps the first status when the backend writes the header twice",
			statuses: []int{503},
			backend: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "the app's own error page")
			},
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "Custom 503",
		},
		{
			name:     "leaves a proxy-generated error alone",
			statuses: []int{503},
			backend: func(w http.ResponseWriter, r *http.Request) {
				SetErrorResponse(w, r, http.StatusServiceUnavailable, nil)
			},
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   "Custom 503",
		},
	}

	errorPages := fstest.MapFS(map[string]*fstest.MapFile{
		"503.html": {Data: []byte("<body>Custom 503</body>")},
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := WithErrorInterceptMiddleware(tt.statuses, tt.backend)
			handler, err := WithErrorPageMiddleware(errorPages, true, handler)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)

			assert.Equal(t, tt.expectedStatus, resp.Result().StatusCode)
			assert.Contains(t, resp.Body.String(), tt.expectedBody)

			for header, value := range tt.expectedHeaders {
				assert.Equal(t, value, resp.Result().Header.Get(header))
			}
		})
	}
}

func TestErrorInterceptMiddleware_DiscardsTheInterceptedBody(t *testing.T) {
	errorPages := fstest.MapFS(map[string]*fstest.MapFile{
		"503.html": {Data: []byte("<body>Custom 503</body>")},
	})

	handler := WithErrorInterceptMiddleware([]int{503}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		n, err := fmt.Fprint(w, "the app's own error page")
		// The target must believe its write succeeded, or ReverseProxy panics.
		assert.NoError(t, err)
		assert.Equal(t, len("the app's own error page"), n)
	}))
	handler, err := WithErrorPageMiddleware(errorPages, true, handler)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Equal(t, "<body>Custom 503</body>", resp.Body.String())
}

func TestErrorInterceptMiddleware_ServiceOptionsValidation(t *testing.T) {
	tests := []struct {
		name          string
		statuses      []int
		expectedError string
	}{
		{name: "unset"},
		{name: "the proxy error statuses", statuses: []int{502, 503, 504}},
		{name: "any client or server error", statuses: []int{404, 599}},
		{
			name:          "a status below the error range",
			statuses:      []int{302},
			expectedError: "intercept-errors must be a 4xx or 5xx status code, got 302",
		},
		{
			name:          "a status above the error range",
			statuses:      []int{600},
			expectedError: "intercept-errors must be a 4xx or 5xx status code, got 600",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := defaultServiceOptions
			options.InterceptErrorStatuses = tt.statuses

			err := options.Validate()

			if tt.expectedError == "" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrServiceOptionsInvalid)
				require.ErrorContains(t, err, tt.expectedError)
			}
		})
	}
}

func TestErrorInterceptMiddleware_ServiceReplacesUpstreamErrors(t *testing.T) {
	errorPagePath := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(errorPagePath, "503.html"),
		[]byte("<body>Sorry, we're down</body>"), 0o644))

	deploy := func(t *testing.T, statuses []int) *Router {
		t.Helper()

		router := testRouter(t)
		_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == defaultHealthCheckConfig.Path {
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, "the app's own error page")
		})

		options := defaultServiceOptions
		options.ErrorPagePath = errorPagePath
		options.InterceptErrorStatuses = statuses

		require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
			options, defaultTargetOptions, defaultDeploymentOptions))

		return router
	}

	t.Run("when the service intercepts the status", func(t *testing.T) {
		statusCode, body := sendGETRequest(deploy(t, []int{503}), "http://example.com/")

		assert.Equal(t, http.StatusServiceUnavailable, statusCode)
		assert.Equal(t, "<body>Sorry, we're down</body>", body)
	})

	t.Run("when the service does not intercept anything", func(t *testing.T) {
		statusCode, body := sendGETRequest(deploy(t, nil), "http://example.com/")

		assert.Equal(t, http.StatusServiceUnavailable, statusCode)
		assert.Equal(t, "the app's own error page", body)
	})
}

func TestErrorInterceptMiddleware_FallsBackToTheDefaultErrorPages(t *testing.T) {
	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == defaultHealthCheckConfig.Path {
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "the app's own error page")
	})

	options := defaultServiceOptions
	options.InterceptErrorStatuses = []int{502}

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, defaultTargetOptions, defaultDeploymentOptions))

	// The server mounts the default pages as the root error page middleware, so
	// a service with no --error-pages of its own still gets a branded page.
	handler, err := WithErrorPageMiddleware(pages.DefaultErrorPages, true, router)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusBadGateway, resp.Result().StatusCode)
	assert.NotContains(t, resp.Body.String(), "the app's own error page")
	assert.Contains(t, resp.Body.String(), "502 — Bad Gateway")
}

func TestErrorInterceptMiddleware_WithBufferedResponses(t *testing.T) {
	errorPagePath := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(errorPagePath, "503.html"),
		[]byte("<body>Sorry, we're down</body>"), 0o644))

	router := testRouter(t)
	_, target := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == defaultHealthCheckConfig.Path {
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, "the app's own error page")
	})

	options := defaultServiceOptions
	options.ErrorPagePath = errorPagePath
	options.InterceptErrorStatuses = []int{503}

	targetOptions := defaultTargetOptions
	targetOptions.BufferResponses = true

	require.NoError(t, router.DeployService("service1", []string{target}, defaultEmptyReaders,
		options, targetOptions, defaultDeploymentOptions))

	statusCode, body := sendGETRequest(router, "http://example.com/")

	assert.Equal(t, http.StatusServiceUnavailable, statusCode)
	assert.Equal(t, "<body>Sorry, we're down</body>", body)
}

func TestErrorInterceptMiddleware_StateFilesWithoutTheOptionKeepInterceptionOff(t *testing.T) {
	_, targetURL := testBackendWithHandler(t, func(w http.ResponseWriter, r *http.Request) {})

	saved := []byte(`{
		"name": "service1",
		"options": {"hosts": ["example.com"], "path_prefixes": ["/"]},
		"target_options": {"health_check_config": {"path": "/up", "interval": 1000000000, "timeout": 5000000000}},
		"active_targets": ["` + targetURL + `"],
		"pause_controller": {"state": 0}
	}`)

	var service Service
	require.NoError(t, json.Unmarshal(saved, &service))
	t.Cleanup(service.Dispose)

	assert.Empty(t, service.options.InterceptErrorStatuses)
}

func TestErrorInterceptMiddleware_FlushesUninterceptedResponses(t *testing.T) {
	flushed := false

	handler := WithErrorInterceptMiddleware([]int{503}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "streaming")
		flusher, ok := w.(http.Flusher)
		require.True(t, ok)
		flusher.Flush()
		flushed = true
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	assert.True(t, flushed)
	assert.True(t, resp.Flushed)
	assert.Equal(t, "streaming", resp.Body.String())
}
