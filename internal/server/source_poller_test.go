package server

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSourcePoller_DecodesGzipBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		fmt.Fprint(gz, `{"data": "compressed"}`)
		gz.Close()
	}))
	t.Cleanup(server.Close)

	var received string
	poller := newSourcePoller(sourcePollerConfig{
		Service: "service1",
		Kind:    "test source",
		Source:  server.URL,
		OnBody: func(body io.Reader) error {
			data, err := io.ReadAll(body)
			received = string(data)
			return err
		},
	})

	poller.poll()

	assert.Equal(t, `{"data": "compressed"}`, received)
}

func TestSourcePoller_RollsBackETagOnInvalidPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v2"`)
		fmt.Fprint(w, `broken`)
	}))
	t.Cleanup(server.Close)

	poller := newSourcePoller(sourcePollerConfig{
		Service: "service1",
		Kind:    "test source",
		Source:  server.URL,
		OnBody: func(body io.Reader) error {
			return fmt.Errorf("invalid payload")
		},
	})
	poller.SeedETag(`"v1"`)

	poller.poll()

	// A rejected payload must not advance the ETag, or the next poll would get
	// a 304 and the broken payload would never be retried.
	require.Equal(t, `"v1"`, poller.ETag())
}
