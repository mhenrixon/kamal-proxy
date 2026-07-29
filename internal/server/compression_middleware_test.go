package server

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var defaultCompressionOptions = CompressionOptions{Encodings: []string{EncodingZstd, EncodingBrotli, EncodingGzip}}

func TestCompressionMiddleware_CompressesWithEachEncoding(t *testing.T) {
	body := strings.Repeat("kamal-proxy ", 500)

	for _, encoding := range []string{EncodingGzip, EncodingBrotli, EncodingZstd} {
		t.Run(encoding, func(t *testing.T) {
			w := runCompression(t, defaultCompressionOptions, requestAccepting(encoding), func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = io.WriteString(w, body)
			})

			assert.Equal(t, encoding, w.Header().Get("Content-Encoding"))
			assert.Equal(t, "Accept-Encoding", w.Header().Get("Vary"))
			assert.Empty(t, w.Header().Get("Content-Length"))
			assert.Less(t, w.body.Len(), len(body))
			assert.Equal(t, body, decompress(t, encoding, w.body.Bytes()))
		})
	}
}

func TestCompressionMiddleware_PassesThroughWhenNotNegotiated(t *testing.T) {
	body := strings.Repeat("kamal-proxy ", 500)

	tests := []struct {
		name        string
		accept      string
		contentType string
		options     CompressionOptions
		expectVary  bool
	}{
		{
			name:        "client accepts nothing we offer",
			accept:      "deflate",
			contentType: "text/html",
			options:     defaultCompressionOptions,
			expectVary:  true,
		},
		{
			name:        "client sends no Accept-Encoding",
			accept:      "",
			contentType: "text/html",
			options:     defaultCompressionOptions,
			expectVary:  true,
		},
		{
			name:        "content type is already compressed",
			accept:      "gzip",
			contentType: "image/png",
			options:     defaultCompressionOptions,
			expectVary:  false,
		},
		{
			name:        "encoding is not configured for the service",
			accept:      "gzip",
			contentType: "text/html",
			options:     CompressionOptions{Encodings: []string{EncodingZstd}},
			expectVary:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := runCompression(t, tt.options, requestAccepting(tt.accept), func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				_, _ = io.WriteString(w, body)
			})

			assert.Empty(t, w.Header().Get("Content-Encoding"))
			assert.Equal(t, body, w.body.String())
			if tt.expectVary {
				assert.Equal(t, "Accept-Encoding", w.Header().Get("Vary"))
			} else {
				assert.Empty(t, w.Header().Get("Vary"))
			}
		})
	}
}

func TestCompressionMiddleware_LeavesTargetEncodedResponsesAlone(t *testing.T) {
	body := strings.Repeat("already gzipped ", 500)

	w := runCompression(t, defaultCompressionOptions, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, body)
	})

	assert.Equal(t, "gzip", w.Header().Get("Content-Encoding"))
	assert.Equal(t, body, w.body.String())
}

func TestCompressionMiddleware_MinimumLength(t *testing.T) {
	tests := []struct {
		name             string
		minLength        int64
		contentLength    string
		size             int
		expectCompressed bool
	}{
		{name: "below the default", size: 100},
		{name: "above the default", size: 4096, expectCompressed: true},
		{name: "declared length below the default", contentLength: "100", size: 100},
		{name: "declared length above the default", contentLength: "4096", size: 4096, expectCompressed: true},
		{name: "custom minimum met", minLength: 32, size: 100, expectCompressed: true},
		{name: "custom minimum missed", minLength: 8192, size: 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.Repeat("a", tt.size)
			options := defaultCompressionOptions
			options.MinLength = tt.minLength

			w := runCompression(t, options, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				if tt.contentLength != "" {
					w.Header().Set("Content-Length", tt.contentLength)
				}
				_, _ = io.WriteString(w, body)
			})

			if tt.expectCompressed {
				assert.Equal(t, EncodingGzip, w.Header().Get("Content-Encoding"))
				assert.Equal(t, body, decompress(t, EncodingGzip, w.body.Bytes()))
			} else {
				assert.Empty(t, w.Header().Get("Content-Encoding"))
				assert.Equal(t, body, w.body.String())
			}
		})
	}
}

func TestCompressionMiddleware_SkipsResponsesWithoutABody(t *testing.T) {
	tests := []struct {
		name   string
		method string
		status int
	}{
		{name: "no content", method: http.MethodGet, status: http.StatusNoContent},
		{name: "not modified", method: http.MethodGet, status: http.StatusNotModified},
		{name: "head request", method: http.MethodHead, status: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://example.com/", nil)
			req.Header.Set("Accept-Encoding", "gzip")

			w := runCompression(t, defaultCompressionOptions, req, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Content-Length", "4096")
				w.WriteHeader(tt.status)
			})

			assert.Equal(t, tt.status, w.status)
			assert.Empty(t, w.Header().Get("Content-Encoding"))
		})
	}
}

func TestCompressionMiddleware_SkipsPartialContent(t *testing.T) {
	body := strings.Repeat("a", 4096)

	w := runCompression(t, defaultCompressionOptions, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Range", "bytes 0-4095/9000")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, body)
	})

	assert.Equal(t, http.StatusPartialContent, w.status)
	assert.Empty(t, w.Header().Get("Content-Encoding"))
	assert.Equal(t, body, w.body.String())
}

func TestCompressionMiddleware_AdjustsValidatorsWhenCompressing(t *testing.T) {
	body := strings.Repeat("a", 4096)

	send := func(accept string) *recordingResponseWriter {
		return runCompression(t, defaultCompressionOptions, requestAccepting(accept), func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("ETag", `"abc123"`)
			w.Header().Set("Accept-Ranges", "bytes")
			_, _ = io.WriteString(w, body)
		})
	}

	compressed := send("gzip")
	assert.Equal(t, `W/"abc123"`, compressed.Header().Get("ETag"))
	assert.Empty(t, compressed.Header().Get("Accept-Ranges"))

	untouched := send("deflate")
	assert.Equal(t, `"abc123"`, untouched.Header().Get("ETag"))
	assert.Equal(t, "bytes", untouched.Header().Get("Accept-Ranges"))
}

func TestCompressionMiddleware_LeavesWeakETagsAlone(t *testing.T) {
	w := runCompression(t, defaultCompressionOptions, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `W/"abc123"`)
		_, _ = io.WriteString(w, strings.Repeat("a", 4096))
	})

	assert.Equal(t, `W/"abc123"`, w.Header().Get("ETag"))
}

func TestCompressionMiddleware_DoesNotRepeatVary(t *testing.T) {
	w := runCompression(t, defaultCompressionOptions, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Vary", "Accept-Encoding, Cookie")
		_, _ = io.WriteString(w, strings.Repeat("a", 4096))
	})

	assert.Equal(t, []string{"Accept-Encoding, Cookie"}, w.Header().Values("Vary"))
}

func TestCompressionMiddleware_AddsVaryAlongsideOtherValues(t *testing.T) {
	w := runCompression(t, defaultCompressionOptions, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Vary", "Cookie")
		_, _ = io.WriteString(w, strings.Repeat("a", 4096))
	})

	assert.Equal(t, []string{"Cookie", "Accept-Encoding"}, w.Header().Values("Vary"))
}

func TestCompressionMiddleware_SniffsAnAbsentContentType(t *testing.T) {
	body := "<html>" + strings.Repeat("a", 4096) + "</html>"

	w := runCompression(t, defaultCompressionOptions, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	})

	assert.Equal(t, EncodingGzip, w.Header().Get("Content-Encoding"))
	assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
	assert.Equal(t, body, decompress(t, EncodingGzip, w.body.Bytes()))
}

func TestCompressionMiddleware_LeavesEventStreamsUnbuffered(t *testing.T) {
	w := runCompression(t, defaultCompressionOptions, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		for range 100 {
			_, _ = io.WriteString(w, "data: hello\n\n")
			w.(http.Flusher).Flush()
		}
	})

	assert.Empty(t, w.Header().Get("Content-Encoding"))
	assert.Equal(t, "header", w.events[0], "the status must reach the client before the first event")
	assert.Equal(t, "flush", w.events[1])
	assert.Equal(t, strings.Repeat("data: hello\n\n", 100), w.body.String())
}

func TestCompressionMiddleware_FlushBeforeTheMinimumSendsUncompressed(t *testing.T) {
	w := runCompression(t, defaultCompressionOptions, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "short")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, strings.Repeat("a", 4096))
	})

	assert.Empty(t, w.Header().Get("Content-Encoding"))
	assert.Equal(t, "short"+strings.Repeat("a", 4096), w.body.String())
}

// ReverseProxy flushes right after the headers of any response whose length it
// does not know, before a single body byte exists. That flush must not settle
// the question, or every chunked response would go out uncompressed.
func TestCompressionMiddleware_FlushBeforeTheBodyDecidesNothing(t *testing.T) {
	body := strings.Repeat("a", 4096)

	w := runCompression(t, defaultCompressionOptions, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		_, _ = io.WriteString(w, body)
	})

	assert.Equal(t, EncodingGzip, w.Header().Get("Content-Encoding"))
	assert.Equal(t, body, decompress(t, EncodingGzip, w.body.Bytes()))
}

func TestCompressionMiddleware_FlushesThroughTheCompressor(t *testing.T) {
	body := strings.Repeat("streamed ", 500)
	w := newRecordingResponseWriter()

	handler := WithCompressionMiddleware(defaultCompressionOptions, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, body)
		rw.(http.Flusher).Flush()

		assert.Positive(t, w.body.Len(), "a flush must push compressed bytes to the client")
	}))
	handler.ServeHTTP(w, requestAccepting("gzip"))

	assert.Equal(t, EncodingGzip, w.Header().Get("Content-Encoding"))
	assert.Equal(t, body, decompress(t, EncodingGzip, w.body.Bytes()))
}

func TestCompressionMiddleware_PreservesTheStatusCode(t *testing.T) {
	w := runCompression(t, defaultCompressionOptions, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, strings.Repeat("a", 4096))
	})

	assert.Equal(t, http.StatusServiceUnavailable, w.status)
	assert.Equal(t, EncodingGzip, w.Header().Get("Content-Encoding"))
}

func TestCompressionMiddleware_SendsAnEmptyResponse(t *testing.T) {
	w := runCompression(t, defaultCompressionOptions, requestAccepting("gzip"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
	})

	assert.Equal(t, http.StatusOK, w.status)
	assert.Empty(t, w.Header().Get("Content-Encoding"))
	assert.Equal(t, 0, w.body.Len())
}

func TestCompressionMiddleware_Hijack(t *testing.T) {
	t.Run("delegates when the writer supports it", func(t *testing.T) {
		w := &hijackableResponseWriter{recordingResponseWriter: newRecordingResponseWriter()}

		handler := WithCompressionMiddleware(defaultCompressionOptions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _, err := w.(http.Hijacker).Hijack()
			require.NoError(t, err)
		}))
		handler.ServeHTTP(w, requestAccepting("gzip"))

		assert.True(t, w.hijacked)
	})

	t.Run("reports when the writer does not", func(t *testing.T) {
		handler := WithCompressionMiddleware(defaultCompressionOptions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _, err := w.(http.Hijacker).Hijack()
			assert.ErrorIs(t, err, http.ErrNotSupported)
		}))
		handler.ServeHTTP(newRecordingResponseWriter(), requestAccepting("gzip"))
	})
}

// Benchmarks

func BenchmarkCompressionMiddleware(b *testing.B) {
	body := []byte(strings.Repeat("<p>a paragraph of perfectly ordinary markup</p>", 400))

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}

	benchmarks := []struct {
		name   string
		accept string
	}{
		{"gzip", EncodingGzip},
		{"br", EncodingBrotli},
		{"zstd", EncodingZstd},
		{"passthrough", "deflate"},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			options := defaultCompressionOptions
			options.Normalize()
			middleware := WithCompressionMiddleware(options, http.HandlerFunc(handler))
			req := requestAccepting(bm.accept)

			b.ReportAllocs()
			for b.Loop() {
				middleware.ServeHTTP(&discardResponseWriter{header: http.Header{}}, req)
			}
		})
	}
}

// Helpers

// discardResponseWriter keeps the benchmark measuring the middleware rather
// than the cost of growing a buffer.
type discardResponseWriter struct {
	header http.Header
}

func (w *discardResponseWriter) Header() http.Header { return w.header }
func (w *discardResponseWriter) WriteHeader(int)     {}
func (w *discardResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func requestAccepting(encoding string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if encoding != "" {
		req.Header.Set("Accept-Encoding", encoding)
	}
	return req
}

func runCompression(t *testing.T, options CompressionOptions, req *http.Request, handler http.HandlerFunc) *recordingResponseWriter {
	t.Helper()

	options.Normalize()
	require.NoError(t, options.Validate())

	w := newRecordingResponseWriter()
	WithCompressionMiddleware(options, handler).ServeHTTP(w, req)
	return w
}

func decompress(t *testing.T, encoding string, data []byte) string {
	t.Helper()

	var reader io.Reader
	switch encoding {
	case EncodingGzip:
		gzipReader, err := gzip.NewReader(bytes.NewReader(data))
		require.NoError(t, err)
		reader = gzipReader
	case EncodingBrotli:
		reader = brotli.NewReader(bytes.NewReader(data))
	case EncodingZstd:
		zstdReader, err := zstd.NewReader(bytes.NewReader(data))
		require.NoError(t, err)
		t.Cleanup(zstdReader.Close)
		reader = zstdReader
	default:
		t.Fatalf("unknown encoding %q", encoding)
	}

	decompressed, err := io.ReadAll(reader)
	require.NoError(t, err)
	return string(decompressed)
}

// recordingResponseWriter keeps the order of header, body and flush events, so
// tests can assert that a streaming response still reaches the client one chunk
// at a time.
type recordingResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
	events []string
}

func newRecordingResponseWriter() *recordingResponseWriter {
	return &recordingResponseWriter{header: http.Header{}, status: http.StatusOK}
}

func (w *recordingResponseWriter) Header() http.Header {
	return w.header
}

func (w *recordingResponseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
	w.events = append(w.events, "header")
}

func (w *recordingResponseWriter) Write(data []byte) (int, error) {
	w.events = append(w.events, "write")
	return w.body.Write(data)
}

func (w *recordingResponseWriter) Flush() {
	w.events = append(w.events, "flush")
}

type hijackableResponseWriter struct {
	*recordingResponseWriter
	hijacked bool
}

func (w *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return nil, nil, nil
}
