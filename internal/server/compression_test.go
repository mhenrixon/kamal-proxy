package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompressionOptions_Negotiate(t *testing.T) {
	all := []string{EncodingZstd, EncodingBrotli, EncodingGzip}

	tests := []struct {
		name      string
		encodings []string
		accept    string
		expected  string
	}{
		{"no header offers nothing", all, "", ""},
		{"single supported encoding", all, "gzip", EncodingGzip},
		{"server preference decides between equals", all, "gzip, deflate, br", EncodingBrotli},
		{"client q-value outranks server preference", all, "gzip;q=1.0, br;q=0.5", EncodingGzip},
		{"ties fall back to server preference", all, "br;q=0.8, gzip;q=0.8", EncodingBrotli},
		{"wildcard takes the first configured encoding", all, "*", EncodingZstd},
		{"explicit entry beats the wildcard", all, "*;q=0.1, gzip", EncodingGzip},
		{"q=0 refuses an encoding", all, "gzip;q=0", ""},
		{"q=0 on the wildcard refuses the rest", all, "gzip;q=0.9, *;q=0", EncodingGzip},
		{"identity is not a compression offer", all, "identity", ""},
		{"unsupported encodings are ignored", all, "deflate, compress", ""},
		{"names match case-insensitively", all, "GZIP", EncodingGzip},
		{"surrounding whitespace is tolerated", all, "  br ;  q=0.9 ", EncodingBrotli},
		{"unparsable q is treated as accepted", all, "gzip;q=nonsense", EncodingGzip},
		{"only configured encodings are offered", []string{EncodingGzip}, "br, zstd", ""},
		{"disabled compression offers nothing", nil, "gzip", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := CompressionOptions{Encodings: tt.encodings}
			assert.Equal(t, tt.expected, options.negotiate(tt.accept))
		})
	}
}

func TestCompressionOptions_CompressibleContentType(t *testing.T) {
	tests := []struct {
		name         string
		contentTypes []string
		contentType  string
		expected     bool
	}{
		{"html with parameters", nil, "text/html; charset=utf-8", true},
		{"plain text", nil, "text/plain", true},
		{"json", nil, "application/json", true},
		{"structured json suffix", nil, "application/vnd.api+json", true},
		{"structured xml suffix", nil, "application/atom+xml", true},
		{"svg", nil, "image/svg+xml", true},
		{"javascript", nil, "application/javascript", true},
		{"wasm", nil, "application/wasm", true},
		{"case is ignored", nil, "APPLICATION/JSON", true},
		{"png is already compressed", nil, "image/png", false},
		{"mp4 is already compressed", nil, "video/mp4", false},
		{"zip is already compressed", nil, "application/zip", false},
		{"woff2 is already compressed", nil, "font/woff2", false},
		{"octet-stream is opaque", nil, "application/octet-stream", false},
		{"event streams stay unbuffered", nil, "text/event-stream", false},
		{"an absent content type decides nothing", nil, "", false},

		{"an explicit list replaces the defaults", []string{"text/plain"}, "text/html", false},
		{"an explicit list still matches", []string{"text/plain"}, "text/plain; charset=utf-8", true},
		{"an explicit wildcard matches its type", []string{"text/*"}, "text/html", true},
		{"an explicit wildcard still excludes event streams", []string{"text/*"}, "text/event-stream", false},
		{"naming event streams opts them in", []string{"text/event-stream"}, "text/event-stream", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := CompressionOptions{Encodings: []string{EncodingGzip}, ContentTypes: tt.contentTypes}
			options.Normalize()
			assert.Equal(t, tt.expected, options.compressibleContentType(tt.contentType))
		})
	}
}

func TestCompressionOptions_Normalize(t *testing.T) {
	options := CompressionOptions{
		Encodings:    []string{"GZIP", " br ", "brotli", "Zstd", "gzip"},
		ContentTypes: []string{"Text/HTML; charset=utf-8", " application/JSON "},
	}
	options.Normalize()

	assert.Equal(t, []string{EncodingGzip, EncodingBrotli, EncodingZstd}, options.Encodings)
	assert.Equal(t, []string{"text/html", "application/json"}, options.ContentTypes)
}

func TestCompressionOptions_Validate(t *testing.T) {
	tests := []struct {
		name          string
		options       CompressionOptions
		expectedError string
	}{
		{
			name:    "disabled",
			options: CompressionOptions{},
		},
		{
			name:    "every supported encoding",
			options: CompressionOptions{Encodings: []string{"gzip", "br", "zstd"}},
		},
		{
			name:          "unsupported encoding",
			options:       CompressionOptions{Encodings: []string{"gzip", "deflate"}},
			expectedError: "deflate",
		},
		{
			name:          "negative minimum length",
			options:       CompressionOptions{Encodings: []string{"gzip"}, MinLength: -1},
			expectedError: "compress-min-length",
		},
		{
			name:          "minimum length without compression",
			options:       CompressionOptions{MinLength: 512},
			expectedError: "compress-min-length requires compress",
		},
		{
			name:          "content types without compression",
			options:       CompressionOptions{ContentTypes: []string{"text/html"}},
			expectedError: "compress-content-type requires compress",
		},
		{
			name:          "malformed content type",
			options:       CompressionOptions{Encodings: []string{"gzip"}, ContentTypes: []string{"texthtml"}},
			expectedError: "texthtml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.options.Validate()
			if tt.expectedError == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, ErrServiceOptionsInvalid)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestCompressionOptions_MinLengthDefaults(t *testing.T) {
	assert.Equal(t, int64(DefaultCompressionMinLength), CompressionOptions{}.minLength())
	assert.Equal(t, int64(1), CompressionOptions{MinLength: 1}.minLength())
	assert.Equal(t, int64(4096), CompressionOptions{MinLength: 4096}.minLength())
}
