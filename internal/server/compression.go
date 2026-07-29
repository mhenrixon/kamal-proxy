package server

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Response compression lets a service serve gzip, brotli or zstd without the
// app knowing about it. Only responses the client asked to have encoded, that
// are not encoded already, and whose media type actually shrinks are touched;
// everything else is passed through byte for byte.

const (
	EncodingGzip   = "gzip"
	EncodingBrotli = "br"
	EncodingZstd   = "zstd"

	// DefaultCompressionMinLength is the response size below which compressing
	// costs more than it saves: the encoder's own framing is a few dozen bytes,
	// and a small body usually fits in a single packet either way.
	DefaultCompressionMinLength = 1024

	eventStreamContentType = "text/event-stream"
)

var supportedEncodings = []string{EncodingGzip, EncodingBrotli, EncodingZstd}

// encodingAliases accepts the names an operator is likely to reach for, mapping
// them onto the token that actually travels in Content-Encoding.
var encodingAliases = map[string]string{"brotli": EncodingBrotli}

// defaultCompressibleContentTypes is an allow list rather than a deny list:
// anything unrecognized is assumed to be already compressed or opaque, which is
// the safer guess for a proxy that cannot see inside the payload.
var defaultCompressibleContentTypes = []string{
	"text/*",
	"application/json",
	"application/javascript",
	"application/x-javascript",
	"application/xml",
	"application/wasm",
	"image/svg+xml",
	"image/x-icon",
}

// compressibleContentTypeSuffixes cover the structured syntax suffixes from RFC
// 6839, so a vendor media type such as application/vnd.api+json compresses
// without the operator having to name it.
var compressibleContentTypeSuffixes = []string{"+json", "+xml", "+text"}

// CompressionOptions is the per-service compression configuration. A zero value
// means compression is off, which is what every service that predates this
// feature restores from its state file.
type CompressionOptions struct {
	// Encodings are the content encodings this service offers, most preferred
	// first. Empty (the default) disables compression.
	Encodings []string `json:"encodings,omitempty"`
	// MinLength is the response size below which compression is skipped. Zero
	// means DefaultCompressionMinLength, not "compress everything".
	MinLength int64 `json:"min_length,omitempty"`
	// ContentTypes replaces the built-in list of compressible media types.
	// Entries may be exact ("application/json") or a type wildcard ("text/*").
	ContentTypes []string `json:"content_types,omitempty"`
}

func (co CompressionOptions) Enabled() bool {
	return len(co.Encodings) > 0
}

func (co *CompressionOptions) Normalize() {
	co.Encodings = normalizeEncodings(co.Encodings)
	co.ContentTypes = normalizeContentTypes(co.ContentTypes)
}

func (co CompressionOptions) Validate() error {
	co.Normalize()

	if !co.Enabled() {
		if co.MinLength != 0 {
			return fmt.Errorf("%w: compress-min-length requires compress", ErrServiceOptionsInvalid)
		}
		if len(co.ContentTypes) > 0 {
			return fmt.Errorf("%w: compress-content-type requires compress", ErrServiceOptionsInvalid)
		}
		return nil
	}

	for _, encoding := range co.Encodings {
		if !slices.Contains(supportedEncodings, encoding) {
			return fmt.Errorf("%w: compress must be one of %s, got %q",
				ErrServiceOptionsInvalid, strings.Join(supportedEncodings, ", "), encoding)
		}
	}

	if co.MinLength < 0 {
		return fmt.Errorf("%w: compress-min-length cannot be negative, got %d", ErrServiceOptionsInvalid, co.MinLength)
	}

	for _, contentType := range co.ContentTypes {
		if !validContentTypePattern(contentType) {
			return fmt.Errorf("%w: compress-content-type must be a media type such as text/html or text/*, got %q",
				ErrServiceOptionsInvalid, contentType)
		}
	}

	return nil
}

// Private

func (co CompressionOptions) minLength() int64 {
	if co.MinLength <= 0 {
		return DefaultCompressionMinLength
	}
	return co.MinLength
}

// negotiate picks the encoding to use for a client's Accept-Encoding header, or
// "" to leave the response alone. The highest q-value wins; ties go to whichever
// encoding the service listed first, so --compress states a server preference.
func (co CompressionOptions) negotiate(acceptEncoding string) string {
	if !co.Enabled() || acceptEncoding == "" {
		return ""
	}

	accepted, wildcard, hasWildcard := parseAcceptEncoding(acceptEncoding)

	best := ""
	bestQuality := 0.0
	for _, encoding := range co.Encodings {
		quality, named := accepted[encoding]
		if !named {
			if !hasWildcard {
				continue
			}
			quality = wildcard
		}

		if quality > bestQuality {
			best, bestQuality = encoding, quality
		}
	}

	return best
}

func (co CompressionOptions) compressibleContentType(contentType string) bool {
	mediaType := normalizeContentType(contentType)
	if mediaType == "" {
		return false
	}

	patterns := co.ContentTypes
	usingDefaults := len(patterns) == 0
	if usingDefaults {
		patterns = defaultCompressibleContentTypes
	}

	// An event stream compresses well on paper, but holding bytes back to fill
	// the encoder's window is exactly what the client asked us not to do. It
	// qualifies only when an operator names it outright.
	if mediaType == eventStreamContentType && !slices.Contains(patterns, mediaType) {
		return false
	}

	for _, pattern := range patterns {
		if matchesContentType(pattern, mediaType) {
			return true
		}
	}

	if !usingDefaults {
		return false
	}

	for _, suffix := range compressibleContentTypeSuffixes {
		if strings.HasSuffix(mediaType, suffix) {
			return true
		}
	}

	return false
}

// parseAcceptEncoding returns the q-value of each named encoding, plus the one
// attached to "*" if the client sent it. A malformed q is read as "accepted":
// the client did ask for the encoding, and refusing to compress on a typo is a
// worse outcome than compressing at the wrong priority.
func parseAcceptEncoding(header string) (map[string]float64, float64, bool) {
	accepted := map[string]float64{}
	wildcard := 0.0
	hasWildcard := false

	for _, entry := range strings.Split(header, ",") {
		name, params, _ := strings.Cut(entry, ";")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}

		quality := 1.0
		for _, param := range strings.Split(params, ";") {
			key, value, found := strings.Cut(param, "=")
			if !found || !strings.EqualFold(strings.TrimSpace(key), "q") {
				continue
			}
			if parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
				quality = parsed
			}
		}

		if name == "*" {
			wildcard, hasWildcard = quality, true
			continue
		}

		accepted[name] = quality
	}

	return accepted, wildcard, hasWildcard
}

func normalizeEncodings(encodings []string) []string {
	if len(encodings) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(encodings))
	for _, encoding := range encodings {
		encoding = strings.ToLower(strings.TrimSpace(encoding))
		if alias, found := encodingAliases[encoding]; found {
			encoding = alias
		}
		if encoding == "" || slices.Contains(normalized, encoding) {
			continue
		}

		normalized = append(normalized, encoding)
	}

	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func normalizeContentTypes(contentTypes []string) []string {
	if len(contentTypes) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(contentTypes))
	for _, contentType := range contentTypes {
		contentType = normalizeContentType(contentType)
		if contentType == "" || slices.Contains(normalized, contentType) {
			continue
		}

		normalized = append(normalized, contentType)
	}

	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

// normalizeContentType drops the parameters, so "text/html; charset=utf-8"
// matches a rule written as "text/html".
func normalizeContentType(contentType string) string {
	mediaType, _, _ := strings.Cut(contentType, ";")
	return strings.ToLower(strings.TrimSpace(mediaType))
}

func matchesContentType(pattern, mediaType string) bool {
	if prefix, found := strings.CutSuffix(pattern, "/*"); found {
		return strings.HasPrefix(mediaType, prefix+"/")
	}

	return pattern == mediaType
}

func validContentTypePattern(pattern string) bool {
	mainType, subType, found := strings.Cut(pattern, "/")
	return found && mainType != "" && subType != "" && !strings.Contains(mainType, "*")
}
