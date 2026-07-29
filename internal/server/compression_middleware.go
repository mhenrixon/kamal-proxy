package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

// Compression levels are fixed rather than configurable: a proxy pays the CPU
// for every response it encodes, and the top levels of all three algorithms buy
// a few percent of ratio for several times the cost.
const (
	gzipCompressionLevel   = 5
	brotliCompressionLevel = 4

	// zstdWindowSize caps the encoder's match window. The library's default is
	// large enough to matter when hundreds of encoders sit in the pool, and HTTP
	// responses rarely have matches beyond a megabyte apart.
	zstdWindowSize = 1 << 20
)

// responseEncoder is the shape gzip.Writer, brotli.Writer and zstd.Encoder all
// share, which is what lets one response writer drive any of them.
type responseEncoder interface {
	io.WriteCloser
	Flush() error
	Reset(w io.Writer)
}

var encoderPools = map[string]*sync.Pool{
	EncodingGzip: {New: func() any {
		encoder, _ := gzip.NewWriterLevel(io.Discard, gzipCompressionLevel)
		return encoder
	}},
	EncodingBrotli: {New: func() any {
		return brotli.NewWriterLevel(io.Discard, brotliCompressionLevel)
	}},
	EncodingZstd: {New: func() any {
		// One goroutine per encoder: the library's default scales with GOMAXPROCS,
		// which on a proxy would mean a goroutine storm under concurrent responses.
		encoder, _ := zstd.NewWriter(io.Discard,
			zstd.WithEncoderLevel(zstd.SpeedDefault),
			zstd.WithEncoderConcurrency(1),
			zstd.WithWindowSize(zstdWindowSize),
		)
		return encoder
	}},
}

// CompressionMiddleware encodes responses on their way back to the client. It
// sits outside the service's own error pages, so a rendered 502 is encoded the
// same way the target's HTML is, and inside the ACME handler, so a challenge
// response is never touched.
type CompressionMiddleware struct {
	options CompressionOptions
	next    http.Handler
}

func WithCompressionMiddleware(options CompressionOptions, next http.Handler) http.Handler {
	return &CompressionMiddleware{
		options: options,
		next:    next,
	}
}

func (h *CompressionMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writer := &compressingResponseWriter{
		ResponseWriter: w,
		options:        h.options,
		encoding:       h.options.negotiate(r.Header.Get("Accept-Encoding")),
		bodyExpected:   r.Method != http.MethodHead,
		statusCode:     http.StatusOK,
	}
	defer writer.finish()

	h.next.ServeHTTP(writer, r)
}

// Private

// compressingResponseWriter holds the response headers back until it knows
// whether it is going to compress, because Content-Encoding, Content-Length and
// ETag all have to change together with the body. It commits as soon as the
// answer is knowable -- which for anything declaring a Content-Type and a
// Content-Length is before the first byte of body.
type compressingResponseWriter struct {
	http.ResponseWriter
	options      CompressionOptions
	encoding     string
	bodyExpected bool

	statusCode  int
	headerSeen  bool
	sentHeader  bool
	decided     bool
	compressing bool
	hijacked    bool

	encoder responseEncoder
	buffer  []byte
	err     error
}

func (w *compressingResponseWriter) WriteHeader(statusCode int) {
	if w.headerSeen {
		return
	}

	w.headerSeen = true
	w.statusCode = statusCode
	w.decideFromHeaders()
}

func (w *compressingResponseWriter) Write(data []byte) (int, error) {
	if !w.headerSeen {
		w.WriteHeader(http.StatusOK)
	}

	if w.decided {
		return w.writeDecided(data)
	}

	w.buffer = append(w.buffer, data...)
	if int64(len(w.buffer)) >= w.options.minLength() {
		w.decide()
	}

	if w.err != nil {
		return 0, w.err
	}
	return len(data), nil
}

func (w *compressingResponseWriter) Flush() {
	if w.hijacked {
		return
	}

	if !w.decided {
		// A flush with nothing behind it decides nothing. ReverseProxy schedules
		// exactly that immediately after the headers of every response whose
		// length it does not know, to get the status out ahead of a slow body --
		// and it races the first body write, so treating it as a decision would
		// make compression a coin toss for every chunked response. There is
		// nothing to push yet either: the headers cannot go out until we know
		// whether Content-Encoding belongs on them.
		if !w.headerSeen || len(w.buffer) == 0 {
			return
		}

		// Bytes are waiting and the client wants them now, so this is as much of
		// the body as the decision is ever going to see.
		w.decide()
	}

	if w.compressing {
		_ = w.encoder.Flush()
	}

	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *compressingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}

	// The connection is no longer ours to frame a response on.
	w.hijacked = true
	w.decided = true

	return hijacker.Hijack()
}

// decideFromHeaders commits early whenever the headers alone settle the
// question, so that a response which streams its body -- an event stream above
// all -- reaches the client with its status intact and no bytes held back.
func (w *compressingResponseWriter) decideFromHeaders() {
	if !w.mayCompress() {
		w.decide()
		return
	}

	contentType := w.Header().Get("Content-Type")
	if contentType == "" {
		// Undecidable until there are bytes to sniff.
		return
	}

	if !w.options.compressibleContentType(contentType) || w.encoding == "" || w.declaredContentLength() >= 0 {
		w.decide()
	}
}

func (w *compressingResponseWriter) decide() {
	if w.decided {
		return
	}
	w.decided = true

	if w.mayCompress() {
		contentType := w.Header().Get("Content-Type")
		sniffed := ""
		if contentType == "" && len(w.buffer) > 0 {
			sniffed = http.DetectContentType(w.buffer)
			contentType = sniffed
		}

		if w.options.compressibleContentType(contentType) {
			// Set whether or not this particular client got a compressed body: a
			// cache holding both representations has to key them apart.
			addVaryOnAcceptEncoding(w.Header())

			if w.encoding != "" && w.bodyAtLeast(w.options.minLength()) {
				if sniffed != "" {
					// net/http sniffs the bytes it is handed, which after this point
					// are compressed ones. Pin what the body actually is.
					w.Header().Set("Content-Type", sniffed)
				}
				w.startCompressing()
			}
		}
	}

	w.sendHeader()
	w.flushBuffer()
}

func (w *compressingResponseWriter) mayCompress() bool {
	if !w.bodyExpected || !statusAllowsBody(w.statusCode) {
		return false
	}

	// The target encoded it already, so re-encoding would only cost CPU.
	if w.Header().Get("Content-Encoding") != "" {
		return false
	}

	// A byte range describes offsets into the identity representation, which is
	// not what a compressed body is.
	return w.Header().Get("Content-Range") == ""
}

func (w *compressingResponseWriter) startCompressing() {
	w.compressing = true
	w.encoder = acquireEncoder(w.encoding, w.ResponseWriter)

	header := w.Header()
	header.Set("Content-Encoding", w.encoding)
	// Both describe the body the target produced, not the one the client is
	// about to receive.
	header.Del("Content-Length")
	header.Del("Accept-Ranges")
	weakenETag(header)
}

func (w *compressingResponseWriter) sendHeader() {
	if w.sentHeader || w.hijacked {
		return
	}

	w.sentHeader = true
	w.ResponseWriter.WriteHeader(w.statusCode)
}

func (w *compressingResponseWriter) flushBuffer() {
	if len(w.buffer) == 0 {
		return
	}

	buffered := w.buffer
	w.buffer = nil

	if _, err := w.writeDecided(buffered); err != nil {
		w.err = err
	}
}

func (w *compressingResponseWriter) writeDecided(data []byte) (int, error) {
	if w.compressing {
		return w.encoder.Write(data)
	}

	return w.ResponseWriter.Write(data)
}

// bodyAtLeast reports whether the response is worth compressing. A declared
// Content-Length answers it without buffering; without one, the answer is
// whatever has accumulated so far.
func (w *compressingResponseWriter) bodyAtLeast(minimum int64) bool {
	if declared := w.declaredContentLength(); declared >= 0 {
		return declared >= minimum
	}

	return int64(len(w.buffer)) >= minimum
}

func (w *compressingResponseWriter) declaredContentLength() int64 {
	value := w.Header().Get("Content-Length")
	if value == "" {
		return -1
	}

	length, err := strconv.ParseInt(value, 10, 64)
	if err != nil || length < 0 {
		return -1
	}

	return length
}

func (w *compressingResponseWriter) finish() {
	if w.hijacked {
		return
	}

	w.decide()

	if w.compressing {
		if err := w.encoder.Close(); err != nil && w.err == nil {
			w.err = err
		}
		releaseEncoder(w.encoding, w.encoder)
		w.encoder = nil
		w.compressing = false
	}

	w.sendHeader()
}

func acquireEncoder(encoding string, w io.Writer) responseEncoder {
	encoder := encoderPools[encoding].Get().(responseEncoder)
	encoder.Reset(w)
	return encoder
}

func releaseEncoder(encoding string, encoder responseEncoder) {
	// Drop the reference to the response writer before parking it, so a pooled
	// encoder never pins a finished request's connection.
	encoder.Reset(io.Discard)
	encoderPools[encoding].Put(encoder)
}

func statusAllowsBody(statusCode int) bool {
	return statusCode >= http.StatusOK &&
		statusCode != http.StatusNoContent &&
		statusCode != http.StatusNotModified
}

func addVaryOnAcceptEncoding(header http.Header) {
	for _, value := range header.Values("Vary") {
		for _, field := range strings.Split(value, ",") {
			field = strings.TrimSpace(field)
			if field == "*" || strings.EqualFold(field, "Accept-Encoding") {
				return
			}
		}
	}

	header.Add("Vary", "Accept-Encoding")
}

// weakenETag downgrades a strong validator, because the compressed body is a
// different representation and a strong ETag may only identify one.
func weakenETag(header http.Header) {
	etag := header.Get("ETag")
	if etag == "" || strings.HasPrefix(etag, "W/") {
		return
	}

	header.Set("ETag", "W/"+etag)
}
