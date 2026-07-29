package server

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// DefaultLogFormat is the format used when --log-format is not given. It is the
// shape kamal-proxy has always written, so the default changes nothing.
const DefaultLogFormat = "json"

// LogFormat selects the slog handler the process writes every line through -
// the access log in LoggingMiddleware as well as the server's own messages,
// because both go to slog.Default().
type LogFormat string

const (
	LogFormatJSON LogFormat = "json"
	LogFormatText LogFormat = "text"
)

// ParseLogFormat maps a --log-format value onto a handler choice. An empty
// value means the default, so an unset or blank LOG_FORMAT boots instead of
// failing.
func ParseLogFormat(value string) (LogFormat, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(value)); normalized {
	case "", string(LogFormatJSON):
		return LogFormatJSON, nil
	case string(LogFormatText), "logfmt":
		// slog's text handler writes logfmt, which is what an operator asking
		// for "logfmt" wants; accepting the name saves them guessing.
		return LogFormatText, nil
	default:
		return "", fmt.Errorf("log-format: %q is not a log format; use %s or text", value, DefaultLogFormat)
	}
}

// NewHandler builds the slog handler for this format. Options are passed
// through rather than rebuilt, so --debug keeps working whichever format is
// selected.
func (f LogFormat) NewHandler(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	if f == LogFormatText {
		return slog.NewTextHandler(w, opts)
	}
	return slog.NewJSONHandler(w, opts)
}
