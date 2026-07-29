package server

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLogFormat(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		expected      LogFormat
		expectedError string
	}{
		{name: "empty is the default", value: "", expected: LogFormatJSON},
		{name: "blank is the default", value: "   ", expected: LogFormatJSON},
		{name: "json", value: "json", expected: LogFormatJSON},
		{name: "text", value: "text", expected: LogFormatText},
		{name: "logfmt is text", value: "logfmt", expected: LogFormatText},
		{name: "uppercase", value: "JSON", expected: LogFormatJSON},
		{name: "padded", value: " Text ", expected: LogFormatText},

		{name: "unknown", value: "xml", expectedError: `log-format: "xml" is not a log format`},
		{name: "typo", value: "jsonl", expectedError: "log-format:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, err := ParseLogFormat(tt.value)

			if tt.expectedError != "" {
				require.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, format)
		})
	}
}

func TestLogFormat_NewHandler(t *testing.T) {
	tests := []struct {
		format   LogFormat
		contains string
	}{
		{format: LogFormatJSON, contains: `"msg":"hello","service":"myapp"`},
		{format: LogFormatText, contains: `msg=hello service=myapp`},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			out := &strings.Builder{}

			logger := slog.New(tt.format.NewHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
			logger.Info("hello", "service", "myapp")

			assert.Contains(t, out.String(), tt.contains)
		})
	}
}

// The handler options have to reach the handler, or --debug would stop working
// the moment an operator picked a non-default format.
func TestLogFormat_NewHandlerHonorsLevel(t *testing.T) {
	for _, format := range []LogFormat{LogFormatJSON, LogFormatText} {
		t.Run(string(format), func(t *testing.T) {
			out := &strings.Builder{}

			logger := slog.New(format.NewHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
			logger.Debug("visible")

			assert.Contains(t, out.String(), "visible")
		})
	}
}
