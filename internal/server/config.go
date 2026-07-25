package server

import (
	"cmp"
	"os"
	"path"
	"syscall"
	"time"
)

const (
	DefaultHttpPort  = 80
	DefaultHttpsPort = 443

	// DefaultReadHeaderTimeout bounds how long a client may take to send its
	// request headers. Without it a handful of slowloris connections can hold
	// listener resources open indefinitely.
	DefaultReadHeaderTimeout = 30 * time.Second

	// DefaultIdleTimeout bounds how long an established keep-alive connection
	// may sit without carrying a request.
	DefaultIdleTimeout = 60 * time.Second

	// DefaultReadTimeout is disabled: it caps the time to read the *entire*
	// request, so any non-zero value truncates slow or large uploads passing
	// through the proxy.
	DefaultReadTimeout = 0

	// DefaultWriteTimeout is disabled: it caps the time to write the *entire*
	// response, so any non-zero value truncates SSE streams (see the
	// text/event-stream bypass in response_buffer_middleware.go) and long
	// downloads.
	DefaultWriteTimeout = 0
)

type Config struct {
	Bind         string
	HttpPort     int
	HttpsPort    int
	MetricsPort  int
	HTTP3Enabled bool

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration

	AlternateConfigDir string
}

func (c Config) SocketPath() string {
	return path.Join(c.runtimeDirectory(), "kamal-proxy.sock")
}

func (c Config) StatePath() string {
	return path.Join(c.dataDirectory(), "kamal-proxy.state")
}

func (c Config) CertificatePath() string {
	return path.Join(c.dataDirectory(), "certs")
}

// Private

func (c Config) runtimeDirectory() string {
	return cmp.Or(os.Getenv("XDG_RUNTIME_DIR"), os.TempDir())
}

func (c Config) dataDirectory() string {
	return cmp.Or(c.AlternateConfigDir, c.defaultDataDirectory())
}

func (c Config) defaultDataDirectory() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}

	dir := path.Join(home, ".config", "kamal-proxy")

	err = os.MkdirAll(dir, syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR)
	if err != nil {
		dir = os.TempDir()
	}

	return dir
}
