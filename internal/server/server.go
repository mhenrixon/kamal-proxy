package server

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme"

	"github.com/basecamp/kamal-proxy/internal/metrics"
	"github.com/basecamp/kamal-proxy/internal/pages"
)

const (
	ACMEStagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type Server struct {
	config          *Config
	router          *Router
	httpListener    net.Listener
	httpsListener   net.Listener
	http3Listener   net.PacketConn
	metricsListener net.Listener
	httpServer      *http.Server
	httpsServer     *http.Server
	http3Server     *http3.Server
	metricsServer   *http.Server
	commandHandler  *CommandHandler
	drainOnce       sync.Once
	shutdownCh      chan struct{}
}

func NewServer(config *Config, router *Router) *Server {
	return &Server{
		config:     config,
		router:     router,
		shutdownCh: make(chan struct{}),
	}
}

// ShutdownRequested is closed once a drain has completed and the process
// should exit.
func (s *Server) ShutdownRequested() <-chan struct{} {
	return s.shutdownCh
}

// BeginDrain closes the public listeners, drains in-flight requests up to
// timeout, saves state, and signals the run loop to exit. Under SO_REUSEPORT a
// new generation holding the same ports keeps serving while this one leaves.
// The RPC socket and metrics server stay up so the caller's reply can flush
// and the drain remains observable; the run loop's deferred Stop tears them
// down. A second call is a no-op.
func (s *Server) BeginDrain(timeout time.Duration) error {
	if timeout <= 0 {
		timeout = cmp.Or(s.config.ShutdownTimeout, DefaultShutdownTimeout)
	}

	s.drainOnce.Do(func() {
		slog.Info("Draining", "timeout", timeout)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		PerformConcurrently(
			func() { s.router.DrainAll(timeout) },
			func() { s.stopHTTPServer(ctx, s.httpServer) },
			func() { s.stopHTTPServer(ctx, s.httpsServer) },
			func() {
				if s.http3Server != nil {
					s.stopHTTPServer(ctx, s.http3Server)
				}
			},
		)

		s.httpListener.Close()
		s.httpsListener.Close()
		if s.http3Listener != nil {
			s.http3Listener.Close()
		}

		_ = s.router.SaveState()

		slog.Info("Drained")

		// Give the RPC reply time to flush before the run loop tears down the
		// command socket.
		go func() {
			time.Sleep(250 * time.Millisecond)
			close(s.shutdownCh)
		}()
	})

	return nil
}

func (s *Server) Start() error {
	if err := s.startMetricsServer(); err != nil {
		return err
	}

	if err := s.startHTTPServers(); err != nil {
		return err
	}

	if err := s.startCommandHandler(); err != nil {
		return err
	}

	slog.Info("Server started", "http", s.HttpPort(), "https", s.HttpsPort())
	return nil
}

func (s *Server) Stop() {
	timeout := cmp.Or(s.config.ShutdownTimeout, DefaultShutdownTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	PerformConcurrently(
		func() { _ = s.commandHandler.Close() },
		func() { s.router.DrainAll(timeout) },
		func() { s.stopHTTPServer(ctx, s.httpServer) },
		func() { s.stopHTTPServer(ctx, s.httpsServer) },
		func() {
			if s.http3Server != nil {
				s.stopHTTPServer(ctx, s.http3Server)
			}
		},
		func() {
			if s.metricsServer != nil {
				s.stopHTTPServer(ctx, s.metricsServer)
			}
		},
	)

	s.httpListener.Close()
	s.httpsListener.Close()

	if s.http3Listener != nil {
		s.http3Listener.Close()
	}
	if s.metricsListener != nil {
		s.metricsListener.Close()
	}

	// Flush routing state so the next boot restores exactly what was serving,
	// even if a mutation raced the last deferred save.
	_ = s.router.SaveState()

	slog.Info("Server stopped")
}

func (s *Server) HttpPort() int {
	return s.httpListener.Addr().(*net.TCPAddr).Port
}

func (s *Server) HttpsPort() int {
	return s.httpsListener.Addr().(*net.TCPAddr).Port
}

// Private

// listen creates a TCP listener, optionally with SO_REUSEPORT so an
// overlapping proxy generation can bind the same address during a handoff.
func (s *Server) listen(network, addr string) (net.Listener, error) {
	if s.config.ReusePort {
		lc := net.ListenConfig{Control: reusePortControl}
		return lc.Listen(context.Background(), network, addr)
	}
	return net.Listen(network, addr)
}

func (s *Server) listenPacket(network, addr string) (net.PacketConn, error) {
	if s.config.ReusePort {
		lc := net.ListenConfig{Control: reusePortControl}
		return lc.ListenPacket(context.Background(), network, addr)
	}
	return net.ListenPacket(network, addr)
}

// newHTTPServer builds an http.Server carrying the configured connection
// timeouts. Every listener shares one timeout policy so none of them is left
// unbounded.
func (s *Server) newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: s.config.ReadHeaderTimeout,
		ReadTimeout:       s.config.ReadTimeout,
		WriteTimeout:      s.config.WriteTimeout,
		IdleTimeout:       s.config.IdleTimeout,
	}
}

func (s *Server) startHTTP3Server(handler http.Handler, httpsAddr string) error {
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")

	http3Listener, err := s.listenPacket("udp", httpsAddr)
	if err != nil {
		return err
	}

	s.http3Listener = http3Listener
	s.http3Server = &http3.Server{
		Handler:     handler,
		IdleTimeout: s.config.IdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS13,
			NextProtos:     []string{"h3"},
			GetCertificate: s.router.GetCertificate,
		},
	}

	go s.http3Server.Serve(s.http3Listener)
	return nil
}

func (s *Server) startHTTPServers() error {
	// Parsed before the enabled check, so a typo fails the boot rather than
	// waiting until someone turns PROXY protocol on.
	proxyProtocolAllowed, err := parseIPPrefixes(s.config.ProxyProtocolAllowIPs, "proxy-protocol-allow-ip")
	if err != nil {
		return err
	}

	httpAddr := fmt.Sprintf("%s:%d", s.config.Bind, s.config.HttpPort)
	httpsAddr := fmt.Sprintf("%s:%d", s.config.Bind, s.config.HttpsPort)

	handler := s.buildHandler()

	httpListener, err := s.listen("tcp", httpAddr)
	if err != nil {
		return err
	}
	if s.config.ProxyProtocol {
		httpListener = withProxyProtocol(httpListener, proxyProtocolAllowed, s.config.ReadHeaderTimeout)
	}
	s.httpListener = httpListener
	s.httpServer = s.newHTTPServer(handler)

	httpsListener, err := s.listen("tcp", httpsAddr)
	if err != nil {
		return err
	}
	if s.config.ProxyProtocol {
		httpsListener = withProxyProtocol(httpsListener, proxyProtocolAllowed, s.config.ReadHeaderTimeout)
	}
	s.httpsListener = httpsListener
	s.httpsServer = s.newHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config.HTTP3Enabled {
			s.http3Server.SetQUICHeaders(w.Header())
		}

		handler.ServeHTTP(w, r)
	}))
	s.httpsServer.TLSConfig = &tls.Config{
		NextProtos:     []string{"h2", "http/1.1", acme.ALPNProto},
		GetCertificate: s.router.GetCertificate,
	}

	if s.config.ProxyProtocol {
		slog.Info("PROXY protocol enabled", "allow", s.config.ProxyProtocolAllowIPs)

		if s.config.HTTP3Enabled {
			// The stream-based PROXY protocol cannot cover the UDP listener, so
			// clients negotiating HTTP/3 are seen at the balancer's address while
			// their TCP requests carry the restored one.
			slog.Warn("HTTP/3 requests bypass PROXY protocol; their client addresses will be the load balancer's")
		}
	}

	go s.httpServer.Serve(s.httpListener)
	go s.httpsServer.ServeTLS(s.httpsListener, "", "")

	if s.config.HTTP3Enabled {
		http3Addr := httpsListener.Addr().String()
		err = s.startHTTP3Server(handler, http3Addr)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) startMetricsServer() error {
	// Parsed before the disabled check, so a typo fails the boot rather than
	// waiting until someone turns metrics on.
	allowed, err := parseIPPrefixes(s.config.MetricsAllowIPs, "metrics-allow-ip")
	if err != nil {
		return err
	}

	if s.config.MetricsPort == 0 {
		slog.Debug("Metrics server disabled")
		return nil
	}

	addr := fmt.Sprintf("%s:%d", s.config.Bind, s.config.MetricsPort)
	handler := withMetricsAllowList(allowed, metrics.Enable())

	l, err := s.listen("tcp", addr)
	if err != nil {
		return err
	}
	s.metricsListener = l
	s.metricsServer = s.newHTTPServer(handler)
	s.metricsServer.Addr = addr

	go s.metricsServer.Serve(s.metricsListener)

	slog.Info("Metrics enabled", "address", addr)

	return nil
}

func (s *Server) startCommandHandler() error {
	s.commandHandler = NewCommandHandler(s.router)
	s.commandHandler.server = s
	_ = os.Remove(s.config.SocketPath())

	return s.commandHandler.Start(s.config.SocketPath())
}

func (s *Server) buildHandler() http.Handler {
	var handler http.Handler

	// Note: handlers are executed in the inverse order.
	handler = s.router
	handler, _ = WithErrorPageMiddleware(pages.DefaultErrorPages, true, handler)
	handler = WithLoggingMiddleware(slog.Default(), s.config.HttpPort, s.config.HttpsPort, handler)
	handler = WithRequestIDMiddleware(handler)
	handler = WithRequestStartMiddleware(handler)

	// Intercept ACME HTTP-01 challenges before other handlers
	if sanManager := s.router.SANCertManager(); sanManager != nil {
		handler = sanManager.HTTPHandler(handler)
	}

	// Mount the domain refresh nudge and pre-flight probe endpoints
	if dynamicDomains := s.router.DynamicDomainManager(); dynamicDomains != nil {
		handler = dynamicDomains.WrapHandler(handler)
	}

	return handler
}

type shutdownable interface {
	Shutdown(ctx context.Context) error
}

func (s *Server) stopHTTPServer(ctx context.Context, server shutdownable) {
	if server != nil {
		err := server.Shutdown(ctx)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				slog.Warn("Closing active connections")
			} else {
				slog.Error("Error while attempting to stop server", "error", err)
			}
		}
	}
}
