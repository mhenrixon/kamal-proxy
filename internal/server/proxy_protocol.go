package server

import (
	"net"
	"net/netip"
	"time"

	"github.com/pires/go-proxyproto"
)

// withProxyProtocol wraps a TCP listener so connections may open with a PROXY
// protocol v1/v2 preamble, restoring the client address an L4 load balancer
// hop would otherwise hide. The preamble is optional: connections without one
// keep their TCP peer address, so load balancer health checks and direct
// probes keep working.
//
// The wrap must sit on the raw TCP listener, before any TLS layering: the
// preamble arrives ahead of the ClientHello, and ServeTLS builds its TLS
// listener on top of whatever listener it is handed.
//
// The wrapped connections expose no CloseWrite, so on the plain-HTTP listener
// net/http skips its graceful half-close when replying to a request whose
// body was never consumed (a 413 or an allow-ip 403 on an upload); such a
// client may see a reset before it reads the error response. TLS connections
// are unaffected -- tls.Conn layers its own CloseWrite above the wrapper.
//
// readHeaderTimeout bounds how long a connection may take to send the
// preamble. Zero falls back to the library's 10s default rather than waiting
// forever -- the HTTP read-header timeout being disabled is no reason to let a
// half-open connection pin a goroutine during header detection.
func withProxyProtocol(listener net.Listener, allowed []netip.Prefix, readHeaderTimeout time.Duration) net.Listener {
	return &proxyproto.Listener{
		Listener:          listener,
		ConnPolicy:        proxyProtocolPolicy(allowed),
		ReadHeaderTimeout: readHeaderTimeout,
	}
}

// proxyProtocolPolicy decides, per connection, whether the peer may assert a
// client address via a PROXY preamble.
//
// An empty allow list trusts every peer -- only safe when nothing but the
// load balancer can reach the port. Otherwise a peer inside the list has its
// preamble honoured (USE) while any other peer has it read and discarded
// (IGNORE): the connection is still served on its real address, so an
// untrusted client can neither spoof an address nor learn that a filter
// exists. An unparseable peer address is treated as untrusted, matching the
// zero-Addr-denies rule the allow-ip filter uses.
func proxyProtocolPolicy(allowed []netip.Prefix) proxyproto.ConnPolicyFunc {
	return func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
		if len(allowed) == 0 {
			return proxyproto.USE, nil
		}

		peer := parseHostAddr(opts.Upstream.String())
		if peer.IsValid() && containsAddr(allowed, peer) {
			return proxyproto.USE, nil
		}

		return proxyproto.IGNORE, nil
	}
}
