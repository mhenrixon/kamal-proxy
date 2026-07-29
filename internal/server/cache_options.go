package server

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

// A shared response cache lets a fleet of proxies answer a hot URL without each
// node re-fetching it once per TTL. Storing is strictly opt-in twice over: the
// service must be deployed with --cache, and the target must mark the response
// `public` with a lifetime. See cache_policy.go for the rules and
// cache_middleware.go for how a stored response is served.

const (
	// DefaultCacheMaxBodySize bounds a single stored response. Bodies past it
	// stream to the client as usual and are simply not stored -- a cache is a
	// latency optimization, not a file server.
	DefaultCacheMaxBodySize = 8 * MB

	// DefaultCacheMaxVariants bounds how many representations one resource may
	// hold. It exists because the proxy can normalize exactly one Vary dimension
	// -- Accept-Encoding, because it understands content codings. Every other
	// dimension is keyed on whatever the client sent, so an app varying on a
	// high-entropy header would otherwise fill the cache with near-duplicates
	// and evict entries that were earning their place.
	DefaultCacheMaxVariants = 32

	// DefaultCacheRevalidateTimeout bounds a background stale-while-revalidate
	// fetch. It runs with no client attached, so nothing else would ever stop it.
	DefaultCacheRevalidateTimeout = 30 * time.Second

	// acceptEncodingHeader is the one Vary dimension the key deliberately does
	// not carry. The cache stores the representation the target produced and
	// sits inside the compression middleware, so every response is encoded for
	// its own client on the way out -- one stored entry serves them all. A
	// response the target encoded itself is refused instead, in
	// responseIsStorable, because that one really is encoding-specific.
	acceptEncodingHeader = "accept-encoding"
)

// CacheOptions is the per-service cache configuration. A zero value means the
// cache is off, which is what every service that predates this feature restores
// from its state file.
type CacheOptions struct {
	// Enabled opts this service into the response cache. Nothing is stored
	// without it, whatever the target's headers say.
	Enabled bool `json:"enabled,omitempty"`
	// MaxBodySize is the largest response body that will be stored. Zero means
	// DefaultCacheMaxBodySize, not "unlimited".
	MaxBodySize int64 `json:"max_body_size,omitempty"`
	// MaxTTL caps the lifetime the target asks for, so a mistaken s-maxage of a
	// year cannot pin content until the next restart. Zero means no cap.
	MaxTTL time.Duration `json:"max_ttl,omitempty"`
	// VaryHeaders are request headers the cache key is computed over, beyond
	// Accept-Encoding. A response that varies on anything not listed here is
	// passed through rather than stored -- see responseIsStorable.
	VaryHeaders []string `json:"vary_headers,omitempty"`
	// VaryCookies are cookie names the cache key is computed over, for apps that
	// serve different content per cookie without saying so in Vary.
	VaryCookies []string `json:"vary_cookies,omitempty"`
	// AllowSetCookie permits storing a response that carries Set-Cookie. Off by
	// default: a shared cache replaying one client's cookie to the next is the
	// worst thing this feature could do.
	AllowSetCookie bool `json:"allow_set_cookie,omitempty"`
	// MaxVariants bounds how many representations one resource may hold when it
	// negotiates. Zero means DefaultCacheMaxVariants. Negative switches
	// automatic variants off entirely, restoring the older behaviour where a
	// response varying on anything undeclared was refused outright.
	MaxVariants int `json:"max_variants,omitempty"`
}

func (co *CacheOptions) Normalize() {
	co.VaryHeaders = normalizeLowercaseNames(co.VaryHeaders)
	co.VaryCookies = normalizeCookieNames(co.VaryCookies)
}

func (co CacheOptions) Validate() error {
	co.Normalize()

	if !co.Enabled {
		switch {
		case co.MaxBodySize != 0:
			return fmt.Errorf("%w: cache-max-body requires cache", ErrServiceOptionsInvalid)
		case co.MaxTTL != 0:
			return fmt.Errorf("%w: cache-max-ttl requires cache", ErrServiceOptionsInvalid)
		case len(co.VaryHeaders) > 0:
			return fmt.Errorf("%w: cache-vary-header requires cache", ErrServiceOptionsInvalid)
		case len(co.VaryCookies) > 0:
			return fmt.Errorf("%w: cache-vary-cookie requires cache", ErrServiceOptionsInvalid)
		case co.AllowSetCookie:
			return fmt.Errorf("%w: cache-allow-set-cookie requires cache", ErrServiceOptionsInvalid)
		case co.MaxVariants != 0:
			return fmt.Errorf("%w: cache-max-variants requires cache", ErrServiceOptionsInvalid)
		}
		return nil
	}

	if co.MaxBodySize < 0 {
		return fmt.Errorf("%w: cache-max-body cannot be negative, got %d", ErrServiceOptionsInvalid, co.MaxBodySize)
	}

	if co.MaxTTL < 0 {
		return fmt.Errorf("%w: cache-max-ttl cannot be negative, got %s", ErrServiceOptionsInvalid, co.MaxTTL)
	}

	for _, name := range co.VaryHeaders {
		if !httpguts.ValidHeaderFieldName(name) {
			return fmt.Errorf("%w: cache-vary-header must be a header name, got %q", ErrServiceOptionsInvalid, name)
		}
	}

	for _, name := range co.VaryCookies {
		if !validCookieName(name) {
			return fmt.Errorf("%w: cache-vary-cookie must be a cookie name, got %q", ErrServiceOptionsInvalid, name)
		}
	}

	return nil
}

// Private

func (co CacheOptions) maxBodySize() int64 {
	if co.MaxBodySize <= 0 {
		return DefaultCacheMaxBodySize
	}
	return co.MaxBodySize
}

// coversVaryField reports whether the primary key already carries a Vary field,
// in which case keying a variant on it too would cost a second lookup for
// nothing.
func (co CacheOptions) coversVaryField(field string) bool {
	return slices.Contains(co.VaryHeaders, field)
}

// automaticVary reports whether a response may be keyed on fields the operator
// did not name. Off restores the older behaviour exactly.
func (co CacheOptions) automaticVary() bool {
	return co.MaxVariants >= 0
}

func (co CacheOptions) maxVariants() int {
	if co.MaxVariants <= 0 {
		return DefaultCacheMaxVariants
	}
	return co.MaxVariants
}

func normalizeLowercaseNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || slices.Contains(normalized, name) {
			continue
		}
		normalized = append(normalized, name)
	}

	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

// normalizeCookieNames keeps the case an operator wrote: cookie names are
// case-sensitive, unlike header field names.
func normalizeCookieNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || slices.Contains(normalized, name) {
			continue
		}
		normalized = append(normalized, name)
	}

	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

// validCookieName applies RFC 6265's token rule, which is the same grammar a
// header field name uses.
func validCookieName(name string) bool {
	return name != "" && httpguts.ValidHeaderFieldName(name)
}
