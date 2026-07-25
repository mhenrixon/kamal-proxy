package server

import (
	"slices"
	"strings"
	"time"
)

// PathTimeout overrides a timeout for requests below a path prefix. A zero
// Timeout disables the timeout for that prefix, rather than falling back to the
// service-wide value.
type PathTimeout struct {
	PathPrefix string        `json:"path_prefix"`
	Timeout    time.Duration `json:"timeout"`
}

// NormalizePathTimeouts canonicalizes the prefixes the same way service path
// prefixes are canonicalized, and orders them longest-first so that
// ResolvePathTimeout can return the most specific match without sorting on
// every request.
func NormalizePathTimeouts(pathTimeouts []PathTimeout) []PathTimeout {
	if len(pathTimeouts) == 0 {
		return nil
	}

	normalized := make([]PathTimeout, len(pathTimeouts))
	for i, pathTimeout := range pathTimeouts {
		normalized[i] = PathTimeout{
			PathPrefix: "/" + strings.Trim(pathTimeout.PathPrefix, "/"),
			Timeout:    pathTimeout.Timeout,
		}
	}

	slices.SortFunc(normalized, func(a, b PathTimeout) int {
		if diff := len(b.PathPrefix) - len(a.PathPrefix); diff != 0 {
			return diff
		}
		return strings.Compare(a.PathPrefix, b.PathPrefix)
	})

	return normalized
}

// ResolvePathTimeout returns the timeout for path, preferring the most specific
// matching prefix and falling back to fallback when nothing matches.
// pathTimeouts must already be normalized.
func ResolvePathTimeout(path string, pathTimeouts []PathTimeout, fallback time.Duration) time.Duration {
	for _, pathTimeout := range pathTimeouts {
		if strings.HasPrefix(EnsureTrailingSlash(path), EnsureTrailingSlash(pathTimeout.PathPrefix)) {
			return pathTimeout.Timeout
		}
	}

	return fallback
}
