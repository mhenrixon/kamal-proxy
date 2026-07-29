package server

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

var ErrorUnableToLoadClientCACertificate = errors.New("unable to load client CA certificate")

// loadClientCAs reads a PEM bundle of certificate authorities used to verify
// client certificates (mTLS). The error names the path, because a deploy failure
// reaches the CLI as a bare string over net/rpc.
func loadClientCAs(path string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w %q: %w", ErrorUnableToLoadClientCACertificate, path, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("%w %q: no PEM certificates found", ErrorUnableToLoadClientCACertificate, path)
	}

	return pool, nil
}
