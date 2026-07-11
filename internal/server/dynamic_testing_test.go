package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/stretchr/testify/require"
)

// testSANCertManager returns a ready manager pointed at staging with temp storage.
// It has no ACME client; tests must not exercise paths that call it.
func testSANCertManager(t testing.TB) *SANCertManager {
	t.Helper()

	tmpDir := t.TempDir()
	manager, err := NewSANCertManager(SANCertManagerConfig{
		Email:     "test@example.com",
		Directory: LetsEncryptStaging,
		CachePath: filepath.Join(tmpDir, "certs"),
		StatePath: filepath.Join(tmpDir, "acme.state"),
	})
	require.NoError(t, err)

	manager.ready = true
	return manager
}

// testSelfSignedCert builds a self-signed certificate for the given domains and
// validity window, with the leaf parsed and attached.
func testSelfSignedCert(t testing.TB, domains []string, notBefore, notAfter time.Time) *tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domains[0]},
		DNSNames:              domains,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// testCertResource builds a lego certificate.Resource backed by a self-signed
// certificate, as the ACME client would return it.
func testCertResource(t testing.TB, domains []string, notBefore, notAfter time.Time) *certificate.Resource {
	t.Helper()

	cert := testSelfSignedCert(t, domains, notBefore, notAfter)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})

	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &certificate.Resource{Domain: domains[0], Certificate: certPEM, PrivateKey: keyPEM}
}

// fakeObtainer records Obtain calls and delegates to a configurable response.
type fakeObtainer struct {
	mu      sync.Mutex
	calls   []certificate.ObtainRequest
	respond func(request certificate.ObtainRequest) (*certificate.Resource, error)
}

func (f *fakeObtainer) Obtain(request certificate.ObtainRequest) (*certificate.Resource, error) {
	f.mu.Lock()
	f.calls = append(f.calls, request)
	f.mu.Unlock()

	return f.respond(request)
}

func (f *fakeObtainer) Calls() []certificate.ObtainRequest {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]certificate.ObtainRequest{}, f.calls...)
}

// successfulObtainer issues a self-signed certificate for whatever is asked.
func successfulObtainer(t testing.TB) *fakeObtainer {
	return &fakeObtainer{
		respond: func(request certificate.ObtainRequest) (*certificate.Resource, error) {
			return testCertResource(t, request.Domains, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour)), nil
		},
	}
}
