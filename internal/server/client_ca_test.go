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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testCA struct {
	certPath string
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
}

// generateTestCA writes a self-signed CA to a temp file and returns it, so tests
// can both point --tls-client-ca-path at it and mint client certificates under
// it. Nothing here touches the network.
func generateTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"kamal-proxy test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	certPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644))

	return &testCA{certPath: certPath, cert: cert, key: key}
}

// issueClientCertificate mints a client certificate signed by the CA.
func (ca *testCA) issueClientCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"kamal-proxy test client"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	return clientCert
}

func TestLoadClientCAs(t *testing.T) {
	ca := generateTestCA(t)

	t.Run("loads a PEM bundle", func(t *testing.T) {
		pool, err := loadClientCAs(ca.certPath)
		require.NoError(t, err)
		assert.NotNil(t, pool)
	})

	t.Run("reports a missing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "absent.pem")

		_, err := loadClientCAs(path)
		require.ErrorIs(t, err, ErrorUnableToLoadClientCACertificate)
		// The CLI only sees this string over RPC, so it has to name the file.
		assert.Contains(t, err.Error(), path)
	})

	t.Run("reports a file holding no certificates", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "garbage.pem")
		require.NoError(t, os.WriteFile(path, []byte("not a certificate"), 0644))

		_, err := loadClientCAs(path)
		require.ErrorIs(t, err, ErrorUnableToLoadClientCACertificate)
		assert.Contains(t, err.Error(), path)
	})
}
