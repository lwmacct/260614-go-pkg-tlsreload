package tlsreload

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestManagerReloadsCertificate(t *testing.T) {
	ctx := t.Context()

	cert1, key1 := mustGenerateTLSPair(t, "one")
	cert2, key2 := mustGenerateTLSPair(t, "two")

	source := newStubSource(SourceData{
		CertPEM: cert1,
		KeyPEM:  key1,
		Version: "1",
	})

	manager, err := NewManager(ctx, source, ManagerOptions{Watch: true, RetryInterval: 10 * time.Millisecond})
	require.NoError(t, err)
	defer manager.Close()

	initial, err := manager.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, initial.Certificate[0], mustParseKeyPair(t, cert1, key1).Certificate[0])

	source.setData(SourceData{
		CertPEM: cert2,
		KeyPEM:  key2,
		Version: "2",
	})
	source.notify("2")

	require.Eventually(t, func() bool {
		current, err := manager.GetCertificate(nil)
		require.NoError(t, err)
		return string(current.Certificate[0]) == string(mustParseKeyPair(t, cert2, key2).Certificate[0])
	}, time.Second, 10*time.Millisecond)
}

func TestManagerKeepsPreviousCertificateOnInvalidReload(t *testing.T) {
	ctx := t.Context()

	cert1, key1 := mustGenerateTLSPair(t, "stable")
	source := newStubSource(SourceData{
		CertPEM: cert1,
		KeyPEM:  key1,
		Version: "1",
	})

	manager, err := NewManager(ctx, source, ManagerOptions{Watch: true, RetryInterval: 10 * time.Millisecond})
	require.NoError(t, err)
	defer manager.Close()

	previous, err := manager.GetCertificate(nil)
	require.NoError(t, err)

	source.setData(SourceData{
		CertPEM: []byte("bad cert"),
		KeyPEM:  []byte("bad key"),
		Version: "2",
	})
	source.notify("2")

	time.Sleep(50 * time.Millisecond)

	current, err := manager.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, previous.Certificate[0], current.Certificate[0])
}

func TestNewManagerRequiresSource(t *testing.T) {
	_, err := NewManager(t.Context(), nil, ManagerOptions{})
	require.Error(t, err)
}

type stubSource struct {
	mu      sync.RWMutex
	data    SourceData
	changes chan string
}

func newStubSource(data SourceData) *stubSource {
	return &stubSource{
		data:    data,
		changes: make(chan string, 8),
	}
}

func (s *stubSource) Name() string { return "stub" }

func (s *stubSource) Load(context.Context) (SourceData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data, nil
}

func (s *stubSource) Watch(ctx context.Context, _ string, notify func(nextVersion string)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case version := <-s.changes:
			notify(version)
		}
	}
}

func (s *stubSource) Close() error { return nil }

func (s *stubSource) setData(data SourceData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = data
}

func (s *stubSource) notify(version string) {
	s.changes <- version
}

func mustGenerateTLSPair(t *testing.T, commonName string) ([]byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func mustParseKeyPair(t *testing.T, certPEM, keyPEM []byte) tls.Certificate {
	t.Helper()
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return certificate
}
