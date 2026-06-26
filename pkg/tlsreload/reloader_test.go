package tlsreload

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewRequiresPaths(t *testing.T) {
	_, err := New(t.Context(), Config{})
	require.Error(t, err)
}

func TestMustNewPanicsOnError(t *testing.T) {
	require.Panics(t, func() {
		MustNew(t.Context(), Config{})
	})
}

func TestNewNormalizesPaths(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	cert, key := mustGenerateTLSPair(t, "normalized")
	require.NoError(t, os.WriteFile(certFile, cert, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key, 0o600))

	reloader, err := New(t.Context(), Config{
		CertFile: " " + certFile + " ",
		KeyFile:  " " + keyFile + " ",
	})
	require.NoError(t, err)
	defer reloader.Close()

	require.Equal(t, certFile, reloader.certFile)
	require.Equal(t, keyFile, reloader.keyFile)
}

func TestMustNewReturnsReloader(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	cert, key := mustGenerateTLSPair(t, "must-new")
	require.NoError(t, os.WriteFile(certFile, cert, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key, 0o600))

	reloader := MustNew(t.Context(), Config{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	defer reloader.Close()

	current, err := reloader.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, current)
}

func TestNewRejectsURIPaths(t *testing.T) {
	_, err := New(t.Context(), Config{
		CertFile: "file:///cert.pem",
		KeyFile:  "key.pem",
	})
	require.Error(t, err)
}

func TestNewRejectsNegativeReloadInterval(t *testing.T) {
	_, err := New(t.Context(), Config{
		CertFile:       "cert.pem",
		KeyFile:        "key.pem",
		ReloadInterval: -time.Second,
	})
	require.Error(t, err)
}

func TestReloaderReloadsCertificateFromFileEvent(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	cert1, key1 := mustGenerateTLSPair(t, "one")
	cert2, key2 := mustGenerateTLSPair(t, "two")
	require.NoError(t, os.WriteFile(certFile, cert1, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key1, 0o600))

	reloader, err := New(t.Context(), Config{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.NoError(t, err)
	defer reloader.Close()

	initial, err := reloader.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, initial.Certificate[0], mustParseKeyPair(t, cert1, key1).Certificate[0])

	require.NoError(t, os.WriteFile(certFile, cert2, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key2, 0o600))

	require.Eventually(t, func() bool {
		current, err := reloader.GetCertificate(nil)
		require.NoError(t, err)
		return string(current.Certificate[0]) == string(mustParseKeyPair(t, cert2, key2).Certificate[0])
	}, 2*time.Second, 10*time.Millisecond)
}

func TestReloaderReloadsCertificateFromFallbackPoll(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	cert1, key1 := mustGenerateTLSPair(t, "one")
	cert2, key2 := mustGenerateTLSPair(t, "two")
	require.NoError(t, os.WriteFile(certFile, cert1, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key1, 0o600))

	reloader, err := New(t.Context(), Config{
		CertFile:       certFile,
		KeyFile:        keyFile,
		ReloadInterval: 10 * time.Millisecond,
		RetryInterval:  10 * time.Millisecond,
	})
	require.NoError(t, err)
	defer reloader.Close()
	require.NoError(t, reloader.watcher.Close())
	reloader.watcher = nil

	initial, err := reloader.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, initial.Certificate[0], mustParseKeyPair(t, cert1, key1).Certificate[0])

	require.NoError(t, os.WriteFile(certFile, cert2, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key2, 0o600))

	require.Eventually(t, func() bool {
		current, err := reloader.GetCertificate(nil)
		require.NoError(t, err)
		return string(current.Certificate[0]) == string(mustParseKeyPair(t, cert2, key2).Certificate[0])
	}, time.Second, 10*time.Millisecond)
}

func TestReloaderKeepsPreviousCertificateOnInvalidReload(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	cert1, key1 := mustGenerateTLSPair(t, "stable")
	require.NoError(t, os.WriteFile(certFile, cert1, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key1, 0o600))

	reloader, err := New(t.Context(), Config{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.NoError(t, err)
	defer reloader.Close()

	previous, err := reloader.GetCertificate(nil)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(certFile, []byte("bad cert"), 0o600))
	require.NoError(t, os.WriteFile(keyFile, []byte("bad key"), 0o600))

	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		current, err := reloader.GetCertificate(nil)
		require.NoError(t, err)
		require.Equal(t, previous.Certificate[0], current.Certificate[0])
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReloaderKeepsPreviousCertificateDuringPartialUpdate(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	cert1, key1 := mustGenerateTLSPair(t, "stable")
	cert2, key2 := mustGenerateTLSPair(t, "next")
	require.NoError(t, os.WriteFile(certFile, cert1, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key1, 0o600))

	reloader, err := New(t.Context(), Config{
		CertFile:       certFile,
		KeyFile:        keyFile,
		ReloadInterval: 10 * time.Millisecond,
		RetryInterval:  10 * time.Millisecond,
	})
	require.NoError(t, err)
	defer reloader.Close()

	initial, err := reloader.GetCertificate(nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certFile, cert2, 0o600))
	time.Sleep(50 * time.Millisecond)

	duringMismatch, err := reloader.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, initial.Certificate[0], duringMismatch.Certificate[0])

	require.NoError(t, os.WriteFile(keyFile, key2, 0o600))
	require.Eventually(t, func() bool {
		current, err := reloader.GetCertificate(nil)
		require.NoError(t, err)
		return string(current.Certificate[0]) == string(mustParseKeyPair(t, cert2, key2).Certificate[0])
	}, time.Second, 10*time.Millisecond)
}

func TestManualReload(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	cert1, key1 := mustGenerateTLSPair(t, "one")
	cert2, key2 := mustGenerateTLSPair(t, "two")
	require.NoError(t, os.WriteFile(certFile, cert1, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key1, 0o600))

	reloader, err := New(t.Context(), Config{
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.NoError(t, err)
	defer reloader.Close()

	require.NoError(t, os.WriteFile(certFile, cert2, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key2, 0o600))
	require.NoError(t, reloader.Reload(t.Context()))

	current, err := reloader.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, mustParseKeyPair(t, cert2, key2).Certificate[0], current.Certificate[0])
}

func TestTLSConfigUsesConfiguredMinVersion(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	cert, key := mustGenerateTLSPair(t, "tls-config")
	require.NoError(t, os.WriteFile(certFile, cert, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key, 0o600))

	reloader, err := New(t.Context(), Config{
		CertFile:   certFile,
		KeyFile:    keyFile,
		MinVersion: tls.VersionTLS13,
	})
	require.NoError(t, err)
	defer reloader.Close()

	cfg := reloader.TLSConfig()
	require.NotNil(t, cfg.GetCertificate)
	require.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
}

func mustGenerateTLSPair(t *testing.T, commonName string) ([]byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          mustRandomSerial(t),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pemEncode("CERTIFICATE", der)
	keyPEM := pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	return certPEM, keyPEM
}

func mustRandomSerial(t *testing.T) *big.Int {
	t.Helper()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	return serial
}

func pemEncode(blockType string, bytes []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: bytes})
}

func mustParseKeyPair(t *testing.T, certPEM, keyPEM []byte) tls.Certificate {
	t.Helper()
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return certificate
}
