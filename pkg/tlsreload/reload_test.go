package tlsreload

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/require"
)

func TestNewRequiresPaths(t *testing.T) {
	_, err := New(t.Context(), Config{Enabled: true}, Options{})
	require.Error(t, err)
}

func TestMustNewPanicsWhenTLSFilesAreMissing(t *testing.T) {
	require.Panics(t, func() {
		MustNew(t.Context(), Config{Enabled: true}, Options{})
	})
}

func TestNewNormalizesPaths(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	cert, key := mustGenerateTLSPair(t, "normalized")
	require.NoError(t, os.WriteFile(certFile, cert, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key, 0o600))

	manager, err := New(t.Context(), Config{
		Enabled:  true,
		CertFile: " " + certFile + " ",
		KeyFile:  " " + keyFile + " ",
	}, Options{})
	require.NoError(t, err)
	defer manager.Close()

	require.Equal(t, certFile, manager.certFile)
	require.Equal(t, keyFile, manager.keyFile)
}

func TestMustNewReturnsEnabledManager(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	cert, key := mustGenerateTLSPair(t, "must-new")
	require.NoError(t, os.WriteFile(certFile, cert, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key, 0o600))

	manager := MustNew(t.Context(), Config{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}, Options{})
	defer manager.Close()

	current, err := manager.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, current)
}

func TestNewRejectsURIPaths(t *testing.T) {
	_, err := New(t.Context(), Config{
		Enabled:  true,
		CertFile: "file:///cert.pem",
		KeyFile:  "key.pem",
	}, Options{})
	require.Error(t, err)
}

func TestNewRejectsNegativePollInterval(t *testing.T) {
	_, err := New(t.Context(), Config{
		Enabled:      true,
		CertFile:     "cert.pem",
		KeyFile:      "key.pem",
		PollInterval: -time.Second,
	}, Options{})
	require.Error(t, err)
}

func TestManagerReloadsCertificateFromFileEvent(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	cert1, key1 := mustGenerateTLSPair(t, "one")
	cert2, key2 := mustGenerateTLSPair(t, "two")
	require.NoError(t, os.WriteFile(certFile, cert1, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key1, 0o600))

	manager, err := New(t.Context(), Config{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}, Options{})
	require.NoError(t, err)
	defer manager.Close()

	initial, err := manager.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, initial.Certificate[0], mustParseKeyPair(t, cert1, key1).Certificate[0])

	require.NoError(t, os.WriteFile(certFile, cert2, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key2, 0o600))

	require.Eventually(t, func() bool {
		current, err := manager.GetCertificate(nil)
		require.NoError(t, err)
		return string(current.Certificate[0]) == string(mustParseKeyPair(t, cert2, key2).Certificate[0])
	}, 2*time.Second, 10*time.Millisecond)
}

func TestManagerReloadsCertificateFromFallbackPoll(t *testing.T) {
	disableFSWatcher(t)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	cert1, key1 := mustGenerateTLSPair(t, "one")
	cert2, key2 := mustGenerateTLSPair(t, "two")
	require.NoError(t, os.WriteFile(certFile, cert1, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key1, 0o600))

	manager, err := New(t.Context(), Config{
		Enabled:      true,
		CertFile:     certFile,
		KeyFile:      keyFile,
		PollInterval: 10 * time.Millisecond,
	}, Options{
		RetryInterval: 10 * time.Millisecond,
	})
	require.NoError(t, err)
	defer manager.Close()

	initial, err := manager.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, initial.Certificate[0], mustParseKeyPair(t, cert1, key1).Certificate[0])

	require.NoError(t, os.WriteFile(certFile, cert2, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key2, 0o600))

	require.Eventually(t, func() bool {
		current, err := manager.GetCertificate(nil)
		require.NoError(t, err)
		return string(current.Certificate[0]) == string(mustParseKeyPair(t, cert2, key2).Certificate[0])
	}, time.Second, 10*time.Millisecond)
}

func TestManagerKeepsPreviousCertificateOnInvalidReload(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	cert1, key1 := mustGenerateTLSPair(t, "stable")
	require.NoError(t, os.WriteFile(certFile, cert1, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key1, 0o600))

	manager, err := New(t.Context(), Config{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}, Options{})
	require.NoError(t, err)
	defer manager.Close()

	previous, err := manager.GetCertificate(nil)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(certFile, []byte("bad cert"), 0o600))
	require.NoError(t, os.WriteFile(keyFile, []byte("bad key"), 0o600))

	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		current, err := manager.GetCertificate(nil)
		require.NoError(t, err)
		require.Equal(t, previous.Certificate[0], current.Certificate[0])
		time.Sleep(10 * time.Millisecond)
	}
}

func TestManagerKeepsPreviousCertificateDuringPartialUpdate(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	cert1, key1 := mustGenerateTLSPair(t, "stable")
	cert2, key2 := mustGenerateTLSPair(t, "next")
	require.NoError(t, os.WriteFile(certFile, cert1, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key1, 0o600))

	manager, err := New(t.Context(), Config{
		Enabled:      true,
		CertFile:     certFile,
		KeyFile:      keyFile,
		PollInterval: 10 * time.Millisecond,
	}, Options{
		RetryInterval: 10 * time.Millisecond,
	})
	require.NoError(t, err)
	defer manager.Close()

	initial, err := manager.GetCertificate(nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certFile, cert2, 0o600))
	time.Sleep(50 * time.Millisecond)

	duringMismatch, err := manager.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, initial.Certificate[0], duringMismatch.Certificate[0])

	require.NoError(t, os.WriteFile(keyFile, key2, 0o600))
	require.Eventually(t, func() bool {
		current, err := manager.GetCertificate(nil)
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

	manager, err := New(t.Context(), Config{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}, Options{})
	require.NoError(t, err)
	defer manager.Close()

	require.NoError(t, os.WriteFile(certFile, cert2, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key2, 0o600))
	require.NoError(t, manager.Reload(t.Context()))

	current, err := manager.GetCertificate(nil)
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

	manager, err := New(t.Context(), Config{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}, Options{
		MinVersion: tls.VersionTLS13,
	})
	require.NoError(t, err)
	defer manager.Close()

	cfg := manager.TLSConfig()
	require.NotNil(t, cfg.GetCertificate)
	require.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
}

func disableFSWatcher(t *testing.T) {
	t.Helper()

	previous := newFSNotifyWatcher
	newFSNotifyWatcher = func() (*fsnotify.Watcher, error) {
		return nil, errors.New("fsnotify disabled for test")
	}
	t.Cleanup(func() {
		newFSNotifyWatcher = previous
	})
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
