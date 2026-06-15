package tlsreload

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewFileSourceRequiresPaths(t *testing.T) {
	_, err := NewFileSource(FileSourceConfig{})
	require.Error(t, err)
}

func TestFileSourceKeepsPreviousCertificateDuringPartialUpdate(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")

	cert1, key1 := mustGenerateTLSPair(t, "stable")
	cert2, key2 := mustGenerateTLSPair(t, "next")

	require.NoError(t, os.WriteFile(certFile, cert1, 0o600))
	require.NoError(t, os.WriteFile(keyFile, key1, 0o600))

	source, err := NewFileSource(FileSourceConfig{
		CertFile:      certFile,
		KeyFile:       keyFile,
		WatchInterval: 10 * time.Millisecond,
	})
	require.NoError(t, err)

	manager, err := NewManager(ctx, source, ManagerOptions{Watch: true, RetryInterval: 10 * time.Millisecond})
	require.NoError(t, err)
	defer manager.Close()

	initial, err := manager.GetCertificate(nil)
	require.NoError(t, err)
	require.Equal(t, initial.Certificate[0], mustParseKeyPair(t, cert1, key1).Certificate[0])

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
