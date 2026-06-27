package tlsreload

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{name: "disabled"},
		{
			name: "enabled reload without fallback poll",
			config: Config{
				Enabled:  true,
				CertFile: "cert.pem",
				KeyFile:  "key.pem",
			},
		},
		{
			name: "enabled reload",
			config: Config{
				Enabled:  true,
				CertFile: "cert.pem",
				KeyFile:  "key.pem",
				Interval: time.Second,
			},
		},
		{
			name: "cert without key",
			config: Config{
				Enabled:  true,
				CertFile: "cert.pem",
			},
			wantErr: true,
		},
		{
			name: "enabled without files",
			config: Config{
				Enabled: true,
			},
			wantErr: true,
		},
		{
			name: "negative reload interval",
			config: Config{
				Enabled:  true,
				CertFile: "cert.pem",
				KeyFile:  "key.pem",
				Interval: -time.Second,
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNewManagerDisabled(t *testing.T) {
	manager, err := NewManager(t.Context(), Config{}, Options{})
	require.NoError(t, err)
	require.False(t, manager.Enabled())
	require.Nil(t, manager.TLSConfig())
	require.Nil(t, manager.Reloader())
}

func TestMustNewManagerPanicsOnError(t *testing.T) {
	require.Panics(t, func() {
		MustNewManager(t.Context(), Config{
			Enabled: true,
		}, Options{})
	})
}

func TestMustNewManagerReturnsManager(t *testing.T) {
	certFile, keyFile := writeManagerTLSFiles(t)

	manager := MustNewManager(t.Context(), Config{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}, Options{})
	t.Cleanup(manager.Close)

	require.True(t, manager.Enabled())
	require.NotNil(t, manager.Reloader())
	require.NotNil(t, manager.TLSConfig())
}

func TestNewManagerUsesReloaderWithoutFallbackPoll(t *testing.T) {
	certFile, keyFile := writeManagerTLSFiles(t)

	manager, err := NewManager(t.Context(), Config{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	}, Options{
		MinVersion: tls.VersionTLS13,
	})

	require.NoError(t, err)
	t.Cleanup(manager.Close)
	require.True(t, manager.Enabled())
	require.NotNil(t, manager.Reloader())
	require.NotNil(t, manager.TLSConfig())
	require.Equal(t, uint16(tls.VersionTLS13), manager.TLSConfig().MinVersion)
	_, err = manager.TLSConfig().GetCertificate(nil)
	require.NoError(t, err)
}

func TestNewManagerUsesReloader(t *testing.T) {
	certFile, keyFile := writeManagerTLSFiles(t)

	manager, err := NewManager(t.Context(), Config{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
		Interval: time.Second,
	}, Options{})

	require.NoError(t, err)
	t.Cleanup(manager.Close)
	require.True(t, manager.Enabled())
	require.NotNil(t, manager.Reloader())
	require.NotNil(t, manager.TLSConfig())
	_, err = manager.TLSConfig().GetCertificate(nil)
	require.NoError(t, err)
}

func writeManagerTLSFiles(t *testing.T) (string, string) {
	t.Helper()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	certPEM, keyPEM := mustGenerateTLSPair(t, "manager")
	require.NoError(t, os.WriteFile(certFile, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyFile, keyPEM, 0o600))
	return certFile, keyFile
}
