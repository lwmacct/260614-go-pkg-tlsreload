package tlsreload

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewBase64SourceRequiresValues(t *testing.T) {
	_, err := NewBase64Source(Base64SourceConfig{})
	require.Error(t, err)
}

func TestBase64SourceLoad(t *testing.T) {
	cert := []byte("cert-pem")
	key := []byte("key-pem")

	source, err := NewBase64Source(Base64SourceConfig{
		CertBase64: base64.StdEncoding.EncodeToString(cert),
		KeyBase64:  base64.StdEncoding.EncodeToString(key),
	})
	require.NoError(t, err)

	data, err := source.Load(t.Context())
	require.NoError(t, err)
	require.Equal(t, cert, data.CertPEM)
	require.Equal(t, key, data.KeyPEM)
}
