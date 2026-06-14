package tlsreload

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewEtcdBundleSourceRequiresEndpoints(t *testing.T) {
	_, err := NewEtcdBundleSource(EtcdBundleSourceConfig{
		BundleKey: "/tls/default",
	})
	require.Error(t, err)
}

func TestNewEtcdBundleSourceRequiresBundleKey(t *testing.T) {
	_, err := NewEtcdBundleSource(EtcdBundleSourceConfig{
		Endpoints: []string{"http://127.0.0.1:2379"},
	})
	require.Error(t, err)
}

func TestDecodeJSONPEMBundle(t *testing.T) {
	bundle, err := DecodeJSONPEMBundle([]byte(`{"cert_pem":"CERT","key_pem":"KEY"}`))
	require.NoError(t, err)
	require.Equal(t, []byte("CERT"), bundle.CertPEM)
	require.Equal(t, []byte("KEY"), bundle.KeyPEM)
}
