//go:build op_integration

package tlsreload_test

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"
	"time"

	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/adapters/op1"
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

const (
	onePasswordIntegrationCert = "op://op-bendian-infra/jwf6zxhmglqdaezvsr5ueuukiy/fullchain"
	onePasswordIntegrationKey  = "op://op-bendian-infra/jwf6zxhmglqdaezvsr5ueuukiy/privkey"
)

func TestOnePasswordServiceAccountIntegration(t *testing.T) {
	tests := []struct {
		name    string
		envName string
		options tlsreload.Options
	}{
		{
			name:    "custom token env",
			envName: "OP_TOKEN",
			options: tlsreload.Options{
				Adapters: []tlsreload.Adapter{
					op1.New(op1.Options{TokenEnv: "OP_TOKEN"}),
				},
			},
		},
		{
			name:    "default token env",
			envName: op1.DefaultTokenEnv,
			options: tlsreload.Options{
				Adapters: []tlsreload.Adapter{
					op1.New(op1.Options{}),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if os.Getenv(test.envName) == "" {
				t.Skipf("%s is empty", test.envName)
			}

			manager, err := tlsreload.New(t.Context(), tlsreload.Config{
				Enabled:  true,
				CertFile: onePasswordIntegrationCert,
				KeyFile:  onePasswordIntegrationKey,
			}, test.options)
			if err != nil {
				t.Fatalf("new manager: %v", err)
			}
			t.Cleanup(manager.Close)

			certificate, err := manager.GetCertificate(nil)
			if err != nil {
				t.Fatalf("get certificate: %v", err)
			}
			if len(certificate.Certificate) == 0 {
				t.Fatal("loaded certificate has no leaf certificates")
			}
			leaf, err := x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				t.Fatalf("parse leaf certificate: %v", err)
			}
			if leaf.Subject.CommonName != "kuaicdn.cn" {
				t.Fatalf("common name = %q, want kuaicdn.cn", leaf.Subject.CommonName)
			}
			if manager.Version() == "" {
				t.Fatal("manager version is empty")
			}

			assertTLSHandshakeUsesManagerCertificate(t, manager)
		})
	}
}

func assertTLSHandshakeUsesManagerCertificate(t *testing.T, manager *tlsreload.Manager) {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", manager.TLSConfig())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			serverErr <- nil
			return
		}
		serverErr <- tlsConn.Handshake()
	}()

	clientConn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName:         "kuaicdn.cn",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	_ = clientConn.Close()

	select {
	case err := <-serverErr:
		if err != nil && !isClosedNetworkConnection(err) {
			t.Fatalf("server handshake: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server handshake timed out")
	}
}

func isClosedNetworkConnection(err error) bool {
	if err == nil {
		return false
	}
	return os.IsTimeout(err) || err == net.ErrClosed
}
