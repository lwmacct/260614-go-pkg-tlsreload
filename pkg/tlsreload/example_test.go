package tlsreload

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func ExampleReloader() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dir, err := os.MkdirTemp("", "tlsreload-example-*")
	if err != nil {
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()

	certFile := filepath.Join(dir, "fullchain.pem")
	keyFile := filepath.Join(dir, "privkey.pem")
	certPEM, keyPEM := mustExampleTLSPair()
	if writeErr := os.WriteFile(certFile, certPEM, 0o600); writeErr != nil {
		return
	}
	if writeErr := os.WriteFile(keyFile, keyPEM, 0o600); writeErr != nil {
		return
	}

	reloader, err := New(ctx, Config{
		CertFile:       certFile,
		KeyFile:        keyFile,
		ReloadInterval: 3 * time.Second,
		MinVersion:     tls.VersionTLS12,
	})
	if err != nil {
		return
	}
	defer reloader.Close()

	cfg := reloader.TLSConfig()
	fmt.Println(cfg.GetCertificate != nil && cfg.MinVersion == tls.VersionTLS12)

	// Output:
	// true
}

func mustExampleTLSPair() ([]byte, []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example",
		},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(3600, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
