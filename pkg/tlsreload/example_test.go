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
	"time"
)

func ExampleManager() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	certPEM, keyPEM := mustExampleTLSPair()

	source := &exampleSource{data: SourceData{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Version: "1",
	}}

	manager, err := NewManager(ctx, source, ManagerOptions{
		Watch:         true,
		RetryInterval: 3 * time.Second,
	})
	if err != nil {
		return
	}
	defer manager.Close()

	cfg := manager.TLSConfig(tls.VersionTLS12)
	fmt.Println(cfg.GetCertificate != nil && cfg.MinVersion == tls.VersionTLS12)

	// Output:
	// true
}

type exampleSource struct {
	data SourceData
}

func (s *exampleSource) Name() string { return "example" }

func (s *exampleSource) Load(context.Context) (SourceData, error) {
	return s.data, nil
}

func (s *exampleSource) Watch(ctx context.Context, _ string, notify func(nextVersion string)) error {
	<-ctx.Done()
	return ctx.Err()
}

func (s *exampleSource) Close() error { return nil }

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
