package tlsreload

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// FileSourceConfig describes a certificate/key pair on local disk.
type FileSourceConfig struct {
	CertFile string
	KeyFile  string
}

// NewFileSource builds a Source that reads PEM files from disk.
func NewFileSource(config FileSourceConfig) (Source, error) {
	certFile, err := normalizeTLSFilePath(config.CertFile)
	if err != nil {
		return nil, fmt.Errorf("cert file: %w", err)
	}
	keyFile, err := normalizeTLSFilePath(config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("tls file source requires both cert file and key file")
	}
	return &fileSource{
		certFile: certFile,
		keyFile:  keyFile,
	}, nil
}

type fileSource struct {
	certFile string
	keyFile  string
}

func (s *fileSource) Name() string { return "files" }

func (s *fileSource) Load(context.Context) (SourceData, error) {
	certPEM, keyPEM, err := readTLSFiles(s.certFile, s.keyFile)
	if err != nil {
		return SourceData{}, err
	}
	return SourceData{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Version: tlsMaterialVersion(certPEM, keyPEM),
	}, nil
}

func (s *fileSource) Close() error { return nil }

func readTLSFiles(certFile, keyFile string) ([]byte, []byte, error) {
	// #nosec G304 -- certificate paths are provided by the embedding application configuration.
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read tls cert file: %w", err)
	}
	// #nosec G304 -- key paths are provided by the embedding application configuration.
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read tls key file: %w", err)
	}
	return certPEM, keyPEM, nil
}

func normalizeTLSFilePath(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	if strings.Contains(trimmed, "://") {
		return "", errors.New("tls file path must not use a URI scheme")
	}
	return trimmed, nil
}
