package tlsreload

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Base64SourceConfig describes a certificate/key pair encoded as base64 PEM bytes.
type Base64SourceConfig struct {
	CertBase64 string
	KeyBase64  string
}

// NewBase64Source builds a Source from base64-encoded PEM bytes.
func NewBase64Source(config Base64SourceConfig) (Source, error) {
	if strings.TrimSpace(config.CertBase64) == "" || strings.TrimSpace(config.KeyBase64) == "" {
		return nil, errors.New("tls base64 source requires both cert base64 and key base64")
	}
	return &base64Source{
		certBase64: config.CertBase64,
		keyBase64:  config.KeyBase64,
	}, nil
}

type base64Source struct {
	certBase64 string
	keyBase64  string
}

func (s *base64Source) Name() string { return "base64" }

func (s *base64Source) Load(_ context.Context) (SourceData, error) {
	certPEM, err := decodeBase64TLSMaterial(s.certBase64)
	if err != nil {
		return SourceData{}, fmt.Errorf("decode tls cert base64: %w", err)
	}
	keyPEM, err := decodeBase64TLSMaterial(s.keyBase64)
	if err != nil {
		return SourceData{}, fmt.Errorf("decode tls key base64: %w", err)
	}
	return SourceData{
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		Version: tlsMaterialVersion(certPEM, keyPEM),
	}, nil
}

func (s *base64Source) Watch(context.Context, string, func(nextVersion string)) error {
	return errors.New("base64 tls source does not support watch")
}

func (s *base64Source) Close() error { return nil }

func decodeBase64TLSMaterial(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(decoded) == 0 {
		return nil, errors.New("decoded tls material is empty")
	}
	return decoded, nil
}
