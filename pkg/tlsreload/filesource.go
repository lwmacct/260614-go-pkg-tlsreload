package tlsreload

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// FileSourceConfig describes a certificate/key pair on local disk.
type FileSourceConfig struct {
	CertFile      string
	KeyFile       string
	WatchInterval time.Duration
}

const defaultFileWatchInterval = 3 * time.Second

// NewFileSource builds a Source that reads PEM files from disk.
func NewFileSource(config FileSourceConfig) (Source, error) {
	if strings.TrimSpace(config.CertFile) == "" || strings.TrimSpace(config.KeyFile) == "" {
		return nil, errors.New("tls file source requires both cert file and key file")
	}
	if config.WatchInterval <= 0 {
		config.WatchInterval = defaultFileWatchInterval
	}
	return &fileSource{
		certFile:      config.CertFile,
		keyFile:       config.KeyFile,
		watchInterval: config.WatchInterval,
	}, nil
}

type fileSource struct {
	certFile      string
	keyFile       string
	watchInterval time.Duration
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

func (s *fileSource) Watch(ctx context.Context, currentVersion string, notify func(nextVersion string)) error {
	ticker := time.NewTicker(s.watchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			data, err := s.Load(ctx)
			if err != nil {
				return err
			}
			if data.Version == currentVersion {
				continue
			}
			currentVersion = data.Version
			notify(data.Version)
		}
	}
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
