package tlsreload

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// EtcdBundleSourceConfig describes a TLS bundle stored in etcd.
type EtcdBundleSourceConfig struct {
	Endpoints    []string
	BundleKey    string
	Username     string
	Password     string
	CAFile       string
	CertFile     string
	KeyFile      string
	DialTimeout  time.Duration
	DecodeBundle func(value []byte) (PEMBundle, error)
}

const defaultEtcdDialTimeout = 5 * time.Second

// NewEtcdBundleSource builds a Source that reads a TLS bundle from etcd.
// When DecodeBundle is nil, it defaults to DecodeJSONPEMBundle.
func NewEtcdBundleSource(config EtcdBundleSourceConfig) (Source, error) {
	if len(config.Endpoints) == 0 {
		return nil, errors.New("etcd bundle source requires at least one endpoint")
	}
	if strings.TrimSpace(config.BundleKey) == "" {
		return nil, errors.New("etcd bundle source requires bundle key")
	}
	if config.DialTimeout <= 0 {
		config.DialTimeout = defaultEtcdDialTimeout
	}
	if config.DecodeBundle == nil {
		config.DecodeBundle = DecodeJSONPEMBundle
	}

	clientConfig := clientv3.Config{
		Endpoints:   config.Endpoints,
		Username:    config.Username,
		Password:    config.Password,
		DialTimeout: config.DialTimeout,
	}

	if config.CAFile != "" || config.CertFile != "" || config.KeyFile != "" {
		tlsConfig, err := newEtcdClientTLSConfig(config)
		if err != nil {
			return nil, err
		}
		clientConfig.TLS = tlsConfig
	}

	client, err := clientv3.New(clientConfig)
	if err != nil {
		return nil, fmt.Errorf("create etcd tls client: %w", err)
	}
	return &etcdBundleSource{
		client:       client,
		bundleKey:    config.BundleKey,
		decodeBundle: config.DecodeBundle,
	}, nil
}

type etcdBundleSource struct {
	client       *clientv3.Client
	bundleKey    string
	decodeBundle func(value []byte) (PEMBundle, error)
}

func (s *etcdBundleSource) Name() string { return "etcd" }

func (s *etcdBundleSource) Load(ctx context.Context) (SourceData, error) {
	resp, err := s.client.Get(ctx, s.bundleKey)
	if err != nil {
		return SourceData{}, fmt.Errorf("get etcd tls bundle: %w", err)
	}
	if len(resp.Kvs) == 0 {
		return SourceData{}, fmt.Errorf("etcd tls bundle key %q not found", s.bundleKey)
	}

	bundle, err := s.decodeBundle(resp.Kvs[0].Value)
	if err != nil {
		return SourceData{}, fmt.Errorf("decode etcd tls bundle: %w", err)
	}

	return SourceData{
		CertPEM: bundle.CertPEM,
		KeyPEM:  bundle.KeyPEM,
		Version: strconv.FormatInt(resp.Kvs[0].ModRevision, 10),
	}, nil
}

func (s *etcdBundleSource) Watch(ctx context.Context, currentVersion string, notify func(nextVersion string)) error {
	startRevision, err := nextEtcdRevision(currentVersion)
	if err != nil {
		return err
	}

	rch := s.client.Watch(ctx, s.bundleKey, clientv3.WithRev(startRevision))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case resp, ok := <-rch:
			if !ok {
				return errors.New("watch etcd tls bundle channel closed")
			}
			if err := resp.Err(); err != nil {
				return fmt.Errorf("watch etcd tls bundle: %w", err)
			}
			if resp.CompactRevision > 0 {
				return fmt.Errorf("watch etcd tls bundle compacted at revision %d", resp.CompactRevision)
			}
			for _, event := range resp.Events {
				notify(strconv.FormatInt(event.Kv.ModRevision, 10))
			}
		}
	}
}

func (s *etcdBundleSource) Close() error { return s.client.Close() }

func newEtcdClientTLSConfig(config EtcdBundleSourceConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if config.CAFile != "" {
		// #nosec G304 -- CA file paths are provided by the embedding application configuration.
		caPEM, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read etcd ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("append etcd ca certificates: invalid pem")
		}
		tlsConfig.RootCAs = pool
	}

	if config.CertFile != "" || config.KeyFile != "" {
		certPEM, keyPEM, err := readTLSFiles(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, err
		}
		certificate, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("load etcd client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return tlsConfig, nil
}

func nextEtcdRevision(version string) (int64, error) {
	if strings.TrimSpace(version) == "" {
		return 0, nil
	}
	revision, err := strconv.ParseInt(version, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse etcd tls revision %q: %w", version, err)
	}
	return revision + 1, nil
}
