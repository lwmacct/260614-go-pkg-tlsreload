package tlsreload

import "context"

// Source provides certificate material and optional change notifications.
type Source interface {
	Name() string
	Load(ctx context.Context) (SourceData, error)
	Watch(ctx context.Context, currentVersion string, notify func(nextVersion string)) error
	Close() error
}

// SourceData is a TLS certificate bundle loaded from a Source.
type SourceData struct {
	CertPEM []byte
	KeyPEM  []byte
	Version string
}
