package tlsreload

import (
	"context"
	"log/slog"
	"time"
)

// FileManagerOptions controls local file certificate loading and reload behavior.
type FileManagerOptions struct {
	CertFile       string
	KeyFile        string
	AutoReload     bool
	ReloadInterval time.Duration
	RetryInterval  time.Duration
	Logger         *slog.Logger
}

// NewFileManager builds a Manager backed by a local certificate/key pair.
func NewFileManager(ctx context.Context, options FileManagerOptions) (*Manager, error) {
	source, err := NewFileSource(FileSourceConfig{
		CertFile: options.CertFile,
		KeyFile:  options.KeyFile,
	})
	if err != nil {
		return nil, err
	}

	return NewManager(ctx, source, ManagerOptions{
		AutoReload:     options.AutoReload,
		ReloadInterval: options.ReloadInterval,
		RetryInterval:  options.RetryInterval,
		Logger:         options.Logger,
	})
}
