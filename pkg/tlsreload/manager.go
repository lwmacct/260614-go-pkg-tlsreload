package tlsreload

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"
)

// Options controls TLS runtime behavior that is not normally sourced from config files.
type Options struct {
	MinVersion    uint16
	RetryInterval time.Duration
	Logger        *slog.Logger
}

// Manager owns a TLS config built from Config and closes any background reload work.
type Manager struct {
	enabled  bool
	config   *tls.Config
	reloader *Reloader
}

// NewManager builds a TLS manager for disabled or hot-reloaded TLS configuration.
func NewManager(ctx context.Context, config Config, options Options) (*Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !config.Enabled {
		return &Manager{}, nil
	}
	if options.MinVersion == 0 {
		options.MinVersion = tls.VersionTLS12
	}

	reloader, err := NewReloader(ctx, ReloaderConfig{
		CertFile:       config.CertFile,
		KeyFile:        config.KeyFile,
		ReloadInterval: config.Interval,
		RetryInterval:  options.RetryInterval,
		MinVersion:     options.MinVersion,
		Logger:         options.Logger,
	})
	if err != nil {
		return nil, err
	}
	return &Manager{
		enabled:  true,
		config:   reloader.TLSConfig(),
		reloader: reloader,
	}, nil
}

// TLSConfig returns the configured TLS config, or nil when TLS is disabled.
func (m *Manager) TLSConfig() *tls.Config {
	if m == nil {
		return nil
	}
	return m.config
}

// Enabled reports whether TLS is enabled.
func (m *Manager) Enabled() bool {
	return m != nil && m.enabled
}

// Reloader returns the active certificate reloader, or nil when TLS is disabled.
func (m *Manager) Reloader() *Reloader {
	if m == nil {
		return nil
	}
	return m.reloader
}

// Close stops background reload activity.
func (m *Manager) Close() {
	if m == nil || m.reloader == nil {
		return
	}
	m.reloader.Close()
	m.reloader = nil
}
