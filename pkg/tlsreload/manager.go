package tlsreload

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	defaultPollInterval  = 5 * time.Minute
	defaultRetryInterval = 2 * time.Second
	defaultPollJitter    = 0.10
)

// Options controls TLS runtime behavior that is not normally sourced from config files.
type Options struct {
	MinVersion        uint16
	RetryInterval     time.Duration
	PollJitterRatio   float64
	Logger            *slog.Logger
	AllowInsecureHTTP bool
	HTTPClient        *http.Client
	Adapters          []Adapter
}

// Manager owns an optional hot-reloadable TLS certificate source.
type Manager struct {
	enabled         bool
	certFile        string
	keyFile         string
	pollInterval    time.Duration
	pollJitterRatio float64
	retryInterval   time.Duration
	minVersion      uint16
	logger          *slog.Logger
	watcher         *fsnotify.Watcher
	loaderOptions   loaderOptions

	reloadMu sync.Mutex
	current  atomic.Pointer[snapshot]

	cancel    context.CancelFunc
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New builds a TLS manager for disabled or hot-reloaded TLS configuration.
func New(ctx context.Context, config Config, options Options) (*Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if !config.Enabled {
		return &Manager{}, nil
	}
	if options.MinVersion == 0 {
		options.MinVersion = tls.VersionTLS12
	}
	if options.RetryInterval <= 0 {
		options.RetryInterval = defaultRetryInterval
	}
	pollInterval := config.PollInterval
	if pollInterval == 0 {
		pollInterval = defaultPollInterval
	}
	pollJitterRatio := options.PollJitterRatio
	if pollJitterRatio == 0 {
		pollJitterRatio = defaultPollJitter
	}
	if pollJitterRatio < 0 || pollJitterRatio >= 1 {
		return nil, errors.New("tls poll jitter ratio must be >= 0 and < 1")
	}

	certFile, err := normalizeTLSLocation(config.CertFile)
	if err != nil {
		return nil, err
	}
	keyFile, err := normalizeTLSLocation(config.KeyFile)
	if err != nil {
		return nil, err
	}
	if certFile == "" || keyFile == "" {
		return nil, errMissingTLSFiles
	}

	adapters, err := newAdapterMap(options.Adapters)
	if err != nil {
		return nil, err
	}

	managerCtx, cancel := context.WithCancel(ctx)
	manager := &Manager{
		enabled:         true,
		certFile:        certFile,
		keyFile:         keyFile,
		pollInterval:    pollInterval,
		pollJitterRatio: pollJitterRatio,
		retryInterval:   options.RetryInterval,
		minVersion:      options.MinVersion,
		logger:          options.Logger,
		loaderOptions: loaderOptions{
			allowInsecureHTTP: options.AllowInsecureHTTP,
			httpClient:        options.HTTPClient,
			adapters:          adapters,
		},
		cancel: cancel,
	}

	if reloadErr := manager.reload(managerCtx, true); reloadErr != nil {
		cancel()
		return nil, reloadErr
	}

	watcher, err := manager.newWatcher()
	switch {
	case errors.Is(err, errNoLocalWatchSources):
		// Remote sources do not have file system events; polling and manual reload still work.
	case err != nil:
		manager.logError("watch tls certificate files failed", "error", err)
	default:
		manager.watcher = watcher
	}

	if manager.watcher != nil || manager.pollInterval > 0 {
		manager.wg.Go(func() {
			manager.backgroundLoop(managerCtx)
		})
	}

	return manager, nil
}

// MustNew is like New but panics if the Manager cannot be created.
func MustNew(ctx context.Context, config Config, options Options) *Manager {
	manager, err := New(ctx, config, options)
	if err != nil {
		panic(err)
	}
	return manager
}

// TLSConfig returns the configured TLS config, or nil when TLS is disabled.
func (m *Manager) TLSConfig() *tls.Config {
	if m == nil || !m.enabled {
		return nil
	}
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     m.minVersion,
	}
}

// Enabled reports whether TLS is enabled.
func (m *Manager) Enabled() bool {
	return m != nil && m.enabled
}

// Close stops background reload activity.
func (m *Manager) Close() {
	if m == nil || !m.enabled {
		return
	}
	m.closeOnce.Do(func() {
		m.cancel()
		if m.watcher != nil {
			_ = m.watcher.Close()
		}
		m.wg.Wait()
	})
}
