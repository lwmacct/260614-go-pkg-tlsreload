package tlsreload

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// ManagerOptions controls runtime reload behavior.
type ManagerOptions struct {
	AutoReload     bool
	ReloadInterval time.Duration
	RetryInterval  time.Duration
	Logger         *slog.Logger
}

// Manager serves the latest valid TLS certificate from a Source.
type Manager struct {
	source         Source
	logger         *slog.Logger
	reloadInterval time.Duration
	retryInterval  time.Duration

	reloadMu    sync.Mutex
	certificate atomic.Pointer[tls.Certificate]

	versionMu sync.RWMutex
	version   string

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager loads the initial certificate and optionally starts a reload loop.
func NewManager(ctx context.Context, source Source, options ManagerOptions) (*Manager, error) {
	if source == nil {
		return nil, errors.New("tls manager requires source")
	}
	if options.AutoReload && options.ReloadInterval <= 0 {
		return nil, errors.New("tls manager reload interval must be greater than zero when auto reload is enabled")
	}
	if options.RetryInterval <= 0 {
		options.RetryInterval = 2 * time.Second
	}

	managerCtx, cancel := context.WithCancel(ctx)
	manager := &Manager{
		source:         source,
		logger:         options.Logger,
		reloadInterval: options.ReloadInterval,
		retryInterval:  options.RetryInterval,
		cancel:         cancel,
	}

	if err := manager.reload(managerCtx); err != nil {
		cancel()
		_ = source.Close()
		return nil, err
	}

	if options.AutoReload {
		manager.wg.Go(func() {
			manager.reloadLoop(managerCtx)
		})
	}

	return manager, nil
}

// Reload forces an immediate certificate refresh from the Source.
func (m *Manager) Reload(ctx context.Context) error {
	return m.reload(ctx)
}

// Close stops background reload activity and closes the Source.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.cancel()
	m.wg.Wait()
	_ = m.source.Close()
}

// GetCertificate implements tls.Config.GetCertificate.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	certificate := m.certificate.Load()
	if certificate == nil {
		return nil, errors.New("tls certificate not loaded")
	}
	return certificate, nil
}

// TLSConfig builds a tls.Config backed by the Manager.
func (m *Manager) TLSConfig(minVersion uint16) *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     minVersion,
	}
}

// Version returns the currently active source version marker.
func (m *Manager) Version() string {
	return m.currentVersion()
}

func (m *Manager) reloadLoop(ctx context.Context) {
	timer := time.NewTimer(m.reloadInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := m.reloadIfChanged(ctx); err != nil {
				m.logError("reload tls certificate failed", "error", err)
				timer.Reset(m.retryInterval)
				continue
			}
			timer.Reset(m.reloadInterval)
		}
	}
}

func (m *Manager) reload(ctx context.Context) error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	data, err := m.source.Load(ctx)
	if err != nil {
		return err
	}

	certificate, err := tls.X509KeyPair(data.CertPEM, data.KeyPEM)
	if err != nil {
		return fmt.Errorf("load tls certificate: %w", err)
	}

	m.certificate.Store(&certificate)
	m.setCurrentVersion(data.Version)
	m.logInfo("tls certificate loaded", "version", data.Version)
	return nil
}

func (m *Manager) reloadIfChanged(ctx context.Context) error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	data, err := m.source.Load(ctx)
	if err != nil {
		return err
	}
	if data.Version != "" && data.Version == m.currentVersion() {
		return nil
	}

	certificate, err := tls.X509KeyPair(data.CertPEM, data.KeyPEM)
	if err != nil {
		return fmt.Errorf("load tls certificate: %w", err)
	}

	m.certificate.Store(&certificate)
	m.setCurrentVersion(data.Version)
	m.logInfo("tls certificate reloaded", "version", data.Version)
	return nil
}

func (m *Manager) currentVersion() string {
	m.versionMu.RLock()
	defer m.versionMu.RUnlock()
	return m.version
}

func (m *Manager) setCurrentVersion(version string) {
	m.versionMu.Lock()
	defer m.versionMu.Unlock()
	m.version = version
}

func (m *Manager) logInfo(msg string, args ...any) {
	if m.logger == nil {
		return
	}
	args = append([]any{"source", m.source.Name()}, args...)
	m.logger.Info(msg, args...)
}

func (m *Manager) logError(msg string, args ...any) {
	if m.logger == nil {
		return
	}
	args = append([]any{"source", m.source.Name()}, args...)
	m.logger.Error(msg, args...)
}
