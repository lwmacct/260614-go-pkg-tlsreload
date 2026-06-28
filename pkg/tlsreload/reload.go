package tlsreload

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

var errMissingTLSFiles = errors.New("tls reload requires both cert file and key file")

var errNoLocalWatchSources = errors.New("tls reload has no local file sources to watch")

var newFSNotifyWatcher = fsnotify.NewWatcher

type snapshot struct {
	certificate tls.Certificate
	version     string
}

// Reload forces an immediate certificate refresh.
func (m *Manager) Reload(ctx context.Context) error {
	if m == nil {
		return errors.New("tls manager is nil")
	}
	if !m.enabled {
		return errors.New("tls manager is disabled")
	}
	return m.reload(ctx, true)
}

// GetCertificate implements tls.Config.GetCertificate.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	current := m.current.Load()
	if current == nil {
		return nil, errors.New("tls certificate not loaded")
	}
	certificate := current.certificate
	return &certificate, nil
}

// Version returns the active certificate material version.
func (m *Manager) Version() string {
	if m == nil {
		return ""
	}
	current := m.current.Load()
	if current == nil {
		return ""
	}
	return current.version
}

func (m *Manager) newWatcher() (*fsnotify.Watcher, error) {
	paths, err := m.localWatchPaths()
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errNoLocalWatchSources
	}

	dirs := make(map[string]struct{})
	for _, watchPath := range paths {
		dirs[filepath.Dir(watchPath)] = struct{}{}
	}

	watcher, err := newFSNotifyWatcher()
	if err != nil {
		return nil, err
	}

	for dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			return nil, fmt.Errorf("watch tls directory %q: %w", dir, err)
		}
	}
	m.watchPaths = paths
	return watcher, nil
}

func (m *Manager) localWatchPaths() ([]string, error) {
	seen := make(map[string]struct{})
	var paths []string
	for _, location := range []string{m.certFile, m.keyFile} {
		_, scheme := parseLocation(location)
		adapter := m.loaderOptions.adapters[scheme]
		watcher, ok := adapter.(Watcher)
		if !ok {
			continue
		}
		watchPaths, err := watcher.WatchPaths(location)
		if err != nil {
			return nil, err
		}
		for _, watchPath := range watchPaths {
			cleaned := filepath.Clean(watchPath)
			if _, exists := seen[cleaned]; exists {
				continue
			}
			seen[cleaned] = struct{}{}
			paths = append(paths, cleaned)
		}
	}
	return paths, nil
}

func (m *Manager) backgroundLoop(ctx context.Context) {
	var timer *time.Timer
	var timerCh <-chan time.Time
	if m.pollInterval > 0 {
		timer = time.NewTimer(m.jitteredPollInterval())
		timerCh = timer.C
		defer timer.Stop()
	}

	var events <-chan fsnotify.Event
	var watcherErrors <-chan error
	if m.watcher != nil {
		events = m.watcher.Events
		watcherErrors = m.watcher.Errors
	}

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if !m.shouldReloadForEvent(event) {
				continue
			}
			if err := m.reload(ctx, false); err != nil {
				m.logError("reload tls certificate from file event failed", "event", event.String(), "error", err)
			}
		case err, ok := <-watcherErrors:
			if !ok {
				watcherErrors = nil
				continue
			}
			m.logError("watch tls certificate files failed", "error", err)
		case <-timerCh:
			if err := m.reload(ctx, false); err != nil {
				m.logError("reload tls certificate failed", "error", err)
				resetTimer(timer, m.retryInterval)
				continue
			}
			resetTimer(timer, m.jitteredPollInterval())
		}
	}
}

func (m *Manager) shouldReloadForEvent(event fsnotify.Event) bool {
	if !event.Has(fsnotify.Write) &&
		!event.Has(fsnotify.Create) &&
		!event.Has(fsnotify.Rename) &&
		!event.Has(fsnotify.Remove) {
		return false
	}
	for _, watchPath := range m.watchPaths {
		if samePath(event.Name, watchPath) {
			return true
		}
	}
	return false
}

func samePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	if leftErr == nil && rightErr == nil {
		return leftAbs == rightAbs
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if timer == nil {
		return
	}
	timer.Reset(duration)
}

func (m *Manager) jitteredPollInterval() time.Duration {
	maxJitter := time.Duration(float64(m.pollInterval) * m.pollJitterRatio)
	if maxJitter <= 0 {
		return m.pollInterval
	}
	jitter, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(maxJitter)+1))
	if err != nil {
		return m.pollInterval
	}
	return m.pollInterval - time.Duration(jitter.Int64())
}

func (m *Manager) reload(ctx context.Context, force bool) error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	material, err := m.loadMaterial(ctx)
	if err != nil {
		return err
	}
	if !force {
		current := m.current.Load()
		if current != nil && current.version == material.version {
			return nil
		}
	}

	certificate, err := tls.X509KeyPair(material.certPEM, material.keyPEM)
	if err != nil {
		return fmt.Errorf("load tls certificate: %w", err)
	}

	next := &snapshot{
		certificate: certificate,
		version:     material.version,
	}
	m.current.Store(next)
	m.logInfo("tls certificate loaded", "version", next.version)
	return nil
}

type material struct {
	certPEM []byte
	keyPEM  []byte
	version string
}

func (m *Manager) loadMaterial(ctx context.Context) (material, error) {
	if err := ctx.Err(); err != nil {
		return material{}, err
	}

	certPEM, keyPEM, err := readTLSLocations(ctx, m.certFile, m.keyFile, m.loaderOptions)
	if err != nil {
		return material{}, err
	}

	return material{
		certPEM: certPEM,
		keyPEM:  keyPEM,
		version: tlsMaterialVersion(certPEM, keyPEM),
	}, nil
}

func (m *Manager) logInfo(msg string, args ...any) {
	if m.logger == nil {
		return
	}
	args = append([]any{"cert_file", redactLocation(m.certFile), "key_file", redactLocation(m.keyFile)}, args...)
	m.logger.Info(msg, args...)
}

func (m *Manager) logError(msg string, args ...any) {
	if m.logger == nil {
		return
	}
	args = append([]any{"cert_file", redactLocation(m.certFile), "key_file", redactLocation(m.keyFile)}, args...)
	m.logger.Error(msg, args...)
}
