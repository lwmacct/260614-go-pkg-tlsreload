package tlsreload

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

var errMissingTLSFiles = errors.New("tls reload requires both cert file and key file")

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
	watcher, err := newFSNotifyWatcher()
	if err != nil {
		return nil, err
	}

	dirs := map[string]struct{}{
		filepath.Dir(m.certFile): {},
		filepath.Dir(m.keyFile):  {},
	}
	for dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			return nil, fmt.Errorf("watch tls directory %q: %w", dir, err)
		}
	}
	return watcher, nil
}

func (m *Manager) backgroundLoop(ctx context.Context) {
	var timer *time.Timer
	var timerCh <-chan time.Time
	if m.pollInterval > 0 {
		timer = time.NewTimer(m.pollInterval)
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
			resetTimer(timer, m.pollInterval)
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
	return samePath(event.Name, m.certFile) || samePath(event.Name, m.keyFile)
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

	certPEM, keyPEM, err := readTLSFiles(m.certFile, m.keyFile)
	if err != nil {
		return material{}, err
	}

	return material{
		certPEM: certPEM,
		keyPEM:  keyPEM,
		version: tlsMaterialVersion(certPEM, keyPEM),
	}, nil
}

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
	return filepath.Clean(trimmed), nil
}

func (m *Manager) logInfo(msg string, args ...any) {
	if m.logger == nil {
		return
	}
	args = append([]any{"cert_file", m.certFile, "key_file", m.keyFile}, args...)
	m.logger.Info(msg, args...)
}

func (m *Manager) logError(msg string, args ...any) {
	if m.logger == nil {
		return
	}
	args = append([]any{"cert_file", m.certFile, "key_file", m.keyFile}, args...)
	m.logger.Error(msg, args...)
}
