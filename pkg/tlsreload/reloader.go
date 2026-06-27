package tlsreload

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ReloaderConfig controls file-backed TLS certificate loading and reload behavior.
type ReloaderConfig struct {
	CertFile string
	KeyFile  string
	// ReloadInterval is a fallback poll interval; file system events are always used when available.
	ReloadInterval time.Duration
	RetryInterval  time.Duration
	MinVersion     uint16
	Logger         *slog.Logger
}

// Reloader serves the latest valid TLS certificate from a certificate/key file pair.
type Reloader struct {
	certFile       string
	keyFile        string
	reloadInterval time.Duration
	retryInterval  time.Duration
	minVersion     uint16
	logger         *slog.Logger
	watcher        *fsnotify.Watcher

	reloadMu sync.Mutex
	current  atomic.Pointer[snapshot]

	cancel    context.CancelFunc
	closeOnce sync.Once
	wg        sync.WaitGroup
}

type snapshot struct {
	certificate tls.Certificate
	version     string
}

// NewReloader loads the initial certificate, watches certificate files for changes, and uses ReloadInterval as a fallback poll interval when greater than zero.
func NewReloader(ctx context.Context, config ReloaderConfig) (*Reloader, error) {
	certFile, err := normalizeTLSFilePath(config.CertFile)
	if err != nil {
		return nil, fmt.Errorf("cert file: %w", err)
	}
	keyFile, err := normalizeTLSFilePath(config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("key file: %w", err)
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("tls reload requires both cert file and key file")
	}
	if config.ReloadInterval < 0 {
		return nil, errors.New("tls reload interval must not be negative")
	}
	if config.RetryInterval <= 0 {
		config.RetryInterval = 2 * time.Second
	}
	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS12
	}

	reloaderCtx, cancel := context.WithCancel(ctx)
	reloader := &Reloader{
		certFile:       certFile,
		keyFile:        keyFile,
		reloadInterval: config.ReloadInterval,
		retryInterval:  config.RetryInterval,
		minVersion:     config.MinVersion,
		logger:         config.Logger,
		cancel:         cancel,
	}

	err = reloader.Reload(reloaderCtx)
	if err != nil {
		cancel()
		return nil, err
	}

	watcher, err := reloader.newWatcher()
	if err != nil {
		reloader.logError("watch tls certificate files failed", "error", err)
	} else {
		reloader.watcher = watcher
	}

	if reloader.watcher != nil || config.ReloadInterval > 0 {
		reloader.wg.Go(func() {
			reloader.backgroundLoop(reloaderCtx)
		})
	}

	return reloader, nil
}

// MustNewReloader is like NewReloader but panics if the Reloader cannot be created.
func MustNewReloader(ctx context.Context, config ReloaderConfig) *Reloader {
	reloader, err := NewReloader(ctx, config)
	if err != nil {
		panic(err)
	}
	return reloader
}

// Reload forces an immediate certificate refresh.
func (r *Reloader) Reload(ctx context.Context) error {
	if r == nil {
		return errors.New("tls reloader is nil")
	}
	return r.reload(ctx, true)
}

// Close stops background reload activity.
func (r *Reloader) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		r.cancel()
		if r.watcher != nil {
			_ = r.watcher.Close()
		}
		r.wg.Wait()
	})
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	current := r.current.Load()
	if current == nil {
		return nil, errors.New("tls certificate not loaded")
	}
	return &current.certificate, nil
}

// TLSConfig builds a tls.Config backed by the Reloader.
func (r *Reloader) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: r.GetCertificate,
		MinVersion:     r.minVersion,
	}
}

// Version returns the active certificate material version.
func (r *Reloader) Version() string {
	if r == nil {
		return ""
	}
	current := r.current.Load()
	if current == nil {
		return ""
	}
	return current.version
}

func (r *Reloader) newWatcher() (*fsnotify.Watcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	dirs := map[string]struct{}{
		filepath.Dir(r.certFile): {},
		filepath.Dir(r.keyFile):  {},
	}
	for dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			return nil, fmt.Errorf("watch tls directory %q: %w", dir, err)
		}
	}
	return watcher, nil
}

func (r *Reloader) backgroundLoop(ctx context.Context) {
	var timer *time.Timer
	var timerCh <-chan time.Time
	if r.reloadInterval > 0 {
		timer = time.NewTimer(r.reloadInterval)
		timerCh = timer.C
		defer timer.Stop()
	}

	var events <-chan fsnotify.Event
	var watcherErrors <-chan error
	if r.watcher != nil {
		events = r.watcher.Events
		watcherErrors = r.watcher.Errors
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
			if !r.shouldReloadForEvent(event) {
				continue
			}
			if err := r.reload(ctx, false); err != nil {
				r.logError("reload tls certificate from file event failed", "event", event.String(), "error", err)
			}
		case err, ok := <-watcherErrors:
			if !ok {
				watcherErrors = nil
				continue
			}
			r.logError("watch tls certificate files failed", "error", err)
		case <-timerCh:
			if err := r.reload(ctx, false); err != nil {
				r.logError("reload tls certificate failed", "error", err)
				resetTimer(timer, r.retryInterval)
				continue
			}
			resetTimer(timer, r.reloadInterval)
		}
	}
}

func (r *Reloader) shouldReloadForEvent(event fsnotify.Event) bool {
	if !event.Has(fsnotify.Write) &&
		!event.Has(fsnotify.Create) &&
		!event.Has(fsnotify.Rename) &&
		!event.Has(fsnotify.Remove) {
		return false
	}
	return samePath(event.Name, r.certFile) || samePath(event.Name, r.keyFile)
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

func (r *Reloader) reload(ctx context.Context, force bool) error {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	material, err := r.loadMaterial(ctx)
	if err != nil {
		return err
	}
	if !force {
		current := r.current.Load()
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
	r.current.Store(next)
	r.logInfo("tls certificate loaded", "version", next.version)
	return nil
}

type material struct {
	certPEM []byte
	keyPEM  []byte
	version string
}

func (r *Reloader) loadMaterial(ctx context.Context) (material, error) {
	if err := ctx.Err(); err != nil {
		return material{}, err
	}

	certPEM, keyPEM, err := readTLSFiles(r.certFile, r.keyFile)
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

func (r *Reloader) logInfo(msg string, args ...any) {
	if r.logger == nil {
		return
	}
	args = append([]any{"cert_file", r.certFile, "key_file", r.keyFile}, args...)
	r.logger.Info(msg, args...)
}

func (r *Reloader) logError(msg string, args ...any) {
	if r.logger == nil {
		return
	}
	args = append([]any{"cert_file", r.certFile, "key_file", r.keyFile}, args...)
	r.logger.Error(msg, args...)
}
