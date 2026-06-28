package git

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

const (
	DefaultRef         = "HEAD"
	DefaultSnapshotTTL = 2 * time.Second
)

// Adapter reads certificate material from files stored in git repositories.
type Adapter struct {
	CacheDir     string
	Repositories map[string]Repository
	SnapshotTTL  time.Duration

	mu        sync.Mutex
	repoLocks map[string]*sync.Mutex
	snapshots map[snapshotKey]snapshotRef
}

type Options struct {
	CacheDir     string
	Repositories map[string]Repository
	SnapshotTTL  time.Duration
}

type Repository struct {
	URL        string
	DefaultRef string
	Auth       transport.AuthMethod
}

func New(options Options) *Adapter {
	repositories := make(map[string]Repository, len(options.Repositories))
	maps.Copy(repositories, options.Repositories)
	return &Adapter{
		CacheDir:     options.CacheDir,
		Repositories: repositories,
		SnapshotTTL:  options.SnapshotTTL,
		repoLocks:    make(map[string]*sync.Mutex),
		snapshots:    make(map[snapshotKey]snapshotRef),
	}
}

func (a *Adapter) Schemes() []string {
	return []string{"git"}
}

func (a *Adapter) Read(ctx context.Context, location string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a == nil {
		return nil, errors.New("git adapter is nil")
	}

	parsed, err := parseLocation(location)
	if err != nil {
		return nil, err
	}
	repository, ok := a.Repositories[parsed.repository]
	if !ok {
		return nil, fmt.Errorf("git repository %q is not configured", parsed.repository)
	}
	if strings.TrimSpace(repository.URL) == "" {
		return nil, fmt.Errorf("git repository %q url is empty", parsed.repository)
	}
	if parsed.ref == "" {
		parsed.ref = repository.DefaultRef
	}
	if parsed.ref == "" {
		parsed.ref = DefaultRef
	}

	repoLock := a.lockForRepository(parsed.repository)
	repoLock.Lock()
	defer repoLock.Unlock()

	repo, err := a.openOrClone(ctx, parsed.repository, repository)
	if err != nil {
		return nil, err
	}

	hash, ok := a.cachedSnapshot(parsed.repository, repository.URL, parsed.ref)
	if !ok {
		fetchErr := fetch(ctx, repo, repository)
		if fetchErr != nil {
			return nil, fetchErr
		}
		hash, err = resolveRevision(repo, parsed.ref)
		if err != nil {
			return nil, err
		}
		a.rememberSnapshot(parsed.repository, repository.URL, parsed.ref, hash)
	}

	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("load git commit %s: %w", hash, err)
	}
	file, err := commit.File(parsed.filePath)
	if err != nil {
		return nil, fmt.Errorf("read git file %q at %s: %w", parsed.filePath, hash, err)
	}
	reader, err := file.Reader()
	if err != nil {
		return nil, fmt.Errorf("open git file %q at %s: %w", parsed.filePath, hash, err)
	}
	defer func() { _ = reader.Close() }()

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read git file %q at %s: %w", parsed.filePath, hash, err)
	}
	return body, nil
}

func BasicAuth(username, password string) transport.AuthMethod {
	return &githttp.BasicAuth{Username: username, Password: password}
}

func TokenAuth(token string) transport.AuthMethod {
	return BasicAuth("git", token)
}

func SSHKey(user string, privateKey []byte, passphrase string) (transport.AuthMethod, error) {
	return gitssh.NewPublicKeys(user, privateKey, passphrase)
}

func SSHKeyFromFile(user, privateKeyFile, passphrase string) (transport.AuthMethod, error) {
	return gitssh.NewPublicKeysFromFile(user, privateKeyFile, passphrase)
}

type parsedLocation struct {
	repository string
	filePath   string
	ref        string
}

func parseLocation(location string) (parsedLocation, error) {
	parsed, err := url.Parse(location)
	if err != nil {
		return parsedLocation{}, fmt.Errorf("parse git location: %w", err)
	}
	if strings.ToLower(parsed.Scheme) != "git" {
		return parsedLocation{}, errors.New("git location scheme must be git")
	}
	if parsed.User != nil {
		return parsedLocation{}, errors.New("git location userinfo is not supported")
	}
	if parsed.Host == "" {
		return parsedLocation{}, errors.New("git location repository is required")
	}
	if parsed.Fragment != "" {
		return parsedLocation{}, errors.New("git location fragment is not supported")
	}

	query := parsed.Query()
	for key := range query {
		if key != "ref" {
			return parsedLocation{}, fmt.Errorf("git location query parameter %q is not supported", key)
		}
	}

	filePath, err := cleanGitFilePath(parsed.Path)
	if err != nil {
		return parsedLocation{}, err
	}
	return parsedLocation{
		repository: parsed.Host,
		filePath:   filePath,
		ref:        strings.TrimSpace(query.Get("ref")),
	}, nil
}

func cleanGitFilePath(value string) (string, error) {
	trimmed := strings.Trim(value, "/")
	if trimmed == "" {
		return "", errors.New("git location file path is required")
	}
	for segment := range strings.SplitSeq(trimmed, "/") {
		switch segment {
		case "", ".", "..":
			return "", fmt.Errorf("git location file path %q is not safe", value)
		}
	}
	cleaned := path.Clean(trimmed)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", fmt.Errorf("git location file path %q is not safe", value)
	}
	return cleaned, nil
}

func (a *Adapter) openOrClone(ctx context.Context, name string, repository Repository) (*gogit.Repository, error) {
	cacheDir, err := a.repositoryCacheDir(name, repository)
	if err != nil {
		return nil, err
	}
	_, statErr := os.Stat(cacheDir)
	if statErr == nil {
		repo, openErr := gogit.PlainOpen(cacheDir)
		if openErr != nil {
			return nil, fmt.Errorf("open git cache for repository %q: %w", name, openErr)
		}
		return repo, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("stat git cache for repository %q: %w", name, statErr)
	}

	mkdirErr := os.MkdirAll(filepath.Dir(cacheDir), 0o700)
	if mkdirErr != nil {
		return nil, fmt.Errorf("create git cache directory: %w", mkdirErr)
	}
	repo, err := gogit.PlainCloneContext(ctx, cacheDir, false, &gogit.CloneOptions{
		URL:        repository.URL,
		Auth:       repository.Auth,
		NoCheckout: true,
		Tags:       gogit.AllTags,
	})
	if err != nil {
		_ = os.RemoveAll(cacheDir)
		return nil, fmt.Errorf("clone git repository %q: %w", name, err)
	}
	return repo, nil
}

func (a *Adapter) repositoryCacheDir(name string, repository Repository) (string, error) {
	root := strings.TrimSpace(a.CacheDir)
	if root == "" {
		userCacheDir, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("resolve user cache directory: %w", err)
		}
		root = filepath.Join(userCacheDir, "tlsreload", "git")
	}

	sum := sha256.Sum256([]byte(name + "\x00" + repository.URL))
	return filepath.Join(root, safeName(name)+"-"+hex.EncodeToString(sum[:])[:16]), nil
}

func safeName(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if r == '-' || r == '_' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
			continue
		}
		builder.WriteByte('-')
	}
	result := strings.Trim(builder.String(), "-.")
	if result == "" {
		return "repo"
	}
	return result
}

func fetch(ctx context.Context, repo *gogit.Repository, repository Repository) error {
	err := repo.FetchContext(ctx, &gogit.FetchOptions{
		Auth:  repository.Auth,
		Tags:  gogit.AllTags,
		Force: true,
	})
	if err == nil || errors.Is(err, gogit.NoErrAlreadyUpToDate) {
		return nil
	}
	return fmt.Errorf("fetch git repository: %w", err)
}

func resolveRevision(repo *gogit.Repository, ref string) (plumbing.Hash, error) {
	var candidates []string
	switch {
	case ref == "HEAD":
		candidates = []string{"refs/remotes/origin/HEAD", "origin/HEAD", "HEAD"}
	case strings.HasPrefix(ref, "refs/") || plumbing.IsHash(ref) || strings.ContainsAny(ref, "~^:{} "):
		candidates = []string{ref}
	default:
		candidates = []string{
			"origin/" + ref,
			"refs/remotes/origin/" + ref,
			"refs/heads/" + ref,
			"refs/tags/" + ref,
			ref,
		}
	}
	if !strings.HasPrefix(ref, "refs/") && strings.ContainsAny(ref, "~^") {
		candidates = append(candidates,
			"origin/"+ref,
			"refs/remotes/origin/"+ref,
		)
	}

	var lastErr error
	for _, candidate := range candidates {
		hash, err := repo.ResolveRevision(plumbing.Revision(candidate))
		if err == nil {
			return *hash, nil
		}
		lastErr = err
	}
	return plumbing.ZeroHash, fmt.Errorf("resolve git ref %q: %w", ref, lastErr)
}

type snapshotKey struct {
	repository string
	url        string
	ref        string
}

type snapshotRef struct {
	hash      plumbing.Hash
	expiresAt time.Time
}

func (a *Adapter) snapshotTTL() time.Duration {
	if a.SnapshotTTL < 0 {
		return 0
	}
	if a.SnapshotTTL == 0 {
		return DefaultSnapshotTTL
	}
	return a.SnapshotTTL
}

func (a *Adapter) cachedSnapshot(repository, repositoryURL, ref string) (plumbing.Hash, bool) {
	ttl := a.snapshotTTL()
	if ttl <= 0 {
		return plumbing.ZeroHash, false
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	snapshot, ok := a.snapshots[snapshotKey{repository: repository, url: repositoryURL, ref: ref}]
	if !ok || time.Now().After(snapshot.expiresAt) {
		return plumbing.ZeroHash, false
	}
	return snapshot.hash, true
}

func (a *Adapter) rememberSnapshot(repository, repositoryURL, ref string, hash plumbing.Hash) {
	ttl := a.snapshotTTL()
	if ttl <= 0 {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.snapshots == nil {
		a.snapshots = make(map[snapshotKey]snapshotRef)
	}
	a.snapshots[snapshotKey{repository: repository, url: repositoryURL, ref: ref}] = snapshotRef{
		hash:      hash,
		expiresAt: time.Now().Add(ttl),
	}
}

func (a *Adapter) lockForRepository(name string) *sync.Mutex {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.repoLocks == nil {
		a.repoLocks = make(map[string]*sync.Mutex)
	}
	repoLock := a.repoLocks[name]
	if repoLock == nil {
		repoLock = &sync.Mutex{}
		a.repoLocks[name] = repoLock
	}
	return repoLock
}

var _ tlsreload.Adapter = (*Adapter)(nil)
