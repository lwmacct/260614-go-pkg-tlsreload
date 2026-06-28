package git

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

func TestAdapterReadsFileFromRepository(t *testing.T) {
	source := newTestRepository(t, map[string]string{
		"certs/fullchain.pem": "cert-v1",
	})

	adapter := New(Options{
		CacheDir:    t.TempDir(),
		SnapshotTTL: -1,
		Repositories: map[string]Repository{
			"certs": {
				URL:        source.dir,
				DefaultRef: "master",
			},
		},
	})

	body, err := adapter.Read(t.Context(), "git://certs/certs/fullchain.pem")
	require.NoError(t, err)
	require.Equal(t, "cert-v1", string(body))
}

func TestAdapterFetchesUpdatedRef(t *testing.T) {
	source := newTestRepository(t, map[string]string{
		"certs/fullchain.pem": "cert-v1",
	})

	adapter := New(Options{
		CacheDir:    t.TempDir(),
		SnapshotTTL: -1,
		Repositories: map[string]Repository{
			"certs": {
				URL:        source.dir,
				DefaultRef: "master",
			},
		},
	})

	body, err := adapter.Read(t.Context(), "git://certs/certs/fullchain.pem")
	require.NoError(t, err)
	require.Equal(t, "cert-v1", string(body))

	source.commit(t, map[string]string{
		"certs/fullchain.pem": "cert-v2",
	})

	body, err = adapter.Read(t.Context(), "git://certs/certs/fullchain.pem")
	require.NoError(t, err)
	require.Equal(t, "cert-v2", string(body))
}

func TestAdapterKeepsSnapshotBrieflyForSameRef(t *testing.T) {
	source := newTestRepository(t, map[string]string{
		"certs/fullchain.pem": "cert-v1",
		"certs/privkey.pem":   "key-v1",
	})

	adapter := New(Options{
		CacheDir:    t.TempDir(),
		SnapshotTTL: time.Hour,
		Repositories: map[string]Repository{
			"certs": {
				URL:        source.dir,
				DefaultRef: "master",
			},
		},
	})

	cert, err := adapter.Read(t.Context(), "git://certs/certs/fullchain.pem")
	require.NoError(t, err)
	require.Equal(t, "cert-v1", string(cert))

	source.commit(t, map[string]string{
		"certs/fullchain.pem": "cert-v2",
		"certs/privkey.pem":   "key-v2",
	})

	key, err := adapter.Read(t.Context(), "git://certs/certs/privkey.pem")
	require.NoError(t, err)
	require.Equal(t, "key-v1", string(key))
}

func TestAdapterReadsExplicitRef(t *testing.T) {
	source := newTestRepository(t, map[string]string{
		"certs/fullchain.pem": "cert-v1",
	})
	first := source.head(t)
	source.commit(t, map[string]string{
		"certs/fullchain.pem": "cert-v2",
	})

	adapter := New(Options{
		CacheDir:    t.TempDir(),
		SnapshotTTL: -1,
		Repositories: map[string]Repository{
			"certs": {
				URL: source.dir,
			},
		},
	})

	body, err := adapter.Read(t.Context(), "git://certs/certs/fullchain.pem?ref="+first.String())
	require.NoError(t, err)
	require.Equal(t, "cert-v1", string(body))
}

func TestAdapterRejectsUnsafePath(t *testing.T) {
	adapter := New(Options{
		Repositories: map[string]Repository{
			"certs": {URL: "unused"},
		},
	})

	_, err := adapter.Read(t.Context(), "git://certs/../secret.pem")
	require.ErrorContains(t, err, "not safe")
}

func TestAdapterRejectsUnknownRepository(t *testing.T) {
	adapter := New(Options{})

	_, err := adapter.Read(t.Context(), "git://missing/certs/fullchain.pem")
	require.ErrorContains(t, err, `git repository "missing" is not configured`)
}

type testRepository struct {
	dir  string
	repo *gogit.Repository
}

func newTestRepository(t *testing.T, files map[string]string) *testRepository {
	t.Helper()

	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	require.NoError(t, err)

	result := &testRepository{dir: dir, repo: repo}
	result.commit(t, files)
	return result
}

func (r *testRepository) commit(t *testing.T, files map[string]string) {
	t.Helper()

	worktree, err := r.repo.Worktree()
	require.NoError(t, err)
	for name, content := range files {
		fullPath := filepath.Join(r.dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o700))
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0o600))
		_, err = worktree.Add(name)
		require.NoError(t, err)
	}
	_, err = worktree.Commit("update test files", &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  "tlsreload",
			Email: "tlsreload@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)
}

func (r *testRepository) head(t *testing.T) plumbing.Hash {
	t.Helper()

	head, err := r.repo.Head()
	require.NoError(t, err)
	return head.Hash()
}
