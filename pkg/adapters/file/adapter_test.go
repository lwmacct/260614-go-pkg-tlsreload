package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdapterReadsLocalPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fullchain.pem")
	require.NoError(t, os.WriteFile(path, []byte("cert"), 0o600))

	body, err := New().Read(t.Context(), path)
	require.NoError(t, err)
	require.Equal(t, "cert", string(body))
}

func TestAdapterReadsFileURI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fullchain.pem")
	require.NoError(t, os.WriteFile(path, []byte("cert"), 0o600))

	body, err := New().Read(t.Context(), "file://"+path)
	require.NoError(t, err)
	require.Equal(t, "cert", string(body))
}

func TestAdapterWatchPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fullchain.pem")

	paths, err := New().WatchPaths("file://" + path)
	require.NoError(t, err)
	require.Equal(t, []string{path}, paths)
}

func TestAdapterRejectsRemoteFileURI(t *testing.T) {
	_, err := New().Read(t.Context(), "file://example.com/fullchain.pem")
	require.ErrorContains(t, err, "invalid file uri")
}
