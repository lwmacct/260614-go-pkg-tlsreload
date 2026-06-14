package tlsreload

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewFileSourceRequiresPaths(t *testing.T) {
	_, err := NewFileSource(FileSourceConfig{})
	require.Error(t, err)
}
