package vault

import (
	"context"
	"errors"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestAdapterReadsRawVaultSecret(t *testing.T) {
	reader := &fakeReader{
		secrets: map[string]*vaultapi.Secret{
			"secret/data/prod/tls": {
				Data: map[string]any{
					"fullchain": "cert",
				},
			},
		},
	}
	adapter := New(Options{Reader: reader})

	body, err := adapter.Read(t.Context(), "vault://secret/data/prod/tls?field=fullchain")
	require.NoError(t, err)
	require.Equal(t, "cert", string(body))
	require.Equal(t, []readCall{{path: "secret/data/prod/tls"}}, reader.calls)
}

func TestAdapterReadsKVv2VaultSecret(t *testing.T) {
	reader := &fakeReader{
		secrets: map[string]*vaultapi.Secret{
			"secret/data/prod/tls": {
				Data: map[string]any{
					"data": map[string]any{
						"privkey": []byte("key"),
					},
				},
			},
		},
	}
	adapter := New(Options{Reader: reader})

	body, err := adapter.Read(t.Context(), "vault://secret/prod/tls?kv=v2&field=privkey&version=3")
	require.NoError(t, err)
	require.Equal(t, "key", string(body))
	require.Equal(t, []readCall{{
		path: "secret/data/prod/tls",
		data: map[string][]string{"version": {"3"}},
	}}, reader.calls)
}

func TestAdapterPropagatesVaultReadError(t *testing.T) {
	vaultErr := errors.New("permission denied")
	adapter := New(Options{
		Reader: &fakeReader{err: vaultErr},
	})

	_, err := adapter.Read(t.Context(), "vault://secret/data/prod/tls?field=fullchain")
	require.ErrorIs(t, err, vaultErr)
	require.ErrorContains(t, err, `read vault secret "secret/data/prod/tls"`)
}

func TestAdapterRejectsMissingSecretAndField(t *testing.T) {
	tests := []struct {
		name   string
		reader *fakeReader
		want   string
	}{
		{
			name: "missing secret",
			reader: &fakeReader{
				secrets: map[string]*vaultapi.Secret{},
			},
			want: "not found",
		},
		{
			name: "missing field",
			reader: &fakeReader{
				secrets: map[string]*vaultapi.Secret{
					"secret/data/prod/tls": {
						Data: map[string]any{},
					},
				},
			},
			want: `field "fullchain" not found`,
		},
		{
			name: "missing kv v2 data",
			reader: &fakeReader{
				secrets: map[string]*vaultapi.Secret{
					"secret/data/prod/tls": {
						Data: map[string]any{},
					},
				},
			},
			want: "has no data object",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := New(Options{Reader: test.reader})
			location := "vault://secret/data/prod/tls?field=fullchain"
			if test.name == "missing kv v2 data" {
				location = "vault://secret/prod/tls?kv=v2&field=fullchain"
			}
			_, err := adapter.Read(t.Context(), location)
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestAdapterRejectsInvalidLocations(t *testing.T) {
	tests := []struct {
		name     string
		location string
		want     string
	}{
		{
			name:     "wrong scheme",
			location: "https://secret/data/prod/tls?field=fullchain",
			want:     "scheme must be vault",
		},
		{
			name:     "userinfo",
			location: "vault://user@secret/data/prod/tls?field=fullchain",
			want:     "userinfo is not supported",
		},
		{
			name:     "missing mount",
			location: "vault:///data/prod/tls?field=fullchain",
			want:     "mount or path is required",
		},
		{
			name:     "missing path",
			location: "vault://secret?field=fullchain",
			want:     "secret path is required",
		},
		{
			name:     "missing field",
			location: "vault://secret/data/prod/tls",
			want:     "field query parameter is required",
		},
		{
			name:     "unsupported query",
			location: "vault://secret/data/prod/tls?field=fullchain&namespace=admin",
			want:     `query parameter "namespace" is not supported`,
		},
		{
			name:     "unsupported kv",
			location: "vault://secret/data/prod/tls?field=fullchain&kv=v3",
			want:     `kv value "v3" is not supported`,
		},
		{
			name:     "unsafe path",
			location: "vault://secret/../tls?field=fullchain",
			want:     "not safe",
		},
	}

	adapter := New(Options{Reader: &fakeReader{}})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := adapter.Read(t.Context(), test.location)
			require.ErrorContains(t, err, test.want)
		})
	}
}

type readCall struct {
	path string
	data map[string][]string
}

type fakeReader struct {
	secrets map[string]*vaultapi.Secret
	err     error
	calls   []readCall
}

func (r *fakeReader) ReadWithContext(_ context.Context, path string) (*vaultapi.Secret, error) {
	r.calls = append(r.calls, readCall{path: path})
	if r.err != nil {
		return nil, r.err
	}
	return r.secrets[path], nil
}

func (r *fakeReader) ReadWithDataWithContext(
	_ context.Context,
	path string,
	data map[string][]string,
) (*vaultapi.Secret, error) {
	r.calls = append(r.calls, readCall{path: path, data: data})
	if r.err != nil {
		return nil, r.err
	}
	return r.secrets[path], nil
}
