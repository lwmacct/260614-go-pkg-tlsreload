package http

import (
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdapterReadsHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = w.Write([]byte("cert"))
	}))
	defer server.Close()

	body, err := New(Options{Client: server.Client()}).Read(t.Context(), server.URL)
	require.NoError(t, err)
	require.Equal(t, "cert", string(body))
}

func TestAdapterRejectsHTTPByDefault(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = w.Write([]byte("cert"))
	}))
	defer server.Close()

	_, err := New(Options{}).Read(t.Context(), server.URL)
	require.ErrorContains(t, err, "requires AllowInsecure")
}

func TestAdapterReadsHTTPWhenAllowed(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = w.Write([]byte("cert"))
	}))
	defer server.Close()

	body, err := New(Options{AllowInsecure: true}).Read(t.Context(), server.URL)
	require.NoError(t, err)
	require.Equal(t, "cert", string(body))
}

func TestAdapterUsesBasicAuth(t *testing.T) {
	server := httptest.NewTLSServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "user" || password != "pass" {
			w.WriteHeader(stdhttp.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("cert"))
	}))
	defer server.Close()

	body, err := New(Options{Client: server.Client()}).Read(t.Context(), withUser(server.URL, "user", "pass"))
	require.NoError(t, err)
	require.Equal(t, "cert", string(body))
}

func TestAdapterRejectsLargeBody(t *testing.T) {
	server := httptest.NewTLSServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		_, _ = w.Write([]byte("too-large"))
	}))
	defer server.Close()

	_, err := New(Options{Client: server.Client(), MaxBytes: 3}).Read(t.Context(), server.URL)
	require.ErrorContains(t, err, "exceeds 3 bytes")
}

func withUser(rawURL, username, password string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	parsed.User = url.UserPassword(username, password)
	return parsed.String()
}
