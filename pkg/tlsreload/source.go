package tlsreload

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

const (
	maxTLSMaterialBytes = 4 << 20
)

type loaderOptions struct {
	adapters map[string]Adapter
}

func readTLSLocations(ctx context.Context, certLocation, keyLocation string, options loaderOptions) ([]byte, []byte, error) {
	certPEM, err := readTLSLocation(ctx, certLocation, options)
	if err != nil {
		return nil, nil, fmt.Errorf("read tls cert file: %w", err)
	}
	keyPEM, err := readTLSLocation(ctx, keyLocation, options)
	if err != nil {
		return nil, nil, fmt.Errorf("read tls key file: %w", err)
	}
	return certPEM, keyPEM, nil
}

func readTLSLocation(ctx context.Context, location string, options loaderOptions) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	_, scheme := parseLocation(location)
	adapter := options.adapters[scheme]
	if adapter == nil {
		return nil, fmt.Errorf("unsupported tls material scheme %q", scheme)
	}
	body, err := adapter.Read(ctx, location)
	if err != nil {
		return nil, err
	}
	if len(body) > maxTLSMaterialBytes {
		source := scheme
		if source == "" {
			source = "file"
		}
		return nil, fmt.Errorf("%s tls material source exceeds %d bytes", source, maxTLSMaterialBytes)
	}
	return body, nil
}

func normalizeTLSLocation(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse tls material location: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "":
		return filepath.Clean(trimmed), nil
	case "file":
		if parsed.Host != "" && parsed.Host != "localhost" {
			return "", fmt.Errorf("tls file uri host %q is not supported", parsed.Host)
		}
		if parsed.Path == "" {
			return "", errors.New("tls file uri path is required")
		}
		return parsed.String(), nil
	case "http", "https":
		return trimmed, nil
	default:
		return trimmed, nil
	}
}

func parseLocation(location string) (*url.URL, string) {
	parsed, err := url.Parse(location)
	if err != nil {
		return &url.URL{}, ""
	}
	return parsed, strings.ToLower(parsed.Scheme)
}

func redactLocation(location string) string {
	parsed, scheme := parseLocation(location)
	if scheme == "" || parsed.User == nil {
		return location
	}
	redacted := *parsed
	redacted.User = url.UserPassword(parsed.User.Username(), "xxxxx")
	return redacted.String()
}
