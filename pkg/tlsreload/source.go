package tlsreload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	onepassword "github.com/1password/onepassword-sdk-go"
)

const (
	// #nosec G101 -- this is an environment variable name, not a token value.
	defaultOnePasswordTokenEnv = "OP_SERVICE_ACCOUNT_TOKEN"
	maxTLSMaterialBytes        = 4 << 20
)

type loaderOptions struct {
	allowInsecureHTTP   bool
	httpClient          *http.Client
	onePasswordToken    string
	onePasswordTokenEnv string
}

var resolveOnePasswordLocation = defaultResolveOnePasswordLocation

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

	parsed, scheme := parseLocation(location)
	switch scheme {
	case "":
		// #nosec G304 -- certificate paths are provided by the embedding application configuration.
		return os.ReadFile(location)
	case "file":
		path, ok := localFilePath(location)
		if !ok {
			return nil, fmt.Errorf("invalid file uri %q", location)
		}
		// #nosec G304 -- certificate paths are provided by the embedding application configuration.
		return os.ReadFile(path)
	case "https":
		return readHTTPLocation(ctx, parsed, options)
	case "http":
		if !options.allowInsecureHTTP {
			return nil, errors.New("http tls material source requires AllowInsecureHTTP")
		}
		return readHTTPLocation(ctx, parsed, options)
	case "op":
		secret, err := resolveOnePasswordLocation(ctx, location, options)
		if err != nil {
			return nil, err
		}
		return []byte(secret), nil
	default:
		return nil, fmt.Errorf("unsupported tls material scheme %q", scheme)
	}
}

func readHTTPLocation(ctx context.Context, parsed *url.URL, options loaderOptions) ([]byte, error) {
	client := options.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	requestURL := *parsed
	user := requestURL.User
	requestURL.User = nil

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	if user != nil {
		password, _ := user.Password()
		request.SetBasicAuth(user.Username(), password)
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("http tls material source returned %s", response.Status)
	}

	limited := io.LimitReader(response.Body, maxTLSMaterialBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxTLSMaterialBytes {
		return nil, fmt.Errorf("http tls material source exceeds %d bytes", maxTLSMaterialBytes)
	}
	return body, nil
}

func defaultResolveOnePasswordLocation(ctx context.Context, location string, options loaderOptions) (string, error) {
	token := options.onePasswordToken
	if token == "" {
		tokenEnv := options.onePasswordTokenEnv
		if tokenEnv == "" {
			tokenEnv = defaultOnePasswordTokenEnv
		}
		token = os.Getenv(tokenEnv)
		if token == "" {
			return "", fmt.Errorf("1password service account token environment variable %s is empty", tokenEnv)
		}
	}

	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo("tlsreload", "0"),
	)
	if err != nil {
		return "", err
	}
	return client.Secrets().Resolve(ctx, location)
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
	case "http", "https", "op":
		return trimmed, nil
	default:
		return "", fmt.Errorf("unsupported tls material scheme %q", scheme)
	}
}

func localFilePath(location string) (string, bool) {
	parsed, scheme := parseLocation(location)
	switch scheme {
	case "":
		return location, true
	case "file":
		if parsed.Host != "" && parsed.Host != "localhost" {
			return "", false
		}
		return filepath.Clean(parsed.Path), true
	default:
		return "", false
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
