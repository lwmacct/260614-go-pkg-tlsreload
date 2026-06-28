package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdhttp "net/http"
	"net/url"
	"strings"
)

const DefaultMaxBytes = 4 << 20

// Adapter reads certificate material from http:// and https:// URLs.
type Adapter struct {
	Client        *stdhttp.Client
	AllowInsecure bool
	MaxBytes      int64
}

type Options struct {
	Client        *stdhttp.Client
	AllowInsecure bool
	MaxBytes      int64
}

func New(options Options) Adapter {
	return Adapter(options)
}

func (Adapter) Schemes() []string {
	return []string{"http", "https"}
}

func (a Adapter) Read(ctx context.Context, location string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	parsed, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parse http tls material source: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
	case "http":
		if !a.AllowInsecure {
			return nil, errors.New("http tls material source requires AllowInsecure")
		}
	default:
		return nil, fmt.Errorf("unsupported http adapter scheme %q", parsed.Scheme)
	}

	client := a.Client
	if client == nil {
		client = stdhttp.DefaultClient
	}

	requestURL := *parsed
	user := requestURL.User
	requestURL.User = nil

	request, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, requestURL.String(), nil)
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

	if response.StatusCode < stdhttp.StatusOK || response.StatusCode >= stdhttp.StatusMultipleChoices {
		return nil, fmt.Errorf("http tls material source returned %s", response.Status)
	}

	maxBytes := a.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	limited := io.LimitReader(response.Body, maxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("http tls material source exceeds %d bytes", maxBytes)
	}
	return body, nil
}
