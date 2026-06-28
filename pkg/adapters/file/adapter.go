package file

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Adapter reads certificate material from local paths and file:// URIs.
type Adapter struct{}

func New() Adapter {
	return Adapter{}
}

func (Adapter) Schemes() []string {
	return []string{"", "file"}
}

func (Adapter) Read(ctx context.Context, location string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, ok := localPath(location)
	if !ok {
		return nil, fmt.Errorf("invalid file uri %q", location)
	}
	// #nosec G304 -- certificate paths are provided by the embedding application configuration.
	return os.ReadFile(path)
}

func (Adapter) WatchPaths(location string) ([]string, error) {
	path, ok := localPath(location)
	if !ok {
		return nil, fmt.Errorf("invalid file uri %q", location)
	}
	return []string{path}, nil
}

func localPath(location string) (string, bool) {
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
