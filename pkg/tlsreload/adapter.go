package tlsreload

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Adapter reads certificate material from one or more URI schemes.
type Adapter interface {
	Schemes() []string
	Read(ctx context.Context, location string) ([]byte, error)
}

// Watcher can be implemented by adapters that can map a location to local files
// suitable for fsnotify-based reload triggers.
type Watcher interface {
	WatchPaths(location string) ([]string, error)
}

func newAdapterMap(adapters []Adapter) (map[string]Adapter, error) {
	if len(adapters) == 0 {
		return map[string]Adapter{}, nil
	}

	adapterMap := make(map[string]Adapter)
	for _, adapter := range adapters {
		if adapter == nil {
			return nil, errors.New("tls adapter must not be nil")
		}
		schemes := adapter.Schemes()
		if len(schemes) == 0 {
			return nil, errors.New("tls adapter schemes must not be empty")
		}
		seen := make([]string, 0, len(schemes))
		for _, value := range schemes {
			scheme := strings.ToLower(strings.TrimSpace(value))
			if slices.Contains(seen, scheme) {
				return nil, fmt.Errorf("tls adapter scheme %q is registered more than once by the same adapter", scheme)
			}
			seen = append(seen, scheme)
			if _, exists := adapterMap[scheme]; exists {
				return nil, fmt.Errorf("tls adapter scheme %q is registered more than once", scheme)
			}
			adapterMap[scheme] = adapter
		}
	}
	return adapterMap, nil
}
