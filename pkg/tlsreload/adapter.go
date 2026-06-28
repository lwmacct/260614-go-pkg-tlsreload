package tlsreload

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Adapter reads certificate material from a URI scheme that is not built in.
type Adapter interface {
	Scheme() string
	Read(ctx context.Context, location string) ([]byte, error)
}

func newAdapterMap(adapters []Adapter) (map[string]Adapter, error) {
	if len(adapters) == 0 {
		return map[string]Adapter{}, nil
	}

	adapterMap := make(map[string]Adapter, len(adapters))
	for _, adapter := range adapters {
		if adapter == nil {
			return nil, errors.New("tls adapter must not be nil")
		}
		scheme := strings.ToLower(strings.TrimSpace(adapter.Scheme()))
		if scheme == "" {
			return nil, errors.New("tls adapter scheme must not be empty")
		}
		switch scheme {
		case "file", "http", "https":
			return nil, fmt.Errorf("tls adapter scheme %q is reserved", scheme)
		}
		if _, exists := adapterMap[scheme]; exists {
			return nil, fmt.Errorf("tls adapter scheme %q is registered more than once", scheme)
		}
		adapterMap[scheme] = adapter
	}
	return adapterMap, nil
}
