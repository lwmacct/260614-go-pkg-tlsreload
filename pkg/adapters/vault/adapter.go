package vault

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

const DefaultTokenEnv = "VAULT_TOKEN" // #nosec G101 -- environment variable name, not a token value.

// Reader is the subset of Vault logical reads used by Adapter.
type Reader interface {
	ReadWithContext(ctx context.Context, path string) (*vaultapi.Secret, error)
	ReadWithDataWithContext(ctx context.Context, path string, data map[string][]string) (*vaultapi.Secret, error)
}

// Adapter reads certificate material from HashiCorp Vault secrets.
type Adapter struct {
	Reader    Reader
	Client    *vaultapi.Client
	Config    *vaultapi.Config
	Address   string
	Token     string
	TokenEnv  string
	Namespace string

	mu     sync.Mutex
	reader Reader
}

type Options struct {
	Reader    Reader
	Client    *vaultapi.Client
	Config    *vaultapi.Config
	Address   string
	Token     string
	TokenEnv  string
	Namespace string
}

func New(options Options) *Adapter {
	return &Adapter{
		Reader:    options.Reader,
		Client:    options.Client,
		Config:    options.Config,
		Address:   options.Address,
		Token:     options.Token,
		TokenEnv:  options.TokenEnv,
		Namespace: options.Namespace,
	}
}

func (a *Adapter) Schemes() []string {
	return []string{"vault"}
}

func (a *Adapter) Read(ctx context.Context, location string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a == nil {
		return nil, errors.New("vault adapter is nil")
	}

	parsed, err := parseLocation(location)
	if err != nil {
		return nil, err
	}
	reader, err := a.vaultReader()
	if err != nil {
		return nil, err
	}

	var secret *vaultapi.Secret
	if parsed.version != "" {
		secret, err = reader.ReadWithDataWithContext(ctx, parsed.logicalPath, map[string][]string{
			"version": {parsed.version},
		})
	} else {
		secret, err = reader.ReadWithContext(ctx, parsed.logicalPath)
	}
	if err != nil {
		return nil, fmt.Errorf("read vault secret %q: %w", parsed.logicalPath, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault secret %q not found", parsed.logicalPath)
	}

	data := secret.Data
	if parsed.kvVersion == "v2" {
		nested, ok := secret.Data["data"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("vault kv v2 secret %q has no data object", parsed.logicalPath)
		}
		data = nested
	}
	value, ok := data[parsed.field]
	if !ok {
		return nil, fmt.Errorf("vault secret %q field %q not found", parsed.logicalPath, parsed.field)
	}
	body, err := materialBytes(value)
	if err != nil {
		return nil, fmt.Errorf("read vault secret %q field %q: %w", parsed.logicalPath, parsed.field, err)
	}
	return body, nil
}

func (a *Adapter) vaultReader() (Reader, error) {
	if a.Reader != nil {
		return a.Reader, nil
	}
	if a.Client != nil {
		return a.Client.Logical(), nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reader != nil {
		return a.reader, nil
	}

	cfg := a.Config
	if cfg == nil {
		cfg = vaultapi.DefaultConfig()
		if cfg.Error != nil {
			return nil, fmt.Errorf("load default vault config: %w", cfg.Error)
		}
	} else {
		cfg = a.Config
	}
	if a.Address != "" {
		cfg.Address = a.Address
	}

	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}
	if a.Token != "" {
		client.SetToken(a.Token)
	} else if a.TokenEnv != "" {
		token := os.Getenv(a.TokenEnv)
		if token == "" {
			return nil, fmt.Errorf("vault token environment variable %s is empty", a.TokenEnv)
		}
		client.SetToken(token)
	}
	if a.Namespace != "" {
		client.SetNamespace(a.Namespace)
	}

	a.reader = client.Logical()
	return a.reader, nil
}

type parsedLocation struct {
	logicalPath string
	field       string
	kvVersion   string
	version     string
}

func parseLocation(location string) (parsedLocation, error) {
	parsed, err := url.Parse(location)
	if err != nil {
		return parsedLocation{}, fmt.Errorf("parse vault location: %w", err)
	}
	if strings.ToLower(parsed.Scheme) != "vault" {
		return parsedLocation{}, errors.New("vault location scheme must be vault")
	}
	if parsed.User != nil {
		return parsedLocation{}, errors.New("vault location userinfo is not supported")
	}
	if parsed.Host == "" {
		return parsedLocation{}, errors.New("vault location mount or path is required")
	}
	if parsed.Fragment != "" {
		return parsedLocation{}, errors.New("vault location fragment is not supported")
	}

	query := parsed.Query()
	for key := range query {
		switch key {
		case "field", "kv", "version":
		default:
			return parsedLocation{}, fmt.Errorf("vault location query parameter %q is not supported", key)
		}
	}
	field := strings.TrimSpace(query.Get("field"))
	if field == "" {
		return parsedLocation{}, errors.New("vault location field query parameter is required")
	}
	kvVersion := strings.TrimSpace(query.Get("kv"))
	switch kvVersion {
	case "", "v1", "v2":
	default:
		return parsedLocation{}, fmt.Errorf("vault location kv value %q is not supported", kvVersion)
	}

	secretPath, err := cleanSecretPath(parsed.EscapedPath())
	if err != nil {
		return parsedLocation{}, err
	}
	logicalPath := parsed.Host + "/" + secretPath
	if kvVersion == "v2" {
		logicalPath = parsed.Host + "/data/" + secretPath
	}

	return parsedLocation{
		logicalPath: logicalPath,
		field:       field,
		kvVersion:   kvVersion,
		version:     strings.TrimSpace(query.Get("version")),
	}, nil
}

func cleanSecretPath(value string) (string, error) {
	escaped := strings.Trim(value, "/")
	if escaped == "" {
		return "", errors.New("vault location secret path is required")
	}
	unescaped, err := url.PathUnescape(escaped)
	if err != nil {
		return "", fmt.Errorf("parse vault secret path: %w", err)
	}
	for segment := range strings.SplitSeq(unescaped, "/") {
		switch segment {
		case "", ".", "..":
			return "", fmt.Errorf("vault location secret path %q is not safe", value)
		}
	}
	cleaned := path.Clean(unescaped)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("vault location secret path %q is not safe", value)
	}
	return cleaned, nil
}

func materialBytes(value any) ([]byte, error) {
	switch typed := value.(type) {
	case string:
		return []byte(typed), nil
	case []byte:
		return append([]byte(nil), typed...), nil
	case fmt.Stringer:
		return []byte(typed.String()), nil
	default:
		return nil, fmt.Errorf("unsupported value type %T", value)
	}
}

var _ tlsreload.Adapter = (*Adapter)(nil)
