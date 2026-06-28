package op

import (
	"context"
	"fmt"
	"os"

	opsdk "github.com/1password/onepassword-sdk-go"
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

const (
	DefaultTokenEnv           = "OP_SERVICE_ACCOUNT_TOKEN" // #nosec G101 -- environment variable name, not a token value.
	DefaultIntegrationName    = "tlsreload"
	DefaultIntegrationVersion = "0"
)

var newSecretsResolver = func(
	ctx context.Context,
	token, integrationName, integrationVersion string,
) (opsdk.SecretsAPI, error) {
	client, err := opsdk.NewClient(
		ctx,
		opsdk.WithServiceAccountToken(token),
		opsdk.WithIntegrationInfo(integrationName, integrationVersion),
	)
	if err != nil {
		return nil, err
	}
	return client.Secrets(), nil
}

// Adapter reads op:// secret references through a 1Password service account.
type Adapter struct {
	Token              string
	TokenEnv           string
	IntegrationName    string
	IntegrationVersion string
}

func New(options Options) Adapter {
	return Adapter(options)
}

type Options struct {
	Token              string
	TokenEnv           string
	IntegrationName    string
	IntegrationVersion string
}

func (a Adapter) Scheme() string {
	return "op"
}

func (a Adapter) Read(ctx context.Context, location string) ([]byte, error) {
	token := a.Token
	if token == "" {
		tokenEnv := a.TokenEnv
		if tokenEnv == "" {
			tokenEnv = DefaultTokenEnv
		}
		token = os.Getenv(tokenEnv)
		if token == "" {
			return nil, fmt.Errorf("1password service account token environment variable %s is empty", tokenEnv)
		}
	}

	integrationName := a.IntegrationName
	if integrationName == "" {
		integrationName = DefaultIntegrationName
	}
	integrationVersion := a.IntegrationVersion
	if integrationVersion == "" {
		integrationVersion = DefaultIntegrationVersion
	}

	secrets, err := newSecretsResolver(ctx, token, integrationName, integrationVersion)
	if err != nil {
		return nil, err
	}
	secret, err := secrets.Resolve(ctx, location)
	if err != nil {
		return nil, err
	}
	return []byte(secret), nil
}

var _ tlsreload.Adapter = Adapter{}
