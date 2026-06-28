package op

import (
	"context"
	"errors"
	"testing"

	opsdk "github.com/1password/onepassword-sdk-go"
	"github.com/stretchr/testify/require"
)

func TestAdapterScheme(t *testing.T) {
	require.Equal(t, []string{"op"}, New(Options{}).Schemes())
}

func TestAdapterReadsWithExplicitToken(t *testing.T) {
	var captured factoryCall
	restoreSecretsResolver(t, func(
		_ context.Context,
		token, integrationName, integrationVersion string,
	) (opsdk.SecretsAPI, error) {
		captured = factoryCall{
			token:              token,
			integrationName:    integrationName,
			integrationVersion: integrationVersion,
		}
		return fakeSecrets{values: map[string]string{
			"op://vault/item/fullchain": "cert",
		}}, nil
	})

	adapter := New(Options{
		Token:              "direct-value",
		IntegrationName:    "custom",
		IntegrationVersion: "1.2.3",
	})

	body, err := adapter.Read(t.Context(), "op://vault/item/fullchain")
	require.NoError(t, err)
	require.Equal(t, "cert", string(body))
	require.Equal(t, factoryCall{
		token:              "direct-value",
		integrationName:    "custom",
		integrationVersion: "1.2.3",
	}, captured)
}

func TestAdapterReadsTokenFromEnvironmentWithDefaults(t *testing.T) {
	t.Setenv("OP_TEST_VALUE", "env-value")

	var captured factoryCall
	restoreSecretsResolver(t, func(
		_ context.Context,
		token, integrationName, integrationVersion string,
	) (opsdk.SecretsAPI, error) {
		captured = factoryCall{
			token:              token,
			integrationName:    integrationName,
			integrationVersion: integrationVersion,
		}
		return fakeSecrets{values: map[string]string{
			"op://vault/item/privkey": "key",
		}}, nil
	})

	body, err := New(Options{TokenEnv: "OP_TEST_VALUE"}).Read(t.Context(), "op://vault/item/privkey")
	require.NoError(t, err)
	require.Equal(t, "key", string(body))
	require.Equal(t, factoryCall{
		token:              "env-value",
		integrationName:    DefaultIntegrationName,
		integrationVersion: DefaultIntegrationVersion,
	}, captured)
}

func TestAdapterRejectsMissingEnvironmentToken(t *testing.T) {
	envName := "OP_EMPTY_" + "VALUE"
	unexpectedErr := errors.New("unexpected resolver factory call")
	t.Setenv(envName, "")
	restoreSecretsResolver(t, func(
		context.Context,
		string,
		string,
		string,
	) (opsdk.SecretsAPI, error) {
		t.Fatal("resolver factory must not be called")
		return nil, unexpectedErr
	})

	_, err := New(Options{TokenEnv: envName}).Read(t.Context(), "op://vault/item/fullchain")
	require.ErrorContains(t, err, "1password service account token environment variable "+envName+" is empty")
}

func TestAdapterPropagatesFactoryError(t *testing.T) {
	factoryErr := errors.New("factory failed")
	restoreSecretsResolver(t, func(
		context.Context,
		string,
		string,
		string,
	) (opsdk.SecretsAPI, error) {
		return nil, factoryErr
	})

	_, err := New(Options{Token: "direct-value"}).Read(t.Context(), "op://vault/item/fullchain")
	require.ErrorIs(t, err, factoryErr)
}

func TestAdapterPropagatesResolveError(t *testing.T) {
	resolveErr := errors.New("resolve failed")
	restoreSecretsResolver(t, func(
		context.Context,
		string,
		string,
		string,
	) (opsdk.SecretsAPI, error) {
		return fakeSecrets{err: resolveErr}, nil
	})

	_, err := New(Options{Token: "direct-value"}).Read(t.Context(), "op://vault/item/fullchain")
	require.ErrorIs(t, err, resolveErr)
}

type factoryCall struct {
	token              string
	integrationName    string
	integrationVersion string
}

type fakeSecrets struct {
	values map[string]string
	err    error
}

func (s fakeSecrets) Resolve(_ context.Context, secretReference string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return s.values[secretReference], nil
}

func (s fakeSecrets) ResolveAll(context.Context, []string) (opsdk.ResolveAllResponse, error) {
	return opsdk.ResolveAllResponse{}, nil
}

func restoreSecretsResolver(
	t *testing.T,
	replacement func(context.Context, string, string, string) (opsdk.SecretsAPI, error),
) {
	t.Helper()

	previous := newSecretsResolver
	newSecretsResolver = replacement
	t.Cleanup(func() {
		newSecretsResolver = previous
	})
}
