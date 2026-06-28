package s3

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"
)

func TestAdapterReadsS3Object(t *testing.T) {
	client := &fakeClient{
		body: "cert",
	}
	adapter := New(Options{
		Client:              client,
		ExpectedBucketOwner: "123456789012",
		RequesterPays:       true,
	})

	body, err := adapter.Read(t.Context(), "s3://cert-bucket/prod/fullchain.pem?versionId=v1")
	require.NoError(t, err)
	require.Equal(t, "cert", string(body))
	require.Len(t, client.inputs, 1)
	require.Equal(t, "cert-bucket", aws.ToString(client.inputs[0].Bucket))
	require.Equal(t, "prod/fullchain.pem", aws.ToString(client.inputs[0].Key))
	require.Equal(t, "v1", aws.ToString(client.inputs[0].VersionId))
	require.Equal(t, "123456789012", aws.ToString(client.inputs[0].ExpectedBucketOwner))
	require.Equal(t, types.RequestPayerRequester, client.inputs[0].RequestPayer)
}

func TestAdapterDecodesObjectKey(t *testing.T) {
	client := &fakeClient{
		body: "key",
	}
	adapter := New(Options{Client: client})

	body, err := adapter.Read(t.Context(), "s3://cert-bucket/prod/fullchain%20with%20space.pem")
	require.NoError(t, err)
	require.Equal(t, "key", string(body))
	require.Equal(t, "prod/fullchain with space.pem", aws.ToString(client.inputs[0].Key))
}

func TestAdapterPropagatesGetObjectError(t *testing.T) {
	s3Err := errors.New("access denied")
	adapter := New(Options{
		Client: &fakeClient{err: s3Err},
	})

	_, err := adapter.Read(t.Context(), "s3://cert-bucket/prod/fullchain.pem")
	require.ErrorIs(t, err, s3Err)
	require.ErrorContains(t, err, `get s3 object "cert-bucket"/"prod/fullchain.pem"`)
}

func TestAdapterRejectsEmptyBody(t *testing.T) {
	adapter := New(Options{
		Client: &fakeClient{nilBody: true},
	})

	_, err := adapter.Read(t.Context(), "s3://cert-bucket/prod/fullchain.pem")
	require.ErrorContains(t, err, "returned empty body")
}

func TestAdapterRejectsInvalidLocations(t *testing.T) {
	tests := []struct {
		name     string
		location string
		want     string
	}{
		{
			name:     "wrong scheme",
			location: "https://cert-bucket/prod/fullchain.pem",
			want:     "scheme must be s3",
		},
		{
			name:     "userinfo",
			location: "s3://user:pass@cert-bucket/prod/fullchain.pem",
			want:     "userinfo is not supported",
		},
		{
			name:     "missing bucket",
			location: "s3:///prod/fullchain.pem",
			want:     "bucket is required",
		},
		{
			name:     "missing key",
			location: "s3://cert-bucket",
			want:     "object key is required",
		},
		{
			name:     "fragment",
			location: "s3://cert-bucket/prod/fullchain.pem#x",
			want:     "fragment is not supported",
		},
		{
			name:     "unsupported query",
			location: "s3://cert-bucket/prod/fullchain.pem?region=us-east-1",
			want:     `query parameter "region" is not supported`,
		},
	}

	adapter := New(Options{Client: &fakeClient{body: "unused"}})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := adapter.Read(t.Context(), test.location)
			require.ErrorContains(t, err, test.want)
		})
	}
}

type fakeClient struct {
	body    string
	nilBody bool
	err     error
	inputs  []awss3.GetObjectInput
}

func (c *fakeClient) GetObject(
	_ context.Context,
	input *awss3.GetObjectInput,
	_ ...func(*awss3.Options),
) (*awss3.GetObjectOutput, error) {
	c.inputs = append(c.inputs, *input)
	if c.err != nil {
		return nil, c.err
	}
	if c.nilBody {
		return &awss3.GetObjectOutput{}, nil
	}
	return &awss3.GetObjectOutput{
		Body: io.NopCloser(strings.NewReader(c.body)),
	}, nil
}
