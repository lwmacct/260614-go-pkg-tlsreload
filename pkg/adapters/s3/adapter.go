package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

// Client is the subset of the AWS S3 client used by Adapter.
type Client interface {
	GetObject(ctx context.Context, input *awss3.GetObjectInput, optFns ...func(*awss3.Options)) (*awss3.GetObjectOutput, error)
}

// Adapter reads certificate material from S3 objects.
type Adapter struct {
	Client              Client
	Config              *aws.Config
	LoadOptions         []func(*config.LoadOptions) error
	Region              string
	Endpoint            string
	UsePathStyle        bool
	Credentials         aws.CredentialsProvider
	ExpectedBucketOwner string
	RequesterPays       bool

	mu     sync.Mutex
	client Client
}

type Options struct {
	Client              Client
	Config              *aws.Config
	LoadOptions         []func(*config.LoadOptions) error
	Region              string
	Endpoint            string
	UsePathStyle        bool
	Credentials         aws.CredentialsProvider
	ExpectedBucketOwner string
	RequesterPays       bool
}

func New(options Options) *Adapter {
	var cfg *aws.Config
	if options.Config != nil {
		copied := options.Config.Copy()
		cfg = &copied
	}
	loadOptions := append([]func(*config.LoadOptions) error(nil), options.LoadOptions...)
	return &Adapter{
		Client:              options.Client,
		Config:              cfg,
		LoadOptions:         loadOptions,
		Region:              options.Region,
		Endpoint:            options.Endpoint,
		UsePathStyle:        options.UsePathStyle,
		Credentials:         options.Credentials,
		ExpectedBucketOwner: options.ExpectedBucketOwner,
		RequesterPays:       options.RequesterPays,
	}
}

func (a *Adapter) Scheme() string {
	return "s3"
}

func (a *Adapter) Read(ctx context.Context, location string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a == nil {
		return nil, errors.New("s3 adapter is nil")
	}

	parsed, err := parseLocation(location)
	if err != nil {
		return nil, err
	}

	client, err := a.s3Client(ctx)
	if err != nil {
		return nil, err
	}

	input := &awss3.GetObjectInput{
		Bucket: aws.String(parsed.bucket),
		Key:    aws.String(parsed.key),
	}
	if parsed.versionID != "" {
		input.VersionId = aws.String(parsed.versionID)
	}
	if a.ExpectedBucketOwner != "" {
		input.ExpectedBucketOwner = aws.String(a.ExpectedBucketOwner)
	}
	if a.RequesterPays {
		input.RequestPayer = types.RequestPayerRequester
	}

	output, err := client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("get s3 object %q/%q: %w", parsed.bucket, parsed.key, err)
	}
	if output.Body == nil {
		return nil, fmt.Errorf("get s3 object %q/%q returned empty body", parsed.bucket, parsed.key)
	}
	defer func() { _ = output.Body.Close() }()

	body, err := io.ReadAll(output.Body)
	if err != nil {
		return nil, fmt.Errorf("read s3 object %q/%q: %w", parsed.bucket, parsed.key, err)
	}
	return body, nil
}

func StaticCredentials(accessKeyID, secretAccessKey, sessionToken string) aws.CredentialsProvider {
	return credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, sessionToken)
}

func (a *Adapter) s3Client(ctx context.Context) (Client, error) {
	if a.Client != nil {
		return a.Client, nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.client != nil {
		return a.client, nil
	}

	cfg, err := a.awsConfig(ctx)
	if err != nil {
		return nil, err
	}
	a.client = awss3.NewFromConfig(cfg, func(options *awss3.Options) {
		if a.Endpoint != "" {
			options.BaseEndpoint = aws.String(a.Endpoint)
		}
		options.UsePathStyle = a.UsePathStyle
	})
	return a.client, nil
}

func (a *Adapter) awsConfig(ctx context.Context) (aws.Config, error) {
	var cfg aws.Config
	if a.Config != nil {
		cfg = a.Config.Copy()
	} else {
		loaded, err := config.LoadDefaultConfig(ctx, a.LoadOptions...)
		if err != nil {
			return aws.Config{}, fmt.Errorf("load aws config for s3 adapter: %w", err)
		}
		cfg = loaded
	}
	if a.Region != "" {
		cfg.Region = a.Region
	}
	if a.Endpoint != "" {
		cfg.BaseEndpoint = aws.String(a.Endpoint)
	}
	if a.Credentials != nil {
		cfg.Credentials = a.Credentials
	}
	return cfg, nil
}

type parsedLocation struct {
	bucket    string
	key       string
	versionID string
}

func parseLocation(location string) (parsedLocation, error) {
	parsed, err := url.Parse(location)
	if err != nil {
		return parsedLocation{}, fmt.Errorf("parse s3 location: %w", err)
	}
	if strings.ToLower(parsed.Scheme) != "s3" {
		return parsedLocation{}, errors.New("s3 location scheme must be s3")
	}
	if parsed.User != nil {
		return parsedLocation{}, errors.New("s3 location userinfo is not supported")
	}
	if parsed.Host == "" {
		return parsedLocation{}, errors.New("s3 location bucket is required")
	}
	if parsed.Fragment != "" {
		return parsedLocation{}, errors.New("s3 location fragment is not supported")
	}

	query := parsed.Query()
	for key := range query {
		if key != "versionId" {
			return parsedLocation{}, fmt.Errorf("s3 location query parameter %q is not supported", key)
		}
	}

	objectKey, err := objectKey(parsed)
	if err != nil {
		return parsedLocation{}, err
	}
	return parsedLocation{
		bucket:    parsed.Host,
		key:       objectKey,
		versionID: strings.TrimSpace(query.Get("versionId")),
	}, nil
}

func objectKey(parsed *url.URL) (string, error) {
	escaped := strings.TrimPrefix(parsed.EscapedPath(), "/")
	if escaped == "" {
		return "", errors.New("s3 location object key is required")
	}
	key, err := url.PathUnescape(escaped)
	if err != nil {
		return "", fmt.Errorf("parse s3 object key: %w", err)
	}
	if key == "" {
		return "", errors.New("s3 location object key is required")
	}
	return key, nil
}

var _ tlsreload.Adapter = (*Adapter)(nil)
