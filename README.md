# tlsreload

面向 Go 服务的文件证书热重载工具。

`tlsreload` 会从本地文件、HTTP(S) 或外部 adapter 加载证书和私钥，为 `net/http` 提供可直接使用的
`tls.Config`。后续重载失败时，会继续使用上一份有效证书，避免服务因为
证书文件短暂不完整或内容错误而中断 TLS 握手。

## 功能

- 使用文件系统事件监听证书和私钥变化。
- 监听父目录而不是单个文件，可覆盖临时文件写入后 rename 替换的更新方式。
- 支持 `https://`、`http://` 和通过 adapter 解析的 `op://`、`vault://`、`git://`、`s3://` 证书来源。
- 支持通过配置间隔启用兜底轮询。
- 部分写入或无效更新时保留上一份有效证书。
- 支持通过 `Reload(ctx)` 手动触发重载。

## 安装

```sh
go get github.com/lwmacct/260614-go-pkg-tlsreload
```

## 使用

应用配置装配使用 `Config` 和 `Options` 创建 `Manager`。`Config` 适合直接嵌入应用配置文件或 CLI flag 结构；`Options` 用于 logger、TLS 最低版本等运行时对象。

```go
package main

import (
	"context"
	"net/http"

	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

func main() {
	ctx := context.Background()

	manager, err := tlsreload.New(ctx, tlsreload.Config{
		Enabled:      true,
		CertFile:     "/etc/ssl/fullchain.pem",
		KeyFile:      "/etc/ssl/privkey.pem",
	}, tlsreload.Options{})
	if err != nil {
		panic(err)
	}
	defer manager.Close()

	server := &http.Server{
		Addr:      ":443",
		Handler:   http.DefaultServeMux,
		TLSConfig: manager.TLSConfig(),
	}

	panic(server.ListenAndServeTLS("", ""))
}
```

## 重载行为

本地文件来源会使用文件系统事件触发重载。`Config.PollInterval` 作为兜底轮询间隔，用于覆盖事件丢失、watcher 受限或远端来源变化的场景。

- `PollInterval > 0`：按该间隔启用兜底轮询。
- 未配置 `PollInterval` 时使用默认 `5 * time.Minute`。
- `Options.PollJitterRatio`：兜底轮询成功后按比例加入向下随机抖动，默认 `0.10`，
  即实际间隔在 `PollInterval * 90%` 到 `PollInterval` 之间。
- `RetryInterval`：兜底轮询重载失败后，下次兜底轮询前的等待时间。

首次加载必须成功。启动后如果重载失败，配置了 logger 时会记录错误，
并继续使用上一份有效证书。

## 证书来源

`Config.CertFile` 和 `Config.KeyFile` 支持以下格式：

- 本地路径：`/etc/ssl/fullchain.pem`
- 文件 URI：`file:///etc/ssl/fullchain.pem`
- HTTPS URL：`https://user:pass@example.com/fullchain.pem`
- HTTP URL：`http://example.com/fullchain.pem`，需要 `Options.AllowInsecureHTTP`
- 1Password secret reference：`op://vault/item/field`
- Vault secret field：`vault://secret/data/prod/tls?field=fullchain`
- Git repository file：`git://repo-name/path/in/repo.pem?ref=main`
- S3 object：`s3://bucket-name/path/in/bucket.pem?versionId=...`

HTTP(S) URL 支持通过 URL userinfo 设置 Basic Auth。日志会隐藏 URL 中的密码。

## 适配器用法

所有证书来源都通过 adapter 读取。`file`、`http`、`https` adapters 默认注册，所以本地路径、
`file://`、`https://` 可直接使用，`http://` 仍需要 `Options.AllowInsecureHTTP`。
`op://`、`vault://`、`git://`、`s3://` 等外部来源需要通过 `Options.Adapters`
显式注入适配器。主包只直接依赖默认 adapters，不直接依赖 1Password、Vault、Git 或 S3
SDK，避免不使用相关来源的项目被迫引入额外依赖。

如果要完全自定义来源集合，可设置 `Options.DisableDefaultAdapters`，然后自行注册需要的
adapters，包括 `pkg/adapters/file` 和 `pkg/adapters/http`。

### 1Password

如果要使用 1Password service account，可引入 `pkg/adapters/op`：

```go
import (
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/adapters/op"
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

manager, err := tlsreload.New(ctx, config, tlsreload.Options{
	Adapters: []tlsreload.Adapter{
		op.New(op.Options{
			TokenEnv: op.DefaultTokenEnv,
		}),
	},
})
```

`op.Adapter` 默认从 `OP_SERVICE_ACCOUNT_TOKEN` 读取 token，也可以通过
`Options.Token` 直接传入，或通过 `Options.TokenEnv` 指定环境变量名。同一个 vault
中可能存在同名 item，生产配置建议使用 item ID 作为 `op://vault/item/field`
中的 item 段，避免用户临时复制副本时造成名称解析歧义。

### Vault

如果要从 HashiCorp Vault 读取证书材料，可引入 `pkg/adapters/vault`。raw logical
path 可以直接写成 `vault://secret/data/prod/tls?field=fullchain`；KV v2 也可以使用
便捷写法 `vault://secret/prod/tls?kv=v2&field=fullchain`，adapter 会读取
`secret/data/prod/tls` 并从返回的 `data` 对象中取字段：

```go
import (
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/adapters/vault"
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

manager, err := tlsreload.New(ctx, tlsreload.Config{
	Enabled:  true,
	CertFile: "vault://secret/prod/tls?kv=v2&field=fullchain",
	KeyFile:  "vault://secret/prod/tls?kv=v2&field=privkey",
}, tlsreload.Options{
	Adapters: []tlsreload.Adapter{
		vault.New(vault.Options{
			Address:  "https://vault.example.com",
			TokenEnv: vault.DefaultTokenEnv,
		}),
	},
})
```

`vault.Options.Client` 可注入已经完成认证的 Vault client；否则 adapter 会基于
Vault 默认配置创建 client，并可通过 `Options.Address`、`Options.Token`、
`Options.TokenEnv`、`Options.Namespace` 覆盖连接参数。KV v2 可在 URI 上追加
`version` 查询参数读取指定版本。Vault 远端变化依赖
`PollInterval` 或手动 `Reload(ctx)` 触发重新读取。

### Git

如果要从 Git 仓库读取证书材料，可引入 `pkg/adapters/git`。`git://` URI 中的
host 是仓库别名，真实仓库 URL 和认证信息通过 adapter options 配置，避免把凭据写进
证书路径配置：

```go
import (
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/adapters/git"
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

manager, err := tlsreload.New(ctx, tlsreload.Config{
	Enabled:  true,
	CertFile: "git://infra-certs/prod/fullchain.pem?ref=main",
	KeyFile:  "git://infra-certs/prod/privkey.pem?ref=main",
}, tlsreload.Options{
	Adapters: []tlsreload.Adapter{
		git.New(git.Options{
			CacheDir: "/var/cache/tlsreload/git",
			Repositories: map[string]git.Repository{
				"infra-certs": {
					URL:        "git@github.com:example/infra-certs.git",
					DefaultRef: "main",
				},
			},
		}),
	},
})
```

`git.Repository.Auth` 支持传入 go-git 的 auth method，也可以使用
`git.BasicAuth`、`git.TokenAuth`、`git.SSHKey` 或
`git.SSHKeyFromFile`。Git 远端变化依赖 `PollInterval` 或手动
`Reload(ctx)` 触发重新读取。为了确保证书和私钥来自同一个 commit，adapter 默认会把
同一个仓库和 ref 的解析结果短暂缓存；生产配置更建议使用 tag 或 commit SHA 作为
`ref`。

### S3

如果要从 S3 或 S3-compatible 对象存储读取证书材料，可引入 `pkg/adapters/s3`。
`s3://` URI 中只包含 bucket、object key 和可选 `versionId`，region、endpoint 和
认证信息通过 adapter options 或 AWS SDK 默认配置链提供：

```go
import (
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/adapters/s3"
	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

manager, err := tlsreload.New(ctx, tlsreload.Config{
	Enabled:  true,
	CertFile: "s3://infra-certs/prod/fullchain.pem",
	KeyFile:  "s3://infra-certs/prod/privkey.pem",
}, tlsreload.Options{
	Adapters: []tlsreload.Adapter{
		s3.New(s3.Options{
			Region: "us-east-1",
		}),
	},
})
```

对于 MinIO、Cloudflare R2 等 S3-compatible 服务，可配置自定义 endpoint、path-style
和静态凭据：

```go
s3.New(s3.Options{
	Region:       "auto",
	Endpoint:     "https://s3.example.com",
	UsePathStyle: true,
	Credentials:  s3.StaticCredentials("access-key", "secret-key", ""),
})
```

如果应用已经自行创建了 AWS S3 client，也可以通过 `Options.Client` 直接注入。
S3 对象变化依赖 `PollInterval` 或手动 `Reload(ctx)` 触发重新读取。

## API

```go
type Config struct {
	Enabled      bool          `json:"enabled"   desc:"是否启用 HTTPS TLS"`
	CertFile     string        `json:"cert-file" desc:"TLS 证书文件路径或 URI"`
	KeyFile      string        `json:"key-file"  desc:"TLS 私钥文件路径或 URI"`
	PollInterval time.Duration `json:"poll-interval" desc:"TLS 证书文件重载兜底轮询间隔，未配置时使用默认间隔"`
}

type Options struct {
	MinVersion             uint16
	RetryInterval          time.Duration
	PollJitterRatio        float64
	Logger                 *slog.Logger
	AllowInsecureHTTP      bool
	HTTPClient             *http.Client
	Adapters               []Adapter
	DisableDefaultAdapters bool
}

type Adapter interface {
	Schemes() []string
	Read(ctx context.Context, location string) ([]byte, error)
}

type Watcher interface {
	WatchPaths(location string) ([]string, error)
}
```

`Config.PollInterval` 默认是 `5 * time.Minute`。`Options.PollJitterRatio` 默认是 `0.10`。
`Options.MinVersion` 默认是 `tls.VersionTLS12`。`Options.RetryInterval` 默认是 `2 * time.Second`。
默认 adapters 包含本地文件和 HTTP(S)；`Options.HTTPClient` 和
`Options.AllowInsecureHTTP` 用于配置默认 HTTP adapter。

主要方法：

```go
manager, err := tlsreload.New(ctx, config, options)
manager = tlsreload.MustNew(ctx, config, options)
tlsConfig := manager.TLSConfig()
enabled := manager.Enabled()
err = manager.Reload(ctx)
version := manager.Version()
manager.Close()
```
