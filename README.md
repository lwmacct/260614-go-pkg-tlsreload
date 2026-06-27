# tlsreload

面向 Go 服务的文件证书热重载工具。

`tlsreload` 会从本地文件、HTTP(S) 或 1Password 加载证书和私钥，为 `net/http` 提供可直接使用的
`tls.Config`。后续重载失败时，会继续使用上一份有效证书，避免服务因为
证书文件短暂不完整或内容错误而中断 TLS 握手。

## 功能

- 使用文件系统事件监听证书和私钥变化。
- 监听父目录而不是单个文件，可覆盖临时文件写入后 rename 替换的更新方式。
- 支持 `https://`、`http://` 和 `op://` 证书来源。
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
	"time"

	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

func main() {
	ctx := context.Background()

	manager, err := tlsreload.New(ctx, tlsreload.Config{
		Enabled:      true,
		CertFile:     "/etc/ssl/fullchain.pem",
		KeyFile:      "/etc/ssl/privkey.pem",
		PollInterval: 3 * time.Second,
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
- `PollInterval == 0`：禁用兜底轮询；本地文件系统事件仍会触发重载。
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

HTTP(S) URL 支持通过 URL userinfo 设置 Basic Auth。日志会隐藏 URL 中的密码。

1Password 使用官方 Go SDK 和 service account token。默认从
`OP_SERVICE_ACCOUNT_TOKEN` 读取 token，也可以通过 `Options.OnePasswordToken`
直接传入，或通过 `Options.OnePasswordTokenEnv` 指定环境变量名。同一个 vault
中可能存在同名 item，生产配置建议使用 item ID 作为 `op://vault/item/field`
中的 item 段，避免用户临时复制副本时造成名称解析歧义。

## API

```go
type Config struct {
	Enabled      bool          `json:"enabled"   desc:"是否启用 HTTPS TLS"`
	CertFile     string        `json:"cert-file" desc:"TLS 证书文件路径或 URI"`
	KeyFile      string        `json:"key-file"  desc:"TLS 私钥文件路径或 URI"`
	PollInterval time.Duration `json:"poll-interval" desc:"TLS 证书文件重载兜底轮询间隔，0 表示禁用兜底轮询"`
}

type Options struct {
	MinVersion          uint16
	RetryInterval       time.Duration
	Logger              *slog.Logger
	AllowInsecureHTTP   bool
	HTTPClient          *http.Client
	OnePasswordToken    string
	OnePasswordTokenEnv string
}
```

`Options.MinVersion` 默认是 `tls.VersionTLS12`。`Options.RetryInterval` 默认是 `2 * time.Second`。

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
