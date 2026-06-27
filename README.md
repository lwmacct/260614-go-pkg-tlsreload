# tlsreload

面向 Go 服务的文件证书热重载工具。

`tlsreload` 会加载证书和私钥文件，为 `net/http` 提供可直接使用的
`tls.Config`。后续重载失败时，会继续使用上一份有效证书，避免服务因为
证书文件短暂不完整或内容错误而中断 TLS 握手。

## 功能

- 使用文件系统事件监听证书和私钥变化。
- 监听父目录而不是单个文件，可覆盖临时文件写入后 rename 替换的更新方式。
- 支持通过配置间隔启用兜底轮询。
- 部分写入或无效更新时保留上一份有效证书。
- 支持通过 `Reload(ctx)` 手动触发重载。

## 安装

```sh
go get github.com/lwmacct/260614-go-pkg-tlsreload
```

## 使用

应用配置装配优先使用 `Config` 和 `Manager`：

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

	manager, err := tlsreload.NewManager(ctx, tlsreload.Config{
		Enabled:  true,
		CertFile: "/etc/ssl/fullchain.pem",
		KeyFile:  "/etc/ssl/privkey.pem",
		Interval: 3 * time.Second,
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

只需要底层热重载器时，可以直接使用 `Reloader`：

```go
package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/lwmacct/260614-go-pkg-tlsreload/pkg/tlsreload"
)

func main() {
	ctx := context.Background()

	reloader := tlsreload.MustNewReloader(ctx, tlsreload.ReloaderConfig{
		CertFile:       "/etc/ssl/fullchain.pem",
		KeyFile:        "/etc/ssl/privkey.pem",
		MinVersion:     tls.VersionTLS12,
		ReloadInterval: 3 * time.Second,
	})
	defer reloader.Close()

	server := &http.Server{
		Addr:      ":443",
		Handler:   http.DefaultServeMux,
		TLSConfig: reloader.TLSConfig(),
	}

	panic(server.ListenAndServeTLS("", ""))
}
```

## 重载行为

文件系统事件是主要重载触发方式。`Config.Interval` 和
`ReloaderConfig.ReloadInterval` 只作为兜底轮询间隔，用于覆盖事件丢失或
watcher 受限的场景。

- `Interval`/`ReloadInterval > 0`：按该间隔启用兜底轮询。
- `Interval`/`ReloadInterval == 0`：禁用兜底轮询；文件系统事件仍会触发重载。
- `RetryInterval`：兜底轮询重载失败后，下次兜底轮询前的等待时间。

首次加载必须成功。启动后如果重载失败，配置了 logger 时会记录错误，
并继续使用上一份有效证书。

## API

```go
type Config struct {
	Enabled  bool          `json:"enabled"   desc:"是否启用 HTTPS TLS"`
	CertFile string        `json:"cert-file" desc:"TLS 证书文件路径"`
	KeyFile  string        `json:"key-file"  desc:"TLS 私钥文件路径"`
	Interval time.Duration `json:"interval"  desc:"TLS 证书文件重载兜底轮询间隔，0 表示禁用兜底轮询"`
}

type Options struct {
	MinVersion    uint16
	RetryInterval time.Duration
	Logger        *slog.Logger
}

type ReloaderConfig struct {
	CertFile       string
	KeyFile        string
	ReloadInterval time.Duration
	RetryInterval  time.Duration
	MinVersion     uint16
	Logger         *slog.Logger
}
```

`Options.MinVersion` 和 `ReloaderConfig.MinVersion` 默认是
`tls.VersionTLS12`。`Options.RetryInterval` 和
`ReloaderConfig.RetryInterval` 默认是 `2 * time.Second`。

主要方法：

```go
manager, err := tlsreload.NewManager(ctx, config, options)
tlsConfig := manager.TLSConfig()
enabled := manager.Enabled()
manager.Close()

reloader, err := tlsreload.NewReloader(ctx, config)
reloader = tlsreload.MustNewReloader(ctx, config)
err = reloader.Reload(ctx)
version := reloader.Version()
reloader.Close()
```
