# tlsreload

面向 Go 服务的文件证书热重载工具。

`tlsreload` 会加载证书和私钥文件，为 `net/http` 提供可直接使用的
`tls.Config`。后续重载失败时，会继续使用上一份有效证书，避免服务因为
证书文件短暂不完整或内容错误而中断 TLS 握手。

## 功能

- 使用文件系统事件监听证书和私钥变化。
- 监听父目录而不是单个文件，可覆盖临时文件写入后 rename 替换的更新方式。
- 支持通过 `ReloadInterval` 配置兜底轮询。
- 部分写入或无效更新时保留上一份有效证书。
- 支持通过 `Reload(ctx)` 手动触发重载。

## 安装

```sh
go get github.com/lwmacct/260614-go-pkg-tlsreload
```

## 使用

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

	reloader, err := tlsreload.New(ctx, tlsreload.Config{
		CertFile:       "/etc/ssl/fullchain.pem",
		KeyFile:        "/etc/ssl/privkey.pem",
		MinVersion:     tls.VersionTLS12,
		ReloadInterval: 3 * time.Second,
	})
	if err != nil {
		panic(err)
	}
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

文件系统事件是主要重载触发方式。`ReloadInterval` 只作为兜底轮询间隔，
用于覆盖事件丢失或 watcher 受限的场景。

- `ReloadInterval > 0`：按该间隔启用兜底轮询。
- `ReloadInterval == 0`：禁用兜底轮询；文件系统事件仍会触发重载。
- `RetryInterval`：兜底轮询重载失败后，下次兜底轮询前的等待时间。

首次加载必须成功。启动后如果重载失败，配置了 logger 时会记录错误，
并继续使用上一份有效证书。

## API

```go
type Config struct {
	CertFile       string
	KeyFile        string
	ReloadInterval time.Duration
	RetryInterval  time.Duration
	MinVersion     uint16
	Logger         *slog.Logger
}
```

`MinVersion` 默认是 `tls.VersionTLS12`。`RetryInterval` 默认是
`2 * time.Second`。

主要方法：

```go
reloader, err := tlsreload.New(ctx, config)
tlsConfig := reloader.TLSConfig()
err = reloader.Reload(ctx)
version := reloader.Version()
reloader.Close()
```
