package tlsreload

import (
	"errors"
	"time"
)

// Config is the application-facing TLS config shape intended for config files and CLI flag binding.
type Config struct {
	Enabled  bool          `json:"enabled"         desc:"是否启用 HTTPS TLS"`
	CertFile string        `json:"cert-file"       desc:"TLS 证书文件路径"`
	KeyFile  string        `json:"key-file"        desc:"TLS 私钥文件路径"`
	Interval time.Duration `json:"interval"        desc:"TLS 证书文件重载兜底轮询间隔，0 表示禁用兜底轮询"`
}

// Validate checks the config-level invariants before TLS runtime setup.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("tls cert-file and key-file must be configured together")
	}
	if c.CertFile == "" || c.KeyFile == "" {
		return errors.New("tls cert-file and key-file are required when tls is enabled")
	}
	if c.Interval < 0 {
		return errors.New("tls interval must not be negative")
	}
	return nil
}
