// Package tlsreload provides hot-reloadable TLS certificate management for Go
// servers.
//
// The package is split into two layers:
//   - Manager, which owns the active certificate and exposes
//     tls.Config.GetCertificate.
//   - Source, which loads certificate material from a backend and optionally
//     watches for changes.
//
// Built-in sources currently support local files, base64-encoded PEM values,
// and etcd-backed PEM bundles.
// Applications are expected to keep their own configuration mapping outside
// this package and construct Sources explicitly.
package tlsreload
