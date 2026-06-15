// Package tlsreload provides hot-reloadable TLS certificate management for Go servers.
//
// The package is split into two layers:
//   - Manager, which owns the active certificate and exposes
//     tls.Config.GetCertificate.
//   - Source, which loads certificate material from a backend.
//
// Built-in sources currently support local files.
package tlsreload
