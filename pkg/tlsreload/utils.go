package tlsreload

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

func tlsMaterialVersion(certPEM, keyPEM []byte) string {
	return tlsVersionHash(certPEM, keyPEM)
}

func tlsVersionHash(parts ...[]byte) string {
	digest := sha256.New()
	for _, part := range parts {
		writeTLSVersionPart(digest, part)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeTLSVersionPart(digest hash.Hash, part []byte) {
	_, _ = digest.Write(part)
	_, _ = digest.Write([]byte{0})
}
