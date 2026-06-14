package tlsreload

import (
	"encoding/json"
	"errors"
	"fmt"
)

// PEMBundle is a certificate/key pair in PEM format.
type PEMBundle struct {
	CertPEM []byte
	KeyPEM  []byte
}

type jsonPEMBundle struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// DecodeJSONPEMBundle decodes a JSON object with cert_pem and key_pem fields.
func DecodeJSONPEMBundle(value []byte) (PEMBundle, error) {
	var bundle jsonPEMBundle
	if err := json.Unmarshal(value, &bundle); err != nil {
		return PEMBundle{}, fmt.Errorf("decode json pem bundle: %w", err)
	}
	if len(bundle.CertPEM) == 0 || len(bundle.KeyPEM) == 0 {
		return PEMBundle{}, errors.New("pem bundle must contain cert_pem and key_pem")
	}
	return PEMBundle{
		CertPEM: []byte(bundle.CertPEM),
		KeyPEM:  []byte(bundle.KeyPEM),
	}, nil
}
