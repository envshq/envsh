package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// parseRSAPublicKey parses a DER-encoded RSA public key.
// The bytes should be in PKIX/SubjectPublicKeyInfo format (as produced
// by x509.MarshalPKIXPublicKey).
func parseRSAPublicKey(der []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing PKIX public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA public key, got %T", pub)
	}
	return rsaPub, nil
}

// marshalRSAPublicKeyDER marshals an RSA public key to DER-encoded PKIX format.
func marshalRSAPublicKeyDER(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshaling RSA public key to PKIX: %w", err)
	}
	return der, nil
}
