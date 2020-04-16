package ufo

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

//ParsePublicRSA parses a PKIX PEM encoded RSA key
func ParsePublicRSA(public string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(public))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("Key type is not RSA")
	}
}

//EncodePublicRSA key takes a PublicKey struct and
//encodes it to a PKIX PEM encoded string
func EncodePublicRSA(pubkey *rsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)

	return string(pubkeyPem), nil
}
