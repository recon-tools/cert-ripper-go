package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func GeneratePrivateKey(signatureAlg x509.SignatureAlgorithm) (keys any, err error) {
	switch signatureAlg {
	case x509.SHA256WithRSA:
		keys, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	case x509.SHA384WithRSA:
		keys, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	case x509.SHA512WithRSA:
		keys, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	case x509.ECDSAWithSHA1:
		keys, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			return nil, err
		}
	case x509.ECDSAWithSHA256:
		keys, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	case x509.ECDSAWithSHA384:
		keys, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
	case x509.ECDSAWithSHA512:
		keys, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, err
		}
	case x509.PureEd25519:
		_, keys, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// ReadKey reads the private key from a .PEM file
func ReadKey(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, fmt.Errorf("cannot find the next PEM formatted block for file %s", path)
	}
	if pemBlock.Type != rsaPrivateKeyType || len(pemBlock.Headers) != 0 {
		return nil, fmt.Errorf("unmatched type or headers for file %s", path)
	}
	return x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
}
