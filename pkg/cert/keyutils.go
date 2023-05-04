package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

func generatePrivateKey(signatureAlg x509.SignatureAlgorithm) (keys any, err error) {
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
