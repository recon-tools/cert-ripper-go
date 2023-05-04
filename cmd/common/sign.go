package common

import (
	"crypto/x509"
	"github.com/thediveo/enumflag/v2"
)

type SignatureAlgorithm enumflag.Flag

const (
	SHA256WithRSA SignatureAlgorithm = iota
	SHA384WithRSA
	SHA512WithRSA
	SHA256WithECDSA
	SHA384WithECDSA
	SHA512WithECDSA
	ED25519
)

var (
	SignatureAlgIds = map[SignatureAlgorithm][]string{
		SHA256WithRSA:   {"SHA256WithRSA"},
		SHA384WithRSA:   {"SHA384WithRSA"},
		SHA512WithRSA:   {"SHA512WithRSA"},
		SHA256WithECDSA: {"SHA256WithECDSA"},
		SHA384WithECDSA: {"SHA384WithECDSA"},
		SHA512WithECDSA: {"SHA512WithECDSA"},
		ED25519:         {"ED25519"},
	}

	SignatureAlgTox509 = map[SignatureAlgorithm]x509.SignatureAlgorithm{
		SHA256WithRSA:   x509.SHA256WithRSA,
		SHA384WithRSA:   x509.SHA384WithRSA,
		SHA512WithRSA:   x509.SHA512WithRSA,
		SHA256WithECDSA: x509.ECDSAWithSHA256,
		SHA384WithECDSA: x509.ECDSAWithSHA384,
		SHA512WithECDSA: x509.ECDSAWithSHA512,
		ED25519:         x509.PureEd25519,
	}
)
