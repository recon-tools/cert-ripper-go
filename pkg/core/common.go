package core

import (
	"crypto/rand"
	"math/big"
)

const (
	certPEMBLockType      = "CERTIFICATE"
	pkcsPEMBlockType      = "PKCS7"
	csrPEMBlockType       = "CERTIFICATE REQUEST"
	rsaPrivateKeyType     = "RSA PRIVATE KEY"
	ecPrivateKeyType      = "EC PRIVATE KEY"
	ed25519PrivateKeyType = "PRIVATE KEY"
)

// Generates a random serial number used for CSR/Certificates
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}
