package cert

import (
	"crypto/rand"
	"math/big"
)

// Generates a random serial number used for CSR/Certificates
func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}
