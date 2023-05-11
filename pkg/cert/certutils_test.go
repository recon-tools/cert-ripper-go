package cert

import (
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCreateCertificate(t *testing.T) {
	hostname := "example.com"
	days := time.Duration(10) * time.Hour * 24
	org := "ACME"

	validFrom, parseErr := time.Parse("2006-01-02 15:04:05", "2023-05-10 02:20:32")
	assert.NoError(t, parseErr)

	privateKey, keyErr := GeneratePrivateKey(x509.PureEd25519)
	assert.NoError(t, keyErr)

	cert, err := CreateCertificate(CertificateInput{
		HostName:     hostname,
		NotBefore:    validFrom,
		ValidFor:     days,
		IsCA:         true,
		Organization: org,
		PrivateKey:   privateKey,
	})

	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Contains(t, cert.DNSNames, hostname)
	assert.Equal(t, validFrom.Unix(), cert.NotBefore.Unix())
	assert.Equal(t, validFrom.Add(days).Unix(), cert.NotAfter.Unix())
	assert.Contains(t, cert.Subject.Organization, org)
	assert.True(t, cert.IsCA)
}

func TestCreateCertificateFromCSR(t *testing.T) {
	days := time.Duration(10) * time.Hour * 24
	validFrom, parseErr := time.Parse("2006-01-02 15:04:05", "2023-05-10 02:20:32")
	assert.NoError(t, parseErr)

	csrPath := "test/test"
	csr, csrErr := DecodeCSR(csrPath)
	assert.NoError(t, csrErr)

	privateKeyPath := "test/test.key"
	privateKey, keyErr := ReadKey(privateKeyPath)
	assert.NoError(t, keyErr)

	cert, err := CreateCertificateFromCSR(csr, validFrom, days, true, privateKey)

	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "ervinszilagyi.dev", cert.Subject.CommonName)
	assert.Equal(t, []string{"ACME"}, cert.Subject.Organization)
	assert.Equal(t, []string{"IT"}, cert.Subject.OrganizationalUnit)
	assert.Equal(t, []string{"RO"}, cert.Subject.Country)
	assert.Equal(t, []string{"TG Mures"}, cert.Subject.Locality)
	assert.Equal(t, x509.SHA256WithRSA, cert.SignatureAlgorithm)
}
