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
	isCa := true
	org := "ACME"

	validFrom, parseErr := time.Parse("2006-01-02 15:04:05", "2023-05-10 02:20:32")
	assert.NoError(t, parseErr)

	privateKey, keyErr := GeneratePrivateKey(x509.PureEd25519)
	assert.NoError(t, keyErr)

	cert, err := CreateCertificate(CertificateInput{
		HostName:     hostname,
		NotBefore:    validFrom,
		ValidFor:     days,
		IsCA:         isCa,
		Organization: org,
		PrivateKey:   privateKey,
	})

	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Contains(t, cert.DNSNames, hostname)
	assert.Equal(t, validFrom.Unix(), cert.NotBefore.Unix())
	assert.Equal(t, validFrom.Add(days).Unix(), cert.NotAfter.Unix())
	assert.Contains(t, cert.Subject.Organization, org)
	assert.Equal(t, isCa, cert.IsCA)
}
