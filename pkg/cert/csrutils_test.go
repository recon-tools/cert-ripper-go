package cert

import (
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateCSR(t *testing.T) {
	request := CertificateRequest{
		CommonName:     "ervinszilagyi.dev",
		Country:        &[]string{"RO"},
		State:          &[]string{"Romania"},
		City:           &[]string{"Tg Mures"},
		Organization:   &[]string{"ACME"},
		OrgUnit:        &[]string{"IT"},
		OidEmail:       "mail@ervinszilagyi.dev",
		EmailAddresses: &[]string{"mail@ervinszilagyi.dev"},
		SignatureAlg:   x509.SHA512WithRSA,
	}

	csr, privateKey, csrErr := CreateCSR(request)

	assert.NoError(t, csrErr)
	assert.NotNil(t, csr)
	assert.NotNil(t, privateKey)
	assert.Equal(t, csr.Subject.CommonName, request.CommonName)
	assert.ElementsMatch(t, csr.Subject.Country, request.Country)
	assert.ElementsMatch(t, csr.Subject.Locality, request.City)
	assert.ElementsMatch(t, csr.Subject.Province, request.State)
	assert.ElementsMatch(t, csr.Subject.Organization, request.Organization)
	assert.ElementsMatch(t, csr.Subject.OrganizationalUnit, request.OrgUnit)
	assert.ElementsMatch(t, csr.EmailAddresses, request.EmailAddresses)
	assert.Equal(t, csr.SignatureAlgorithm, request.SignatureAlg)
}
