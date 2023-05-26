package core

import (
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateCSR(t *testing.T) {
	request := CertificateRequest{
		CommonName:              "ervinszilagyi.dev",
		Country:                 &[]string{"RO"},
		State:                   &[]string{"Mures"},
		City:                    &[]string{"Tg Mures"},
		Street:                  &[]string{"Gh. Doja"},
		PostalCode:              &[]string{"555222"},
		Organization:            &[]string{"ACME, Acc3ntur3"},
		OrgUnit:                 &[]string{"IT"},
		OidEmail:                "mail@ervinszilagyi.dev",
		EmailAddresses:          &[]string{"mail@ervinszilagyi.dev"},
		SignatureAlg:            x509.SHA512WithRSA,
		SubjectAlternativeHosts: &[]string{"alternative.com"},
	}

	csr, privateKey, csrErr := CreateCSR(request)

	assert.NoError(t, csrErr)
	assert.NotNil(t, csr)
	assert.NotNil(t, privateKey)
	assert.Equal(t, csr.Subject.CommonName, request.CommonName)
	assert.ElementsMatch(t, csr.Subject.Country, *request.Country)
	assert.ElementsMatch(t, csr.Subject.Locality, *request.City)
	assert.ElementsMatch(t, csr.Subject.Province, *request.State)
	assert.ElementsMatch(t, csr.Subject.StreetAddress, *request.Street)
	assert.ElementsMatch(t, csr.Subject.PostalCode, *request.PostalCode)
	assert.ElementsMatch(t, csr.Subject.Organization, *request.Organization)
	assert.ElementsMatch(t, csr.Subject.OrganizationalUnit, *request.OrgUnit)
	assert.ElementsMatch(t, csr.EmailAddresses, *request.EmailAddresses)
	assert.ElementsMatch(t, csr.DNSNames, *request.SubjectAlternativeHosts)
	assert.Equal(t, csr.SignatureAlgorithm, request.SignatureAlg)
}

func TestDecodeCSR(t *testing.T) {
	csrPath := "test/test.csr"
	csr, csrErr := DecodeCSR(csrPath)
	assert.NotNil(t, csr)
	assert.NoError(t, csrErr)

	assert.Equal(t, "ervinszilagyi.dev", csr.Subject.CommonName)
	assert.ElementsMatch(t, []string{"ACME", "home"}, csr.Subject.Organization)
	assert.ElementsMatch(t, []string{"IT", "HR"}, csr.Subject.OrganizationalUnit)
	assert.ElementsMatch(t, []string{"RO"}, csr.Subject.Country)
	assert.ElementsMatch(t, []string{"Mures"}, csr.Subject.Province)
	assert.ElementsMatch(t, []string{"Tg Mures"}, csr.Subject.Locality)
	assert.ElementsMatch(t, []string{"Gh. Doja"}, csr.Subject.StreetAddress)
	assert.ElementsMatch(t, []string{"222111"}, csr.Subject.PostalCode)
	assert.ElementsMatch(t, []string{"mail@ervinszilagyi.dev"}, csr.EmailAddresses)
	assert.ElementsMatch(t, []string{"example.com", "alter.nativ"}, csr.DNSNames)
	assert.Equal(t, x509.SHA256WithRSA, csr.SignatureAlgorithm)
}

func TestDecodeCSRRequiredFieldsOnly(t *testing.T) {
	csrPath := "test/minimal.csr"
	csr, csrErr := DecodeCSR(csrPath)
	assert.NotNil(t, csr)
	assert.NoError(t, csrErr)

	assert.Equal(t, "ervinszilagyi.dev", csr.Subject.CommonName)
	assert.ElementsMatch(t, []string{}, csr.Subject.Organization)
	assert.ElementsMatch(t, []string{}, csr.Subject.OrganizationalUnit)
	assert.ElementsMatch(t, []string{}, csr.Subject.Country)
	assert.ElementsMatch(t, []string{}, csr.Subject.Province)
	assert.ElementsMatch(t, []string{}, csr.Subject.Locality)
	assert.ElementsMatch(t, []string{}, csr.Subject.StreetAddress)
	assert.ElementsMatch(t, []string{}, csr.Subject.PostalCode)
	assert.ElementsMatch(t, []string{}, csr.EmailAddresses)
	assert.ElementsMatch(t, []string{}, csr.DNSNames)
	assert.Equal(t, x509.SHA256WithRSA, csr.SignatureAlgorithm)
}
