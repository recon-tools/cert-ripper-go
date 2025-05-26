package core

import (
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCreateCertificateRequiredFields(t *testing.T) {
	validFrom, parseErr := time.Parse("2006-01-02 15:04:05", "2023-05-10 02:20:32")
	assert.NoError(t, parseErr)

	caPrivateKeyPath := "test/ca-cert.key.pem"
	caPrivateKey, caKeyErr := ReadKey(caPrivateKeyPath)
	assert.NoError(t, caKeyErr)

	caCertPath := "test/ca-cert.pem"
	caCert, caCertErr := DecodeCACertificate(caCertPath)
	assert.NoError(t, caCertErr)

	privateKey, keyErr := GeneratePrivateKey(x509.PureEd25519)
	assert.NoError(t, keyErr)

	certInput := CertificateInput{
		CAPrivateKey: caPrivateKey,
		CA:           caCert,

		CommonName: "example.com",
		NotBefore:  validFrom,
		ValidFor:   time.Duration(10) * time.Hour * 24,
		PrivateKey: privateKey,
	}

	cert, err := CreateCertificate(certInput)

	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Contains(t, cert.Subject.CommonName, certInput.CommonName)
	assert.Equal(t, validFrom.Unix(), cert.NotBefore.Unix())
	assert.Equal(t, validFrom.Add(certInput.ValidFor).Unix(), cert.NotAfter.Unix())
	assert.False(t, cert.IsCA)
}

func TestCreateCertificateAllFields(t *testing.T) {
	caPrivateKeyPath := "test/ca-cert.key.pem"
	caPrivateKey, caKeyErr := ReadKey(caPrivateKeyPath)
	assert.NoError(t, caKeyErr)

	caCertPath := "test/ca-cert.pem"
	caCert, caCertErr := DecodeCACertificate(caCertPath)
	assert.NoError(t, caCertErr)

	validFrom, parseErr := time.Parse("2006-01-02 15:04:05", "2023-05-10 02:20:32")
	assert.NoError(t, parseErr)

	privateKey, keyErr := GeneratePrivateKey(x509.PureEd25519)
	assert.NoError(t, keyErr)

	certInput := CertificateInput{
		CA:           caCert,
		CAPrivateKey: caPrivateKey,

		CommonName:              "example.com",
		NotBefore:               validFrom,
		ValidFor:                time.Duration(10) * time.Hour * 24,
		PrivateKey:              privateKey,
		Country:                 &[]string{"RO"},
		State:                   &[]string{"Mures"},
		City:                    &[]string{"Tg Mures"},
		Street:                  &[]string{"Principala"},
		PostalCode:              &[]string{"555222"},
		Organization:            &[]string{"ACME"},
		OrgUnit:                 &[]string{"IT"},
		EmailAddresses:          &[]string{"mail@ervinszilagyi.dev"},
		OidEmail:                "mail@dev.com",
		SubjectAlternativeHosts: &[]string{"alter.example.com"},
	}

	cert, err := CreateCertificate(certInput)

	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, validFrom.Unix(), cert.NotBefore.Unix())
	assert.Equal(t, validFrom.Add(certInput.ValidFor).Unix(), cert.NotAfter.Unix())
	assert.Equal(t, cert.Subject.CommonName, certInput.CommonName)
	assert.ElementsMatch(t, cert.Subject.Country, *certInput.Country)
	assert.ElementsMatch(t, cert.Subject.Province, *certInput.State)
	assert.ElementsMatch(t, cert.Subject.Locality, *certInput.City)
	assert.ElementsMatch(t, cert.Subject.StreetAddress, *certInput.Street)
	assert.ElementsMatch(t, cert.Subject.PostalCode, *certInput.PostalCode)
	assert.ElementsMatch(t, cert.Subject.Organization, *certInput.Organization)
	assert.ElementsMatch(t, cert.Subject.OrganizationalUnit, *certInput.OrgUnit)
	assert.ElementsMatch(t, cert.DNSNames, *certInput.SubjectAlternativeHosts)
	assert.ElementsMatch(t, cert.EmailAddresses, *certInput.EmailAddresses)
	assert.False(t, cert.IsCA)
}

func TestCreateCertificateFromCSR(t *testing.T) {
	caPrivateKeyPath := "test/ca-cert.key.pem"
	caPrivateKey, caKeyErr := ReadKey(caPrivateKeyPath)
	assert.NoError(t, caKeyErr)

	caCertPath := "test/ca-cert.pem"
	caCert, caCertErr := DecodeCACertificate(caCertPath)
	assert.NoError(t, caCertErr)

	days := time.Duration(10) * time.Hour * 24
	validFrom, parseErr := time.Parse("2006-01-02 15:04:05", "2023-05-10 02:20:32")
	assert.NoError(t, parseErr)

	csrPath := "test/test.csr"
	csr, csrErr := DecodeCSR(csrPath)
	assert.NoError(t, csrErr)

	privateKeyPath := "test/test.csr.key"
	privateKey, keyErr := ReadKey(privateKeyPath)
	assert.NoError(t, keyErr)

	cert, err := CreateCertificateFromCSR(csr, validFrom, days, caCert, caPrivateKey, privateKey)

	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "ervinszilagyi.dev", cert.Subject.CommonName)
	assert.ElementsMatch(t, []string{"ACME", "home"}, cert.Subject.Organization)
	assert.ElementsMatch(t, []string{"IT", "HR"}, cert.Subject.OrganizationalUnit)
	assert.ElementsMatch(t, []string{"RO"}, cert.Subject.Country)
	assert.ElementsMatch(t, []string{"Mures"}, cert.Subject.Province)
	assert.ElementsMatch(t, []string{"Tg Mures"}, cert.Subject.Locality)
	assert.ElementsMatch(t, []string{"Gh. Doja"}, cert.Subject.StreetAddress)
	assert.ElementsMatch(t, []string{"222111"}, cert.Subject.PostalCode)
	assert.ElementsMatch(t, []string{"mail@ervinszilagyi.dev"}, cert.EmailAddresses)
	assert.ElementsMatch(t, []string{"example.com", "alter.nativ"}, cert.DNSNames)
	assert.Equal(t, x509.SHA256WithRSA, cert.SignatureAlgorithm)
}

func TestCreateCertificateFromCSRRequiredFieldsOnly(t *testing.T) {
	caPrivateKeyPath := "test/ca-cert.key.pem"
	caPrivateKey, caKeyErr := ReadKey(caPrivateKeyPath)
	assert.NoError(t, caKeyErr)

	caCertPath := "test/ca-cert.pem"
	caCert, caCertErr := DecodeCACertificate(caCertPath)
	assert.NoError(t, caCertErr)

	days := time.Duration(10) * time.Hour * 24
	validFrom, parseErr := time.Parse("2006-01-02 15:04:05", "2023-05-10 02:20:32")
	assert.NoError(t, parseErr)

	csrPath := "test/minimal.csr"
	csr, csrErr := DecodeCSR(csrPath)
	assert.NoError(t, csrErr)

	privateKeyPath := "test/minimal.csr.key"
	privateKey, keyErr := ReadKey(privateKeyPath)
	assert.NoError(t, keyErr)

	cert, err := CreateCertificateFromCSR(csr, validFrom, days, caCert, caPrivateKey, privateKey)

	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "ervinszilagyi.dev", cert.Subject.CommonName)
	assert.ElementsMatch(t, []string{}, csr.Subject.Organization)
	assert.ElementsMatch(t, []string{}, csr.Subject.OrganizationalUnit)
	assert.ElementsMatch(t, []string{}, csr.Subject.Country)
	assert.ElementsMatch(t, []string{}, csr.Subject.Province)
	assert.ElementsMatch(t, []string{}, csr.Subject.Locality)
	assert.ElementsMatch(t, []string{}, csr.Subject.StreetAddress)
	assert.ElementsMatch(t, []string{}, csr.Subject.PostalCode)
	assert.ElementsMatch(t, []string{}, csr.EmailAddresses)
	assert.ElementsMatch(t, []string{}, csr.DNSNames)
	assert.Equal(t, x509.SHA256WithRSA, cert.SignatureAlgorithm)
}

func TestDecodePEMCertificate(t *testing.T) {
	pem, decodeErr := DecodeCertificate("test/cert.pem")
	assert.NoError(t, decodeErr)

	assert.Equal(t, 1, len(pem))

	assert.Equal(t, "cert1.example.com", pem[0].Subject.CommonName)
}

func TestDecodePKCSCertificate(t *testing.T) {
	pkcs, decodeErr := DecodeCertificate("test/pkcs.p7b")
	assert.NoError(t, decodeErr)

	assert.Equal(t, 2, len(pkcs))

	commonNames := make([]string, 0)
	for _, certificate := range pkcs {
		commonNames = append(commonNames, certificate.Subject.CommonName)
	}

	assert.ElementsMatch(t, []string{"cert1.example.com", "cert2.example.com"}, commonNames)
}
