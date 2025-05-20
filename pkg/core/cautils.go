package core

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"
)

type CaInput struct {
	CommonName string
	NotBefore  time.Time
	ValidFor   time.Duration

	Country        *[]string
	State          *[]string
	City           *[]string
	Street         *[]string
	PostalCode     *[]string
	Organization   *[]string
	OrgUnit        *[]string
	EmailAddresses *[]string

	PrivateKey any
}

func CreateCertificateAuthority(caInput CaInput) (*x509.Certificate, error) {
	serialNumber, serialNrErr := generateSerialNumber()

	subject := pkix.Name{}

	if serialNrErr != nil {
		return nil, serialNrErr
	}

	if caInput.Country != nil {
		subject.Country = append([]string{}, *caInput.Country...)
	}

	if caInput.State != nil {
		subject.Province = append([]string{}, *caInput.State...)
	}

	if caInput.City != nil {
		subject.Locality = append([]string{}, *caInput.City...)
	}

	if caInput.Street != nil {
		subject.StreetAddress = append([]string{}, *caInput.Street...)
	}

	if caInput.PostalCode != nil {
		subject.PostalCode = append([]string{}, *caInput.PostalCode...)
	}

	if caInput.Organization != nil {
		subject.Organization = append([]string{}, *caInput.Organization...)
	}

	if caInput.OrgUnit != nil {
		subject.OrganizationalUnit = append([]string{}, *caInput.OrgUnit...)
	}

	ca := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             caInput.NotBefore,
		NotAfter:              caInput.NotBefore.Add(caInput.ValidFor),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader,
		ca, ca, getPublicKey(caInput.PrivateKey), caInput.PrivateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(derBytes)
}
