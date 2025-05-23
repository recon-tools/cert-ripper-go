package core

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
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

	subject := pkix.Name{
		CommonName: caInput.CommonName,
	}

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

	if caInput.EmailAddresses != nil {
		ca.EmailAddresses = append(ca.EmailAddresses, *caInput.EmailAddresses...)
	}

	if caInput.PrivateKey == nil {
		return nil, fmt.Errorf("CreateCertificateAuthority: PrivateKey must not be nil")
	}

	derBytes, err := x509.CreateCertificate(rand.Reader,
		ca, ca, getPublicKey(caInput.PrivateKey), caInput.PrivateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(derBytes)
}

// DecodeCACertificate reads a certificate file, decodes it. The reason for returning a slice is that PKCS7 files
// are allowed to contain multiple certificates
func DecodeCACertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certFormat := filepath.Ext(path)

	if len(certFormat) > 0 {
		certFormat = certFormat[1:]
	} else {
		return nil, fmt.Errorf("DecodeCACertificate: failed to deduct output format from path %s", path)
	}

	formatToAction := map[string]func(data []byte) ([]*x509.Certificate, error){
		"pem": decodePem,
		"crt": decodePem,
		"cer": decodePem,
		"der": decodeDer,
		"p7b": decodePkcs,
		"p7c": decodePkcs,
	}
	action, ok := formatToAction[certFormat]
	if !ok {
		return nil, fmt.Errorf("DecodeCACertificate: unsupported certificate format %s", certFormat)
	}

	ca, decodeErr := action(data)
	if decodeErr != nil {
		return nil, decodeErr
	}

	// We assume that the CA file has only 1 certificate
	if len(ca) >= 1 {
		return ca[0], nil
	}

	return nil, fmt.Errorf("DecodeCACertificate: ca certifcate could not be decoded, no valid certificate found in the file %s", path)
}
