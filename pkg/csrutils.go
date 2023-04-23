package pkg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/grantae/certinfo"
	"os"
	"path/filepath"
)

const (
	csrPEMBlockType = "CERTIFICATE REQUEST"
)

type CertificateRequest struct {
	CommonName   string
	Country      string
	State        string
	City         string
	Organization string
	OrgUnit      string
	Email        string
}

// CreateCSR creates a new Certificate Signature Request and returns it as a slice of bytes
func CreateCSR(request CertificateRequest) ([]byte, error) {
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	keyBytes, _ := rsa.GenerateKey(rand.Reader, 1024)

	subj := pkix.Name{
		CommonName:         request.CommonName,
		Country:            []string{request.Country},
		Province:           []string{request.State},
		Locality:           []string{request.City},
		Organization:       []string{request.Organization},
		OrganizationalUnit: []string{request.OrgUnit},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(request.Email),
				},
			},
		},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

// SaveCSR saves the CSR in PEM format to a location
func SaveCSR(csr []byte, targetPath string) error {
	path := filepath.FromSlash(targetPath)

	if _, ioErr := os.Stat(path); ioErr == nil {
		return fmt.Errorf("file with location %s already exists", path)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  csrPEMBlockType,
		Bytes: csr,
	})

	if ioErr := os.WriteFile(path, pemData, 0644); ioErr != nil {
		return ioErr
	}
	return nil
}

// DecodeCSR reads a PEM .csr file, decodes it
func DecodeCSR(path string) (*x509.CertificateRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, fmt.Errorf("cannot find the next PEM formatted block for file %s", path)
	}
	if pemBlock.Type != csrPEMBlockType || len(pemBlock.Headers) != 0 {
		return nil, fmt.Errorf("unmatched type or headers for file %s", path)
	}
	return x509.ParseCertificateRequest(pemBlock.Bytes)
}

// PrintCSR print the content the CSR request to the STDOUT in OpenSSL text format
func PrintCSR(csr *x509.CertificateRequest) error {
	csrText, err := certinfo.CertificateRequestText(csr)
	if err != nil {
		return err
	}
	fmt.Print(csrText)

	return nil
}
