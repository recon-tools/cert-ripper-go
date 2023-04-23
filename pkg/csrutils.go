package pkg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// CreateCSR creates a new Certificate Signature Request and returns it as a slice of bytes
func CreateCSR(commonName string,
	country string,
	state string,
	city string,
	organization string,
	orgUnit string,
	email string) ([]byte, error) {
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	keyBytes, _ := rsa.GenerateKey(rand.Reader, 1024)

	subj := pkix.Name{
		CommonName:         commonName,
		Country:            []string{country},
		Province:           []string{state},
		Locality:           []string{city},
		Organization:       []string{organization},
		OrganizationalUnit: []string{orgUnit},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(email),
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
		return nil, fmt.Errorf("Failed to create CSR!\nError: %w", err)
	}

	return csr, nil
}

// SaveCSR saves the CSR in PEM format to a location
func SaveCSR(csr []byte, targetPath string) error {
	path := filepath.FromSlash(targetPath)

	info, statErr := os.Stat(path)
	if statErr != nil {
		return fmt.Errorf("Failed to check path %s\n", path)
	}

	if info.IsDir() {
		path = filepath.Join(targetPath, "csr.pem")
	}

	if _, ioErr := os.Stat(path); ioErr == nil {
		return fmt.Errorf("File with path %s already exists\n", path)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

	if ioErr := os.WriteFile(path, pemData, 0644); ioErr != nil {
		return fmt.Errorf("Failed to save CSR to the location of %s\nError: %w", targetPath, ioErr)
	}
	return nil
}
