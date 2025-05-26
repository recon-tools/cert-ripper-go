package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/smallstep/certinfo"
	"net"
	"os"
	"path/filepath"
)

type CertificateRequest struct {
	CommonName     string
	Country        *[]string
	State          *[]string
	City           *[]string
	Street         *[]string
	PostalCode     *[]string
	Organization   *[]string
	OrgUnit        *[]string
	EmailAddresses *[]string
	OidEmail       string

	SubjectAlternativeHosts *[]string

	SignatureAlg x509.SignatureAlgorithm
}

// CreateCSR creates a new Certificate Signature Request and returns it as a slice of bytes
func CreateCSR(request CertificateRequest) (*x509.CertificateRequest, any, error) {
	serialNumber, serialNrErr := generateSerialNumber()
	if serialNrErr != nil {
		return nil, nil, serialNrErr
	}

	subject := pkix.Name{
		CommonName:   request.CommonName,
		SerialNumber: serialNumber.String(),
	}

	if request.OidEmail != "" {
		var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
		subject.ExtraNames = []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(request.OidEmail),
				},
			},
		}
	}

	subject.Country = append([]string{}, *request.Country...)
	subject.Province = append([]string{}, *request.State...)
	subject.Locality = append([]string{}, *request.City...)
	subject.StreetAddress = append([]string{}, *request.Street...)
	subject.PostalCode = append([]string{}, *request.PostalCode...)
	subject.Organization = append([]string{}, *request.Organization...)
	subject.OrganizationalUnit = append([]string{}, *request.OrgUnit...)

	keys, keyErr := GeneratePrivateKey(request.SignatureAlg)
	if keyErr != nil {
		return nil, nil, keyErr
	}

	template := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: request.SignatureAlg,
	}

	if request.SubjectAlternativeHosts != nil {
		for _, altName := range *request.SubjectAlternativeHosts {
			if ip := net.ParseIP(altName); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, altName)
			}
		}
	}

	template.EmailAddresses = append(template.EmailAddresses, *request.EmailAddresses...)

	csrBytes, csrErr := x509.CreateCertificateRequest(rand.Reader, &template, keys)
	if csrErr != nil {
		return nil, nil, csrErr
	}

	csr, csrParseErr := x509.ParseCertificateRequest(csrBytes)
	if csrParseErr != nil {
		return nil, nil, csrParseErr
	}

	return csr, keys, nil
}

// SaveCSR saves the CSR in PEM format to a location
func SaveCSR(csr *x509.CertificateRequest, targetPath string) error {
	if _, ioErr := os.Stat(targetPath); ioErr == nil {
		return fmt.Errorf("file with location %s already exists", targetPath)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  csrPEMBlockType,
		Bytes: csr.Raw,
	})

	return os.WriteFile(targetPath, pemData, 0644)
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

// SavePrivateKey saves the private key (RSA, EC) in PEM format to a location
func SavePrivateKey(privateKey any, targetPath string) error {
	if _, ioErr := os.Stat(targetPath); ioErr == nil {
		return fmt.Errorf("file with location %s already exists", targetPath)
	}

	if mkErr := os.MkdirAll(filepath.Dir(targetPath), 0o755); mkErr != nil {
		return fmt.Errorf("failed to create target directory \"%s\" for the private key. Error: %w", targetPath, mkErr)
	}

	var pemData []byte
	privateKeyDer, keyErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if keyErr != nil {
		return keyErr
	}

	pemType := ed25519PrivateKeyType
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		pemType = rsaPrivateKeyType
	case *ecdsa.PrivateKey:
		pemType = ecPrivateKeyType
	case ed25519.PrivateKey:
		pemType = ed25519PrivateKeyType
	}

	pemData = pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: privateKeyDer,
	})

	return os.WriteFile(targetPath, pemData, 0644)
}
