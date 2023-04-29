package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
	csrPEMBlockType       = "CERTIFICATE REQUEST"
	rsaPrivateKeyType     = "RSA PRIVATE KEY"
	ecPrivateKeyType      = "EC PRIVATE KEY"
	ed25519PrivateKeyType = "PRIVATE KEY"
)

type CertificateRequest struct {
	CommonName   string
	Country      string
	State        string
	City         string
	Organization string
	OrgUnit      string
	Email        string
	SignatureAlg x509.SignatureAlgorithm
}

// CreateCSR creates a new Certificate Signature Request and returns it as a slice of bytes
func CreateCSR(request CertificateRequest) ([]byte, any, error) {
	var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

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

	var keys any
	var keyErr error
	switch request.SignatureAlg {
	case x509.SHA256WithRSA:
		keys, keyErr = rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			return nil, nil, keyErr
		}
	case x509.SHA384WithRSA:
		keys, keyErr = rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			return nil, nil, keyErr
		}
	case x509.SHA512WithRSA:
		keys, keyErr = rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			return nil, nil, keyErr
		}
	case x509.ECDSAWithSHA256:
		keys, keyErr = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			return nil, nil, keyErr
		}
	case x509.ECDSAWithSHA384:
		keys, keyErr = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if keyErr != nil {
			return nil, nil, keyErr
		}
	case x509.ECDSAWithSHA512:
		keys, keyErr = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if keyErr != nil {
			return nil, nil, keyErr
		}
	case x509.PureEd25519:
		_, keys, keyErr = ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			return nil, nil, keyErr
		}
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: request.SignatureAlg,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, keys)
	if err != nil {
		return nil, nil, err
	}

	return csr, keys, nil
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

// SavePrivateKey saves the private key (RSA, EC) in PEM format to a location
func SavePrivateKey(privateKey any, targetPath string) error {
	path := filepath.FromSlash(targetPath)
	if _, ioErr := os.Stat(path); ioErr == nil {
		return fmt.Errorf("file with location %s already exists", path)
	}

	var pemData []byte
	privateKeyDer, keyErr := x509.MarshalPKCS8PrivateKey(privateKey)
	if keyErr != nil {
		return keyErr
	}

	switch privateKey.(type) {
	case *rsa.PrivateKey:
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  rsaPrivateKeyType,
			Bytes: privateKeyDer,
		})

	case *ecdsa.PrivateKey:
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  ecPrivateKeyType,
			Bytes: privateKeyDer,
		})

	case ed25519.PrivateKey:
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  ed25519PrivateKeyType,
			Bytes: privateKeyDer,
		})
	}

	if ioErr := os.WriteFile(path, pemData, 0644); ioErr != nil {
		return ioErr
	}

	return nil
}
