package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/smallstep/certinfo"
	"go.mozilla.org/pkcs7"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GetCertificateChain gets the certificate chain for the hostname or a URL. In case the certificate chain does not
// contain the root certificate, we will attend to fetch it using issuer location of the last certificate from the chain.
func GetCertificateChain(u *url.URL) ([]*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", u.Host), conf)
	if err != nil {
		return nil, err
	}
	defer func(conn *tls.Conn) {
		err = conn.Close()
		if err != nil {
			err = fmt.Errorf("failed to close connection to %s, error: %w", u.Host, err)
		}
	}(conn)

	chain := conn.ConnectionState().PeerCertificates
	rootCert, certErr := getRootCertificateIfPossible(chain)
	if certErr != nil {
		return nil, certErr
	}
	if certErr != nil {
		chain = append(chain, rootCert...)
	}

	return chain, err
}

// Get the root certificate, if it is possible. If the chain contains the root certificate, we will return an empty slice.
// If the chain does not contain the root certificate, we attempt to fetch it using the authority information access
// of the last certificate from the chain.
func getRootCertificateIfPossible(chain []*x509.Certificate) ([]*x509.Certificate, error) {
	var cert *x509.Certificate
	if len(chain) >= 1 {
		cert = chain[len(chain)-1]
	}
	issuer := cert.RawIssuer
	subject := cert.RawSubject

	// Check if certificate is self-signed
	if !bytes.Equal(issuer, subject) {
		if len(cert.IssuingCertificateURL) > 0 {
			certURI := cert.IssuingCertificateURL[0]
			resp, err := http.Get(certURI)
			if err != nil {
				return nil,
					fmt.Errorf("failed to retrieve certificate from remote location %s, error: %w",
						cert.IssuingCertificateURL[0], err)
			}
			defer func(Body io.ReadCloser) {
				_ = Body.Close()
			}(resp.Body)

			certBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve certificate from remote location, error: %w", err)
			}

			return decodeBinaryCertificates(certURI, certBytes)
		}
	}

	return make([]*x509.Certificate, 0), nil
}

// Convert a slice of bytes to a x509 Certificate object.
func decodeBinaryCertificates(certURI string, data []byte) ([]*x509.Certificate, error) {
	certFormat := filepath.Ext(certURI)
	if len(certFormat) > 0 {
		certFormat = certFormat[1:]
	} else {
		return nil, fmt.Errorf("failed to deduct output format from path %s", certURI)
	}

	// Usually, each remote location is providing a binary certificate, most of them being in DER format
	formatToAction := map[string]func(data []byte) ([]*x509.Certificate, error){
		"crt": decodeDer,
		"cer": decodeDer,
		"der": decodeDer,
		"p7c": decodePkcs,
	}

	action, ok := formatToAction[certFormat]
	if !ok {
		return nil, fmt.Errorf("unsupported certificate format %s", certFormat)
	}

	return action(data)
}

// PrintCertificates prints the certificates from the chain to stdout in human-readable format.
func PrintCertificates(host string, chain []*x509.Certificate) error {
	fmt.Printf("Found %d certificates in the certificate chain for %s \n", len(chain), host)
	for _, cert := range chain {
		txtData, parseErr := certinfo.CertificateText(cert)
		if parseErr != nil {
			return fmt.Errorf("failed to convert certificate to TXT(OpenSSL) format, error: %w", parseErr)
		}
		fmt.Println("===========================")
		fmt.Print(txtData)
	}

	return nil
}

// SaveCertificates saves the certificates from the chain into a folder
func SaveCertificates(folderPath string, chain []*x509.Certificate, certFormat string) error {
	for i, cert := range chain {
		var prefix string
		switch i {
		case 0:
			prefix = "server"
		case 1:
			prefix = "root"
		default:
			prefix = fmt.Sprintf("inter-%d", i)
		}
		path := filepath.Join(folderPath, strings.Join([]string{
			prefix,
			strings.ReplaceAll(strings.TrimSpace(strings.ToLower(cert.Issuer.CommonName)), " ", "."),
			certFormat},
			"."))
		if ioErr := SaveCertificate(path, cert, certFormat); ioErr != nil {
			return ioErr
		}
	}

	return nil
}

// SaveCertificate saves a certificate to the location specified by the `path` using a supported format
func SaveCertificate(path string, cert *x509.Certificate, certFormat string) error {
	formatToAction := map[string]func(string, *x509.Certificate) error{
		"pem": saveAsPem,
		"crt": saveAsPem,
		"cer": saveAsPem,
		"txt": saveAsTxt,
		"der": saveAsDer,
		"p7b": saveAsPkcs,
		"p7c": saveAsPkcs,
	}
	action, ok := formatToAction[certFormat]
	if !ok {
		return fmt.Errorf("unsupported certificate type %s", certFormat)
	}
	return action(path, cert)
}

// Save a certificate to the location specified by the `path` using PEM format
func saveAsPem(path string, cert *x509.Certificate) error {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  certPEMBLockType,
		Bytes: cert.Raw,
	})
	ioErr := os.WriteFile(path, pemData, 0644)
	if ioErr != nil {
		return ioErr
	}

	return nil
}

// Save a certificate to the location specified by the `path` using human-readable OpenSSL text output format
func saveAsTxt(path string, cert *x509.Certificate) error {
	txtData, parseErr := certinfo.CertificateText(cert)
	if parseErr != nil {
		return parseErr
	}
	if ioErr := os.WriteFile(path, []byte(txtData), 0644); ioErr != nil {
		return ioErr
	}

	return nil
}

// Save a certificate to the location specified by the `path` using binary DER format
func saveAsDer(path string, cert *x509.Certificate) error {
	if ioErr := os.WriteFile(path, cert.Raw, 0644); ioErr != nil {
		return ioErr
	}
	return nil
}

// Save a certificate to the location specified by the `path` using PKCS (p7b or p7c) format
func saveAsPkcs(path string, cert *x509.Certificate) error {
	certificateData, err := pkcs7.DegenerateCertificate(cert.Raw)
	if err != nil {
		return err
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  pkcsPEMBlockType,
		Bytes: certificateData,
	})

	if ioErr := os.WriteFile(path, pemData, 0644); ioErr != nil {
		return ioErr
	}

	return nil
}

// ValidateCertificate validate server certificate using the following steps:
// 1. Check the expiration date
// 2. Check if the certificate is trusted using the trust store from the host machine
// 3. Check if the certificate is not part of a revocation list
func ValidateCertificate(host string, cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, fmt.Errorf("no certificate provided for validation for host %s", host)
	}

	// Check if the certificate is between expiration bounds
	currentTime := time.Now().UTC()

	if !currentTime.After(cert.NotBefore) {
		return false, fmt.Errorf("certificate for host %s is not valid yet. It will be valid after %s",
			host, cert.NotBefore)
	}

	if !currentTime.Before(cert.NotAfter) {
		return false, fmt.Errorf("certificate for host %s will expire at %s", host, cert.NotBefore)
	}

	// Verify if the certificate by building a certificate chain and check if the root is in the trusted store of
	// the host requesting the validation
	opts := x509.VerifyOptions{
		DNSName: host,
		Roots:   nil,
	}

	chain, err := cert.Verify(opts)
	if err != nil {
		return false, fmt.Errorf("invalide certificate, verification error: %w", err)
	}

	// Verify if the certificate is part of a revocation list
	revoked, err := isCertificateRevoked(cert)

	if len(chain) > 0 && !revoked {
		return true, nil
	}

	return false, nil
}

// Check if a certificate is in the revocation list using the CA's distribution point
func isCertificateRevoked(cert *x509.Certificate) (bool, error) {
	crlURL := cert.CRLDistributionPoints[0]
	resp, err := http.Get(crlURL)
	if err != nil {
		panic(err)
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	rl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return false, err
	}

	for _, r := range rl.RevokedCertificates {
		if r.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}

type CertificateInput struct {
	CommonName string
	NotBefore  time.Time
	ValidFor   time.Duration
	IsCA       bool

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

	PrivateKey any
}

// CreateCertificate generates a self-signed X509 certificate
func CreateCertificate(certInput CertificateInput) (*x509.Certificate, error) {
	serialNumber, serialNrErr := generateSerialNumber()
	if serialNrErr != nil {
		return nil, serialNrErr
	}

	subject := pkix.Name{
		CommonName: certInput.CommonName,
	}

	if certInput.OidEmail != "" {
		var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
		subject.ExtraNames = []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(certInput.OidEmail),
				},
			},
		}
	}

	if certInput.Country != nil {
		subject.Country = append([]string{}, *certInput.Country...)
	}

	if certInput.State != nil {
		subject.Province = append([]string{}, *certInput.State...)
	}

	if certInput.City != nil {
		subject.Locality = append([]string{}, *certInput.City...)
	}

	if certInput.Street != nil {
		subject.StreetAddress = append([]string{}, *certInput.Street...)
	}

	if certInput.PostalCode != nil {
		subject.PostalCode = append([]string{}, *certInput.PostalCode...)
	}

	if certInput.Organization != nil {
		subject.Organization = append([]string{}, *certInput.Organization...)
	}

	if certInput.OrgUnit != nil {
		subject.OrganizationalUnit = append([]string{}, *certInput.OrgUnit...)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    certInput.NotBefore,
		NotAfter:     certInput.NotBefore.Add(certInput.ValidFor),

		KeyUsage:              getKeyUsage(certInput.PrivateKey),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if certInput.SubjectAlternativeHosts != nil {
		for _, altName := range *certInput.SubjectAlternativeHosts {
			if ip := net.ParseIP(altName); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, altName)
			}
		}
	}

	if certInput.EmailAddresses != nil {
		template.EmailAddresses = append(template.EmailAddresses, *certInput.EmailAddresses...)
	}

	if certInput.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader,
		&template, &template, getPublicKey(certInput.PrivateKey), certInput.PrivateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(derBytes)
}

// CreateCertificateFromCSR generates a self-signed X509 certificate from a CSR request
func CreateCertificateFromCSR(request *x509.CertificateRequest,
	notBefore time.Time,
	validFor time.Duration,
	isCA bool,
	privateKey any) (*x509.Certificate, error) {
	serialNumber, serialNrErr := generateSerialNumber()
	if serialNrErr != nil {
		return nil, serialNrErr
	}

	notAfter := notBefore.Add(validFor)

	subject := pkix.Name{
		CommonName:   request.Subject.CommonName,
		SerialNumber: serialNumber.String(),
	}

	subject.Country = append(subject.Country, request.Subject.Country...)
	subject.Province = append(subject.Province, request.Subject.Province...)
	subject.Locality = append(subject.Locality, request.Subject.Locality...)
	subject.StreetAddress = append(subject.StreetAddress, request.Subject.StreetAddress...)
	subject.PostalCode = append(subject.PostalCode, request.Subject.PostalCode...)
	subject.Organization = append(subject.Organization, request.Subject.Organization...)
	subject.OrganizationalUnit = append(subject.OrganizationalUnit, request.Subject.OrganizationalUnit...)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              getKeyUsage(privateKey),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.IPAddresses = append(template.IPAddresses, request.IPAddresses...)
	template.DNSNames = append(template.DNSNames, request.DNSNames...)
	template.EmailAddresses = append(template.EmailAddresses, request.EmailAddresses...)

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, getPublicKey(privateKey), privateKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(derBytes)
}

// Extract the public key from a `PrivateKey` object
func getPublicKey(privateKey any) any {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

// Get the key usage. KeyUsage represents the set of actions that are valid for a given key
func getKeyUsage(privateKey any) x509.KeyUsage {
	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := privateKey.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	return keyUsage
}

// DecodeCertificate reads a certificate file, decodes it. The reason for returning a slice is that PKCS7 files
// are allowed to contain multiple certificates
func DecodeCertificate(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certFormat := filepath.Ext(path)

	if len(certFormat) > 0 {
		certFormat = certFormat[1:]
	} else {
		return nil, fmt.Errorf("failed to deduct output format from path %s", path)
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
		return nil, fmt.Errorf("unsupported certificate format %s", certFormat)
	}

	return action(data)
}

func decodePem(data []byte) ([]*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, fmt.Errorf("cannot decode PEM certificate file")
	}
	if pemBlock.Type != certPEMBLockType || len(pemBlock.Headers) != 0 {
		return nil, fmt.Errorf("unmatched type or headers for certificate")
	}

	cert, parsErr := x509.ParseCertificate(pemBlock.Bytes)
	if parsErr != nil {
		return nil, parsErr
	}

	return []*x509.Certificate{cert}, nil
}

func decodeDer(data []byte) ([]*x509.Certificate, error) {
	crt, parseErr := x509.ParseCertificate(data)
	if parseErr != nil {
		return nil, parseErr
	}
	return []*x509.Certificate{crt}, nil
}

func decodePkcs(data []byte) ([]*x509.Certificate, error) {
	pkcsBlock, parseErr := pkcs7.Parse(data)
	if parseErr != nil {
		return nil, parseErr
	}
	return pkcsBlock.Certificates, nil
}
