package pkg

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/grantae/certinfo"
	"go.mozilla.org/pkcs7"
	"io"
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
		return nil, fmt.Errorf("Failed to connect to %s\nError: %w\n", u.Host, err)
	}
	defer func(conn *tls.Conn) {
		err = conn.Close()
		if err != nil {
			err = fmt.Errorf("Failed to close connection to %s\nError: %w\n", u.Host, err)
		}
	}(conn)

	chain := conn.ConnectionState().PeerCertificates
	rootCert, _ := getRootCertificateIfPossible(chain)
	if rootCert != nil {
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
					fmt.Errorf("Failed to retrieve certificate from remote location %s\nError: %w\n",
						cert.IssuingCertificateURL[0], err)
			}
			defer func(Body io.ReadCloser) {
				_ = Body.Close()
			}(resp.Body)

			certBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("Failed to retrieve certificate from remote location\nError: %w\n", err)
			}

			return convertBytesTox509Certificate(certURI, certBytes)
		}
	}

	return make([]*x509.Certificate, 0), nil
}

// Convert a slice of bytes to a x509 Certificate object.
func convertBytesTox509Certificate(certURI string, certBytes []byte) ([]*x509.Certificate, error) {
	certFormat := filepath.Ext(certURI)
	switch certFormat {
	case ".p7c":
		{
			pkcsBlock, err := pkcs7.Parse(certBytes)
			if err != nil {
				return nil, fmt.Errorf("Failed to decode PKCS7 certificate from %s\nError: %w\n", certURI, err)
			}
			return pkcsBlock.Certificates, nil
		}
	case ".der":
		fallthrough
	case ".crt":
		{
			crt, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return nil, fmt.Errorf("Failed to decode DER certificate from %s\nError: %s\n", certURI, err)
			}
			return []*x509.Certificate{crt}, nil
		}
	default:
		return nil, fmt.Errorf("Unsupported certificate format %s\n", certFormat)
	}
}

// PrintCertificates prints the certificates from the chain to stdout in human-readable format.
func PrintCertificates(host string, chain []*x509.Certificate) error {
	fmt.Printf("Found %d certificates in the certificate chain for %s \n", len(chain), host)
	for _, cert := range chain {
		txtData, parseErr := certinfo.CertificateText(cert)
		if parseErr != nil {
			return fmt.Errorf("Failed to convert certificate to TXT(OpenSSL) format\nError: %w\n", parseErr)
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
			strings.ReplaceAll(strings.TrimSpace(strings.ToLower(cert.Issuer.CommonName)), " ", ".")},
			"."))
		if err := saveCertificate(path, cert, certFormat); err != nil {
			return fmt.Errorf("Failed to save certificate\nError: %w\n", err)
		}
	}

	return nil
}

// Save a certificate to the location specified by the `path` using a supported format
func saveCertificate(path string, cert *x509.Certificate, certFormat string) error {
	path = strings.Join([]string{path, certFormat}, ".")
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
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	err := os.WriteFile(path, pemData, 0644)
	if err != nil {
		return fmt.Errorf("Failed to save certificate to the location of %s\nError: %w", path, err)
	}

	return nil
}

// Save a certificate to the location specified by the `path` using human-readable OpenSSL text output format
func saveAsTxt(path string, cert *x509.Certificate) error {
	txtData, parseErr := certinfo.CertificateText(cert)
	if parseErr != nil {
		return fmt.Errorf("Failed to convert certificate to TXT(OpenSSL) format\nError: %w\n", parseErr)
	}
	if ioErr := os.WriteFile(path, []byte(txtData), 0644); ioErr != nil {
		return fmt.Errorf("Failed to save certificate to the location of %s\nError: %w", path, ioErr)
	}

	return nil
}

// Save a certificate to the location specified by the `path` using binary DER format
func saveAsDer(path string, cert *x509.Certificate) error {
	if ioErr := os.WriteFile(path, cert.Raw, 0644); ioErr != nil {
		return fmt.Errorf("Failed to save certificate to the location of %s\nError: %w", path, ioErr)
	}
	return nil
}

// Save a certificate to the location specified by the `path` using PKCS (p7b or p7c) format
func saveAsPkcs(path string, cert *x509.Certificate) error {
	certificateData, err := pkcs7.DegenerateCertificate(cert.Raw)
	if err != nil {
		return fmt.Errorf("Failed to degenerate certificate\nError: %w", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PKCS7",
		Bytes: certificateData,
	})

	if ioErr := os.WriteFile(path, pemData, 0644); ioErr != nil {
		return fmt.Errorf("Failed to save certificate to the location of %s\nError: %w", path, ioErr)
	}

	return nil
}

// ValidateCertificate validate server certificate using the following steps:
// 1. Check the expiration date
// 2. Check if the certificate is trusted using the trust store from the host machine
// 3. Check if the certificate is not part of a revocation list
func ValidateCertificate(host string, cert *x509.Certificate) (bool, error) {
	if cert == nil {
		return false, fmt.Errorf("No certificate provided for validation for host %s\n", host)
	}

	// Check if the certificate is between expiration bounds
	currentTime := time.Now().UTC()

	if !currentTime.After(cert.NotBefore) {
		return false, fmt.Errorf("Certificate for host %s will is not valid yet. It will be valid after %s\n",
			host, cert.NotBefore)
	}

	if !currentTime.Before(cert.NotAfter) {
		return false, fmt.Errorf("Certificate for host %s will expired at %s\n", host, cert.NotBefore)
	}

	// Verify if the certificate by building a certificate chain and check if the root is in the trusted store of
	// the host requesting the validation
	opts := x509.VerifyOptions{
		DNSName: host,
		Roots:   nil,
	}

	chain, err := cert.Verify(opts)
	if err != nil {
		return false, fmt.Errorf("Invalidate certificate. Verification err: %w\n", err)
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
		return false, fmt.Errorf("Failed to get revocation list.\nError:%w", err)
	}

	rl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return false, fmt.Errorf("Failed to parse revocation list.\nError:%w", err)
	}

	for _, r := range rl.RevokedCertificates {
		if r.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}
