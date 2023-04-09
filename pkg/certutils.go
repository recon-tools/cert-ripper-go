package pkg

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/fullsailor/pkcs7"
	"github.com/grantae/certinfo"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// GetCertificateChain gets the certificate chain for the hostname or a URL. In case the certificate chain does not
// contain the root certificate, we will attend to fetch it using issuer location of the last certificate from the chain.
func GetCertificateChain(u *url.URL) ([]*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, connectionErr := tls.Dial("tcp", fmt.Sprintf("%s:443", u.Host), conf)
	if connectionErr != nil {
		log.Printf("Failed to connect to %s\n Error: %s", u.Host, connectionErr)
		return nil, connectionErr
	}
	defer func(conn *tls.Conn) {
		err := conn.Close()
		if err != nil {
			log.Printf("Error in closing connection to %s\n Error: %s", u.Host, err)
		}
	}(conn)

	chain := conn.ConnectionState().PeerCertificates
	rootCert, _ := getRootCertificateIfPossible(chain)
	if rootCert != nil {
		chain = append(chain, rootCert...)
	}
	return chain, nil
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
				log.Printf("Failed to retrieve certificate from remote location %s\n Error: %s\n",
					cert.IssuingCertificateURL[0], err)
				return nil, err
			}
			defer func(Body io.ReadCloser) {
				_ = Body.Close()
			}(resp.Body)

			certBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Println("Failed to read certificate for parsing:", err)
				return nil, err
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
				log.Println("Failed to parse PKCS7 cert:", err)
				return nil, err
			}
			return pkcsBlock.Certificates, nil
		}
	case ".der":
		fallthrough
	case ".crt":
		{
			crt, err := x509.ParseCertificate(certBytes)
			if err != nil {
				log.Println("Failed to decode CRT cert:", err)
				return nil, err
			}
			return []*x509.Certificate{crt}, nil
		}
	default:
		log.Println("Invalid certificate format:", certFormat)
		return nil, fmt.Errorf("invalid certificate format")
	}
}

// PrintCertificates prints the certificates from the chain to stdout in human-readable format.
func PrintCertificates(host string, chain []*x509.Certificate) error {
	fmt.Printf("Found %d certificates in the certificate chain for %s \n", len(chain), host)
	for _, cert := range chain {
		txtData, parseErr := certinfo.CertificateText(cert)
		if parseErr != nil {
			log.Println("Cannot convert certificate to TXT!", parseErr)
			return parseErr
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
			return err
		}
	}

	return nil
}

func saveCertificate(path string, cert *x509.Certificate, certFormat string) error {
	path = strings.Join([]string{path, certFormat}, ".")
	formatToAction := map[string]func(string, *x509.Certificate) error{
		"pem": saveAsPem,
		"txt": saveAsTxt,
	}
	action, ok := formatToAction[certFormat]
	if !ok {
		return fmt.Errorf("invalid certificate type")
	}
	return action(path, cert)
}

func saveAsPem(path string, cert *x509.Certificate) error {
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	err := os.WriteFile(path, pemData, 0644)
	if err != nil {
		log.Println("Certificate could not be saved!", err)
		return err
	}

	return nil
}

func saveAsTxt(path string, cert *x509.Certificate) error {
	txtData, parseErr := certinfo.CertificateText(cert)
	if parseErr != nil {
		log.Println("Cannot convert certificate to TXT!", parseErr)
		return parseErr
	}
	ioErr := os.WriteFile(path, []byte(txtData), 0644)
	if ioErr != nil {
		log.Println("Certificate could not be saved!", ioErr)
		return ioErr
	}

	return nil
}
