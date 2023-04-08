package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/fullsailor/pkcs7"
	"github.com/grantae/certinfo"
	"io"
	"log"
	"net/http"
	"net/url"
)

// Get the certificate chain for the hostname or a URL. In case the certificate chain does not contain the root
// certificate, we will attend to fetch it using issuer location of the last certificate from the chain.
func getCertificateChain(u *url.URL) ([]*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, connectionErr := tls.Dial("tcp", fmt.Sprintf("%s:443", u.Host), conf)
	if connectionErr != nil {
		log.Println("Error in Dial", connectionErr)
		return nil, connectionErr
	}
	defer func(conn *tls.Conn) {
		err := conn.Close()
		if err != nil {
			log.Println("Error in closing connection to host", err)
		}
	}(conn)

	chain := conn.ConnectionState().PeerCertificates
	rootCert, err := getRootCertificateIfPossible(chain)
	if err != nil {
		//
	} else {
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
			resp, err := http.Get(cert.IssuingCertificateURL[0])
			if err != nil {
				log.Println(fmt.Sprintf("Failed to retrieve certificate from remote location `%s",
					cert.IssuingCertificateURL[0]), err)
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

			pkcsBlock, err := pkcs7.Parse(certBytes)
			if err != nil {
				log.Println("Failed to parse PKCS7 cert:", err)
				return nil, err
			}

			return pkcsBlock.Certificates, nil
		}
	}

	return make([]*x509.Certificate, 0), nil
}

// Print the certificates from the chain in human-readable format.
func printCertificates(host string, certs []*x509.Certificate) {
	fmt.Printf("Found %d certificates in the certificate chain for %s \n", len(certs), host)
	for _, cert := range certs {
		result, err := certinfo.CertificateText(cert)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("===========================")
		fmt.Print(result)
	}
}
