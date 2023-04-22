package cmd

import (
	"cert-ripper-go/pkg"
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"net/url"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate the certificate",
	Long: `Validate the certificate using the following checks:
1. Check the expiration date
2. Check if the certificate is trusted using the trust store from the host machine
3. Check if the certificate is not part of a revocation list
`,
	Run: runValidate,
}

func runValidate(cmd *cobra.Command, args []string) {
	var u *url.URL
	if pkg.IsValidHostname(rawUrl) {
		u = &url.URL{
			Host: rawUrl,
		}
	} else {
		var parseErr error
		u, parseErr = url.ParseRequestURI(rawUrl)
		if parseErr != nil {
			log.Printf("Failed to parse URL %s\nError: %s", rawUrl, parseErr)
		}
	}

	certs, fetchErr := pkg.GetCertificateChain(u)
	if fetchErr != nil {
		log.Println("Failed to fetch certificate chain", fetchErr)
	}

	if len(certs) <= 0 {
		log.Println("No certificates in the chain")
		return
	}

	isValid, validationErr := pkg.ValidateCertificate(u.Host, certs[0])
	if validationErr != nil {
		fmt.Printf("Server certificate validation failed. Reason: %s", validationErr)
		return
	}
	if isValid {
		fmt.Printf("Certificate for host %s is valid", u.Host)
	} else {
		fmt.Println("Server certificate validation failed. Reason: none")
	}
}

func init() {
	includeValidateFlags(validateCmd)
}

func includeValidateFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&rawUrl, "url", "u", "www.example.com",
		"URL or hostname for which we would want to grab the certificate chain.")
}
