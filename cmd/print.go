package cmd

import (
	"cert-ripper-go/pkg"
	"github.com/spf13/cobra"
	"log"
	"net/url"
)

var printCmd = &cobra.Command{
	Use:   "print",
	Short: "Print the certificates from the chain to the standard output",
	Long:  ``,
	Run:   runPrint,
}

func runPrint(cmd *cobra.Command, args []string) {
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

	if ioErr := pkg.PrintCertificates(u.Host, certs); ioErr != nil {
		log.Println("Failed to print certificate to the standard output", ioErr)
	}
}

func init() {
	includePrintFlags(printCmd)
}

func includePrintFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&rawUrl, "url", "u", "www.example.com",
		"URL or hostname for which we would want to grab the certificate chain.")
}
