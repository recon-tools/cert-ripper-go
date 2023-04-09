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

var printRawUrl string

func runPrint(cmd *cobra.Command, args []string) {
	var u *url.URL
	if pkg.IsValidHostname(printRawUrl) {
		u = &url.URL{
			Host: printRawUrl,
		}
	} else {
		var parseErr error
		u, parseErr = url.ParseRequestURI(printRawUrl)
		if parseErr != nil {
			log.Println("Error parsing URL", parseErr)
		}
	}

	certs, err := pkg.GetCertificateChain(u)
	if err != nil {
		log.Println("Error fetching certificate chain:", err)
	}
	_ = pkg.PrintCertificates(u.Host, certs)
}

func init() {
	includePrintFlags(printCmd)
}

func includePrintFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&printRawUrl, "url", "www.example.com",
		"URL or hostname for which we would want to grab the certificate chain.")
}
