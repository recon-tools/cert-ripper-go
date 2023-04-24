package print

import (
	"cert-ripper-go/pkg/cert"
	"cert-ripper-go/pkg/host"
	"github.com/spf13/cobra"
	"log"
	"net/url"
)

var (
	Cmd = &cobra.Command{
		Use:   "print",
		Short: "Print the certificates from the chain to the standard output",
		Long:  ``,
		Run:   runPrint,
	}

	rawUrl string
)

func runPrint(cmd *cobra.Command, args []string) {
	var u *url.URL
	if host.IsValidHostname(rawUrl) {
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

	certs, fetchErr := cert.GetCertificateChain(u)
	if fetchErr != nil {
		log.Println("Failed to fetch certificate chain", fetchErr)
	}

	if ioErr := cert.PrintCertificates(u.Host, certs); ioErr != nil {
		log.Println("Failed to print certificate to the standard output", ioErr)
	}
}

func init() {
	includePrintFlags(Cmd)
}

func includePrintFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&rawUrl, "url", "u", "www.example.com",
		"URL or hostname for which we would want to grab the certificate chain.")
}
