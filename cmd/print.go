package cmd

import (
	"cert-ripper-go/pkg"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"net/url"
)

var printCmd = &cobra.Command{
	Use:   "print",
	Short: "Print the certificates from the chain to the standard output.",
	Long:  ``,
	Run:   runPrint,
}

var rawUrl string

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
			log.Println("Error parsing URL", parseErr)
		}
	}

	certs, err := pkg.GetCertificateChain(u)
	if err != nil {
		log.Println("Error fetching certificate chain:", err)
	}
	pkg.PrintCertificates(u.Host, certs)
}

func init() {
	includePrintFlags(printCmd)
}

func includePrintFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&rawUrl, "url", "www.example.com",
		"URL or hostname for which we would want to grab the certificate chain.")
	err := viper.BindPFlag("url", cmd.PersistentFlags().Lookup("url"))
	if err != nil {
		return
	}
}
