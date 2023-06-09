package print

import (
	"cert-ripper-go/pkg/core"
	"cert-ripper-go/pkg/host"
	"github.com/spf13/cobra"
	"net/url"
)

var (
	Cmd = &cobra.Command{
		Use:   "print",
		Short: "Fetch the certificate chain from a remote location and print them to the standard output",
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
			cmd.PrintErrf("Failed to parse URL %s\nError: %s", rawUrl, parseErr)
			return
		}
	}

	certs, fetchErr := core.GetCertificateChain(u)
	if fetchErr != nil {
		cmd.PrintErrf("Failed to fetch certificate chain. Error: %s", fetchErr)
		return
	}

	if ioErr := core.PrintCertificates(u.Host, certs); ioErr != nil {
		cmd.PrintErrf("Failed to print certificate to the standard output. Error: %s", ioErr)
		return
	}
}

func init() {
	includePrintFlags(Cmd)
}

func includePrintFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&rawUrl, "url", "u", "",
		"[Required] URL or hostname for which we would want to grab the certificate chain.")

	if err := cmd.MarkFlagRequired("url"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
