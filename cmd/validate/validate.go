package validate

import (
	"cert-ripper-go/pkg/core"
	"cert-ripper-go/pkg/host"
	"github.com/spf13/cobra"
	"net/url"
)

var (
	Cmd = &cobra.Command{
		Use:   "validate",
		Short: "Validate the certificate",
		Long: `Validate the certificate using the following checks:
1. Check the expiration date
2. Check if the certificate is trusted using the trust store from the host machine
3. Check if the certificate is not part of a revocation list
`,
		Run: runValidate,
	}

	rawUrl string
)

func runValidate(cmd *cobra.Command, args []string) {
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

	if len(certs) <= 0 {
		cmd.PrintErr("No certificates in the chain.")
		return
	}

	isValid, validationErr := core.ValidateCertificate(u.Host, certs[0])
	if validationErr != nil {
		cmd.PrintErrf("Server certificate validation failed. Error: %s", validationErr)
		return
	}
	if isValid {
		cmd.Printf("Certificate for host %s is valid", u.Host)
	} else {
		cmd.Println("Server certificate validation failed.")
	}
}

func init() {
	includeValidateFlags(Cmd)
}

func includeValidateFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&rawUrl, "url", "u", "",
		"[Required] URL or hostname for which we would want to grab the certificate chain.")

	if err := cmd.MarkFlagRequired("url"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
