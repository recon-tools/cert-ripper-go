package export

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/pkg/core"
	"cert-ripper-go/pkg/host"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"net/url"
	"path/filepath"
)

var (
	targetFolderPath string

	Cmd = &cobra.Command{
		Use:   "export",
		Short: "Export the certificates from the chain and save them into a folder",
		Long:  ``,
		Run:   runExport,
	}

	certFormat common.CertFormat
	rawUrl     string
)

func runExport(cmd *cobra.Command, args []string) {
	var u *url.URL
	if host.IsValidHostname(rawUrl) {
		u = &url.URL{
			Host: rawUrl,
		}
	} else {
		var parseErr error
		u, parseErr = url.ParseRequestURI(rawUrl)
		if parseErr != nil {
			cmd.PrintErrf("Failed to parse URL %s . Error: %s", rawUrl, parseErr)
			return
		}
	}

	path := filepath.FromSlash(targetFolderPath)

	certs, fetchErr := core.GetCertificateChain(u)
	if fetchErr != nil {
		cmd.PrintErrf("Failed to fetch the certificate chain. Error: %s", fetchErr)
		return
	}

	if ioErr := core.SaveCertificates(path, certs, common.CertFormatIds[certFormat][0]); ioErr != nil {
		cmd.PrintErrf("Failed to save a certificate from the chain. Error: %s", ioErr)
		return
	}
}

func init() {
	includeExportFlags(Cmd)
}

func includeExportFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&rawUrl, "url", "u", "",
		"URL or hostname for which we would want to grab the certificate chain.")
	cmd.Flags().StringVarP(&targetFolderPath, "path", "p", ".",
		"Path to a writeable folder where the certificates will be saved.")
	cmd.Flags().VarP(
		enumflag.New(&certFormat, "certFormat", common.CertFormatIds, enumflag.EnumCaseInsensitive),
		"format", "f",
		"Exported certificate format; can be 'pem' (default if omitted), 'crt', 'cer', 'der', 'p7b', 'p7c' or 'txt'")

	if err := cmd.MarkFlagRequired("url"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
