package export

import (
	"cert-ripper-go/pkg/cert"
	"cert-ripper-go/pkg/host"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"net/url"
	"path/filepath"
)

type CertFormat enumflag.Flag

const (
	PEM CertFormat = iota
	CRT
	CER
	TXT
	DER
	P7B
	P7C
)

var (
	targetFolderPath string

	Cmd = &cobra.Command{
		Use:   "export",
		Short: "Export the certificates from the chain and save them into a folder",
		Long:  ``,
		Run:   runExport,
	}

	CertFormatIds = map[CertFormat][]string{
		PEM: {"pem"},
		CRT: {"crt"},
		CER: {"cer"},
		TXT: {"txt"},
		DER: {"der"},
		P7B: {"p7b"},
		P7C: {"p7c"},
	}

	certFormat CertFormat
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

	certs, fetchErr := cert.GetCertificateChain(u)
	if fetchErr != nil {
		cmd.PrintErrf("Failed to fetch the certificate chain. Error: %s", fetchErr)
		return
	}

	if ioErr := cert.SaveCertificates(path, certs, CertFormatIds[certFormat][0]); ioErr != nil {
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
		enumflag.New(&certFormat, "certFormat", CertFormatIds, enumflag.EnumCaseInsensitive),
		"format", "f",
		"Exported certificate format; can be 'pem' (default if omitted), 'crt', 'cer', 'der', 'p7b', 'p7c' or 'txt'")

	if err := cmd.MarkFlagRequired("url"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
