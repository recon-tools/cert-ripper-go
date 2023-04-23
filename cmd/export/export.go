package export

import (
	"cert-ripper-go/pkg"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"log"
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

	path := filepath.FromSlash(targetFolderPath)

	certs, fetchErr := pkg.GetCertificateChain(u)
	if fetchErr != nil {
		log.Println("Failed to fetch the certificate chain", fetchErr)
	}

	if ioErr := pkg.SaveCertificates(path, certs, CertFormatIds[certFormat][0]); ioErr != nil {
		log.Println("Failed to save a certificate from the chain", ioErr)
	}
}

func init() {
	includeExportFlags(Cmd)
}

func includeExportFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&rawUrl, "url", "u", "www.example.com",
		"URL or hostname for which we would want to grab the certificate chain.")
	cmd.PersistentFlags().StringVarP(&targetFolderPath, "path", "p", ".",
		"Path to a writeable folder where the certificates will be saved.")
	cmd.PersistentFlags().VarP(
		enumflag.New(&certFormat, "certFormat", CertFormatIds, enumflag.EnumCaseInsensitive),
		"format", "f",
		"Exported certificate format; can be 'pem' (default if omitted), 'crt', 'cer', 'der', 'p7b', 'p7c' or 'txt'")
}
