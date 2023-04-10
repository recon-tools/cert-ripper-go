package cmd

import (
	"cert-ripper-go/pkg"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"log"
	"net/url"
	"path/filepath"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export the certificates from the chain and save them into a folder",
	Long:  ``,
	Run:   runExport,
}

var exportRawUrl string
var targetFolderPath string

type CertFormat enumflag.Flag

const (
	PEM CertFormat = iota
	TXT
	DER
)

var CertFormatIds = map[CertFormat][]string{
	PEM: {"pem"},
	TXT: {"txt"},
	DER: {"der"},
}

var certFormat CertFormat

func runExport(cmd *cobra.Command, args []string) {
	var u *url.URL
	if pkg.IsValidHostname(exportRawUrl) {
		u = &url.URL{
			Host: exportRawUrl,
		}
	} else {
		var parseErr error
		u, parseErr = url.ParseRequestURI(exportRawUrl)
		if parseErr != nil {
			log.Printf("Failed to parse URL %s\nError: %s", exportRawUrl, parseErr)
		}
	}

	path := filepath.FromSlash(targetFolderPath)

	certs, fetchErr := pkg.GetCertificateChain(u)
	if fetchErr != nil {
		log.Println("Failed to fetch certificate chain", fetchErr)
	}

	if ioErr := pkg.SaveCertificates(path, certs, CertFormatIds[certFormat][0]); ioErr != nil {
		log.Println("Failed to save certificate from a chain", ioErr)
	}
}

func init() {
	includeExportFlags(exportCmd)
}

func includeExportFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&exportRawUrl, "url", "u", "www.example.com",
		"URL or hostname for which we would want to grab the certificate chain.")
	cmd.PersistentFlags().StringVarP(&targetFolderPath, "path", "p", ".",
		"Path to a writeable folder where the certificates will be saved.")
	cmd.PersistentFlags().VarP(
		enumflag.New(&certFormat, "certFormat", CertFormatIds, enumflag.EnumCaseInsensitive),
		"format", "f",
		"Output certificate format; can be 'pem' (default if omitted), 'der' or 'txt'")
}
