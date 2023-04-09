package cmd

import (
	"cert-ripper-go/pkg"
	"github.com/spf13/cobra"
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
			log.Println("Error parsing URL", parseErr)
		}
	}

	path := filepath.FromSlash(targetFolderPath)

	certs, fetchErr := pkg.GetCertificateChain(u)
	if fetchErr != nil {
		log.Println("Error fetching certificate chain:", fetchErr)
	}

	if ioErr := pkg.SaveCertificates(path, certs); ioErr != nil {
		log.Println("Error while saving file with certificate content:", ioErr)
	}
}

func init() {
	includeExportFlags(exportCmd)
}

func includeExportFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&exportRawUrl, "url", "www.example.com",
		"URL or hostname for which we would want to grab the certificate chain.")
	cmd.PersistentFlags().StringVar(&targetFolderPath, "path", ".",
		"Path to a writeable folder where the certificates will be saved.")
}
