package generate

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/pkg/cert"
	hostutils "cert-ripper-go/pkg/host"
	"crypto/x509"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"time"
)

var (
	generateFromStdioCommand = &cobra.Command{
		Use:   "fromstdio",
		Short: "Generate a self-signed certificate",
		Long:  ``,
		Run:   runGenerateFromStdio,
	}

	hostName     string
	validFrom    string
	validFor     int64
	isCa         bool
	organization string
	signatureAlg common.SignatureAlgorithm
	targetPath   string
)

func runGenerateFromStdio(cmd *cobra.Command, args []string) {
	if !hostutils.IsValidHostname(hostName) {
		cmd.PrintErrf("Invalid hostname %s", hostName)
		return
	}

	var validFromDateTime time.Time
	if validFrom == "now" {
		validFromDateTime = time.Now()
	} else {
		var parseErr error
		validFromDateTime, parseErr = time.Parse("2006-01-02 15:04:05", validFrom)
		if parseErr != nil {
			cmd.PrintErrf("Invalid date format %s", validFrom)
			return
		}
	}

	privateKey, err := cert.GeneratePrivateKey(common.SignatureAlgTox509[signatureAlg])
	if err != nil {
		cmd.PrintErrf("Failed to generate private key. Error: %s", err)
		return
	}

	certificate, err := cert.CreateCertificate(hostName, validFromDateTime, time.Duration(validFor*3600*24), isCa,
		organization, privateKey)

	if err := cert.SaveCertificates(targetPath, []*x509.Certificate{certificate}, "pem"); err != nil {
		cmd.PrintErrf("Failed to save certificate. Error: %s", err)
		return
	}
}

func init() {
	includeGenerateFromStdio(generateFromStdioCommand)
}

func includeGenerateFromStdio(cmd *cobra.Command) {
	cmd.Flags().StringVar(&hostName, "host", "",
		"Hostname.")
	cmd.Flags().StringVar(&validFrom, "validFrom", "now",
		"Creation UTC date formatted as yyyy-mm-dd HH:MM:SS, example: 2006-01-02 15:04:05")
	cmd.Flags().Int64Var(&validFor, "validFor", 365,
		"Duration in days until which the certificates will be valid")
	cmd.Flags().BoolVar(&isCa, "isCa", false,
		"Specify if the currently generated certificate should be its own Certificate Authority")
	cmd.Flags().StringVar(&organization, "organization", "",
		"Organization (example: Acme)")
	cmd.Flags().Var(
		enumflag.New(&signatureAlg, "signatureAlg", common.SignatureAlgIds, enumflag.EnumCaseInsensitive),
		"signatureAlg", "Signature Algorithm (allowed values: SHA256WithRSA, SHA384WithRSA, SHA512WithRSA,"+
			"SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA)")
	cmd.Flags().StringVar(&targetPath, "targetPath", ".",
		"Target path for the CSR to be saved.")
}
