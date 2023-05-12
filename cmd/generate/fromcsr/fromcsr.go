package fromcsr

import (
	"cert-ripper-go/pkg/cert"
	"github.com/spf13/cobra"
	"time"
)

var (
	Cmd = &cobra.Command{
		Use:   "fromcsr",
		Short: "Generate a self-signed certificate from a CSR request",
		Long:  ``,
		Run:   runGenerateFromCsrRequest,
	}

	csrPath        string
	privateKeyPath string
	targetPath     string
	validFrom      string
	validFor       int64
)

func runGenerateFromCsrRequest(cmd *cobra.Command, args []string) {
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

	csr, csrErr := cert.DecodeCSR(csrPath)
	if csrErr != nil {
		cmd.PrintErrf("Failed to read and decode CSR from file %s. Error: %s", csrPath, csrErr)
		return
	}

	privateKey, keyErr := cert.ReadKey(privateKeyPath)
	if keyErr != nil {
		cmd.PrintErrf("Failed to read private key from file %s. Error: %s", privateKeyPath, keyErr)
		return
	}

	certificate, certErr := cert.CreateCertificateFromCSR(csr, validFromDateTime,
		time.Duration(validFor)*time.Hour*24, true, privateKey)
	if certErr != nil {
		cmd.PrintErrf("Failed to create certificate from CSR. Error: %s", certErr)
		return
	}

	if ioErr := cert.SaveCertificate(targetPath, certificate, "pem"); ioErr != nil {
		cmd.PrintErrf("Failed to save certificate. Error: %s", ioErr)
		return
	}
}

func init() {
	includeGenerateFromCsrFlags(Cmd)
}

func includeGenerateFromCsrFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&csrPath, "csrPath", ".",
		"Path to the CSR in PEM format.")
	cmd.Flags().StringVar(&privateKeyPath, "privateKeyPath", ".",
		"Path to the Private Key in PEM format")
	cmd.Flags().StringVar(&targetPath, "targetPath", ".",
		"Path to save the generated certificate")
	cmd.Flags().StringVar(&validFrom, "validFrom", "now",
		"Creation UTC date formatted as yyyy-mm-dd HH:MM:SS, example: 2006-01-02 15:04:05")
	cmd.Flags().Int64Var(&validFor, "validFor", 365,
		"Duration in days until which the certificates will be valid")
}
