package fromcsr

import (
	"cert-ripper-go/pkg/core"
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
	caPath         string
	targetPath     string
	validFrom      string
	validFor       int64
	isCa           bool
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

	csr, csrErr := core.DecodeCSR(csrPath)
	if csrErr != nil {
		cmd.PrintErrf("Failed to read and decode CSR from path \"%s\" Error: %s", csrPath, csrErr)
		return
	}

	ca, caErr := core.DecodeCertificate(caPath)
	if caErr != nil {
		cmd.PrintErrf("Failed to read and decode CA from path \"%s\" Error: %s", caPath, caErr)
		return
	}

	privateKey, keyErr := core.ReadKey(privateKeyPath)
	if keyErr != nil {
		cmd.PrintErrf("Failed to read private key from path \"%s\" Error: %s", privateKeyPath, keyErr)
		return
	}

	certificate, certErr := core.CreateCertificateFromCSR(csr, validFromDateTime,
		time.Duration(validFor)*time.Hour*24, ca[0], privateKey)
	if certErr != nil {
		cmd.PrintErrf("Failed to create certificate from CSR. Error: %s", certErr)
		return
	}

	if ioErr := core.SaveCertificate(targetPath, certificate, "pem"); ioErr != nil {
		cmd.PrintErrf("Failed to save certificate. Error: %s", ioErr)
		return
	}
}

func init() {
	includeGenerateFromCsrFlags(Cmd)
}

func includeGenerateFromCsrFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&csrPath, "csrPath", "s", "",
		"[Required] Path to the CSR in PEM format.")
	cmd.Flags().StringVarP(&caPath, "caPath", "c", "",
		"[Required] Path to CA certificate")
	cmd.Flags().StringVarP(&privateKeyPath, "privateKeyPath", "k", "",
		"[Required] Path to the Private Key in PEM format")
	cmd.Flags().StringVarP(&targetPath, "targetPath", "t", "cert.pem",
		"[Optional] Path to save the generated certificate. "+
			"Default: the certificate will be saved in the current working directory with the name of cert.pem")
	cmd.Flags().StringVar(&validFrom, "validFrom", "now",
		"[Optional] Creation UTC date formatted as yyyy-mm-dd HH:MM:SS, example: 2006-01-02 15:04:05 "+
			"Default: current time (now)")
	cmd.Flags().Int64Var(&validFor, "validFor", 365,
		"[Optional] Duration in days in days until which the certificates will be valid."+
			"Default: 365 days")
	cmd.Flags().BoolVar(&isCa, "isCa", false,
		"[Optional] Specify if the currently generated certificate should be its own Certificate Authority."+
			"Default: false if not specified")

	if err := cmd.MarkFlagRequired("csrPath"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}

	if err := cmd.MarkFlagRequired("caPath"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}

	if err := cmd.MarkFlagRequired("privateKeyPath"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
