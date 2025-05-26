package fromcsr

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/cmd/generate/shared"
	"cert-ripper-go/pkg/core"
	"crypto/x509"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"path/filepath"
	"time"
)

var (
	Cmd = &cobra.Command{
		Use:     "fromcsr",
		Short:   "Generate a self-signed certificate from a CSR request",
		Long:    ``,
		PreRunE: shared.ValidateCmdFlags,
		Run:     runGenerateFromCsrRequest,
	}

	caPath           string
	caPrivateKeyPath string

	csrPath        string
	targetPath     string
	validFrom      string
	validFor       int64
	signatureAlg   common.SignatureAlgorithm
	certNamePrefix string
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

	targetPath = filepath.FromSlash(targetPath)

	csr, csrErr := core.DecodeCSR(csrPath)
	if csrErr != nil {
		cmd.PrintErrf("Failed to read and decode CSR from path \"%s\" Error: %s", csrPath, csrErr)
		return
	}

	caPrivateKey, caPrivateKeyErr := shared.RetrieveOrGeneratePrivateKey(caPrivateKeyPath, targetPath,
		fmt.Sprintf("ca-%s", certNamePrefix), signatureAlg)
	if caPrivateKeyErr != nil {
		cmd.PrintErrf("Failed to load CA private key: %s", caPrivateKeyErr)
		return
	}

	var ca *x509.Certificate
	if len(caPath) > 0 {
		var caErr error
		ca, caErr = core.DecodeCACertificate(caPath)
		if caErr != nil {
			cmd.PrintErrf("Failed to read and decode CA from path \"%s\" Error: %s", caPath, caErr)
			return
		}
	} else {
		caInput := core.CaInput{
			NotBefore:  validFromDateTime,
			ValidFor:   time.Duration(validFor) * time.Hour * 24,
			PrivateKey: caPrivateKey,
		}

		var certErr error
		ca, certErr = core.CreateCertificateAuthority(caInput)
		if certErr != nil {
			cmd.PrintErrf("Failed to create CA certificate. Error: %s", certErr)
			return
		}

		newCACertPath := shared.ComputeCertificatePath(targetPath, fmt.Sprintf("ca-%s", certNamePrefix))
		if saveErr := core.SaveCertificate(newCACertPath, ca, "pem"); saveErr != nil {
			cmd.PrintErrf("Failed to save CA certificate. Error: %s", saveErr)
			return
		}
	}

	privateKey, keyErr := core.GeneratePrivateKey(common.SignatureAlgTox509[signatureAlg])
	if keyErr != nil {
		cmd.PrintErrf("Failed to generate private key. Error: %s", keyErr)
		return
	}

	keyPath := shared.ComputeKeyPath(targetPath, certNamePrefix)
	keyIoError := core.SavePrivateKey(privateKey, keyPath)
	if keyIoError != nil {
		cmd.PrintErrf("Failed to save private key. Error: %s", keyIoError)
		return
	}

	certificate, certErr := core.CreateCertificateFromCSR(csr, validFromDateTime,
		time.Duration(validFor)*time.Hour*24, ca, caPrivateKey, privateKey)
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
		"[Optional] Path to CA certificate")
	cmd.Flags().StringVarP(&caPrivateKeyPath, "caPrivateKeyPath", "k", "",
		"[Optional] Path to CA certificate's private key. Required if --caPath (-a) is set.")
	cmd.Flags().Var(
		enumflag.New(&signatureAlg, "signatureAlg", common.SignatureAlgIds, enumflag.EnumCaseInsensitive),
		"signatureAlg", "[Optional] Signature Algorithm (allowed values: SHA256WithRSA (default if omitted)"+
			", SHA384WithRSA, SHA512WithRSA, SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA)")
	cmd.Flags().StringVarP(&targetPath, "targetPath", "t", "cert.pem",
		"[Optional] Path to save the generated certificate. "+
			"Default: the certificate will be saved in the current working directory with the name of cert.pem")
	cmd.Flags().StringVar(&validFrom, "validFrom", "now",
		"[Optional] Creation UTC date formatted as yyyy-mm-dd HH:MM:SS, example: 2006-01-02 15:04:05 "+
			"Default: current time (now)")
	cmd.Flags().Int64Var(&validFor, "validFor", 365,
		"[Optional] Duration in days in days until which the certificates will be valid."+
			"Default: 365 days")

	if err := cmd.MarkFlagRequired("csrPath"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
