package ca

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/cmd/generate/shared"
	"cert-ripper-go/pkg/core"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"path/filepath"
	"time"
)

var (
	Cmd = &cobra.Command{
		Use:   "ca",
		Short: "Create a Certificate Authority certificate.",
		Long:  ``,
		Run:   generateCACertificate,
	}

	validFrom      string
	validFor       int64
	country        *[]string
	state          *[]string
	city           *[]string
	street         *[]string
	postalCode     *[]string
	organization   *[]string
	orgUnit        *[]string
	emailAddresses *[]string
	signatureAlg   common.SignatureAlgorithm
	targetPath     string
	certNamePrefix string
)

func generateCACertificate(cmd *cobra.Command, args []string) {

	var validFromDateTime time.Time
	if validFrom == "now" {
		validFromDateTime = time.Now()
	} else {
		var parseErr error
		validFromDateTime, parseErr = time.Parse("2006-01-02 15:04:05", validFrom)
		if parseErr != nil {
			cmd.PrintErrf("Invalid date format %s. Error: %s", validFrom, parseErr)
			return
		}
	}

	targetPath = filepath.FromSlash(targetPath)

	certPath := shared.ComputeCertificatePath(targetPath, certNamePrefix)
	keyPath := shared.ComputeKeyPath(targetPath, certNamePrefix)

	privateKey, keyErr := core.GeneratePrivateKey(common.SignatureAlgTox509[signatureAlg])
	if keyErr != nil {
		cmd.PrintErrf("Failed to generate private key. Error: %s", keyErr)
		return
	}

	keyIoError := core.SavePrivateKey(privateKey, keyPath)
	if keyIoError != nil {
		cmd.PrintErrf("Failed to save private key. Error: %s", keyIoError)
		return
	}

	caInput := core.CaInput{
		NotBefore:      validFromDateTime,
		ValidFor:       time.Duration(validFor) * time.Hour * 24,
		Country:        country,
		State:          state,
		City:           city,
		Street:         street,
		PostalCode:     postalCode,
		Organization:   organization,
		OrgUnit:        orgUnit,
		EmailAddresses: emailAddresses,
		PrivateKey:     privateKey,
	}

	certificate, certErr := core.CreateCertificateAuthority(caInput)
	if certErr != nil {
		cmd.PrintErrf("Failed to create CA certificate. Error: %s", certErr)
		return
	}

	if saveErr := core.SaveCertificate(certPath, certificate, "pem"); saveErr != nil {
		cmd.PrintErrf("Failed to save CA certificate. Error: %s", saveErr)
		return
	}
}

func init() {
	includeGenerateCAFromStdio(Cmd)
}

func includeGenerateCAFromStdio(cmd *cobra.Command) {
	cmd.Flags().StringVar(&validFrom, "validFrom", "now",
		"[Optional] Creation UTC date formatted as yyyy-mm-dd HH:MM:SS, example: 2006-01-02 15:04:05 . "+
			"Default: current time (now)")
	cmd.Flags().Int64Var(&validFor, "validFor", 365,
		"[Optional] Duration in days until which the certificates will be valid. "+
			"Default: 365 days")
	country = cmd.Flags().StringSlice("country", nil,
		"[Optional] Country code (example: US). It can accept multiple values divided by comma. "+
			"Default: none")
	state = cmd.Flags().StringSlice("state", nil,
		"[Optional] Province/State (example: California). It can accept multiple values divided by comma. "+
			"Default: none")
	city = cmd.Flags().StringSlice("city", nil,
		"[Optional] Locality/City (example: New-York). It can accept multiple values divided by comma. "+
			"Default: none")
	street = cmd.Flags().StringSlice("street", nil,
		"[Optional] Street Address. It can accept multiple values divided by comma. "+
			"Default: none")
	postalCode = cmd.Flags().StringSlice("postalCode", nil,
		"[Optional] Postal Code. It can accept multiple values divided by comma. "+
			"Default: none")
	organization = cmd.Flags().StringSlice("organization", nil,
		"[Optional] Organization (example: Acme). It can accept multiple values divided by comma. "+
			"Default: none")
	orgUnit = cmd.Flags().StringSlice("organizationUnit", nil,
		"[Optional] Organization unit (example: IT). It can accept multiple values divided by comma. "+
			"Default: none")
	emailAddresses = cmd.Flags().StringSlice("email", nil,
		"[Optional] Email Addresses. It can accept multiple values divided by comma. Default: none")
	cmd.Flags().Var(
		enumflag.New(&signatureAlg, "signatureAlg", common.SignatureAlgIds, enumflag.EnumCaseInsensitive),
		"signatureAlg", "[Optional] Signature Algorithm (allowed values: SHA256WithRSA (default if omitted)"+
			", SHA384WithRSA, SHA512WithRSA, SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA)")
	cmd.Flags().Lookup("signatureAlg").NoOptDefVal = "SHA256WithRSA"
	cmd.Flags().StringVar(&targetPath, "targetPath", ".",
		"Target path for the CSR to be saved.")
	cmd.Flags().StringVar(&certNamePrefix, "certNamePrefix", "ca-cert",
		"[Optional] Prefix for the name of the certificate. The certificate will be saved in the folder "+
			"provided with --targetPath. The name of the certificate will be <certNamePrefix>.pem (or other extension "+
			"requested). Additionally, this prefix will be used in the name of the private key and/or the name of the "+
			"ca certificate.")
}
