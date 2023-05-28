package fromstdio

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/pkg/core"
	hostutils "cert-ripper-go/pkg/host"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"path"
	"path/filepath"
	"time"
)

var (
	Cmd = &cobra.Command{
		Use:   "fromstdio",
		Short: "Generate a self-signed certificate",
		Long:  ``,
		Run:   runGenerateFromStdio,
	}

	commonName              string
	validFrom               string
	validFor                int64
	isCa                    bool
	country                 *[]string
	state                   *[]string
	city                    *[]string
	street                  *[]string
	postalCode              *[]string
	organization            *[]string
	orgUnit                 *[]string
	oidEmail                string
	emailAddresses          *[]string
	subjectAlternativeHosts *[]string
	signatureAlg            common.SignatureAlgorithm
	targetPath              string
)

func runGenerateFromStdio(cmd *cobra.Command, args []string) {
	if !hostutils.IsValidHostname(commonName) {
		cmd.PrintErrf("Invalid hostname %s", commonName)
		return
	}

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

	var certPath string
	var keyPath string
	extension := filepath.Ext(targetPath)
	if extension == "" {
		// We assume that a path without an extension is a directory. We append the certificate and the key name to it
		certPath = path.Join(targetPath, "cert")
		keyPath = path.Join(targetPath, "cert.pem.key")
	} else {
		pathWithoutExt := targetPath[0 : len(targetPath)-len(extension)]
		certPath = pathWithoutExt + ".pem"
		keyPath = pathWithoutExt + ".pem.key"
	}

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

	certInput := core.CertificateInput{
		CommonName:              commonName,
		NotBefore:               validFromDateTime,
		ValidFor:                time.Duration(validFor) * time.Hour * 24,
		IsCA:                    isCa,
		Country:                 country,
		State:                   state,
		City:                    city,
		Street:                  street,
		PostalCode:              postalCode,
		Organization:            organization,
		OrgUnit:                 orgUnit,
		OidEmail:                oidEmail,
		EmailAddresses:          emailAddresses,
		SubjectAlternativeHosts: subjectAlternativeHosts,
		PrivateKey:              privateKey,
	}

	certificate, certErr := core.CreateCertificate(certInput)
	if certErr != nil {
		cmd.PrintErrf("Failed to create certificate. Error: %s", certErr)
		return
	}

	if saveErr := core.SaveCertificate(certPath, certificate, "pem"); saveErr != nil {
		cmd.PrintErrf("Failed to save certificate. Error: %s", saveErr)
		return
	}
}

func init() {
	includeGenerateFromStdio(Cmd)
}

func includeGenerateFromStdio(cmd *cobra.Command) {
	cmd.Flags().StringVar(&commonName, "commonName", "",
		"[Required] Hostname/Common name (example: domain.com).")
	cmd.Flags().StringVar(&validFrom, "validFrom", "now",
		"[Optional] Creation UTC date formatted as yyyy-mm-dd HH:MM:SS, example: 2006-01-02 15:04:05 . "+
			"Default: current time (now)")
	cmd.Flags().Int64Var(&validFor, "validFor", 365,
		"[Optional] Duration in days until which the certificates will be valid. "+
			"Default: 365 days")
	cmd.Flags().BoolVar(&isCa, "isCa", false,
		"[Optional] Specify if the currently generated certificate should be its own Certificate Authority. "+
			"Default: false if not specified")
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
	cmd.Flags().StringVar(&oidEmail, "oidEmail", "",
		"[Optional] Object Identifier (OID) Email Address. Default: none")
	emailAddresses = cmd.Flags().StringSlice("email", nil,
		"[Optional] Email Addresses. It can accept multiple values divided by comma. Default: none")
	subjectAlternativeHosts = cmd.Flags().StringSlice("subjectAlternativeHost", nil,
		"[Optional] Subject Alternative Hosts. It can accept multiple values divided by comma. "+
			"Default: none")
	cmd.Flags().Var(
		enumflag.New(&signatureAlg, "signatureAlg", common.SignatureAlgIds, enumflag.EnumCaseInsensitive),
		"signatureAlg", "[Optional] Signature Algorithm (allowed values: SHA256WithRSA (default if omitted)"+
			", SHA384WithRSA, SHA512WithRSA, SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA)")
	cmd.Flags().Lookup("signatureAlg").NoOptDefVal = "SHA256WithRSA"
	cmd.Flags().StringVar(&targetPath, "targetPath", "./cert.pem",
		"Target path for the CSR to be saved.")

	if err := cmd.MarkFlagRequired("commonName"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
