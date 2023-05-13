package fromstdio

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/pkg/cert"
	hostutils "cert-ripper-go/pkg/host"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"time"
)

var (
	Cmd = &cobra.Command{
		Use:   "fromstdio",
		Short: "Generate a self-signed certificate",
		Long:  ``,
		Run:   runGenerateFromStdio,
	}

	hostName                string
	validFrom               string
	validFor                int64
	isCa                    bool
	country                 *[]string
	state                   *[]string
	city                    *[]string
	streetAddress           *[]string
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
			cmd.PrintErrf("Invalid date format %s. Error: %s", validFrom, parseErr)
			return
		}
	}

	privateKey, keyErr := cert.GeneratePrivateKey(common.SignatureAlgTox509[signatureAlg])
	if keyErr != nil {
		cmd.PrintErrf("Failed to generate private key. Error: %s", keyErr)
		return
	}

	certInput := cert.CertificateInput{
		CommonName:              hostName,
		NotBefore:               validFromDateTime,
		ValidFor:                time.Duration(validFor) * time.Hour * 24,
		IsCA:                    isCa,
		Country:                 country,
		State:                   state,
		City:                    city,
		Street:                  streetAddress,
		PostalCode:              postalCode,
		Organization:            organization,
		OrgUnit:                 orgUnit,
		OidEmail:                oidEmail,
		EmailAddresses:          emailAddresses,
		SubjectAlternativeHosts: subjectAlternativeHosts,
		PrivateKey:              privateKey,
	}

	certificate, certErr := cert.CreateCertificate(certInput)
	if certErr != nil {
		cmd.PrintErrf("Failed to create certificate. Error: %s", certErr)
		return
	}

	if saveErr := cert.SaveCertificate(targetPath, certificate, "pem"); saveErr != nil {
		cmd.PrintErrf("Failed to save certificate. Error: %s", saveErr)
		return
	}
}

func init() {
	includeGenerateFromStdio(Cmd)
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
	country = cmd.Flags().StringSlice("country", nil,
		"Country code (example: US).")
	state = cmd.Flags().StringSlice("state", nil,
		"Province/State (example: California)")
	city = cmd.Flags().StringSlice("city", nil,
		"Locality/City (example: New-York)")
	streetAddress = cmd.Flags().StringSlice("streetAddress", nil,
		"Street Address")
	postalCode = cmd.Flags().StringSlice("postalCode", nil,
		"Postal Code")
	organization = cmd.Flags().StringSlice("organization", nil,
		"Organization (example: Acme)")
	orgUnit = cmd.Flags().StringSlice("organizationUnit", nil,
		"Organization unit (example: IT)")
	cmd.Flags().StringVar(&oidEmail, "oidEmail", "",
		"Object Identifier (OID) Email Address")
	emailAddresses = cmd.Flags().StringSlice("email", nil,
		"Email Addresses")
	subjectAlternativeHosts = cmd.Flags().StringSlice("subjectAlternativeHosts", nil,
		"Subject Alternative Hosts")
	cmd.Flags().Var(
		enumflag.New(&signatureAlg, "signatureAlg", common.SignatureAlgIds, enumflag.EnumCaseInsensitive),
		"signatureAlg", "Signature Algorithm (allowed values: SHA256WithRSA, SHA384WithRSA, SHA512WithRSA,"+
			"SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA)")
	cmd.Flags().Lookup("signatureAlg").NoOptDefVal = "SHA256WithRSA"
	cmd.Flags().StringVar(&targetPath, "targetPath", "./cert.pem",
		"Target path for the CSR to be saved.")
}
