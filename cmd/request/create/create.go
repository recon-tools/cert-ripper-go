package create

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/pkg/cert"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
)

var (
	Cmd = &cobra.Command{
		Use:   "create",
		Short: "Create a CSR (certificate signing request)",
		Long:  ``,
		Run:   runCreateRequest,
	}

	commonName     string
	country        *[]string
	state          *[]string
	city           *[]string
	street         *[]string
	postalCode     *[]string
	organization   *[]string
	orgUnit        *[]string
	targetPath     string
	signatureAlg   common.SignatureAlgorithm
	oidEmail       string
	emailAddresses *[]string
)

func runCreateRequest(cmd *cobra.Command, args []string) {
	request := cert.CertificateRequest{
		CommonName:     commonName,
		Country:        country,
		State:          state,
		City:           city,
		Street:         street,
		PostalCode:     postalCode,
		Organization:   organization,
		OrgUnit:        orgUnit,
		OidEmail:       oidEmail,
		EmailAddresses: emailAddresses,
		SignatureAlg:   common.SignatureAlgTox509[signatureAlg],
	}

	csr, privateKey, csrErr := cert.CreateCSR(request)
	if csrErr != nil {
		cmd.PrintErrf("Failed create CSR. Error: %s", csrErr)
		return
	}

	ioErr := cert.SaveCSR(csr, targetPath)
	if ioErr != nil {
		cmd.PrintErrf("Failed to save CSR to location %s. Error: %s", targetPath, ioErr)
		return
	}

	privateKeyTargetPath := targetPath + ".key"
	ioErr = cert.SavePrivateKey(privateKey, privateKeyTargetPath)
	if ioErr != nil {
		cmd.PrintErrf("Failed to save Private KEY for CSR to location %s. Error: %s", privateKeyTargetPath, ioErr)
		return
	}
}

func init() {
	includeCreateRequestFlags(Cmd)
}

func includeCreateRequestFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&commonName, "commonName", "",
		"Common name (example: domain.com).")
	country = cmd.Flags().StringSlice("country", nil,
		"Country code (example: US).")
	state = cmd.Flags().StringSlice("state", nil,
		"Province/State (example: California)")
	city = cmd.Flags().StringSlice("city", nil,
		"Locality/City (example: New-York)")
	street = cmd.Flags().StringSlice("street", nil,
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
		"Subject Alternative Email Addresses")
	cmd.Flags().StringVar(&targetPath, "targetPath", "./csr.pem",
		"Target path for the CSR to be saved.")
	cmd.Flags().Var(
		enumflag.New(&signatureAlg, "signatureAlg", common.SignatureAlgIds, enumflag.EnumCaseInsensitive),
		"signatureAlg", "Signature Algorithm (allowed values: SHA256WithRSA (default if omitted)"+
			", SHA384WithRSA, SHA512WithRSA, SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA)")
	cmd.Flags().Lookup("signatureAlg").NoOptDefVal = "SHA256WithRSA"

	if err := cmd.MarkFlagRequired("commonName"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
