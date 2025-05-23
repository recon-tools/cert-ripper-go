package create

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/pkg/core"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"path/filepath"
)

var (
	Cmd = &cobra.Command{
		Use:   "create",
		Short: "Create a CSR (certificate signing request)",
		Long:  ``,
		Run:   runCreateRequest,
	}

	commonName              string
	country                 *[]string
	state                   *[]string
	city                    *[]string
	street                  *[]string
	postalCode              *[]string
	organization            *[]string
	orgUnit                 *[]string
	targetPath              string
	signatureAlg            common.SignatureAlgorithm
	oidEmail                string
	emailAddresses          *[]string
	subjectAlternativeHosts *[]string
)

func runCreateRequest(cmd *cobra.Command, args []string) {
	request := core.CertificateRequest{
		CommonName:              commonName,
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
		SignatureAlg:            common.SignatureAlgTox509[signatureAlg],
	}

	targetPath = filepath.FromSlash(targetPath)

	var csrPath string
	var keyPath string
	extension := filepath.Ext(targetPath)
	if extension == "" {
		// We assume that a path without an extension is a directory. We append the certificate and the key name to it
		csrPath = filepath.Join(targetPath, "csr.pem")
		keyPath = filepath.Join(targetPath, "csr.pem.key")
	} else {
		pathWithoutExt := targetPath[0 : len(targetPath)-len(extension)]
		csrPath = pathWithoutExt + ".pem"
		keyPath = pathWithoutExt + ".pem.key"
	}

	csr, privateKey, csrErr := core.CreateCSR(request)
	if csrErr != nil {
		cmd.PrintErrf("Failed create CSR. Error: %s", csrErr)
		return
	}

	ioErr := core.SaveCSR(csr, csrPath)
	if ioErr != nil {
		cmd.PrintErrf("Failed to save CSR to location %s. Error: %s", targetPath, ioErr)
		return
	}

	ioErr = core.SavePrivateKey(privateKey, keyPath)
	if ioErr != nil {
		cmd.PrintErrf("Failed to save Private KEY for CSR to location %s. Error: %s", keyPath, ioErr)
		return
	}
}

func init() {
	includeCreateRequestFlags(Cmd)
}

func includeCreateRequestFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&commonName, "commonName", "c", "",
		"[Required] Hostname/Common name (example: domain.com).")
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
		"[Optional] Object Identifier (OID) Email Address. "+
			"Default: none")
	emailAddresses = cmd.Flags().StringSlice("email", nil,
		"[Optional] Email Addresses. It can accept multiple values divided by comma. "+
			"Default: none")
	subjectAlternativeHosts = cmd.Flags().StringSlice("subjectAlternativeHosts", nil,
		"[Optional] Subject Alternative Hosts. It can accept multiple values divided by comma. "+
			"Default: none")
	cmd.Flags().StringVarP(&targetPath, "targetPath", "t", "csr.pem",
		"[Optional] Target path for the CSR to be saved. "+
			"Default: the certificate signature request will be saved in the current working directory with the name of csr.pem")
	cmd.Flags().Var(
		enumflag.New(&signatureAlg, "signatureAlg", common.SignatureAlgIds, enumflag.EnumCaseInsensitive),
		"signatureAlg", "[Optional] Signature Algorithm (allowed values: SHA256WithRSA (default if omitted)"+
			", SHA384WithRSA, SHA512WithRSA, SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA)")
	cmd.Flags().Lookup("signatureAlg").NoOptDefVal = "SHA256WithRSA"

	if err := cmd.MarkFlagRequired("commonName"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
