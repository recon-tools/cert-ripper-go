package request

import (
	"cert-ripper-go/cmd/common"
	"cert-ripper-go/pkg/cert"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
)

var (
	createCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a CSR (certificate signing request)",
		Long:  ``,
		Run:   runCreateRequest,
	}

	commonName   string
	country      string
	state        string
	city         string
	organization string
	orgUnit      string
	email        string
	targetPath   string
	signatureAlg common.SignatureAlgorithm
)

func runCreateRequest(cmd *cobra.Command, args []string) {
	request := cert.CertificateRequest{
		CommonName:   commonName,
		Country:      country,
		State:        state,
		City:         city,
		Organization: organization,
		OrgUnit:      orgUnit,
		Email:        email,
		SignatureAlg: common.SignatureAlgTox509[signatureAlg],
	}

	csr, privateKey, csrErr := cert.CreateCSR(request)
	if csrErr != nil {
		fmt.Printf("Failed create CSR. Error: %s", csrErr)
		return
	}

	ioErr := cert.SaveCSR(csr, targetPath)
	if ioErr != nil {
		fmt.Printf("Failed to save CSR to location %s. Error: %s", targetPath, ioErr)
		return
	}

	privateKeyTargetPath := targetPath + ".key"
	ioErr = cert.SavePrivateKey(privateKey, privateKeyTargetPath)
	if ioErr != nil {
		fmt.Printf("Failed to save Private KEY for CSR to location %s. Error: %s", privateKeyTargetPath, ioErr)
		return
	}
}

func init() {
	includeCreateRequestFlags(createCmd)
}

func includeCreateRequestFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&commonName, "commonName", "",
		"Common name (example: domain.com).")
	cmd.Flags().StringVar(&country, "country", "",
		"Country code (example: US).")
	cmd.Flags().StringVar(&state, "state", "",
		"Province/State (example: California)")
	cmd.Flags().StringVar(&city, "city", "",
		"Locality/City (example: New-York)")
	cmd.Flags().StringVar(&organization, "organization", "",
		"Organization (example: Acme)")
	cmd.Flags().StringVar(&orgUnit, "organizationUnit", "",
		"Organization unit (example: IT)")
	cmd.Flags().StringVar(&email, "email", "",
		"Email address")
	cmd.Flags().StringVar(&targetPath, "targetPath", ".",
		"Target path for the CSR to be saved.")
	cmd.Flags().Var(
		enumflag.New(&signatureAlg, "signatureAlg", common.SignatureAlgIds, enumflag.EnumCaseInsensitive),
		"signatureAlg", "Signature Algorithm (allowed values: SHA256WithRSA, SHA384WithRSA, SHA512WithRSA,"+
			"SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA)")

	if err := cmd.MarkFlagRequired("commonName"); err != nil {
		fmt.Println("Failed to mark flag as required", err)
		return
	}

	if err := cmd.MarkFlagRequired("country"); err != nil {
		fmt.Println("Failed to mark flag as required", err)
		return
	}

	if err := cmd.MarkFlagRequired("city"); err != nil {
		fmt.Println("Failed to mark flag as required", err)
		return
	}

	if err := cmd.MarkFlagRequired("organization"); err != nil {
		fmt.Println("Failed to mark flag as required", err)
		return
	}

	if err := cmd.MarkFlagRequired("email"); err != nil {
		fmt.Println("Failed to mark flag as required", err)
		return
	}

	if err := cmd.MarkFlagRequired("signatureAlg"); err != nil {
		fmt.Println("Failed to mark flag as required", err)
		return
	}
}
