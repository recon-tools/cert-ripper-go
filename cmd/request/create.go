package request

import (
	"cert-ripper-go/pkg"
	"github.com/spf13/cobra"
	"log"
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
)

func runCreateRequest(cmd *cobra.Command, args []string) {
	request := pkg.CertificateRequest{
		CommonName:   commonName,
		Country:      country,
		State:        state,
		City:         city,
		Organization: organization,
		OrgUnit:      orgUnit,
		Email:        email,
	}

	csr, csrErr := pkg.CreateCSR(request)
	if csrErr != nil {
		log.Printf("Failed create CSR. Error: %s", csrErr)
	}
	ioErr := pkg.SaveCSR(csr, targetPath)
	if ioErr != nil {
		log.Printf("Failed to save CSR to location %s. Error: %s", targetPath, ioErr)
	}
}

func init() {
	includeCreateRequestFlags(Cmd)
}

func includeCreateRequestFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&commonName, "commonName", "",
		"Common name (example: domain.com).")
	cmd.PersistentFlags().StringVar(&country, "country", "",
		"Country code (example: US).")
	cmd.PersistentFlags().StringVar(&state, "state", "",
		"Province/State (example: California)")
	cmd.PersistentFlags().StringVar(&city, "city", "",
		"Locality/City (example: New-York)")
	cmd.PersistentFlags().StringVar(&organization, "organization", "",
		"Organization (example: Acme)")
	cmd.PersistentFlags().StringVar(&orgUnit, "organizationUnit", "",
		"Organization unit (example: IT)")
	cmd.PersistentFlags().StringVar(&email, "email", "",
		"Email address")
	cmd.PersistentFlags().StringVar(&targetPath, "targetPath", ".",
		"Target path for the CSR to be saved.")
}
