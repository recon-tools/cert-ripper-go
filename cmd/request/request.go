package request

import (
	"cert-ripper-go/pkg"
	"github.com/spf13/cobra"
	"log"
)

var (
	Cmd = &cobra.Command{
		Use:   "request",
		Short: "Create a CSR (certificate signing request)",
		Long:  ``,
		Run:   runRequest,
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

func runRequest(cmd *cobra.Command, args []string) {
	csr, csrErr := pkg.CreateCSR(commonName, country, state, city, organization, orgUnit, email)
	if csrErr != nil {
		log.Printf("Failed create CSR\nError: %s", csrErr)
	}
	ioErr := pkg.SaveCSR(csr, targetPath)
	if ioErr != nil {
		log.Printf("Failed to save CSR to location %s\nError: %s", targetPath, csrErr)
	}
}

func init() {
	includeRequestFlags(Cmd)
}

func includeRequestFlags(cmd *cobra.Command) {
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
	cmd.PersistentFlags().StringVar(&orgUnit, "email", "",
		"Email address")
	cmd.PersistentFlags().StringVar(&targetPath, "targetPath", ".",
		"Target path for the CSR to be saved.")
}
