package request

import (
	"cert-ripper-go/pkg/cert"
	"crypto/x509"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
	"log"
)

type SignatureAlgorithm enumflag.Flag

const (
	SHA256WithRSA SignatureAlgorithm = iota
	SHA384WithRSA
	SHA512WithRSA
	SHA256WithECDSA
	SHA384WithECDSA
	SHA512WithECDSA
)

var (
	createCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a CSR (certificate signing request)",
		Long:  ``,
		Run:   runCreateRequest,
	}

	signatureAlgIds = map[SignatureAlgorithm][]string{
		SHA256WithRSA:   {"SHA256WithRSA"},
		SHA384WithRSA:   {"SHA384WithRSA"},
		SHA512WithRSA:   {"SHA512WithRSA"},
		SHA256WithECDSA: {"SHA256WithECDSA"},
		SHA384WithECDSA: {"SHA384WithECDSA"},
		SHA512WithECDSA: {"SHA512WithECDSA"},
	}

	signatureAlgTox509 = map[SignatureAlgorithm]x509.SignatureAlgorithm{
		SHA256WithRSA:   x509.SHA256WithRSA,
		SHA384WithRSA:   x509.SHA384WithRSA,
		SHA512WithRSA:   x509.SHA512WithRSA,
		SHA256WithECDSA: x509.ECDSAWithSHA256,
		SHA384WithECDSA: x509.ECDSAWithSHA384,
		SHA512WithECDSA: x509.ECDSAWithSHA512,
	}

	commonName   string
	country      string
	state        string
	city         string
	organization string
	orgUnit      string
	email        string
	targetPath   string
	signatureAlg SignatureAlgorithm
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
		SignatureAlg: signatureAlgTox509[signatureAlg],
	}

	csr, csrErr := cert.CreateCSR(request)
	if csrErr != nil {
		log.Printf("Failed create CSR. Error: %s", csrErr)
	}
	ioErr := cert.SaveCSR(csr, targetPath)
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
	cmd.PersistentFlags().Var(
		enumflag.New(&signatureAlg, "signatureAlg", signatureAlgIds, enumflag.EnumCaseInsensitive),
		"signatureAlg", "Signature Algorithm (allowed values: SHA256WithRSA, SHA384WithRSA, SHA512WithRSA,"+
			"SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA)")
}
