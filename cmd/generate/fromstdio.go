package generate

import (
	"cert-ripper-go/cmd/common"
	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
)

var (
	generateFromStdioCommand = &cobra.Command{
		Use:   "fromstdio",
		Short: "Generate a self-signed certificate",
		Long:  ``,
		Run:   runGenerateFromStdio,
	}

	host         string
	validFrom    string
	validFor     string
	isCa         string
	signatureAlg common.SignatureAlgorithm
)

func runGenerateFromStdio(cmd *cobra.Command, args []string) {
	//
}

func init() {
	includeGenerateFromStdio(generateFromStdioCommand)
}

func includeGenerateFromStdio(cmd *cobra.Command) {
	cmd.Flags().StringVar(&host, "host", "",
		"Hostname.")
	cmd.Flags().StringVar(&validFrom, "validFrom", "",
		"Creation date formatted as Jan 1 15:04:05 2011 .")
	cmd.Flags().StringVar(&validFor, "validFor", "",
		"Duration in seconds until which the certificates will be valid")
	cmd.Flags().StringVar(&isCa, "isCa", "",
		"Specify if the currently generated certificate should be its own Certificate Authority")
	cmd.Flags().Var(
		enumflag.New(&signatureAlg, "signatureAlg", common.SignatureAlgIds, enumflag.EnumCaseInsensitive),
		"signatureAlg", "Signature Algorithm (allowed values: SHA256WithRSA, SHA384WithRSA, SHA512WithRSA,"+
			"SHA256WithECDSA, SHA384WithECDSA, SHA512WithECDSA)")
}
