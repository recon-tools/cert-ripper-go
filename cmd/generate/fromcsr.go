package generate

import (
	"github.com/spf13/cobra"
)

var (
	generateFromCsrCommand = &cobra.Command{
		Use:   "fromcsr",
		Short: "Generate a self-signed certificate from a CSR request",
		Long:  ``,
		Run:   runGenerateFromCsrRequest,
	}

	csrPath string
)

func runGenerateFromCsrRequest(cmd *cobra.Command, args []string) {
	//
}

func init() {
	includeGenerateFromCsrFlags(generateFromCsrCommand)
}

func includeGenerateFromCsrFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&csrPath, "path", "",
		"Path to the CSR file.")

	//
}
