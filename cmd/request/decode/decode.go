package decode

import (
	"cert-ripper-go/pkg/cert"
	"github.com/spf13/cobra"
)

var (
	Cmd = &cobra.Command{
		Use:   "decode",
		Short: "Decode and print CSR file to the STDOUT in OpenSSL text format",
		Long:  ``,
		Run:   runDecodeRequest,
	}

	csrPath string
)

func runDecodeRequest(cmd *cobra.Command, args []string) {
	csr, csrErr := cert.DecodeCSR(csrPath)
	if csrErr != nil {
		cmd.PrintErrf("Failed to decode csr with path %s. Error: %s", csrPath, csrErr)
		return
	}

	ioErr := cert.PrintCSR(csr)
	if ioErr != nil {
		cmd.PrintErrf("Failed to print csr with path %s. Error: %s", csrPath, ioErr)
		return
	}
}

func init() {
	includeDecodeRequestFlags(Cmd)
}

func includeDecodeRequestFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&csrPath, "path", "",
		"Path for of the CSR file.")

	if err := cmd.MarkFlagRequired("path"); err != nil {
		cmd.PrintErrf("Failed to mark flag as required. Error: %s", err)
		return
	}
}
